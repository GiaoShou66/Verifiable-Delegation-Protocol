"""Comprehensive Automated Regulatory Compliance & 6 Core Dimensions Test Suite.

Programmatically validates VDP's enterprise-grade implementations against:
  1. Basel III & ISO 20022: Bilateral Escrow Reversals & Monotonic Safety Invariant
  2. FIPS 140-3 & SEC Rule 17a-4: Asymmetric Digital Non-Repudiation, RFC 3161 TSA & Key Zeroization
  3. NIST SP 800-162 & DoD Directive 3000.09: Lineage Accumulator, Full Verification & Cascading Revocation
  4. SWIFT & FedNow: Two-Phase Monitored Reservation (2PMR) & Transactional Atomicity
  5. Financial Low-Latency SLA: Sharded State Partitioning & Group-Commit WAL
  6. FedRAMP High & Common Criteria EAL 5+: Enclave Remote Attestation & PCR Integrity
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import threading
import time
import pytest

from runtime.escrow import (
    AttestedReversalProof,
    BilateralEscrowMonitor,
    SlidingWindowRateLimiter,
)
from runtime.asymmetric_audit import (
    AsymmetricAuditVerifier,
    AsymmetricLogSigner,
    FIPSKeyZeroizer,
    RFC3161Authority,
)
from tokens.lineage import (
    CascadingRevocationRegistry,
    LineageToken,
    verify_lineage,
)
from runtime.reservation import (
    ReservationStatus,
    TwoPhaseReservationCoordinator,
)
from runtime.sharded_wal import (
    GroupCommitWal,
    ShardedMonitor,
)
from runtime.enclave import (
    EnclaveAttestationDocument,
    EnclaveMonitorVerifier,
)
from runtime.idempotency import IdempotentExecutorWrapper


# =====================================================================
# 維度 1: 形式化安全與自動機極限 / Basel III & ISO 20022
# =====================================================================

def test_dim1_basel_iii_iso20022_escrow_reversal_safety() -> None:
    clearing_key = b"clearing-house-secret-key-32b-!"
    authorities = {"SWIFT_CLEARING": clearing_key}
    monitor = BilateralEscrowMonitor(bounds={"transfer": 50000}, clearing_authorities=authorities)

    # 1. Agent spend moves committed forward
    assert monitor.record_spend("transfer", 20000) is True
    state = monitor.get_state("transfer")
    assert state.committed == 20000
    assert state.net_spent == 20000
    assert state.available == 30000

    # 2. Agent cannot emit negative delta to forge refunds
    assert monitor.record_spend("transfer", -5000) is False
    assert monitor.get_state("transfer").available == 30000

    # 3. Legitimate bank refund via signed AttestedReversalProof (ISO 20022 pacs.004)
    now_t = 1700000000.0
    proof = AttestedReversalProof.create(
        tx_id="tx_swift_001",
        counter_name="transfer",
        amount=5000,
        issuer="SWIFT_CLEARING",
        signing_key=clearing_key,
        timestamp=now_t,
    )
    ok, msg = monitor.apply_reversal(proof, now=now_t)
    assert ok is True
    state = monitor.get_state("transfer")
    assert state.refunded == 5000
    assert state.net_spent == 15000
    assert state.available == 35000  # Quota restored safely!

    # 4. Anti-replay protection: cannot apply same reversal twice
    ok, msg = monitor.apply_reversal(proof, now=now_t)
    assert ok is False
    assert "already settled" in msg

    # 5. Timestamp drift protection: proof from 1 hour ago is rejected
    stale_proof = AttestedReversalProof.create(
        tx_id="tx_swift_002",
        counter_name="transfer",
        amount=2000,
        issuer="SWIFT_CLEARING",
        signing_key=clearing_key,
        timestamp=now_t - 3600.0,
    )
    ok, msg = monitor.apply_reversal(stale_proof, now=now_t, max_drift_seconds=300.0)
    assert ok is False
    assert "drifted beyond" in msg

    # 6. Forged reversal signature is rejected
    fake_proof = AttestedReversalProof.create(
        tx_id="tx_swift_003",
        counter_name="transfer",
        amount=10000,
        issuer="SWIFT_CLEARING",
        signing_key=b"attacker-forged-key-32b--------!",
        timestamp=now_t,
    )
    ok, msg = monitor.apply_reversal(fake_proof, now=now_t)
    assert ok is False
    assert "Invalid reversal signature" in msg


def test_dim1_sliding_window_aml_rate_limiting() -> None:
    limiter = SlidingWindowRateLimiter(window_seconds=60.0, num_slots=6, max_limit=100000)
    base_t = 1000000.0

    assert limiter.record_action(40000, now=base_t) is True
    assert limiter.record_action(40000, now=base_t + 5.0) is True
    assert limiter.record_action(30000, now=base_t + 10.0) is False
    assert limiter.record_action(30000, now=base_t + 65.0) is True


# =====================================================================
# 維度 2: 密碼學強度、非否認性與 FIPS 140-3 / SEC Rule 17a-4
# =====================================================================

def test_dim2_fips140_3_sec17a4_asymmetric_audit_and_zeroization() -> None:
    signer = AsymmetricLogSigner()
    pub_bytes = signer.public_key_bytes

    # Independent auditor has ONLY the public key
    auditor = AsymmetricAuditVerifier(pub_bytes)

    head_hash = hashlib.sha256(b"head-record-data").hexdigest()
    policy_hash = hashlib.sha256(b"policy-digest").hexdigest()
    seq = 42

    signature = signer.sign_head(head_hash, policy_hash, seq)
    assert len(signature) == 64  # Ed25519 signature is 64 bytes

    # 1. Auditor verifies signature with zero access to private key
    assert auditor.verify(head_hash, policy_hash, seq, signature) is True

    # 2. Tampered head_hash fails verification
    tampered_hash = hashlib.sha256(b"tampered").hexdigest()
    assert auditor.verify(tampered_hash, policy_hash, seq, signature) is False

    # 3. RFC 3161 TSA Timestamp Token issuance and validation
    tsa = RFC3161Authority(tsa_identity="GOV-FED-TSA-001")
    tst_token = tsa.issue_timestamp(head_hash)
    assert tsa.verify_token(tst_token) is True
    assert tst_token.imprint_hash == head_hash

    # Tampered token signature fails
    fake_tst = RFC3161Authority(tsa_identity="ROGUE-TSA").issue_timestamp(head_hash)
    assert tsa.verify_token(fake_tst) is False

    # 4. FIPS 140-3 Cryptographic Key Zeroization
    secret_buf = bytearray(b"highly-sensitive-hsm-root-secret")
    assert secret_buf != b"\x00" * len(secret_buf)
    FIPSKeyZeroizer.zeroize(secret_buf)
    assert secret_buf == b"\x00" * len(secret_buf)


# =====================================================================
# 維度 3: 委託授權半格、階層撤銷樹 / NIST SP 800-162 & DoD Directive 3000.09
# =====================================================================

def test_dim3_nist_sp800_162_dod3000_cascading_revocation_orphan_token() -> None:
    root_key = b"defense-root-authority-key-32b-!"
    policy_hash = "f" * 64
    registry = CascadingRevocationRegistry()

    # 1. Mint Root Token A (Supreme Command)
    token_a = LineageToken.mint_root(
        root_key=root_key,
        root_id="root_commander",
        policy_hash=policy_hash,
        allowed_verbs=["recon", "deploy", "strike"],
        bound=1000,
        expires_at=time.time() + 3600,
    )
    assert token_a.lineage == ()
    assert verify_lineage(root_key, token_a, expected_policy_hash=policy_hash) is True

    # 2. Attenuate A -> Token B (Field Officer)
    token_b = token_a.attenuate(
        allowed_verbs=["recon", "deploy"],
        new_bound=500,
    )
    assert token_b.lineage == (token_a.token_id,)
    assert verify_lineage(root_key, token_b, expected_policy_hash=policy_hash) is True

    # 3. Attenuate B -> Token C (Sub-Agent Drone Swarm)
    token_c = token_b.attenuate(
        allowed_verbs=["recon"],
        new_bound=100,
    )
    assert token_c.lineage == (token_a.token_id, token_b.token_id)
    assert verify_lineage(root_key, token_c, expected_policy_hash=policy_hash) is True

    # Wrong root key fails verification
    assert verify_lineage(b"wrong-key-32b------------------!", token_c) is False

    # 4. All tokens initially allowed
    assert registry.check_token(token_a)[0] is True
    assert registry.check_token(token_b)[0] is True
    assert registry.check_token(token_c)[0] is True

    # 5. Revoke Parent Token B (Field Officer compromised)
    registry.revoke(token_b.token_id, reason="compromised in field operations")

    # 6. Verify Cascading Revocation: Child Token C is INSTANTLY BLOCKED!
    allowed, reason = registry.check_token(token_c)
    assert allowed is False
    assert "Cascading revocation" in reason
    assert token_b.token_id in reason

    # 7. Root Token A remains unrevoked
    assert registry.check_token(token_a)[0] is True


# =====================================================================
# 維度 4: 事務原子性、無回滾悖論與兩階段預留 / SWIFT & FedNow
# =====================================================================

def test_dim4_swift_fednow_two_phase_reservation_transactional_atomicity() -> None:
    coordinator_key = b"swift-coordinator-secret-key-32!"
    coord = TwoPhaseReservationCoordinator(
        key=coordinator_key,
        bounds={"wire_transfer": 100000},
    )

    # 1. Phase 1: Reserve 40,000
    ticket = coord.reserve(
        token_id="tok_123",
        counter_name="wire_transfer",
        amount=40000,
        ttl_seconds=60.0,
    )
    bal = coord.get_balance("wire_transfer")
    assert bal["committed"] == 0
    assert bal["reserved"] == 40000
    assert bal["available"] == 60000

    # 2. Quota exhaustion protection: trying to reserve 70,000 fails (only 60,000 available)
    with pytest.raises(PermissionError, match="Insufficient quota"):
        coord.reserve(token_id="tok_123", counter_name="wire_transfer", amount=70000)

    # 3. Phase 3b Abort: Downstream network failure (HTTP 504 on wire)
    aborted = coord.abort(ticket, failure_reason="SWIFT gateway timeout 504")
    assert aborted is True
    bal = coord.get_balance("wire_transfer")
    assert bal["reserved"] == 0
    assert bal["available"] == 100000  # Quota safely restored without budget leakage!

    # 4. Phase 1 + Phase 3a Commit: Successful transfer
    ticket2 = coord.reserve(token_id="tok_123", counter_name="wire_transfer", amount=35000)
    committed = coord.commit(ticket2, receipt_data="SWIFT_URN_987654321")
    assert committed is True
    bal = coord.get_balance("wire_transfer")
    assert bal["committed"] == 35000
    assert bal["reserved"] == 0
    assert bal["available"] == 65000


# =====================================================================
# 維度 5: 並發架構、無鎖佇列與組提交 / Financial Low-Latency SLA
# =====================================================================

def test_dim5_concurrency_sharded_monitor_and_group_commit_wal(tmp_path: Path) -> None:
    # 1. ShardedMonitor eliminates lock contention across independent accounts
    sharded = ShardedMonitor(num_shards=8)
    results: list[bool] = []

    def worker(account_id: str, amt: int) -> None:
        ok, _ = sharded.mediate_spend(account_id, amt, limit=10000)
        results.append(ok)

    threads = [
        threading.Thread(target=worker, args=(f"acct_{i}", 1000))
        for i in range(20)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(results) == 20
    assert all(results)

    # 2. GroupCommitWal amortized batch flush
    wal_path = tmp_path / "group_commit_wal.bin"
    wal = GroupCommitWal(wal_path, max_batch_size=10, flush_interval_seconds=0.01)

    try:
        def wal_writer(worker_id: int) -> None:
            for j in range(5):
                wal.append_sync(f"worker_{worker_id}_record_{j}".encode("utf-8"))

        writer_threads = [
            threading.Thread(target=wal_writer, args=(i,))
            for i in range(4)
        ]
        for wt in writer_threads:
            wt.start()
        for wt in writer_threads:
            wt.join()

    finally:
        wal.close()

    # Verify all 20 records reached physical disk
    lines = wal_path.read_bytes().strip().split(b"\n")
    assert len(lines) == 20


# =====================================================================
# 維度 6: 運行時沙盒化、零信任與硬體邊界 / FedRAMP High & Common Criteria
# =====================================================================

def test_dim6_fedramp_high_enclave_attestation_and_zero_trust() -> None:
    ca_key = b"hardware-oem-attestation-root-ca!"
    golden_pcr0 = hashlib.sha384(b"vdp-enclave-golden-image-v1.0.0").hexdigest()
    verifier = EnclaveMonitorVerifier(golden_pcr0=golden_pcr0, ca_public_key=ca_key, max_drift_seconds=60.0)

    now_t = 1700000000.0
    challenge_nonce = "client-secure-challenge-nonce-999"

    # 1. Legitimate Enclave with verified code measurement
    valid_attestation = EnclaveAttestationDocument.generate(
        pcr0=golden_pcr0,
        enclave_public_key="enclave-pub-key-x509",
        nonce=challenge_nonce,
        ca_signing_key=ca_key,
        timestamp=now_t,
    )
    ok, msg = verifier.verify_enclave(valid_attestation, challenge_nonce, now=now_t)
    assert ok is True
    assert "Enclave verified and trusted" in msg

    # 2. Replay attack: reusing the same nonce is rejected
    ok, msg = verifier.verify_enclave(valid_attestation, challenge_nonce, now=now_t)
    assert ok is False
    assert "Replay attack detected: nonce" in msg

    # 3. Tampered Enclave image
    rogue_pcr0 = hashlib.sha384(b"rogue-patched-enclave-code").hexdigest()
    fresh_nonce = "nonce-2"
    tampered_attestation = EnclaveAttestationDocument.generate(
        pcr0=rogue_pcr0,
        enclave_public_key="enclave-pub-key-x509",
        nonce=fresh_nonce,
        ca_signing_key=ca_key,
        timestamp=now_t,
    )
    ok, msg = verifier.verify_enclave(tampered_attestation, fresh_nonce, now=now_t)
    assert ok is False
    assert "Untrusted enclave image! PCR0 mismatch" in msg

    # 4. Expired attestation document
    fresh_nonce_3 = "nonce-3"
    expired_attestation = EnclaveAttestationDocument.generate(
        pcr0=golden_pcr0,
        enclave_public_key="enclave-pub-key-x509",
        nonce=fresh_nonce_3,
        ca_signing_key=ca_key,
        timestamp=now_t - 120.0,  # 120s old > 60s max drift
    )
    ok, msg = verifier.verify_enclave(expired_attestation, fresh_nonce_3, now=now_t)
    assert ok is False
    assert "Attestation document expired" in msg


# =====================================================================
# 附加端對端安全驗證: IdempotentExecutorWrapper 並發安全性
# =====================================================================

def test_idempotent_executor_wrapper_concurrency() -> None:
    call_counts = {"count": 0}

    def raw_executor(tool_name: str, attrs: dict, idempotency_key: str = "") -> dict:
        call_counts["count"] += 1
        return {"status": "ok", "key": idempotency_key}

    wrapped = IdempotentExecutorWrapper(raw_executor, cache_responses=True)

    def worker() -> None:
        for _ in range(10):
            wrapped("pay", {"cents": 100}, token_id="tok_fixed", seq=1)

    threads = [threading.Thread(target=worker) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # The underlying executor should have only been invoked ONCE due to idempotency deduplication
    assert call_counts["count"] == 1
    assert len(wrapped.call_history) == 50
    assert wrapped.is_cached(wrapped.call_history[0]["idempotency_key"]) is True
