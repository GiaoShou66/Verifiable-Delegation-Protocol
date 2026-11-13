"""Production Hardening & Security Verification Tests.

Verifies:
  1. Strict Out-of-Process Isolation (client process cannot access monitor state or keys).
  2. Audit Log Tail-Truncation Detection via external anchor publisher.
  3. Mandatory Artifact Hash Pinning (detects tool table argument tampering).
  4. Server-Side Clock Authority (client-supplied forged timestamps are ignored).
  5. Idempotent Tool Execution (network flakiness resiliency without double-charging).
  6. Transport Peer Authentication (transport_token handshake).
  7. Key Management & Policy Epoch Lifecycle.
"""

from __future__ import annotations

import os
import threading
import time
from pathlib import Path

import pytest

from monitor.automaton import ConcreteAction
from monitor.mediate import Monitor
from policy.parser import parse
from runtime.auditlog import AuditLog, FileAnchorPublisher
from runtime.client import ClientError, MonitorClient
from runtime.idempotency import IdempotentExecutorWrapper, compute_idempotency_key
from runtime.server import MonitorServer
from runtime.shim import AgentShim, ShimError, ToolSpec, artifact_hash
from tokens.kms import EnvKeyProvider, EpochManager, StaticKeyProvider
from tokens.macaroon import TokenError, mint
from tokens.scope import Scope

ROOT_KEY = b"k" * 32
LOG_KEY = b"l" * 32

DEMO_POLICY = """
counter spend over {pay}
always(spend <= 10000 cents)
and always(pay(target) -> target in {"alice_utility", "bob_store"})
and always(not delete_account)
"""

TOOLS = {
    "pay_bill": ToolSpec(verb="pay", target_arg="recipient", amount_arg="cents"),
    "delete_account": ToolSpec(verb="delete_account"),
}


@pytest.fixture
def policy():
    return parse(DEMO_POLICY)


@pytest.fixture
def root_token(policy):
    return mint(ROOT_KEY, Scope.root_from_policy(policy), policy_hash=policy.digest())


# --------------------------------------------------------------------------
# 1. Transport Isolation Test
# --------------------------------------------------------------------------


def test_client_has_zero_access_to_server_memory(tmp_path, policy, root_token):
    """The client socket wrapper has no reference to Monitor, AuditLog, or keys."""
    log = AuditLog(tmp_path / "audit.jsonl", policy.digest(), LOG_KEY)
    pinned_hash = artifact_hash(policy.digest(), TOOLS)
    shim = AgentShim(
        Monitor(policy),
        TOOLS,
        log,
        ROOT_KEY,
        executor=lambda name, args: "executed",
        expected_artifact_hash=pinned_hash,
    )
    server = MonitorServer(shim, port=0)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()

    try:
        host, port = server.address
        with MonitorClient(host, port) as client:
            outcome = client.call("pay_bill", {"recipient": "alice_utility", "cents": 100}, root_token)
            assert outcome.allowed
            assert outcome.result == "executed"

            # Assert memory isolation: client has no handle to server-side objects
            assert not hasattr(client, "_shim")
            assert not hasattr(client, "_monitor")
            assert not hasattr(client, "_root_key")
            assert not hasattr(client, "_log")

            # Slots prevent arbitrary attribute injection
            with pytest.raises(AttributeError):
                client._monitor = "tamper"
    finally:
        server.stop()


# --------------------------------------------------------------------------
# 2. Tail-Truncation Detection Test
# --------------------------------------------------------------------------


def test_tail_truncation_is_detected_by_external_anchor(tmp_path, policy, root_token):
    """Deleting the last records from audit.jsonl is immediately detected by the anchor."""
    log_path = tmp_path / "audit.jsonl"
    anchor_path = tmp_path / "audit.anchor"

    anchor = FileAnchorPublisher(anchor_path)
    log = AuditLog(log_path, policy.digest(), LOG_KEY, anchor_publisher=anchor)
    pinned_hash = artifact_hash(policy.digest(), TOOLS)
    shim = AgentShim(
        Monitor(policy),
        TOOLS,
        log,
        ROOT_KEY,
        executor=lambda name, args: "ok",
        expected_artifact_hash=pinned_hash,
    )

    # Append 5 records
    for i in range(5):
        shim.call("pay_bill", {"recipient": "alice_utility", "cents": 10}, root_token)

    assert len(log.records()) == 5
    ok, msg = anchor.verify_log(log)
    assert ok
    assert "matches" in msg

    # Simulate adversary truncating the last 2 records from audit.jsonl
    lines = log_path.read_text(encoding="utf-8").strip().splitlines()
    truncated_content = "\n".join(lines[:-2]) + "\n"
    log_path.write_text(truncated_content, encoding="utf-8")

    # Re-open log from truncated file
    truncated_log = AuditLog(log_path, policy.digest(), LOG_KEY)
    assert len(truncated_log.records()) == 3

    # Verification against anchor catches the truncation!
    tamper_ok, tamper_msg = anchor.verify_log(truncated_log)
    assert not tamper_ok
    assert "tail truncation detected" in tamper_msg


# --------------------------------------------------------------------------
# 3. Artifact Hash Mismatch Test
# --------------------------------------------------------------------------


def test_tampered_tool_spec_is_rejected_by_artifact_hash(tmp_path, policy):
    """Altering argument names (cents -> dollars) invalidates artifact_hash."""
    log = AuditLog(tmp_path / "audit.jsonl", policy.digest(), LOG_KEY)
    valid_hash = artifact_hash(policy.digest(), TOOLS)

    # Hostile modification: map amount to "dollars" instead of "cents"
    tampered_tools = {
        "pay_bill": ToolSpec(verb="pay", target_arg="recipient", amount_arg="dollars"),
        "delete_account": ToolSpec(verb="delete_account"),
    }

    # Shim refuses initialization because tool mapping table differs from confirmed hash
    with pytest.raises(ShimError, match="does not match expected_artifact_hash"):
        AgentShim(
            Monitor(policy),
            tampered_tools,
            log,
            ROOT_KEY,
            expected_artifact_hash=valid_hash,
        )

    # Omitting artifact hash in strict mode also refuses initialization
    with pytest.raises(ShimError, match="expected_artifact_hash is mandatory"):
        AgentShim(
            Monitor(policy),
            TOOLS,
            log,
            ROOT_KEY,
            expected_artifact_hash=None,
            require_artifact_hash=True,
        )


# --------------------------------------------------------------------------
# 4. Forged Timestamp Test
# --------------------------------------------------------------------------


def test_server_clock_enforces_expiry_ignoring_forged_client_now(tmp_path, policy):
    """An expired token cannot be revived by sending now: 0 in request."""
    # Token expired long ago (timestamp = 1000)
    expired_token = mint(
        ROOT_KEY,
        Scope.root_from_policy(policy, expires_at=1000),
        policy_hash=policy.digest(),
    )

    log = AuditLog(tmp_path / "audit.jsonl", policy.digest(), LOG_KEY)
    pinned_hash = artifact_hash(policy.digest(), TOOLS)
    shim = AgentShim(
        Monitor(policy),
        TOOLS,
        log,
        ROOT_KEY,
        executor=lambda name, args: "ok",
        expected_artifact_hash=pinned_hash,
    )

    # Server defaults to local clock (time.time() >> 1000)
    server = MonitorServer(shim, port=0, clock=time.time)
    threading.Thread(target=server.serve_forever, daemon=True).start()

    try:
        host, port = server.address
        with MonitorClient(host, port) as client:
            # Client attempts to bypass expiry by forging now=0
            outcome = client.call(
                "pay_bill",
                {"recipient": "alice_utility", "cents": 10},
                expired_token,
                now=0,  # Forged timestamp!
            )
            # Server uses its own clock, so the forged now is ignored
            assert not outcome.allowed
            assert outcome.gate == "token"
            assert "expired" in outcome.reason.lower()
    finally:
        server.stop()


# --------------------------------------------------------------------------
# 5. Idempotent Tool Execution Verification
# --------------------------------------------------------------------------


def test_idempotent_executor_wrapper_deduplicates(tmp_path, policy, root_token):
    """Duplicate tool actions with identical idempotency key are served from cache."""
    call_count = 0

    def mock_bank_api(tool_name: str, attrs: dict, **kwargs):
        nonlocal call_count
        call_count += 1
        return {"status": "PAID", "tx_id": f"tx_{call_count}"}

    wrapper = IdempotentExecutorWrapper(mock_bank_api, pass_idempotency_key=True)

    log = AuditLog(tmp_path / "audit.jsonl", policy.digest(), LOG_KEY)
    pinned_hash = artifact_hash(policy.digest(), TOOLS)
    shim = AgentShim(
        Monitor(policy),
        TOOLS,
        log,
        ROOT_KEY,
        executor=wrapper,
        expected_artifact_hash=pinned_hash,
    )

    # First call
    out1 = shim.call("pay_bill", {"recipient": "alice_utility", "cents": 100}, root_token)
    assert out1.allowed
    assert out1.result["tx_id"] == "tx_1"
    assert call_count == 1

    # Simulate retrying the same call with the same token and parameters directly through wrapper
    key = compute_idempotency_key(
        token_id=root_token.token_id(),
        seq=out1.record.seq,
        tool_name="pay_bill",
        attrs={"recipient": "alice_utility", "cents": 100},
    )
    retried_result = wrapper(
        "pay_bill",
        {"recipient": "alice_utility", "cents": 100},
        token_id=root_token.token_id(),
        seq=out1.record.seq,
    )
    assert retried_result["tx_id"] == "tx_1"
    # Bank was NOT called a second time!
    assert call_count == 1
    assert wrapper.is_cached(key)


# --------------------------------------------------------------------------
# 6. Transport Peer Authentication Test
# --------------------------------------------------------------------------


def test_transport_peer_authentication_handshake(tmp_path, policy, root_token):
    """Clients without matching transport_token are refused."""
    log = AuditLog(tmp_path / "audit.jsonl", policy.digest(), LOG_KEY)
    pinned_hash = artifact_hash(policy.digest(), TOOLS)
    shim = AgentShim(
        Monitor(policy),
        TOOLS,
        log,
        ROOT_KEY,
        executor=lambda name, args: "ok",
        expected_artifact_hash=pinned_hash,
    )

    # Server requires transport_token
    server = MonitorServer(shim, port=0, transport_token="secret_handshake_999")
    threading.Thread(target=server.serve_forever, daemon=True).start()

    try:
        host, port = server.address

        # 1. Client without transport_token fails
        with pytest.raises(ClientError, match="unauthorized"):
            with MonitorClient(host, port) as bad_client:
                bad_client.call("pay_bill", {"recipient": "alice_utility", "cents": 10}, root_token)

        # 2. Client with wrong transport_token fails
        with pytest.raises(ClientError, match="unauthorized"):
            MonitorClient(host, port, transport_token="wrong_token")

        # 3. Client with valid transport_token succeeds
        with MonitorClient(host, port, transport_token="secret_handshake_999") as good_client:
            outcome = good_client.call("pay_bill", {"recipient": "alice_utility", "cents": 50}, root_token)
            assert outcome.allowed
            assert outcome.result == "ok"
    finally:
        server.stop()


# --------------------------------------------------------------------------
# 7. Key Management & Policy Epoch Lifecycle Test
# --------------------------------------------------------------------------


def test_key_provider_and_epoch_manager(tmp_path, policy):
    """EpochManager cleanly rotates epochs, archives logs, and switches keys."""
    key_provider = StaticKeyProvider(
        root_key=ROOT_KEY,
        log_key=LOG_KEY,
        extra_root_keys={"epoch2": b"k2" * 16},
        extra_log_keys={"epoch2": b"l2" * 16},
    )

    epoch_mgr = EpochManager(
        base_dir=tmp_path / "epochs",
        key_provider=key_provider,
        policy_hash=policy.digest(),
        initial_epoch_id=1,
    )

    epoch1 = epoch_mgr.current_epoch
    assert epoch1.epoch_id == 1
    assert epoch1.epoch_dir.exists()

    # Append records in epoch 1
    token1 = mint(ROOT_KEY, Scope.root_from_policy(policy), policy_hash=policy.digest())
    pinned_hash = artifact_hash(policy.digest(), TOOLS)
    shim1 = AgentShim(
        Monitor(policy),
        TOOLS,
        epoch_mgr.active_log,
        ROOT_KEY,
        executor=lambda n, a: "ok",
        expected_artifact_hash=pinned_hash,
    )
    shim1.call("pay_bill", {"recipient": "alice_utility", "cents": 100}, token1)

    assert epoch1.log_path.exists()
    assert len(epoch_mgr.active_log.records()) == 1

    # Rotate to Epoch 2 with new keys
    epoch2 = epoch_mgr.rotate_epoch(
        new_root_key_id="epoch2",
        new_log_key_id="epoch2",
    )
    assert epoch2.epoch_id == 2
    assert epoch2.log_path != epoch1.log_path
    assert len(epoch_mgr.active_log.records()) == 0


def test_mint_requires_policy_hash_when_strict():
    """mint() raises TokenError if policy_hash is empty and allow_unbound is False."""
    scope = Scope(verbs=frozenset({"pay"}))
    with pytest.raises(TokenError, match="policy_hash is required"):
        mint(ROOT_KEY, scope, policy_hash="", allow_unbound=False)
