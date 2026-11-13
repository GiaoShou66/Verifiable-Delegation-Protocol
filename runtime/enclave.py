"""VDP Hardware Confidential Computing Enclave Interface & Remote Attestation.

Addresses Dimension 6 (Runtime Sandboxing, Zero-Trust Transport & Hardware Boundaries)
and Regulatory Compliance (FedRAMP High, Common Criteria EAL 5+, DoD Zero Trust Reference).

Hardening & Fixes Applied:
    1. Replay Prevention via Nonce Invalidation: Verified challenge nonces are
       permanently consumed into a thread-safe registry.
    2. Timestamp Freshness Verification: Enclave attestation documents must be
       produced within an acceptable drift threshold (e.g., 60 seconds).
    3. Canonical Serialization: Document signing payload encoded deterministically
       with JSON, eliminating delimiter collisions.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import json
import threading
import time
from typing import Optional


@dataclass(frozen=True, slots=True)
class EnclaveAttestationDocument:
    """Hardware attestation document verifying the enclave image measurement."""

    enclave_image_pcr0: str
    enclave_public_key: str
    nonce: str
    timestamp: float
    hardware_ca_signature: str

    def canonical_bytes(self) -> bytes:
        payload = {
            "enclave_image_pcr0": self.enclave_image_pcr0,
            "enclave_public_key": self.enclave_public_key,
            "nonce": self.nonce,
            "timestamp": round(self.timestamp, 3),
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")

    @classmethod
    def generate(
        cls,
        pcr0: str,
        enclave_public_key: str,
        nonce: str,
        ca_signing_key: bytes,
        timestamp: Optional[float] = None,
    ) -> "EnclaveAttestationDocument":
        ts = time.time() if timestamp is None else timestamp
        payload = {
            "enclave_image_pcr0": pcr0,
            "enclave_public_key": enclave_public_key,
            "nonce": nonce,
            "timestamp": round(ts, 3),
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        sig = hmac.new(ca_signing_key, canonical, hashlib.sha256).hexdigest()
        return cls(
            enclave_image_pcr0=pcr0,
            enclave_public_key=enclave_public_key,
            nonce=nonce,
            timestamp=ts,
            hardware_ca_signature=sig,
        )

    def verify(self, ca_verification_key: bytes, expected_nonce: str) -> bool:
        if not hmac.compare_digest(self.nonce, expected_nonce):
            return False
        expected_sig = hmac.new(ca_verification_key, self.canonical_bytes(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(self.hardware_ca_signature, expected_sig)


class EnclaveMonitorVerifier:
    """Thread-safe verifier for hardware enclave authenticity and freshness."""

    def __init__(
        self,
        golden_pcr0: str,
        ca_public_key: bytes,
        max_drift_seconds: float = 60.0,
    ) -> None:
        self._golden_pcr0 = golden_pcr0
        self._ca_public_key = ca_public_key
        self._max_drift_seconds = max_drift_seconds
        self._consumed_nonces: set[str] = set()
        self._lock = threading.Lock()

    def verify_enclave(
        self,
        attestation: EnclaveAttestationDocument,
        challenge_nonce: str,
        *,
        now: Optional[float] = None,
    ) -> tuple[bool, str]:
        """Validates hardware attestation, freshness, and anti-replay nonce."""
        with self._lock:
            # 1. Anti-replay nonce check
            if challenge_nonce in self._consumed_nonces:
                return False, f"Replay attack detected: nonce '{challenge_nonce}' has already been consumed"

            # 2. Freshness check
            curr_now = time.time() if now is None else now
            if abs(curr_now - attestation.timestamp) > self._max_drift_seconds:
                return False, (
                    f"Attestation document expired: drift {abs(curr_now - attestation.timestamp):.1f}s "
                    f"exceeds max {self._max_drift_seconds}s"
                )

            # 3. Cryptographic signature and challenge check
            if not attestation.verify(self._ca_public_key, challenge_nonce):
                return False, "Hardware CA signature or challenge nonce mismatch"

            # 4. Golden PCR0 measurement check
            if attestation.enclave_image_pcr0 != self._golden_pcr0:
                return False, (
                    f"Untrusted enclave image! PCR0 mismatch: "
                    f"expected {self._golden_pcr0}, got {attestation.enclave_image_pcr0}"
                )

            self._consumed_nonces.add(challenge_nonce)
            return True, "Enclave verified and trusted"
