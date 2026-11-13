"""VDP Cryptographic Lineage Accumulator & Cascading Revocation Registry.

Addresses Dimension 3 (Capability Delegation Semilattice & Hierarchical Revocation Tree)
and Regulatory Compliance (NIST SP 800-162 ABAC, DoD Directive 3000.09 Autonomy in Weapons/Defense).

Hardening & Fixes Applied:
    1. Preserved Root Invariants: `LineageToken` retains immutable `root_verbs`,
       `root_bound`, and `root_expires_at`, allowing exact deterministic re-derivation
       of the root signature during downstream verification.
    2. Caveat Chain Traversal: `verify_lineage` starts at root and sequentially
       derives every intermediate HMAC tag and lineage accumulator.
    3. Thread-Safe Cascading Revocation: `CascadingRevocationRegistry` protects
       revocation lookups under concurrency.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import json
import threading
from typing import Optional, Sequence


@dataclass(frozen=True, slots=True)
class LineageCaveat:
    """Historical caveat recording one step of capability attenuation."""

    allowed_verbs: tuple[str, ...]
    bound: Optional[int]
    expires_at: Optional[float]
    parent_token_id: str

    def canonical_bytes(self) -> bytes:
        payload = {
            "allowed_verbs": sorted(list(self.allowed_verbs)),
            "bound": self.bound,
            "expires_at": self.expires_at,
            "parent_token_id": self.parent_token_id,
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


@dataclass(frozen=True, slots=True)
class LineageToken:
    """An attenuated capability token carrying a tamper-proof ancestor lineage accumulator."""

    root_id: str
    token_id: str
    policy_hash: str
    root_verbs: tuple[str, ...]
    root_bound: Optional[int]
    root_expires_at: Optional[float]
    allowed_verbs: tuple[str, ...]
    bound: Optional[int]
    expires_at: Optional[float]
    lineage: tuple[str, ...]  # Ancestor token IDs in order from root to parent
    caveats: tuple[LineageCaveat, ...]
    signature: bytes

    @staticmethod
    def _compute_lineage_digest(lineage: tuple[str, ...]) -> bytes:
        canonical = json.dumps(list(lineage), separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(canonical).digest()

    @classmethod
    def mint_root(
        cls,
        root_key: bytes,
        root_id: str,
        policy_hash: str,
        allowed_verbs: Sequence[str],
        bound: Optional[int] = None,
        expires_at: Optional[float] = None,
    ) -> "LineageToken":
        """Mints a root token with an empty lineage."""
        if not policy_hash:
            raise ValueError("Root token must be bound to a non-empty policy_hash")
        verbs = tuple(sorted(set(allowed_verbs)))
        lineage = ()
        caveats = ()

        payload = {
            "allowed_verbs": list(verbs),
            "bound": bound,
            "expires_at": expires_at,
            "policy_hash": policy_hash,
            "root_id": root_id,
            "type": "root",
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        sig = hmac.new(root_key, canonical, hashlib.sha256).digest()
        token_id = hmac.new(sig, b"lineage_id", hashlib.sha256).hexdigest()

        return cls(
            root_id=root_id,
            token_id=token_id,
            policy_hash=policy_hash,
            root_verbs=verbs,
            root_bound=bound,
            root_expires_at=expires_at,
            allowed_verbs=verbs,
            bound=bound,
            expires_at=expires_at,
            lineage=lineage,
            caveats=caveats,
            signature=sig,
        )

    def attenuate(
        self,
        *,
        allowed_verbs: Optional[Sequence[str]] = None,
        new_bound: Optional[int] = None,
        new_expires_at: Optional[float] = None,
    ) -> "LineageToken":
        """Attenuates token monotonically and accumulates self.token_id into child lineage."""
        # 1. Semilattice Verbs
        if allowed_verbs is None:
            child_verbs = self.allowed_verbs
        else:
            cand = set(allowed_verbs)
            if not cand.issubset(set(self.allowed_verbs)):
                raise ValueError("Cannot attenuate: requested verbs exceed parent scope")
            child_verbs = tuple(sorted(cand))

        # 2. Semilattice Bound
        if new_bound is None:
            child_bound = self.bound
        else:
            if new_bound < 0:
                raise ValueError("Bound must be non-negative")
            if self.bound is not None and new_bound > self.bound:
                raise ValueError(f"Cannot expand bound from {self.bound} to {new_bound}")
            child_bound = new_bound

        # 3. Semilattice Expiration
        if new_expires_at is None:
            child_expires_at = self.expires_at
        else:
            if self.expires_at is not None and new_expires_at > self.expires_at:
                raise ValueError("Cannot extend expiry beyond parent expiry")
            child_expires_at = new_expires_at

        # 4. Accumulate lineage: child inherits parent's lineage + parent's token_id
        child_lineage = self.lineage + (self.token_id,)
        caveat = LineageCaveat(
            allowed_verbs=child_verbs,
            bound=child_bound,
            expires_at=child_expires_at,
            parent_token_id=self.token_id,
        )

        caveat_payload = caveat.canonical_bytes() + self._compute_lineage_digest(child_lineage)
        child_sig = hmac.new(self.signature, caveat_payload, hashlib.sha256).digest()
        child_id = hmac.new(child_sig, b"lineage_id", hashlib.sha256).hexdigest()

        return LineageToken(
            root_id=self.root_id,
            token_id=child_id,
            policy_hash=self.policy_hash,
            root_verbs=self.root_verbs,
            root_bound=self.root_bound,
            root_expires_at=self.root_expires_at,
            allowed_verbs=child_verbs,
            bound=child_bound,
            expires_at=child_expires_at,
            lineage=child_lineage,
            caveats=self.caveats + (caveat,),
            signature=child_sig,
        )


def verify_lineage(
    root_key: bytes,
    token: LineageToken,
    expected_policy_hash: Optional[str] = None,
) -> bool:
    """Verifies the complete cryptographic HMAC chain from root key to leaf LineageToken."""
    if not isinstance(token, LineageToken):
        return False
    if expected_policy_hash is not None and token.policy_hash != expected_policy_hash:
        return False

    # 1. Recompute root signature from immutable root parameters
    payload = {
        "allowed_verbs": list(token.root_verbs),
        "bound": token.root_bound,
        "expires_at": token.root_expires_at,
        "policy_hash": token.policy_hash,
        "root_id": token.root_id,
        "type": "root",
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    current_sig = hmac.new(root_key, canonical, hashlib.sha256).digest()
    current_lineage: tuple[str, ...] = ()

    # 2. Re-trace each caveat and assert lineage accumulator
    for caveat in token.caveats:
        current_id = hmac.new(current_sig, b"lineage_id", hashlib.sha256).hexdigest()
        current_lineage = current_lineage + (current_id,)
        lineage_digest = LineageToken._compute_lineage_digest(current_lineage)
        caveat_payload = caveat.canonical_bytes() + lineage_digest
        current_sig = hmac.new(current_sig, caveat_payload, hashlib.sha256).digest()

    return hmac.compare_digest(current_sig, token.signature)


class CascadingRevocationRegistry:
    """Thread-safe revocation manager with O(depth) cascading subtree invalidation."""

    def __init__(self) -> None:
        self._revoked_ids: dict[str, str] = {}
        self._lock = threading.RLock()

    def revoke(self, token_id: str, reason: str = "revoked by admin") -> None:
        """Revokes a specific token ID."""
        with self._lock:
            self._revoked_ids[token_id] = reason

    def check_token(self, token: LineageToken) -> tuple[bool, Optional[str]]:
        """Verifies if a token or any of its ancestors is revoked."""
        with self._lock:
            if token.token_id in self._revoked_ids:
                return False, f"Token '{token.token_id}' is directly revoked: {self._revoked_ids[token.token_id]}"

            for ancestor_id in token.lineage:
                if ancestor_id in self._revoked_ids:
                    return False, (
                        f"Cascading revocation: Ancestor token '{ancestor_id}' was revoked "
                        f"({self._revoked_ids[ancestor_id]}). Child token '{token.token_id}' is invalid."
                    )

            return True, None
