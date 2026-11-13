"""VDP Bilateral Escrow & Sliding-Window Rate Limiting Engine.

Addresses Dimension 1 (Formal Safety & Automata Boundaries) and
Regulatory Compliance (Basel III Liquidity, ISO 20022 Reversals, AML Velocity).

Hardening & Fixes Applied:
    1. Complete Thread-Safety: All state modifications in `BilateralEscrowMonitor` and
       `SlidingWindowRateLimiter` protected by reentrant locks (RLock), eliminating
       TOCTOU concurrency races and double-spend/over-commit vulnerabilities.
    2. Canonical Serialization: `AttestedReversalProof` uses deterministic JSON
       encoding to eliminate delimiter injection vulnerabilities.
    3. Clock-Drift & Anti-Replay: Proof verification validates against a maximum
       acceptable timestamp drift window and tracks processed transaction IDs atomically.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import hmac
import json
import threading
import time
from typing import Mapping, Optional


@dataclass(frozen=True, slots=True)
class AttestedReversalProof:
    """Cryptographically signed reversal/refund proof from a clearing authority.
    
    Conforms to ISO 20022 camt.056 (Payment Return) / pacs.004 (Payment Return).
    """

    tx_id: str
    counter_name: str
    amount: int
    issuer: str
    timestamp: float
    signature: str

    def canonical_bytes(self) -> bytes:
        payload = {
            "amount": self.amount,
            "counter_name": self.counter_name,
            "issuer": self.issuer,
            "timestamp": round(self.timestamp, 3),
            "tx_id": self.tx_id,
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")

    @classmethod
    def create(
        cls,
        tx_id: str,
        counter_name: str,
        amount: int,
        issuer: str,
        signing_key: bytes,
        timestamp: Optional[float] = None,
    ) -> "AttestedReversalProof":
        if amount <= 0:
            raise ValueError(f"Reversal amount must be positive, got {amount}")
        ts = time.time() if timestamp is None else timestamp
        payload = {
            "amount": amount,
            "counter_name": counter_name,
            "issuer": issuer,
            "timestamp": round(ts, 3),
            "tx_id": tx_id,
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        sig = hmac.new(signing_key, canonical, hashlib.sha256).hexdigest()
        return cls(
            tx_id=tx_id,
            counter_name=counter_name,
            amount=amount,
            issuer=issuer,
            timestamp=ts,
            signature=sig,
        )

    def verify(self, verifying_key: bytes) -> bool:
        if self.amount <= 0:
            return False
        expected = hmac.new(verifying_key, self.canonical_bytes(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(self.signature, expected)


@dataclass(slots=True)
class EscrowAccountState:
    """Tracks bilateral committed, reserved, and refunded states for a single counter."""

    bound: int
    committed: int = 0
    reserved: int = 0
    refunded: int = 0
    processed_reversal_txs: set[str] = field(default_factory=set)

    @property
    def net_spent(self) -> int:
        return self.committed - self.refunded

    @property
    def available(self) -> int:
        return max(0, self.bound - (self.net_spent + self.reserved))


class BilateralEscrowMonitor:
    """Thread-safe Bilateral Escrow Monitor preserving safety invariants under financial reversals.

    Theorem (Escrow Monotonic Safety):
        For all execution traces, net_spent + reserved <= bound is an inductive invariant.
    """

    def __init__(
        self,
        bounds: Mapping[str, int],
        clearing_authorities: Mapping[str, bytes],
    ) -> None:
        self._states: dict[str, EscrowAccountState] = {
            name: EscrowAccountState(bound=bound) for name, bound in bounds.items()
        }
        self._clearing_authorities = dict(clearing_authorities)
        self._lock = threading.RLock()

    def get_state(self, counter_name: str) -> EscrowAccountState:
        with self._lock:
            if counter_name not in self._states:
                raise KeyError(f"Unknown counter: {counter_name}")
            state = self._states[counter_name]
            # Return snapshot copy
            return EscrowAccountState(
                bound=state.bound,
                committed=state.committed,
                reserved=state.reserved,
                refunded=state.refunded,
                processed_reversal_txs=set(state.processed_reversal_txs),
            )

    def can_spend(self, counter_name: str, amount: int) -> bool:
        if amount < 0:
            return False
        with self._lock:
            state = self._states.get(counter_name)
            if state is None:
                return False
            return state.available >= amount

    def record_spend(self, counter_name: str, amount: int) -> bool:
        """Agent spend: strictly non-negative delta. Increases committed directly."""
        if amount < 0:
            return False
        with self._lock:
            state = self._states.get(counter_name)
            if state is None or state.available < amount:
                return False
            state.committed += amount
            return True

    def apply_reversal(
        self,
        proof: AttestedReversalProof,
        *,
        now: Optional[float] = None,
        max_drift_seconds: float = 300.0,
    ) -> tuple[bool, str]:
        """Apply an external, cryptographically signed reversal proof."""
        with self._lock:
            state = self._states.get(proof.counter_name)
            if state is None:
                return False, f"Unknown counter '{proof.counter_name}'"

            key = self._clearing_authorities.get(proof.issuer)
            if key is None:
                return False, f"Untrusted clearing authority '{proof.issuer}'"

            # Clock drift check
            curr_now = time.time() if now is None else now
            if abs(curr_now - proof.timestamp) > max_drift_seconds:
                return False, (
                    f"Reversal proof timestamp drifted beyond {max_drift_seconds}s "
                    f"(proof: {proof.timestamp}, now: {curr_now})"
                )

            if not proof.verify(key):
                return False, "Invalid reversal signature"

            if proof.tx_id in state.processed_reversal_txs:
                return False, f"Reversal transaction '{proof.tx_id}' already settled (anti-replay)"

            if proof.amount > state.net_spent:
                return False, (
                    f"Reversal amount {proof.amount} exceeds net spent {state.net_spent}"
                )

            state.refunded += proof.amount
            state.processed_reversal_txs.add(proof.tx_id)
            return True, "Reversal successfully applied"


class SlidingWindowRateLimiter:
    """Thread-safe O(1) Time-Slotted Ring Buffer for Anti-Money Laundering (AML) velocity limits."""

    def __init__(self, window_seconds: float, num_slots: int, max_limit: int) -> None:
        if num_slots <= 0 or window_seconds <= 0 or max_limit <= 0:
            raise ValueError("All parameters must be strictly positive")
        self._window_seconds = float(window_seconds)
        self._num_slots = int(num_slots)
        self._slot_duration = self._window_seconds / self._num_slots
        self._max_limit = int(max_limit)

        self._slots: list[int] = [0] * self._num_slots
        self._slot_timestamps: list[float] = [0.0] * self._num_slots
        self._total_in_window: int = 0
        self._lock = threading.Lock()

    def _rotate_locked(self, now: float) -> None:
        """Prunes expired slots."""
        for i in range(self._num_slots):
            slot_time = self._slot_timestamps[i]
            if slot_time > 0 and (now - slot_time) >= self._window_seconds:
                self._total_in_window -= self._slots[i]
                self._slots[i] = 0
                self._slot_timestamps[i] = 0.0

    def record_action(self, amount: int, now: Optional[float] = None) -> bool:
        """Attempts to record action within the sliding window. Returns True if allowed."""
        if amount < 0:
            return False
        current_time = time.time() if now is None else now

        with self._lock:
            self._rotate_locked(current_time)

            if self._total_in_window + amount > self._max_limit:
                return False

            slot_idx = int(current_time / self._slot_duration) % self._num_slots
            slot_epoch_start = current_time - (current_time % self._slot_duration)

            if self._slot_timestamps[slot_idx] < slot_epoch_start:
                self._total_in_window -= self._slots[slot_idx]
                self._slots[slot_idx] = 0

            self._slots[slot_idx] += amount
            self._slot_timestamps[slot_idx] = slot_epoch_start
            self._total_in_window += amount
            return True

    @property
    def current_usage(self) -> int:
        with self._lock:
            self._rotate_locked(time.time())
            return max(0, self._total_in_window)
