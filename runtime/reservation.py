"""VDP Two-Phase Monitored Reservation Protocol (2PMR).

Addresses Dimension 4 (Transactional Atomicity, In-Doubt States & The No-Rollback Paradox)
and Regulatory Compliance (SWIFT Settlement Invariants, FedNow Atomicity, ISO 20022 2PC).

Hardening & Fixes Applied:
    1. Critical Concurrency Thread-Safety: `TwoPhaseReservationCoordinator` protected
       by reentrant locks (RLock), eliminating TOCTOU double-spend/double-reservation races.
    2. Canonical Serialization: `ReservationTicket` signing payload serialized with
       deterministic JSON, eliminating delimiter collisions.
    3. Memory Leak Prevention: Stale, expired, and settled reservation records older than
       the retention window are actively pruned to prevent unbounded memory growth.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import hashlib
import hmac
import json
import threading
import time
from typing import Mapping, Optional


class ReservationStatus(str, Enum):
    PENDING = "PENDING"
    COMMITTED = "COMMITTED"
    ABORTED = "ABORTED"
    EXPIRED = "EXPIRED"


@dataclass(frozen=True, slots=True)
class ReservationTicket:
    """Cryptographic reservation ticket binding a specific operation to reserved quota."""

    reservation_id: str
    token_id: str
    counter_name: str
    amount: int
    expires_at: float
    signature: str

    def canonical_bytes(self) -> bytes:
        payload = {
            "amount": self.amount,
            "counter_name": self.counter_name,
            "expires_at": round(self.expires_at, 3),
            "reservation_id": self.reservation_id,
            "token_id": self.token_id,
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")

    def verify(self, signing_key: bytes) -> bool:
        expected = hmac.new(signing_key, self.canonical_bytes(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(self.signature, expected)


@dataclass(slots=True)
class ReservationRecord:
    ticket: ReservationTicket
    status: ReservationStatus = ReservationStatus.PENDING
    settled_at: Optional[float] = None
    receipt_data: Optional[str] = None


class TwoPhaseReservationCoordinator:
    """Thread-safe coordinator for 2-Phase Monitored Reservations."""

    def __init__(
        self,
        key: bytes,
        bounds: Mapping[str, int],
        record_retention_seconds: float = 3600.0,
    ) -> None:
        self._key = key
        self._bounds = dict(bounds)
        self._committed: dict[str, int] = {k: 0 for k in bounds}
        self._reserved: dict[str, int] = {k: 0 for k in bounds}
        self._records: dict[str, ReservationRecord] = {}
        self._retention_seconds = record_retention_seconds
        self._lock = threading.RLock()

    def get_balance(self, counter_name: str) -> dict[str, int]:
        with self._lock:
            bound = self._bounds[counter_name]
            committed = self._committed[counter_name]
            reserved = self._reserved[counter_name]
            available = max(0, bound - (committed + reserved))
            return {
                "available": available,
                "bound": bound,
                "committed": committed,
                "reserved": reserved,
            }

    def reserve(
        self,
        token_id: str,
        counter_name: str,
        amount: int,
        ttl_seconds: float = 30.0,
        now: Optional[float] = None,
    ) -> ReservationTicket:
        """Phase 1: Reserve quota. Thread-safe atomic check and allocation."""
        if amount <= 0:
            raise ValueError(f"Reservation amount must be positive, got {amount}")

        with self._lock:
            if counter_name not in self._bounds:
                raise KeyError(f"Unknown counter '{counter_name}'")

            curr_now = time.time() if now is None else now
            self._prune_and_expire_locked(curr_now)

            available = self._bounds[counter_name] - (
                self._committed[counter_name] + self._reserved[counter_name]
            )
            if amount > available:
                raise PermissionError(
                    f"Insufficient quota for '{counter_name}': requested {amount}, available {available}"
                )

            res_id = hashlib.sha256(
                f"{token_id}:{counter_name}:{amount}:{curr_now}:{len(self._records)}".encode("utf-8")
            ).hexdigest()[:24]

            expires_at = curr_now + ttl_seconds
            raw_ticket = ReservationTicket(
                reservation_id=res_id,
                token_id=token_id,
                counter_name=counter_name,
                amount=amount,
                expires_at=expires_at,
                signature="",
            )
            sig = hmac.new(self._key, raw_ticket.canonical_bytes(), hashlib.sha256).hexdigest()
            ticket = ReservationTicket(
                reservation_id=res_id,
                token_id=token_id,
                counter_name=counter_name,
                amount=amount,
                expires_at=expires_at,
                signature=sig,
            )

            self._reserved[counter_name] += amount
            self._records[res_id] = ReservationRecord(ticket=ticket)
            return ticket

    def commit(
        self,
        ticket: ReservationTicket,
        receipt_data: str,
        now: Optional[float] = None,
    ) -> bool:
        """Phase 3a: Commit reserved quota upon confirmed tool execution."""
        if not ticket.verify(self._key):
            raise PermissionError("Invalid reservation ticket signature")

        with self._lock:
            rec = self._records.get(ticket.reservation_id)
            if rec is None or rec.status != ReservationStatus.PENDING:
                return False

            curr_now = time.time() if now is None else now
            if curr_now > ticket.expires_at:
                rec.status = ReservationStatus.EXPIRED
                self._reserved[ticket.counter_name] -= ticket.amount
                return False

            self._reserved[ticket.counter_name] -= ticket.amount
            self._committed[ticket.counter_name] += ticket.amount
            rec.status = ReservationStatus.COMMITTED
            rec.settled_at = curr_now
            rec.receipt_data = receipt_data
            return True

    def abort(
        self,
        ticket: ReservationTicket,
        failure_reason: str,
        now: Optional[float] = None,
    ) -> bool:
        """Phase 3b: Abort reservation on network error or downstream tool failure."""
        if not ticket.verify(self._key):
            raise PermissionError("Invalid reservation ticket signature")

        with self._lock:
            rec = self._records.get(ticket.reservation_id)
            if rec is None or rec.status != ReservationStatus.PENDING:
                return False

            curr_now = time.time() if now is None else now
            self._reserved[ticket.counter_name] -= ticket.amount
            rec.status = ReservationStatus.ABORTED
            rec.settled_at = curr_now
            rec.receipt_data = failure_reason
            return True

    def _prune_and_expire_locked(self, now: float) -> None:
        """Garbage collects expired reservations and prunes old historical records."""
        to_delete: list[str] = []
        for res_id, rec in self._records.items():
            if rec.status == ReservationStatus.PENDING and now > rec.ticket.expires_at:
                rec.status = ReservationStatus.EXPIRED
                self._reserved[rec.ticket.counter_name] -= rec.ticket.amount
            elif rec.status != ReservationStatus.PENDING:
                settled_at = rec.settled_at or rec.ticket.expires_at
                if now - settled_at > self._retention_seconds:
                    to_delete.append(res_id)

        for res_id in to_delete:
            del self._records[res_id]
