"""VDP L3 — scopes as a meet-semilattice (DESIGN.md sections 5.1 and 5.2).

    Field         Domain          Meet          Ordering
    verbs         finite set      intersection  subset
    targets       finite set      intersection  subset
    max_amount    N u {inf}       min           <=
    max_total     N u {inf}       min           <=
    expires_at    N u {inf}       min           <=

Scope ordering is POINTWISE: S <= S' iff every field of S is below the
corresponding field of S'.

--- The monotonicity claim, and why it is unconditional ---

    attenuate(S, C) = S meet C

`meet` is a greatest lower bound, so `S meet C <= S` BY DEFINITION OF MEET, for
EVERY C whatsoever -- including a hostile, malformed, or wider-looking one. A
caveat demanding max_amount = 10**9 meets with a parent's 500 to give 500. There
is no code path in `meet` that can produce a value above the parent's, because
the only operation available is the meet itself: there is no setter, no union,
no max, and no "widen" anywhere in this module.

By induction on delegation depth: S_n = S_0 meet C_1 meet ... meet C_n <= S_0.

THIS IS SET-THEORETIC AND UNCONDITIONAL. It does not depend on HMAC, on the
agent being honest, or on caveat validation. The HMAC chain in `macaroon.py` is
what stops an agent from PRESENTING a scope it was never given; it is not what
makes attenuation narrowing. Those are two different claims resting on two
different things, and only the second one needs a cryptographic assumption.

--- None means TOP, not "missing" ---

`None` in any field means "this field constrains nothing" -- the top of that
field's lattice. It is the identity for meet: meet(x, TOP) = x. That is what
makes a caveat that mentions only one field work correctly: every field it does
not mention is TOP and therefore leaves the parent's value alone.

A TOP field is NOT fail-closed on its own, and this module does not pretend
otherwise. `Scope.root_from_policy` never produces a TOP verbs or targets field,
and `runtime.shim` refuses a root token whose verbs or targets are TOP, so a
capability-naming dimension is always bounded in practice. Enforced there, and
stated here.

--- No clock ---

`expires_at` is an integer Unix epoch second. Nothing in this module reads a
clock: `permits()` takes `now` as an argument. Wall-clock time stays out of the
automaton entirely (DESIGN.md open question 3) and out of this file too, so a
scope decision is reproducible from its inputs alone.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from policy.ast import Policy

__all__ = ["Scope", "ScopeError", "TOP"]

#: Top of every field's lattice: "constrains nothing". Identity for meet.
TOP = None


class ScopeError(ValueError):
    """A structurally invalid scope. Raised at construction, never later."""


def _freeze_names(values: object, what: str) -> frozenset[str] | None:
    if values is TOP:
        return TOP
    if isinstance(values, (str, bytes)) or not hasattr(values, "__iter__"):
        raise ScopeError(f"{what} must be a collection of strings, or None for TOP")
    out: set[str] = set()
    for value in values:
        if not isinstance(value, str):
            raise ScopeError(f"{what} contains {value!r}, which is not a string")
        out.add(value)
    return frozenset(out)


def _check_bound(value: object, what: str) -> int | None:
    if value is TOP:
        return TOP
    # bool subclasses int; True must not silently become the bound 1.
    if isinstance(value, bool) or not isinstance(value, int):
        raise ScopeError(f"{what} must be an integer or None, got {type(value).__name__}")
    if value < 0:
        raise ScopeError(f"{what} must be non-negative, got {value}")
    return value


def _meet_set(a: frozenset[str] | None, b: frozenset[str] | None) -> frozenset[str] | None:
    if a is TOP:
        return b
    if b is TOP:
        return a
    return a & b


def _le_set(a: frozenset[str] | None, b: frozenset[str] | None) -> bool:
    if b is TOP:
        return True  # everything is below TOP
    if a is TOP:
        return False  # TOP is above every proper set
    return a <= b


def _meet_num(a: int | None, b: int | None) -> int | None:
    if a is TOP:
        return b
    if b is TOP:
        return a
    return min(a, b)


def _le_num(a: int | None, b: int | None) -> bool:
    if b is TOP:
        return True
    if a is TOP:
        return False
    return a <= b


@dataclass(frozen=True, slots=True)
class Scope:
    """A point in the scope lattice. Immutable; the only operation is meet.

    Used for both a root scope S_0 and a caveat C_i -- they are the same kind of
    object, which is exactly why `attenuate` is just `meet` and cannot be
    anything else.
    """

    verbs: frozenset[str] | None = TOP
    targets: frozenset[str] | None = TOP
    max_amount: int | None = TOP
    max_total: int | None = TOP
    expires_at: int | None = TOP

    def __post_init__(self) -> None:
        object.__setattr__(self, "verbs", _freeze_names(self.verbs, "verbs"))
        object.__setattr__(self, "targets", _freeze_names(self.targets, "targets"))
        object.__setattr__(self, "max_amount", _check_bound(self.max_amount, "max_amount"))
        object.__setattr__(self, "max_total", _check_bound(self.max_total, "max_total"))
        object.__setattr__(self, "expires_at", _check_bound(self.expires_at, "expires_at"))

    # --- lattice ---

    def meet(self, other: "Scope") -> "Scope":
        """S meet C. The ONLY way to build a derived scope.

        Pointwise greatest lower bound. `meet(S, C) <= S` and `meet(S, C) <= C`
        hold for every pair, unconditionally -- see the module docstring.
        """
        if not isinstance(other, Scope):
            raise ScopeError(f"can only meet with a Scope, got {type(other).__name__}")
        return Scope(
            verbs=_meet_set(self.verbs, other.verbs),
            targets=_meet_set(self.targets, other.targets),
            max_amount=_meet_num(self.max_amount, other.max_amount),
            max_total=_meet_num(self.max_total, other.max_total),
            expires_at=_meet_num(self.expires_at, other.expires_at),
        )

    def is_subset_of(self, other: "Scope") -> bool:
        """S <= S', pointwise. A PARTIAL order: two scopes may be incomparable."""
        if not isinstance(other, Scope):
            raise ScopeError(f"can only compare with a Scope, got {type(other).__name__}")
        return (
            _le_set(self.verbs, other.verbs)
            and _le_set(self.targets, other.targets)
            and _le_num(self.max_amount, other.max_amount)
            and _le_num(self.max_total, other.max_total)
            and _le_num(self.expires_at, other.expires_at)
        )

    @property
    def names_capabilities(self) -> bool:
        """True when neither capability-naming dimension is TOP.

        A root token whose verbs or targets are unrestricted authorizes every
        verb and every target the monitor happens to know. `runtime.shim`
        refuses such a root, which is what keeps the token gate fail-closed on
        the dimensions that name what the agent may do.
        """
        return self.verbs is not TOP and self.targets is not TOP

    # --- the per-action check ---

    def permits(
        self, verb: object, target: object, amount: object, *, now: object = None
    ) -> str | None:
        """Is this action inside the scope? Returns None if yes, else a reason.

        TOTAL: hostile types produce a refusal string, never an exception, so
        the token gate has the same fail-closed shape as the monitor's alpha.

        This checks the action AGAINST THE SCOPE ONLY. `max_total` is cumulative
        and cannot be decided from a single action, so it is not checked here --
        the shim holds the per-token running total. See `runtime.shim`.
        """
        if not isinstance(verb, str):
            return f"verb must be a string, got {type(verb).__name__}"
        if not isinstance(target, str):
            return f"target must be a string, got {type(target).__name__}"
        if isinstance(amount, bool) or not isinstance(amount, int):
            return f"amount must be an integer, got {type(amount).__name__}"
        if amount < 0:
            return f"amount must be non-negative, got {amount}"

        if self.verbs is not TOP and verb not in self.verbs:
            return f"verb {verb!r} is outside this token's scope"
        if self.targets is not TOP and target not in self.targets:
            return f"target {target!r} is outside this token's scope"
        if self.max_amount is not TOP and amount > self.max_amount:
            return (
                f"amount {amount} exceeds this token's per-action limit "
                f"{self.max_amount}"
            )

        if self.expires_at is not TOP:
            # Fail closed: a token that can expire cannot be checked without a
            # clock reading, so a missing one is a refusal rather than a pass.
            if isinstance(now, bool) or not isinstance(now, int):
                return "this token expires, but no integer `now` was supplied"
            if now > self.expires_at:
                return f"token expired at {self.expires_at} (now {now})"

        return None

    # --- construction and identity ---

    @staticmethod
    def root_from_policy(policy: Policy, *, expires_at: int | None = TOP) -> "Scope":
        """The widest scope that phi could ever permit.

        Targets come from T and `max_amount` from the largest cap in phi, so the
        root token can never be wider than the policy the human authorized.

        `max_total` is deliberately left TOP. A cumulative total is TRACE
        HISTORY, and DESIGN.md 5.4 puts trace history in the monitor: a token
        cannot encode "you have already spent 400", and a root token that tried
        to would be duplicating the monitor's counter -- shadowing it, since
        whichever gate is tighter fires first and the other never runs.
        `max_total` exists so a PARENT can hand a child a smaller cumulative
        allowance out of the shared cap, which is a statement about delegation
        rather than about phi.

        Verbs are V MINUS the prohibited ones. V is the universe of verbs NAMED
        anywhere in phi, and a prohibited verb is named there precisely so the
        monitor can refuse it -- including it in the root scope would make the
        token claim an authority the monitor blocks unconditionally. The
        conjunction of the two gates would still be safe, since either one
        blocking is a block, but the token would be describing itself wrongly to
        anyone who read it. The two gates agree at the top instead.
        """
        if not isinstance(policy, Policy):
            raise ScopeError(f"expected a Policy, got {type(policy).__name__}")
        permitted = frozenset(v for v in policy.verbs if not policy.is_prohibited(v))
        return Scope(
            verbs=permitted,
            targets=policy.targets,
            max_amount=policy.c_max,
            max_total=TOP,
            expires_at=expires_at,
        )

    def to_obj(self) -> dict:
        """Plain-data view. Sets are sorted; TOP is null. Order is deterministic."""
        return {
            "verbs": None if self.verbs is TOP else sorted(self.verbs),
            "targets": None if self.targets is TOP else sorted(self.targets),
            "max_amount": self.max_amount,
            "max_total": self.max_total,
            "expires_at": self.expires_at,
        }

    @staticmethod
    def from_obj(obj: object) -> "Scope":
        """Rebuild a scope from plain data. STRICT: this parses hostile input.

        Unknown keys are an error rather than being ignored, because a silently
        dropped field is how a scope ends up wider than the bytes that were
        signed.
        """
        if not isinstance(obj, dict):
            raise ScopeError(f"scope must be an object, got {type(obj).__name__}")
        allowed = {"verbs", "targets", "max_amount", "max_total", "expires_at"}
        extra = set(obj) - allowed
        if extra:
            raise ScopeError(f"scope has unknown key(s) {sorted(extra)}")
        return Scope(
            verbs=obj.get("verbs"),
            targets=obj.get("targets"),
            max_amount=obj.get("max_amount"),
            max_total=obj.get("max_total"),
            expires_at=obj.get("expires_at"),
        )

    def canonical(self) -> bytes:
        """Canonical JSON: sorted keys, no whitespace, integers only.

        The HMAC chain signs exactly these bytes, so serialization must not be a
        malleability surface: one scope, one byte string, always.
        """
        return json.dumps(
            self.to_obj(), sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")

    def describe(self) -> str:
        """One line a human can read. Reporting only; nothing decides on this."""
        verbs = "any" if self.verbs is TOP else ",".join(sorted(self.verbs)) or "none"
        if self.targets is TOP:
            targets = "any"
        else:
            named = sorted(t for t in self.targets if t)
            targets = ",".join(named) or "none"
        return (
            f"verbs={verbs} targets={targets} "
            f"max_amount={'unbounded' if self.max_amount is TOP else self.max_amount} "
            f"max_total={'unbounded' if self.max_total is TOP else self.max_total} "
            f"expires_at={'never' if self.expires_at is TOP else self.expires_at}"
        )
