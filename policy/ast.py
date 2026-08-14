"""VDP L1 — policy AST (DESIGN.md section 2.3).

Immutable by construction: frozen dataclasses, no mutation API, and none will be
added. A changed policy is a NEW policy artifact requiring a NEW human
authorization.

--- The sound half of the liveness defense (DESIGN.md section 2.5) ---

This module has NO class for `eventually`, for response patterns
(`always(p -> eventually q)`), or for any unbounded-obligation form. There is no
constructor that could hold one and no code path that could emit one. A liveness
property therefore cannot be compiled into phi regardless of what the upstream
LLM does. That is unconditional: it is a statement about which types exist, not
about anyone behaving well.

--- Universes and the fail-closed sinks ---

`Policy.verbs` (V) and `Policy.targets` (T) are the finite universes the
abstraction function alpha maps into. Anything outside them becomes a
fail-closed sink symbol and is blocked by the monitor (DESIGN.md section 1.2).

Refinement over DESIGN.md section 1.2: T always contains the sentinel
`NO_TARGET` (the empty string). DESIGN.md derived T from whitelists and
prohibitions alone, but prohibitions name no targets, so a target-less action
(`read_balance`, `check_status`) had no legal symbol and would have been blocked
unconditionally. The shim maps target-less tool calls to NO_TARGET. This widens
T by exactly one element that no whitelist can accidentally contain, because
NO_TARGET is rejected as a whitelist member below.

--- Whitelist scope, stated plainly ---

A whitelist clause constrains only its own verb. A verb with a counter but no
whitelist clause accepts ANY target in T, including targets that appear only in
some other verb's whitelist. That is the policy author's choice, not an
oversight: no whitelist clause means no target restriction on that verb. The
plain-language renderer says so explicitly.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Union

__all__ = [
    "Cap",
    "Clause",
    "CounterDecl",
    "NO_TARGET",
    "Policy",
    "PolicyError",
    "Prohibition",
    "RESERVED_WORDS",
    "Whitelist",
]


class PolicyError(ValueError):
    """A structurally invalid policy. Raised at construction, never later."""


#: Sentinel target for actions that act on no entity. Always a member of T.
NO_TARGET = ""

#: Grammar keywords (DESIGN.md section 2.2, extended by SPEC.md section 2.1a).
#: Cannot be used as verb or counter names, otherwise `render_formal` would
#: emit text that does not re-parse.
RESERVED_WORDS = frozenset(
    {
        "always",
        "and",
        "calls",
        "counter",
        "counting",
        "in",
        "not",
        "over",
        "per",
        "target",
    }
)

_IDENT_RE = re.compile(r"^[a-z][a-z0-9_]*$")

#: Targets are free strings, but control characters would make the audit log and
#: the formal rendering ambiguous to a human reader, so they are rejected.
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")


def _check_ident(value: object, what: str) -> str:
    if not isinstance(value, str):
        raise PolicyError(f"{what} must be a string, got {type(value).__name__}")
    if not _IDENT_RE.match(value):
        raise PolicyError(
            f"{what} {value!r} is not a valid identifier "
            f"(required: lowercase, [a-z][a-z0-9_]*)"
        )
    if value in RESERVED_WORDS:
        raise PolicyError(f"{what} {value!r} is a reserved word")
    return value


def _check_target(value: object) -> str:
    if not isinstance(value, str):
        raise PolicyError(f"target must be a string, got {type(value).__name__}")
    if value == NO_TARGET:
        raise PolicyError(
            "the empty string is the reserved NO_TARGET sentinel and cannot be "
            "named in a whitelist"
        )
    if _CONTROL_RE.search(value):
        raise PolicyError(f"target {value!r} contains a control character")
    return value


def _check_nat(value: object, what: str) -> int:
    # bool is a subclass of int; True would silently become the bound 1.
    if isinstance(value, bool) or not isinstance(value, int):
        raise PolicyError(f"{what} must be an integer, got {type(value).__name__}")
    if value < 0:
        raise PolicyError(f"{what} must be non-negative, got {value}")
    return value


def _freeze_strs(values: object, what: str, check) -> frozenset[str]:
    if isinstance(values, (str, bytes)) or not hasattr(values, "__iter__"):
        raise PolicyError(f"{what} must be a collection of strings")
    return frozenset(check(v) for v in values)


@dataclass(frozen=True, slots=True)
class CounterDecl:
    """`counter <name> over {<verbs>} [per target] [counting calls]` — which
    verbs contribute to which counter, and how.

    Counters are monotone non-decreasing (DESIGN.md section 2.1): no decrement,
    no reset, no time window. That is what keeps Q finite and what makes the
    worst-case analysis in L2 sound.

    `counting`: False (default) means the amount-summing counter DESIGN.md
    describes — each matching action contributes its `amount`. True means a
    CALL-COUNTING counter — each matching action contributes exactly 1,
    regardless of amount. This is the same automaton shape (monotone, bounded,
    q_bad on overflow); only the increment changes. It exists to bound the
    number of times a zero-cost or variable-cost verb (`read_balance`,
    `check_status`) may be called, which an amount-summing counter cannot do —
    a verb with a cap but a zero-amount path is unbounded in call count under
    the amount-summing rule alone.

    `per_target`: False (default) means ONE running total shared across every
    target the counter's verbs touch. True means an INDEPENDENT running total
    PER TARGET — the bound applies to each target separately ("at most $100
    to any ONE recipient" rather than "$100 total across all recipients").
    Still monotone and bounded: T is finite (section 1.2), so this widens Q by
    a finite, known factor (one state dimension per (counter, target) pair)
    rather than making it infinite — see SPEC.md section 2.1b.
    """

    name: str
    verbs: frozenset[str]
    counting: bool = False
    per_target: bool = False

    def __post_init__(self) -> None:
        _check_ident(self.name, "counter name")
        object.__setattr__(
            self,
            "verbs",
            _freeze_strs(self.verbs, "counter verbs", lambda v: _check_ident(v, "verb")),
        )
        if not self.verbs:
            raise PolicyError(f"counter {self.name!r} has an empty verb set")
        if not isinstance(self.counting, bool):
            raise PolicyError(
                f"counter {self.name!r}: counting must be a bool, "
                f"got {type(self.counting).__name__}"
            )
        if not isinstance(self.per_target, bool):
            raise PolicyError(
                f"counter {self.name!r}: per_target must be a bool, "
                f"got {type(self.per_target).__name__}"
            )


@dataclass(frozen=True, slots=True)
class Cap:
    """`always(<counter> <= <bound> [unit])` — a cumulative resource bound.

    `bound` is in MINOR UNITS and is always an integer. `unit` is display-only
    and never affects semantics; the monitor never reads it.
    """

    counter: str
    bound: int
    unit: str | None = None

    def __post_init__(self) -> None:
        _check_ident(self.counter, "counter name")
        _check_nat(self.bound, "cap bound")
        if self.unit is not None:
            _check_ident(self.unit, "unit")


@dataclass(frozen=True, slots=True)
class Whitelist:
    """`always(<verb>(target) -> target in {...})` — memoryless target guard."""

    verb: str
    allowed: frozenset[str]

    def __post_init__(self) -> None:
        _check_ident(self.verb, "verb")
        object.__setattr__(
            self, "allowed", _freeze_strs(self.allowed, "whitelist targets", _check_target)
        )
        if not self.allowed:
            # An empty whitelist is expressible but is a trap: it means the verb
            # can never fire, which the author almost certainly did not intend.
            # `always(not verb)` says that outright and renders honestly.
            raise PolicyError(
                f"whitelist for verb {self.verb!r} is empty; use always(not {self.verb}) "
                f"if you mean to forbid it outright"
            )


@dataclass(frozen=True, slots=True)
class Prohibition:
    """`always(not <verb>)` — memoryless hard prohibition."""

    verb: str

    def __post_init__(self) -> None:
        _check_ident(self.verb, "verb")


Clause = Union[Cap, Whitelist, Prohibition]


@dataclass(frozen=True, slots=True)
class Policy:
    """phi: a conjunction of safety clauses over a declared set of counters.

    Conjunction is closed in the fragment (DESIGN.md section 2.1): an
    intersection of safety properties is a safety property, so composition needs
    no special case here.
    """

    counters: tuple[CounterDecl, ...]
    clauses: tuple[Clause, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "counters", tuple(self.counters))
        object.__setattr__(self, "clauses", tuple(self.clauses))

        for decl in self.counters:
            if not isinstance(decl, CounterDecl):
                raise PolicyError(f"counters must be CounterDecl, got {type(decl).__name__}")
        for clause in self.clauses:
            if not isinstance(clause, (Cap, Whitelist, Prohibition)):
                raise PolicyError(f"unknown clause type {type(clause).__name__}")

        names = [d.name for d in self.counters]
        if len(set(names)) != len(names):
            raise PolicyError("duplicate counter declaration")

        if not self.clauses:
            # An empty phi is technically enforceable (V is empty, so alpha maps
            # every action to the unknown-verb sink and everything blocks), but a
            # human authorizing nothing is a bug, not an intent.
            raise PolicyError("policy has no clauses")

        capped: set[str] = set()
        for cap in self.caps:
            if cap.counter not in names:
                raise PolicyError(f"cap references undeclared counter {cap.counter!r}")
            if cap.counter in capped:
                raise PolicyError(
                    f"counter {cap.counter!r} has more than one cap; state one bound"
                )
            capped.add(cap.counter)

        for decl in self.counters:
            if decl.name not in capped:
                # An uncapped counter contributes state with no bound, so Q would
                # be infinite. Every declared counter must be capped.
                raise PolicyError(f"counter {decl.name!r} is declared but never capped")

        seen_wl: set[str] = set()
        for wl in self.whitelists:
            if wl.verb in seen_wl:
                raise PolicyError(
                    f"verb {wl.verb!r} has more than one whitelist; state one set"
                )
            seen_wl.add(wl.verb)

        seen_pro: set[str] = set()
        for pro in self.prohibitions:
            if pro.verb in seen_pro:
                raise PolicyError(f"verb {pro.verb!r} is prohibited more than once")
            seen_pro.add(pro.verb)

    # --- derived views (all pure, all recomputed; nothing is cached mutably) ---

    @property
    def caps(self) -> tuple[Cap, ...]:
        return tuple(c for c in self.clauses if isinstance(c, Cap))

    @property
    def whitelists(self) -> tuple[Whitelist, ...]:
        return tuple(c for c in self.clauses if isinstance(c, Whitelist))

    @property
    def prohibitions(self) -> tuple[Prohibition, ...]:
        return tuple(c for c in self.clauses if isinstance(c, Prohibition))

    @property
    def verbs(self) -> frozenset[str]:
        """V — the finite verb universe. Anything outside it is blocked."""
        vs: set[str] = set()
        for decl in self.counters:
            vs |= decl.verbs
        for wl in self.whitelists:
            vs.add(wl.verb)
        for pro in self.prohibitions:
            vs.add(pro.verb)
        return frozenset(vs)

    @property
    def targets(self) -> frozenset[str]:
        """T — the finite target universe, always including NO_TARGET."""
        ts: set[str] = {NO_TARGET}
        for wl in self.whitelists:
            ts |= wl.allowed
        return frozenset(ts)

    @property
    def c_max(self) -> int:
        """The largest cap bound in phi. Amounts above it saturate to the sink."""
        return max((c.bound for c in self.caps), default=0)

    def counter_named(self, name: str) -> CounterDecl:
        for decl in self.counters:
            if decl.name == name:
                return decl
        raise KeyError(name)

    def cap_for(self, counter: str) -> Cap | None:
        for cap in self.caps:
            if cap.counter == counter:
                return cap
        return None

    def whitelist_for(self, verb: str) -> Whitelist | None:
        for wl in self.whitelists:
            if wl.verb == verb:
                return wl
        return None

    def is_prohibited(self, verb: str) -> bool:
        return any(p.verb == verb for p in self.prohibitions)

    def counters_for_verb(self, verb: str) -> tuple[CounterDecl, ...]:
        return tuple(d for d in self.counters if verb in d.verbs)

    # --- identity ---

    def to_canonical_obj(self) -> dict:
        """Deterministic, order-preserving plain-data view of phi.

        Sets are emitted sorted so that two equal policies always serialize
        identically. Clause order is preserved because it is part of policy
        equality and of the formal rendering round-trip.
        """
        clauses: list[dict] = []
        for clause in self.clauses:
            if isinstance(clause, Cap):
                clauses.append(
                    {
                        "kind": "cap",
                        "counter": clause.counter,
                        "bound": clause.bound,
                        "unit": clause.unit,
                    }
                )
            elif isinstance(clause, Whitelist):
                clauses.append(
                    {
                        "kind": "whitelist",
                        "verb": clause.verb,
                        "allowed": sorted(clause.allowed),
                    }
                )
            else:
                clauses.append({"kind": "prohibition", "verb": clause.verb})
        return {
            "version": 2,
            "counters": [
                {
                    "name": d.name,
                    "verbs": sorted(d.verbs),
                    "counting": d.counting,
                    "per_target": d.per_target,
                }
                for d in self.counters
            ],
            "clauses": clauses,
        }

    def canonical(self) -> bytes:
        """Canonical JSON: sorted keys, no whitespace, UTF-8, integers only.

        Serialization is not a malleability surface: the same phi always yields
        the same bytes, so `digest()` is a stable identity for the policy
        artifact that L3 tokens and the L4 log chain bind to.
        """
        return json.dumps(
            self.to_canonical_obj(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")

    def digest(self) -> str:
        """policy_hash — SHA-256 of `canonical()`, hex."""
        return hashlib.sha256(self.canonical()).hexdigest()
