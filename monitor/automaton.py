"""VDP L2 — the deterministic bad-prefix automaton A_phi (DESIGN.md section 3).

    A_phi = (Q, Sigma, delta, q0, F_bad)

    Q     = ({0..N_1} x ... x {0..N_k}) union {q_bad}
    q0    = (0, ..., 0)
    F_bad = {q_bad}, absorbing

Runtime state is the tuple of counter valuations -- a few machine words. |Q| is
large but is NEVER enumerated: delta is evaluated symbolically per symbol. That
is a representation choice and does not change the automaton's semantics.

--- What is unconditional here ---

delta is total and deterministic, alpha is total, and q_bad is absorbing. Those
three facts are what the induction in DESIGN.md section 3.4 rests on, and they
rest on no cryptographic assumption whatsoever. `tests/test_monitor.py` checks
them against a reference checker written independently of this file.

--- Fail closed ---

alpha maps anything it does not recognize to a sink symbol: an unknown verb, an
unknown target, a negative or non-integer amount, or an amount larger than any
bound in phi. Every sink transitions straight to q_bad. There is no code path in
which an unmappable action is allowed. `attrs` is carried for the audit log and
the executor and is INVISIBLE to delta -- anything that must affect a decision
has to be lifted into verb, target, or amount by the shim's mapping table.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping, Union

from policy.ast import NO_TARGET, Policy

__all__ = [
    "BAD",
    "Automaton",
    "BOT_TARGET",
    "BOT_VERB",
    "ConcreteAction",
    "State",
    "Symbol",
    "TOP_AMOUNT",
]


#: Fail-closed sinks. Deliberately not valid identifiers and not valid targets,
#: so no policy can name them and no agent can spell one that is treated as real.
BOT_VERB = "<unknown-verb>"
BOT_TARGET = "<unknown-target>"
TOP_AMOUNT = -1  # stands for the out-of-range amount class; never a real amount


@dataclass(frozen=True, slots=True)
class ConcreteAction:
    """A normalized agent tool call, before abstraction.

    `amount` is a non-negative integer in MINOR UNITS. Never a float. Actions
    with no resource cost carry amount 0. Nothing here is validated at
    construction: this type must be able to hold whatever a hostile agent
    submitted, so that alpha -- not the constructor -- is the thing that decides
    what it means. Rejecting at construction would move the fail-closed decision
    out of the automaton and into an exception path.
    """

    verb: object
    target: object = NO_TARGET
    amount: object = 0
    attrs: Mapping[str, object] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class Symbol:
    """An element of Sigma: an abstracted action the automaton can read."""

    verb: str
    target: str
    amount: int

    @property
    def is_sink(self) -> bool:
        return (
            self.verb == BOT_VERB
            or self.target == BOT_TARGET
            or self.amount == TOP_AMOUNT
        )

    def __str__(self) -> str:
        return f"{self.verb}({self.target!r}, {self.amount})"


class _Bad:
    """The absorbing bad state, q_bad. A singleton, distinct from any valuation."""

    __slots__ = ()

    def __repr__(self) -> str:
        return "q_bad"

    def __reduce__(self):
        return (_bad_singleton, ())


def _bad_singleton() -> "_Bad":
    return BAD


BAD = _Bad()

#: A state is either a tuple of counter valuations (aligned with
#: `Policy.counters` order) or the absorbing q_bad.
State = Union[tuple[int, ...], _Bad]


class Automaton:
    """A_phi for a fixed policy. Constructed once; never mutated.

    The agent has no reference to this object in a correct deployment -- the
    shim holds it. It exposes no mutation API, and `policy` is a frozen
    dataclass, so there is nothing to edit even if a reference leaks in-process.
    See DESIGN.md section 7.5 for the honest statement of that limitation.
    """

    __slots__ = ("_policy", "_counter_names", "_counter_verbs", "_bounds", "_q0")

    def __init__(self, policy: Policy) -> None:
        if not isinstance(policy, Policy):
            raise TypeError(f"expected a Policy, got {type(policy).__name__}")
        self._policy = policy
        self._counter_names = tuple(d.name for d in policy.counters)
        self._counter_verbs = tuple(d.verbs for d in policy.counters)
        # The AST guarantees every declared counter has exactly one cap, so this
        # lookup cannot be None. If that ever changes, Q would be unbounded.
        self._bounds = tuple(
            policy.cap_for(d.name).bound for d in policy.counters  # type: ignore[union-attr]
        )
        self._q0: tuple[int, ...] = tuple(0 for _ in policy.counters)

    # --- immutable views ---

    @property
    def policy(self) -> Policy:
        return self._policy

    @property
    def counter_names(self) -> tuple[str, ...]:
        return self._counter_names

    @property
    def bounds(self) -> tuple[int, ...]:
        return self._bounds

    @property
    def q0(self) -> tuple[int, ...]:
        return self._q0

    @staticmethod
    def is_bad(q: State) -> bool:
        return q is BAD

    # --- abstraction ---

    def alpha(self, action: ConcreteAction) -> Symbol:
        """Sigma-abstraction of a concrete action. TOTAL: never raises.

        Every rejection is expressed as a sink symbol rather than an exception,
        so that a hostile input follows exactly the same code path as a benign
        one and lands in q_bad by the ordinary transition rule.
        """
        verb = action.verb
        if not isinstance(verb, str) or verb not in self._policy.verbs:
            verb_sym = BOT_VERB
        else:
            verb_sym = verb

        target = action.target
        if not isinstance(target, str) or target not in self._policy.targets:
            target_sym = BOT_TARGET
        else:
            target_sym = target

        amount = action.amount
        if isinstance(amount, bool) or not isinstance(amount, int):
            amount_sym = TOP_AMOUNT
        elif amount < 0 or amount > self._policy.c_max:
            # Saturation at C_max is what keeps Sigma finite. An amount above
            # every bound in phi cannot be part of any allowed trace anyway.
            amount_sym = TOP_AMOUNT
        else:
            amount_sym = amount

        return Symbol(verb=verb_sym, target=target_sym, amount=amount_sym)

    # --- transition ---

    def delta(self, q: State, symbol: Symbol) -> State:
        """delta(q, a). TOTAL and DETERMINISTIC. q_bad is absorbing.

        The guards are a DISJUNCTION, not a precedence chain: any one of them
        firing yields q_bad, and their order here is irrelevant to the result.
        """
        if q is BAD:
            return BAD
        if not isinstance(symbol, Symbol):
            raise TypeError(f"expected a Symbol, got {type(symbol).__name__}")
        if not isinstance(q, tuple) or len(q) != len(self._bounds):
            raise ValueError("state does not belong to this automaton")

        # Fail-closed sinks (DESIGN.md section 1.2).
        if symbol.is_sink:
            return BAD

        policy = self._policy

        # Hard prohibition.
        if policy.is_prohibited(symbol.verb):
            return BAD

        # Whitelist violation. A verb with no whitelist clause has no target
        # restriction beyond membership in T, which alpha already enforced.
        whitelist = policy.whitelist_for(symbol.verb)
        if whitelist is not None and symbol.target not in whitelist.allowed:
            return BAD

        # Cap. Counters are monotone non-decreasing, so a single comparison per
        # counter suffices and no history beyond the valuation is needed.
        values = list(q)
        for i, verbs in enumerate(self._counter_verbs):
            if symbol.verb in verbs:
                new_value = values[i] + symbol.amount
                if new_value > self._bounds[i]:
                    return BAD
                values[i] = new_value

        return tuple(values)

    # --- convenience for verification and tests ---

    def run(self, symbols) -> State:
        """Fold delta over a symbol sequence from q0. Used by log replay."""
        q: State = self._q0
        for symbol in symbols:
            q = self.delta(q, symbol)
        return q

    def describe_state(self, q: State) -> str:
        if q is BAD:
            return "q_bad"
        parts = [
            f"{name}={value}/{bound}"
            for name, value, bound in zip(self._counter_names, q, self._bounds)
        ]
        return "(" + ", ".join(parts) + ")" if parts else "()"
