"""VDP L2 — worst-case preview by reachability over A_phi (DESIGN.md section 4).

Computed over ALL traces the monitor would allow -- never over predicted agent
behavior. The human authorizes a number they have seen computed, not a promise
they have been given.

--- L_max ---

Continuous case (the normal one for payments): the agent may choose any integer
amount, so every value 0..N_i is reachable and L_max(i) = N_i.

Discrete case: when the shim's mapping table fixes a finite set of per-action
costs D_i, L_max(i) = max{ sum x_j*d_j : x_j in N, sum x_j*d_j <= N_i }. This is
unbounded-knapsack reachability, solved exactly by a DP over 0..N_i in
O(N_i * |D_i|). It can be strictly LESS than N_i: with D = {300} and N = 500,
L_max = 300, and the human should be told 300.

The result records which case applied, because "<= 500 because that is your cap"
and "<= 300 because nothing you allow adds up past it" are different facts, and
the second is fragile -- it changes if the mapping table changes.

--- The honesty rule ---

Every verb in V appears in the preview. A verb with no cap is UNBOUNDED IN
COUNT and says so. A verb that has a cap is still unbounded in COUNT whenever a
zero-cost call is allowed -- the cap bounds the total, not the number of calls,
and the preview states that distinction rather than letting the reader assume
a cap implies a call limit. Silently omitting an unbounded dimension would be
the single most misleading thing this system could do.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping

from policy.ast import NO_TARGET, Policy
from policy.render import format_amount

from monitor.automaton import BAD, Automaton, ConcreteAction

__all__ = ["CounterWorstCase", "WorstCase", "worst_case"]

#: Guard for the discrete DP. Bounds are in minor units, so a large cap with a
#: fixed-cost table can make the DP table big. Above this, the analyzer reports
#: the cap instead of a tighter reachable maximum, and says that it did.
_DP_CELL_LIMIT = 20_000_000


@dataclass(frozen=True, slots=True)
class CounterWorstCase:
    """Worst case for one counter, and the basis on which it was computed."""

    counter: str
    bound: int
    unit: str | None
    l_max: int
    basis: str  # "cap" | "reachable" | "cap (dp skipped: table too large)"

    @property
    def is_tight(self) -> bool:
        """True when nothing the policy allows can add up to the full cap."""
        return self.l_max < self.bound


@dataclass(frozen=True, slots=True)
class WorstCase:
    """Everything bounded, and everything not bounded, under phi."""

    counters: tuple[CounterWorstCase, ...] = ()
    recipient_limits: tuple[tuple[str, int], ...] = ()  # (verb, |W|)
    unrestricted_target_verbs: tuple[str, ...] = ()
    impossible_verbs: tuple[str, ...] = ()
    uncapped_verbs: tuple[str, ...] = ()  # unbounded in count AND in amount
    unbounded_count_verbs: tuple[str, ...] = ()  # capped in total, unlimited calls
    notes: tuple[str, ...] = field(default=())

    def lines(self) -> list[str]:
        """The preview, one fact per line. Passed straight to the gate."""
        out: list[str] = []

        for item in self.counters:
            amount = format_amount(item.l_max, item.unit)
            if item.basis == "reachable" and item.is_tight:
                cap = format_amount(item.bound, item.unit)
                why = f"nothing you allow adds up past it; your cap is {cap}"
            elif item.basis.startswith("cap ("):
                why = item.basis
            else:
                why = "your cap"
            out.append(f"worst case {item.counter} <= {amount} ({why});")

        for verb, count in self.recipient_limits:
            out.append(f"{verb}: limited to {count} target(s);")

        for verb in self.unrestricted_target_verbs:
            out.append(
                f"{verb}: any target named anywhere in this policy "
                f"(no whitelist of its own);"
            )

        for verb in self.impossible_verbs:
            out.append(f"{verb}: impossible;")

        for verb in self.uncapped_verbs:
            out.append(f"{verb}: unlimited number of times, and no amount cap;")

        for verb in self.unbounded_count_verbs:
            out.append(
                f"{verb}: unlimited number of times (the cap bounds the total, "
                f"not the call count);"
            )

        out.extend(self.notes)
        return out


def _validate_cost_model(
    cost_model: Mapping[str, object] | None, policy: Policy
) -> dict[str, frozenset[int]]:
    if cost_model is None:
        return {}
    validated: dict[str, frozenset[int]] = {}
    for verb, costs in cost_model.items():
        if verb not in policy.verbs:
            raise ValueError(
                f"cost model names verb {verb!r}, which is not in the policy"
            )
        if isinstance(costs, (str, bytes)) or not hasattr(costs, "__iter__"):
            raise ValueError(
                f"cost model for {verb!r} must be a collection of integers"
            )
        values = list(costs)
        if not values:
            raise ValueError(f"cost model for {verb!r} is empty")
        for value in values:
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(
                    f"cost model for {verb!r} contains {value!r}; costs must be "
                    f"non-negative integers in minor units"
                )
        validated[verb] = frozenset(values)
    return validated


def _reachable_max(bound: int, costs: frozenset[int]) -> int:
    """Unbounded-knapsack reachability: largest total <= bound.

    Exact, integer-only. Zero costs are skipped because they add nothing to the
    total (they matter for CALL COUNT, which is reported separately).
    """
    usable = sorted(d for d in costs if 0 < d <= bound)
    if not usable:
        return 0
    reachable = bytearray(bound + 1)
    reachable[0] = 1
    best = 0
    for total in range(bound + 1):
        if not reachable[total]:
            continue
        best = total
        for cost in usable:
            nxt = total + cost
            if nxt <= bound:
                reachable[nxt] = 1
    return best


def _verb_is_possible(
    automaton: Automaton, verb: str, costs: frozenset[int] | None
) -> bool:
    """Does ANY symbol with this verb leave q0 without entering q_bad?

    Answered by asking the automaton itself -- alpha then delta -- rather than
    re-deriving the guards, so the preview cannot disagree with enforcement.
    """
    policy = automaton.policy
    whitelist = policy.whitelist_for(verb)
    targets = (
        sorted(whitelist.allowed) if whitelist is not None else sorted(policy.targets)
    )
    if not targets:
        return False

    # In the continuous model the agent may pick any integer, and 0 is always
    # available, so a single zero-amount probe decides possibility.
    candidate_amounts = [0] if costs is None else sorted(costs)

    for target in targets:
        for amount in candidate_amounts:
            symbol = automaton.alpha(
                ConcreteAction(verb=verb, target=target, amount=amount)
            )
            if automaton.delta(automaton.q0, symbol) is not BAD:
                return True
    return False


def worst_case(
    policy: Policy, cost_model: Mapping[str, object] | None = None
) -> WorstCase:
    """Compute the worst case phi permits.

    `cost_model` maps a verb to the finite set of per-action amounts the shim
    can produce for it. Supplying it enables the discrete DP and can yield a
    tighter, HONEST bound. Omitting it means the agent may choose any integer
    amount, so L_max is the cap itself.
    """
    automaton = Automaton(policy)
    costs = _validate_cost_model(cost_model, policy)

    counters: list[CounterWorstCase] = []
    notes: list[str] = []

    for decl in policy.counters:
        cap = policy.cap_for(decl.name)
        if cap is None:  # unreachable: the AST rejects an uncapped counter
            raise ValueError(f"counter {decl.name!r} has no cap")

        covered = all(verb in costs for verb in decl.verbs)
        if not covered:
            counters.append(
                CounterWorstCase(
                    counter=decl.name,
                    bound=cap.bound,
                    unit=cap.unit,
                    l_max=cap.bound,
                    basis="cap",
                )
            )
            continue

        union: set[int] = set()
        for verb in decl.verbs:
            union |= costs[verb]
        if cap.bound * max(len(union), 1) > _DP_CELL_LIMIT:
            counters.append(
                CounterWorstCase(
                    counter=decl.name,
                    bound=cap.bound,
                    unit=cap.unit,
                    l_max=cap.bound,
                    basis="cap (dp skipped: table too large)",
                )
            )
            continue

        counters.append(
            CounterWorstCase(
                counter=decl.name,
                bound=cap.bound,
                unit=cap.unit,
                l_max=_reachable_max(cap.bound, frozenset(union)),
                basis="reachable",
            )
        )

    recipient_limits: list[tuple[str, int]] = []
    unrestricted: list[str] = []
    impossible: list[str] = []
    uncapped: list[str] = []
    unbounded_count: list[str] = []

    for verb in sorted(policy.verbs):
        verb_costs = costs.get(verb)
        if not _verb_is_possible(automaton, verb, verb_costs):
            impossible.append(verb)
            continue

        whitelist = policy.whitelist_for(verb)
        if whitelist is not None:
            recipient_limits.append((verb, len(whitelist.allowed)))
        else:
            unrestricted.append(verb)

        verb_counters = policy.counters_for_verb(verb)
        if not verb_counters:
            uncapped.append(verb)
        elif verb_costs is None or 0 in verb_costs:
            # A zero-amount call never advances a counter, so the number of
            # calls is unbounded even though the total is capped.
            unbounded_count.append(verb)

    known_targets = sorted(t for t in policy.targets if t != NO_TARGET)
    notes.append(
        f"any target outside these {len(known_targets)} name(s) is blocked: "
        f"{', '.join(known_targets) if known_targets else '(none named)'}"
    )
    if cost_model is None:
        notes.append(
            "amounts were treated as freely chosen integers; if your tools have "
            "fixed prices, supply a cost model for a tighter bound"
        )

    return WorstCase(
        counters=tuple(counters),
        recipient_limits=tuple(recipient_limits),
        unrestricted_target_verbs=tuple(unrestricted),
        impossible_verbs=tuple(impossible),
        uncapped_verbs=tuple(uncapped),
        unbounded_count_verbs=tuple(unbounded_count),
        notes=tuple(notes),
    )
