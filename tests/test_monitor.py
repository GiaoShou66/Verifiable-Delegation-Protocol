"""L2 tests — the automaton, the mediation loop, and the worst-case analyzer.

The load-bearing test here is invariant (a) from DESIGN.md section 8:

    NO ALLOWED PREFIX IS A BAD PREFIX.

It is checked by CROSS-IMPLEMENTATION AGREEMENT. `reference_violates` below
re-evaluates phi straight from the DESIGN.md section 2.1 definitions -- it walks
the clause list, accumulates counters, and compares -- and it shares no code with
`monitor/automaton.py`, which evaluates guards symbolically per symbol. Two
independent implementations, cross-checked over generated hostile traces.

The automaton argument in DESIGN.md section 3.4 is unconditional GIVEN that the
implementation matches the specification. These tests are the only thing standing
between "the proof is right" and "the code implements the thing the proof is
about," so they check the specification's three load-bearing facts directly:
alpha is total, delta is total and deterministic, and q_bad is absorbing.
"""

from __future__ import annotations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from tests.strategies import hostile_actions, policies

from monitor.automaton import (
    BAD,
    BOT_TARGET,
    BOT_VERB,
    Automaton,
    ConcreteAction,
    Symbol,
)
from monitor.mediate import ALLOW, BLOCK, Monitor
from monitor.worstcase import worst_case
from policy.ast import Cap, CounterDecl, NO_TARGET, Policy, Prohibition, Whitelist
from policy.parser import parse

DEMO_TEXT = """
counter spend over {pay}

always(spend <= 50000 cents)
and always(pay(target) -> target in {"alice_utility", "bob_pharmacy", "carol_grocer"})
and always(not delete_account)
"""


def demo_policy() -> Policy:
    return parse(DEMO_TEXT)


# --------------------------------------------------------------------------
# the independent reference checker
# --------------------------------------------------------------------------


#: The single dimension a GLOBAL counter keeps, standing in for section 3.2's
#: `slot(i, target) = *`. Not a string, so it cannot collide with any target.
_GLOBAL = object()


def reference_violates(policy: Policy, actions) -> bool:
    """Does this trace violate phi? Evaluated directly from DESIGN.md 2.1.

    Deliberately written in a different shape from `Automaton.delta`: it loops
    over `policy.clauses`, accumulates every counter first and compares
    afterwards, and re-derives the well-formedness conditions of section 1.2
    inline. It imports nothing from `monitor`. If this and the automaton ever
    disagree, one of them is wrong and the property test says so.

    Covers both counter modes from spec revision 0.3 (sections 2.1a
    call-counting, 2.1b per-target). It previously modelled only the
    amount-summing global case -- which was invisible because `policies()`
    never generated the other three combinations either, so SPEC.md section
    3.4's independent-checker obligation was being met for vdp-spec-0.2
    policies only.
    """
    # {counter name: {target or _GLOBAL: running total}}. A global counter
    # keeps exactly one entry; a per-target counter keeps one per target it
    # has actually seen, which is bounded because T is finite (section 1.2).
    totals: dict[str, dict] = {decl.name: {} for decl in policy.counters}

    for action in actions:
        # Section 1.2 -- the conditions under which alpha yields a sink symbol.
        if not isinstance(action.verb, str) or action.verb not in policy.verbs:
            return True
        if not isinstance(action.target, str) or action.target not in policy.targets:
            return True
        if isinstance(action.amount, bool) or not isinstance(action.amount, int):
            return True
        if action.amount < 0 or action.amount > policy.c_max:
            return True

        # Section 2.1 -- the memoryless clauses.
        for clause in policy.clauses:
            if isinstance(clause, Prohibition) and clause.verb == action.verb:
                return True
            if (
                isinstance(clause, Whitelist)
                and clause.verb == action.verb
                and action.target not in clause.allowed
            ):
                return True

        # Section 2.1 -- monotone cumulative counters, in all four
        # combinations of the two independent flags (sections 2.1a, 2.1b):
        #
        #   counting=False  contributes `amount`  |  counting=True   contributes 1
        #   per_target=False one running total    |  per_target=True one per target
        #
        # Written from the spec text, not from `Automaton.delta`: a per-target
        # counter is modelled here as a dict keyed by target, where the
        # automaton allocates a flat state slot per (counter, target). If the
        # two ever disagree, the property test says so -- which is the whole
        # point of keeping this checker shaped differently.
        for decl in policy.counters:
            if action.verb in decl.verbs:
                key = action.target if decl.per_target else _GLOBAL
                step = 1 if decl.counting else action.amount
                totals[decl.name][key] = totals[decl.name].get(key, 0) + step
        for clause in policy.clauses:
            if isinstance(clause, Cap) and any(
                total > clause.bound for total in totals[clause.counter].values()
            ):
                return True

    return False


# --------------------------------------------------------------------------
# alpha: total, and fail-closed on every input class in section 1.2
# --------------------------------------------------------------------------


def test_alpha_maps_a_well_formed_action_to_itself():
    automaton = Automaton(demo_policy())
    symbol = automaton.alpha(ConcreteAction("pay", "alice_utility", 100))
    assert symbol == Symbol(verb="pay", target="alice_utility", amount=100)
    assert not symbol.is_sink


@pytest.mark.parametrize(
    "action",
    [
        ConcreteAction("transfer", "alice_utility", 1),  # verb not in V
        ConcreteAction("pay", "mallory", 1),  # target not in T
        ConcreteAction("pay", "alice_utility ", 1),  # near-miss target
        ConcreteAction("pay", "ALICE_UTILITY", 1),
        ConcreteAction("pay", "alice_utility", -1),  # negative
        ConcreteAction("pay", "alice_utility", 50001),  # above every bound
        ConcreteAction("pay", "alice_utility", 1.5),  # float
        ConcreteAction("pay", "alice_utility", True),  # bool is not an amount
        ConcreteAction("pay", "alice_utility", None),
        ConcreteAction("pay", "alice_utility", "100"),
        ConcreteAction(None, "alice_utility", 1),
        ConcreteAction(42, "alice_utility", 1),
        ConcreteAction("pay", 42, 1),
        ConcreteAction("pay", None, 1),
    ],
)
def test_fail_closed_classes_all_block(action):
    """Every malformed input class in DESIGN.md 1.2 blocks. Obligation (d)."""
    monitor = Monitor(demo_policy())
    result = monitor.submit(action)
    assert result.decision == BLOCK
    assert monitor.state == (0,)


def test_alpha_never_raises_on_hostile_input():
    automaton = Automaton(demo_policy())
    for junk in [object(), b"pay", [], {}, 3 + 4j]:
        symbol = automaton.alpha(ConcreteAction(junk, junk, junk))
        assert symbol.is_sink


def test_sinks_cannot_be_spelled_by_an_agent():
    """The sink markers are not valid verbs or targets, so no policy names them
    and no agent can submit one that is treated as real."""
    automaton = Automaton(demo_policy())
    for verb, target in [(BOT_VERB, "alice_utility"), ("pay", BOT_TARGET)]:
        assert automaton.alpha(ConcreteAction(verb, target, 0)).is_sink


def test_target_less_action_uses_the_no_target_sentinel():
    phi = parse("counter spend over {ping}\nalways(spend <= 10)")
    automaton = Automaton(phi)
    symbol = automaton.alpha(ConcreteAction("ping", NO_TARGET, 0))
    assert not symbol.is_sink
    assert automaton.delta(automaton.q0, symbol) == (0,)


# --------------------------------------------------------------------------
# delta: total, deterministic, absorbing
# --------------------------------------------------------------------------


def test_q_bad_is_absorbing():
    automaton = Automaton(demo_policy())
    good = automaton.alpha(ConcreteAction("pay", "alice_utility", 1))
    assert automaton.delta(BAD, good) is BAD


def test_delta_is_deterministic():
    automaton = Automaton(demo_policy())
    symbol = automaton.alpha(ConcreteAction("pay", "alice_utility", 7))
    first = automaton.delta((3,), symbol)
    for _ in range(5):
        assert automaton.delta((3,), symbol) == first


def test_delta_rejects_a_state_from_another_automaton():
    automaton = Automaton(demo_policy())
    symbol = automaton.alpha(ConcreteAction("pay", "alice_utility", 1))
    with pytest.raises(ValueError):
        automaton.delta((0, 0), symbol)


def test_guards_are_a_disjunction_not_a_precedence_chain():
    """An action that trips several guards at once still lands in q_bad."""
    phi = parse(
        """
        counter spend over {pay}
        always(spend <= 10)
        and always(pay(target) -> target in {"alice"})
        and always(not pay)
        """
    )
    automaton = Automaton(phi)
    symbol = automaton.alpha(ConcreteAction("pay", "alice", 5))
    assert automaton.delta(automaton.q0, symbol) is BAD


# --------------------------------------------------------------------------
# mediation: the demo scenario, concretely
# --------------------------------------------------------------------------


def test_allowed_payments_advance_the_counter():
    monitor = Monitor(demo_policy())
    assert monitor.submit(ConcreteAction("pay", "alice_utility", 20000)).decision == ALLOW
    assert monitor.state == (20000,)
    assert monitor.submit(ConcreteAction("pay", "bob_pharmacy", 15000)).decision == ALLOW
    assert monitor.state == (35000,)
    assert monitor.remaining() == {"spend": 15000}


def test_the_cap_blocks_and_the_state_does_not_move():
    monitor = Monitor(demo_policy())
    monitor.submit(ConcreteAction("pay", "alice_utility", 49999))
    result = monitor.submit(ConcreteAction("pay", "alice_utility", 2))
    assert result.decision == BLOCK
    assert monitor.state == (49999,)
    assert "over its cap" in result.reason
    # The monitor is not poisoned by a refusal: a payment that still fits works.
    assert monitor.submit(ConcreteAction("pay", "alice_utility", 1)).decision == ALLOW
    assert monitor.state == (50000,)


def test_splitting_a_payment_does_not_defeat_the_cap():
    """Obligation: the counter is cumulative, so salami-slicing hits the same wall."""
    monitor = Monitor(demo_policy())
    allowed = 0
    for _ in range(1000):
        result = monitor.submit(ConcreteAction("pay", "alice_utility", 100))
        if result.decision == ALLOW:
            allowed += 100
    assert allowed == 50000
    assert monitor.state == (50000,)


def test_hammering_with_refused_actions_never_advances_the_state():
    """A hostile agent cannot drive the monitor toward a bound with blocks."""
    monitor = Monitor(demo_policy())
    for _ in range(200):
        assert monitor.submit(ConcreteAction("pay", "mallory", 40000)).decision == BLOCK
    assert monitor.state == (0,)
    assert monitor.submit(ConcreteAction("pay", "alice_utility", 50000)).decision == ALLOW


def test_prohibition_blocks_regardless_of_target_or_amount():
    monitor = Monitor(demo_policy())
    # "anything" is not in T, so it blocks on the unknown-target sink before the
    # prohibition guard is reached. Both are blocks; only the wording differs.
    for target in ["alice_utility", NO_TARGET, "anything"]:
        for amount in [0, 1, 50000]:
            assert (
                monitor.submit(ConcreteAction("delete_account", target, amount)).decision
                == BLOCK
            )
    result = monitor.submit(ConcreteAction("delete_account", NO_TARGET, 0))
    assert "prohibited outright" in result.reason
    assert monitor.state == (0,)


def test_block_reason_reports_the_guard_that_fired():
    monitor = Monitor(demo_policy())
    monitor.submit(ConcreteAction("pay", "alice_utility", 50000))
    result = monitor.submit(ConcreteAction("pay", "mallory", 1))
    # An unknown target is a sink, so alpha has already erased the whitelist
    # question -- the reason must say that rather than inventing a cap story.
    assert "unknown target" in result.reason


def test_monitor_exposes_no_way_to_set_the_state():
    monitor = Monitor(demo_policy())
    with pytest.raises(AttributeError):
        monitor.state = (50000,)  # type: ignore[misc]
    with pytest.raises(AttributeError):
        monitor.policy = demo_policy()  # type: ignore[misc]
    assert not hasattr(monitor, "__dict__")  # __slots__: no attribute can be added


def test_decision_is_immutable():
    monitor = Monitor(demo_policy())
    result = monitor.submit(ConcreteAction("pay", "alice_utility", 1))
    with pytest.raises(AttributeError):
        result.decision = BLOCK  # type: ignore[misc]


# --------------------------------------------------------------------------
# invariant (a): no allowed prefix is a bad prefix
# --------------------------------------------------------------------------


@settings(max_examples=300)
@given(st.data())
def test_no_allowed_prefix_is_a_bad_prefix(data):
    """Invariant (a), cross-checked against an independent evaluator of phi."""
    phi = data.draw(policies())
    actions = data.draw(st.lists(hostile_actions(phi), max_size=12))

    monitor = Monitor(phi)
    allowed = []
    for action in actions:
        result = monitor.submit(action)
        if result.decision == ALLOW:
            allowed.append(action)
            # Every prefix of the allowed subsequence, not merely the whole of
            # it: bad prefixes are extension-closed, so this is the statement
            # the induction in DESIGN.md 3.4 actually makes.
            assert not reference_violates(phi, allowed)

    assert not reference_violates(phi, allowed)


@settings(max_examples=300)
@given(st.data())
def test_monitor_is_total_and_a_block_never_moves_the_state(data):
    phi = data.draw(policies())
    actions = data.draw(st.lists(hostile_actions(phi), max_size=12))

    monitor = Monitor(phi)
    for action in actions:
        before = monitor.state
        result = monitor.submit(action)  # must not raise, whatever was submitted
        assert result.decision in (ALLOW, BLOCK)
        if result.decision == BLOCK:
            assert monitor.state == before
            assert result.post_state == result.pre_state
        else:
            assert monitor.state == result.post_state
        assert monitor.state is not BAD


@settings(max_examples=200)
@given(st.data())
def test_counters_are_monotone_non_decreasing(data):
    phi = data.draw(policies())
    actions = data.draw(st.lists(hostile_actions(phi), max_size=12))

    monitor = Monitor(phi)
    previous = monitor.state
    for action in actions:
        monitor.submit(action)
        assert all(new >= old for new, old in zip(monitor.state, previous, strict=True))
        previous = monitor.state


@settings(max_examples=200)
@given(st.data())
def test_the_agent_can_never_reach_q_bad(data):
    """q_bad is a verdict about a rejected symbol, never a state the monitor
    occupies. If the monitor could enter it, every later action would block and
    the guarantee would be indistinguishable from a crash."""
    phi = data.draw(policies())
    actions = data.draw(st.lists(hostile_actions(phi), max_size=15))
    monitor = Monitor(phi)
    for action in actions:
        monitor.submit(action)
        assert isinstance(monitor.state, tuple)


# --------------------------------------------------------------------------
# call-counting counters (SPEC.md section 2.1a)
# --------------------------------------------------------------------------


def test_a_counting_counter_advances_by_one_regardless_of_amount():
    """Three calls with amounts 0, 3, 1 -- if this counter summed amount it
    would already be blocked on the third (0+3+1=4 > 3). It is not: a
    counting counter advances by 1 per call, not by amount."""
    phi = parse(
        "counter checks over {check_status} counting calls\nalways(checks <= 3)"
    )
    monitor = Monitor(phi)
    for amount in (0, 3, 1):
        result = monitor.submit(ConcreteAction("check_status", NO_TARGET, amount))
        assert result.decision == ALLOW
    assert monitor.state == (3,)
    # A 4th call of any amount, including 0, is blocked: the counter tracks
    # CALLS, not amount.
    result = monitor.submit(ConcreteAction("check_status", NO_TARGET, 0))
    assert result.decision == BLOCK
    assert monitor.state == (3,)


def test_amount_summing_and_counting_counters_do_not_interfere():
    """Two counters over the same verb: one sums amount, one counts calls."""
    phi = parse(
        """
        counter spend over {pay}
        counter pay_calls over {pay} counting calls
        always(spend <= 1000)
        and always(pay_calls <= 2)
        and always(pay(target) -> target in {"alice"})
        """
    )
    monitor = Monitor(phi)
    r1 = monitor.submit(ConcreteAction("pay", "alice", 100))
    assert r1.decision == ALLOW
    assert monitor.state == (100, 1)
    r2 = monitor.submit(ConcreteAction("pay", "alice", 100))
    assert r2.decision == ALLOW
    assert monitor.state == (200, 2)
    # spend has headroom (200 <= 1000) but pay_calls is exhausted (2/2).
    r3 = monitor.submit(ConcreteAction("pay", "alice", 1))
    assert r3.decision == BLOCK
    assert monitor.state == (200, 2)


# --------------------------------------------------------------------------
# per-target counters (SPEC.md section 2.1b)
# --------------------------------------------------------------------------


def test_per_target_counters_track_each_target_independently():
    """$100 to any ONE recipient. Alice can be paid up to 100 even after Bob
    has already been paid up to 100 -- the bound applies per target, not
    across all of them."""
    phi = parse(
        """
        counter spend over {pay} per target
        always(spend <= 100)
        and always(pay(target) -> target in {"alice", "bob"})
        """
    )
    monitor = Monitor(phi)
    r1 = monitor.submit(ConcreteAction("pay", "alice", 100))
    assert r1.decision == ALLOW
    r2 = monitor.submit(ConcreteAction("pay", "bob", 100))
    assert r2.decision == ALLOW
    # Alice is now exhausted; Bob is a DIFFERENT target and is unaffected.
    r3 = monitor.submit(ConcreteAction("pay", "alice", 1))
    assert r3.decision == BLOCK
    r4 = monitor.submit(ConcreteAction("pay", "bob", 1))
    assert r4.decision == BLOCK  # bob is now exhausted too, independently


def test_per_target_and_global_counters_over_the_same_verb_are_independent():
    phi = parse(
        """
        counter per_recipient over {pay} per target
        counter total over {pay}
        always(per_recipient <= 100)
        and always(total <= 150)
        and always(pay(target) -> target in {"alice", "bob"})
        """
    )
    monitor = Monitor(phi)
    assert monitor.submit(ConcreteAction("pay", "alice", 100)).decision == ALLOW
    # Alice's per-target cap (100) is now exhausted, even though the global
    # total (100/150) has headroom.
    assert monitor.submit(ConcreteAction("pay", "alice", 1)).decision == BLOCK
    # Bob has a fresh per-target allowance, but the GLOBAL total does not:
    # 100 + 51 = 151 > 150.
    assert monitor.submit(ConcreteAction("pay", "bob", 51)).decision == BLOCK
    assert monitor.submit(ConcreteAction("pay", "bob", 50)).decision == ALLOW


def test_describe_state_reports_only_touched_targets():
    phi = parse(
        """
        counter spend over {pay} per target
        always(spend <= 100)
        and always(pay(target) -> target in {"alice", "bob"})
        """
    )
    monitor = Monitor(phi)
    monitor.submit(ConcreteAction("pay", "alice", 40))
    text = monitor.describe_state()
    assert "alice=40" in text
    assert "bob" not in text  # untouched targets are not listed


# --------------------------------------------------------------------------
# worst-case preview
# --------------------------------------------------------------------------


def test_continuous_case_reports_the_cap_itself():
    result = worst_case(demo_policy())
    (spend,) = result.counters
    assert spend.l_max == 50000
    assert spend.basis == "cap"
    assert not spend.is_tight
    assert "worst case spend <= $500.00 (your cap);" in result.lines()


def test_discrete_case_can_be_strictly_tighter_than_the_cap():
    """DESIGN.md 4.1: with D = {300} and N = 500, L_max = 300, and the human
    must be told 300 -- together with the fact that it is fragile."""
    phi = parse(
        """
        counter spend over {pay}
        always(spend <= 500)
        and always(pay(target) -> target in {"alice"})
        """
    )
    result = worst_case(phi, cost_model={"pay": {300}})
    (spend,) = result.counters
    assert spend.l_max == 300
    assert spend.basis == "reachable"
    assert spend.is_tight
    assert "nothing you allow adds up past it" in "\n".join(result.lines())


def test_worst_case_names_recipient_limits_impossibilities_and_unbounded_verbs():
    phi = parse(
        """
        counter spend over {pay}
        always(spend <= 50000 cents)
        and always(pay(target) -> target in {"alice_utility", "bob_pharmacy", "carol_grocer"})
        and always(not delete_account)
        and always(read_balance(target) -> target in {"main_account"})
        """
    )
    lines = "\n".join(worst_case(phi).lines())
    assert "pay: limited to 3 target(s);" in lines
    assert "delete_account: impossible;" in lines
    assert "read_balance: unlimited number of times, and no amount cap;" in lines


def test_a_capped_verb_is_still_unbounded_in_call_count():
    """A cap bounds the total, not the number of calls. Saying otherwise by
    omission would be the most misleading thing this preview could do."""
    lines = "\n".join(worst_case(demo_policy()).lines())
    assert "pay: unlimited number of times (the cap bounds the total" in lines


def test_worst_case_reports_a_counting_counter_in_calls_and_bounds_the_verb():
    phi = parse(
        "counter checks over {check_status} counting calls\nalways(checks <= 7)"
    )
    result = worst_case(phi)
    (checks,) = result.counters
    assert checks.counting is True
    assert checks.basis == "calls"
    assert checks.l_max == 7
    lines = "\n".join(result.lines())
    assert "worst case checks <= 7 call(s)" in lines
    # A call-counted verb is bounded in count, so it must NOT appear in either
    # of the "unlimited" lists -- that would contradict the cap above.
    assert "check_status" not in result.uncapped_verbs
    assert "check_status" not in result.unbounded_count_verbs


def test_worst_case_reports_per_target_cap_with_honest_aggregate():
    """DESIGN.md 4.2's honesty rule, extended to per-target counters: the
    preview must not report only the per-target bound and let the human
    infer a smaller total than the policy actually permits."""
    phi = parse(
        """
        counter spend over {pay} per target
        always(spend <= 10000 cents)
        and always(pay(target) -> target in {"alice", "bob", "carol"})
        """
    )
    result = worst_case(phi)
    (spend,) = result.counters
    assert spend.per_target is True
    assert spend.target_count == 3
    assert spend.l_max == 10000
    assert spend.aggregate_l_max == 30000
    lines = "\n".join(result.lines())
    assert "$100.00 to any ONE target" in lines
    assert "$300.00 in aggregate across 3 target(s)" in lines


def test_worst_case_rejects_a_cost_model_for_a_verb_phi_never_names():
    with pytest.raises(ValueError, match="not in the policy"):
        worst_case(demo_policy(), cost_model={"transfer": {100}})


@pytest.mark.parametrize(
    "costs", [{"pay": []}, {"pay": [-1]}, {"pay": [1.5]}, {"pay": [True]}, {"pay": 5}]
)
def test_worst_case_rejects_a_malformed_cost_model(costs):
    with pytest.raises(ValueError):
        worst_case(demo_policy(), cost_model=costs)


def reference_reachable_max(bound: int, costs) -> int:
    """Reachability by explicit search. Independent of the DP in worstcase.py."""
    usable = [c for c in costs if 0 < c <= bound]
    seen = {0}
    frontier = [0]
    while frontier:
        total = frontier.pop()
        for cost in usable:
            nxt = total + cost
            if nxt <= bound and nxt not in seen:
                seen.add(nxt)
                frontier.append(nxt)
    return max(seen)


@settings(max_examples=150)
@given(
    st.integers(min_value=0, max_value=400),
    st.lists(st.integers(min_value=0, max_value=200), min_size=1, max_size=3, unique=True),
)
def test_discrete_l_max_matches_an_independent_reachability_search(bound, costs):
    phi = Policy(
        counters=(CounterDecl(name="spend", verbs=frozenset({"pay"})),),
        clauses=(
            Cap(counter="spend", bound=bound),
            Whitelist(verb="pay", allowed=frozenset({"alice"})),
        ),
    )
    (spend,) = worst_case(phi, cost_model={"pay": costs}).counters
    assert spend.l_max == reference_reachable_max(bound, costs)


@settings(max_examples=150)
@given(st.data())
def test_no_allowed_trace_exceeds_the_previewed_worst_case(data):
    """The preview must be an UPPER BOUND on every trace the monitor allows.

    This is the claim the human is asked to authorize against, so it is checked
    against the monitor rather than against the analyzer's own reasoning: the
    trace is driven through `Monitor.submit`, and only actions it allowed count.
    """
    bound = data.draw(st.integers(min_value=0, max_value=400))
    costs = data.draw(
        st.lists(
            st.integers(min_value=0, max_value=200), min_size=1, max_size=3, unique=True
        )
    )
    phi = Policy(
        counters=(CounterDecl(name="spend", verbs=frozenset({"pay"})),),
        clauses=(
            Cap(counter="spend", bound=bound),
            Whitelist(verb="pay", allowed=frozenset({"alice"})),
        ),
    )
    (spend,) = worst_case(phi, cost_model={"pay": costs}).counters

    monitor = Monitor(phi)
    amounts = data.draw(st.lists(st.sampled_from(costs), max_size=25))
    for amount in amounts:
        monitor.submit(ConcreteAction("pay", "alice", amount))
    assert monitor.state[0] <= spend.l_max


def test_preview_states_which_targets_are_outside_the_policy_entirely():
    notes = "\n".join(worst_case(demo_policy()).notes)
    assert "any target outside these 3 name(s) is blocked" in notes
    assert "freely chosen integers" in notes
