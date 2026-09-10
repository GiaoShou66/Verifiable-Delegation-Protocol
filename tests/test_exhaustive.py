"""Exhaustive check of the SPEC.md section 3.4 correctness obligation.

Section 3.4: "for the sequence sigma = a_1 ... a_n of actions the monitor
ALLOWED, no prefix of sigma is a bad prefix of phi." tests/test_properties.py
already checks this with Hypothesis, which SAMPLES the space of policies and
traces -- finding zero counterexamples in a few hundred random draws is
evidence, not proof.

This file instead ENUMERATES. Over a small, fixed alphabet it constructs
EVERY syntactically distinct policy in a grid that exercises all four
counter-mode combinations (SPEC.md sections 2.1a, 2.1b) crossed with every
per-verb clause shape (none, prohibited, or one of three whitelist sizes),
and for each one replays EVERY trace up to length MAX_TRACE_LENGTH over that
alphabet -- not a sample of them. At every single step of every single trace
of every single policy, the automaton's ALLOW/BLOCK decision is compared
against `tests.test_monitor.reference_violates`, the independently-written
checker (imports nothing from `monitor`) the property tests already use.
Because the comparison happens at every prefix, not only at a trace's end,
this is exactly section 3.4's obligation, checked exhaustively rather than
sampled, at the stated bounds.

What is NOT enumerated, and why that is a stated bound rather than a hidden
gap:

- A counter, when one is declared, always covers BOTH verbs in the grid.
  Which verbs a counter covers is a plain membership test in section 3.2
  ("verb in counters[i].verbs"); every trace here already exercises both
  verbs against a counter that covers both, so a bug in that membership
  check would still surface. What this grid does NOT reach is a counter
  covering a PROPER SUBSET of the declared verbs interacting with a trace
  that mixes covered and uncovered verbs -- test_properties.py's Hypothesis
  suite does generate that shape; this file does not duplicate it.
- Well-typed actions only. Totality of `alpha` on hostile input (wrong
  types, non-str verbs, huge ints, ...) is a separate property, already
  covered by test_monitor.py's "alpha: total, and fail-closed" section.
  Mixing that concern into this grid would multiply the enumeration without
  testing anything new about section 3.4 specifically.

Runtime is a real constraint, not an oversight: this file runs on every CI
push. The bounds below (|V|=2, |T|=2, amounts and cap bounds in {0,1,2},
traces up to length 3) were measured at ~1.8 million (policy, trace-prefix)
steps in ~25 seconds on ordinary hardware before being fixed here. Widening
MAX_TRACE_LENGTH, AMOUNTS, or CAP_BOUNDS is a one-line change; it is not
widened by default because CI wall-clock is a cost this repository should
not spend silently.
"""

from __future__ import annotations

import itertools

from monitor.automaton import BAD, Automaton, ConcreteAction
from policy.ast import Cap, CounterDecl, Policy, PolicyError, Prohibition, Whitelist
from policy.render import render_formal
from tests.test_monitor import reference_violates

#: The well-typed alphabet every enumerated policy and trace is built from.
#: Two verbs and two targets are the smallest sizes that let a whitelist
#: meaningfully exclude something (a 1-target universe can only ever whitelist
#: "everything" or "nothing", which would silently skip the interesting case).
VERBS = ("a", "b")
TARGETS = ("x", "y")
AMOUNTS = (0, 1, 2)
CAP_BOUNDS = (0, 1, 2)
MAX_TRACE_LENGTH = 3

#: The five shapes a single verb's clause can take: no clause at all,
#: prohibited outright, or whitelisted to one of the three non-empty subsets
#: of TARGETS. An empty whitelist is not a shape here because Policy already
#: rejects it at construction (section 2.3) -- it is not this grid's job to
#: re-test that rejection, tests/test_policy.py already does.
_CLAUSE_SHAPES = ("none", "prohibited", "wl_x", "wl_y", "wl_xy")


def _counter_configs():
    """Every counter a policy in this grid may declare: none, or one counter
    over BOTH verbs at every (counting, per_target) combination and every cap
    bound -- see the module docstring for why the verb set is fixed rather
    than varied."""
    yield None
    for counting in (False, True):
        for per_target in (False, True):
            for bound in CAP_BOUNDS:
                yield (counting, per_target, bound)


def _clause_for(verb: str, shape: str):
    if shape == "none":
        return None
    if shape == "prohibited":
        return Prohibition(verb=verb)
    if shape == "wl_x":
        return Whitelist(verb=verb, allowed=frozenset({"x"}))
    if shape == "wl_y":
        return Whitelist(verb=verb, allowed=frozenset({"y"}))
    if shape == "wl_xy":
        return Whitelist(verb=verb, allowed=frozenset({"x", "y"}))
    raise AssertionError(f"unknown clause shape {shape!r}")  # pragma: no cover


def enumerate_policies() -> list[Policy]:
    """Every policy in the grid described by the module docstring.

    A combination that would leave a policy with zero clauses (no counter,
    and both verbs left at "none") is skipped rather than constructed and
    caught -- Policy correctly refuses it (section 2.3), and this grid is not
    the place re-testing that refusal belongs.
    """
    policies: list[Policy] = []
    for counter_cfg in _counter_configs():
        for shape_a, shape_b in itertools.product(_CLAUSE_SHAPES, repeat=2):
            counters: list[CounterDecl] = []
            clauses: list[Cap | Whitelist | Prohibition] = []
            if counter_cfg is not None:
                counting, per_target, bound = counter_cfg
                counters.append(
                    CounterDecl(
                        name="c",
                        verbs=frozenset(VERBS),
                        counting=counting,
                        per_target=per_target,
                    )
                )
                clauses.append(Cap(counter="c", bound=bound, unit=None))
            for verb, shape in zip(VERBS, (shape_a, shape_b), strict=True):
                clause = _clause_for(verb, shape)
                if clause is not None:
                    clauses.append(clause)
            if not clauses:
                continue
            try:
                policies.append(Policy(counters=tuple(counters), clauses=tuple(clauses)))
            except PolicyError as exc:  # pragma: no cover -- grid is constructed valid
                raise AssertionError(
                    f"the grid produced an invalid policy it should not have: {exc}"
                ) from exc
    return policies


def enumerate_traces() -> list[tuple[ConcreteAction, ...]]:
    """Every trace of length 0 through MAX_TRACE_LENGTH over the well-typed
    alphabet -- every ordering, every repetition, not a sample."""
    symbols = tuple(
        ConcreteAction(verb=v, target=t, amount=a)
        for v in VERBS
        for t in TARGETS
        for a in AMOUNTS
    )
    traces: list[tuple[ConcreteAction, ...]] = []
    for length in range(MAX_TRACE_LENGTH + 1):
        traces.extend(itertools.product(symbols, repeat=length))
    return traces


def test_enumeration_bounds_are_what_the_docstring_claims():
    """Guards the harness itself: if the grid's shape ever drifts, the
    exhaustive test below would silently exhaust less than it claims to."""
    policies = enumerate_policies()
    traces = enumerate_traces()
    assert len(policies) > 300
    assert len(traces) == sum(12**length for length in range(MAX_TRACE_LENGTH + 1))


def test_exhaustive_no_bad_prefix_over_small_policies():
    """SPEC.md section 3.4, enumerated rather than sampled.

    For every policy in the grid and every trace over the alphabet, replay
    the trace one action at a time. At each step, the automaton's decision
    (does `delta` reach q_bad?) must agree with the independent checker's
    verdict on appending that action to the sequence ALLOWED so far -- the
    exact claim section 3.4 makes, checked at every prefix of every trace.
    """
    policies = enumerate_policies()
    traces = enumerate_traces()
    steps_checked = 0

    for policy in policies:
        automaton = Automaton(policy)
        for trace in traces:
            state = automaton.q0
            executed: list[ConcreteAction] = []
            for action in trace:
                symbol = automaton.alpha(action)
                post = automaton.delta(state, symbol)
                automaton_allows = post is not BAD
                reference_allows = not reference_violates(policy, executed + [action])
                steps_checked += 1
                assert automaton_allows == reference_allows, (
                    f"automaton and reference disagree at step {len(executed)}\n"
                    f"policy:\n{render_formal(policy)}\n"
                    f"executed so far: {executed!r}\n"
                    f"next action: {action!r}\n"
                    f"automaton allows={automaton_allows}, "
                    f"reference allows={reference_allows}"
                )
                if automaton_allows:
                    state = post
                    executed.append(action)

    # Not a magic number: this is what 324 policies x 1885 traces up to
    # length 3 actually produces, measured before this bound was fixed. A
    # drop here means the grid silently shrank; see
    # test_enumeration_bounds_are_what_the_docstring_claims for the same
    # guard stated the other way round.
    assert steps_checked > 1_500_000
