"""Cross-layer property tests — the two invariants, driven END TO END.

`test_monitor.py` and `test_tokens.py` establish invariants (a) and (b) against
their own layers. This file establishes them against the thing an agent
actually touches: `AgentShim.call()`, with the token gate, the monitor, the
executor, and the audit log all in the path.

That distinction matters. A layer can be correct while the composition leaks --
by advancing a counter on a refused action, by executing before deciding, or by
logging something other than what was decided. The properties here are stated
over the SHIM's observable behavior, and the reference checker they compare
against is the one from `test_monitor.py`, which knows nothing about any of it.
"""

from __future__ import annotations

import itertools
from itertools import pairwise

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from tests.strategies import hostile_actions, policies, widening_caveats
from tests.test_monitor import reference_violates

from monitor.automaton import Automaton, ConcreteAction
from monitor.mediate import Monitor
from monitor.worstcase import worst_case
from runtime.auditlog import AuditLog
from runtime.shim import AgentShim, ToolSpec
from tokens.macaroon import Token, attenuate, mint
from tokens.scope import Scope

ROOT_KEY = b"\x55" * 32
LOG_KEY = b"\x66" * 32

#: Hypothesis reuses a function-scoped `tmp_path` across examples, so every
#: `build` below has to open a log nobody else will touch. `_LOG_SEQ` makes the
#: filename unique per call -- without it, a second example inherits the first
#: example's chain and its counters, which is exactly the cross-contamination
#: `AuditLog` refuses to allow.
_SUPPRESS = [HealthCheck.function_scoped_fixture]
_LOG_SEQ = itertools.count()


def tools_for(policy) -> dict[str, ToolSpec]:
    """A tool per verb in phi, named so that a tool name is never a verb name.

    That keeps "an unmapped tool cannot impersonate a verb" an honest property
    rather than an accident of naming.
    """
    return {
        f"do_{verb}": ToolSpec(verb=verb, target_arg="t", amount_arg="a")
        for verb in sorted(policy.verbs)
    }


def build(policy, tmp_path, name: str, token: Token | None = None):
    log = AuditLog(
        tmp_path / f"{name}-{next(_LOG_SEQ)}.jsonl", policy.digest(), LOG_KEY
    )
    shim = AgentShim(Monitor(policy), tools_for(policy), log, ROOT_KEY)
    if token is None:
        token = mint(ROOT_KEY, Scope.root_from_policy(policy))
    return shim, log, token


def call_action(shim, token, action: ConcreteAction):
    """Submit a ConcreteAction through the shim as an ordinary tool call."""
    return shim.call(f"do_{action.verb}", {"t": action.target, "a": action.amount}, token)


def counters_of(shim, policy) -> dict[str, int]:
    """The monitor's counter values, recovered from the public headroom view."""
    remaining = shim.remaining()
    return {cap.counter: cap.bound - remaining[cap.counter] for cap in policy.caps}


# --------------------------------------------------------------------------
# invariant (a), end to end
# --------------------------------------------------------------------------


@settings(max_examples=150, suppress_health_check=_SUPPRESS, deadline=None)
@given(st.data())
def test_nothing_the_shim_executes_violates_phi(tmp_path, data):
    """Invariant (a) through the full stack, against an independent checker."""
    phi = data.draw(policies())
    actions = data.draw(st.lists(hostile_actions(phi), max_size=10))
    shim, log, token = build(phi, tmp_path, "a")

    executed: list[ConcreteAction] = []
    for action in actions:
        outcome = call_action(shim, token, action)
        if outcome.allowed:
            executed.append(action)
            assert not reference_violates(phi, executed)

    assert not reference_violates(phi, executed)
    assert log.verify(Automaton(phi)).ok


@settings(max_examples=150, suppress_health_check=_SUPPRESS, deadline=None)
@given(st.data())
def test_a_refused_call_changes_nothing_an_agent_can_observe(tmp_path, data):
    """A block must leave the counter and the token's total alone.

    If a refusal moved either, an agent could burn its allowance by submitting
    actions it knew would fail -- the cheapest attack there is, since a refusal
    costs it nothing.
    """
    phi = data.draw(policies())
    actions = data.draw(st.lists(hostile_actions(phi), max_size=10))
    shim, _log, token = build(phi, tmp_path, "b")

    for action in actions:
        before = (shim.remaining(), shim.spent_under(token))
        outcome = call_action(shim, token, action)
        if not outcome.allowed:
            assert (shim.remaining(), shim.spent_under(token)) == before
            assert outcome.record.pre_state == outcome.record.post_state


@settings(max_examples=100, suppress_health_check=_SUPPRESS, deadline=None)
@given(st.data())
def test_the_worst_case_shown_to_the_human_bounds_every_executed_trace(tmp_path, data):
    """The preview is what the human authorized against, so it must hold over
    the shim's behavior and not merely over the analyzer's own model."""
    phi = data.draw(policies())
    actions = data.draw(st.lists(hostile_actions(phi), max_size=12))
    preview = {c.counter: c.l_max for c in worst_case(phi).counters}

    shim, _log, token = build(phi, tmp_path, "c")
    for action in actions:
        call_action(shim, token, action)

    for name, spent in counters_of(shim, phi).items():
        assert spent <= preview[name]


# --------------------------------------------------------------------------
# invariant (b), end to end
# --------------------------------------------------------------------------


@settings(max_examples=100, suppress_health_check=_SUPPRESS, deadline=None)
@given(st.data())
def test_a_child_token_can_never_do_what_its_parent_could_not(tmp_path, data):
    """The runtime form of invariant (b): allowed(child) is a SUBSET of
    allowed(parent), action by action.

    Two independent shims are used so neither run's monitor state can make the
    other look more restricted than it is. That is the only way to compare the
    TOKENS rather than the histories.
    """
    phi = data.draw(policies())
    caveats = data.draw(st.lists(widening_caveats(), min_size=1, max_size=4))
    actions = data.draw(st.lists(hostile_actions(phi), max_size=8))

    parent = mint(ROOT_KEY, Scope.root_from_policy(phi))
    child = parent
    for caveat in caveats:
        child = attenuate(child, caveat)
    assert child.scope.is_subset_of(parent.scope)

    parent_shim, _p, _pt = build(phi, tmp_path, "parent", parent)
    child_shim, _c, _ct = build(phi, tmp_path, "child", child)

    for action in actions:
        child_outcome = call_action(child_shim, child, action)
        parent_outcome = call_action(parent_shim, parent, action)
        if child_outcome.allowed:
            assert parent_outcome.allowed


@settings(max_examples=100, suppress_health_check=_SUPPRESS, deadline=None)
@given(st.data())
def test_delegation_depth_never_widens_anything(tmp_path, data):
    """Attenuating further can only remove capability, at every depth."""
    phi = data.draw(policies())
    caveats = data.draw(st.lists(widening_caveats(), max_size=5))
    action = data.draw(hostile_actions(phi))

    token = mint(ROOT_KEY, Scope.root_from_policy(phi))
    allowed_at_depth = []
    for caveat in [None, *caveats]:
        if caveat is not None:
            token = attenuate(token, caveat)
        shim, _log, _t = build(phi, tmp_path, f"d{token.depth}", token)
        allowed_at_depth.append(call_action(shim, token, action).allowed)

    # Once a depth refuses the action, no deeper token may accept it.
    for shallower, deeper in pairwise(allowed_at_depth):
        assert shallower or not deeper


# --------------------------------------------------------------------------
# the log is a faithful record of what happened
# --------------------------------------------------------------------------


@settings(max_examples=100, suppress_health_check=_SUPPRESS, deadline=None)
@given(st.data())
def test_the_log_replays_to_the_same_decisions_for_any_hostile_trace(tmp_path, data):
    phi = data.draw(policies())
    actions = data.draw(st.lists(hostile_actions(phi), max_size=10))
    shim, log, token = build(phi, tmp_path, "log")

    for action in actions:
        call_action(shim, token, action)

    # Every attempt appears, allowed or not. A log that recorded only successes
    # would be a record of nothing worth auditing.
    records = log.records()
    assert len(records) == len(actions)
    assert log.verify(Automaton(phi)).ok

    replayed = Automaton(phi).q0
    for record in records:
        if record.decision == "ALLOW":
            assert list(replayed) == list(record.pre_state)
            replayed = tuple(record.post_state)

    names = [decl.name for decl in phi.counters]
    assert dict(zip(names, replayed, strict=True)) == counters_of(shim, phi)
