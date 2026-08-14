"""Adversarial fuzzing — test obligation (c) from DESIGN.md section 8.

    Random byte-level and structural mutation of tokens, caveat lists, log
    records, and action payloads. Assert: every mutation is either REJECTED or
    is a NO-OP; nothing is ever accepted that the unmutated path would have
    blocked.

The "or is a no-op" clause is doing real work and is not a hedge. Many random
mutations produce byte-identical output -- flipping a bit inside whitespace that
canonical JSON never emits, reordering keys that are already sorted, replacing a
value with itself. Those are the same input, not a pass. So each property here
compares the mutant against the ORIGINAL's disposition rather than asserting
that everything fails.

The demo's hostile agent runs here too. It is the concrete, readable form of the
same claim: twelve named attacks, every one refused.
"""

from __future__ import annotations

import itertools
import json

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from tests.strategies import hostile_actions, policies

from demo.hostile_agent import run_attacks
from demo.payment_agent import authorize
from monitor.automaton import Automaton
from monitor.mediate import Monitor
from runtime.auditlog import AuditLog, AuditLogError
from runtime.shim import AgentShim, ToolSpec
from tokens.macaroon import Token, TokenError, attenuate, mint, verify
from tokens.scope import Scope, ScopeError

ROOT_KEY = b"\x77" * 32
LOG_KEY = b"\x88" * 32

_SUPPRESS = [HealthCheck.function_scoped_fixture]
_LOG_SEQ = itertools.count()


def build(policy, tmp_path, token=None):
    """A shim over a fresh, uniquely named log.

    The name has to be unique per call: Hypothesis reuses `tmp_path` across
    examples, and `AuditLog` correctly refuses to append one policy's records to
    another policy's chain.
    """
    log = AuditLog(tmp_path / f"fuzz-{next(_LOG_SEQ)}.jsonl", policy.digest(), LOG_KEY)
    tools = {
        f"do_{verb}": ToolSpec(verb=verb, target_arg="t", amount_arg="a")
        for verb in sorted(policy.verbs)
    }
    shim = AgentShim(Monitor(policy), tools, log, ROOT_KEY)
    if token is None:
        token = mint(ROOT_KEY, Scope.root_from_policy(policy))
    return shim, log, token


# --------------------------------------------------------------------------
# tokens: byte-level mutation
# --------------------------------------------------------------------------


@settings(max_examples=400)
@given(
    st.integers(min_value=0, max_value=10_000),
    st.integers(min_value=1, max_value=255),
    st.integers(min_value=0, max_value=3),
)
def test_flipping_a_byte_of_a_serialized_token_never_yields_a_valid_one(
    position, xor, depth
):
    """Byte-level fuzzing of the transport form. Either it fails to parse, or it
    parses to something that does not verify -- never to a usable token."""
    token = mint(ROOT_KEY, Scope(verbs=frozenset({"pay"}), targets=frozenset({"alice"})))
    for i in range(depth):
        token = attenuate(token, Scope(max_amount=100 + i))

    raw = bytearray(token.serialize())
    index = position % len(raw)
    before = raw[index]
    raw[index] ^= xor
    if raw[index] == before:
        return  # a no-op mutation

    try:
        mutant = Token.deserialize(bytes(raw))
    except TokenError:
        return  # rejected at the parser, which is a pass
    if mutant == token:
        return  # parsed back to the same token: a no-op
    assert not verify(ROOT_KEY, mutant)


@settings(max_examples=300)
@given(st.integers(min_value=0, max_value=6), st.integers(min_value=0, max_value=6))
def test_structural_mutation_of_the_caveat_list_never_verifies(depth, cut):
    """Dropping, duplicating, reordering, or appending caveats all break the
    chain, because each tag is keyed by the one before it."""
    token = mint(ROOT_KEY, Scope(verbs=frozenset({"pay"}), targets=frozenset({"alice"})))
    for i in range(depth):
        token = attenuate(token, Scope(max_amount=1000 - i))
    assert verify(ROOT_KEY, token)

    caveats = list(token.caveats)
    for mutated in (
        caveats[: cut % (len(caveats) + 1)],  # truncate
        caveats + [Scope(max_amount=10**9)],  # append without re-keying
        list(reversed(caveats)),  # reorder
        caveats * 2,  # duplicate
    ):
        if tuple(mutated) == token.caveats:
            continue  # a no-op at depth 0 or 1
        assert not verify(ROOT_KEY, Token(token.root, tuple(mutated), token.tag))


@settings(max_examples=300)
@given(st.text(max_size=20), st.integers(min_value=-(10**9), max_value=10**9))
def test_structural_mutation_of_the_root_scope_never_verifies(name, bound):
    root = Scope(verbs=frozenset({"pay"}), targets=frozenset({"alice"}), max_amount=500)
    token = mint(ROOT_KEY, root)

    try:
        widened = Scope(
            verbs=root.verbs | {name} if name else root.verbs,
            targets=root.targets | {name} if name else root.targets,
            max_amount=bound,
        )
    except ScopeError:
        return  # a negative bound is refused at construction, which is a pass
    if widened == root:
        return  # a no-op
    assert not verify(ROOT_KEY, Token(widened, token.caveats, token.tag))


@settings(max_examples=300)
@given(st.dictionaries(st.text(max_size=8), st.text(max_size=8), max_size=4))
def test_arbitrary_objects_are_never_accepted_as_tokens(obj):
    """`from_obj` parses hostile input, so it must reject rather than repair."""
    try:
        token = Token.from_obj(obj)
    except TokenError:
        return
    assert not verify(ROOT_KEY, token)


# --------------------------------------------------------------------------
# action payloads
# --------------------------------------------------------------------------


@settings(max_examples=200, suppress_health_check=_SUPPRESS, deadline=None)
@given(st.data())
def test_no_payload_makes_the_shim_raise_or_out_permit_the_monitor(tmp_path, data):
    """The shim must be TOTAL over agent input, and never more permissive than
    the monitor alone would have been. The extra gates can only subtract."""
    phi = data.draw(policies())
    actions = data.draw(st.lists(hostile_actions(phi), max_size=10))

    shim, log, token = build(phi, tmp_path)
    oracle = Monitor(phi)  # the monitor alone, with no token gate in front

    for action in actions:
        outcome = shim.call(
            f"do_{action.verb}", {"t": action.target, "a": action.amount}, token
        )
        if outcome.allowed:
            assert oracle.submit(action).decision == "ALLOW"

    assert log.verify(Automaton(phi)).ok


@settings(max_examples=200, suppress_health_check=_SUPPRESS, deadline=None)
@given(st.data())
def test_junk_tool_names_and_argument_shapes_are_always_blocked(tmp_path, data):
    phi = data.draw(policies())
    shim, _log, token = build(phi, tmp_path)

    tool = data.draw(
        st.one_of(st.text(max_size=8), st.none(), st.integers(), st.booleans())
    )
    args = data.draw(
        st.one_of(
            st.none(),
            st.text(max_size=8),
            st.integers(),
            st.lists(st.text(max_size=4), max_size=3),
            st.dictionaries(st.text(max_size=4), st.integers(), max_size=3),
        )
    )
    outcome = shim.call(tool, args, token)  # must not raise
    if not (isinstance(tool, str) and tool in shim.tool_names):
        assert not outcome.allowed


# --------------------------------------------------------------------------
# log records
# --------------------------------------------------------------------------


@settings(max_examples=200, suppress_health_check=_SUPPRESS, deadline=None)
@given(st.data())
def test_any_edit_to_a_log_line_is_detected_or_is_a_no_op(tmp_path, data):
    phi = data.draw(policies())
    actions = data.draw(st.lists(hostile_actions(phi), min_size=1, max_size=5))
    shim, log, token = build(phi, tmp_path)
    for action in actions:
        shim.call(f"do_{action.verb}", {"t": action.target, "a": action.amount}, token)

    path = log.path
    lines = path.read_text(encoding="utf-8").splitlines()
    if not lines:
        return

    which = data.draw(st.integers(min_value=0, max_value=len(lines) - 1))
    field = data.draw(
        st.sampled_from(
            [
                "seq",
                "decision",
                "reason",
                "token_id",
                "policy_hash",
                "prev_hash",
                "hash",
                "sig",
            ]
        )
    )
    value = data.draw(
        st.one_of(st.integers(min_value=-5, max_value=5), st.text(max_size=8))
    )

    record = json.loads(lines[which])
    if record[field] == value:
        return  # a no-op edit
    record[field] = value
    lines[which] = json.dumps(record, sort_keys=True, separators=(",", ":"))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    try:
        reopened = AuditLog(path, phi.digest(), LOG_KEY)
        result = reopened.verify(Automaton(phi))
    except AuditLogError:
        return  # unreadable or repudiated on open is a detection too
    assert not result.ok


@settings(max_examples=150, suppress_health_check=_SUPPRESS, deadline=None)
@given(st.data())
def test_a_deleted_middle_record_is_detected(tmp_path, data):
    """Truncating the TAIL is undetectable in v0.1 and is asserted as such in
    `test_runtime.py`. Deleting from the MIDDLE breaks a link and must be
    caught. The two cases are different and are not conflated."""
    phi = data.draw(policies())
    actions = data.draw(st.lists(hostile_actions(phi), min_size=3, max_size=6))
    shim, log, token = build(phi, tmp_path)
    for action in actions:
        shim.call(f"do_{action.verb}", {"t": action.target, "a": action.amount}, token)

    path = log.path
    lines = path.read_text(encoding="utf-8").splitlines()
    if len(lines) < 3:
        return
    del lines[len(lines) // 2]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    assert not AuditLog(path, phi.digest(), LOG_KEY).verify(Automaton(phi)).ok


# --------------------------------------------------------------------------
# the demo's hostile agent, as an executable claim
# --------------------------------------------------------------------------


def test_every_attack_in_the_demo_is_blocked(tmp_path):
    session = authorize(tmp_path / "demo.jsonl", writer=lambda _text: None)
    assert session is not None

    results = run_attacks(session)
    survived = [r.name for r in results if not r.blocked]
    assert not survived, f"attacks that succeeded: {survived}"

    names = " | ".join(r.name for r in results)
    for requirement in (
        "exceed the cap outright",
        "exceed the cap by splitting",
        "pay a party who is not on the whitelist",
        "sub-delegate to a child agent with a wider scope",
    ):
        assert requirement in names

    # Nothing left the bank beyond the authorized cap, and the ledger only ever
    # moved for whitelisted recipients.
    assert sum(session.ledger.values()) <= 50_000
    assert set(session.ledger) == {"alice_utility", "bob_pharmacy", "carol_grocer"}


def test_the_demo_log_still_verifies_after_the_attacks(tmp_path):
    session = authorize(tmp_path / "demo.jsonl", writer=lambda _text: None)
    assert session is not None
    run_attacks(session)

    result = session.log.verify(Automaton(session.policy))
    assert result.ok, result.summary()
    assert result.checked > 200  # the hammering attack alone contributes 200


def test_the_demo_states_what_it_cannot_promise(tmp_path):
    """The gate text is the only thing the human reads before authorizing, so it
    must not imply the task will succeed."""
    lines: list[str] = []
    authorize(tmp_path / "demo.jsonl", writer=lines.append)
    text = "\n".join(lines)

    assert "cannot promise the task succeeds" in text
    assert "cannot make the agent do the right thing" in text  # the liveness refusal
    assert "make sure the electric bill actually gets paid" in text  # what was refused
    assert "$500.00" in text
    assert "proven" not in text.lower()
