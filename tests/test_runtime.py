"""L4 tests — the shim, the audit log, and the attestation stub.

Two things are being established here.

FIRST, that the shim is a genuine mediator: every tool call goes through both
gates, an unmappable call is blocked rather than passed through, and nothing an
agent can pass raises out of `call()`. An exception escaping the mediation loop
would be a control-flow channel around it.

SECOND, that the log is evidence rather than decoration. `verify(automaton)` is
pure transition checking -- it recomputes delta over every record -- so a log
that verifies is a log whose recorded decisions follow from phi. The tests also
pin the LIMITS: tail truncation is undetectable in v0.1, and there is a test
asserting exactly that, rather than leaving a reader to assume `ok is True`
means "complete".
"""

from __future__ import annotations

import json

import pytest

from monitor.automaton import Automaton, ConcreteAction
from monitor.mediate import Monitor
from policy.parser import parse
from runtime.attest import NullAttestor
from runtime.auditlog import AuditLog, AuditLogError, genesis_hash
from runtime.shim import AgentShim, ShimError, ToolSpec
from tokens.macaroon import attenuate, mint
from tokens.scope import Scope

ROOT_KEY = b"\x33" * 32
LOG_KEY = b"\x44" * 32

DEMO_TEXT = """
counter spend over {pay}

always(spend <= 50000 cents)
and always(pay(target) -> target in {"alice_utility", "bob_pharmacy", "carol_grocer"})
and always(not delete_account)
"""

TOOLS = {
    "pay_bill": ToolSpec(verb="pay", target_arg="recipient", amount_arg="cents"),
    "close_account": ToolSpec(verb="delete_account"),
}


@pytest.fixture
def phi():
    return parse(DEMO_TEXT)


@pytest.fixture
def shim(tmp_path, phi):
    log = AuditLog(tmp_path / "audit.jsonl", phi.digest(), LOG_KEY)
    return AgentShim(
        Monitor(phi), TOOLS, log, ROOT_KEY, executor=lambda name, args: "ok"
    )


@pytest.fixture
def token(phi):
    return mint(ROOT_KEY, Scope.root_from_policy(phi))


def log_of(shim: AgentShim, tmp_path) -> AuditLog:
    """Reopen the log the way an auditor would: from the file, not the shim."""
    return AuditLog(tmp_path / "audit.jsonl", shim.policy_hash, LOG_KEY)


# --------------------------------------------------------------------------
# the shim as a mediator
# --------------------------------------------------------------------------


def test_a_permitted_call_is_executed_and_logged(shim, token):
    outcome = shim.call("pay_bill", {"recipient": "alice_utility", "cents": 20000}, token)
    assert outcome.allowed
    assert outcome.result == "ok"
    assert outcome.error is None
    assert outcome.record.decision == "ALLOW"
    assert outcome.record.post_state == [20000]
    assert shim.remaining() == {"spend": 30000}


def test_both_gates_must_pass(shim, phi):
    """A valid token is necessary, not sufficient: the monitor is independent.

    The token here deliberately carries NO cumulative bound of its own, so the
    only thing left standing between the agent and a second payment is the
    monitor's counter -- which is trace history, and which no token can encode.
    """
    unbounded_total = mint(
        ROOT_KEY,
        Scope(
            verbs=frozenset({"pay"}),
            targets=phi.targets,
            max_amount=phi.c_max,
            max_total=None,
        ),
    )
    assert shim.call(
        "pay_bill", {"recipient": "alice_utility", "cents": 50000}, unbounded_total
    ).allowed
    blocked = shim.call(
        "pay_bill", {"recipient": "alice_utility", "cents": 1}, unbounded_total
    )
    assert not blocked.allowed
    assert "over its cap" in blocked.reason  # the monitor refused, not the token


def test_a_call_with_no_token_is_blocked_before_the_monitor(shim):
    outcome = shim.call("pay_bill", {"recipient": "alice_utility", "cents": 1})
    assert not outcome.allowed
    assert "no capability token" in outcome.reason
    assert shim.remaining() == {"spend": 50000}  # q untouched
    assert outcome.record.pre_state == outcome.record.post_state


def test_a_forged_token_is_blocked(shim, phi):
    outcome = shim.call(
        "pay_bill",
        {"recipient": "alice_utility", "cents": 1},
        mint(b"\x99" * 32, Scope.root_from_policy(phi)),  # minted under a foreign key
    )
    assert not outcome.allowed
    assert "does not verify" in outcome.reason


def test_a_root_token_that_names_nothing_is_refused(shim):
    outcome = shim.call(
        "pay_bill", {"recipient": "alice_utility", "cents": 1}, mint(ROOT_KEY, Scope())
    )
    assert not outcome.allowed
    assert "must name what it authorizes" in outcome.reason


def test_an_attenuated_token_narrows_what_the_same_shim_will_do(shim, token):
    child = attenuate(token, Scope(targets=frozenset({"bob_pharmacy"}), max_amount=100))
    assert shim.call("pay_bill", {"recipient": "bob_pharmacy", "cents": 100}, child).allowed
    denied = shim.call("pay_bill", {"recipient": "alice_utility", "cents": 100}, child)
    assert not denied.allowed
    assert "outside this token's scope" in denied.reason
    too_big = shim.call("pay_bill", {"recipient": "bob_pharmacy", "cents": 101}, child)
    assert "per-action limit" in too_big.reason


def test_max_total_is_enforced_per_token_and_is_cumulative(shim, token):
    child = attenuate(token, Scope(max_total=250))
    args = {"recipient": "alice_utility", "cents": 100}
    assert shim.call("pay_bill", args, child).allowed
    assert shim.call("pay_bill", args, child).allowed
    third = shim.call("pay_bill", args, child)
    assert not third.allowed
    assert "over its max_total" in third.reason
    assert shim.spent_under(child) == 200
    # The parent's own token still works. That is its own authority being used,
    # not an escalation, and VDP does not attempt to prevent it.
    assert shim.call("pay_bill", args, token).allowed


def test_an_expiring_token_needs_a_clock_reading_from_the_caller(shim, phi):
    expiring = mint(ROOT_KEY, Scope.root_from_policy(phi, expires_at=1_000))
    args = {"recipient": "alice_utility", "cents": 1}
    assert not shim.call("pay_bill", args, expiring).allowed  # no `now` supplied
    assert shim.call("pay_bill", args, expiring, now=999).allowed
    assert not shim.call("pay_bill", args, expiring, now=1_001).allowed


@pytest.mark.parametrize(
    "call_args",
    [
        ("no_such_tool", {"recipient": "alice_utility", "cents": 1}),
        (None, {"cents": 1}),
        (42, {}),
        ("pay_bill", None),
        ("pay_bill", "not a mapping"),
        ("pay_bill", {"recipient": "mallory", "cents": 1}),
        ("pay_bill", {"recipient": "alice_utility"}),  # missing amount
        ("pay_bill", {"recipient": "alice_utility", "cents": -1}),
        ("pay_bill", {"recipient": "alice_utility", "cents": 1.5}),
        ("pay_bill", {"recipient": "alice_utility", "cents": True}),
        ("pay_bill", {"recipient": "alice_utility", "cents": "1"}),
        ("pay_bill", {"recipient": "alice_utility", "cents": 50001}),
        ("close_account", {}),
    ],
)
def test_unmappable_or_malformed_calls_are_blocked_not_repaired(shim, token, call_args):
    outcome = shim.call(*call_args, token)  # must not raise, whatever was passed
    assert not outcome.allowed
    assert shim.remaining() == {"spend": 50000}


def test_an_unmapped_tool_named_like_a_verb_cannot_impersonate_it(shim, token):
    """`pay` is a verb in phi but not a tool in the table. It must still block.

    The unmapped call normalizes to `verb=None`, so the token gate refuses it
    first; had it got past that, alpha had already abstracted it to the
    unknown-verb sink, which is what the recorded symbol shows. Either gate
    alone is sufficient, which is the point of them being independent.
    """
    outcome = shim.call("pay", {"recipient": "alice_utility", "cents": 1}, token)
    assert not outcome.allowed
    assert outcome.record.symbol["verb"] == "<unknown-verb>"
    assert outcome.record.action["attrs"]["unmapped_tool"] == "'pay'"
    assert shim.remaining() == {"spend": 50000}


def test_a_tool_mapping_to_a_verb_phi_never_names_is_refused_at_construction(
    tmp_path, phi
):
    log = AuditLog(tmp_path / "a.jsonl", phi.digest(), LOG_KEY)
    with pytest.raises(ShimError, match="which phi never names"):
        AgentShim(Monitor(phi), {"wire": ToolSpec(verb="transfer")}, log, ROOT_KEY)


def test_a_log_opened_under_another_policy_is_refused(tmp_path, phi):
    other = parse("counter spend over {pay}\nalways(spend <= 1)")
    log = AuditLog(tmp_path / "a.jsonl", other.digest(), LOG_KEY)
    with pytest.raises(ShimError, match="different policy"):
        AgentShim(Monitor(phi), TOOLS, log, ROOT_KEY)


def test_an_executor_that_raises_does_not_roll_the_counter_back(tmp_path, phi, token):
    def boom(name, args):
        raise RuntimeError("the bank said no")

    log = AuditLog(tmp_path / "audit.jsonl", phi.digest(), LOG_KEY)
    shim = AgentShim(Monitor(phi), TOOLS, log, ROOT_KEY, executor=boom)
    outcome = shim.call("pay_bill", {"recipient": "alice_utility", "cents": 100}, token)

    assert outcome.allowed  # the DECISION stands; only the execution failed
    assert outcome.error == "RuntimeError: the bank said no"
    assert shim.remaining() == {"spend": 49900}  # under-spends, never over-spends
    assert log.records()[-1].decision == "ALLOW"


def test_the_shim_exposes_no_handle_to_the_monitor_or_the_log(shim):
    assert not hasattr(shim, "__dict__")  # __slots__: no attribute can be added
    for forbidden in ("monitor", "log", "policy", "submit", "automaton"):
        assert not hasattr(shim, forbidden)


def test_the_tool_table_cannot_be_edited_through_the_shim(shim):
    with pytest.raises(TypeError):
        shim._tools["evil"] = ToolSpec(verb="pay")  # MappingProxyType is read-only


# --------------------------------------------------------------------------
# the audit log
# --------------------------------------------------------------------------


def test_every_attempt_is_logged_including_the_blocked_ones(shim, token, tmp_path):
    shim.call("pay_bill", {"recipient": "alice_utility", "cents": 100}, token)
    shim.call("pay_bill", {"recipient": "mallory", "cents": 100}, token)
    shim.call("close_account", {}, token)

    records = log_of(shim, tmp_path).records()
    assert [r.decision for r in records] == ["ALLOW", "BLOCK", "BLOCK"]
    assert [r.seq for r in records] == [0, 1, 2]
    # A block is evidence, not state: the blocked records leave q where it was.
    assert records[1].pre_state == records[1].post_state == [100]


def test_the_log_verifies_by_replaying_the_automaton(shim, token, tmp_path, phi):
    for cents in (100, 200, 49999):
        shim.call("pay_bill", {"recipient": "alice_utility", "cents": cents}, token)
    shim.call("close_account", {}, token)

    result = log_of(shim, tmp_path).verify(Automaton(phi))
    assert result.ok, result.summary()
    assert result.checked == 4
    assert result.tail_truncation_undetectable is True
    assert "tail truncation cannot be detected" in result.summary()


def test_the_chain_binds_the_log_to_one_policy(shim, token, tmp_path, phi):
    shim.call("pay_bill", {"recipient": "alice_utility", "cents": 1}, token)
    records = log_of(shim, tmp_path).records()
    assert records[0].prev_hash == genesis_hash(phi.digest())
    assert records[0].policy_hash == phi.digest()

    other = parse("counter spend over {pay}\nalways(spend <= 1)")
    with pytest.raises(AuditLogError, match="different policy_hash"):
        AuditLog(tmp_path / "audit.jsonl", other.digest(), LOG_KEY)


@pytest.mark.parametrize(
    "field, value",
    [
        ("decision", "ALLOW"),
        ("post_state", [0]),
        ("reason", "within policy"),
        ("token_id", "deadbeef"),
    ],
)
def test_editing_a_record_is_detected(shim, token, tmp_path, phi, field, value):
    shim.call("pay_bill", {"recipient": "alice_utility", "cents": 100}, token)
    shim.call("pay_bill", {"recipient": "mallory", "cents": 100}, token)

    path = tmp_path / "audit.jsonl"
    lines = path.read_text(encoding="utf-8").splitlines()
    tampered = json.loads(lines[1])
    tampered[field] = value
    lines[1] = json.dumps(tampered, sort_keys=True, separators=(",", ":"))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    result = log_of(shim, tmp_path).verify(Automaton(phi))
    assert not result.ok
    assert any("hash does not match" in problem for problem in result.problems)


def test_reordering_records_is_detected(shim, token, tmp_path, phi):
    for cents in (100, 200):
        shim.call("pay_bill", {"recipient": "alice_utility", "cents": cents}, token)
    path = tmp_path / "audit.jsonl"
    lines = path.read_text(encoding="utf-8").splitlines()
    path.write_text("\n".join(reversed(lines)) + "\n", encoding="utf-8")

    result = log_of(shim, tmp_path).verify(Automaton(phi))
    assert not result.ok


def test_a_forged_signature_without_the_log_key_is_detected(shim, token, tmp_path, phi):
    shim.call("pay_bill", {"recipient": "alice_utility", "cents": 100}, token)
    path = tmp_path / "audit.jsonl"
    record = json.loads(path.read_text(encoding="utf-8").strip())
    record["sig"] = "00" * 32
    path.write_text(
        json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )

    result = log_of(shim, tmp_path).verify(Automaton(phi))
    assert not result.ok
    assert any("signature does not verify" in problem for problem in result.problems)


def test_truncating_the_tail_is_not_detected_and_the_result_says_so(
    shim, token, tmp_path, phi
):
    """The documented v0.1 gap (DESIGN.md 6.3). Asserted, not glossed over."""
    for cents in (100, 200, 300):
        shim.call("pay_bill", {"recipient": "alice_utility", "cents": cents}, token)

    path = tmp_path / "audit.jsonl"
    head_before = log_of(shim, tmp_path).head
    lines = path.read_text(encoding="utf-8").splitlines()
    path.write_text(lines[0] + "\n", encoding="utf-8")

    result = log_of(shim, tmp_path).verify(Automaton(phi))
    assert result.ok  # a truncated log is a VALID CHAIN over fewer records
    assert result.checked == 1
    assert result.tail_truncation_undetectable
    # An external anchor for the final hash is the only thing that would have
    # caught this, and v0.1 does not anchor externally.
    assert log_of(shim, tmp_path).head != head_before


def test_the_log_has_no_update_or_delete_method(shim, tmp_path):
    log = log_of(shim, tmp_path)
    for forbidden in ("update", "delete", "truncate", "rewrite", "clear", "pop"):
        assert not hasattr(log, forbidden)


def test_appending_resumes_an_existing_log_rather_than_overwriting_it(
    shim, token, tmp_path, phi
):
    shim.call("pay_bill", {"recipient": "alice_utility", "cents": 100}, token)

    action = ConcreteAction("pay", "alice_utility", 1)
    reopened = log_of(shim, tmp_path)
    reopened.append(
        action=action,
        symbol=Automaton(phi).alpha(action),
        pre_state=(100,),
        post_state=(101,),
        decision="ALLOW",
        reason="within policy",
        token_id="x",
    )
    records = log_of(shim, tmp_path).records()
    assert [r.seq for r in records] == [0, 1]
    assert log_of(shim, tmp_path).verify(Automaton(phi)).ok


def test_a_malformed_line_is_an_error_not_a_skipped_record(shim, token, tmp_path):
    shim.call("pay_bill", {"recipient": "alice_utility", "cents": 100}, token)
    path = tmp_path / "audit.jsonl"
    path.write_text(path.read_text(encoding="utf-8") + "{not json}\n", encoding="utf-8")
    with pytest.raises(AuditLogError):
        log_of(shim, tmp_path).records()


def test_a_short_log_key_is_refused(tmp_path, phi):
    with pytest.raises(AuditLogError, match="at least 32 bytes"):
        AuditLog(tmp_path / "a.jsonl", phi.digest(), b"short")


def test_an_unserializable_payload_is_recorded_rather_than_dropped(shim, token, tmp_path):
    shim.call("pay_bill", {"recipient": object(), "cents": 1}, token)
    record = log_of(shim, tmp_path).records()[0]
    assert record.decision == "BLOCK"
    assert "object object at" in record.action["target"]


# --------------------------------------------------------------------------
# attestation: a stub that claims nothing
# --------------------------------------------------------------------------


def test_the_null_attestor_attests_nothing_and_names_the_limits(
    shim, token, tmp_path, phi
):
    shim.call("pay_bill", {"recipient": "alice_utility", "cents": 1}, token)
    attestation = NullAttestor().attest(log_of(shim, tmp_path).records(), phi)

    assert attestation.attested is False
    assert attestation.evidence == b""
    assert "NOT ATTESTED" in attestation.claim
    assert "truncation" in attestation.claim
    assert "proven" not in attestation.claim.lower()
    assert NullAttestor().verify(attestation) is False
