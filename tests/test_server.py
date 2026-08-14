"""L4 tests — MonitorServer / MonitorClient (SPEC.md section 11).

Establishes that the reference transport binding reproduces the SAME
decisions an in-process AgentShim would, that concurrent connections do not
deadlock (a real bug found by manually running the client and server against
each other before any test existed), and that a hostile client cannot get
anything past the wire that the in-process shim would not also refuse.
"""

from __future__ import annotations

import socket
import threading

import pytest

from monitor.mediate import Monitor
from policy.parser import parse
from runtime.auditlog import AuditLog
from runtime.client import ClientError, MonitorClient
from runtime.server import MonitorServer, ServerError
from runtime.shim import AgentShim, ToolSpec
from tokens.macaroon import mint
from tokens.scope import Scope

ROOT_KEY = b"\x77" * 32
LOG_KEY = b"\x88" * 32

DEMO_TEXT = """
counter spend over {pay}
always(spend <= 100)
and always(pay(target) -> target in {"alice", "bob"})
and always(not delete_account)
"""

TOOLS = {
    "pay_bill": ToolSpec(verb="pay", target_arg="t", amount_arg="a"),
    "close_account": ToolSpec(verb="delete_account"),
}


@pytest.fixture
def phi():
    return parse(DEMO_TEXT)


@pytest.fixture
def running_server(tmp_path, phi):
    log = AuditLog(tmp_path / "audit.jsonl", phi.digest(), LOG_KEY)
    shim = AgentShim(
        Monitor(phi), TOOLS, log, ROOT_KEY, executor=lambda name, args: f"ok:{name}"
    )
    server = MonitorServer(shim, port=0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server
    server.stop()


@pytest.fixture
def token(phi):
    return mint(ROOT_KEY, Scope.root_from_policy(phi))


def connect(server: MonitorServer) -> MonitorClient:
    host, port = server.address
    return MonitorClient(host, port, timeout=5.0)


# --------------------------------------------------------------------------
# the client reproduces the same decisions as the in-process shim
# --------------------------------------------------------------------------


def test_an_allowed_call_round_trips_through_the_wire(running_server, token):
    with connect(running_server) as client:
        outcome = client.call("pay_bill", {"t": "alice", "a": 40}, token)
    assert outcome.allowed
    assert outcome.result == "ok:pay_bill"
    assert outcome.error is None


def test_a_blocked_call_reports_the_same_reason_shape(running_server, token):
    with connect(running_server) as client:
        outcome = client.call("pay_bill", {"t": "mallory", "a": 10}, token)
    assert not outcome.allowed
    assert outcome.gate == "token"
    assert "outside this token's scope" in outcome.reason


def test_the_cap_is_enforced_cumulatively_across_multiple_calls(running_server, token):
    with connect(running_server) as client:
        first = client.call("pay_bill", {"t": "alice", "a": 60}, token)
        second = client.call("pay_bill", {"t": "alice", "a": 60}, token)
    assert first.allowed
    assert not second.allowed
    assert "over its cap" in second.reason


def test_remaining_reflects_calls_made_through_the_wire(running_server, token):
    with connect(running_server) as client:
        client.call("pay_bill", {"t": "alice", "a": 30}, token)
        remaining = client.remaining()
    assert remaining == {"spend": 70}


def test_a_call_with_no_token_is_blocked_same_as_in_process(running_server):
    with connect(running_server) as client:
        outcome = client.call("pay_bill", {"t": "alice", "a": 10}, None)
    assert not outcome.allowed
    assert "no capability token presented" in outcome.reason


def test_the_prohibited_verb_is_blocked_over_the_wire(running_server, token):
    with connect(running_server) as client:
        outcome = client.call("close_account", {}, token)
    assert not outcome.allowed


# --------------------------------------------------------------------------
# what never crosses the wire
# --------------------------------------------------------------------------


def test_the_root_key_never_appears_in_any_response(running_server, token):
    with connect(running_server) as client:
        outcome = client.call("pay_bill", {"t": "alice", "a": 10}, token)
        remaining_resp = client.remaining()
    assert ROOT_KEY.hex() not in repr(outcome)
    assert ROOT_KEY.hex() not in repr(remaining_resp)
    assert LOG_KEY.hex() not in repr(outcome)


# --------------------------------------------------------------------------
# hostile / malformed input over the wire
# --------------------------------------------------------------------------


def test_malformed_json_is_a_protocol_error_not_a_crash(running_server):
    host, port = running_server.address
    raw = socket.create_connection((host, port), timeout=5.0)
    raw.sendall(b"this is not json\n")
    response = raw.makefile("rb").readline()
    raw.close()
    assert b'"ok":false' in response
    assert b"not valid JSON" in response


def test_a_non_object_request_is_a_protocol_error(running_server):
    host, port = running_server.address
    raw = socket.create_connection((host, port), timeout=5.0)
    raw.sendall(b"[1,2,3]\n")
    response = raw.makefile("rb").readline()
    raw.close()
    assert b'"ok":false' in response
    assert b"expected an object" in response


def test_an_unknown_op_is_refused(running_server):
    host, port = running_server.address
    raw = socket.create_connection((host, port), timeout=5.0)
    raw.sendall(b'{"op":"delete_everything"}\n')
    response = raw.makefile("rb").readline()
    raw.close()
    assert b'"ok":false' in response
    assert b"unknown op" in response


def test_a_malformed_token_object_is_a_block_not_a_crash(running_server):
    with connect(running_server) as client:
        outcome = client._request(
            {"op": "call", "tool_name": "pay_bill", "args": {}, "token": {"junk": 1}}
        )
    assert outcome["allowed"] is False
    assert outcome["gate"] == "token"
    assert "malformed token" in outcome["reason"]


def test_a_result_that_is_not_json_serializable_falls_back_to_repr(tmp_path, phi, token):
    log = AuditLog(tmp_path / "a.jsonl", phi.digest(), LOG_KEY)
    shim = AgentShim(
        Monitor(phi), TOOLS, log, ROOT_KEY, executor=lambda name, args: object()
    )
    server = MonitorServer(shim, port=0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with connect(server) as client:
            outcome = client.call("pay_bill", {"t": "alice", "a": 10}, token)
        assert outcome.allowed
        assert isinstance(outcome.result, str)
        assert outcome.result.startswith("<object")
    finally:
        server.stop()


# --------------------------------------------------------------------------
# concurrency: multiple connections must not deadlock each other
# --------------------------------------------------------------------------


def test_two_concurrent_connections_do_not_deadlock(running_server, token):
    """Regression: an earlier single-threaded connection loop handled one
    connection fully before accepting the next, so a second client's
    `connect()` succeeded at the TCP level but its first request hung
    forever waiting for a server that was still busy with the first
    connection. Held open on purpose here to prove that no longer happens.
    """
    client_a = connect(running_server)
    client_b = connect(running_server)
    try:
        out_a = client_a.call("pay_bill", {"t": "alice", "a": 10}, token)
        out_b = client_b.call("pay_bill", {"t": "bob", "a": 10}, token)
        assert out_a.allowed
        assert out_b.allowed
    finally:
        client_a.close()
        client_b.close()


def test_concurrent_calls_still_enforce_the_shared_cumulative_cap(running_server, token):
    """The lock serializes shim access across connections, so the cap (100)
    is still exactly 100, not something racy, even when hammered from
    several threads at once."""
    results = []
    lock = threading.Lock()

    def worker():
        with connect(running_server) as client:
            outcome = client.call("pay_bill", {"t": "alice", "a": 20}, token)
        with lock:
            results.append(outcome.allowed)

    threads = [threading.Thread(target=worker) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10)

    assert len(results) == 10
    # 100 / 20 = exactly 5 can succeed; the rest must be blocked.
    assert sum(results) == 5


# --------------------------------------------------------------------------
# construction and binding
# --------------------------------------------------------------------------


def test_construction_requires_an_agent_shim():
    with pytest.raises(ServerError, match="expected an AgentShim"):
        MonitorServer("not a shim")  # type: ignore[arg-type]


def test_binds_loopback_by_default(tmp_path, phi):
    log = AuditLog(tmp_path / "a.jsonl", phi.digest(), LOG_KEY)
    shim = AgentShim(Monitor(phi), TOOLS, log, ROOT_KEY)
    server = MonitorServer(shim, port=0)
    try:
        host, _port = server.address
        assert host == "127.0.0.1"
    finally:
        server.stop()


def test_client_error_on_unreachable_server():
    with pytest.raises((ClientError, OSError, ConnectionError)):
        MonitorClient("127.0.0.1", 1, timeout=1.0)
