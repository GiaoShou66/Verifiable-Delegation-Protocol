"""Resource bounds and durability — the parts a hostile peer or a crash hits.

These are not tests of the guarantee; SPEC.md section 3.4 owns that. They
cover the two ways this implementation could fail WITHOUT ever letting a bad
prefix through: by being knocked over, and by forgetting what it decided.

- `MonitorServer` is the agent's only door into the monitor, and the agent is
  outside the TCB (SPEC.md section 7). An unbounded read, a missing timeout,
  or an uncapped thread count each let the peer deny service to the one
  component the guarantee is stated against.
- `AuditLog` is written AFTER an action executes (DESIGN.md section 3.3). A
  buffered write that never reaches disk turns "every decision is recorded"
  into "every decision the page cache happened to flush".
"""

from __future__ import annotations

import socket
import threading
import time

import pytest

from monitor.automaton import ConcreteAction
from monitor.mediate import Monitor
from policy.parser import parse
from runtime.auditlog import AuditLog
from runtime.server import MonitorServer, ServerError
from runtime.shim import AgentShim, ToolSpec

ROOT_KEY = b"r" * 32
LOG_KEY = b"l" * 32

PHI_TEXT = """
counter spend over {pay}
always(spend <= 100)
and always(pay(target) -> target in {"alice"})
"""

TOOLS = {"pay_bill": ToolSpec(verb="pay", target_arg="t", amount_arg="a")}


@pytest.fixture
def phi():
    return parse(PHI_TEXT)


def _shim(tmp_path, phi, **log_kwargs) -> AgentShim:
    log = AuditLog(tmp_path / "audit.jsonl", phi.digest(), LOG_KEY, **log_kwargs)
    return AgentShim(
        Monitor(phi), TOOLS, log, ROOT_KEY, executor=lambda name, args: f"ok:{name}"
    )


def _serve(server: MonitorServer) -> threading.Thread:
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return thread


def _raw(server: MonitorServer, timeout: float = 5.0) -> socket.socket:
    host, port = server.address
    return socket.create_connection((host, port), timeout=timeout)


def _compact(data: bytes) -> bytes:
    return data.replace(b" ", b"")


#: The smallest well-formed request there is: no token, no args, no
#: executor call. Useful when the point of a test is the TRANSPORT, not
#: the decision.
REMAINING_REQUEST = b'{"op":"remaining"}\n'


# --------------------------------------------------------------------------
# Request-line bounds
# --------------------------------------------------------------------------


def test_over_length_line_is_refused_not_buffered(tmp_path, phi):
    """A peer streaming a newline-free line gets one refusal and a closed
    socket, instead of growing the server's read buffer without bound."""
    server = MonitorServer(_shim(tmp_path, phi), port=0, max_line_bytes=4096)
    _serve(server)
    try:
        with _raw(server) as sock:
            sock.sendall(b"x" * 65536)  # sixteen times the limit, no newline
            reply = sock.makefile("rb").readline()
        assert b'"ok":false' in _compact(reply)
        assert b"exceeds" in reply
    finally:
        server.stop()


def test_a_line_under_the_limit_still_works(tmp_path, phi):
    """The bound must reject only what is genuinely over it -- an off-by-one
    here would start refusing legitimate requests."""
    server = MonitorServer(_shim(tmp_path, phi), port=0, max_line_bytes=4096)
    _serve(server)
    try:
        with _raw(server) as sock:
            line = (
                '{"op":"call","tool_name":"pay_bill","args":{"t":"alice","a":1},'
                '"token":null,"now":null}\n'
            )
            assert len(line) < 4096
            sock.sendall(line.encode("ascii"))
            reply = sock.makefile("rb").readline()
        # Reached the monitor: ok:true, then BLOCKed at the token gate because
        # no token was sent. `ok:false` here would mean the transport refused.
        assert b'"ok":true' in _compact(reply)
        assert b'"allowed":false' in _compact(reply)
    finally:
        server.stop()


def test_eof_mid_line_closes_without_a_verdict(tmp_path, phi):
    """A half-sent request is not a request: it must not be parsed, and must
    not hang the connection thread."""
    server = MonitorServer(_shim(tmp_path, phi), port=0)
    _serve(server)
    try:
        sock = _raw(server)
        sock.sendall(b'{"op":"remaining"')  # no newline, then EOF
        sock.shutdown(socket.SHUT_WR)
        assert sock.makefile("rb").readline() == b""
        sock.close()
    finally:
        server.stop()


# --------------------------------------------------------------------------
# Timeouts and connection caps
# --------------------------------------------------------------------------


def test_idle_connection_is_closed(tmp_path, phi):
    """A peer that connects and says nothing must not pin a thread forever."""
    server = MonitorServer(_shim(tmp_path, phi), port=0, idle_timeout=0.3)
    _serve(server)
    try:
        with _raw(server) as sock:
            assert sock.makefile("rb").readline() == b""  # server closed it
    finally:
        server.stop()


def test_connection_cap_refuses_rather_than_spawning(tmp_path, phi):
    """Past `max_connections` a new connection is refused with ok:false -- the
    honest signal, because the monitor was never consulted."""
    server = MonitorServer(_shim(tmp_path, phi), port=0, max_connections=1)
    _serve(server)
    held = None
    try:
        held = _raw(server)
        held.sendall(b'{"op":"remaining"}\n')
        assert b'"ok":true' in _compact(held.makefile("rb").readline())

        with _raw(server) as second:
            reply = second.makefile("rb").readline()
        assert b'"ok":false' in _compact(reply)
        assert b"connection limit" in reply
    finally:
        if held is not None:
            held.close()
        server.stop()


def test_connection_slot_is_released_on_close(tmp_path, phi):
    """A server that refused forever would be its own denial of service.
    Closing a connection must return its slot.

    The release happens on the connection's own thread once it observes EOF,
    so it is not instantaneous from the client's side -- hence the bounded
    retry. What is under test is that the slot comes back AT ALL: with a leak,
    every attempt after the first would be refused until the deadline.
    """
    server = MonitorServer(_shim(tmp_path, phi), port=0, max_connections=1)
    _serve(server)
    try:
        for round_number in range(3):
            deadline = time.monotonic() + 5.0
            while True:
                reply = b""
                try:
                    with _raw(server) as sock:
                        sock.sendall(REMAINING_REQUEST)
                        reply = sock.makefile("rb").readline()
                except OSError:
                    pass  # refused mid-flight: the slot is not back yet
                if b'"ok":true' in _compact(reply):
                    break
                assert time.monotonic() < deadline, (
                    f"round {round_number}: the connection slot was never "
                    f"released (last reply: {reply!r})"
                )
                time.sleep(0.02)
    finally:
        server.stop()


@pytest.mark.parametrize(
    "kwargs",
    [
        {"max_line_bytes": 0},
        {"max_line_bytes": -1},
        {"max_connections": 0},
        {"idle_timeout": 0},
        {"idle_timeout": -1.0},
    ],
)
def test_nonsense_bounds_are_refused_at_construction(tmp_path, phi, kwargs):
    """A limit of zero or a negative timeout is a caller bug. Refuse it where
    it is written, not at the first connection."""
    with pytest.raises(ServerError):
        MonitorServer(_shim(tmp_path, phi), port=0, **kwargs)


# --------------------------------------------------------------------------
# Audit log durability
# --------------------------------------------------------------------------


def test_record_is_on_disk_before_append_returns(tmp_path, phi):
    """An independent reader must see the record the instant the call returns
    -- not whenever a buffer happens to flush."""
    shim = _shim(tmp_path, phi)
    outcome = shim.call("pay_bill", {"t": "alice", "a": 1}, None)
    assert outcome.allowed is False  # no token: blocked, and still recorded

    path = tmp_path / "audit.jsonl"
    assert path.read_text(encoding="utf-8").count("\n") == 1


def test_fsync_setting_does_not_change_the_bytes(tmp_path, phi):
    """`fsync=False` is a durability tradeoff and nothing else. The record,
    and therefore every hash in the chain, must be identical either way."""
    durable = AuditLog(tmp_path / "a.jsonl", phi.digest(), LOG_KEY, fsync=True)
    fast = AuditLog(tmp_path / "b.jsonl", phi.digest(), LOG_KEY, fsync=False)
    assert durable.head == fast.head

    symbol = Monitor(phi).automaton.alpha(
        ConcreteAction(verb="pay", target="alice", amount=1)
    )
    common = dict(
        action=None,
        symbol=symbol,
        pre_state=(0,),
        post_state=(1,),
        decision="ALLOW",
        reason="test",
        token_id="<no-token>",
    )
    left = durable.append(**common)
    right = fast.append(**common)
    assert left.hash == right.hash
    assert left.sig == right.sig


def test_verify_reports_a_corrupt_line_instead_of_raising(tmp_path, phi):
    """A half-written or tampered line is a FINDING about the log. A verifier
    that raises tells an operator less than one naming the bad record -- and
    an exception reads as a crash bug rather than as tamper detection."""
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path, phi.digest(), LOG_KEY, fsync=False)
    symbol = Monitor(phi).automaton.alpha(
        ConcreteAction(verb="pay", target="alice", amount=1)
    )
    log.append(
        action=None,
        symbol=symbol,
        pre_state=(0,),
        post_state=(1,),
        decision="ALLOW",
        reason="test",
        token_id="<no-token>",
    )
    assert log.verify().ok is True

    # What a crash mid-write leaves behind.
    with path.open("a", encoding="utf-8") as handle:
        handle.write('{"seq": 1, "truncated"\n')

    result = log.verify()
    assert result.ok is False
    assert any("unreadable" in problem for problem in result.problems)
    assert result.tail_truncation_undetectable is True
