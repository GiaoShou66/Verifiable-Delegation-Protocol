"""VDP L4 — reference transport binding: the monitor as a separate process.

DESIGN.md section 7.5 states the rule plainly: the monitor must be OUTSIDE
the agent's control surface. Every other reference module in this repository
runs in-process with the demo agent, which that section calls out as an
ARCHITECTURAL separation, not an ENFORCED one. This module and `runtime.client`
are what makes it enforced: `MonitorServer` hosts an `AgentShim` behind a
loopback TCP socket, and `MonitorClient` (runtime/client.py) is the entire
surface an agent process gets -- no reference to the monitor, the audit log,
or the root key crosses the process boundary, only JSON.

--- Why TCP loopback, and why NDJSON ---

Standard library only, cross-platform (this repository targets Windows,
where AF_UNIX support is recent and inconsistent enough not to rely on), and
no framework dependency. One JSON object per line (newline-delimited),
ASCII-escaped for the same reason `runtime.auditlog` escapes its records:
several non-ASCII line-separator code points break naive line-based readers,
and a line-oriented protocol is worth keeping genuinely line-oriented.

--- What crosses the wire, and what does not ---

A `call` request carries the tool name, arguments, and a TOKEN in its plain
wire form (SPEC.md section 5.5) -- transmitting the token is fine: DESIGN.md
5.3 already establishes that HOLDING a token is not authorization, so
handing it to the server the agent already effectively has is not a new
exposure. What never crosses the wire in either direction: the root key, the
log key, the `AuditLog` or `Monitor` objects themselves, or any full audit
`Record` (only the agent-facing outcome fields go back).

--- Binding, deliberately narrow by default ---

`MonitorServer` binds `127.0.0.1` unless told otherwise. Listening on every
interface by default would make "reachable only over a narrow interface" a
lie the moment this module was imported into a networked deployment.

--- Resource bounds, because the peer is hostile ---

SPEC.md section 7 puts the AGENT outside the TCB, and this module is the
agent's only door into the monitor. A peer that exhausts the monitor's
memory, threads, or file descriptors has denied service to the one component
the whole guarantee is stated against -- so every unbounded resource on this
path is bounded here, explicitly:

- `max_line_bytes` -- a request line is read with a limit. A peer that opens
  a connection and streams bytes containing no newline would otherwise grow
  the read buffer without bound (`readline()` on a socket file object has no
  limit of its own). Over-length gets one `ok: false` response and the
  connection is dropped: a stream whose framing has already been violated
  cannot be resynchronized, only abandoned.
- `idle_timeout` -- an accepted connection that never sends anything, or
  stalls mid-request, is closed rather than holding its thread forever.
- `max_connections` -- concurrent connection threads are capped. Past the
  cap a new connection is refused with `ok: false` and closed immediately,
  which is honest (`ok: false` means the monitor was never consulted, SPEC.md
  section 11.2) and costs one short-lived socket rather than a thread.

None of these can turn a BLOCK into an ALLOW; they only ever refuse earlier,
and they refuse at the transport, before any token or monitor gate is
consulted. That is the same shape as every other gate here (SPEC.md section
5.4a), so section 3.4's correctness argument is untouched.
"""

from __future__ import annotations

import json
import socket
import threading
from typing import Mapping

from runtime.shim import AgentShim
from tokens.macaroon import Token, TokenError

__all__ = [
    "DEFAULT_IDLE_TIMEOUT",
    "DEFAULT_MAX_CONNECTIONS",
    "DEFAULT_MAX_LINE_BYTES",
    "MonitorServer",
    "ServerError",
]

#: Largest request line accepted, in bytes. A `call` request carries a tool
#: name, an args object, and a token whose caveat chain is bounded only by how
#: many times a holder chose to attenuate -- so this is generous. It exists to
#: be finite, not to be tight.
DEFAULT_MAX_LINE_BYTES = 1 << 20  # 1 MiB

#: Seconds an accepted connection may sit without completing a request line
#: before it is closed. Blocking, synchronous clients (`runtime.client`) send
#: a request immediately and wait, so this only ever fires on a stalled or
#: abandoned peer.
DEFAULT_IDLE_TIMEOUT = 30.0

#: Concurrent connection threads. One per agent process is the expected shape
#: (this module's class docstring); the cap is what stops a peer that opens
#: sockets in a loop from turning connection accounting into thread
#: exhaustion.
DEFAULT_MAX_CONNECTIONS = 64


class ServerError(ValueError):
    """A misconfigured server. Never raised in response to a client request --
    a malformed request produces a JSON error response instead (see
    `_handle_request`), consistent with `AgentShim.call` never raising out of
    the mediation loop for hostile input."""


def _encode_line(obj: Mapping) -> bytes:
    return (
        json.dumps(dict(obj), separators=(",", ":"), ensure_ascii=True) + "\n"
    ).encode("ascii")


def _jsonable(value: object) -> object:
    """Best-effort JSON-safe view of an executor's result.

    Mirrors `runtime.auditlog._plain`'s reasoning: an executor is outside the
    TCB and can return anything. Falling back to `repr` keeps the response
    encodable rather than raising out of the connection handler.
    """
    try:
        json.dumps(value)
    except TypeError:
        return repr(value)
    return value


class MonitorServer:
    """Hosts an `AgentShim` behind a loopback TCP socket.

    Each accepted CONNECTION runs on its own thread, so one agent holding a
    connection open cannot starve another from ever being accepted (an
    earlier single-threaded version of this class deadlocked exactly that
    way under two concurrent clients -- found by testing this module against
    itself, not by review). But every actual call into the shim -- across
    every connection -- is serialized through one lock, because `Monitor`,
    `AgentShim`, and `AuditLog` are NOT thread-safe on their own (DESIGN.md:
    "single-threaded by design"; none of their state mutations take a lock).
    The lock is what lets "many connections" and "one sequential decision
    stream" both be true at once: I/O concurrency without decision-path
    concurrency.
    """

    __slots__ = (
        "_shim",
        "_sock",
        "_running",
        "_lock",
        "_max_line_bytes",
        "_idle_timeout",
        "_slots",
    )

    def __init__(
        self,
        shim: AgentShim,
        host: str = "127.0.0.1",
        port: int = 0,
        *,
        max_line_bytes: int = DEFAULT_MAX_LINE_BYTES,
        idle_timeout: float | None = DEFAULT_IDLE_TIMEOUT,
        max_connections: int = DEFAULT_MAX_CONNECTIONS,
        backlog: int = 64,
    ) -> None:
        """`max_line_bytes`, `idle_timeout`, and `max_connections` bound what
        a hostile peer can consume; see this module's docstring. Each may be
        tuned, and `idle_timeout=None` disables the timeout, but the byte and
        connection limits have no "unlimited" setting on purpose -- an
        unbounded read on an agent-facing socket is the defect, not a mode."""
        if not isinstance(shim, AgentShim):
            raise ServerError(f"expected an AgentShim, got {type(shim).__name__}")
        if not isinstance(max_line_bytes, int) or max_line_bytes < 1:
            raise ServerError("max_line_bytes must be a positive integer")
        if not isinstance(max_connections, int) or max_connections < 1:
            raise ServerError("max_connections must be a positive integer")
        if idle_timeout is not None and (
            not isinstance(idle_timeout, (int, float)) or idle_timeout <= 0
        ):
            raise ServerError("idle_timeout must be a positive number, or None")
        self._shim = shim
        self._max_line_bytes = max_line_bytes
        self._idle_timeout = None if idle_timeout is None else float(idle_timeout)
        self._slots = threading.BoundedSemaphore(max_connections)
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((host, port))
        self._sock.listen(backlog)
        self._running = False
        self._lock = threading.Lock()

    @property
    def address(self) -> tuple[str, int]:
        """The bound (host, port) -- useful when `port=0` asked for an
        ephemeral one, e.g. in tests."""
        return self._sock.getsockname()[:2]

    def serve_forever(self) -> None:
        """Accept connections until `stop()` closes the listening socket.

        Each connection is handled on its own daemon thread. Typically this
        method itself is also run on a dedicated thread:
        `threading.Thread(target=server.serve_forever, daemon=True).start()`.
        """
        self._running = True
        while self._running:
            try:
                conn, _addr = self._sock.accept()
            except OSError:
                break  # the listening socket was closed by stop()
            if not self._slots.acquire(blocking=False):
                # At the connection cap. Refuse honestly and cheaply: `ok:
                # false` says the monitor was never consulted (SPEC.md section
                # 11.2), which is exactly true, and costs no thread.
                self._refuse(conn, "monitor is at its connection limit")
                continue
            try:
                threading.Thread(
                    target=self._run_connection, args=(conn,), daemon=True
                ).start()
            except RuntimeError:
                # The interpreter refused a new thread -- which is exactly the
                # exhaustion `max_connections` exists to survive, so it must
                # not be the thing that kills the accept loop. Release the slot
                # we took, refuse this connection, keep serving. Without this,
                # the slot leaks AND the exception escapes serve_forever,
                # leaving a monitor that accepts nothing ever again.
                self._slots.release()
                self._refuse(conn, "monitor could not start a handler thread")

    def _refuse(self, conn: socket.socket, reason: str) -> None:
        """Send one protocol-level refusal and close. Best effort: a peer that
        is already gone is not an error worth propagating."""
        try:
            conn.sendall(_encode_line({"ok": False, "error": reason}))
        except OSError:
            pass
        finally:
            conn.close()

    def _run_connection(self, conn: socket.socket) -> None:
        try:
            self._handle_connection(conn)
        finally:
            conn.close()
            self._slots.release()

    def stop(self) -> None:
        self._running = False
        try:
            self._sock.close()
        except OSError:
            pass

    # --- connection handling ---

    def _handle_connection(self, conn: socket.socket) -> None:
        if self._idle_timeout is not None:
            conn.settimeout(self._idle_timeout)
        reader = conn.makefile("rb")
        limit = self._max_line_bytes
        while True:
            try:
                # Read one byte past the limit so an over-length line is
                # DISTINGUISHABLE from one that exactly fills it. `TimeoutError`
                # (a socket timeout) is an OSError, so a stalled peer lands here
                # and the connection is dropped.
                line = reader.readline(limit + 1)
            except OSError:
                return
            if not line:
                return  # client closed its end
            if len(line) > limit:
                # Framing is already broken -- the rest of this line is still
                # in the stream and there is no safe point to resume from.
                # Answer once, then drop the connection.
                self._refuse(
                    conn,
                    f"malformed request: line exceeds {limit} bytes",
                )
                return
            if not line.endswith(b"\n"):
                return  # EOF mid-line: an incomplete request is not a request
            response = self._handle_request(line)
            try:
                conn.sendall(_encode_line(response))
            except OSError:
                return

    def _handle_request(self, line: bytes) -> dict:
        try:
            req = json.loads(line.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            return {"ok": False, "error": f"malformed request: not valid JSON ({exc})"}
        if not isinstance(req, dict):
            return {
                "ok": False,
                "error": f"malformed request: expected an object, got {type(req).__name__}",
            }

        op = req.get("op")
        if op == "call":
            return self._handle_call(req)
        if op == "remaining":
            with self._lock:
                return {"ok": True, "remaining": self._shim.remaining()}
        return {"ok": False, "error": f"unknown op {op!r}"}

    def _handle_call(self, req: dict) -> dict:
        tool_name = req.get("tool_name")
        args = req.get("args")
        token_obj = req.get("token")
        now = req.get("now")

        token: object = None
        if token_obj is not None:
            try:
                token = Token.from_obj(token_obj)
            except TokenError as exc:
                # A malformed token is a BLOCK, not a protocol error -- same
                # shape AgentShim.call gives a hostile token it constructed
                # itself. The connection stays healthy; the call is refused.
                # No lock needed: nothing reached the shim.
                return {
                    "ok": True,
                    "allowed": False,
                    "reason": f"malformed token: {exc}",
                    "gate": "token",
                    "result": None,
                    "error": None,
                }

        # Every decision, from any connection, goes through this one lock --
        # the shim, monitor, and audit log are not thread-safe individually.
        with self._lock:
            outcome = self._shim.call(tool_name, args, token, now=now)
        return {
            "ok": True,
            "allowed": outcome.allowed,
            "reason": outcome.reason,
            "gate": outcome.gate,
            "result": _jsonable(outcome.result),
            "error": outcome.error,
        }
