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
"""

from __future__ import annotations

import json
import socket
import threading
from typing import Mapping

from runtime.shim import AgentShim
from tokens.macaroon import Token, TokenError

__all__ = ["MonitorServer", "ServerError"]


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

    __slots__ = ("_shim", "_sock", "_running", "_lock")

    def __init__(
        self, shim: AgentShim, host: str = "127.0.0.1", port: int = 0
    ) -> None:
        if not isinstance(shim, AgentShim):
            raise ServerError(f"expected an AgentShim, got {type(shim).__name__}")
        self._shim = shim
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((host, port))
        self._sock.listen(5)
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
            threading.Thread(
                target=self._run_connection, args=(conn,), daemon=True
            ).start()

    def _run_connection(self, conn: socket.socket) -> None:
        try:
            self._handle_connection(conn)
        finally:
            conn.close()

    def stop(self) -> None:
        self._running = False
        try:
            self._sock.close()
        except OSError:
            pass

    # --- connection handling ---

    def _handle_connection(self, conn: socket.socket) -> None:
        reader = conn.makefile("rb")
        while True:
            try:
                line = reader.readline()
            except OSError:
                return
            if not line:
                return  # client closed its end
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
