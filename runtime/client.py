"""VDP L4 — thin client for `runtime.server.MonitorServer`.

This is the ENTIRE surface an agent process gets when the monitor runs
separately (DESIGN.md section 7.5): `call()` and `remaining()`, talking to a
socket. No reference to `Monitor`, `AuditLog`, or any key crosses into this
module or the process that imports it -- there is nothing here TO hold such
a reference to.

Wire protocol: newline-delimited JSON, request/response, matching
`runtime.server`'s handler exactly. See that module's docstring for the
framing rationale and SPEC.md section 11 for the normative definition.
"""

from __future__ import annotations

import json
import socket
from dataclasses import dataclass
from typing import Mapping

from tokens.macaroon import Token

__all__ = ["ClientError", "ClientOutcome", "MonitorClient"]


class ClientError(ConnectionError):
    """A transport-level or protocol-level failure talking to the server.

    Distinct from a BLOCK: a `ClientOutcome` with `allowed=False` means the
    monitor was reached and refused the action. A `ClientError` means the
    monitor was never consulted at all -- the caller cannot treat the two as
    interchangeable "no" answers.
    """


@dataclass(frozen=True, slots=True)
class ClientOutcome:
    """What the client gets back. Mirrors the agent-facing fields of
    `runtime.shim.Outcome` -- NOT its `record`, which stays server-side."""

    allowed: bool
    reason: str
    gate: str
    result: object = None
    error: str | None = None


class MonitorClient:
    """A connection to a `MonitorServer`. One socket, blocking, synchronous."""

    __slots__ = ("_sock", "_reader")

    def __init__(self, host: str, port: int, *, timeout: float | None = 10.0) -> None:
        self._sock = socket.create_connection((host, port), timeout=timeout)
        self._reader = self._sock.makefile("rb")

    def close(self) -> None:
        try:
            self._sock.close()
        except OSError:
            pass

    def __enter__(self) -> "MonitorClient":
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    # --- the agent's entire surface ---

    def call(
        self,
        tool_name: object,
        args: Mapping | None = None,
        token: Token | None = None,
        *,
        now: object = None,
    ) -> ClientOutcome:
        """Mediate one tool call through the remote monitor.

        Mirrors `AgentShim.call`'s signature. `token` MAY be omitted (a
        no-token call is a normal, total input to the shim -- it BLOCKS with
        a reason, same as calling the in-process shim with `token=None`;
        this method does not special-case it).
        """
        payload = {
            "op": "call",
            "tool_name": tool_name,
            "args": dict(args) if isinstance(args, Mapping) else None,
            "token": token.to_obj() if isinstance(token, Token) else None,
            "now": now,
        }
        response = self._request(payload)
        return ClientOutcome(
            allowed=bool(response.get("allowed", False)),
            reason=str(response.get("reason", "")),
            gate=str(response.get("gate", "")),
            result=response.get("result"),
            error=response.get("error"),
        )

    def remaining(self) -> dict:
        response = self._request({"op": "remaining"})
        value = response.get("remaining", {})
        return value if isinstance(value, dict) else {}

    # --- transport ---

    def _request(self, obj: Mapping) -> dict:
        line = json.dumps(dict(obj), separators=(",", ":"), ensure_ascii=True) + "\n"
        try:
            self._sock.sendall(line.encode("ascii"))
            response_line = self._reader.readline()
        except OSError as exc:
            raise ClientError(f"transport failure talking to the monitor: {exc}") from exc

        if not response_line:
            raise ClientError("monitor closed the connection")
        try:
            response = json.loads(response_line.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ClientError(f"malformed response from monitor: {exc}") from exc
        if not isinstance(response, dict) or not response.get("ok"):
            detail = response.get("error") if isinstance(response, dict) else response
            raise ClientError(f"monitor rejected the request: {detail!r}")
        return response
