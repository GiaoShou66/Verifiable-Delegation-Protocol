"""VDP L4 — Idempotent executor adapter for external tool actions.

In real-world networks, downstream service calls (banks, APIs) can drop or timeout
(e.g., 504 Gateway Timeout). Because VDP enforces a conservative "no-rollback" rule
(DESIGN.md section 3.3), rolling counters back upon network failure would break the
safety theorem by allowing rogue agents to manufacture fake timeouts to reclaim budget.

`IdempotentExecutorWrapper` bridges this gap:
  1. Computes a deterministic idempotency key = SHA256(token_id + ":" + seq + ":" + canonical_action).
  2. Forwards this key to the downstream tool API (e.g. as `idempotency_key=...`).
  3. Caches successful/prior results so that if an agent retries an identical action with
     the same token, the downstream executor deduplicates without double-charging,
     preserving both safety and network resiliency.
"""

from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import dataclass
from typing import Any, Callable, Mapping

from monitor.automaton import ConcreteAction

__all__ = ["IdempotentExecutorWrapper", "compute_idempotency_key"]


def compute_idempotency_key(
    token_id: str,
    seq: int,
    tool_name: str = "",
    attrs: Mapping | None = None,
    action: ConcreteAction | None = None,
) -> str:
    """Compute a deterministic idempotency key for an action."""
    raw_attrs = (action.attrs if action is not None else attrs) or {}
    t_name = tool_name or (str(action.verb) if action is not None else "")
    action_dict: dict[str, Any] = {
        "tool_name": t_name,
        "attrs": {
            str(k): (v if isinstance(v, (str, int, float, bool, type(None))) else repr(v))
            for k, v in sorted(dict(raw_attrs).items())
        },
    }
    canonical = json.dumps(action_dict, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    payload = f"{token_id}:{seq}:{canonical}".encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


class IdempotentExecutorWrapper:
    """Wraps an executor callable to provide idempotency keys and cached results."""

    __slots__ = ("_executor", "_pass_key", "_cache_responses", "_cache", "_call_history", "_lock")

    def __init__(
        self,
        executor: Callable[..., Any],
        *,
        pass_idempotency_key: bool = True,
        cache_responses: bool = True,
    ) -> None:
        self._executor = executor
        self._pass_key = pass_idempotency_key
        self._cache_responses = cache_responses
        self._cache: dict[str, Any] = {}
        self._call_history: list[dict[str, Any]] = []
        self._lock = threading.Lock()

    @property
    def call_history(self) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._call_history)

    def is_cached(self, idempotency_key: str) -> bool:
        with self._lock:
            return idempotency_key in self._cache

    def __call__(
        self,
        tool_name: str,
        attrs: dict,
        *,
        token_id: str = "<no-token>",
        seq: int = 0,
        action: ConcreteAction | None = None,
        **extra: Any,
    ) -> Any:
        key = compute_idempotency_key(
            token_id=token_id,
            seq=seq,
            tool_name=tool_name,
            attrs=attrs,
            action=action,
        )

        with self._lock:
            if self._cache_responses and key in self._cache:
                self._call_history.append({
                    "tool_name": tool_name,
                    "idempotency_key": key,
                    "cached": True,
                    "result": self._cache[key],
                })
                return self._cache[key]

        call_kwargs = dict(extra)
        if self._pass_key:
            call_kwargs["idempotency_key"] = key

        try:
            res = self._executor(tool_name, attrs, **call_kwargs)
        except TypeError:
            # Underlying executor does not take extra kwargs
            res = self._executor(tool_name, attrs)

        with self._lock:
            if self._cache_responses:
                self._cache[key] = res

            self._call_history.append({
                "tool_name": tool_name,
                "idempotency_key": key,
                "cached": False,
                "result": res,
            })
        return res
