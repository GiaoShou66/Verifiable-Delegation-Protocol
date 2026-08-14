"""VDP L4 — the agent shim (DESIGN.md sections 1.1, 5.4, 6).

    tool call -> normalize -> TOKEN GATE -> MONITOR GATE -> execute -> log

`call()` is the ONLY method an agent may reach. The shim holds the monitor, the
audit log, the root key, and the mapping table; it exposes none of them.

--- Two independent gates ---

A valid token is NECESSARY, NOT SUFFICIENT (DESIGN.md 5.4). Both must pass:

  1. the token verifies against `k` and the action lies within S_n, and
  2. the monitor allows the action from the current q.

Either failing blocks. The token binds SCOPE; the monitor binds TRACE HISTORY.
The token gate runs first only so that a bad token cannot advance the monitor's
counter -- the order is not a precedence rule, since both must pass anyway.

Adding a gate can only SHRINK the set of allowed traces, so the L2 theorem ("no
executed prefix is a bad prefix") survives untouched: every action this shim
executes was allowed by the monitor, and the monitor's guarantee is about
exactly that set.

--- max_total is shim state, and that is deliberate ---

`Scope.max_total` is cumulative and cannot be decided from a single action, so
the shim keeps a per-token running total. This is NOT monitor state and does not
weaken the automaton argument -- it is a third conjunctive gate that can only
block more. It is also not visible to the agent, which is what stops a child
agent from resetting its own allowance by re-presenting its token.

--- The mapping table is part of the policy artifact ---

`attrs` never reaches the automaton (DESIGN.md 1.1). Anything that must affect a
decision has to be lifted into verb, target, or amount HERE, by a table the
agent cannot write. An unknown tool name maps to `verb=None`, which alpha sinks
-- one code path, no special case, and no way for an unmapped tool named "pay"
to be mistaken for the real `pay`.

--- The in-process caveat, stated plainly ---

In a real deployment the monitor runs in a separate process and the agent
reaches it only over a narrow IPC surface exposing `call()`. HERE IT RUNS IN THE
SAME PROCESS as the demo agent. "Outside the model's control surface" is
therefore an ARCHITECTURAL property, not an ENFORCED one: nothing at the
language level stops code in this process from reaching a private attribute.
`__slots__`, frozen dataclasses, and a single public method are what this
implementation does about it. Memory isolation is NOT claimed. DESIGN.md 7.5.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from types import MappingProxyType
from typing import Callable, Mapping

from monitor.automaton import ConcreteAction
from monitor.mediate import ALLOW, BLOCK, Monitor
from policy.ast import NO_TARGET
from runtime.auditlog import AuditLog, Record
from tokens.macaroon import Token, verify

__all__ = [
    "AgentShim",
    "Outcome",
    "ShimError",
    "ToolSpec",
    "artifact_hash",
    "canonical_tool_table",
    "tool_table_hash",
]


class ShimError(ValueError):
    """A misconfigured shim. Never raised in response to agent input."""


def _as_amount(value: object) -> int:
    """An amount as an integer, or 0. Used only for the shim's own ledger.

    By the time this is called the token gate and the monitor have both accepted
    the action, so the value is already a non-negative integer. The check is
    here anyway because a ledger that could be fed a non-integer would be a way
    to corrupt the max_total gate, and `assert` is not an enforcement mechanism.
    """
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return 0
    return value


@dataclass(frozen=True, slots=True)
class ToolSpec:
    """How one tool name becomes a `ConcreteAction`.

    Part of the policy artifact, not agent-writable. `target_arg` and
    `amount_arg` name keys in the agent's argument dict; `fixed_target` and
    `fixed_amount` pin them regardless of what the agent supplies, which is how
    a fixed-price or target-less tool is expressed.
    """

    verb: str
    target_arg: str | None = None
    amount_arg: str | None = None
    fixed_target: str | None = None
    fixed_amount: int | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.verb, str) or not self.verb:
            raise ShimError("ToolSpec.verb must be a non-empty string")
        if self.target_arg is not None and self.fixed_target is not None:
            raise ShimError(f"{self.verb}: give target_arg or fixed_target, not both")
        if self.amount_arg is not None and self.fixed_amount is not None:
            raise ShimError(f"{self.verb}: give amount_arg or fixed_amount, not both")

    def normalize(self, args: object) -> ConcreteAction:
        """Map agent arguments to a ConcreteAction. TOTAL: never raises.

        Missing or wrong-typed arguments are passed through UNCHANGED so that
        alpha -- not this function -- decides what they mean. Repairing them
        here would move the fail-closed decision out of the automaton.
        """
        mapping = args if isinstance(args, Mapping) else {}

        if self.fixed_target is not None:
            target: object = self.fixed_target
        elif self.target_arg is not None:
            target = mapping.get(self.target_arg, None)
        else:
            target = NO_TARGET

        if self.fixed_amount is not None:
            amount: object = self.fixed_amount
        elif self.amount_arg is not None:
            amount = mapping.get(self.amount_arg, None)
        else:
            amount = 0

        return ConcreteAction(
            verb=self.verb, target=target, amount=amount, attrs=dict(mapping)
        )


@dataclass(frozen=True, slots=True)
class Outcome:
    """What the agent gets back. Immutable, and it carries no monitor handle."""

    allowed: bool
    reason: str
    record: Record
    result: object = None
    error: str | None = None
    #: Which gate refused: "token", "monitor", or "" when nothing refused.
    #: Reporting only. The gates are a CONJUNCTION, so this names the first one
    #: that happened to fire, not the only one that would have.
    gate: str = ""


def _unmappable(tool_name: object, args: object) -> ConcreteAction:
    """The fail-closed normalization for a tool with no entry in the table.

    `verb=None` is not a string, so alpha maps it to the unknown-verb sink and
    delta sends it to q_bad by the ordinary rule. The raw tool name is kept in
    attrs for the log, where it is evidence rather than input to a decision.
    """
    attrs = dict(args) if isinstance(args, Mapping) else {"args": repr(args)}
    attrs["unmapped_tool"] = repr(tool_name)
    return ConcreteAction(verb=None, target=NO_TARGET, amount=0, attrs=attrs)


def canonical_tool_table(tools: Mapping[str, "ToolSpec"]) -> bytes:
    """Deterministic bytes for a tool mapping table.

    Canonical JSON: sorted tool names, sorted keys, no whitespace -- same
    shape discipline as `Policy.canonical()` and `Scope.canonical()`. This is
    the "meaning" half of a policy artifact that DESIGN.md section 1.1
    describes but that a bare `policy_hash` cannot cover: `attrs` never
    reaches the automaton, so whatever maps a tool name to (verb, target,
    amount) is exactly as load-bearing as phi itself, and has to be
    independently checkable.
    """
    obj = {
        name: {
            "verb": spec.verb,
            "target_arg": spec.target_arg,
            "amount_arg": spec.amount_arg,
            "fixed_target": spec.fixed_target,
            "fixed_amount": spec.fixed_amount,
        }
        for name, spec in sorted(dict(tools).items())
    }
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def tool_table_hash(tools: Mapping[str, "ToolSpec"]) -> str:
    """SHA-256 hex of `canonical_tool_table`."""
    return hashlib.sha256(canonical_tool_table(tools)).hexdigest()


def artifact_hash(policy_hash: str, tools: Mapping[str, "ToolSpec"]) -> str:
    """SHA-256 hex binding a policy_hash to a specific tool mapping table.

    This is the value an integrator SHOULD record alongside `policy_hash` at
    the confirmation gate (DESIGN.md section 2.6) if they want a human's
    confirmation to be provably tied to the exact table wired into the shim,
    not just to phi. `policy.confirm` does not compute this itself -- L1
    never imports L4 (see that module's docstring) -- so producing and
    displaying it is the caller's responsibility.
    """
    return hashlib.sha256(
        policy_hash.encode("utf-8") + b"\x00" + canonical_tool_table(tools)
    ).hexdigest()


class AgentShim:
    """Mediates every tool call. The agent sees `call()` and nothing else."""

    __slots__ = (
        "_monitor",
        "_tools",
        "_log",
        "_root_key",
        "_executor",
        "_spent",
        "_artifact_hash",
    )

    def __init__(
        self,
        monitor: Monitor,
        tools: Mapping[str, ToolSpec],
        log: AuditLog,
        root_key: bytes,
        executor: Callable[[str, Mapping], object] | None = None,
        *,
        expected_artifact_hash: str | None = None,
    ) -> None:
        """
        `expected_artifact_hash`: optional. If given, construction FAILS
        unless it equals `artifact_hash(monitor.policy.digest(), tools)` --
        the same check the log's own policy_hash gets (`log.policy_hash !=
        monitor.policy.digest()` below), but for the tool table. Omit it (the
        default) to skip this check entirely; existing callers that never
        pass it are unaffected. Passing it is how an integrator makes "the
        table wired into this shim is the exact one shown at confirmation" a
        checked fact instead of an assumption.
        """
        if not isinstance(monitor, Monitor):
            raise ShimError(f"expected a Monitor, got {type(monitor).__name__}")
        if not isinstance(log, AuditLog):
            raise ShimError(f"expected an AuditLog, got {type(log).__name__}")
        if log.policy_hash != monitor.policy.digest():
            raise ShimError("the audit log was opened under a different policy")
        if not isinstance(root_key, (bytes, bytearray)) or len(root_key) < 32:
            raise ShimError("root_key must be at least 32 bytes")

        table: dict[str, ToolSpec] = {}
        for name, spec in dict(tools).items():
            if not isinstance(spec, ToolSpec):
                raise ShimError(f"tool {name!r} is not a ToolSpec")
            if spec.verb not in monitor.policy.verbs:
                raise ShimError(
                    f"tool {name!r} maps to verb {spec.verb!r}, which phi never names; "
                    f"a tool the policy cannot describe must not be mappable"
                )
            table[name] = spec

        computed_artifact_hash = artifact_hash(monitor.policy.digest(), table)
        if (
            expected_artifact_hash is not None
            and expected_artifact_hash != computed_artifact_hash
        ):
            raise ShimError(
                "the tool table does not match expected_artifact_hash; it may "
                "not be the table the human confirmed"
            )

        self._monitor = monitor
        self._tools = MappingProxyType(table)
        self._log = log
        self._root_key = bytes(root_key)
        self._executor = executor
        self._spent: dict[str, int] = {}
        self._artifact_hash = computed_artifact_hash

    # --- operator-facing views. NOT part of the agent's surface. ---

    @property
    def artifact_hash(self) -> str:
        """SHA-256 binding this shim's policy_hash to its exact tool table.

        Record this (not bare `policy_hash`) if you want to detect, after
        the fact, that the table an agent was actually mediated against
        differs from the one shown at confirmation.
        """
        return self._artifact_hash

    @property
    def policy_hash(self) -> str:
        return self._monitor.policy.digest()

    @property
    def tool_names(self) -> tuple[str, ...]:
        return tuple(sorted(self._tools))

    def remaining(self) -> dict[str, int]:
        return self._monitor.remaining()

    def spent_under(self, token: Token) -> int:
        return self._spent.get(token.token_id(), 0)

    # --- the agent's entire surface ---

    def call(
        self,
        tool_name: object,
        args: object = None,
        token: object = None,
        *,
        now: object = None,
    ) -> Outcome:
        """Mediate one tool call. TOTAL: any input yields an Outcome.

        A hostile agent can pass anything at all here. Nothing it passes can
        raise out of this method, because every rejection is a BLOCK with a
        reason rather than an exception -- an exception would be a control-flow
        channel out of the mediation loop.
        """
        spec = self._tools.get(tool_name) if isinstance(tool_name, str) else None
        action = spec.normalize(args) if spec is not None else _unmappable(tool_name, args)
        symbol = self._monitor.automaton.alpha(action)

        token_id = token.token_id() if isinstance(token, Token) else "<no-token>"
        pre = self._monitor.state

        refusal = self._token_refusal(token, action, now)
        if refusal is not None:
            # Blocked before the monitor was consulted, so q is untouched and
            # the record shows pre_state on both sides -- the same shape a
            # monitor-side block has.
            return self._finish(
                action, symbol, pre, pre, BLOCK, refusal, token_id, None, None, "token"
            )

        decision = self._monitor.submit(action)
        if decision.decision == BLOCK:
            return self._finish(
                action,
                decision.symbol,
                decision.pre_state,
                decision.post_state,
                BLOCK,
                decision.reason,
                token_id,
                None,
                None,
                "monitor",
            )

        # Allowed. The counter has already advanced -- DESIGN.md 3.3: if
        # execution fails now, VDP under-spends the authorization rather than
        # rolling anything back.
        self._spent[token_id] = self._spent.get(token_id, 0) + _as_amount(action.amount)

        result: object = None
        error: str | None = None
        try:
            if self._executor is not None:
                result = self._executor(tool_name, dict(action.attrs))
        except Exception as exc:  # the executor is outside the TCB
            error = f"{type(exc).__name__}: {exc}"

        # The record is written whatever the executor did, including raising:
        # the log is evidence of the DECISION, and the decision was made before
        # the executor ran.
        return self._finish(
            action,
            decision.symbol,
            decision.pre_state,
            decision.post_state,
            ALLOW,
            decision.reason,
            token_id,
            result,
            error,
        )

    # --- internals ---

    def _token_refusal(
        self, token: object, action: ConcreteAction, now: object
    ) -> str | None:
        """The token gate. Returns None to pass, or the reason it refused."""
        if not isinstance(token, Token):
            return f"no capability token presented (got {type(token).__name__})"
        if not verify(self._root_key, token):
            return "token does not verify against the root key"
        if not token.root.names_capabilities:
            return (
                "token's root scope leaves verbs or targets unrestricted; a root "
                "token must name what it authorizes"
            )

        scope = token.scope
        refusal = scope.permits(action.verb, action.target, action.amount, now=now)
        if refusal is not None:
            return refusal

        if scope.max_total is not None:
            spent = self._spent.get(token.token_id(), 0)
            total = spent + _as_amount(action.amount)
            if total > scope.max_total:
                return (
                    f"would take this token's total to {total}, over its max_total "
                    f"of {scope.max_total}"
                )
        return None

    def _finish(
        self,
        action,
        symbol,
        pre,
        post,
        decision: str,
        reason: str,
        token_id: str,
        result: object,
        error: str | None,
        gate: str = "",
    ) -> Outcome:
        record = self._log.append(
            action=action,
            symbol=symbol,
            pre_state=pre,
            post_state=post,
            decision=decision,
            reason=reason,
            token_id=token_id,
        )
        return Outcome(
            allowed=decision == ALLOW,
            reason=reason,
            record=record,
            result=result,
            error=error,
            gate=gate,
        )
