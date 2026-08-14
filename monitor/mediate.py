"""VDP L2 — the mediation loop (DESIGN.md section 3.3).

    def submit(q, concrete_action):
        a  = alpha(concrete_action)      # total; may yield a fail-closed symbol
        q2 = delta(q, a)
        if q2 in F_bad:
            return BLOCK, q              # state UNCHANGED
        return ALLOW, q2

--- Why a block does not advance the state ---

A blocked action leaves no trace in q. A hostile agent therefore cannot drive
the monitor toward a bound by issuing actions it knows will be refused. Blocked
attempts are still recorded by the audit log in L4 -- they are evidence, not
state.

--- Ordering ---

Decide, then execute, then log. If execution fails after an ALLOW, the counter
has already advanced. That is deliberate and conservative: it can only
UNDER-spend the authorization, never over-spend it. VDP does not roll the
counter back, because rollback is exactly the "make it work" feature that would
break the guarantee.

--- Control surface ---

`Monitor` exposes `submit` and read-only views. There is no setter for q, no way
to load a state, and no way to swap phi. In a real deployment this object lives
in a separate process reached over a narrow IPC surface; in this reference
implementation it lives in the same process as the demo agent, which is an
ARCHITECTURAL separation rather than an ENFORCED one. DESIGN.md section 7.5
states that limitation rather than assuming it away.
"""

from __future__ import annotations

from dataclasses import dataclass

from policy.ast import Policy

from monitor.automaton import BAD, BOT_TARGET, BOT_VERB, Automaton, ConcreteAction, State, Symbol

__all__ = ["ALLOW", "BLOCK", "Decision", "Monitor"]

ALLOW = "ALLOW"
BLOCK = "BLOCK"


@dataclass(frozen=True, slots=True)
class Decision:
    """The outcome of one mediation step. Immutable; safe to hand to the log."""

    decision: str  # ALLOW | BLOCK
    symbol: Symbol
    pre_state: State
    post_state: State
    reason: str

    @property
    def allowed(self) -> bool:
        return self.decision == ALLOW


class Monitor:
    """M_phi: mediates every agent action against A_phi.

    No network. No clock. No filesystem. The decision path is a pure function of
    (phi, q, action), which is what makes L4 log replay reproduce it exactly.
    """

    __slots__ = ("_automaton", "_q")

    def __init__(self, policy: Policy | Automaton) -> None:
        self._automaton = policy if isinstance(policy, Automaton) else Automaton(policy)
        self._q: State = self._automaton.q0

    # --- read-only views ---

    @property
    def automaton(self) -> Automaton:
        return self._automaton

    @property
    def policy(self) -> Policy:
        return self._automaton.policy

    @property
    def state(self) -> State:
        """Current q. A tuple, so the caller holds a value, not a handle."""
        return self._q

    def describe_state(self) -> str:
        return self._automaton.describe_state(self._q)

    def remaining(self) -> dict[str, int]:
        """Headroom per counter. Reporting only; never consulted by delta.

        For a per_target counter (SPEC.md section 2.1b) this reports the
        TIGHTEST remaining headroom across every target touched so far (the
        minimum), since a single number cannot represent |T| independent
        totals. It is advisory only, same as the rest of this method.
        """
        layouts = self._automaton.layouts
        if self._q is BAD:
            return {layout.name: 0 for layout in layouts}
        out: dict[str, int] = {}
        for layout in layouts:
            if layout.per_target:
                out[layout.name] = min(
                    layout.bound - self._q[i] for i in layout.slots.values()
                )
            else:
                out[layout.name] = layout.bound - self._q[layout.slots]
        return out

    # --- mediation ---

    def submit(self, action: ConcreteAction) -> Decision:
        """Mediate one action. The ONLY agent-facing entry point.

        Total: any input a hostile agent can construct yields a Decision rather
        than an exception, because alpha is total and delta is total over the
        symbols alpha produces.
        """
        symbol = self._automaton.alpha(action)
        pre = self._q
        post = self._automaton.delta(pre, symbol)

        if post is BAD:
            # State unchanged. The reason is computed for the human and the log;
            # it is NOT what produced the decision -- delta already did that.
            return Decision(
                decision=BLOCK,
                symbol=symbol,
                pre_state=pre,
                post_state=pre,
                reason=self._explain_block(pre, symbol),
            )

        self._q = post
        return Decision(
            decision=ALLOW,
            symbol=symbol,
            pre_state=pre,
            post_state=post,
            reason="within policy",
        )

    # --- explanation (reporting only) ---

    def _explain_block(self, q: State, symbol: Symbol) -> str:
        """Human-readable cause of a block.

        Advisory text derived by re-checking the same guards delta uses. If this
        function and delta ever disagreed, DELTA IS THE AUTHORITY -- this only
        chooses wording. It reports every guard that fired, because the guards
        are a disjunction and more than one can be true at once.
        """
        automaton = self._automaton
        policy = automaton.policy
        reasons: list[str] = []

        if symbol.verb == BOT_VERB:
            reasons.append("unknown verb (not named anywhere in the policy)")
        if symbol.target == BOT_TARGET:
            reasons.append("unknown target (not named anywhere in the policy)")
        if symbol.amount < 0:
            reasons.append(
                "amount is not a non-negative integer within the policy's largest bound"
            )

        if not symbol.is_sink:
            if policy.is_prohibited(symbol.verb):
                reasons.append(f"{symbol.verb} is prohibited outright")
            whitelist = policy.whitelist_for(symbol.verb)
            if whitelist is not None and symbol.target not in whitelist.allowed:
                reasons.append(
                    f"{symbol.target!r} is not on the whitelist for {symbol.verb}"
                )
            if isinstance(q, tuple):
                for layout in automaton.layouts:
                    if symbol.verb not in layout.verbs:
                        continue
                    idx = (
                        layout.slots[symbol.target]
                        if layout.per_target
                        else layout.slots
                    )
                    increment = 1 if layout.counting else symbol.amount
                    total = q[idx] + increment
                    if total > layout.bound:
                        where = (
                            f" for target {symbol.target!r}" if layout.per_target else ""
                        )
                        reasons.append(
                            f"would take {layout.name}{where} to {total}, "
                            f"over its cap of {layout.bound}"
                        )

        if q is BAD:
            reasons.append("monitor is already in q_bad (absorbing)")
        if not reasons:
            # Unreachable unless delta and this function have diverged. Say so
            # rather than inventing a plausible-sounding cause.
            reasons.append("blocked by the automaton; no guard could be attributed")
        return "; ".join(reasons)
