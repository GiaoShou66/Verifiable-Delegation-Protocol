"""VDP demo — an elderly-user payment agent, end to end.

    speech -> [LLM] -> Intent -> compile -> phi
                                     |
                                     +-> worst-case preview
                                     |
                                HUMAN CONFIRMS
                                     |
                              mint root token
                                     |
                    agent tool call -> shim -> monitor -> bank
                                              |
                                        audit log (hash-chained)

Run it:  python -m demo.payment_agent

--- What is real here and what is simulated ---

REAL: the policy compiler, the automaton, the mediation loop, the worst-case
analyzer, the token chain, the shim, and the audit log. Every decision below is
made by the same code the tests exercise.

SIMULATED: the LLM (a canned intent object -- the model is outside the TCB, so
substituting a fixed answer changes no guarantee), the human at the gate (a
scripted "AUTHORIZE"), and the bank (an in-memory dict).

--- The in-process caveat ---

The monitor runs in THIS process, alongside the agent. That is an architectural
separation, not an enforced one. See DESIGN.md 7.5 and `runtime/shim.py`.
"""

from __future__ import annotations

import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Mapping

from monitor.mediate import Monitor
from monitor.worstcase import worst_case
from policy.ast import Policy
from policy.compile import compile_intent
from policy.confirm import CONFIRM_PHRASE, request_confirmation
from runtime.auditlog import AuditLog
from runtime.shim import AgentShim, ToolSpec, artifact_hash
from tokens.macaroon import Token, mint
from tokens.scope import Scope

__all__ = [
    "COST_MODEL",
    "DEMO_INTENT",
    "LOG_KEY",
    "RECIPIENTS",
    "ROOT_KEY",
    "SPOKEN_REQUEST",
    "Session",
    "TOOLS",
    "authorize",
    "bank_ledger",
    "main",
    "run_errands",
]

#: What the person said. Free-form, ambiguous, and containing one wish VDP
#: cannot encode -- which is the point of the `rejected` list below.
SPOKEN_REQUEST = (
    "You can pay my bills for me. Only the electric company, the pharmacy, and "
    "the grocer -- nobody else. Don't spend more than five hundred dollars "
    "altogether. Never close my account. And make sure the electric bill "
    "actually gets paid on time."
)

RECIPIENTS = ("alice_utility", "bob_pharmacy", "carol_grocer")

#: What an LLM returns for that speech. Canned here: the model is outside the
#: TCB, and the confirmation gate is what makes this layer safe, not the
#: model's care. Note the liveness wish landing in `rejected` rather than being
#: approximated into a clause.
DEMO_INTENT: dict = {
    "counters": [{"name": "spend", "verbs": ["pay"], "bound": 50000, "unit": "cents"}],
    "whitelists": [{"verb": "pay", "allowed": list(RECIPIENTS)}],
    "prohibitions": [{"verb": "delete_account"}],
    "rejected": [
        {
            "utterance": "make sure the electric bill actually gets paid on time",
            "reason": (
                "This cannot be enforced by monitoring. A monitor sees a finite "
                "prefix of behavior; no finite prefix can ever witness that "
                "something has FAILED to happen eventually, so there is nothing "
                "for the monitor to block. VDP can stop the agent from doing the "
                "wrong thing. It cannot make the agent do the right thing."
            ),
        }
    ],
}

#: The mapping table: tool name -> alphabet symbol. Part of the policy artifact
#: and NOT agent-writable. A tool absent from this table is unmappable and
#: therefore blocked.
TOOLS: dict[str, ToolSpec] = {
    "pay_bill": ToolSpec(verb="pay", target_arg="recipient", amount_arg="cents"),
    "close_account": ToolSpec(verb="delete_account"),
}

#: Demo keys. In a deployment these live with the issuer and the monitor, never
#: in a repository and never anywhere the agent can read them.
ROOT_KEY = b"vdp-demo-root-key-not-a-secret!!"
LOG_KEY = b"vdp-demo-log-key-also-not-secret"

#: Fixed prices would let the analyzer report a TIGHTER bound than the cap.
#: This demo leaves it None: the agent may choose any amount, so L_max is the
#: cap itself, and the preview says which case applied.
COST_MODEL = None


@dataclass(frozen=True, slots=True)
class Session:
    """Everything an authorized delegation consists of. Immutable."""

    policy: Policy
    monitor: Monitor
    shim: AgentShim
    token: Token
    log: AuditLog
    ledger: dict


def bank_ledger() -> dict:
    """A fake bank. Executes only what the shim has already allowed."""
    return {name: 0 for name in RECIPIENTS}


def authorize(
    log_path: str | Path,
    *,
    writer: Callable[[str], None] = print,
    reader: Callable[[str], str] | None = None,
    intent: Mapping | None = None,
) -> Session | None:
    """Run the full authorization pipeline. Returns None if the human declines.

    `reader` defaults to a scripted "AUTHORIZE". In a deployment it is a person
    reading the preview -- and nothing downstream exists until they type it.
    """
    compiled = compile_intent(dict(intent) if intent is not None else DEMO_INTENT)
    policy = compiled.policy

    # The preview is computed by reachability over the REAL automaton, so the
    # human cannot be shown a bound that differs from the one enforced.
    preview = worst_case(policy, cost_model=COST_MODEL)

    writer("THE PERSON SAID:")
    writer(f"  {SPOKEN_REQUEST}\n")

    confirmation = request_confirmation(
        compiled,
        preview.lines(),
        reader=reader if reader is not None else (lambda _prompt: CONFIRM_PHRASE),
        writer=writer,
    )
    if not confirmation.confirmed:
        return None

    monitor = Monitor(policy)
    log = AuditLog(log_path, policy.digest(), LOG_KEY)
    ledger = bank_ledger()

    def executor(tool_name: str, args: Mapping) -> str:
        # Reached ONLY after both gates have allowed the action.
        recipient = args.get("recipient")
        cents = args.get("cents", 0)
        ledger[recipient] = ledger.get(recipient, 0) + cents
        return f"paid {recipient} {cents} cents"

    # Bind the shim to the EXACT tool table shown at confirmation (SPEC.md
    # section 1.1) -- an integrator who wires up a different table (e.g. a
    # typo'd amount_arg that silently changes what "amount" means) is refused
    # here rather than authorized under the wrong meaning.
    expected = artifact_hash(policy.digest(), TOOLS)
    shim = AgentShim(
        monitor, TOOLS, log, ROOT_KEY, executor=executor,
        expected_artifact_hash=expected,
    )
    # Bind the root token to THIS policy artifact (SPEC.md section 5.1a), not
    # just to a root key: two policies can share an identical root scope, and
    # an unbound token would verify under either.
    token = mint(ROOT_KEY, Scope.root_from_policy(policy), policy_hash=policy.digest())

    writer("\nAUTHORIZED.")
    writer(f"  policy_hash:   {policy.digest()}")
    writer(f"  artifact_hash: {shim.artifact_hash}")
    writer(f"  root token:    {token.token_id()[:16]}...")
    writer(f"  scope:         {token.scope.describe()}")
    return Session(
        policy=policy, monitor=monitor, shim=shim, token=token, log=log, ledger=ledger
    )


def run_errands(session: Session, *, writer: Callable[[str], None] = print) -> None:
    """A well-behaved agent doing the job it was delegated."""
    writer("\nAGENT ACTS:")
    for recipient, cents in (
        ("alice_utility", 12_450),
        ("bob_pharmacy", 3_200),
        ("carol_grocer", 8_900),
    ):
        outcome = session.shim.call(
            "pay_bill", {"recipient": recipient, "cents": cents}, session.token
        )
        verdict = "ALLOW" if outcome.allowed else f"BLOCK ({outcome.reason})"
        writer(f"  pay_bill {recipient:<14} {cents:>7} -> {verdict}")
    writer(f"  remaining: {session.shim.remaining()}")


def main(argv: list[str] | None = None) -> int:
    from monitor.automaton import Automaton

    with tempfile.TemporaryDirectory(prefix="vdp-demo-") as tmp:
        log_path = Path(tmp) / "audit.jsonl"
        session = authorize(log_path)
        if session is None:
            print("Not authorized. Nothing was minted and nothing was started.")
            return 1

        run_errands(session)

        print("\nAUDIT LOG:")
        result = session.log.verify(Automaton(session.policy))
        print("  " + result.summary().replace("\n", "\n  "))
        print(f"  head: {session.log.head[:16]}...")
        print(f"  bank ledger: {session.ledger}")
        print(
            "\nVDP kept the agent inside the authorized bounds. It did NOT promise "
            "the errands were done well, or done at all."
        )
    return 0


if __name__ == "__main__":  # pragma: no cover - manual entry point
    raise SystemExit(main())
