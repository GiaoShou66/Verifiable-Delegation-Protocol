"""VDP L1 — the human confirmation gate (DESIGN.md section 2.6).

    speech -> [LLM] -> Intent -> render(compile(Intent)) + worst-case preview
                              -> HUMAN CONFIRMS -> policy artifact

The gate sits between compilation and authorization, and the agent cannot reach
it. Nothing here is called by the runtime shim, and nothing here is reachable
from an agent tool call.

--- Why the preview is passed in, not computed here ---

The worst-case analysis lives in L2 (`monitor.worstcase`), because it is
reachability over A_phi. This module takes the already-computed lines as data.
That keeps the layering one-directional (L1 never imports L2) and it means the
gate cannot show a preview that was computed by anything other than the real
automaton.

`require_preview=True` is the default and exists so that a caller cannot show a
policy for authorization WITHOUT its worst case. Authorizing a bound without
seeing what it permits is the failure mode this whole protocol exists to
prevent, so it is refused rather than merely discouraged.

--- What confirmation is, and is not ---

`Confirmation` records that a specific human typed a specific phrase against a
specific policy_hash. It is not a signature and carries no cryptographic weight:
this is a local record, not evidence against a third party. L3 mints the token
that actually authorizes; it takes the policy_hash from here.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Sequence

from policy.compile import CompiledIntent
from policy.render import render_english, render_formal

__all__ = [
    "CONFIRM_PHRASE",
    "Confirmation",
    "ConfirmationError",
    "gate_text",
    "request_confirmation",
]


class ConfirmationError(ValueError):
    """The gate was invoked in a way that would be unsafe to present."""


#: Typed in full, exactly. Not "y", not Enter. A single keystroke is too easy to
#: issue without reading, and the thing being agreed to is a spending authority.
CONFIRM_PHRASE = "AUTHORIZE"


@dataclass(frozen=True, slots=True)
class Confirmation:
    """Record of a human decision at the gate. Immutable.

    Carries no cryptographic weight -- see the module docstring.
    """

    policy_hash: str
    confirmed: bool


def gate_text(
    compiled: CompiledIntent,
    preview_lines: Sequence[str],
    *,
    require_preview: bool = True,
) -> str:
    """Build the exact text shown to the human before authorization.

    Contains, in order: what was refused, the policy in plain language, the
    policy in formal syntax, the computed worst case, and the standing
    disclaimer that VDP bounds behavior rather than guaranteeing success.
    """
    if not isinstance(compiled, CompiledIntent):
        raise ConfirmationError(
            f"expected a CompiledIntent, got {type(compiled).__name__}"
        )
    if isinstance(preview_lines, str):
        raise ConfirmationError(
            "preview_lines must be a sequence of lines, not a string"
        )
    lines = [str(line) for line in preview_lines]
    if require_preview and not lines:
        raise ConfirmationError(
            "refusing to present a policy for authorization without its computed "
            "worst case; compute it with monitor.worstcase and pass it in"
        )

    policy = compiled.policy
    out: list[str] = []

    if compiled.rejected:
        out.append("NOT INCLUDED -- these could not be encoded:")
        for item in compiled.rejected:
            out.append(f'  - "{item.utterance}"')
            out.append(f"      {item.reason}")
        out.append("")

    out.append("YOUR POLICY, IN PLAIN LANGUAGE:")
    out.append(render_english(policy))
    out.append("")
    out.append("THE SAME POLICY, EXACTLY AS ENFORCED:")
    out.append(render_formal(policy))
    out.append("")
    out.append("WORST CASE IF YOU AUTHORIZE THIS:")
    out.extend(f"  {line}" for line in lines)
    out.append("")
    out.append(
        "This is what the agent CAN do, not what it WILL do. VDP keeps the agent "
        "inside these limits. It cannot promise the task succeeds, and it cannot "
        "promise the agent spends less than the worst case above."
    )
    out.append(f"policy_hash: {policy.digest()}")
    return "\n".join(out)


def request_confirmation(
    compiled: CompiledIntent,
    preview_lines: Sequence[str],
    *,
    reader: Callable[[str], str] = input,
    writer: Callable[[str], None] = print,
    require_preview: bool = True,
) -> Confirmation:
    """Show the gate text and collect a decision. Fail-closed.

    Anything other than the exact phrase -- empty input, "y", "yes", EOF, an
    interrupt -- is NOT a confirmation. There is no default-yes path.
    """
    writer(gate_text(compiled, preview_lines, require_preview=require_preview))
    prompt = f"\nType {CONFIRM_PHRASE} to authorize, or anything else to cancel: "
    try:
        answer = reader(prompt)
    except (EOFError, KeyboardInterrupt):
        # No input stream, or the human walked away. Treat as refusal.
        answer = ""
    confirmed = isinstance(answer, str) and answer.strip() == CONFIRM_PHRASE
    if not confirmed:
        writer("Not authorized. No token was minted and no monitor was started.")
    return Confirmation(policy_hash=compiled.policy.digest(), confirmed=confirmed)
