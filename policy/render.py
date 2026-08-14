"""VDP L1 — rendering phi back to text (DESIGN.md section 2.4).

Two renderers, with different contracts:

- `render_formal(phi)` emits section 2.2 syntax and MUST round-trip:
  `parse(render_formal(phi)) == phi`. Tested.
- `render_english(phi)` is one-way, for humans. It is deliberately NOT parseable
  back, so no one is tempted to treat prose as a source of truth.

Both render the SAME object the monitor enforces. There is no parallel
description that could drift from phi.

--- Honesty rule ---

`render_english` names every verb in V exactly once, including verbs that are
neither capped nor whitelisted. Those are UNBOUNDED IN COUNT and are stated as
such. Omitting them would be the most misleading thing this renderer could do
(DESIGN.md section 4.2), so the omission is structurally impossible here: the
listing iterates over V, not over the clause list.
"""

from __future__ import annotations

import json

from policy.ast import Cap, NO_TARGET, Policy, Whitelist

__all__ = ["render_english", "render_formal", "format_amount"]


def format_amount(amount: int, unit: str | None) -> str:
    """Human display of a minor-unit integer.

    Integer arithmetic only — no float ever touches a monetary value, not even
    for display, so a rendered amount can never disagree with the bound the
    monitor enforces.
    """
    if unit == "cents":
        sign = "-" if amount < 0 else ""
        whole, frac = divmod(abs(amount), 100)
        return f"{sign}${whole:,}.{frac:02d}"
    if unit is None:
        return f"{amount:,}"
    return f"{amount:,} {unit}"


def _quote(value: str) -> str:
    """Emit a target as a grammar-legal double-quoted string."""
    return json.dumps(value, ensure_ascii=False)


def render_formal(policy: Policy) -> str:
    """Emit phi in the section 2.2 concrete syntax. Round-trips through `parse`."""
    lines: list[str] = []
    for decl in policy.counters:
        verbs = ", ".join(sorted(decl.verbs))
        lines.append(f"counter {decl.name} over {{{verbs}}}")
    if policy.counters:
        lines.append("")

    rendered: list[str] = []
    for clause in policy.clauses:
        if isinstance(clause, Cap):
            unit = f" {clause.unit}" if clause.unit else ""
            rendered.append(f"always({clause.counter} <= {clause.bound}{unit})")
        elif isinstance(clause, Whitelist):
            allowed = ", ".join(_quote(t) for t in sorted(clause.allowed))
            rendered.append(f"always({clause.verb}(target) -> target in {{{allowed}}})")
        else:
            rendered.append(f"always(not {clause.verb})")

    lines.append("\nand ".join(rendered))
    return "\n".join(lines)


def _cap_limits(policy: Policy, verb: str) -> list[str]:
    out: list[str] = []
    for decl in policy.counters_for_verb(verb):
        cap = policy.cap_for(decl.name)
        if cap is None:  # unreachable: the AST rejects an uncapped counter
            continue
        shared = sorted(decl.verbs - {verb})
        together = f", shared with {', '.join(shared)}" if shared else ""
        out.append(
            f"at most {format_amount(cap.bound, cap.unit)} in total"
            f' (running total "{decl.name}"{together})'
        )
    return out


def render_english(policy: Policy) -> str:
    """One-way plain-language rendering of phi, for the human to re-read.

    States allowances, prohibitions, and — critically — which verbs carry no
    bound at all.
    """
    allow_lines: list[str] = []
    forbid_lines: list[str] = []

    for verb in sorted(policy.verbs):
        if policy.is_prohibited(verb):
            forbid_lines.append(f"  - {verb}: never, under any circumstance.")
            continue

        limits = _cap_limits(policy, verb)

        whitelist = policy.whitelist_for(verb)
        if whitelist is not None:
            names = ", ".join(sorted(whitelist.allowed))
            limits.append(f"only these targets ({len(whitelist.allowed)}): {names}")
        else:
            limits.append("any target this policy knows of (no target restriction)")

        if not policy.counters_for_verb(verb):
            limits.append("no limit on how many times, and no limit on amount")

        allow_lines.append(f"  - {verb}: " + "; ".join(limits) + ".")

    parts: list[str] = []
    if allow_lines:
        parts.append("You allow:")
        parts.extend(allow_lines)
    if forbid_lines:
        parts.append("You forbid:")
        parts.extend(forbid_lines)

    known = sorted(t for t in policy.targets if t != NO_TARGET)
    if known:
        parts.append(
            "Any target not named above is unknown to this policy and is blocked."
        )
    else:
        parts.append("This policy names no targets; every targeted action is blocked.")

    return "\n".join(parts)
