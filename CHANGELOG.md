# Changelog

All notable changes to the VDP **protocol spec** are documented here. This
tracks `SPEC.md` revisions and the reference implementation's conformance to
them — not ordinary code changes (see git history for those).

Format loosely follows [Keep a Changelog](https://keepachangelog.com/).
Spec revisions are `vdp-spec-MAJOR.MINOR`; this project is pre-1.0, so any
minor revision may include breaking changes to the grammar or wire formats.

## [Unreleased]

One NORMATIVE change to SPEC.md, plus reference-implementation hardening
that does not alter any wire format. No policy, token, or audit record
written under `vdp-spec-0.3` changes shape, so this is not a revision bump —
but the transport rule below is a MUST NOT that a conforming implementation
has to satisfy, and it is recorded here rather than folded silently into
0.3.

- **`now` MUST NOT come from an untrusted peer** (SPEC.md §11.2, new
  paragraph). `Scope.expires_at` (§5.1) is checked against a `now` that
  `Scope.permits` receives as an argument, because nothing in the token layer
  reads a clock. §11.2's request shape carries a `now` field, and the
  reference `MonitorServer` read it straight from the request — so an agent
  holding a token that expired years ago sent `now: 0` and the expiry check
  passed. §7 already says the agent may lie in every field it controls; this
  was such a field, which made `expires_at` bound nothing at all against the
  adversary it is specified for. Demonstrated end to end before fixing.
  `MonitorServer` now reads its own clock by default and ignores the
  request's `now`; the field stays on the wire for compatibility but is not
  believed. `clock=None` restores the old behavior for deterministic tests
  and genuinely trusted peers. A conforming implementation SHOULD read its
  own clock, and one that does not MUST NOT describe `expires_at` as a bound
  against §7's adversary.
- **Plain-language rendering no longer understates a per-target cap**
  (`policy.render.render_english`). It described a per-target counter as "at
  most $100.00 to any one target" and stopped; with three whitelisted
  recipients the policy permits $300.00. `worst_case()` already reported both
  figures as §4 requires, but the rendering is a separate surface that
  `confirm.gate_text` can be asked to show without the preview
  (`require_preview=False`), and it is the one a human actually reads. It now
  states the aggregate too. Global caps are unchanged: their bound already is
  the total.
- **Transport resource bounds** (SPEC.md §11 behavior, no wire change).
  `MonitorServer` gains `max_line_bytes`, `idle_timeout`, and
  `max_connections`. A request line was read with no limit, an accepted
  connection had no timeout, and connection threads were uncapped — none of
  which could let a bad prefix through, but all of which let a hostile local
  peer deny service to the monitor. They refuse earlier and never later, so
  §3.4 is untouched.
- **Audit records are `fsync`ed before `append()` returns**
  (`AuditLog(fsync=True)`, the default). The order is decide, execute, log
  (DESIGN.md §3.3), so a crash in that window previously lost the record of
  an action that had already happened. `AuditLog.verify()` also now reports
  an unparsable line as a finding rather than raising, matching the reasoning
  already documented for the 64-hex digest check.
- **Conformance vectors are executed** (`tests/test_conformance.py`).
  §10 names `spec/conformance/*.vectors.json` as the conformance criterion,
  but nothing read them: the reference implementation could drift from its
  own published fixtures with a green suite. The shipped JSON Schemas in
  `spec/schema/` are now also validated against what `Policy`, `Token`, and
  `Record` actually emit, rather than only checked for being well-formed.
- **The §3.4 independent checker now covers every counter mode.**
  `tests/strategies.py` built `CounterDecl` without `counting` or
  `per_target`, so `policies()` only ever generated vdp-spec-0.2 policies and
  three of the four combinations were never reached by any property test —
  including per-target, the mode that widens `Q` by a factor of `|T|`.
  §3.4's obligation was being met for 0.2 policies only. Both the generator
  and the reference checker now handle all four; the implementation and the
  checker agree across them.
- **§3.4 is now also checked by exhaustive enumeration, not only by
  sampling** (`tests/test_exhaustive.py`). Hypothesis-based property tests
  finding zero counterexamples across a few hundred random draws is
  evidence, not proof. This file constructs every policy in a small fixed
  grid (all four counter-mode combinations crossed with every per-verb
  clause shape) and replays every trace up to length 3 over a small
  alphabet — not a sample of either — comparing the automaton's decision
  against the same independent reference checker at every prefix of every
  trace. ~1.8 million (policy, trace-prefix) comparisons, ~25s, zero
  disagreements. The bounds (|V|=2, |T|=2, amounts and cap bounds in
  {0,1,2}, trace length ≤3) are stated in the module docstring along with
  what is deliberately not covered (a counter over a proper verb subset;
  hostile-typed input, both already exercised by the sampled suite) —
  widening any bound is a one-line change, not attempted by default because
  CI wall-clock is a cost this repository should not spend silently.
- **Packaging and CI.** `pyproject.toml` (zero runtime dependencies, the
  standard-library-only claim expressed in metadata), `py.typed` markers, and
  a workflow running the suite on 3.11–3.13 across Linux and Windows, plus a
  check that the enforcement path imports nothing third-party even when
  `cryptography` is installed.
- **Key management and a deployment checklist** (SECURITY.md). There was no
  guidance for the two keys the token and log guarantees rest on. The
  checklist states plainly that every hardening option is off by default and
  that those defaults are chosen for backward compatibility, not safety.

## [vdp-spec-0.3] — counters, artifact binding, transport, attestation, revocation

Seven additions. All backward compatible at the policy-language and
API level — a policy or integration using none of the new features behaves
exactly as under `vdp-spec-0.2` — but bumping the spec revision because the
policy artifact's and token's **canonical wire shapes** changed
(`version: 1` → `2` for policy artifacts, §2.4; `policy_hash` now required
on tokens, §5.5):

- **Call-counting counters** (SPEC.md §2.1a). `CounterDecl.counting: bool`
  (default `false`). `true` makes a counter advance by 1 per matching
  action instead of by `amount` — same automaton shape (monotone, bounded,
  `q_bad` on overflow), so §3.4's correctness argument is unaffected. Closes
  a real gap: an amount-summing cap does not bound call *count* when zero is
  a legal amount (`read_balance`, `check_status` were previously "unlimited
  number of times" even under a cap). Grammar: `counter <name> over {...}
  counting calls`. `worst_case()` reports such counters in calls, not
  amount, and no longer lists a call-counted verb as unbounded in count.
- **Per-target counters** (SPEC.md §2.1a/§2.1b). `CounterDecl.per_target:
  bool` (default `false`). `true` makes a counter's bound apply
  independently to each target ("at most $100 to any ONE recipient"
  instead of "$100 total across all recipients"). `T` is finite, so this
  widens `Q` by a known finite factor — one state dimension per
  `(counter, target)` pair — rather than making it infinite; the reference
  implementation allocates these as flat slots in the state tuple, keeping
  audit-log serialization unchanged (still a flat list of ints). Grammar:
  `counter <name> over {...} per target`, combinable with `counting calls`.
  `worst_case()` now reports BOTH the per-target maximum and the honest
  aggregate maximum across every reachable target (per-target × target
  count) — reporting only the per-target figure would understate total
  exposure, which is exactly the omission DESIGN.md §4.2 warns against.
- **Tool mapping table binding** (SPEC.md §1.1). `runtime.shim` gains
  `artifact_hash(policy_hash, tools)`, `tool_table_hash(tools)`, and an
  opt-in `AgentShim(..., expected_artifact_hash=...)` construction check.
  Closes a real gap: `policy_hash` covered φ but nothing bound the mapping
  table that decides what an `amount` argument actually MEANS — swapping
  `amount_arg="cents"` for `amount_arg="dollars"` silently authorized 100×
  the confirmed loss without changing `policy_hash` at all. Opt-in and fully
  backward compatible: omitting the new parameter (the default) preserves
  vdp-spec-0.2 behavior exactly.
- **Root token bound to a policy artifact** (SPEC.md §5.1a). `Token` gains
  `policy_hash: str = ""`. Two policies with different caps distributed
  across different counters can produce an IDENTICAL root scope
  (`Scope.root_from_policy` derives only verbs/targets/c_max), so a root
  token minted for one previously verified interchangeably under the other
  given a shared root key — the monitor gate still enforced the real φ, so
  no bound was ever exceeded, but the token itself claimed no specific
  authorization. `mint(key, root, policy_hash=...)` binds it into the root
  HMAC's input (`t_0`), so it cannot be edited post-mint without breaking
  the tag; `verify(key, token, expected_policy_hash=...)` and the shim's
  token gate both check it, but only when a token actually carries a
  non-empty value — an unbound token (`policy_hash: ""`, the `mint()`
  default) behaves exactly as under vdp-spec-0.2. Token wire format (§5.5)
  now REQUIRES the `policy_hash` key regardless of binding, which is why
  this bump is a breaking spec revision rather than a pure addition.
- **Revocation gate** (SPEC.md §5.4a). `AgentShim.revoke(token_id)` /
  `.is_revoked(token_id)`. A third conjunctive gate, same "only ever blocks
  more" shape as `max_total` — safe alongside §3.4's correctness argument
  without modification. Closes the standard macaroon gap (no revocation by
  construction; a leaked token is live until `expires_at`). Revoking a
  parent's `token_id` does NOT revoke an already-attenuated child's (it has
  a different `token_id`); subtree revocation, if needed, is the caller's
  responsibility to track. Pure addition — nothing is ever revoked unless
  `revoke()` is called.
- **Audit log external anchoring** (SPEC.md §6.3). `AuditLog(..., on_append=
  callback)`. Invoked with the new `head` hash after every append, including
  a BLOCK. Makes external-anchor publication a first-class, wireable path
  instead of a property (`AuditLog.head`) nobody was actually calling —
  closing the tail-truncation gap requires the caller to publish `head`
  somewhere the agent cannot write, which this makes easy to do correctly
  rather than easy to forget. The underlying gap (SECURITY.md) remains the
  default: it closes only when `on_append` is actually wired to an
  agent-inaccessible destination.
- **Ed25519 attestation** (SPEC.md §6.4). `runtime.attest.Ed25519Attestor`,
  implementing `Attestor` with asymmetric checkpoint signatures over
  `(policy_hash, log head)`. Gives non-repudiation the audit log's own HMAC
  signature (§6.1) cannot: a verifier holding only the public key can
  confirm a specific issuer vouched for a specific head. Requires the
  optional `cryptography` package, imported lazily only when this class is
  instantiated — the enforcement path stays standard-library-only, and
  `NullAttestor` remains the default. `Attestation.claim` never says
  "proven"; it states the hardness assumption and explicitly disclaims that
  this establishes anything about whether recorded decisions follow from φ
  (that is still §6.2's job, done separately by `AuditLog.verify`).
- **Transport binding** (SPEC.md §11, new). Reference implementation:
  `runtime.server.MonitorServer` / `runtime.client.MonitorClient`, NDJSON
  over TCP loopback. Makes the "monitor outside the agent's control
  surface" rule (DESIGN.md §7.5) an ENFORCED property instead of only an
  architectural one — every other reference module in this repository runs
  in-process with the demo agent. Not a MUST for `vdp-spec-0.3` conformance
  (a spec whose only interface was "call this method" could not have two
  independent implementations talk to each other; this section exists so
  it need not stay that way, without forcing an in-process embedding to
  invent a transport it doesn't need). Only agent-facing outcome fields
  (`allowed`, `reason`, `gate`, `result`, `error`) cross the wire; the root
  key, log key, and `Monitor`/`AuditLog` objects never do. Every decision
  across every connection is serialized through one lock — `Monitor`,
  `AgentShim`, and `AuditLog` are not individually thread-safe, and a
  thread-per-connection model without that lock would have silently broken
  the "single sequential decision stream" assumption §3.4 rests on. An
  earlier single-threaded connection-handling design deadlocked under two
  concurrent clients; found by running the client and server against each
  other, not by review, and fixed before any test existed for it.

## [vdp-spec-0.2] — reference implementation

Five deviations from the 0.1 design, found during implementation and folded
into the spec rather than left as a silent gap between document and code:

- **`T` always contains a `NO_TARGET` sentinel.** §1.2 (0.1) derived `T` from
  whitelists and prohibitions alone. Prohibitions name no targets, so a
  target-less action (`read_balance`, `check_status`) had no legal symbol and
  would have been blocked unconditionally. `T` now always contains the empty
  string, which no whitelist may name.
- **A root token's scope excludes prohibited verbs and carries no
  `max_total`.** `max_total` on a root token would shadow the monitor's own
  cumulative counter rather than compose with it. It now exists solely so a
  parent can hand a child a smaller cumulative allowance out of the shared
  cap. Confirmed by the demo: the salami-slicing attack is refused by the
  monitor, where trace history belongs.
- **`max_total` is enforced by the shim, as a third conjunctive gate.** A
  cumulative bound cannot be decided from a single action. This is not
  monitor state and does not weaken the "no bad prefix" argument — a gate
  that only ever blocks more cannot enlarge the set of executed traces.
- **The audit log is canonicalized ASCII-only.** `ensure_ascii=True` is a
  format requirement, not a style choice: several non-ASCII line-separator
  code points break common line-splitters, and an agent controls the target
  string that could contain one. `Record.from_obj` also validates that hash
  fields are 64-character lowercase hex, so a tampered digest can't turn a
  detection into a crash via `hmac.compare_digest` raising on non-ASCII
  input. Both found by the adversarial fuzzer, not by review.
- **`Outcome.gate` reports which gate refused.** Reporting only, for the
  demo and for operators — the gates are a conjunction, so this names the
  first gate that fired, not the only one that would have.

## [vdp-spec-0.1] — initial design

Original design: finite-alphabet automaton over policy safety fragment,
attenuable HMAC-chained capability tokens, hash-chained audit log, worst-case
reachability preview, human confirmation gate.

---

## Open questions (tracked, not yet resolved)

Carried from DESIGN.md §11. These would be breaking (minor-version) spec
changes if adopted — tracked here instead of as silent TODOs.

1. **Continuous vs. discrete amounts.** The discrete-case DP (§4.1) only pays
   off when a shim's mapping table fixes per-action costs. Worth building
   into a future revision, or wait for a scenario that needs it?
2. **Counter scoping.** v0.1/0.2 has counters over verb sets only.
   Per-target counters ("at most $100 to any one recipient") are a natural
   next form and remain safety properties, but enlarge `Q` to
   `∏(N+1)^|T|`. Deferred.
3. **Expiry.** `expires_at` sits in the token scope, not in φ — wall-clock
   time stays out of the automaton entirely. Confirm this is the intended
   split before building anything that assumes otherwise.
