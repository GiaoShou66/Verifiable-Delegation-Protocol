# Security

VDP is designed to give a **strong, narrow** guarantee: "never out of bounds"
(see [DESIGN.md §0](DESIGN.md#0-what-vdp-claims-and-what-it-does-not)). It is
not designed to guarantee task completion, agent honesty, or that the agent
spends less than the authorized worst case. Read this document to know
exactly what a security report against VDP should be about.

## Threat model

**Adversary**: a fully adversarial agent. It may call the runtime boundary
any number of times, in any order, with any arguments; lie in every field it
controls; attempt to mint child tokens with wider caveats; attempt to
replay, reorder, or forge tokens; attempt to write the audit log directly;
attempt to mutate φ or the monitor state; collude with a child agent it
delegated to.

### Trust boundary

| Inside TCB | Outside TCB |
|---|---|
| Monitor process (φ, `A_φ`, `q`) | The agent, and any child agent |
| Policy artifact after human confirmation | The LLM that produces `Intent` |
| Root key `k`, log key `k_log` | Tool arguments, tool results |
| Audit log writer | The executor's downstream service |
| The human's confirmation decision | Everything the agent says about itself |

### Attacks and dispositions

| Attack | Disposition | Rests on |
|---|---|---|
| Exceed spend cap | Blocked: `v_i + amt > N_i → q_bad` | Unconditional |
| Pay non-whitelisted target | Blocked: `target ∉ W → q_bad` | Unconditional |
| Perform prohibited verb | Blocked | Unconditional |
| Unknown or unmapped verb/target | Blocked (`⊥` sinks) | Unconditional |
| Malformed, negative, oversized amount | Blocked (`⊤_amt`) | Unconditional |
| Sub-delegate with wider scope | Caveat is met, not applied; scope narrows | Unconditional |
| Split payment into many small ones | Blocked at the cap; counter is cumulative | Unconditional |
| Hammer with actions it knows will fail | Blocked, state unchanged, attempts logged | Unconditional |
| Forge a token | Blocked by chain verification | **HMAC assumption** |
| Strip a caveat from a held token | Blocked; recomputation needs `k` or `t_{i-1}` | **HMAC assumption** |
| Tamper with the audit log | Detected on replay | **SHA-256 + external anchor** |
| Truncate the log tail | **Not detected** in v0.1 | — (documented gap) |
| Mislead the LLM during intent extraction | Caught, if at all, at the confirmation gate | **Human attention** |

### Explicitly out of scope

- OS-level compromise, memory scraping, debugger attachment, key exfiltration.
- Side channels and timing.
- Bugs in the monitor implementation itself (mitigated by tests, not eliminated).
- Semantic mismatch between what the user *meant* and what φ *says*. The
  confirmation gate is the only defense, and it is a human one.
- Whether the downstream executor honors the decision. VDP decides; it does
  not verify that the bank actually moved the money.

### The in-process caveat, stated plainly

The rule is: *the monitor must be outside the agent's control surface.* In a
real deployment that means a separate process or host, with the agent
reaching it only over a narrow interface exposing `submit()`/`call()` and
nothing else.

**The reference implementation runs the monitor in the same process as the
demo agent.** In-process, "outside the control surface" is an *architectural*
property, not an *enforced* one — nothing at the language level stops code in
that process from reaching into the monitor's attributes. The implementation
mitigates this by exposing no mutation API on the monitor, the policy, or the
log; keeping the agent-facing surface to a single `call()` method; and
keeping policy/AST objects frozen. It does **not** claim memory isolation it
does not have. Process separation is a deployment concern, tracked as a known
gap rather than quietly assumed.

### Known gaps (spec revision 0.3)

- **Audit log tail truncation is undetectable** without an externally-held
  anchor for the latest hash. VDP does not anchor externally by default
  (DESIGN.md §6.3 / §6.4), but `AuditLog(..., on_append=...)` (added in
  spec revision 0.3) lets you wire publication of `head` to somewhere the
  agent cannot write, on every record, without polling for it yourself.
  This closes the gap only if you actually pass `on_append` and the
  destination it publishes to is itself outside the agent's write access —
  the gap remains the default.
- **The audit log signature (`sig`) is symmetric (HMAC)**, so it proves "the
  agent did not forge this," not "the issuer did not forge this." There is
  no non-repudiation guarantee in this revision.
- **External attestation defaults to a stub** (`NullAttestor`). An optional
  `Ed25519Attestor` (spec revision 0.3, requires the `cryptography` package)
  gives non-repudiation for a checkpoint — "this issuer vouched for this log
  head" — to a verifier holding only the public key. It does NOT establish
  that recorded decisions follow from φ (that is still local replay,
  `AuditLog.verify`) and does NOT detect tail truncation between
  checkpoints. `NullAttestor` remains the default; nothing is attested
  unless you explicitly instantiate `Ed25519Attestor` and wire it in.

- **Availability is not part of the guarantee.** The "no bad prefix"
  property (SPEC.md §3.4) says nothing about the monitor still being
  reachable. `runtime.server.MonitorServer` bounds what a hostile local peer
  can consume — `max_line_bytes` (a request line is read with a limit, so a
  peer streaming newline-free bytes cannot grow the read buffer without
  bound), `idle_timeout` (a stalled connection is closed rather than pinning
  a thread), and `max_connections` (concurrent connection threads are
  capped, and connections past the cap are refused with `ok: false`). These
  refuse EARLIER, never later, so they cannot turn a BLOCK into an ALLOW.
  They are defaults, not a claim: a peer that can open sockets in a loop can
  still make the monitor unavailable, and an unavailable monitor means no
  actions are authorized, not that actions proceed unchecked.
- **Token expiry depends on who supplies the clock.** `Scope.expires_at` is
  checked against a `now` passed into `Scope.permits`; nothing in `tokens/`
  reads a clock, by design. `MonitorServer` therefore reads its OWN clock by
  default and ignores the `now` field in the request. If you construct it
  with `clock=None`, or build another transport that believes the peer's
  `now`, then `expires_at` bounds nothing: an agent holding a token that
  expired years ago sends `now: 0` and the check passes. In that
  configuration `expires_at` is a convenience for cooperative callers, not a
  control against the adversary described above.
- **The transport does not authenticate its peer.** Any local process that
  can reach the loopback port can send requests. Holding a token is not
  authorization (SPEC.md §5.3) and both gates still run, so this does not
  widen anyone's authority — but it does mean process-level isolation of the
  monitor's port is the deployer's job, not this module's.
- **A record reaches disk before `append()` returns** (`fsync=True`, the
  default). Without it, the decide → execute → log order (DESIGN.md §3.3)
  means a crash could leave an action that HAPPENED with no record that it
  did. `fsync=False` opts out; anything relying on the log as evidence
  should not.

None of these are silent — each is asserted explicitly in the relevant
module's docstring and in [DESIGN.md §6–7](DESIGN.md).

## Key management

VDP has two symmetric keys, and the guarantees that depend on them are
different. Neither is generated, stored, or rotated for you — this section
says what you must do, because nothing in the code will do it or warn you.

| Key | Guards | If it leaks |
|---|---|---|
| Root key `k` | Token unforgeability (§5.3). Only `mint()` needs it. | An attacker mints root tokens with any scope. The monitor gate still holds — φ is never exceeded — but the token gate is gone. |
| Log key `k_log` | The audit log's `sig` field (§6.1). | An attacker can forge `sig` on records they write. The hash chain still links, so a verifier holding an external anchor still detects tampering; one without it does not. |

**Generation.** Both MUST be at least 32 bytes
(`tokens.macaroon.MIN_KEY_BYTES`; `mint()` and `AuditLog()` refuse shorter
ones). Use a CSPRNG — `secrets.token_bytes(32)`. Do not derive either from a
password, a hostname, a policy hash, or anything else guessable.

**Separation.** Use two independent keys. Reusing one value for both puts the
log's integrity and the tokens' unforgeability behind a single secret, for no
benefit — the domain-separation prefixes (§5.3) stop cross-protocol
reinterpretation, not a shared-key compromise.

**Storage.** `k` MUST NOT be reachable by any agent (§5.3), which in practice
means it never lives in the agent's process, its environment, or any file it
can read. This is the same boundary DESIGN.md §7.5 draws for the monitor
itself, and `runtime.server` is how you enforce it rather than merely assert
it.

**Rotation: there is no mechanism, and that is a real limitation.** No
re-keying path exists. Changing `k` invalidates every outstanding token at
once, including ones already delegated to sub-agents, because verification
recomputes the whole chain from the root. Changing `k_log` makes every
existing `sig` fail to verify; the hash chain still checks, so the log is
readable but its signatures are not. Plan rotation as a policy boundary: new
key, new policy artifact, new log — which the code already pushes you toward,
since `AuditLog` refuses to append to a log written under a different
`policy_hash`.

**Compromise.** If `k` leaks: revoke outstanding `token_id`s you know of
(§5.4a), rotate `k`, and re-mint. Note that revocation does not reach
descendants — an attenuated child has a different `token_id` (§5.4a), so a
subtree you did not enumerate stays live until `expires_at`. If `k_log`
leaks, the log's `sig` values are worthless from that point on; the hash
chain and any external anchor you published are what remain.

## Deployment checklist

Every item here is OFF by default, and the defaults are chosen for backward
compatibility, not for safety. A deployment that skips these is running a
weaker system than this repository describes, silently.

- [ ] **Bind the root token to the policy artifact.** `mint(k, scope)`
      defaults to `policy_hash=""` — unbound. Pass `policy.digest()`, and
      have the verifier require it. Unbound tokens verify interchangeably
      between two policies that produce the same root scope (§5.1a).
- [ ] **Assert the tool mapping table.** Pass `expected_artifact_hash=` to
      `AgentShim`. `policy_hash` alone does not cover the table that decides
      what an `amount` argument MEANS — swapping `cents` for `dollars`
      authorizes 100× the confirmed loss without changing `policy_hash`
      (§1.1).
- [ ] **Wire an external anchor.** Pass `on_append=` to `AuditLog` and
      publish each `head` somewhere the agent cannot write. Without it, tail
      truncation is undetectable, and `verify()` will keep telling you so.
- [ ] **Run the monitor out of process.** Use `runtime.server.MonitorServer`
      / `runtime.client.MonitorClient`. In-process is an architectural
      separation, not an enforced one (DESIGN.md §7.5).
- [ ] **Isolate the monitor's port.** The transport does not authenticate its
      peer: any local process that can reach the loopback port can send
      requests. Both gates still run, so this widens nobody's authority — but
      restricting who can reach the port is your job, not the module's.
- [ ] **Let the server keep time.** Leave `MonitorServer`'s `clock` at its
      default. With `clock=None` the agent's own `now` decides expiry, and
      `expires_at` stops being a bound.
- [ ] **Leave `fsync=True`.** The order is decide, execute, log; without the
      sync a crash can lose the record of an action that already happened.
- [ ] **Keep both keys off the agent's side of the boundary.** See above.

## Reporting a vulnerability

If you find a way to violate the "never out of bounds" guarantee — an
executed action that is a bad prefix of the confirmed policy, a token whose
effective scope is not a subset of its parent's, or a way to make the audit
log accept a tampered record as valid *within the stated threat model above*
— please report it privately rather than opening a public issue.

Open a GitHub security advisory on this repository (**Security → Report a
vulnerability**), or contact the maintainers directly if advisories are not
yet enabled. Include:

- the policy artifact (or a minimal reproduction) and the action sequence,
- which guarantee in [SPEC.md §7](SPEC.md#7-threat-model-summary--see-designmd-7-and-securitymd-for-full-discussion)
  or this document you believe was violated,
- whether the break is unconditional or depends on a cryptographic
  assumption you can also break.

Reports about the *documented* gaps above (log truncation, HMAC
non-repudiation, attestation) are welcome as design discussion but are not
novel findings — please open a regular issue for those instead.

We have no bug bounty program at this time.
