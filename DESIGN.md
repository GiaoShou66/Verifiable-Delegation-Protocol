# VDP — Verifiable Delegation Protocol

**Design document. Revision 0.1. No implementation code exists yet.**

Implementation language: **Python 3.11+**, standard library only for the enforcement path
(`hmac`, `hashlib`, `json`). Test-only dependencies: `pytest`, `hypothesis`.
Rationale: the monitor's decision path must have no network dependency and few moving
parts; the standard library gives us HMAC-SHA256 and canonical JSON without pulling a
supply chain into the trusted computing base.

---

## 0. What VDP claims, and what it does not

VDP guarantees **"never out of bounds."**

> For every finite sequence of actions the agent actually executes, that sequence is not a
> bad prefix of the authorized policy φ.

VDP does **not** guarantee, and no part of this system will ever be built to imply:

- that the delegated task completes,
- that the agent behaves usefully,
- that the agent spends *less* than the authorized worst case,
- that the agent is honest about its intentions.

The agent is assumed adversarial. If a policy authorizes up to 500 units of loss, a
malicious agent will lose exactly 500 units and VDP will consider that a success. This is
why the **worst-case preview** exists: the human authorizes a number they have seen
computed, not a promise they have been given.

**Deliberately excluded features** (each would imply a liveness or best-effort guarantee
VDP cannot make): retries, task-completion tracking, agent reputation, anomaly scoring,
"reasonable spend" heuristics, rollback, refunds.

---

## 1. Actions and the alphabet Σ

### 1.1 Concrete action

The runtime shim intercepts an agent tool call and normalizes it to:

```
ConcreteAction = (verb: str, target: str, amount: int, attrs: dict)
```

- `verb` — what is being done. Free string at the boundary.
- `target` — the entity acted upon (recipient account, device, record ID). Free string.
- `amount` — a non-negative integer in **minor units** (cents, watt-hours, bytes). Never a
  float. Actions with no resource cost carry `amount = 0`.
- `attrs` — carried for the audit log and for the executor. **Not visible to the
  automaton.** Anything that must affect a decision has to be lifted into `verb`, `target`,
  or `amount` by the shim's mapping table, which is part of the policy artifact and is not
  agent-writable.

### 1.2 Abstraction to a finite alphabet

A policy φ declares a finite verb universe `V` and a finite target universe `T` (the union
of every whitelist and prohibition named in φ). Amounts are saturated at the largest
counter bound `C_max = max{N_i}` appearing in φ.

```
Σ  =  (V ∪ {⊥_verb})  ×  (T ∪ {⊥_target})  ×  ({0, 1, …, C_max} ∪ {⊤_amt})
```

The abstraction function:

```
α(verb, target, amount, attrs) =
    ( verb   if verb   ∈ V else ⊥_verb,
      target if target ∈ T else ⊥_target,
      amount if 0 ≤ amount ≤ C_max else ⊤_amt )
```

α is total and deterministic. `⊥_verb`, `⊥_target`, `⊤_amt` are the **fail-closed sinks**:
any symbol containing one of them transitions directly to `q_bad`, so an unrecognized verb,
an unknown recipient, a negative amount, a non-integer amount, or an amount larger than any
bound in the policy is *blocked*, not allowed. Malformed input that cannot even be
normalized into a `ConcreteAction` is likewise blocked without consulting the automaton.

Σ is finite, so `A_φ` is a genuine DFA and the standard safety/bad-prefix argument applies
verbatim. Σ is also large (`|Σ| = (|V|+1)(|T|+1)(C_max+2)`), so δ is **never materialized as
a table** — it is evaluated symbolically per symbol. This is a representation choice; it
does not change the automaton's semantics.

### 1.3 Why amounts are in the alphabet rather than in a side channel

Putting the amount inside the symbol keeps `A_φ` a plain DFA over a finite alphabet instead
of a register automaton or counter machine, which would require a separate (and weaker)
theory. The cost is a conceptually large Σ. The benefit is that the induction proof in §3.4
is the textbook one, with no extra hypotheses.

---

## 2. Policy language

### 2.1 Fragment

φ is restricted to the **safety fragment of LTL plus monotone resource counters**. Exactly
three atomic forms, plus conjunction:

| Form | Meaning | Memory |
|---|---|---|
| `always(counter C <= N)` | cumulative sum of `amount` over actions in `C`'s scope never exceeds `N` | stateful |
| `always(verb(target) -> target in W)` | whenever `verb` occurs, its target is in whitelist `W` | memoryless |
| `always(not verb)` | `verb` never occurs | memoryless |

Conjunction is closed in the fragment: an intersection of safety properties is a safety
property, and the product of their monitors is the monitor of the conjunction. Composition
therefore needs no special case.

**Counters are monotone non-decreasing.** No refunds, no decrement, no reset, no time
window in v0.1. This is required for both the finiteness of Q (§3.1) and the correctness of
the worst-case analysis (§4). Sliding-window and decrementing counters are a real extension
but they change the theory and are explicitly out of scope for this revision.

### 2.2 Grammar

```ebnf
policy      ::= decls clause ( "and" clause )*

decls       ::= ( "counter" ident "over" verbset )*
                                    (* which verbs contribute to which counter  *)

clause      ::= cap | whitelist | prohibition

cap         ::= "always" "(" ident "<=" integer unit? ")"
                                    (* ident names a counter declared in decls  *)

whitelist   ::= "always" "(" ident "(" "target" ")" "->" "target" "in" set ")"

prohibition ::= "always" "(" "not" ident ")"

verbset     ::= "{" ident ( "," ident )* "}"
set         ::= "{" string ( "," string )* "}"

unit        ::= ident                (* display only; never affects semantics    *)
integer     ::= [0-9]+               (* minor units, non-negative                *)
ident       ::= [a-z][a-z0-9_]*
```

Concrete example (the demo policy):

```
counter spend over {pay}

always(spend <= 50000 cents)
and always(pay(target) -> target in {"alice_utility", "bob_pharmacy", "carol_grocer"})
and always(not delete_account)
```

### 2.3 AST

```
Policy       = { counters: [CounterDecl], clauses: [Clause] }
CounterDecl  = { name: str, verbs: frozenset[str] }
Cap          = { counter: str, bound: int, unit: str|None }
Whitelist    = { verb: str, allowed: frozenset[str] }
Prohibition  = { verb: str }
```

The AST is immutable (frozen dataclasses). There is no mutation API on `Policy` and none
will be added; a changed policy is a new policy artifact that requires a new human
authorization.

### 2.4 Plain-language rendering

Every `Policy` renders back to English, and the renderer is the *same object* the monitor
enforces — not a parallel description that can drift:

```
You allow:
  • Paying at most $500.00 in total.
  • Paying only these recipients: alice_utility, bob_pharmacy, carol_grocer.
You forbid:
  • Deleting the account, ever.
```

Round-trip test: `parse(render_formal(φ)) == φ`, where `render_formal` emits §2.2 syntax.
The English rendering above is one-way by design (it is for humans, not for the parser).

### 2.5 Structured intent, and the liveness rejection

Free-form user speech is turned into a **structured intent object** by an LLM. That LLM is
**outside the trusted computing base**. It is a convenience layer, and the human
confirmation step (§2.6) is what makes it safe, not the model's care.

```
Intent = {
  counters:     [ {name, verbs[], bound, unit} ],
  whitelists:   [ {verb, allowed[]} ],
  prohibitions: [ {verb} ],
  rejected:     [ {utterance, reason} ]    # liveness / unsupported, surfaced to the user
}
```

The prompt constrains the model to this schema and instructs it to place anything it cannot
express — "make sure it actually books the ticket", "always reply within an hour",
"eventually pay the bill" — into `rejected` with a reason, rather than approximating it.

Two layers of defense, and they are not equally strong:

1. **Best-effort (LLM):** the model classifies liveness utterances into `rejected`. This can
   fail. It is not a guarantee.
2. **Sound (compiler):** the AST has *no constructor* for `eventually`, for response
   patterns (`always(p -> eventually q)`), or for any unbounded-obligation form. There is no
   syntax to express them and no code path that could emit them. A liveness property
   therefore cannot be compiled into φ regardless of what the LLM does.

The user-visible rejection message states the reason plainly, e.g.:

> "Eventually books the ticket" cannot be enforced by monitoring. A monitor sees a finite
> prefix of behavior; no finite prefix can ever witness that something has *failed* to
> happen eventually, so there is nothing for the monitor to block. VDP can stop the agent
> from doing the wrong thing. It cannot make the agent do the right thing.

### 2.6 Human confirmation gate

Compilation from `Intent` to `Policy` is a pure function. Between it and authorization sits
a mandatory gate the agent cannot reach:

```
speech → [LLM] → Intent → show render(compile(Intent)) + worst-case preview
                                 → HUMAN CONFIRMS → signed Policy artifact
```

The human sees the rendered policy (§2.4) *and* the computed worst case (§4) before
authorizing. Unconfirmed intents produce no token and no monitor.

---

## 3. Monitor synthesis

### 3.1 States

For a policy with counters `c_1 … c_k` and bounds `N_1 … N_k`:

```
Q        =  ( {0..N_1} × … × {0..N_k} )  ∪  { q_bad }
q₀       =  (0, …, 0)
F_bad    =  { q_bad }
```

Q is finite because each counter is bounded above by its own `N_i` and is monotone
non-decreasing (§2.1); a valuation that would exceed `N_i` is not a state, it *is* `q_bad`.
The memoryless clauses (whitelist, prohibition) contribute no state components — they are
pure guards on the transition. `q_bad` is absorbing.

`|Q| = ∏(N_i + 1) + 1`, which is large but never enumerated (§1.2). The monitor's runtime
state is the tuple of counter valuations: a few machine words.

### 3.2 Transition function

For `q = (v_1, …, v_k)` and symbol `a = (verb, target, amt)`:

```
δ(q, a) = q_bad   if  verb   = ⊥_verb                      (unknown verb — fail closed)
        | q_bad   if  target = ⊥_target                    (unknown target — fail closed)
        | q_bad   if  amt    = ⊤_amt                       (out-of-range amount — fail closed)
        | q_bad   if  ∃ Prohibition(verb)                  (hard prohibition)
        | q_bad   if  ∃ Whitelist(verb, W) ∧ target ∉ W    (whitelist violation)
        | q_bad   if  ∃ i. verb ∈ counters[i].verbs ∧ v_i + amt > N_i   (cap exceeded)
        | (v_1', …, v_k')  otherwise, where
              v_i' = v_i + amt   if verb ∈ counters[i].verbs
                   = v_i         otherwise

δ(q_bad, a) = q_bad    for all a                            (absorbing)
```

δ is total and deterministic: every `(q, a)` pair has exactly one image, and the guards form
a disjunction, not a precedence chain — any one guard firing yields `q_bad`.

### 3.3 Mediation loop

```
def submit(q, concrete_action):
    a  = α(concrete_action)         # total; may yield a fail-closed symbol
    q2 = δ(q, a)
    if q2 in F_bad:
        return BLOCK, q             # state unchanged — a block is not a state transition
    return ALLOW, q2
```

The monitor state advances **only** on allow. A blocked action leaves no trace in `q`, so a
hostile agent cannot drive the monitor toward a bound by issuing actions it knows will be
refused. Blocked attempts *are* recorded in the audit log (§6) — they are evidence, not
state.

Execution order is: decide, then execute, then log. If execution fails after an allow, the
counter has already advanced. That is deliberate and conservative — it can only under-spend
the authorization, never over-spend it. VDP does not roll the counter back, because rollback
is exactly the kind of "make it work" feature that would break the guarantee.

### 3.4 Correctness argument

**Claim.** Let `σ = a_1 … a_n` be the sequence of actions the monitor *allowed*. Then no
prefix of σ is a bad prefix of φ.

**Proof.** By induction on n.

- *Base.* `n = 0`. The empty trace sits at `q₀ ∉ F_bad`. Nothing has happened; φ is not yet
  violated.
- *Step.* Assume after `a_1 … a_{n-1}` the monitor is at `q_{n-1} ∉ F_bad`, and that being
  in a non-bad state means the trace so far is not a bad prefix. That correspondence is the
  defining property of the bad-prefix automaton, which `A_φ` is by construction in §3.2 —
  each guard is exactly the negation of one conjunct of φ evaluated against the trace so
  far. The monitor admits `a_n` only when `δ(q_{n-1}, a_n) ∉ F_bad`, and it sets
  `q_n = δ(q_{n-1}, a_n)`. So `q_n ∉ F_bad`, and `a_1 … a_n` is not a bad prefix. ∎

Bad prefixes are extension-closed: once a trace is bad, every extension of it is bad.
Contrapositive: if the current trace is not bad, no prefix of it is. This is why checking
only the current state suffices, and it is why `q_bad` must be absorbing.

**This argument is unconditional.** It rests on no cryptographic assumption. It rests on:
δ being total and deterministic; α being total; `F_bad` being absorbing; and the
implementation matching §3.2 — which is what the property-based tests exercise, using a
reference checker written independently of the automaton.

---

## 4. Worst-case preview (reachability)

Before authorization, compute — over *all* traces `A_φ` would allow, not over any predicted
agent behavior — the maximum of each bounded resource.

### 4.1 Maximum loss `L_max`

For counter `c_i` with bound `N_i`, let `D_i` be the set of per-action amounts the agent can
choose for verbs in `counters[i].verbs`:

- **Continuous case** — the agent may choose any integer amount (the normal case for
  payments). Every value `0 … N_i` is reachable, so `L_max(i) = N_i`.
- **Discrete case** — the shim's mapping table fixes a finite set of costs
  `D_i = {d_1, …, d_m}` (fixed-price actions, per-unit device costs). Then

  ```
  L_max(i) = max { Σ x_j·d_j  :  x_j ∈ ℕ,  Σ x_j·d_j ≤ N_i }
  ```

  This is the unbounded-knapsack / coin-reachability problem. Solved exactly by a DP over
  `0 … N_i` in `O(N_i · |D_i|)`. It can be strictly less than `N_i`: with `D = {300}` and
  `N = 500`, `L_max = 300`, and the human should be told 300, not 500.

The analyzer reports which case applied, because "≤ 500 because that is your cap" and
"≤ 300 because nothing you allow adds up past it" are different facts, and the second is
fragile — it changes if the mapping table changes.

### 4.2 Other bounded resources

- **Distinct counterparties** — `|W|` for each whitelist clause. Reported as "recipients
  limited to 3 entities."
- **Impossible actions** — every `always(not v)` clause, and more strongly every verb in `V`
  that no clause permits. Reported as "account deletion impossible."
- **Unbounded dimensions** — any verb with no cap and no whitelist is *unbounded in count*.
  This must be surfaced honestly: "read_balance: unlimited number of times." Silently
  omitting unbounded dimensions from the preview would be the single most misleading thing
  this system could do.

### 4.3 Preview sentence

```
You are authorizing:
  worst case loss ≤ $500.00 (your cap);
  recipients limited to 3 entities;
  account deletion impossible;
  balance checks: unlimited.
This is what the agent CAN do, not what it WILL do. VDP cannot promise the task succeeds.
```

---

## 5. Attenuable capability tokens (L3)

### 5.1 Scope as a lattice

A scope is a record of typed fields, each drawn from a meet-semilattice:

| Field | Domain | Meet (⊓) | Ordering (⊆) |
|---|---|---|---|
| `verbs` | finite set | set intersection | subset |
| `targets` | finite set | set intersection | subset |
| `max_amount` | ℕ ∪ {∞} | `min` | `≤` |
| `max_total` | ℕ ∪ {∞} | `min` | `≤` |
| `expires_at` | ℕ ∪ {∞} | `min` | `≤` |

Scope ordering is pointwise: `S ⊆ S'` iff every field of `S` is below the corresponding
field of `S'`. `expires_at` is an integer Unix epoch second — no formatted date strings and
no timezone parsing anywhere in the decision path.

### 5.2 Attenuation and the monotonicity claim

```
attenuate(S, C)  =  S ⊓ C
```

`⊓` is a greatest lower bound, so `S ⊓ C ⊆ S` by definition of meet, for *every* `C`
whatsoever — including a hostile, malformed, or wider-looking one. A caveat demanding
`max_amount = 10^9` meets with the parent's `500` to give `500`. There is no code path in
`attenuate` that can produce a value above the parent's, because there is no operation
available other than `⊓`.

By induction on delegation depth: `S_n = S_0 ⊓ C_1 ⊓ … ⊓ C_n ⊆ S_0`.

**This claim is unconditional and set-theoretic.** It does not depend on HMAC, on the agent
being honest, or on caveat validation.

### 5.3 HMAC chain

```
t_0 = HMAC-SHA256(k,       canonical(S_0))
t_i = HMAC-SHA256(t_{i-1}, canonical(C_i))
```

`k` is the root key, held by the monitor/issuer only. `canonical()` is deterministic JSON
(sorted keys, no whitespace, integers only) so that serialization is not a malleability
surface.

A presented token is `(S_0, [C_1 … C_n], t_n)`. Verification recomputes the chain from `S_0`
and the caveat list using `k`, and compares with `hmac.compare_digest`. A holder of `t_n`
cannot strip `C_n` to widen its scope, because recomputing `t_{n-1}` requires `k` (or
knowledge of `t_{n-1}`, which a downstream-only holder does not have).

**This is conditional on the HMAC-SHA256 assumption** (PRF / existential unforgeability) and
on `k` staying secret. If `k` leaks, an attacker mints whatever it likes. Note also that a
*parent* obviously still holds its own broader token; that is its own authority being used,
not an escalation, and VDP does not attempt to prevent it.

### 5.4 Tokens and the monitor are independent gates

A valid token is necessary, not sufficient. Both must pass:

1. the token verifies and the action lies within `S_n`, **and**
2. the monitor allows the action from the current `q`.

Either failing blocks. The token binds *scope*; the monitor binds *trace history* (the
cumulative counter). A token cannot encode "you have already spent 400" — that is monitor
state, and it lives outside the agent's reach.

---

## 6. Proof-carrying actions and the audit log (L4)

### 6.1 Record

Append-only JSONL, one canonical-JSON object per line:

```
Record = {
  seq, action, symbol, pre_state, post_state, decision,   # decision ∈ {ALLOW, BLOCK}
  token_id, policy_hash, prev_hash, hash, sig
}
```

- `hash_i = SHA256(prev_hash ‖ canonical(record_i without hash and sig))`
- `hash_0` chains from a genesis constant that includes `policy_hash`, binding the log to
  the exact policy it was produced under.
- `sig = HMAC-SHA256(k_log, hash_i)`.
- Ordering comes from `seq` and the chain, not from wall-clock time. No timestamp is used in
  any decision.

### 6.2 Local verification

Replay: for each record, recompute `α`, recompute `δ(pre_state, symbol)`, check it equals
`post_state` (for ALLOW) or lands in `F_bad` with `post_state == pre_state` (for BLOCK), and
check the hash chain links. Pure automaton transition checking. No network. The crypto is
only there to detect tampering with the log file itself.

### 6.3 Honest limits of the log

- **Append-only** is enforced by the API (no update or delete methods) and by opening the
  file in append mode. Against an attacker with filesystem write access, tampering is
  **detectable, not preventable** — and detectable only by a verifier who knows the latest
  `hash_n` from outside the file. Truncation of the tail is undetectable without such an
  external anchor. VDP v0.1 does not anchor externally.
- **`sig` uses HMAC**, which is symmetric. It gives integrity against the agent, which does
  not hold `k_log`. It gives **no non-repudiation** against the monitor itself, because a
  verifier has to be given the same key that signs. An auditor using this can conclude "the
  agent did not forge this," not "the monitor did not forge this."

### 6.4 External attestation interface (stubbed)

```python
class Attestor(Protocol):
    def attest(self, log_segment, policy) -> Attestation: ...
    def verify(self, attestation) -> bool: ...
```

Shipped implementation: `NullAttestor`, which returns "not attested." Documented, not
claimed. Any real instantiation — asymmetric signatures for non-repudiation, or a succinct
non-interactive proof of compliance that does not reveal the trace — is **at best
computationally sound under standard assumptions**, needs a hardness assumption and possibly
a trusted setup, and must be labeled as such in any UI. The reference implementation will
not print the word "proven" for anything crossing this interface.

---

## 7. Threat model

### 7.1 Adversary

A fully adversarial agent. It may: call the shim any number of times, in any order, with any
arguments; lie in every field it controls; attempt to mint child tokens with wider caveats;
attempt to replay, reorder, or forge tokens; attempt to write the audit log; attempt to
mutate φ or the monitor state; collude with a child agent it delegated to.

### 7.2 Trust boundary

| Inside TCB | Outside TCB |
|---|---|
| Monitor process (φ, `A_φ`, `q`) | The agent, and any child agent |
| Policy artifact after human confirmation | The LLM that produces `Intent` |
| Root key `k`, log key `k_log` | Tool arguments, tool results |
| Audit log writer | The executor's downstream service |
| The human's confirmation decision | Everything the agent says about itself |

### 7.3 Attacks and dispositions

| Attack | Disposition | Rests on |
|---|---|---|
| Exceed spend cap | Blocked: `v_i + amt > N_i → q_bad` | Unconditional (§3.4) |
| Pay non-whitelisted target | Blocked: `target ∉ W → q_bad` | Unconditional |
| Perform prohibited verb | Blocked | Unconditional |
| Unknown or unmapped verb/target | Blocked (`⊥` sinks) | Unconditional |
| Malformed, negative, oversized amount | Blocked (`⊤_amt`) | Unconditional |
| Sub-delegate with wider scope | Caveat is met, not applied; scope narrows | Unconditional (§5.2) |
| Split payment into many small ones | Blocked at the cap; counter is cumulative | Unconditional |
| Hammer with actions it knows will fail | Blocked, state unchanged, attempts logged | Unconditional |
| Forge a token | Blocked by chain verification | **HMAC assumption** |
| Strip a caveat from a held token | Blocked; recomputation needs `k` or `t_{i-1}` | **HMAC assumption** |
| Tamper with the audit log | Detected on replay | **SHA-256 + external anchor** |
| Truncate the log tail | **Not detected** in v0.1 | — (documented gap) |
| Mislead the LLM during intent extraction | Caught, if at all, at the confirmation gate | **Human attention** |

### 7.4 Explicitly out of scope

- OS-level compromise, memory scraping, debugger attachment, key exfiltration.
- Side channels and timing.
- Bugs in the monitor implementation itself (mitigated by tests, not eliminated).
- Semantic mismatch between what the user *meant* and what φ *says*. The confirmation gate
  is the only defense, and it is a human one.
- Whether the downstream executor honors the decision. VDP decides; it does not verify that
  the bank actually moved the money.

### 7.5 The in-process caveat — stated plainly

The rule is: *the monitor must be outside the model's control surface.* In a real deployment
that means a separate process or host, with the agent reaching it only over a narrow IPC
surface exposing `submit()` and nothing else.

**The reference implementation runs the monitor in the same Python process as the demo
agent.** In-process, "outside the control surface" is an *architectural* property, not an
*enforced* one: nothing at the language level stops code in that process from reaching into
the monitor's attributes. The implementation will:

- expose no mutation API on the monitor, the policy, or the log;
- keep the agent-facing surface to a single `submit()` call;
- make policy and AST objects frozen;
- state this limitation in the module docstrings and in the demo output.

It will **not** claim memory isolation it does not have. Process separation is a deployment
concern, and it is listed here as a known gap rather than quietly assumed.

---

## 8. Module layout and build order

```
policy/     ast.py  parser.py  compile.py  render.py  llm_prompt.py  confirm.py
monitor/    automaton.py  mediate.py  worstcase.py
tokens/     scope.py  macaroon.py
runtime/    shim.py  auditlog.py  attest.py
demo/       payment_agent.py  hostile_agent.py
tests/      test_policy.py  test_monitor.py  test_tokens.py  test_runtime.py
            test_properties.py  test_adversarial.py
```

Built in that order; each layer's tests pass before the next begins.

### Test obligations

**(a) No allowed prefix is a bad prefix.** Hypothesis generates random policies and random
action traces, including hostile ones: cap-straddling amounts, near-miss target names,
unknown verbs, zero and boundary amounts. For every trace, feed it through the monitor,
collect the allowed subsequence, and independently re-evaluate φ over that subsequence with
a straightforward reference checker written separately from the automaton. Assert no
violation. Two independent implementations, cross-checked.

**(b) Sub-delegated scope ⊆ parent scope.** Hypothesis generates random scopes and random
caveat chains of random depth, including caveats that try to widen every field. Assert
`S_n ⊆ S_0`, and pairwise `S_i ⊆ S_{i-1}`, at every depth.

**(c) Adversarial fuzzing.** Random byte-level and structural mutation of tokens, caveat
lists, log records, and action payloads. Assert: every mutation is either rejected or is a
no-op; nothing is ever accepted that the unmutated path would have blocked.

**(d) Fail-closed.** Every malformed input class enumerated in §1.2 blocks.

**(e) Round-trip.** `parse(render_formal(φ)) == φ` for generated policies.

### Demo

An elderly-user payment agent: cap $500.00, whitelist of three recipients, hard prohibition
on account deletion. The hostile agent attempts, and must fail at, all three of:

1. exceeding the cap, including by splitting into many small payments,
2. paying a recipient not on the whitelist,
3. sub-delegating to a child agent with a *wider* scope than its own.

---

## 9. Summary: unconditional vs. conditional

**Unconditional** — no cryptographic or behavioral assumption:

- No executed trace is a bad prefix of φ (§3.4), given δ and α are implemented as specified.
- `S_n ⊆ S_0` at every delegation depth (§5.2).
- Unknown or unmappable actions are blocked (§1.2).
- No liveness property can be compiled into φ (§2.5).

**Conditional on cryptographic assumptions** — HMAC-SHA256 unforgeability, SHA-256 collision
resistance, key secrecy:

- Tokens cannot be forged, or widened by stripping caveats (§5.3).
- Audit log tampering is detected (§6.3), and tail truncation only with an external anchor.

**Not guaranteed at all:**

- That the task succeeds.
- That the agent spends less than `L_max`.
- That φ captures what the human actually meant.
- That the log tail has not been truncated (v0.1).
- Anything crossing the external-attestation interface (§6.4), which is a stub.

---

## 10. Open questions for review

1. **Continuous vs. discrete amounts.** §4.1 gives `L_max = N_i` whenever the agent picks
   amounts freely. The discrete DP only pays off when the shim's mapping table fixes costs.
   Is the discrete case worth building in v0.1, or should it wait until a scenario needs it?
2. **Counter scoping.** v0.1 has counters over verb sets only. Per-target counters
   ("at most $100 to any one recipient") are a natural next form and remain safety
   properties, but they enlarge Q to `∏(N+1)^|T|`. Deferred unless you want it now.
3. **Expiry.** `expires_at` sits in the token scope, not in φ. That keeps wall-clock time
   out of the automaton entirely. Confirm that is the split you want.
