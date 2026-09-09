# VDP Protocol Specification

**vdp-spec-0.3** — Normative. This document defines the wire formats, grammar,
and decision procedures that any conforming VDP implementation MUST reproduce
byte-for-byte where a hash or signature is involved, and semantically
elsewhere. It is derived from, and kept in sync with, [DESIGN.md](DESIGN.md),
which carries the rationale, proofs, and worked examples this document omits.
Where the two disagree, this document wins for implementers; open an issue.

The key words "MUST", "MUST NOT", "SHOULD", "SHOULD NOT", and "MAY" are to be
interpreted as in RFC 2119.

The reference implementation ([Module layout](#8-module-layout)) is **a**
conforming implementation, not the protocol itself. Nothing in this document
requires Python, and a second implementation in another language that passes
the [conformance vectors](spec/conformance/) is equally conforming.

---

## 0. Status

| | |
|---|---|
| Spec revision | 0.3 |
| Reference implementation | matches this revision, except recorded deviations (none outstanding — see [CHANGELOG.md](CHANGELOG.md)) |
| Stability | pre-1.0. Grammar and wire formats may change between minor revisions; each change is logged in [CHANGELOG.md](CHANGELOG.md). |

A conforming implementation MUST declare which `vdp-spec-N.N` it implements,
and MUST reject a policy artifact or token stamped with a spec version it does
not implement rather than guessing at compatibility. See [§9](#9-versioning-and-compatibility).

---

## 1. Actions and the alphabet Σ

### 1.1 Concrete action

The runtime boundary (an agent tool call, or equivalent) normalizes each
action to:

```
ConcreteAction = (verb: str, target: str, amount: int, attrs: dict)
```

- `verb` — free string; what is being done.
- `target` — free string; the entity acted upon.
- `amount` — a non-negative integer in **minor units** (cents, watt-hours,
  bytes). Never a float. Zero for actions with no resource cost.
- `attrs` — carried for the audit log and the executor. **MUST NOT** be
  visible to the automaton. Anything that must affect a decision MUST be
  lifted into `verb`, `target`, or `amount` by a mapping table that is part
  of the policy artifact and is not agent-writable.

**The mapping table's integrity matters as much as φ's own.** `policy_hash`
(§2.4) covers φ but not this table by itself — nothing stops a caller from
swapping which argument name maps to `amount` (e.g. `"cents"` → `"dollars"`,
silently authorizing 100× the confirmed loss) without changing `policy_hash`
at all. An implementation SHOULD provide a way to compute a combined hash
over `(policy_hash, mapping table)` — an `artifact_hash` — and SHOULD let a
caller assert an expected `artifact_hash` at construction time, refusing to
proceed on mismatch. This is a SHOULD, not a MUST, in this revision: binding
is opt-in (an implementation MAY skip the check entirely, e.g. for a policy
authored and consumed by the same trusted process), but an implementation
that skips it MUST NOT claim `policy_hash` alone protects the mapping table.

### 1.2 Abstraction to a finite alphabet

A policy φ declares a finite verb universe `V` and finite target universe `T`.
`T` MUST always contain the sentinel `NO_TARGET` (the empty string `""`),
which no whitelist clause may name — this is the symbol for target-less
actions (e.g. `read_balance`). Amounts saturate at `C_max`, the largest cap
bound in φ (`C_max = 0` if φ declares no caps).

```
Σ  =  (V ∪ {⊥_verb})  ×  (T ∪ {⊥_target})  ×  ({0, 1, …, C_max} ∪ {⊤_amt})

α(verb, target, amount, attrs) =
    ( verb   if verb   ∈ V else ⊥_verb,
      target if target ∈ T else ⊥_target,
      amount if 0 ≤ amount ≤ C_max else ⊤_amt )
```

`α` MUST be total and deterministic. An implementation MUST route any input
it cannot even normalize into a `ConcreteAction` (wrong types, missing
required fields) to a BLOCK without consulting the automaton — this is the
same fail-closed outcome as an `⊥`/`⊤` symbol, produced one step earlier.

`δ` (§3) MUST NOT be materialized as a table; it MUST be evaluated
symbolically per symbol. Σ is finite but large: `|Σ| = (|V|+1)(|T|+1)(C_max+2)`.

---

## 2. Policy language

### 2.1 Fragment

φ is the safety fragment of LTL plus monotone resource counters — exactly
three atomic clause forms, plus conjunction:

| Form | Meaning | State |
|---|---|---|
| `always(counter C <= N)` | cumulative sum of `amount` over actions in `C`'s scope never exceeds `N` | stateful |
| `always(verb(target) -> target in W)` | whenever `verb` occurs, its target ∈ whitelist `W` | memoryless |
| `always(not verb)` | `verb` never occurs | memoryless |

Counters MUST be monotone non-decreasing: no decrement, no reset, no time
window. There is deliberately no syntax for `eventually`, for response
patterns (`always(p -> eventually q)`), or for any unbounded-obligation form —
an implementation's policy AST MUST have no constructor that could hold one.

### 2.1a Counter increment mode

Each counter declaration carries an increment mode, `counting: bool`
(default `false`):

- **`false` — amount-summing** (the mode above): a matching action
  contributes its `amount` to the counter.
- **`true` — call-counting**: a matching action contributes exactly `1` to
  the counter, regardless of `amount`.

Both modes are the same automaton shape — monotone, bounded, `q_bad` on
overflow (§3.1–3.2) — only the per-action increment differs, so the §3.4
correctness argument holds for either mode without modification. Call-
counting exists because an amount-summing counter cannot bound how many
times a zero-amount or variable-amount verb (`read_balance`, `check_status`)
may be called: a cap on the total does not imply a cap on the count when
zero is a legal amount. This addition is backward compatible — a policy that
never uses `counting: true` behaves exactly as in `vdp-spec-0.2`.

### 2.1b Counter scope: global or per-target

Each counter declaration also carries a scope, `per_target: bool` (default
`false`):

- **`false` — global** (the mode above): one running total, shared across
  every target the counter's verbs touch.
- **`true` — per-target**: an INDEPENDENT running total for each target —
  the bound applies to each target separately ("at most $100 to any ONE
  recipient," not "$100 total across all recipients").

`counting` and `per_target` are orthogonal and MAY be combined (e.g. "at
most 5 calls to any one target").

**Effect on `Q`.** `T` is finite (§1.2), so a per-target counter widens the
automaton's state space by a known, finite factor: it MUST be implemented as
one state dimension per `(counter, target)` pair rather than a data
structure keyed by targets seen so far only — either is finite, but the
former keeps state comparison and audit-log replay (§6) straightforward.
This does not make `Q` infinite and the §3.4 correctness argument is
unaffected: it is still a statement about a finite product of bounded
dimensions.

**Effect on the worst-case preview (§4).** A per-target counter's bound is a
PER-TARGET maximum, not an aggregate one. An implementation MUST report
both: the per-target maximum, and the aggregate maximum across every target
the counter's verbs can reach (per-target maximum × number of reachable
targets). Reporting only the per-target number understates total exposure
by exactly that factor and is the dishonesty §4's rule exists to prevent.

This addition is backward compatible — a policy that never uses
`per_target: true` behaves exactly as in `vdp-spec-0.2`.

### 2.2 Grammar

```ebnf
policy        ::= decls clause ( "and" clause )*

decls         ::= ( "counter" ident "over" verbset scope_mode? counting_mode? )*
scope_mode    ::= "per" "target"          (* opt-in per-target scope, section 2.1b *)
counting_mode ::= "counting" "calls"      (* opt-in call-counting, section 2.1a *)

clause        ::= cap | whitelist | prohibition

cap           ::= "always" "(" ident "<=" integer unit? ")"

whitelist     ::= "always" "(" ident "(" "target" ")" "->" "target" "in" set ")"

prohibition   ::= "always" "(" "not" ident ")"

verbset       ::= "{" ident ( "," ident )* "}"
set           ::= "{" string ( "," string )* "}"

unit          ::= ident                (* display only; MUST NOT affect semantics *)
integer       ::= [0-9]+               (* minor units, non-negative *)
ident         ::= [a-z][a-z0-9_]*      (* MUST NOT be a reserved word — see below *)
```

When both suffixes are present, `scope_mode` MUST precede `counting_mode`
(e.g. `counter c over {v} per target counting calls`) — a fixed order, not a
free choice, so `render_formal` output is unambiguous to re-parse.

Reserved words (not usable as a verb or counter name): `always`, `and`,
`calls`, `counter`, `counting`, `in`, `not`, `over`, `per`, `target`.

Example:

```
counter spend over {pay}

always(spend <= 50000 cents)
and always(pay(target) -> target in {"alice_utility", "bob_pharmacy", "carol_grocer"})
and always(not delete_account)
```

### 2.3 AST and structural rules

```
Policy       = { counters: [CounterDecl], clauses: [Clause] }
CounterDecl  = { name: str, verbs: frozenset[str],
                 counting: bool = false, per_target: bool = false }
Cap          = { counter: str, bound: int, unit: str|None }
Whitelist    = { verb: str, allowed: frozenset[str] }
Prohibition  = { verb: str }
```

A `Policy` MUST be immutable once constructed. A conforming implementation
MUST reject construction (not merely warn) when:

- a counter name is duplicated;
- φ has zero clauses (an empty policy authorizes nothing coherently and is
  almost certainly a caller bug, not an intent);
- a `Cap` references an undeclared counter, or a counter has more than one cap;
- a declared counter is never capped (this would make its state component
  unbounded);
- a verb has more than one `Whitelist` clause, or a verb is prohibited more
  than once;
- a `Whitelist.allowed` set is empty (use `always(not verb)` instead — an
  empty whitelist silently forbids the verb without saying so).

Derived, MUST be computed (never separately stored):

- `V` (verbs) = every verb named in any counter, whitelist, or prohibition.
- `T` (targets) = `{NO_TARGET}` ∪ every target named in any whitelist.
- `c_max` = max bound over all caps, or `0` if there are none.

### 2.4 Canonical form and policy_hash

```
canonical(φ) = json.dumps(to_canonical_obj(φ), sort_keys=True,
                           separators=(",", ":"), ensure_ascii=False).encode("utf-8")
policy_hash  = SHA256(canonical(φ)).hexdigest()
```

`to_canonical_obj` MUST emit set-valued fields (counter verbs, whitelist
targets) sorted, and MUST preserve clause declaration order (order is part of
policy identity and of the round-trip below). It MUST include a `version`
field (see [§9](#9-versioning-and-compatibility)); as of `vdp-spec-0.3` this
is `2`, and each counter object MUST include its `counting` (§2.1a) and
`per_target` (§2.1b) flags:

```json
{"version": 2, "counters": [{"name": "spend", "verbs": ["pay"], "counting": false, "per_target": false}], "clauses": [...]}
```

Round-trip requirement: `parse(render_formal(φ)) == φ` for every constructible
φ — the formal renderer and the parser MUST be inverses.

### 2.5 Structured intent (LLM-facing schema)

Free-form user speech MAY be compiled to φ via an intermediate `Intent`
object. The component producing `Intent` is **outside the trusted computing
base** — nothing downstream may treat it as more than untrusted structured
input.

```
Intent = {
  counters:     [ {name, verbs[], bound, unit?} ],
  whitelists:   [ {verb, allowed[]} ],
  prohibitions: [ {verb} ],
  rejected:     [ {utterance, reason} ]
}
```

An implementation MUST reject unknown top-level or per-entry keys in `Intent`
(no silent drop). `rejected` entries MUST pass through to the confirmation
step unmodified and MUST NOT influence the compiled φ — the compiler's
refusal to accept `eventually`-shaped keys does not depend on the LLM having
correctly classified them into `rejected`.

### 2.6 Human confirmation gate

```
speech → [LLM] → Intent → show render(compile(Intent)) + worst-case preview (§4)
                                 → HUMAN CONFIRMS → signed Policy artifact
```

An implementation MUST NOT produce a token or a monitor for an unconfirmed
Intent. The human-readable rendering (§2.4's `render_formal`, or an
English-language rendering) MUST be generated from the same `Policy` object
the monitor enforces, never from a parallel description that could drift.

---

## 3. Monitor automaton `A_φ`

### 3.1 States

For counters `c_1 … c_k` with bounds `N_1 … N_k`, where a **global** counter
(`per_target: false`, §2.1b) contributes one dimension `{0..N_i}` and a
**per-target** counter (`per_target: true`) contributes `|T|` dimensions
`{0..N_i}^{|T|}`, one per target — finite because `T` is finite (§1.2):

```
Q      =  ( {0..N_1}^{d_1} × … × {0..N_k}^{d_k} )  ∪  { q_bad },   d_i = |T| if counter i is per-target, else 1
q₀     =  (0, …, 0)
F_bad  =  { q_bad }
```

`q_bad` MUST be absorbing (`δ(q_bad, a) = q_bad` for all `a`). Memoryless
clauses (whitelist, prohibition) contribute no state component.

### 3.2 Transition function

For `q = (v_1, …, v_k)` and symbol `a = (verb, target, amt)`, in this order —
a disjunction of guards, not a precedence chain, but every implementation
MUST produce the same verdict regardless of guard evaluation order since
exactly one of "some guard fires" or "none fire" is true for any `(q, a)`:

```
δ(q, a) = q_bad   if verb   = ⊥_verb
        | q_bad   if target = ⊥_target
        | q_bad   if amt    = ⊤_amt
        | q_bad   if ∃ Prohibition(verb)
        | q_bad   if ∃ Whitelist(verb, W) ∧ target ∉ W
        | q_bad   if ∃ i. verb ∈ counters[i].verbs ∧ v_{i,slot(i,target)} + inc_i(amt) > N_i
        | q'       otherwise, where q' agrees with q except
              q'_{i,slot(i,target)} = v_{i,slot(i,target)} + inc_i(amt)   for every i with verb ∈ counters[i].verbs

inc_i(amt)        = 1        if counters[i].counting              (§2.1a, call-counting)
                  = amt      otherwise                            (amount-summing)
slot(i, target)   = target   if counters[i].per_target             (§2.1b, per-target: one dimension per target)
                  = •        otherwise (the counter's single global dimension)
```

`δ` MUST be total and deterministic. `inc_i` depends only on the static
`counting` flag of counter `i`, never on `amt`'s value itself, so `Q`'s
finiteness argument (§3.1) is unaffected: `inc_i(amt) ≥ 0` in both modes,
since `amt` is already saturated to `0 ≤ amt ≤ C_max` by `α` before `δ` runs.
`slot(i, target)` is total because by this point `target ∈ T` (the
`⊥_target` guard already fired otherwise), and a per-target counter's
dimensions cover every member of `T` (§3.1).

### 3.3 Mediation loop

```
def submit(q, concrete_action):
    a  = α(concrete_action)
    q2 = δ(q, a)
    if q2 in F_bad:
        return BLOCK, q      # state MUST NOT change on BLOCK
    return ALLOW, q2
```

Required properties:

- State MUST advance only on ALLOW. A BLOCK MUST leave `q` unchanged.
- Blocked attempts MUST still be written to the audit log (§6) — they are
  evidence, not automaton state.
- Execution order MUST be: decide, then execute, then log. An implementation
  MUST NOT roll a counter back if execution fails after an ALLOW.

### 3.4 Correctness obligation

Any conforming implementation MUST satisfy: for the sequence `σ = a_1 … a_n`
of actions the monitor allowed, no prefix of σ is a bad prefix of φ. This
follows by induction from §3.1–3.3 exactly as implemented (see DESIGN.md §3.4
for the full argument) and MUST be checked by an independent reference
checker over random policies and traces, not only by unit examples — see
[§10](#10-conformance-testing).

---

## 4. Worst-case preview

Before human confirmation, an implementation MUST compute and display, over
**all** traces `A_φ` would allow (not predicted agent behavior):

- **Per-counter maximum** `L_max(i)`. Continuous case (agent picks any
  integer amount): `L_max(i) = N_i`. Discrete case (a fixed mapping table of
  per-action costs `D_i`): `L_max(i)` is the coin-reachability maximum
  `≤ N_i`, computed exactly by DP. An implementation MUST report which case
  applied — a bound that is tight only because of a mapping table is fragile
  in a way a policy-derived bound is not, and MUST be labeled as such.
- **Bounded-but-not-monetary dimensions**: distinct whitelisted targets
  (`|W|`), impossible verbs (`always(not v)` and any verb in `V` no clause
  permits).
- **Unbounded dimensions**: any verb with no cap and no whitelist. MUST be
  surfaced explicitly (e.g. "unlimited") — silently omitting an unbounded
  dimension from the preview is the single worst failure mode this interface
  has, per DESIGN.md §4.2.
- **Call-counting counters** (§2.1a): `L_max` for such a counter is always
  its bound — the increment is a constant `1` per matching action
  independent of amount, so `0..N_i` is reachable one call at a time and no
  cost-model DP applies. A verb governed by at least one call-counting
  counter MUST NOT be reported as unbounded in call count (§4.2's
  "unbounded in count" case is specifically the gap this mode closes) even
  if it also permits a zero amount.
- **Per-target counters** (§2.1b): report BOTH the per-target maximum
  (computed exactly as the continuous/discrete case above) AND the aggregate
  maximum across every target the counter's verbs can reach — per-target
  maximum × number of reachable targets. An implementation MUST NOT report
  only the per-target figure: a human reading "≤ $100" for a per-target cap
  with 3 whitelisted recipients has not been told the worst case is $300,
  which is exactly the omission this section exists to prevent.

---

## 5. Attenuable capability tokens

### 5.1 Scope

A `Scope` is a record over a meet-semilattice:

| Field | Domain | Meet (⊓) | Ordering (⊆) |
|---|---|---|---|
| `verbs` | finite set ∪ {⊤} | intersection | subset |
| `targets` | finite set ∪ {⊤} | intersection | subset |
| `max_amount` | ℕ ∪ {⊤} | min | ≤ |
| `max_total` | ℕ ∪ {⊤} | min | ≤ |
| `expires_at` | ℕ ∪ {⊤} | min | ≤ |

`⊤` ("TOP", represented as `null`/`None`) means "constrains nothing" and is
the identity for meet. `expires_at` MUST be an integer Unix epoch second —
no formatted date strings, no timezone parsing in the decision path.

A root scope derived from φ (`Scope.root_from_policy`) MUST NOT leave both
`verbs` and `targets` at `⊤` — an implementation MUST refuse to accept a root
token whose scope does not name its capabilities. `max_total` on a root scope
MUST be left at `⊤`: cumulative spend is monitor state (§3), and a root token
that duplicated it would shadow the monitor's own counter.

### 5.1a Binding a root token to a policy artifact

Two policies can, by construction, produce an identical root scope: `Scope.
root_from_policy` derives only `(V minus prohibited verbs, T, c_max)`, so two
policies with different caps distributed across different counters can
collapse to the same `(verbs, targets, max_amount)` triple. Without an
explicit binding, a root token minted for one such policy verifies
interchangeably under another that shares the same root key — the monitor
gate (§5.4) still enforces the actual φ, so no bound is exceeded, but the
token itself claims an authority tied to no particular policy artifact.

A `Token` MAY carry `policy_hash: str`, default `""` (unbound — vdp-spec-0.2
behavior). When non-empty, it MUST be included in the root MAC's input
(§5.3), so it cannot be edited post-mint without invalidating the tag. A
verifier MAY require a specific `expected_policy_hash`; when it does, a token
whose `policy_hash` does not match MUST be refused, independent of whether
its MAC still verifies (MAC integrity proves the field was not tampered
with — it does not by itself assert which value the verifier requires). An
implementation SHOULD refuse a token whose `policy_hash` does not match its
own monitor's `policy.digest()` whenever that field is non-empty; whether to
also require every token be bound (rejecting `policy_hash: ""` outright) is
a deployment policy choice, not something this spec revision mandates.

### 5.2 Attenuation

```
attenuate(S, C) = S ⊓ C
```

This MUST be the only operation that produces a derived scope — no setter,
union, max, or "widen" may exist anywhere a caveat is applied. By induction,
`S_n = S_0 ⊓ C_1 ⊓ … ⊓ C_n ⊆ S_0` at every delegation depth, for every `C_i`
including hostile or malformed-looking ones. This property is set-theoretic
and holds independent of §5.3's cryptographic assumption.

### 5.3 HMAC caveat chain

```
t_0 = HMAC-SHA256(k,       "vdp/v1/root\x00"   ‖ policy_hash ‖ canonical(S_0))
t_i = HMAC-SHA256(t_{i-1}, "vdp/v1/caveat\x00" ‖ canonical(C_i))
```

`policy_hash` (§5.1a) is UTF-8 bytes, `""` when unbound — included in `t_0`'s
input unconditionally (an empty string contributes no bytes but keeps the
domain shape uniform between bound and unbound tokens). It is NOT part of
any `t_i` for `i > 0`: only the root's identity is bound to a policy: a
caveat is a purely local narrowing operation (§5.2) and needs no policy
context of its own.

A token is the tuple `(S_0, [C_1 … C_n], t_n)`, together with `policy_hash`.
`k` (the root key) MUST be
held only by the issuer, MUST be at least 32 bytes, and MUST NOT be
reachable by any agent. Verification MUST recompute the chain and compare
with a constant-time comparison (`hmac.compare_digest` or equivalent) —
never a short-circuiting `==`.

Domain-separation prefixes (`vdp/v1/root\x00`, `vdp/v1/caveat\x00`) MUST be
included so root-scope bytes and caveat-scope bytes can never be
reinterpreted as each other.

`attenuate` (minting a child token) requires no key — any holder of `t_{i-1}`
can compute `t_i`. Only issuing a **root** token requires `k`.

Canonical scope bytes for the chain:

```
canonical(S) = json.dumps(to_obj(S), sort_keys=True,
                           separators=(",", ":"), ensure_ascii=False).encode("utf-8")
```

where `to_obj` emits `⊤` as `null` and set fields sorted.

This is conditional on the HMAC-SHA256 PRF/unforgeability assumption and on
`k` staying secret — unlike §5.2, an implementation MUST NOT claim this
guarantee is unconditional.

### 5.4 Two independent gates

A valid token is necessary, not sufficient. An implementation MUST require
**both**:

1. the token verifies against `k`, and the action lies within `S_n`
   (including a shim-held running total against `max_total`, since a
   cumulative bound cannot be decided from a single action and MUST NOT be
   encoded inside the token itself), **and**
2. the monitor (§3) allows the action from the current `q`.

Either failing MUST block. Token order relative to the monitor MAY vary, but
if the token gate runs first, a failing token MUST NOT advance monitor state.

### 5.4a Revocation (optional third gate)

Macaroon-style tokens have no revocation by construction — a leaked or
misbehaving token is live until `expires_at` (§5.1), which MAY be far in the
future or absent entirely. An implementation MAY maintain a set of revoked
`token_id`s (§5.5's `token_id`, not the tag) and refuse any token whose
`token_id` is a member, as a THIRD conjunctive gate alongside the two in
§5.4.

This is safe to add without revisiting §3.4: a gate that can only turn a
future ALLOW into a BLOCK cannot enlarge the set of executed traces, which is
the only thing that argument is about (the same reasoning §5.4 already
applies to `max_total`). Revoking a token MUST NOT retroactively affect
records already written to the audit log (§6) — it affects only calls made
*after* the revocation, exactly like every other gate here.

Revoking a **parent** token's `token_id` does NOT automatically revoke a
child's: `attenuate` (§5.2) produces a caveat chain with a different
`token_id`. An implementation that wants "revoke this delegation and
everything downstream of it" MUST track and revoke each `token_id` in that
subtree individually, or MUST document that it does not support subtree
revocation — silently assuming one revocation call covers descendants it
never inspected would be a false guarantee.

### 5.5 Token wire format

```json
{
  "root":        { "verbs": [...]|null, "targets": [...]|null,
                    "max_amount": <int>|null, "max_total": <int>|null,
                    "expires_at": <int>|null },
  "caveats":     [ <Scope object, same shape as root>, ... ],
  "tag":         "<hex-encoded HMAC-SHA256 output>",
  "policy_hash": "<string, \"\" if unbound>"
}
```

Parsing MUST reject unknown top-level or scope-level keys, and MUST reject a
token object missing `policy_hash` — vdp-spec-0.2 tokens (which had no such
field) are not wire-compatible with this revision; see [§9](#9-versioning-and-compatibility).
`tag` MUST decode as hex; a decode failure is a structural error, distinct
from (and MUST be distinguishable in code from, though not necessarily in
the boolean verification result) a failed verification.

---

## 6. Audit log

### 6.1 Record format

Append-only JSONL, one canonical-JSON object per physical line:

```json
{
  "seq": <int>, "action": {...}, "symbol": {...},
  "pre_state": [...], "post_state": [...],
  "decision": "ALLOW"|"BLOCK", "reason": "<string>",
  "token_id": "<hex or \"<no-token>\">",
  "policy_hash": "<64-hex>", "prev_hash": "<64-hex>",
  "hash": "<64-hex>", "sig": "<64-hex>"
}
```

- `hash = SHA256(prev_hash || canonical(record without hash/sig))`.
- `hash_0`'s predecessor is `genesis_hash = SHA256("vdp/v1/genesis\x00" || policy_hash)`
  — this binds the whole log to one exact policy artifact.
- `sig = HMAC-SHA256(k_log, hash)`.
- Record ordering MUST come from `seq` and the hash chain, **never** from a
  timestamp. No record MAY contain a timestamp, and no decision MAY depend
  on wall-clock time.
- Log record JSON MUST be serialized with `ensure_ascii=True`. Rationale:
  JSONL is one record per physical *line*, and common line-splitters break on
  several non-ASCII line-separator code points (U+0085, U+000B, U+000C,
  U+2028, U+2029) in addition to `\n`; an unescaped one inside an
  agent-controlled `target` string would otherwise split one record into two
  for such a reader.
- `hash`, `sig`, `prev_hash`, `policy_hash` MUST each be validated as exactly
  64 lowercase hex characters on parse — not just type-checked — because a
  non-hex value reaching a constant-time-compare primitive can raise instead
  of returning `False`, turning a tamper *detection* into a crash.
  `token_id` is exempt (it may hold the literal sentinel `<no-token>`).

### 6.2 Verification (replay)

A verifier MUST, for every record in sequence:

1. check `seq` is contiguous from 0;
2. check `policy_hash` matches the log's declared policy;
3. check `prev_hash` equals the previous record's `hash` (or `genesis_hash`
   for record 0);
4. recompute `hash` and `sig` and compare;
5. if replaying against a live automaton: recompute `δ(pre_state, symbol)`
   and confirm it equals `post_state` for ALLOW, or lands in `q_bad` with
   `post_state == pre_state` for BLOCK.

This uses no network and reads no clock.

### 6.3 Honest limits (MUST be disclosed by any implementation)

- Append-only is enforced only by the writing API (no update/delete method).
  Against an attacker with filesystem write access, tampering is
  **detectable, not preventable**, and detectable only by a verifier holding
  the latest `hash_n` from *outside* the file.
- **Tail truncation is undetectable without an external anchor.** An
  implementation MUST NOT report verification success in a way a reader
  could mistake for "nothing was removed" — surface this explicitly in the
  verification result. An implementation SHOULD provide a first-class way to
  publish `head` (§6.1's chain tip) to an external anchor on every append —
  e.g. a caller-supplied callback invoked with the new `head` after each
  write — rather than leaving external anchoring as something a caller must
  remember to poll for. Publishing `head` is still the caller's
  responsibility; the log itself has no network access (§6.1) and MUST NOT
  gain any to satisfy this.
- `sig` is symmetric (HMAC). It proves "the agent did not forge this," never
  "the issuer/monitor did not forge this." Non-repudiation requires
  asymmetric signatures and is out of scope for this revision (§6.4).

### 6.4 External attestation interface (optional, stubbed)

```
Attestor.attest(log_segment, policy) -> Attestation
Attestor.verify(attestation) -> bool
```

A conforming implementation MAY ship only a null attestor that reports "not
attested." Any real instantiation (asymmetric signatures, a succinct proof of
compliance) is at best computationally sound under a stated hardness
assumption and MUST be labeled as such — an implementation MUST NOT print
the word "proven" for anything crossing this interface.

**Asymmetric checkpoint signatures (optional).** An implementation MAY
provide an `Attestor` that signs a CHECKPOINT — `(policy_hash, log head)` at
the time `attest()` is called — with an asymmetric key, giving non-
repudiation that the symmetric HMAC signature in §6.1 cannot: a verifier
holding only the public key can confirm a specific issuer vouched for a
specific head, without being able to forge that claim themselves. This is
still not a claim about the trace's correctness (that is §6.2's job) and
MUST say so in `Attestation.claim`. Such an implementation MAY depend on a
cryptography library beyond the standard library — attestation is
explicitly not on any decision path (`Attestor`'s definition above) — but
MUST NOT make that dependency required for the enforcement path (§0's
"standard library only" scope is unaffected; only this opt-in interface may
reach outside it).

---

## 7. Threat model (summary — see DESIGN.md §7 and [SECURITY.md](SECURITY.md) for full discussion)

**Adversary**: a fully adversarial agent. It may call the runtime boundary
any number of times, in any order, with any arguments; lie in every field it
controls; attempt to mint wider-scoped child tokens; attempt to
replay/reorder/forge tokens; attempt to write the audit log directly;
attempt to mutate φ or monitor state; collude with a delegated child agent.

**Inside the TCB**: the monitor process (φ, `A_φ`, `q`); the policy artifact
after human confirmation; the root key and log key; the audit log writer;
the human's confirmation decision.

**Outside the TCB**: the agent and any child agent; the LLM that produces
`Intent`; tool arguments and tool results; the executor's downstream
service; anything the agent says about itself.

**In-process caveat**: the monitor MUST be architecturally outside the
agent's control surface — in a real deployment, a separate process or host
reachable only through a `submit()`/`call()`-shaped narrow interface. If a
reference or demo implementation runs the monitor in the same process as the
agent, it MUST say so explicitly and MUST NOT claim memory isolation it does
not have.

---

## 8. Module layout

Non-normative pointer to the reference implementation's structure — a second
implementation is free to organize differently as long as it exposes
equivalent operations.

```
policy/     ast.py  parser.py  compile.py  render.py  llm_prompt.py  confirm.py
monitor/    automaton.py  mediate.py  worstcase.py
tokens/     scope.py  macaroon.py
runtime/    shim.py  auditlog.py  attest.py
```

---

## 9. Versioning and compatibility

- A compiled policy artifact's canonical form (§2.4) MUST carry a `version`
  integer field. `version: 2` denotes the AST shape defined in §2.3 of this
  spec revision (vdp-spec-0.3) — `version: 1` (vdp-spec-0.2) lacked the
  `counting` field on `CounterDecl`; this reference implementation never
  reads a canonical artifact back into a `Policy` (the canonical form is
  write-only, used solely to compute `policy_hash`), so `version: 1` is
  retired rather than dual-supported. An implementation that DOES load
  policy artifacts back MUST refuse `version: 1` per the next bullet, not
  silently default the missing `counting` field.
- A monitor implementation MUST refuse to load a policy artifact whose
  `version` it does not recognize, rather than attempting best-effort
  interpretation.
- The token wire format (§5.5) and audit log record format (§6.1) are
  versioned implicitly by the spec revision (`vdp-spec-0.3`) rather than by a
  per-object field; a breaking change to either format requires a new minor
  spec revision and MUST be recorded in [CHANGELOG.md](CHANGELOG.md).
- Grammar extensions (e.g. sliding windows — see DESIGN.md §11's remaining
  open questions) that enlarge the clause fragment (§2.1) are breaking for
  `Q` finiteness proofs and MUST bump the spec's minor version. Call-
  counting (§2.1a) and per-target (§2.1b) counters are examples already
  shipped this way, in `vdp-spec-0.3`.

---

## 10. Conformance testing

An implementation claims conformance to `vdp-spec-0.3` by passing the
portable test vectors in [`spec/conformance/`](spec/conformance/) — policy +
action trace + expected per-action decision/state fixtures, and JSON Schemas
in [`spec/schema/`](spec/schema/) for the wire formats in §5.5 and §6.1.
These are language-agnostic; the reference implementation's `tests/` suite
additionally covers implementation-specific obligations (round-trip parsing,
scope-monotonicity property tests, adversarial fuzzing) described in
DESIGN.md §8.

---

## 11. Transport binding (reference; not required for conformance)

§0 and DESIGN.md §7.5 both state the rule: the monitor MUST be architecturally
reachable only over a narrow interface, ideally a separate process or host.
Everything in §1–§10 defines data shapes and decision procedures; none of it
prescribes HOW `submit()`/`call()` is reached across that boundary. An
implementation MAY invent its own transport and remain fully conformant —
this section is not a MUST, because a `vdp-spec-0.3` implementation embedded
in a single trusted process (§7's documented in-process caveat) has no
transport to speak of. It exists because a protocol whose only real
interface is "call this method in this address space" cannot have two
independent implementations talk to each other, and VDP should not stay in
that state by default.

### 11.1 Reference binding: NDJSON over TCP loopback

The reference implementation's `runtime.server.MonitorServer` /
`runtime.client.MonitorClient` define one concrete, working binding. An
implementation choosing to be wire-compatible with it SHOULD follow this
section; one that does not still conforms to `vdp-spec-0.3` as long as §1–§10
are met.

- **Transport**: TCP. The reference binds `127.0.0.1` by default — SHOULD NOT
  default to a wider interface, since a monitor silently reachable from
  outside the local machine contradicts "narrow interface" the moment such a
  binding is the default rather than an explicit choice.
- **Framing**: newline-delimited JSON (NDJSON) — one JSON object per line,
  request and response strictly alternating on a given connection. Encoding
  MUST be ASCII-escaped (`ensure_ascii`-equivalent), for the same reason
  §6.1 requires it of audit records: a handful of non-ASCII line-separator
  code points break naive line readers, and a line-oriented protocol should
  not depend on every implementation's JSON encoder agreeing on which
  characters count as "a line."
- **Concurrency**: multiple connections MAY be open at once (one per agent
  process, typically), but every decision — every `submit`/`call` — MUST be
  serialized against the same monitor/log state, because `Monitor`,
  `AgentShim`, and `AuditLog` are not individually thread-safe (DESIGN.md:
  "single-threaded by design"). The reference implementation does this with
  one lock shared across all connections, and one thread per connection for
  I/O. An implementation MAY use a different concurrency model, but MUST NOT
  let two decisions interleave against the same monitor state.

### 11.2 Request/response shapes

Two operations, both objects on one line each:

```json
{"op": "call", "tool_name": <string>, "args": <object|null>,
 "token": <Token object per section 5.5, or null>, "now": <int|null>}
```
```json
{"op": "remaining"}
```

Responses always carry `"ok": <bool>`. `ok: false` is a TRANSPORT/PROTOCOL
failure (malformed JSON, unknown `op`) — distinct from `ok: true, "allowed":
false`, which means the monitor was reached and refused the action. An
implementation MUST NOT collapse these into one signal: a caller needs to
know whether the monitor was consulted at all.

```json
{"ok": true, "allowed": <bool>, "reason": <string>, "gate": <string>,
 "result": <any JSON value>, "error": <string|null>}
```
```json
{"ok": true, "remaining": {<counter name>: <int>, ...}}
```
```json
{"ok": false, "error": <string>}
```

**`now`, and who is allowed to supply it.** `expires_at` (§5.1) is checked
against a `now` that `Scope.permits` receives as an argument, because nothing
in the token layer reads a clock. Over a transport, something must supply it,
and the request shape above carries a `now` field for that purpose.

An implementation MUST NOT decide expiry from a `now` supplied by an
untrusted peer. §7 places the agent outside the TCB and states that it may
lie in every field it controls; over this binding `now` is such a field, so
believing it means an agent holding a long-expired token sends `now: 0` and
the check passes. That is not a weakened bound — `expires_at` stops
constraining anything at all. A conforming server SHOULD read its own clock
and ignore the request's `now`, which is what the reference implementation
does by default (`MonitorServer(clock=time.time)`); the field remains part of
the request shape for compatibility and MAY still be parsed, but MUST NOT be
the basis of an expiry decision unless the peer is trusted, which for an
agent it is not. An implementation that does trust it MUST say so, and MUST
NOT describe `expires_at` as a bound against the §7 adversary.

A malformed `token` object MUST be handled as a BLOCK with `gate: "token"`
(reusing §5.4's ordinary token-gate refusal shape), not as a protocol-level
`ok: false` — a hostile or corrupted token is exactly the kind of input
`AgentShim.call` is already required to handle without raising (§1.1), and
the transport boundary MUST NOT weaken that guarantee by treating it as a
different class of failure.

### 11.3 What MUST NOT cross this (or any) transport

The root key, the log key, the `Monitor`/`AuditLog` objects themselves, and
any full audit `Record` (only the agent-facing outcome fields — `allowed`,
`reason`, `gate`, `result`, `error` — belong in a response). A `Token` in its
plain wire form (§5.5) MAY cross the wire in both directions: §5.3 already
establishes that holding a token is not authorization, so transmitting one
the agent already effectively holds is not a new exposure.
