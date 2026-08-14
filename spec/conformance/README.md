# Conformance vectors

Language-agnostic test fixtures for `vdp-spec-0.2`. See [SPEC.md §10](../../SPEC.md#10-conformance-testing).

Each `*.vectors.json` file declares one `policy` (matching
[`policy-artifact.schema.json`](../schema/policy-artifact.schema.json)) and a
list of named `vectors`. Each vector is an ordered sequence of `steps`
replayed against the monitor automaton (`A_φ`, SPEC.md §3) starting from
`q0`. For each step:

1. Normalize `action` (already in `ConcreteAction` shape here) via `α`.
2. Compute `δ(pre_state, symbol)`.
3. Assert the resulting `decision` (`ALLOW`/`BLOCK`) and `post_state` exactly
   match `expect`.
4. Feed `post_state` forward as `pre_state` for the next step in the same
   vector.

A conforming implementation passes a vector file by reproducing every
`expect` block exactly. These vectors were generated against, and checked
to pass, the reference implementation in this repository.

| File | Covers |
|---|---|
| [`basic-policy.vectors.json`](basic-policy.vectors.json) | Whitelist violation, hard prohibition, unknown verb, cumulative cap + block/resume, no-target verb with unrestricted target, amount saturation and negative amounts. |
| [`counting-counters.vectors.json`](counting-counters.vectors.json) | Call-counting counters (`counting: true`, SPEC.md §2.1a): increments by 1 regardless of amount, and an amount-summing counter + a call-counting counter over the same verb advancing independently. |
| [`per-target-counters.vectors.json`](per-target-counters.vectors.json) | Per-target counters (`per_target: true`, SPEC.md §2.1b): independent tracking per target, and a per-target counter + a global counter over the same verb advancing independently. |

Not yet covered here (exercised instead by the reference implementation's
`tests/test_properties.py` and `tests/test_adversarial.py`, which are
Python-specific): token attenuation/HMAC chain vectors, audit log
hash-chain replay vectors, and property-based/fuzz coverage. Contributions
adding portable vectors for those are welcome.
