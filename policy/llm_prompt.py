"""VDP L1 — the LLM-facing intent extraction prompt (DESIGN.md section 2.5).

THIS MODULE IS OUTSIDE THE TRUSTED COMPUTING BASE.

It contains a prompt and a strict JSON reader. It makes no network call and it
holds no credentials — the caller is responsible for talking to whatever model
it likes and handing the raw text here. That keeps the enforcement path free of
any network dependency, per the design rule.

What makes this layer safe is NOT the model's care. It is:

  1. `policy.compile.validate_intent`, which rejects unknown keys, wrong types,
     and anything outside the section 2.5 schema, and
  2. the human confirmation gate in `policy.confirm`, which shows the compiled
     policy and its worst case before anything is authorized.

A model that hallucinates a recipient, widens a bound, or invents a field
produces either a hard error or a visibly wrong policy at the gate. It does not
produce a quietly wrong authorization.
"""

from __future__ import annotations

import json
import re

from policy.compile import LIVENESS_REJECTION_MESSAGE

__all__ = ["INTENT_EXTRACTION_PROMPT", "INTENT_JSON_SCHEMA", "extract_intent"]


#: JSON Schema for the intent object. Supplied to the model as structured-output
#: constraints where the provider supports it. It is a convenience, not a
#: control: `validate_intent` re-checks everything regardless.
INTENT_JSON_SCHEMA: dict = {
    "type": "object",
    "additionalProperties": False,
    "required": ["counters", "whitelists", "prohibitions", "rejected"],
    "properties": {
        "counters": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["name", "verbs", "bound"],
                "properties": {
                    "name": {"type": "string", "pattern": "^[a-z][a-z0-9_]*$"},
                    "verbs": {
                        "type": "array",
                        "minItems": 1,
                        "items": {"type": "string", "pattern": "^[a-z][a-z0-9_]*$"},
                    },
                    "bound": {"type": "integer", "minimum": 0},
                    "unit": {"type": ["string", "null"]},
                },
            },
        },
        "whitelists": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["verb", "allowed"],
                "properties": {
                    "verb": {"type": "string", "pattern": "^[a-z][a-z0-9_]*$"},
                    "allowed": {
                        "type": "array",
                        "minItems": 1,
                        "items": {"type": "string", "minLength": 1},
                    },
                },
            },
        },
        "prohibitions": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["verb"],
                "properties": {
                    "verb": {"type": "string", "pattern": "^[a-z][a-z0-9_]*$"}
                },
            },
        },
        "rejected": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["utterance", "reason"],
                "properties": {
                    "utterance": {"type": "string"},
                    "reason": {"type": "string"},
                },
            },
        },
    },
}


INTENT_EXTRACTION_PROMPT = f"""\
You convert a person's spoken instructions for an AI agent into a STRUCTURED
INTENT object. You do not enforce anything. A separate program compiles your
output into a formal policy, computes the worst case it permits, and shows both
to the person for confirmation before anything is authorized.

Output ONE JSON object and nothing else. No prose, no code fence, no commentary.

Schema — exactly these four top-level keys, all required, each a list:

{{
  "counters":     [{{"name": <ident>, "verbs": [<ident>...], "bound": <integer>,
                    "unit": <string or null>}}],
  "whitelists":   [{{"verb": <ident>, "allowed": [<string>...]}}],
  "prohibitions": [{{"verb": <ident>}}],
  "rejected":     [{{"utterance": <string>, "reason": <string>}}]
}}

<ident> means lowercase snake_case matching [a-z][a-z0-9_]*.

RULES

1. AMOUNTS ARE INTEGERS IN MINOR UNITS. "$500" becomes bound 50000 with unit
   "cents". Never emit a decimal, never emit a float, never emit a currency
   symbol inside the number.

2. A counter is a CUMULATIVE, NEVER-DECREASING total over the verbs listed in
   it. There is no reset, no refund, no per-day or per-week window. If the
   person says "$100 per week", you CANNOT express it. Put it in "rejected"
   with a reason saying that only cumulative totals are supported.

3. Put an utterance in "rejected" -- do not approximate it -- whenever it is:
   - a liveness or completion wish: "make sure it books the ticket", "always
     respond within an hour", "eventually pay the bill", "don't waste money",
     "be reasonable", "try your best";
   - a time window, schedule, or deadline of any kind;
   - a per-recipient or per-item sub-limit ("at most $50 to any one person");
   - anything requiring judgment about the world rather than a check on an
     action ("only pay legitimate invoices").
   For liveness wishes, use this reason verbatim:
   "{LIVENESS_REJECTION_MESSAGE}"

4. NEVER INVENT. Do not add a recipient the person did not name. Do not add a
   prohibition they did not state. Do not tighten or loosen a number they gave.
   If a recipient's identity is ambiguous, do not guess it into "allowed"; put
   the utterance in "rejected" and let the person restate it.

5. Emit no key that is not in the schema above. A key such as "eventually",
   "goals", "deadlines", or "retries" causes the compiler to reject your entire
   output.

6. If the person states no limit of a given kind, emit an empty list for it.
   An empty "whitelists" means that verb accepts any target the policy knows
   of -- say so in "rejected" only if the person seemed to expect a restriction.

WHAT THIS SYSTEM CAN AND CANNOT DO -- state nothing beyond this:
It can stop the agent from acting outside the stated limits. It cannot make the
agent complete the task, cannot promise the agent spends less than the cap, and
cannot judge whether a permitted action was a good idea.

PERSON'S INSTRUCTIONS:
{{utterance}}
"""


_FENCE_RE = re.compile(r"^\s*```(?:json)?\s*(?P<body>.*?)\s*```\s*$", re.DOTALL)


def extract_intent(model_output: str) -> dict:
    """Parse a model's raw text into an intent dict. Strict, no repair.

    Tolerates exactly one deviation from the prompt: a surrounding markdown code
    fence, because that is a formatting artifact rather than a semantic one.
    Everything else -- trailing prose, multiple objects, invalid JSON -- is an
    error. The parser does NOT attempt to fix a malformed intent; a model that
    cannot follow the schema is a model whose output the human should see fail,
    not one whose output should be silently guessed at.

    The returned dict is NOT yet validated against the section 2.5 schema. Pass
    it to `policy.compile.compile_intent`, which does that.
    """
    if not isinstance(model_output, str):
        raise ValueError(
            f"model output must be a string, got {type(model_output).__name__}"
        )

    text = model_output.strip()
    fence = _FENCE_RE.match(text)
    if fence is not None:
        text = fence.group("body").strip()

    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"model output is not valid JSON: {exc}") from exc

    if not isinstance(parsed, dict):
        raise ValueError(
            f"model output must be a JSON object, got {type(parsed).__name__}"
        )
    return parsed
