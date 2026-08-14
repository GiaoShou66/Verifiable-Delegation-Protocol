"""VDP L1 — structured intent -> phi (DESIGN.md sections 2.5 and 2.6).

`compile_intent` is a PURE function. It performs no I/O, calls no model, and
touches no clock. The LLM that produced the intent object is OUTSIDE the trusted
computing base; this compiler is inside it, and it treats its input as hostile
data, not as advice.

--- Two layers of liveness defense, unequal in strength ---

1. Best-effort (the LLM): classifies liveness utterances into `rejected`. Can
   fail. Not a guarantee. Not relied on here.
2. Sound (this module + `policy.ast`): there is no code path that emits an
   `eventually`, a response pattern, or any unbounded obligation, because no
   such AST node exists. Additionally, `validate_intent` rejects unknown keys
   outright, so an LLM that invents `{"eventually": ...}` produces a hard error
   rather than a silently dropped field.

The `rejected` list is carried through untouched and shown at the confirmation
gate. It affects no compiled clause — it is there so the human learns which of
their wishes VDP declined to encode.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from policy.ast import Cap, Clause, CounterDecl, Policy, PolicyError, Prohibition, Whitelist

__all__ = [
    "CompiledIntent",
    "IntentError",
    "LIVENESS_REJECTION_MESSAGE",
    "RejectedIntent",
    "compile_intent",
    "validate_intent",
]


class IntentError(ValueError):
    """The intent object is not a valid intent. Never partially applied."""


#: Shown verbatim to the user whenever an utterance is rejected as liveness.
LIVENESS_REJECTION_MESSAGE = (
    "This cannot be enforced by monitoring. A monitor sees a finite prefix of "
    "behavior; no finite prefix can ever witness that something has FAILED to "
    "happen eventually, so there is nothing for the monitor to block. VDP can "
    "stop the agent from doing the wrong thing. It cannot make the agent do the "
    "right thing."
)

#: Keys an LLM is likely to invent when it tries to smuggle a liveness or
#: best-effort property past the schema. Matched only to give a better error
#: message; the rejection itself comes from the unknown-key check, which is
#: exhaustive and does not depend on this list being complete.
_TEMPORAL_HINT_KEYS = frozenset(
    {
        "eventually",
        "eventualities",
        "guarantees",
        "goals",
        "objectives",
        "obligations",
        "responses",
        "deadlines",
        "retries",
        "sla",
        "must_complete",
    }
)

_TOP_KEYS = frozenset({"counters", "whitelists", "prohibitions", "rejected"})
_COUNTER_KEYS = frozenset({"name", "verbs", "bound", "unit"})
_WHITELIST_KEYS = frozenset({"verb", "allowed"})
_PROHIBITION_KEYS = frozenset({"verb"})
_REJECTED_KEYS = frozenset({"utterance", "reason"})


@dataclass(frozen=True, slots=True)
class RejectedIntent:
    """An utterance VDP declined to encode, and why. Carried, never compiled."""

    utterance: str
    reason: str


@dataclass(frozen=True, slots=True)
class CompiledIntent:
    """Result of compilation: phi, plus what was refused on the way."""

    policy: Policy
    rejected: tuple[RejectedIntent, ...] = field(default=())

    def __post_init__(self) -> None:
        object.__setattr__(self, "rejected", tuple(self.rejected))


def _require_mapping(value: object, where: str) -> dict:
    if not isinstance(value, dict):
        raise IntentError(f"{where} must be an object, got {type(value).__name__}")
    for key in value:
        if not isinstance(key, str):
            raise IntentError(f"{where} has a non-string key {key!r}")
    return value


def _require_list(value: object, where: str) -> list:
    if not isinstance(value, list):
        raise IntentError(f"{where} must be a list, got {type(value).__name__}")
    return value


def _require_str(value: object, where: str) -> str:
    if not isinstance(value, str):
        raise IntentError(f"{where} must be a string, got {type(value).__name__}")
    return value


def _check_keys(
    obj: dict, allowed: frozenset[str], required: frozenset[str], where: str
) -> None:
    """Strict schema: unknown keys are an error, never ignored.

    Silently dropping an unrecognized field is how a policy ends up narrower or
    wider than the human believes. Failing loudly is the whole point.
    """
    extra = set(obj) - allowed
    if extra:
        temporal = sorted(extra & _TEMPORAL_HINT_KEYS)
        if temporal:
            raise IntentError(
                f"{where} contains unsupported key(s) {temporal}, which look like a "
                f"liveness or best-effort property. {LIVENESS_REJECTION_MESSAGE}"
            )
        raise IntentError(f"{where} contains unknown key(s) {sorted(extra)}")
    missing = required - set(obj)
    if missing:
        raise IntentError(f"{where} is missing required key(s) {sorted(missing)}")


def validate_intent(intent: object) -> dict:
    """Validate the intent object against the section 2.5 schema, strictly.

    Returns a normalized copy with the four top-level lists always present.
    Raises `IntentError` on anything else. Does not build a policy.
    """
    obj = _require_mapping(intent, "intent")
    _check_keys(obj, _TOP_KEYS, frozenset(), "intent")

    normalized: dict[str, list] = {
        "counters": _require_list(obj.get("counters", []), "intent.counters"),
        "whitelists": _require_list(obj.get("whitelists", []), "intent.whitelists"),
        "prohibitions": _require_list(
            obj.get("prohibitions", []), "intent.prohibitions"
        ),
        "rejected": _require_list(obj.get("rejected", []), "intent.rejected"),
    }

    for i, entry in enumerate(normalized["counters"]):
        where = f"intent.counters[{i}]"
        entry = _require_mapping(entry, where)
        _check_keys(entry, _COUNTER_KEYS, frozenset({"name", "verbs", "bound"}), where)
        _require_str(entry["name"], f"{where}.name")
        verbs = _require_list(entry["verbs"], f"{where}.verbs")
        if not verbs:
            raise IntentError(f"{where}.verbs is empty")
        for j, verb in enumerate(verbs):
            _require_str(verb, f"{where}.verbs[{j}]")
        if len(set(verbs)) != len(verbs):
            raise IntentError(f"{where}.verbs contains a duplicate")
        bound = entry["bound"]
        if isinstance(bound, bool) or not isinstance(bound, int):
            raise IntentError(f"{where}.bound must be an integer in minor units")
        if bound < 0:
            raise IntentError(f"{where}.bound must be non-negative, got {bound}")
        unit = entry.get("unit")
        if unit is not None:
            _require_str(unit, f"{where}.unit")

    for i, entry in enumerate(normalized["whitelists"]):
        where = f"intent.whitelists[{i}]"
        entry = _require_mapping(entry, where)
        _check_keys(entry, _WHITELIST_KEYS, _WHITELIST_KEYS, where)
        _require_str(entry["verb"], f"{where}.verb")
        allowed = _require_list(entry["allowed"], f"{where}.allowed")
        if not allowed:
            raise IntentError(
                f"{where}.allowed is empty; state a prohibition instead if the verb "
                f"is meant to be impossible"
            )
        for j, target in enumerate(allowed):
            _require_str(target, f"{where}.allowed[{j}]")

    for i, entry in enumerate(normalized["prohibitions"]):
        where = f"intent.prohibitions[{i}]"
        entry = _require_mapping(entry, where)
        _check_keys(entry, _PROHIBITION_KEYS, _PROHIBITION_KEYS, where)
        _require_str(entry["verb"], f"{where}.verb")

    for i, entry in enumerate(normalized["rejected"]):
        where = f"intent.rejected[{i}]"
        entry = _require_mapping(entry, where)
        _check_keys(entry, _REJECTED_KEYS, _REJECTED_KEYS, where)
        _require_str(entry["utterance"], f"{where}.utterance")
        _require_str(entry["reason"], f"{where}.reason")

    return normalized


def compile_intent(intent: object) -> CompiledIntent:
    """Compile a structured intent into phi. Pure, total-or-raising.

    Clause order is deterministic — caps in declaration order, then whitelists,
    then prohibitions — so that the same intent always yields byte-identical
    `Policy.canonical()`, and therefore the same policy_hash.
    """
    normalized = validate_intent(intent)

    counters: list[CounterDecl] = []
    clauses: list[Clause] = []

    try:
        for entry in normalized["counters"]:
            counters.append(
                CounterDecl(name=entry["name"], verbs=frozenset(entry["verbs"]))
            )
            clauses.append(
                Cap(counter=entry["name"], bound=entry["bound"], unit=entry.get("unit"))
            )
        for entry in normalized["whitelists"]:
            clauses.append(
                Whitelist(verb=entry["verb"], allowed=frozenset(entry["allowed"]))
            )
        for entry in normalized["prohibitions"]:
            clauses.append(Prohibition(verb=entry["verb"]))

        policy = Policy(counters=tuple(counters), clauses=tuple(clauses))
    except PolicyError as exc:
        # The AST owns every structural rule. The compiler re-raises rather than
        # duplicating them, so there is exactly one definition of "valid phi".
        raise IntentError(str(exc)) from exc

    rejected = tuple(
        RejectedIntent(utterance=entry["utterance"], reason=entry["reason"])
        for entry in normalized["rejected"]
    )
    return CompiledIntent(policy=policy, rejected=rejected)
