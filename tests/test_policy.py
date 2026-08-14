"""L1 tests — AST validity, parser, round-trip, intent compilation, gate.

The load-bearing test here is `test_round_trip_generated`: `render_formal` is
what a human re-reads to check their own policy, so if it could ever render
something that parses back to a DIFFERENT phi, the human would be reading a
description of a policy other than the one being enforced. Hypothesis generates
policies rather than only checking hand-written ones.

The other invariants (no allowed prefix is a bad prefix; sub-delegated scope is
a subset) belong to L2 and L3 and are tested there.
"""

from __future__ import annotations

import pytest
from hypothesis import given, settings

from tests.strategies import policies

from policy.ast import (
    Cap,
    CounterDecl,
    NO_TARGET,
    Policy,
    PolicyError,
    Prohibition,
    RESERVED_WORDS,
    Whitelist,
)
from policy.compile import IntentError, compile_intent, validate_intent
from policy.confirm import (
    CONFIRM_PHRASE,
    ConfirmationError,
    gate_text,
    request_confirmation,
)
from policy.llm_prompt import INTENT_EXTRACTION_PROMPT, extract_intent
from policy.parser import ParseError, parse
from policy.render import format_amount, render_english, render_formal

DEMO_TEXT = """
counter spend over {pay}

always(spend <= 50000 cents)
and always(pay(target) -> target in {"alice_utility", "bob_pharmacy", "carol_grocer"})
and always(not delete_account)
"""


def demo_policy() -> Policy:
    return parse(DEMO_TEXT)


# --------------------------------------------------------------------------
# parser
# --------------------------------------------------------------------------


def test_parses_demo_policy():
    phi = demo_policy()
    assert phi.counters == (CounterDecl(name="spend", verbs=frozenset({"pay"})),)
    assert phi.caps == (Cap(counter="spend", bound=50000, unit="cents"),)
    assert phi.whitelists == (
        Whitelist(
            verb="pay",
            allowed=frozenset({"alice_utility", "bob_pharmacy", "carol_grocer"}),
        ),
    )
    assert phi.prohibitions == (Prohibition(verb="delete_account"),)


def test_universes_and_c_max():
    phi = demo_policy()
    assert phi.verbs == frozenset({"pay", "delete_account"})
    assert phi.targets == frozenset(
        {NO_TARGET, "alice_utility", "bob_pharmacy", "carol_grocer"}
    )
    assert phi.c_max == 50000


def test_comments_and_whitespace_are_ignored():
    phi = parse(
        """
        # a spending authority
        counter spend over {pay}
        always(spend <= 100)   # one hundred minor units
        """
    )
    assert phi.caps[0].bound == 100
    assert phi.caps[0].unit is None


@pytest.mark.parametrize(
    "text",
    [
        "always(eventually pay)",
        "always(pay -> eventually confirm)",
        "eventually(pay)",
        "sometimes(pay)",
    ],
)
def test_liveness_syntax_has_no_production(text):
    """No temporal operator other than `always` exists in the grammar."""
    with pytest.raises(ParseError):
        parse(text)


@pytest.mark.parametrize(
    "text",
    [
        "",
        "always(spend <= 100)",  # counter never declared
        'counter spend over {pay}\nalways(pay(target) -> target in {"a"})',  # uncapped
        "counter spend over {pay}\nalways(spend <= 1) and always(spend <= 2)",
        "counter spend over {pay}\nalways(spend <= 1) and always(pay(target) -> target in {})",
        "counter spend over {pay}\nalways(spend <= -5)",
        "counter spend over {pay}\nalways(spend <= 1) extra",
        "counter and over {pay}\nalways(and <= 1)",  # reserved word
        "counter spend over {pay, pay}\nalways(spend <= 1)",
        "counter spend over {}\nalways(spend <= 1)",
        "counter spend over {Pay}\nalways(spend <= 1)",  # not an ident
    ],
)
def test_malformed_policies_are_rejected(text):
    with pytest.raises(ParseError):
        parse(text)


def test_parse_rejects_non_string():
    with pytest.raises(ParseError):
        parse(b"counter spend over {pay}")  # type: ignore[arg-type]


# --------------------------------------------------------------------------
# AST validation
# --------------------------------------------------------------------------


def test_no_target_sentinel_cannot_be_whitelisted():
    with pytest.raises(PolicyError):
        Whitelist(verb="pay", allowed=frozenset({NO_TARGET}))


def test_bool_bound_is_not_an_integer_bound():
    # bool subclasses int; True must not silently become the bound 1.
    with pytest.raises(PolicyError):
        Cap(counter="spend", bound=True)


def test_reserved_words_cannot_name_things():
    for word in RESERVED_WORDS:
        with pytest.raises(PolicyError):
            Prohibition(verb=word)


def test_policy_is_immutable():
    phi = demo_policy()
    with pytest.raises(AttributeError):
        phi.clauses = ()  # type: ignore[misc]


def test_digest_is_stable_and_order_sensitive():
    a = demo_policy()
    b = parse(render_formal(a))
    assert a.digest() == b.digest()

    reordered = Policy(counters=a.counters, clauses=tuple(reversed(a.clauses)))
    assert reordered.digest() != a.digest()


# --------------------------------------------------------------------------
# rendering and round-trip
# --------------------------------------------------------------------------


def test_round_trip_demo():
    phi = demo_policy()
    assert parse(render_formal(phi)) == phi


def test_render_english_names_every_verb_including_unbounded_ones():
    phi = parse(
        """
        counter spend over {pay}
        always(spend <= 50000 cents)
        and always(pay(target) -> target in {"alice_utility"})
        and always(not delete_account)
        and always(read_balance(target) -> target in {"main_account"})
        """
    )
    english = render_english(phi)
    for verb in phi.verbs:
        assert verb in english
    assert "$500.00" in english
    assert "never, under any circumstance" in english


def test_render_english_flags_a_verb_with_no_bound_at_all():
    phi = parse(
        """
        counter spend over {pay}
        always(spend <= 100)
        and always(not wipe)
        """
    )
    # `pay` is capped; `wipe` is forbidden. Add a verb that is neither: it must
    # be described as unlimited, not quietly omitted.
    phi2 = Policy(
        counters=phi.counters,
        clauses=phi.clauses + (Whitelist(verb="peek", allowed=frozenset({"acct"})),),
    )
    english = render_english(phi2)
    assert "no limit on how many times" in english


def test_format_amount_uses_integer_math():
    assert format_amount(50000, "cents") == "$500.00"
    assert format_amount(5, "cents") == "$0.05"
    assert format_amount(123456789, "cents") == "$1,234,567.89"
    assert format_amount(7, None) == "7"
    assert format_amount(7, "watt_hours") == "7 watt_hours"


@settings(max_examples=200)
@given(policies())
def test_round_trip_generated(phi: Policy):
    """parse(render_formal(phi)) == phi, for generated policies.

    If this ever fails, the text a human re-reads is not the policy being
    enforced.
    """
    assert parse(render_formal(phi)) == phi


@settings(max_examples=100)
@given(policies())
def test_render_english_covers_v(phi: Policy):
    english = render_english(phi)
    for verb in phi.verbs:
        assert verb in english


# --------------------------------------------------------------------------
# intent compilation
# --------------------------------------------------------------------------


GOOD_INTENT = {
    "counters": [{"name": "spend", "verbs": ["pay"], "bound": 50000, "unit": "cents"}],
    "whitelists": [
        {"verb": "pay", "allowed": ["alice_utility", "bob_pharmacy", "carol_grocer"]}
    ],
    "prohibitions": [{"verb": "delete_account"}],
    "rejected": [
        {"utterance": "make sure the bill actually gets paid", "reason": "liveness"}
    ],
}


def test_compile_intent_matches_the_written_policy():
    compiled = compile_intent(GOOD_INTENT)
    assert compiled.policy.digest() == demo_policy().digest()
    assert compiled.rejected[0].utterance == "make sure the bill actually gets paid"


def test_compile_intent_is_deterministic():
    a = compile_intent(GOOD_INTENT).policy
    b = compile_intent(GOOD_INTENT).policy
    assert a.canonical() == b.canonical()


def test_rejected_entries_never_become_clauses():
    intent = dict(GOOD_INTENT)
    intent["rejected"] = [
        {"utterance": "eventually book the ticket", "reason": "liveness"},
        {"utterance": "at most $50 per person", "reason": "no per-target counters"},
    ]
    compiled = compile_intent(intent)
    assert len(compiled.policy.clauses) == len(
        compile_intent(GOOD_INTENT).policy.clauses
    )


def test_unknown_top_level_key_is_rejected():
    with pytest.raises(IntentError, match="unknown key"):
        validate_intent({**GOOD_INTENT, "surprise": []})


def test_temporal_key_is_rejected_with_the_liveness_explanation():
    with pytest.raises(IntentError, match="cannot be enforced by monitoring"):
        validate_intent({**GOOD_INTENT, "eventually": [{"verb": "pay"}]})


@pytest.mark.parametrize(
    "mutation",
    [
        {"counters": [{"name": "spend", "verbs": ["pay"], "bound": 500.0}]},
        {"counters": [{"name": "spend", "verbs": ["pay"], "bound": True}]},
        {"counters": [{"name": "spend", "verbs": ["pay"], "bound": -1}]},
        {"counters": [{"name": "spend", "verbs": [], "bound": 1}]},
        {"counters": [{"name": "spend", "verbs": ["pay", "pay"], "bound": 1}]},
        {"counters": [{"name": "Spend", "verbs": ["pay"], "bound": 1}]},
        {"whitelists": [{"verb": "pay", "allowed": []}]},
        {"whitelists": [{"verb": "pay", "allowed": [""]}]},
        {"whitelists": [{"verb": "pay"}]},
        {"prohibitions": [{"verb": "pay", "why": "x"}]},
        {"rejected": [{"utterance": "x"}]},
        {"counters": "not a list"},
    ],
)
def test_malformed_intents_are_rejected(mutation):
    with pytest.raises(IntentError):
        compile_intent({**GOOD_INTENT, **mutation})


def test_intent_with_only_a_prohibition_compiles():
    compiled = compile_intent(
        {
            "counters": [],
            "whitelists": [],
            "prohibitions": [{"verb": "wipe"}],
            "rejected": [],
        }
    )
    assert compiled.policy.verbs == frozenset({"wipe"})


def test_empty_intent_produces_no_policy():
    with pytest.raises(IntentError, match="no clauses"):
        compile_intent(
            {"counters": [], "whitelists": [], "prohibitions": [], "rejected": []}
        )


# --------------------------------------------------------------------------
# LLM boundary
# --------------------------------------------------------------------------


def test_prompt_states_the_two_things_vdp_cannot_do():
    assert "cannot make the" in INTENT_EXTRACTION_PROMPT
    assert "minor units" in INTENT_EXTRACTION_PROMPT.lower()
    assert "{utterance}" in INTENT_EXTRACTION_PROMPT


def test_extract_intent_accepts_a_fenced_object():
    assert extract_intent('```json\n{"counters": []}\n```') == {"counters": []}


@pytest.mark.parametrize(
    "text",
    [
        'Here you go: {"counters": []}',
        '{"counters": []} and that is my answer',
        "[]",
        "not json at all",
        "",
    ],
)
def test_extract_intent_does_not_repair_malformed_output(text):
    with pytest.raises(ValueError):
        extract_intent(text)


# --------------------------------------------------------------------------
# confirmation gate
# --------------------------------------------------------------------------


PREVIEW = ["worst case loss <= $500.00 (your cap)", "recipients limited to 3 entities"]


def test_gate_refuses_to_present_a_policy_without_its_worst_case():
    compiled = compile_intent(GOOD_INTENT)
    with pytest.raises(ConfirmationError, match="worst case"):
        gate_text(compiled, [])


def test_gate_text_shows_policy_worst_case_rejections_and_the_disclaimer():
    compiled = compile_intent(GOOD_INTENT)
    text = gate_text(compiled, PREVIEW)
    assert "alice_utility" in text
    assert "worst case loss <= $500.00 (your cap)" in text
    assert "make sure the bill actually gets paid" in text
    assert "cannot promise the task succeeds" in text
    assert compiled.policy.digest() in text


@pytest.mark.parametrize(
    "answer", ["", "y", "yes", "authorize", " AUTHORIZE now", "AUTHORISE"]
)
def test_only_the_exact_phrase_authorizes(answer):
    compiled = compile_intent(GOOD_INTENT)
    result = request_confirmation(
        compiled, PREVIEW, reader=lambda _: answer, writer=lambda _: None
    )
    assert result.confirmed is False
    assert result.policy_hash == compiled.policy.digest()


def test_exact_phrase_authorizes():
    compiled = compile_intent(GOOD_INTENT)
    result = request_confirmation(
        compiled,
        PREVIEW,
        reader=lambda _: f"  {CONFIRM_PHRASE}  ",
        writer=lambda _: None,
    )
    assert result.confirmed is True


@pytest.mark.parametrize("boom", [EOFError, KeyboardInterrupt])
def test_no_input_stream_is_a_refusal(boom):
    compiled = compile_intent(GOOD_INTENT)

    def reader(_prompt: str) -> str:
        raise boom()

    result = request_confirmation(
        compiled, PREVIEW, reader=reader, writer=lambda _: None
    )
    assert result.confirmed is False
