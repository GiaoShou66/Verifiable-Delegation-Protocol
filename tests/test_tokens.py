"""L3 tests — the scope lattice and the HMAC caveat chain.

Invariant (b) from DESIGN.md section 8:

    SUB-DELEGATED SCOPE IS A SUBSET OF PARENT SCOPE, AT EVERY DEPTH.

The generated caveats include ones that deliberately try to WIDEN every field:
supersets of verbs and targets, 2**63 amount bounds, far-future expiry. None of
them can widen anything, and the reason is not that this file checks them -- it
is that `attenuate` has no operation available other than `meet`, which is a
greatest lower bound. These tests demonstrate that; they do not create it.

The two claims are tested separately and reported separately:

  - monotonicity   -- unconditional, set-theoretic
  - unforgeability -- conditional on HMAC-SHA256 and on key secrecy

A test named `..._conditional_on_hmac` checks that this implementation does what
the HMAC assumption would give it. It is not testing the assumption.
"""

from __future__ import annotations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from tests.strategies import policies, scopes, widening_caveats

from policy.parser import parse
from tokens.macaroon import MIN_KEY_BYTES, Token, TokenError, attenuate, mint, verify
from tokens.scope import TOP, Scope, ScopeError

KEY = b"\x11" * 32
OTHER_KEY = b"\x22" * 32

DEMO_TEXT = """
counter spend over {pay}

always(spend <= 50000 cents)
and always(pay(target) -> target in {"alice_utility", "bob_pharmacy", "carol_grocer"})
and always(not delete_account)
"""


def demo_root() -> Scope:
    return Scope.root_from_policy(parse(DEMO_TEXT))


# --------------------------------------------------------------------------
# the lattice
# --------------------------------------------------------------------------


def test_meet_intersects_sets_and_takes_the_minimum_of_bounds():
    parent = Scope(
        verbs=frozenset({"pay", "read"}),
        targets=frozenset({"alice", "bob"}),
        max_amount=500,
        max_total=5000,
        expires_at=1_000_000,
    )
    caveat = Scope(
        verbs=frozenset({"pay", "wipe"}),
        targets=frozenset({"bob", "carol"}),
        max_amount=100,
        max_total=9_999_999,
        expires_at=900_000,
    )
    child = parent.meet(caveat)
    assert child.verbs == frozenset({"pay"})
    assert child.targets == frozenset({"bob"})
    assert child.max_amount == 100
    assert child.max_total == 5000  # the caveat asked for more and did not get it
    assert child.expires_at == 900_000


def test_top_is_the_identity_for_meet():
    scope = demo_root()
    assert scope.meet(Scope()) == scope
    assert Scope().meet(scope) == scope


@settings(max_examples=300)
@given(scopes(), scopes())
def test_meet_is_a_greatest_lower_bound(a: Scope, b: Scope):
    """The whole of invariant (b) rests on this one algebraic fact."""
    m = a.meet(b)
    assert m.is_subset_of(a)
    assert m.is_subset_of(b)


@settings(max_examples=200)
@given(scopes(), scopes(), scopes())
def test_meet_is_commutative_associative_and_idempotent(a: Scope, b: Scope, c: Scope):
    assert a.meet(b) == b.meet(a)
    assert a.meet(b).meet(c) == a.meet(b.meet(c))
    assert a.meet(a) == a


@settings(max_examples=200)
@given(scopes())
def test_subset_is_reflexive(a: Scope):
    assert a.is_subset_of(a)


def test_top_is_above_every_proper_value_and_nothing_is_above_top():
    bounded = Scope(verbs=frozenset({"pay"}), max_amount=1)
    assert bounded.is_subset_of(Scope())
    assert not Scope().is_subset_of(bounded)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"verbs": "pay"},  # a bare string is not a set of names
        {"verbs": [1]},
        {"max_amount": -1},
        {"max_amount": True},  # bool subclasses int
        {"max_amount": 1.5},
        {"expires_at": "2026-08-07"},  # no date strings anywhere
    ],
)
def test_malformed_scopes_are_rejected_at_construction(kwargs):
    with pytest.raises(ScopeError):
        Scope(**kwargs)


def test_root_from_policy_matches_v_t_and_c_max():
    phi = parse(DEMO_TEXT)
    root = Scope.root_from_policy(phi, expires_at=1_000_000)
    # V minus the prohibited verbs: a root token must not claim an authority the
    # monitor refuses unconditionally.
    assert root.verbs == frozenset({"pay"})
    assert root.verbs < phi.verbs
    assert root.targets == phi.targets
    assert root.max_amount == phi.c_max == 50000
    # max_total is left TOP on purpose: a cumulative total is trace history and
    # belongs to the monitor. A root token that carried one would shadow the
    # monitor's counter instead of composing with it (DESIGN.md 5.4).
    assert root.max_total is TOP
    assert root.names_capabilities


# --------------------------------------------------------------------------
# invariant (b): monotonicity at every delegation depth
# --------------------------------------------------------------------------


@settings(max_examples=300)
@given(scopes(), st.lists(widening_caveats(), max_size=6))
def test_sub_delegated_scope_is_a_subset_at_every_depth(root: Scope, caveats):
    """Invariant (b). Unconditional: no cryptographic assumption is used here."""
    token = mint(KEY, root)
    parent_scope = token.scope
    assert parent_scope == root

    for depth, caveat in enumerate(caveats, start=1):
        token = attenuate(token, caveat)
        assert token.depth == depth
        assert token.scope.is_subset_of(parent_scope)  # pairwise S_i <= S_{i-1}
        assert token.scope.is_subset_of(root)  # and S_n <= S_0
        parent_scope = token.scope


@settings(max_examples=200)
@given(st.lists(widening_caveats(), min_size=1, max_size=6))
def test_a_caveat_that_asks_for_more_gets_no_more(caveats):
    root = Scope(
        verbs=frozenset({"pay"}),
        targets=frozenset({"alice"}),
        max_amount=500,
        max_total=500,
        expires_at=1_000_000,
    )
    token = mint(KEY, root)
    for caveat in caveats:
        token = attenuate(token, caveat)
    final = token.scope
    assert final.verbs <= frozenset({"pay"})
    assert final.targets <= frozenset({"alice"})
    # A bounded parent field can never become TOP in the child, so these are
    # plain integer comparisons rather than disjunctions hiding an escape hatch.
    assert final.max_amount is not TOP and final.max_amount <= 500
    assert final.max_total is not TOP and final.max_total <= 500
    assert final.expires_at is not TOP and final.expires_at <= 1_000_000


def test_the_hostile_sub_delegation_from_the_demo_fails_to_widen():
    """The concrete attack: a child agent asks for a wider scope than its parent."""
    parent = mint(KEY, demo_root())
    wider = Scope(
        verbs=frozenset({"pay", "delete_account", "transfer"}),
        targets=frozenset({"mallory"}),
        max_amount=10**9,
        max_total=10**9,
    )
    child = attenuate(parent, wider)

    assert child.scope.is_subset_of(parent.scope)
    assert "delete_account" not in child.scope.verbs
    assert child.scope.targets == frozenset()  # mallory was never in T
    assert child.scope.max_amount == 50000
    assert verify(KEY, child)  # the child token is authentic -- and useless
    assert child.scope.permits("pay", "mallory", 1) is not None


@settings(max_examples=200)
@given(policies(), st.lists(widening_caveats(), max_size=4))
def test_no_delegated_token_permits_a_verb_the_policy_never_named(phi, caveats):
    root = Scope.root_from_policy(phi)
    token = mint(KEY, root)
    for caveat in caveats:
        token = attenuate(token, caveat)
    assert token.scope.verbs <= phi.verbs
    assert token.scope.targets <= phi.targets


# --------------------------------------------------------------------------
# the per-action scope check
# --------------------------------------------------------------------------


def test_permits_accepts_an_in_scope_action_and_names_the_reason_otherwise():
    scope = Scope(verbs=frozenset({"pay"}), targets=frozenset({"alice"}), max_amount=500)
    assert scope.permits("pay", "alice", 500) is None
    assert "outside this token's scope" in scope.permits("wipe", "alice", 1)
    assert "outside this token's scope" in scope.permits("pay", "mallory", 1)
    assert "per-action limit" in scope.permits("pay", "alice", 501)


@pytest.mark.parametrize(
    "args",
    [
        (None, "alice", 1),
        ("pay", None, 1),
        ("pay", "alice", None),
        ("pay", "alice", 1.5),
        ("pay", "alice", True),
        ("pay", "alice", -1),
    ],
)
def test_permits_is_total_and_fail_closed_on_hostile_types(args):
    scope = Scope(verbs=frozenset({"pay"}), targets=frozenset({"alice"}))
    assert scope.permits(*args) is not None  # a refusal, never an exception


def test_an_expiring_token_without_a_clock_reading_is_refused():
    scope = Scope(verbs=frozenset({"pay"}), targets=frozenset({"alice"}), expires_at=100)
    assert scope.permits("pay", "alice", 1) is not None  # no `now` supplied
    assert scope.permits("pay", "alice", 1, now=100) is None
    assert "expired" in scope.permits("pay", "alice", 1, now=101)


def test_max_total_is_not_decided_per_action_here():
    """A token cannot encode "you have already spent 400" -- that is monitor and
    shim state, not scope. `permits` therefore ignores max_total by design."""
    scope = Scope(verbs=frozenset({"pay"}), targets=frozenset({"alice"}), max_total=10)
    assert scope.permits("pay", "alice", 1000) is None


# --------------------------------------------------------------------------
# the HMAC chain -- CONDITIONAL on the HMAC assumption
# --------------------------------------------------------------------------


def test_a_minted_token_verifies_and_a_foreign_key_does_not():
    token = mint(KEY, demo_root())
    assert verify(KEY, token)
    assert not verify(OTHER_KEY, token)


def test_attenuation_needs_no_key_and_the_child_still_verifies():
    parent = mint(KEY, demo_root())
    child = attenuate(parent, Scope(max_amount=100))  # no key argument exists
    assert verify(KEY, child)
    assert child.scope.max_amount == 100


@settings(max_examples=100)
@given(st.lists(scopes(), min_size=1, max_size=5))
def test_stripping_a_caveat_breaks_verification_conditional_on_hmac(caveats):
    """A holder of t_n cannot recompute t_{n-1}: that needs `k`."""
    token = mint(KEY, demo_root())
    for caveat in caveats:
        token = attenuate(token, caveat)
    assert verify(KEY, token)

    stripped = Token(root=token.root, caveats=token.caveats[:-1], tag=token.tag)
    assert not verify(KEY, stripped)


def test_swapping_a_caveat_breaks_verification_conditional_on_hmac():
    token = attenuate(mint(KEY, demo_root()), Scope(max_amount=100))
    forged = Token(root=token.root, caveats=(Scope(max_amount=10**9),), tag=token.tag)
    assert not verify(KEY, forged)


def test_editing_the_root_scope_breaks_verification_conditional_on_hmac():
    token = mint(KEY, demo_root())
    widened = Token(
        root=Scope(
            verbs=frozenset({"pay", "delete_account"}),
            targets=token.root.targets,
            max_amount=10**9,
            max_total=10**9,
        ),
        caveats=token.caveats,
        tag=token.tag,
    )
    assert not verify(KEY, widened)


def test_flipping_one_bit_of_the_tag_breaks_verification():
    token = mint(KEY, demo_root())
    flipped = Token(
        root=token.root,
        caveats=token.caveats,
        tag=bytes([token.tag[0] ^ 1]) + token.tag[1:],
    )
    assert not verify(KEY, flipped)


def test_verify_returns_false_rather_than_raising_for_a_non_token():
    for junk in [None, "token", 42, {"tag": "00"}, b""]:
        assert verify(KEY, junk) is False


def test_a_short_key_is_refused_rather_than_used():
    with pytest.raises(TokenError, match="at least 32 bytes"):
        mint(b"short", demo_root())
    with pytest.raises(TokenError):
        verify(b"short", mint(KEY, demo_root()))
    assert MIN_KEY_BYTES == 32


def test_the_root_and_caveat_macs_are_domain_separated():
    """A caveat's bytes must never be reinterpretable as a root scope's bytes."""
    scope = Scope(max_amount=100)
    as_root = mint(KEY, scope)
    # The same scope, presented as the sole caveat under a TOP root.
    as_caveat = attenuate(mint(KEY, Scope()), scope)
    assert as_root.tag != as_caveat.tag


# --------------------------------------------------------------------------
# serialization -- strict, because this parses hostile input
# --------------------------------------------------------------------------


@settings(max_examples=200)
@given(scopes(), st.lists(scopes(), max_size=4))
def test_serialization_round_trips_and_preserves_verification(root, caveats):
    token = mint(KEY, root)
    for caveat in caveats:
        token = attenuate(token, caveat)
    restored = Token.deserialize(token.serialize())
    assert restored == token
    assert verify(KEY, restored)
    assert restored.scope == token.scope


@pytest.mark.parametrize(
    "obj",
    [
        {"root": {}, "caveats": [], "tag": "00", "extra": 1},
        {"root": {}, "caveats": []},
        {"root": {}, "caveats": {}, "tag": "00"},
        {"root": {}, "caveats": [], "tag": "zz"},
        {"root": {}, "caveats": [], "tag": 0},
        {"root": {"surprise": 1}, "caveats": [], "tag": "00"},
        {"root": [], "caveats": [], "tag": "00"},
        [],
        "token",
    ],
)
def test_malformed_token_data_is_rejected_not_repaired(obj):
    with pytest.raises(TokenError):
        Token.from_obj(obj)


def test_token_id_is_stable_and_does_not_leak_the_tag():
    token = attenuate(mint(KEY, demo_root()), Scope(max_amount=100))
    assert token.token_id() == Token.deserialize(token.serialize()).token_id()
    assert token.tag.hex() not in token.token_id()
    # A different caveat chain is a different identity.
    other = attenuate(mint(KEY, demo_root()), Scope(max_amount=101))
    assert token.token_id() != other.token_id()


def test_a_token_is_immutable():
    token = mint(KEY, demo_root())
    with pytest.raises(AttributeError):
        token.tag = b"\x00" * 32  # type: ignore[misc]
    with pytest.raises(AttributeError):
        token.caveats = ()  # type: ignore[misc]
