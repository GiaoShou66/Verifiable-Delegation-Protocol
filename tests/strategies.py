"""Shared hypothesis strategies.

`policies()` generates structurally valid phi. `hostile_actions()` generates the
action stream an ADVERSARIAL agent would produce: valid calls mixed with unknown
verbs, near-miss target names, boundary and over-boundary amounts, negative
amounts, floats, bools, None, and wrong types. The point is that the monitor
must return a Decision for every one of them -- never an exception, never an
allow it should not have made.
"""

from __future__ import annotations

from hypothesis import strategies as st

from monitor.automaton import ConcreteAction
from policy.ast import Cap, CounterDecl, Policy, Prohibition, RESERVED_WORDS, Whitelist

__all__ = ["IDENTS", "TARGETS", "hostile_actions", "policies"]

IDENTS = st.from_regex(r"\A[a-z][a-z0-9_]{0,6}\Z").filter(
    lambda s: s not in RESERVED_WORDS
)
TARGETS = st.text(
    alphabet=st.characters(blacklist_categories=("Cc", "Cs")), min_size=1, max_size=10
)


@st.composite
def policies(draw) -> Policy:
    """Generate a structurally valid phi.

    Counter membership, whitelists, and prohibitions may overlap in every way
    the AST permits, so the generated policies include the awkward cases: a verb
    that is both capped and prohibited (dead), a counter shared by several
    verbs, a capped verb with no target restriction.
    """
    verbs = draw(st.lists(IDENTS, min_size=1, max_size=4, unique=True))
    counter_names = draw(st.lists(IDENTS, min_size=0, max_size=2, unique=True))

    counters: list[CounterDecl] = []
    clauses: list = []
    for name in counter_names:
        members = draw(
            st.lists(
                st.sampled_from(verbs), min_size=1, max_size=len(verbs), unique=True
            )
        )
        counters.append(CounterDecl(name=name, verbs=frozenset(members)))
        clauses.append(
            Cap(
                counter=name,
                bound=draw(st.integers(min_value=0, max_value=10**6)),
                unit=draw(st.one_of(st.none(), IDENTS)),
            )
        )

    for verb in draw(
        st.lists(st.sampled_from(verbs), max_size=len(verbs), unique=True)
    ):
        allowed = draw(st.lists(TARGETS, min_size=1, max_size=3, unique=True))
        clauses.append(Whitelist(verb=verb, allowed=frozenset(allowed)))

    for verb in draw(
        st.lists(st.sampled_from(verbs), max_size=len(verbs), unique=True)
    ):
        clauses.append(Prohibition(verb=verb))

    if not clauses:
        clauses.append(Prohibition(verb=verbs[0]))
    return Policy(counters=tuple(counters), clauses=tuple(clauses))


def _amounts(policy: Policy) -> st.SearchStrategy:
    """Amounts a hostile agent would try, including everything alpha must sink."""
    c_max = policy.c_max
    interesting = sorted({0, 1, c_max, c_max + 1, c_max - 1, -1, -c_max})
    return st.one_of(
        st.sampled_from(interesting),
        st.integers(min_value=-10, max_value=max(c_max, 1)),
        st.integers(),
        st.floats(allow_nan=True, allow_infinity=True),
        st.booleans(),
        st.none(),
        st.text(max_size=3),
    )


def _near_miss(target: str) -> list[str]:
    """Names that look like a whitelisted one but are not it."""
    return [target + " ", " " + target, target.upper(), target + "​", target * 2]


def hostile_actions(policy: Policy) -> st.SearchStrategy:
    """Actions an adversarial agent might submit against this phi."""
    known_verbs = sorted(policy.verbs)
    known_targets = sorted(policy.targets)
    near_misses = [m for t in known_targets if t for m in _near_miss(t)]

    verbs = st.one_of(
        st.sampled_from(known_verbs) if known_verbs else st.none(),
        IDENTS,
        st.text(max_size=5),
        st.none(),
        st.integers(),
    )
    targets = st.one_of(
        st.sampled_from(known_targets) if known_targets else st.none(),
        st.sampled_from(near_misses) if near_misses else st.none(),
        TARGETS,
        st.none(),
        st.integers(),
    )
    return st.builds(
        ConcreteAction,
        verb=verbs,
        target=targets,
        amount=_amounts(policy),
        attrs=st.just({}),
    )
