"""Conformance vectors, actually executed (SPEC.md section 10).

`spec/conformance/*.vectors.json` is what SPEC.md section 10 names as the
criterion for claiming conformance to `vdp-spec-0.3`. Until this file existed
the vectors were shipped DATA -- a second implementer could check themselves
against them, but the reference implementation could drift from its own
published fixtures and every test in this suite would still pass. That is the
wrong way round: the vectors are worth trusting only if the implementation
that generated them is held to them on every commit.

The files are read the way an OUTSIDE implementation must read them: rebuilt
into a `Policy` from the artifact JSON, replayed through `alpha` and `delta`,
compared against `expect` exactly. Nothing here reaches into a private helper
that produced the vectors -- a test that regenerates a fixture and compares it
to itself proves nothing.

Note on direction: SPEC.md section 2.4 makes the canonical form WRITE-only in
this implementation (`policy_hash` is computed from it; nothing reads it
back). `_policy_from_obj` below is therefore test-local on purpose. It reads
the same artifact shape a second implementation must parse, which is exactly
what the vectors are for -- but promoting it to library code would be a spec
commitment (SPEC.md section 9's `version: 1` refusal rule binds any
implementation that DOES load artifacts back), not a refactor.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from monitor.automaton import BAD, Automaton, ConcreteAction
from policy.ast import Cap, CounterDecl, Policy, Prohibition, Whitelist

VECTOR_DIR = Path(__file__).resolve().parent.parent / "spec" / "conformance"

#: The spec revision these vectors are stamped with. A vector file declaring
#: anything else is a version mismatch, not a test to run -- SPEC.md section 9
#: requires refusing an unrecognized revision rather than guessing at it.
EXPECTED_SPEC_VERSION = "vdp-spec-0.3"

#: Artifact shape version (SPEC.md section 2.4). `version: 1` is retired
#: (SPEC.md section 9) and MUST be refused, not defaulted.
EXPECTED_ARTIFACT_VERSION = 2


def _policy_from_obj(obj: dict) -> Policy:
    """Rebuild a `Policy` from a canonical policy-artifact object.

    Deliberately strict, the way SPEC.md section 9 requires a loader to be: an
    unknown artifact `version` is refused rather than best-effort interpreted,
    and an unknown clause `kind` is an error rather than a skipped clause --
    silently dropping one would turn a vector that tests a prohibition into a
    vector that tests nothing.
    """
    version = obj.get("version")
    if version != EXPECTED_ARTIFACT_VERSION:
        raise AssertionError(
            f"artifact version {version!r} is not {EXPECTED_ARTIFACT_VERSION}; "
            "SPEC.md section 9 requires refusing an unrecognized version"
        )

    counters = tuple(
        CounterDecl(
            name=decl["name"],
            verbs=frozenset(decl["verbs"]),
            counting=bool(decl.get("counting", False)),
            per_target=bool(decl.get("per_target", False)),
        )
        for decl in obj["counters"]
    )

    clauses: list[Cap | Whitelist | Prohibition] = []
    for clause in obj["clauses"]:
        kind = clause["kind"]
        if kind == "cap":
            clauses.append(
                Cap(
                    counter=clause["counter"],
                    bound=clause["bound"],
                    unit=clause.get("unit"),
                )
            )
        elif kind == "whitelist":
            clauses.append(
                Whitelist(verb=clause["verb"], allowed=frozenset(clause["allowed"]))
            )
        elif kind == "prohibition":
            clauses.append(Prohibition(verb=clause["verb"]))
        else:
            raise AssertionError(f"unknown clause kind {kind!r}")

    return Policy(counters=counters, clauses=tuple(clauses))


def _load_cases() -> list[tuple[str, str, dict, dict]]:
    """Flatten every vector file into (file, vector name, policy obj, vector).

    A file may declare one `policy` shared by all its vectors, or one per
    vector; both shapes appear in `spec/conformance/` today.
    """
    cases: list[tuple[str, str, dict, dict]] = []
    files = sorted(VECTOR_DIR.glob("*.vectors.json"))
    assert files, f"no vector files found in {VECTOR_DIR}"
    for path in files:
        doc = json.loads(path.read_text(encoding="utf-8"))
        assert doc.get("spec_version") == EXPECTED_SPEC_VERSION, (
            f"{path.name}: spec_version is {doc.get('spec_version')!r}, "
            f"expected {EXPECTED_SPEC_VERSION!r}"
        )
        shared = doc.get("policy")
        for vector in doc["vectors"]:
            policy_obj = vector.get("policy", shared)
            assert policy_obj is not None, (
                f"{path.name}:{vector['name']} declares no policy and the file "
                "has no shared one"
            )
            cases.append((path.name, vector["name"], policy_obj, vector))
    return cases


CASES = _load_cases()


def test_vector_files_are_discovered() -> None:
    """Guards the harness itself: a glob that silently matched nothing would
    make every parametrized test below vacuously pass."""
    assert len(CASES) >= 6


@pytest.mark.parametrize(
    ("filename", "name", "policy_obj", "vector"),
    CASES,
    ids=[f"{filename}::{name}" for filename, name, _, _ in CASES],
)
def test_conformance_vector(
    filename: str, name: str, policy_obj: dict, vector: dict
) -> None:
    """Replay one vector; every `expect` block must reproduce exactly.

    Per SPEC.md section 10 and `spec/conformance/README.md`: normalize the
    action via alpha, compute delta from `pre_state`, assert the decision and
    `post_state`, feed `post_state` forward. A BLOCK must leave the state
    unchanged (SPEC.md section 3.3).
    """
    automaton = Automaton(_policy_from_obj(policy_obj))
    state = automaton.q0

    for index, step in enumerate(vector["steps"]):
        where = f"{filename}::{name} step {index}"
        expect = step["expect"]

        assert list(state) == list(expect["pre_state"]), (
            f"{where}: pre_state drifted -- vector expects "
            f"{expect['pre_state']}, replay carried {list(state)}"
        )

        action = step["action"]
        symbol = automaton.alpha(
            ConcreteAction(
                verb=action["verb"],
                target=action["target"],
                amount=action["amount"],
            )
        )
        post = automaton.delta(state, symbol)

        if expect["decision"] == "ALLOW":
            assert post is not BAD, f"{where}: expected ALLOW, delta reached q_bad"
            assert list(post) == list(expect["post_state"]), (
                f"{where}: post_state is {list(post)}, vector expects "
                f"{expect['post_state']}"
            )
            state = post
        elif expect["decision"] == "BLOCK":
            assert post is BAD, f"{where}: expected BLOCK, delta produced {post!r}"
            assert list(expect["post_state"]) == list(expect["pre_state"]), (
                f"{where}: the vector itself is wrong -- a BLOCK must leave the "
                "state unchanged (SPEC.md section 3.3)"
            )
            # State is NOT advanced. That is the rule under test.
        else:
            raise AssertionError(f"{where}: unknown decision {expect['decision']!r}")


def test_artifact_version_one_is_refused() -> None:
    """SPEC.md section 9: a loader MUST refuse `version: 1` rather than
    defaulting the fields that revision lacked."""
    with pytest.raises(AssertionError, match="section 9"):
        _policy_from_obj(
            {
                "version": 1,
                "counters": [{"name": "spend", "verbs": ["pay"]}],
                "clauses": [
                    {"kind": "cap", "counter": "spend", "bound": 10, "unit": None}
                ],
            }
        )


# --------------------------------------------------------------------------
# The shipped JSON Schemas vs what the code actually emits
# --------------------------------------------------------------------------

SCHEMA_DIR = Path(__file__).resolve().parent.parent / "spec" / "schema"


def _schema(name: str) -> dict:
    return json.loads((SCHEMA_DIR / name).read_text(encoding="utf-8"))


@pytest.fixture
def jsonschema_module():
    """`jsonschema` is a test-only convenience, not a dependency of anything
    on the enforcement path. Skip rather than fail when it is absent."""
    return pytest.importorskip("jsonschema")


def test_policy_artifact_matches_its_schema(jsonschema_module):
    """SPEC.md section 10 ships these schemas so OTHER implementations can
    code against them. A schema that has drifted from what this code emits
    misleads every one of them, silently, and the CI check that the schema
    merely parses would not notice."""
    phi = _policy_from_obj(CASES[0][2])
    jsonschema_module.validate(phi.to_canonical_obj(), _schema("policy-artifact.schema.json"))


def test_token_wire_format_matches_its_schema(jsonschema_module):
    from tokens.macaroon import attenuate, mint
    from tokens.scope import Scope

    phi = _policy_from_obj(CASES[0][2])
    token = mint(b"k" * 32, Scope.root_from_policy(phi), policy_hash=phi.digest())
    jsonschema_module.validate(token.to_obj(), _schema("token.schema.json"))

    # An attenuated token carries caveats; the schema must cover that shape
    # too, not just the freshly minted one.
    narrowed = attenuate(token, Scope(verbs=frozenset({"pay"})))
    jsonschema_module.validate(narrowed.to_obj(), _schema("token.schema.json"))


def test_audit_record_matches_its_schema(tmp_path, jsonschema_module):
    from monitor.mediate import Monitor
    from runtime.auditlog import AuditLog

    phi = _policy_from_obj(CASES[0][2])
    log = AuditLog(tmp_path / "audit.jsonl", phi.digest(), b"l" * 32, fsync=False)
    symbol = Monitor(phi).automaton.alpha(
        ConcreteAction(verb="pay", target="alice", amount=1)
    )
    record = log.append(
        action=None,
        symbol=symbol,
        pre_state=(0,),
        post_state=(1,),
        decision="ALLOW",
        reason="conformance",
        token_id="<no-token>",
    )
    jsonschema_module.validate(record.to_obj(), _schema("audit-record.schema.json"))
