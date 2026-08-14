"""L4 tests — Ed25519Attestor (SPEC.md section 6.4).

`cryptography` is an OPTIONAL dependency: nothing on VDP's enforcement path
needs it, and this module is skipped entirely if it is not installed, rather
than making the whole suite fail on a missing extra.
"""

from __future__ import annotations

import pytest

from policy.parser import parse
from runtime.attest import Attestation, AttestError, Ed25519Attestor
from runtime.auditlog import genesis_hash

ed25519 = pytest.importorskip(
    "cryptography.hazmat.primitives.asymmetric.ed25519",
    reason="cryptography is an optional dependency for Ed25519Attestor",
)

PHI = parse("counter spend over {pay}\nalways(spend <= 100)")


def _keypair():
    private = ed25519.Ed25519PrivateKey.generate()
    return private, private.public_key()


def test_attest_produces_a_verifiable_checkpoint_over_an_empty_segment():
    private, public = _keypair()
    attestor = Ed25519Attestor(private_key=private, public_key=public)
    attestation = attestor.attest([], PHI)
    assert attestation.attested is True
    assert attestor.verify(attestation) is True


def test_claim_never_says_proven():
    private, _ = _keypair()
    attestation = Ed25519Attestor(private_key=private).attest([], PHI)
    assert "proven" not in attestation.claim.lower()
    assert "computationally sound" in attestation.claim


def test_a_public_key_only_instance_can_verify_but_not_attest():
    private, public = _keypair()
    signer = Ed25519Attestor(private_key=private)
    attestation = signer.attest([], PHI)

    verifier = Ed25519Attestor(public_key=public)
    assert verifier.verify(attestation) is True
    with pytest.raises(AttestError, match="has no private_key"):
        verifier.attest([], PHI)


def test_a_foreign_public_key_does_not_verify():
    private_a, _ = _keypair()
    _, public_b = _keypair()
    attestation = Ed25519Attestor(private_key=private_a).attest([], PHI)
    assert Ed25519Attestor(public_key=public_b).verify(attestation) is False


def test_tampering_with_evidence_breaks_verification():
    private, public = _keypair()
    attestor = Ed25519Attestor(private_key=private, public_key=public)
    attestation = attestor.attest([], PHI)
    corrupted = bytearray(attestation.evidence)
    corrupted[0] ^= 1
    tampered = Attestation(
        attested=True, claim=attestation.claim, evidence=bytes(corrupted)
    )
    assert attestor.verify(tampered) is False


def test_verify_is_total_and_never_raises_on_hostile_evidence():
    private, public = _keypair()
    attestor = Ed25519Attestor(private_key=private, public_key=public)
    for evidence in (b"", b"short", b"\x00" * 64, object()):
        bad = Attestation(attested=True, claim="x", evidence=evidence)  # type: ignore[arg-type]
        assert attestor.verify(bad) is False
    assert attestor.verify(Attestation(attested=False, claim="x")) is False
    assert attestor.verify("not an attestation") is False  # type: ignore[arg-type]


def test_construction_requires_at_least_one_key():
    with pytest.raises(ValueError, match="private_key.*public_key.*or both"):
        Ed25519Attestor()


def test_construction_rejects_the_wrong_key_type():
    private, public = _keypair()
    with pytest.raises(TypeError, match="private_key must be"):
        Ed25519Attestor(private_key=public)  # a public key, wrong slot
    with pytest.raises(TypeError, match="public_key must be"):
        Ed25519Attestor(public_key=private)


def test_public_key_is_derived_from_private_key_when_omitted():
    private, public = _keypair()
    signer = Ed25519Attestor(private_key=private)
    attestation = signer.attest([], PHI)
    # The SAME instance can verify its own attestation without an explicit
    # public_key, because it derives one from private_key.public_key().
    assert signer.verify(attestation) is True


def test_different_policies_produce_different_checkpoints():
    private, public = _keypair()
    attestor = Ed25519Attestor(private_key=private, public_key=public)
    other = parse("counter spend over {pay}\nalways(spend <= 999)")
    a = attestor.attest([], PHI)
    b = attestor.attest([], other)
    assert a.evidence != b.evidence
    # Cross-checking is meaningless without knowing which policy a checkpoint
    # belongs to, but the raw signatures must at least differ.


def test_attest_with_no_dep_raises_a_clear_import_error(monkeypatch):
    """Simulate `cryptography` being absent: the ImportError must name the
    package and the install command, not surface a bare ModuleNotFoundError
    from deep inside the class."""
    import builtins

    real_import = builtins.__import__

    def blocking_import(name, *args, **kwargs):
        if name.startswith("cryptography"):
            raise ImportError("No module named 'cryptography'")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", blocking_import)
    with pytest.raises(ImportError, match="pip install cryptography"):
        Ed25519Attestor(private_key=object())
