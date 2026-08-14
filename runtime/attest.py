"""VDP L4 — external attestation interface. STUBBED ON PURPOSE.

DESIGN.md section 6.4. The shipped implementation is `NullAttestor`, which
returns "not attested" and nothing else.

--- Why this is a stub and not a feature ---

Local verification (`AuditLog.verify`) is pure automaton transition checking and
needs no assumption beyond "SHA-256 and HMAC behave." Anything CROSSING this
interface is a different animal: a bank, hospital, or auditor wants a statement
they can check without being handed `k_log` and without being shown the whole
trace.

Any real instantiation -- asymmetric signatures for non-repudiation, or a
succinct non-interactive proof of policy compliance that does not reveal the
trace -- is AT BEST COMPUTATIONALLY SOUND UNDER STANDARD ASSUMPTIONS. It needs a
hardness assumption, possibly a trusted setup, and it must be labeled as such
wherever it is surfaced.

This module therefore ships no implementation that could be mistaken for one.
`Attestation.claim` is the only text a UI may show, and `NullAttestor` sets it
to a sentence saying nothing has been attested. Nothing here prints the word
"proven", and nothing built on this interface should either.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, Sequence

from policy.ast import Policy
from runtime.auditlog import Record, genesis_hash

__all__ = [
    "Attestation",
    "Attestor",
    "Ed25519Attestor",
    "NullAttestor",
    "AttestError",
]


@dataclass(frozen=True, slots=True)
class Attestation:
    """What an attestor returns. `attested=False` is a complete, valid answer."""

    attested: bool
    #: The ONLY string a UI may display for this attestation. It must state the
    #: assumption any claim rests on, or state that there is no claim.
    claim: str
    #: Opaque to VDP: a signature, a proof, or nothing.
    evidence: bytes = b""


class Attestor(Protocol):
    """External attestation. Optional, and not on any decision path.

    An implementation must not be consulted to decide whether an action is
    allowed. The monitor decides; an attestor only makes a statement afterwards
    that a third party might check.
    """

    def attest(self, log_segment: Sequence[Record], policy: Policy) -> Attestation: ...

    def verify(self, attestation: Attestation) -> bool: ...


class NullAttestor:
    """The shipped DEFAULT implementation. Attests nothing, and says so.

    It exists so callers can be written against `Attestor` without any caller
    ever being able to display an unearned claim.
    """

    __slots__ = ()

    _CLAIM = (
        "NOT ATTESTED. VDP v0.1 ships no external attestation. Local verification "
        "of the audit log establishes that the recorded decisions follow from phi "
        "and that the file has not been edited by anyone lacking the log key. It "
        "does not establish anything to a third party who does not hold that key, "
        "and it cannot detect truncation of the log's tail."
    )

    def attest(self, log_segment: Sequence[Record], policy: Policy) -> Attestation:
        return Attestation(attested=False, claim=self._CLAIM, evidence=b"")

    def verify(self, attestation: Attestation) -> bool:
        """False for anything. There is nothing here that could be verified."""
        return False


_ED25519_CLAIM = (
    "Ed25519 signature over (policy_hash, log head) by the issuer's public key. "
    "This is AT BEST computationally sound under the discrete-log-in-elliptic-"
    "curves hardness assumption -- it is not a proof. It establishes only that "
    "THIS issuer produced THIS checkpoint at some point; it does NOT establish "
    "that the recorded decisions follow from phi (that is what local replay, "
    "AuditLog.verify, is for -- and this attestor's signature says nothing "
    "about whether that replay would succeed) and it does NOT detect tail "
    "truncation between this checkpoint and the next one."
)

_ED25519_DOMAIN = b"vdp/v1/attest/ed25519\x00"


def _ed25519_message(policy_hash: str, head: str) -> bytes:
    """Bytes an Ed25519 checkpoint signs over: which policy, which log head."""
    return _ED25519_DOMAIN + policy_hash.encode("utf-8") + b"\x00" + head.encode("utf-8")


class AttestError(ValueError):
    """Ed25519Attestor was asked to attest without a private key."""


class Ed25519Attestor:
    """Optional, OPT-IN external attestation via Ed25519 checkpoint signatures.

    Requires the third-party `cryptography` package, imported lazily (only
    when this class is instantiated) so the rest of VDP -- including the
    entire enforcement path -- stays standard-library-only per DESIGN.md's
    stated rationale. Install it with `pip install cryptography` if you want
    this class; nothing else in VDP needs it.

    This is exactly the kind of instantiation `runtime.attest`'s module
    docstring warns about: it is AT BEST computationally sound under a
    standard hardness assumption, and it is labeled as such in every
    `Attestation.claim` it produces -- see `_ED25519_CLAIM`. It signs a
    CHECKPOINT (policy_hash + the log's current head), not the trace itself:
    a verifier who trusts the issuer's public key learns "this issuer vouched
    for this exact head at some point," which is a non-repudiation claim
    (unlike `AuditLog`'s own HMAC signature, which is symmetric and proves
    only "the agent did not forge this"). It is still NOT a proof that the
    recorded decisions follow from phi; that is `AuditLog.verify`'s job, and
    this class never substitutes for it -- `attest`/`verify` here are
    reachable from no decision path, exactly as `runtime.attest.Attestor`
    requires.
    """

    __slots__ = ("_private_key", "_public_key")

    def __init__(self, *, private_key: object = None, public_key: object = None) -> None:
        """
        At least one of `private_key` / `public_key` MUST be given.
        `private_key`, an `ed25519.Ed25519PrivateKey`, is required to call
        `attest()` (the issuer's role). `public_key`, an
        `ed25519.Ed25519PublicKey`, is required to call `verify()` (the
        auditor's role) -- if omitted but `private_key` is given, it is
        derived automatically via `private_key.public_key()`, so an issuer
        that also wants to self-check can use one instance for both roles.
        """
        try:
            from cryptography.hazmat.primitives.asymmetric import ed25519
        except ImportError as exc:  # pragma: no cover - exercised only without the dep
            raise ImportError(
                "Ed25519Attestor requires the optional 'cryptography' package: "
                "pip install cryptography"
            ) from exc

        if private_key is None and public_key is None:
            raise ValueError("Ed25519Attestor needs a private_key, a public_key, or both")
        if private_key is not None and not isinstance(
            private_key, ed25519.Ed25519PrivateKey
        ):
            raise TypeError(
                f"private_key must be an Ed25519PrivateKey, got {type(private_key).__name__}"
            )
        if public_key is not None and not isinstance(
            public_key, ed25519.Ed25519PublicKey
        ):
            raise TypeError(
                f"public_key must be an Ed25519PublicKey, got {type(public_key).__name__}"
            )

        self._private_key = private_key
        self._public_key = public_key if public_key is not None else (
            private_key.public_key() if private_key is not None else None
        )

    def attest(self, log_segment: Sequence[Record], policy: Policy) -> Attestation:
        """Sign a checkpoint over (policy_hash, current log head).

        `log_segment` is used only for its LAST record's hash (the current
        chain tip) -- consistent with this being a checkpoint signature, not
        a per-record one. An empty segment signs the policy's genesis hash
        instead, so a checkpoint can be produced even before any action has
        been mediated.
        """
        if self._private_key is None:
            raise AttestError(
                "this Ed25519Attestor has no private_key; it can verify but not attest"
            )
        if not isinstance(policy, Policy):
            raise TypeError(f"policy must be a Policy, got {type(policy).__name__}")

        head = log_segment[-1].hash if log_segment else genesis_hash(policy.digest())
        message = _ed25519_message(policy.digest(), head)
        signature = self._private_key.sign(message)
        return Attestation(
            attested=True, claim=_ED25519_CLAIM, evidence=signature + message
        )

    def verify(self, attestation: Attestation) -> bool:
        """Recompute and check the signature. Never raises for bad input.

        Returns False for anything malformed, unattested, or wrong-length --
        same "verdict, not exception" discipline as `tokens.macaroon.verify`.
        """
        if self._public_key is None:
            return False
        if not isinstance(attestation, Attestation) or not attestation.attested:
            return False
        evidence = attestation.evidence
        if not isinstance(evidence, (bytes, bytearray)) or len(evidence) < 64:
            return False
        signature, message = bytes(evidence[:64]), bytes(evidence[64:])
        try:
            self._public_key.verify(signature, message)
        except Exception:
            # InvalidSignature is the expected failure; anything else raised
            # by a hostile evidence blob is caught here too rather than
            # propagating out of a function whose contract is a bool.
            return False
        return True
