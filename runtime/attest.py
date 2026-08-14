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
from runtime.auditlog import Record

__all__ = ["Attestation", "Attestor", "NullAttestor"]


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
    """The shipped implementation. Attests nothing, and says so.

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
