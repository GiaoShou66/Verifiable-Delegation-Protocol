"""VDP L4 — the agent shim, the audit log, and the attestation stub.

Imports L1 (`policy`), L2 (`monitor`), and L3 (`tokens`). Imports nothing from
`demo`. This is the only layer that touches the filesystem, and it does so only
to append to the audit log -- never on the decision path, which stays a pure
function of (phi, q, token, action, now).

The agent's entire surface is `AgentShim.call()`. Everything else here is for
the operator or the auditor.
"""

from runtime.attest import Attestation, Attestor, NullAttestor
from runtime.auditlog import (
    AuditLog,
    AuditLogError,
    Record,
    VerificationResult,
    genesis_hash,
)
from runtime.shim import AgentShim, Outcome, ShimError, ToolSpec

__all__ = [
    "AgentShim",
    "Attestation",
    "Attestor",
    "AuditLog",
    "AuditLogError",
    "NullAttestor",
    "Outcome",
    "Record",
    "ShimError",
    "ToolSpec",
    "VerificationResult",
    "genesis_hash",
]
