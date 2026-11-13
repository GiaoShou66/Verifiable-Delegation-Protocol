"""VDP L3/L4 — Key Management & Epoch-Based Lifecycle (SECURITY.md).

VDP requires two independent 32-byte symmetric keys:
  - `k`: Root key for capability token unforgeability (SPEC.md section 5.3).
  - `k_log`: Audit log signature key (SPEC.md section 6.1).

Neither key may live on the agent's side of the boundary.
Because VDP has no in-place re-keying mechanism (rotating `k` invalidates all outstanding
tokens, and rotating `k_log` invalidates past log signatures), key rotation is modeled
as an explicit POLICY EPOCH boundary:
  New Keys -> New Policy Artifact -> New Epoch Directory & Audit Log.
"""

from __future__ import annotations

import base64
import os
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from runtime.auditlog import AuditLog, FileAnchorPublisher

__all__ = [
    "EnvKeyProvider",
    "EpochManager",
    "KMSError",
    "KeyProvider",
    "PolicyEpoch",
    "StaticKeyProvider",
]


class KMSError(ValueError):
    """Failure to retrieve or rotate keys."""


class KeyProvider(Protocol):
    """Protocol for retrieving root and log keys from secure storage (Env, Vault, KMS)."""

    def get_root_key(self, key_id: str = "default") -> bytes:
        """Retrieve the >=32 byte root token signing key."""
        ...

    def get_log_key(self, key_id: str = "default") -> bytes:
        """Retrieve the >=32 byte audit log HMAC key."""
        ...


def _decode_key(raw: str | bytes) -> bytes:
    if isinstance(raw, bytes):
        b = raw
    else:
        # Check if hex-encoded
        val = raw.strip()
        if len(val) >= 64 and all(c in "0123456789abcdefABCDEF" for c in val):
            try:
                b = bytes.fromhex(val)
            except ValueError:
                b = val.encode("utf-8")
        else:
            try:
                b = base64.b64decode(val, validate=True)
            except Exception:
                b = val.encode("utf-8")
    if len(b) < 32:
        raise KMSError(f"retrieved key must be at least 32 bytes, got {len(b)}")
    return b


class StaticKeyProvider:
    """Key provider backed by in-memory bytes (for testing or pre-configured services)."""

    __slots__ = ("_root_keys", "_log_keys")

    def __init__(
        self,
        root_key: bytes | str,
        log_key: bytes | str,
        *,
        extra_root_keys: dict[str, bytes | str] | None = None,
        extra_log_keys: dict[str, bytes | str] | None = None,
    ) -> None:
        self._root_keys: dict[str, bytes] = {"default": _decode_key(root_key)}
        self._log_keys: dict[str, bytes] = {"default": _decode_key(log_key)}
        if extra_root_keys:
            for kid, k in extra_root_keys.items():
                self._root_keys[kid] = _decode_key(k)
        if extra_log_keys:
            for kid, k in extra_log_keys.items():
                self._log_keys[kid] = _decode_key(k)

    def get_root_key(self, key_id: str = "default") -> bytes:
        if key_id not in self._root_keys:
            raise KMSError(f"unknown root key_id {key_id!r}")
        return self._root_keys[key_id]

    def get_log_key(self, key_id: str = "default") -> bytes:
        if key_id not in self._log_keys:
            raise KMSError(f"unknown log key_id {key_id!r}")
        return self._log_keys[key_id]


class EnvKeyProvider:
    """Key provider reading secrets from environment variables."""

    __slots__ = ("_root_var", "_log_var")

    def __init__(
        self,
        root_key_var: str = "VDP_ROOT_KEY",
        log_key_var: str = "VDP_LOG_KEY",
    ) -> None:
        self._root_var = root_key_var
        self._log_var = log_key_var

    def get_root_key(self, key_id: str = "default") -> bytes:
        var_name = self._root_var if key_id == "default" else f"{self._root_var}_{key_id.upper()}"
        val = os.environ.get(var_name)
        if not val:
            raise KMSError(f"environment variable {var_name!r} not set")
        return _decode_key(val)

    def get_log_key(self, key_id: str = "default") -> bytes:
        var_name = self._log_var if key_id == "default" else f"{self._log_var}_{key_id.upper()}"
        val = os.environ.get(var_name)
        if not val:
            raise KMSError(f"environment variable {var_name!r} not set")
        return _decode_key(val)


@dataclass(frozen=True, slots=True)
class PolicyEpoch:
    """Metadata describing one active policy and key epoch."""

    epoch_id: int
    policy_hash: str
    root_key_id: str
    log_key_id: str
    epoch_dir: Path
    log_path: Path
    anchor_path: Path


class EpochManager:
    """Manages epoch boundaries, archiving historical logs and rotating keys cleanly."""

    __slots__ = ("_base_dir", "_key_provider", "_current_epoch", "_active_log", "_active_anchor")

    def __init__(
        self,
        base_dir: str | Path,
        key_provider: KeyProvider,
        policy_hash: str,
        *,
        initial_epoch_id: int = 1,
        root_key_id: str = "default",
        log_key_id: str = "default",
    ) -> None:
        self._base_dir = Path(base_dir)
        self._base_dir.mkdir(parents=True, exist_ok=True)
        self._key_provider = key_provider
        epoch_dir = self._base_dir / f"epoch_{initial_epoch_id}"
        epoch_dir.mkdir(parents=True, exist_ok=True)

        log_path = epoch_dir / "audit.jsonl"
        anchor_path = epoch_dir / "audit.anchor"

        self._current_epoch = PolicyEpoch(
            epoch_id=initial_epoch_id,
            policy_hash=policy_hash,
            root_key_id=root_key_id,
            log_key_id=log_key_id,
            epoch_dir=epoch_dir,
            log_path=log_path,
            anchor_path=anchor_path,
        )
        self._active_anchor = FileAnchorPublisher(anchor_path)
        self._active_log = AuditLog(
            log_path,
            policy_hash=policy_hash,
            log_key=key_provider.get_log_key(log_key_id),
            anchor_publisher=self._active_anchor,
        )

    @property
    def current_epoch(self) -> PolicyEpoch:
        return self._current_epoch

    @property
    def active_log(self) -> AuditLog:
        return self._active_log

    @property
    def active_anchor(self) -> FileAnchorPublisher:
        return self._active_anchor

    def rotate_epoch(
        self,
        new_policy_hash: str | None = None,
        *,
        new_root_key_id: str | None = None,
        new_log_key_id: str | None = None,
    ) -> PolicyEpoch:
        """Finalize the current epoch and transition to the next epoch."""
        next_id = self._current_epoch.epoch_id + 1
        eff_policy_hash = new_policy_hash or self._current_epoch.policy_hash
        eff_root_kid = new_root_key_id or self._current_epoch.root_key_id
        eff_log_kid = new_log_key_id or self._current_epoch.log_key_id

        next_dir = self._base_dir / f"epoch_{next_id}"
        next_dir.mkdir(parents=True, exist_ok=True)
        next_log_path = next_dir / "audit.jsonl"
        next_anchor_path = next_dir / "audit.anchor"

        new_anchor = FileAnchorPublisher(next_anchor_path)
        new_log = AuditLog(
            next_log_path,
            policy_hash=eff_policy_hash,
            log_key=self._key_provider.get_log_key(eff_log_kid),
            anchor_publisher=new_anchor,
        )

        self._current_epoch = PolicyEpoch(
            epoch_id=next_id,
            policy_hash=eff_policy_hash,
            root_key_id=eff_root_kid,
            log_key_id=eff_log_kid,
            epoch_dir=next_dir,
            log_path=next_log_path,
            anchor_path=next_anchor_path,
        )
        self._active_log = new_log
        self._active_anchor = new_anchor
        return self._current_epoch

