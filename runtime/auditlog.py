"""VDP L4 — the append-only, hash-chained audit log (DESIGN.md section 6).

    hash_i = SHA256(prev_hash || canonical(record without hash and sig))
    hash_0 chains from a genesis constant that includes policy_hash
    sig     = HMAC-SHA256(k_log, hash_i)

Ordering comes from `seq` and the chain, NOT from wall-clock time. There is no
timestamp in a record and no clock is read anywhere in this file, so a log
replays identically on any machine and no decision can depend on the hour.

--- What is honest about "append-only" ---

Append-only is enforced by the API -- there is no update method and no delete
method, and the file is opened in append mode -- and that is ALL it is enforced
by. Against an attacker with filesystem write access, tampering is DETECTABLE,
NOT PREVENTABLE, and detectable only by a verifier who knows the latest `hash_n`
from outside the file.

TRUNCATION OF THE TAIL IS UNDETECTABLE without such an external anchor, and
this log has no network access with which to publish one itself. `verify()`
says so in its own result rather than quietly reporting success: a truncated
log is a VALID CHAIN over fewer records, and no amount of hashing inside the
file can change that. `AuditLog(..., on_append=...)` is the wiring point --
publish each `head` somewhere the agent cannot write and the gap closes; leave
it unwired and it stays open, which is why `verify()` keeps saying so.

--- What durability is worth ---

A record is written and flushed to disk with `fsync` before `append()`
returns (`fsync=False` opts out, for tests and throughput). DESIGN.md section
3.3 fixes the order as decide, execute, log -- so a crash between an action
executing and a buffered write reaching disk would leave an action that
HAPPENED with no evidence that it did. Of the two directions this can fail
in, that is the one that must not happen.

--- What `sig` is worth ---

`sig` is an HMAC, which is symmetric. It gives integrity against the AGENT,
which does not hold `k_log`. It gives NO NON-REPUDIATION against the monitor
itself, because a verifier has to be handed the same key that signs. An auditor
using this can conclude "the agent did not forge this." It cannot conclude "the
monitor did not forge this." Asymmetric signatures would be needed for the
second claim and are not implemented (see `runtime/attest.py`).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from monitor.automaton import BAD, Automaton, Symbol

__all__ = ["AuditLog", "AuditLogError", "Record", "VerificationResult", "genesis_hash"]


class AuditLogError(ValueError):
    """A malformed record or an unusable log file."""


def _fsync_dir(directory: Path) -> None:
    """Sync a directory entry, where the platform has such a thing.

    POSIX needs this for a newly created file to be findable after a crash.
    Windows has no directory file descriptor to open, so `os.open` on one
    fails -- that is expected, not an error to propagate out of `append()`.
    """
    try:
        fd = os.open(directory, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


_GENESIS_DOMAIN = b"vdp/v1/genesis\x00"

#: SHA-256 / HMAC-SHA256 output, hex. `token_id` is deliberately NOT held to
#: this: it carries the sentinel "<no-token>" when an agent presented none.
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")

#: Fields that are hashed. `hash` and `sig` are excluded because they are
#: derived from exactly these.
_HASHED_FIELDS = (
    "seq",
    "action",
    "symbol",
    "pre_state",
    "post_state",
    "decision",
    "reason",
    "token_id",
    "policy_hash",
    "prev_hash",
)

#: The type every field must have. A record that satisfies the key set but not
#: these is malformed, and `Record.from_obj` refuses it rather than letting a
#: wrong type surface later as a TypeError instead of a verdict.
_FIELD_TYPES: dict[str, type] = {
    "seq": int,
    "action": dict,
    "symbol": dict,
    "pre_state": list,
    "post_state": list,
    "decision": str,
    "reason": str,
    "token_id": str,
    "policy_hash": str,
    "prev_hash": str,
    "hash": str,
    "sig": str,
}


def genesis_hash(policy_hash: str) -> str:
    """hash_0's predecessor. Binds the whole log to the exact policy artifact.

    A log produced under one phi cannot be presented as a log produced under
    another: every hash in the chain depends on this value.
    """
    if not isinstance(policy_hash, str):
        raise AuditLogError("policy_hash must be a string")
    return hashlib.sha256(_GENESIS_DOMAIN + policy_hash.encode("utf-8")).hexdigest()


def _plain(value: object) -> object:
    """JSON-safe view of an agent-supplied value.

    A hostile agent can submit any object at all, and the log has to record what
    it submitted. Anything that is not a JSON scalar is stored as its `repr`, so
    an unserializable payload cannot break the log or -- worse -- cause the
    record to be silently dropped.
    """
    if value is None or isinstance(value, (bool, int, str)):
        return value
    return repr(value)


def _canonical(obj: dict) -> bytes:
    """Canonical JSON for a log record. ASCII-ONLY, deliberately.

    `ensure_ascii=True` is a format requirement here, not a stylistic choice.
    JSONL means one record per PHYSICAL LINE, and an agent controls the target
    string. Python's `str.splitlines()` -- and many other line splitters --
    break on U+0085, U+000B, U+000C, U+2028 and U+2029 as well as on newline, so
    an unescaped one of those inside a target would split a single record into
    two for any reader that uses them. Escaping every non-ASCII character makes
    that impossible.

    The same function computes the hash and writes the line, so the chain is
    over exactly the bytes on disk.
    """
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")


def _state_obj(state) -> list:
    """A state as plain data. q_bad never appears in practice: the monitor does
    not enter it, and a BLOCK records pre_state on both sides."""
    if state is BAD:
        return ["q_bad"]
    return list(state)


@dataclass(frozen=True, slots=True)
class Record:
    """One mediated action. Immutable; `hash` and `sig` are computed, not set."""

    seq: int
    action: dict
    symbol: dict
    pre_state: list
    post_state: list
    decision: str
    reason: str
    token_id: str
    policy_hash: str
    prev_hash: str
    hash: str
    sig: str

    def hashed_obj(self) -> dict:
        return {field: getattr(self, field) for field in _HASHED_FIELDS}

    def to_obj(self) -> dict:
        obj = self.hashed_obj()
        obj["hash"] = self.hash
        obj["sig"] = self.sig
        return obj

    @staticmethod
    def from_obj(obj: object) -> "Record":
        """Rebuild a record from plain data. STRICT: this parses hostile input.

        Both the key set AND the value types are checked. Checking only the keys
        would let a tampered line through the parser and turn a detection into a
        TypeError somewhere downstream -- which is a crash, not a verdict. Every
        rejection here is an `AuditLogError`, so a caller sees "this log is bad"
        rather than an arbitrary exception from arbitrary code.
        """
        if not isinstance(obj, dict):
            raise AuditLogError(f"record must be an object, got {type(obj).__name__}")
        expected = set(_HASHED_FIELDS) | {"hash", "sig"}
        if set(obj) != expected:
            raise AuditLogError(
                f"record keys differ from the schema: {sorted(set(obj) ^ expected)}"
            )

        for field, kind in _FIELD_TYPES.items():
            value = obj[field]
            # bool subclasses int; a boolean seq would pass an isinstance check.
            if kind is int and isinstance(value, bool):
                raise AuditLogError(f"{field} must be an integer, got a bool")
            if not isinstance(value, kind):
                raise AuditLogError(
                    f"{field} must be {kind.__name__}, got {type(value).__name__}"
                )
        if obj["seq"] < 0:
            raise AuditLogError(f"seq must be non-negative, got {obj['seq']}")

        # The four digest fields are always SHA-256 or HMAC-SHA256 output that
        # this system produced, so they are 64 lowercase hex characters. The
        # check is not cosmetic: `hmac.compare_digest` RAISES on a non-ASCII
        # string, so a tampered digest containing one would crash `verify()`
        # instead of failing it -- turning a detection into an exception.
        for field in ("hash", "sig", "prev_hash", "policy_hash"):
            if not _HEX64_RE.match(obj[field]):
                raise AuditLogError(
                    f"{field} is not a 64-character lowercase hex digest"
                )

        return Record(**obj)


@dataclass(frozen=True, slots=True)
class VerificationResult:
    """The outcome of replaying a log. `ok` is never the whole story."""

    ok: bool
    checked: int
    problems: tuple[str, ...] = ()
    #: Always True from inside the file. A verifier who does not hold `hash_n`
    #: from outside it cannot tell a complete log from a truncated one, no
    #: matter what the chain says. This field exists so nobody reads
    #: `ok is True` as "nothing was removed."
    tail_truncation_undetectable: bool = True

    def summary(self) -> str:
        lines = [f"{'OK' if self.ok else 'FAILED'}: {self.checked} record(s) checked"]
        lines.extend(f"  - {problem}" for problem in self.problems)
        if self.ok:
            lines.append(
                "  note: tail truncation cannot be detected from inside the file; "
                "compare the final hash against an external anchor "
                "(AuditLog(on_append=...)) to close that gap"
            )
        return "\n".join(lines)


class AuditLog:
    """Append-only JSONL. No update method, no delete method, and none will be
    added: those are the only two operations that could rewrite history.

    The agent must never hold a reference to this object. It is reached only
    through `runtime.shim`, which exposes `call()` and nothing else.
    """

    __slots__ = (
        "_path",
        "_policy_hash",
        "_log_key",
        "_last_hash",
        "_seq",
        "_on_append",
        "_fsync",
    )

    def __init__(
        self,
        path: str | Path,
        policy_hash: str,
        log_key: bytes,
        *,
        on_append: "Callable[[str], None] | None" = None,
        fsync: bool = True,
    ) -> None:
        """
        `fsync`: default True. Each `append()` flushes the record and calls
        `os.fsync` before returning, so a record exists on disk before the
        caller proceeds. The decision order is decide, execute, log
        (DESIGN.md section 3.3); with buffered writes alone, a crash in that
        window loses the evidence for an action that already happened, which
        is the one failure direction an audit log cannot have. Set it False
        only where losing the tail on a crash is acceptable -- tests, or a
        throughput measurement that says so.

        `on_append`: optional. If given, called with the new `head` hash
        (hex string) after every successful `append()` -- including for a
        BLOCK, since a blocked attempt still advances the chain (section
        6.1: it is evidence, not automaton state). This is the first-class
        way to publish the latest hash somewhere the agent cannot write, so
        that tail truncation (section 6.3's documented gap: undetectable
        without an external anchor) becomes detectable to anyone who saw a
        later `head` than what a tampered file now shows. `AuditLog.head`
        already exposed this value as a property; `on_append` exists because
        a value nobody is wired to read protects nothing.

        Exceptions raised by `on_append` propagate to the `append()` caller
        AFTER the record has already been written to disk and `_last_hash`
        updated -- publication failing is not grounds to un-write a record
        that already happened, the same "under-spend, never roll back"
        philosophy DESIGN.md section 3.3 applies to execution.
        """
        if not isinstance(log_key, (bytes, bytearray)) or len(log_key) < 32:
            raise AuditLogError("log_key must be at least 32 bytes")
        self._path = Path(path)
        self._policy_hash = policy_hash
        self._log_key = bytes(log_key)
        self._last_hash = genesis_hash(policy_hash)
        self._seq = 0
        self._on_append = on_append
        self._fsync = bool(fsync)

        # Resume an existing log rather than overwriting it: opening for write
        # would be a delete in disguise.
        if self._path.exists():
            records = self.records()
            for record in records:
                if record.policy_hash != policy_hash:
                    raise AuditLogError(
                        "existing log was written under a different policy_hash; a "
                        "new policy is a new authorization and needs a new log"
                    )
            if records:
                self._last_hash = records[-1].hash
                self._seq = records[-1].seq + 1

    @property
    def path(self) -> Path:
        return self._path

    @property
    def policy_hash(self) -> str:
        return self._policy_hash

    @property
    def head(self) -> str:
        """The latest hash. Publish this outside the file if you want tail
        truncation to be detectable at all."""
        return self._last_hash

    def _sign(self, digest: str) -> str:
        return hmac.new(self._log_key, digest.encode("utf-8"), hashlib.sha256).hexdigest()

    def append(
        self,
        *,
        action,
        symbol: Symbol,
        pre_state,
        post_state,
        decision: str,
        reason: str,
        token_id: str,
    ) -> Record:
        """Write one record and link it into the chain. The ONLY writer.

        Blocked attempts are recorded exactly like allowed ones. They are
        evidence, not state: they appear here and change nothing in the monitor.
        """
        body = {
            "seq": self._seq,
            "action": {
                "verb": _plain(getattr(action, "verb", None)),
                "target": _plain(getattr(action, "target", None)),
                "amount": _plain(getattr(action, "amount", None)),
                "attrs": {
                    str(key): _plain(value)
                    for key, value in dict(getattr(action, "attrs", {}) or {}).items()
                },
            },
            "symbol": {
                "verb": symbol.verb,
                "target": symbol.target,
                "amount": symbol.amount,
            },
            "pre_state": _state_obj(pre_state),
            "post_state": _state_obj(post_state),
            "decision": decision,
            "reason": reason,
            "token_id": token_id,
            "policy_hash": self._policy_hash,
            "prev_hash": self._last_hash,
        }
        digest = hashlib.sha256(
            self._last_hash.encode("utf-8") + _canonical(body)
        ).hexdigest()
        record = Record(**body, hash=digest, sig=self._sign(digest))

        is_new = not self._path.exists()
        with self._path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(_canonical(record.to_obj()).decode("utf-8") + "\n")
            if self._fsync:
                handle.flush()
                os.fsync(handle.fileno())
        if self._fsync and is_new:
            # A newly created file's DIRECTORY entry needs its own sync on
            # POSIX, or the first record can survive as a file nobody can
            # find. Best effort: Windows has no directory file descriptor to
            # sync, and raises here rather than silently doing nothing.
            _fsync_dir(self._path.parent)

        self._last_hash = digest
        self._seq += 1
        if self._on_append is not None:
            self._on_append(digest)
        return record

    def records(self) -> list[Record]:
        """Read the log back. Pure; does not touch the chain state."""
        if not self._path.exists():
            return []
        out: list[Record] = []
        with self._path.open("r", encoding="utf-8") as handle:
            for lineno, line in enumerate(handle, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(Record.from_obj(json.loads(line)))
                except (json.JSONDecodeError, AuditLogError, TypeError) as exc:
                    raise AuditLogError(f"line {lineno}: {exc}") from exc
        return out

    def verify(self, automaton: Automaton | None = None) -> VerificationResult:
        """Replay the log: chain links, signatures, and -- with an automaton --
        the transitions themselves.

        The automaton check is PURE TRANSITION CHECKING: recompute
        delta(pre_state, symbol) and confirm it equals post_state for an ALLOW,
        or lands in q_bad with post_state == pre_state for a BLOCK. No network,
        no clock. The crypto only detects tampering with the FILE; the automaton
        check is what establishes that the decisions were the ones phi mandates.
        """
        problems: list[str] = []
        prev = genesis_hash(self._policy_hash)
        try:
            records = self.records()
        except AuditLogError as exc:
            # An unreadable line is a FINDING about the log, not a crash in
            # the verifier. Same reasoning as `Record.from_obj`'s hex check
            # (see above): a tampered or half-written file must produce a
            # verdict, because a verifier that raises tells an operator far
            # less than one that says "record 7 is unparsable".
            return VerificationResult(
                ok=False, checked=0, problems=(f"log is unreadable: {exc}",)
            )

        for index, record in enumerate(records):
            where = f"record {index} (seq {record.seq})"
            if record.seq != index:
                problems.append(f"{where}: seq is out of order")
            if record.policy_hash != self._policy_hash:
                problems.append(f"{where}: written under a different policy")
            if record.prev_hash != prev:
                problems.append(f"{where}: prev_hash does not link to the previous record")
            expected = hashlib.sha256(
                record.prev_hash.encode("utf-8") + _canonical(record.hashed_obj())
            ).hexdigest()
            if not hmac.compare_digest(expected, record.hash):
                problems.append(f"{where}: hash does not match its contents")
            if not hmac.compare_digest(self._sign(record.hash), record.sig):
                problems.append(f"{where}: signature does not verify")
            if automaton is not None:
                problems.extend(_replay_problems(automaton, record, where))
            prev = record.hash

        return VerificationResult(
            ok=not problems, checked=len(records), problems=tuple(problems)
        )


def _replay_problems(automaton: Automaton, record: Record, where: str) -> list[str]:
    try:
        symbol = Symbol(
            verb=record.symbol["verb"],
            target=record.symbol["target"],
            amount=record.symbol["amount"],
        )
        pre = tuple(record.pre_state)
    except (KeyError, TypeError) as exc:
        return [f"{where}: cannot rebuild the symbol or state ({exc})"]

    try:
        post = automaton.delta(pre, symbol)
    except (ValueError, TypeError) as exc:
        return [f"{where}: state does not belong to this automaton ({exc})"]

    problems: list[str] = []
    if record.decision == "ALLOW":
        if post is BAD:
            problems.append(f"{where}: recorded ALLOW but delta lands in q_bad")
        elif list(post) != list(record.post_state):
            problems.append(f"{where}: post_state does not match delta(pre, symbol)")
    elif record.decision == "BLOCK":
        if post is not BAD:
            problems.append(f"{where}: recorded BLOCK but delta does not reach q_bad")
        if list(record.post_state) != list(record.pre_state):
            problems.append(f"{where}: a BLOCK must leave the state unchanged")
    else:
        problems.append(f"{where}: unknown decision {record.decision!r}")
    return problems
