"""VDP L3 — the HMAC caveat chain (DESIGN.md section 5.3).

    t_0 = HMAC-SHA256(k,       canonical(S_0))
    t_i = HMAC-SHA256(t_{i-1}, canonical(C_i))

A presented token is `(S_0, [C_1 ... C_n], t_n)` and its effective scope is
`S_n = S_0 meet C_1 meet ... meet C_n`.

--- Two claims, resting on two different things ---

1. SCOPE MONOTONICITY -- `S_n <= S_0` at every depth. Set-theoretic and
   UNCONDITIONAL. It lives in `tokens/scope.py` and holds no matter what this
   file does, because `meet` is the only way to combine scopes.

2. UNFORGEABILITY -- an agent cannot present a token it was not given, and
   cannot strip a caveat to widen one it holds. CONDITIONAL on HMAC-SHA256
   being a secure PRF / existentially unforgeable, and on the root key `k`
   staying secret. If `k` leaks, an attacker mints whatever it likes. This file
   makes claim 2 and nothing stronger.

Stripping is prevented because recomputing `t_{n-1}` from `t_n` requires `k`
(or knowledge of `t_{n-1}` itself, which a downstream-only holder never had).
Note also that a PARENT still holds its own broader token. That is its own
authority being used, not an escalation, and VDP does not attempt to prevent it.

--- Attenuation needs no key ---

`attenuate` is computable by any holder: `t_i = HMAC(t_{i-1}, C_i)` uses the
token's own tag as the key. That is the macaroon property -- delegation without
contacting the issuer -- and it is why `mint` is the only function here that
takes `k`.

--- Domain separation ---

Root and caveat MACs are computed over distinct domain-separation prefixes, so a
caveat's bytes can never be reinterpreted as a root scope's bytes, or the other
way round, even though both are canonical `Scope` JSON.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass

from tokens.scope import Scope, ScopeError

__all__ = ["MIN_KEY_BYTES", "Token", "TokenError", "attenuate", "mint", "verify"]


class TokenError(ValueError):
    """A structurally invalid token. Never a verification verdict -- that is a
    bool, so that a forged token and a malformed one cannot be confused."""


#: 256 bits, matching the HMAC-SHA256 output. Shorter keys are refused rather
#: than accepted with a warning nobody reads.
MIN_KEY_BYTES = 32

_ROOT_DOMAIN = b"vdp/v1/root\x00"
_CAVEAT_DOMAIN = b"vdp/v1/caveat\x00"


def _check_key(key: object) -> bytes:
    if not isinstance(key, (bytes, bytearray)):
        raise TokenError(f"key must be bytes, got {type(key).__name__}")
    if len(key) < MIN_KEY_BYTES:
        raise TokenError(f"key must be at least {MIN_KEY_BYTES} bytes, got {len(key)}")
    return bytes(key)


def _mac(key: bytes, domain: bytes, payload: bytes) -> bytes:
    return hmac.new(key, domain + payload, hashlib.sha256).digest()


@dataclass(frozen=True, slots=True)
class Token:
    """`(S_0, [C_1 ... C_n], t_n)`. Immutable; there is no setter for the tag.

    Holding a Token is NOT authorization. `runtime.shim` verifies it against the
    root key on every call and checks the action against `scope` -- and the
    monitor still has to allow the action independently (DESIGN.md 5.4).
    """

    root: Scope
    caveats: tuple[Scope, ...]
    tag: bytes
    #: Which policy artifact this ROOT token was minted under. "" (default)
    #: means unbound -- two structurally-identical root scopes minted under
    #: DIFFERENT policies (same V-minus-prohibited, same T, same c_max; see
    #: `Scope.root_from_policy`) would otherwise verify interchangeably under
    #: a shared root key, even though each claims authority tied to no
    #: particular phi. Binding is opt-in at `mint()`; once present it is part
    #: of the MAC input (see `_mac` calls below), so it cannot be edited
    #: without invalidating the tag -- same protection `token_id` gets from
    #: the chain, extended to cover which policy this token means.
    policy_hash: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.root, Scope):
            raise TokenError(f"root must be a Scope, got {type(self.root).__name__}")
        caveats = tuple(self.caveats)
        for caveat in caveats:
            if not isinstance(caveat, Scope):
                raise TokenError(f"caveat must be a Scope, got {type(caveat).__name__}")
        object.__setattr__(self, "caveats", caveats)
        if not isinstance(self.tag, (bytes, bytearray)):
            raise TokenError(f"tag must be bytes, got {type(self.tag).__name__}")
        object.__setattr__(self, "tag", bytes(self.tag))
        if not isinstance(self.policy_hash, str):
            raise TokenError(
                f"policy_hash must be a string, got {type(self.policy_hash).__name__}"
            )

    @property
    def scope(self) -> Scope:
        """S_n = S_0 meet C_1 meet ... meet C_n. Recomputed, never stored.

        Storing it would create a second place for the scope to live and a way
        for the two to disagree. The chain of caveats is the truth.
        """
        result = self.root
        for caveat in self.caveats:
            result = result.meet(caveat)
        return result

    @property
    def depth(self) -> int:
        """Delegation depth n. 0 is a root token."""
        return len(self.caveats)

    def token_id(self) -> str:
        """Stable identifier for the SCOPE CHAIN, for the audit log.

        SHA-256 over the canonical root, its policy_hash binding, and the
        caveats. The tag is deliberately not included: the id goes into a log
        a third party may read, and it must not carry any part of a
        secret-keyed value.
        """
        digest = hashlib.sha256()
        digest.update(_ROOT_DOMAIN)
        digest.update(self.policy_hash.encode("utf-8"))
        digest.update(self.root.canonical())
        for caveat in self.caveats:
            digest.update(_CAVEAT_DOMAIN)
            digest.update(caveat.canonical())
        return digest.hexdigest()

    def to_obj(self) -> dict:
        return {
            "root": self.root.to_obj(),
            "caveats": [caveat.to_obj() for caveat in self.caveats],
            "tag": self.tag.hex(),
            "policy_hash": self.policy_hash,
        }

    @staticmethod
    def from_obj(obj: object) -> "Token":
        """Rebuild a token from plain data. STRICT: this parses hostile input.

        Raises on anything malformed. It does NOT verify -- a well-formed token
        and an authentic one are different questions, and conflating them is how
        a parser ends up being trusted.
        """
        if not isinstance(obj, dict):
            raise TokenError(f"token must be an object, got {type(obj).__name__}")
        extra = set(obj) - {"root", "caveats", "tag", "policy_hash"}
        if extra:
            raise TokenError(f"token has unknown key(s) {sorted(extra)}")
        missing = {"root", "caveats", "tag", "policy_hash"} - set(obj)
        if missing:
            raise TokenError(f"token is missing key(s) {sorted(missing)}")

        caveats_obj = obj["caveats"]
        if not isinstance(caveats_obj, list):
            raise TokenError(f"caveats must be a list, got {type(caveats_obj).__name__}")
        tag_hex = obj["tag"]
        if not isinstance(tag_hex, str):
            raise TokenError(f"tag must be a hex string, got {type(tag_hex).__name__}")
        try:
            tag = bytes.fromhex(tag_hex)
        except ValueError as exc:
            raise TokenError(f"tag is not valid hex: {exc}") from exc
        policy_hash = obj["policy_hash"]
        if not isinstance(policy_hash, str):
            raise TokenError(
                f"policy_hash must be a string, got {type(policy_hash).__name__}"
            )

        try:
            root = Scope.from_obj(obj["root"])
            caveats = tuple(Scope.from_obj(c) for c in caveats_obj)
        except ScopeError as exc:
            raise TokenError(str(exc)) from exc
        return Token(root=root, caveats=caveats, tag=tag, policy_hash=policy_hash)

    def serialize(self) -> bytes:
        """Canonical JSON transport form. Deterministic for a given token."""
        return json.dumps(
            self.to_obj(), sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")

    @staticmethod
    def deserialize(raw: object) -> "Token":
        if isinstance(raw, (bytes, bytearray)):
            try:
                text = bytes(raw).decode("utf-8")
            except UnicodeDecodeError as exc:
                raise TokenError(f"token bytes are not UTF-8: {exc}") from exc
        elif isinstance(raw, str):
            text = raw
        else:
            raise TokenError(f"expected bytes or str, got {type(raw).__name__}")
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError as exc:
            raise TokenError(f"token is not valid JSON: {exc}") from exc
        return Token.from_obj(parsed)


def mint(key: bytes, root: Scope, policy_hash: str = "") -> Token:
    """Issue a root token. The ONLY function here that needs `k`.

    Called by the issuer after the human confirmation gate, never by an agent.

    `policy_hash`: optional, and the default is the WEAKER of the two paths.
    "" (default) mints an unbound token, exactly as before this parameter
    existed -- the default is backward compatibility, not a recommendation.
    Passing `policy.digest()` binds this root token's tag to that specific
    policy artifact (Token.policy_hash), closing the gap where two
    structurally-identical root scopes minted under different policies verify
    interchangeably (SPEC.md section 5.1a). A deployment should pass it and
    have the verifier require it; SECURITY.md's deployment checklist lists
    this first for that reason.
    """
    key_bytes = _check_key(key)
    if not isinstance(root, Scope):
        raise TokenError(f"root must be a Scope, got {type(root).__name__}")
    if not isinstance(policy_hash, str):
        raise TokenError(
            f"policy_hash must be a string, got {type(policy_hash).__name__}"
        )
    return Token(
        root=root,
        caveats=(),
        tag=_mac(
            key_bytes, _ROOT_DOMAIN, policy_hash.encode("utf-8") + root.canonical()
        ),
        policy_hash=policy_hash,
    )


def attenuate(token: Token, caveat: Scope) -> Token:
    """Mint a child token by appending a caveat. Needs NO key.

    The child's effective scope is `token.scope meet caveat`, which is below the
    parent's for EVERY caveat, hostile ones included. There is no argument to
    this function that can widen anything -- see `tokens/scope.py`.

    `policy_hash` MUST carry over from the parent unchanged: it is part of
    the root's identity (section 5.1a), not a per-caveat concern, and the
    already-computed `token.tag` was built assuming exactly this value --
    defaulting it to "" here would silently break verification for every
    legitimately attenuated child of a bound token.
    """
    if not isinstance(token, Token):
        raise TokenError(f"expected a Token, got {type(token).__name__}")
    if not isinstance(caveat, Scope):
        raise TokenError(f"caveat must be a Scope, got {type(caveat).__name__}")
    return Token(
        root=token.root,
        caveats=token.caveats + (caveat,),
        tag=_mac(token.tag, _CAVEAT_DOMAIN, caveat.canonical()),
        policy_hash=token.policy_hash,
    )


def verify(key: bytes, token: object, expected_policy_hash: str | None = None) -> bool:
    """Recompute the chain and compare in constant time.

    Returns a BOOL and does not raise for a token object that is merely wrong: a
    caller must not be able to distinguish "forged" from "malformed" by catching
    a different exception. A bad key type is still an error, because that is a
    bug in the verifier's own configuration, not agent input.

    UNFORGEABILITY IS CONDITIONAL on the HMAC-SHA256 assumption and on `k`
    staying secret. This function does not and cannot establish more than that.

    `expected_policy_hash`: optional. If given, verification also fails
    unless `token.policy_hash == expected_policy_hash` -- e.g. a shim passing
    its own monitor's `policy.digest()` here refuses a token minted for a
    DIFFERENT policy even if that policy happens to produce an identical root
    scope. MAC integrity alone (the check above) proves policy_hash was not
    tampered with in transit; it does not by itself assert WHICH policy_hash
    a verifier requires -- this parameter is how a caller states that.
    """
    key_bytes = _check_key(key)
    if not isinstance(token, Token):
        return False
    if expected_policy_hash is not None and token.policy_hash != expected_policy_hash:
        return False
    expected = _mac(
        key_bytes,
        _ROOT_DOMAIN,
        token.policy_hash.encode("utf-8") + token.root.canonical(),
    )
    for caveat in token.caveats:
        expected = _mac(expected, _CAVEAT_DOMAIN, caveat.canonical())
    return hmac.compare_digest(expected, token.tag)
