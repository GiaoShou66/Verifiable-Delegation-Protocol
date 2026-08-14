"""VDP L3 — attenuable capability tokens.

Imports `policy` (L1) for `Scope.root_from_policy`. Imports nothing from
`monitor`, `runtime`, or `demo`. No network, no clock, no filesystem: a token
decision is a pure function of (key, token, action, now), where `now` is passed
in by the caller.

Two claims live here and they are NOT equally strong:

  - `S_n <= S_0` at every delegation depth is SET-THEORETIC and UNCONDITIONAL
    (`tokens/scope.py`).
  - Tokens cannot be forged, or widened by stripping a caveat, which is
    CONDITIONAL on HMAC-SHA256 unforgeability and on the root key staying
    secret (`tokens/macaroon.py`).

A valid token is NECESSARY, NOT SUFFICIENT. The monitor is an independent gate
and must also allow the action (DESIGN.md section 5.4).
"""

from tokens.macaroon import MIN_KEY_BYTES, Token, TokenError, attenuate, mint, verify
from tokens.scope import TOP, Scope, ScopeError

__all__ = [
    "MIN_KEY_BYTES",
    "Scope",
    "ScopeError",
    "TOP",
    "Token",
    "TokenError",
    "attenuate",
    "mint",
    "verify",
]
