"""VDP L1 — policy language.

Parser + AST for the policy language, and a compiler from a structured intent
object to phi. See DESIGN.md sections 2.1 through 2.6.

Nothing in this package performs I/O on the enforcement path, and nothing here
imports from `monitor`, `tokens`, or `runtime`. Layering is one-directional.
"""

from policy.ast import (
    Cap,
    Clause,
    CounterDecl,
    NO_TARGET,
    Policy,
    PolicyError,
    Prohibition,
    Whitelist,
)
from policy.compile import CompiledIntent, IntentError, compile_intent, validate_intent
from policy.parser import ParseError, parse
from policy.render import render_english, render_formal

__all__ = [
    "Cap",
    "Clause",
    "CompiledIntent",
    "CounterDecl",
    "IntentError",
    "NO_TARGET",
    "ParseError",
    "Policy",
    "PolicyError",
    "Prohibition",
    "Whitelist",
    "compile_intent",
    "parse",
    "render_english",
    "render_formal",
    "validate_intent",
]
