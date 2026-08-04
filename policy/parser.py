"""VDP L1 — tokenizer and recursive-descent parser (DESIGN.md section 2.2).

Grammar, verbatim from DESIGN.md:

    policy      ::= decls clause ( "and" clause )*
    decls       ::= ( "counter" ident "over" verbset )*
    clause      ::= cap | whitelist | prohibition
    cap         ::= "always" "(" ident "<=" integer unit? ")"
    whitelist   ::= "always" "(" ident "(" "target" ")" "->" "target" "in" set ")"
    prohibition ::= "always" "(" "not" ident ")"
    verbset     ::= "{" ident ( "," ident )* "}"
    set         ::= "{" string ( "," string )* "}"
    unit        ::= ident
    integer     ::= [0-9]+
    ident       ::= [a-z][a-z0-9_]*

The grammar has no production for `eventually`, no response pattern, and no
temporal operator other than `always`. That is the syntactic half of the
liveness rejection; the semantic half is that `policy.ast` has no class to hold
one either (DESIGN.md section 2.5).

The parser exists so a human can re-read their own policy as text and re-load
it. It is NOT on the monitor's decision path — the monitor is handed a `Policy`
object, never a string.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from policy.ast import Cap, Clause, CounterDecl, Policy, PolicyError, Prohibition, Whitelist

__all__ = ["ParseError", "parse"]


class ParseError(ValueError):
    """Malformed policy text. Carries a 1-based line and column."""


@dataclass(frozen=True, slots=True)
class _Token:
    kind: str  # IDENT | INT | STRING | ( | ) | { | } | , | <= | -> | EOF
    value: str
    line: int
    col: int


# Order matters: "<=" and "->" must be tried before single characters, and
# STRING before anything else that could swallow a quote.
_TOKEN_SPEC = [
    ("WS", r"[ \t\r\n]+"),
    ("COMMENT", r"\#[^\n]*"),
    ("LE", r"<="),
    ("ARROW", r"->"),
    ("STRING", r'"(?:[^"\\\x00-\x1f]|\\["\\/bfnrt]|\\u[0-9a-fA-F]{4})*"'),
    ("INT", r"[0-9]+"),
    ("IDENT", r"[a-z][a-z0-9_]*"),
    ("PUNCT", r"[(){},]"),
]
_MASTER_RE = re.compile("|".join(f"(?P<{name}>{pat})" for name, pat in _TOKEN_SPEC))

_STRING_ESCAPES = {
    '"': '"',
    "\\": "\\",
    "/": "/",
    "b": "\b",
    "f": "\f",
    "n": "\n",
    "r": "\r",
    "t": "\t",
}


def _unquote(raw: str) -> str:
    """Decode a JSON-style double-quoted string.

    Hand-written rather than delegating to `json.loads` so that the accepted
    escape set is exactly the one the tokenizer's regex admits — one grammar,
    not two that could disagree.
    """
    body = raw[1:-1]
    out: list[str] = []
    i = 0
    while i < len(body):
        ch = body[i]
        if ch != "\\":
            out.append(ch)
            i += 1
            continue
        esc = body[i + 1]
        if esc == "u":
            out.append(chr(int(body[i + 2 : i + 6], 16)))
            i += 6
        else:
            out.append(_STRING_ESCAPES[esc])
            i += 2
    return "".join(out)


def _tokenize(text: str) -> list[_Token]:
    tokens: list[_Token] = []
    pos = 0
    line = 1
    line_start = 0
    while pos < len(text):
        match = _MASTER_RE.match(text, pos)
        if match is None:
            raise ParseError(
                f"line {line}, column {pos - line_start + 1}: "
                f"unexpected character {text[pos]!r}"
            )
        kind = match.lastgroup
        value = match.group()
        col = pos - line_start + 1
        if kind in ("WS", "COMMENT"):
            newlines = value.count("\n")
            if newlines:
                line += newlines
                line_start = match.start() + value.rfind("\n") + 1
        elif kind == "PUNCT":
            tokens.append(_Token(value, value, line, col))
        elif kind == "STRING":
            tokens.append(_Token("STRING", _unquote(value), line, col))
        elif kind == "LE":
            tokens.append(_Token("<=", value, line, col))
        elif kind == "ARROW":
            tokens.append(_Token("->", value, line, col))
        else:
            tokens.append(_Token(kind, value, line, col))
        pos = match.end()
    tokens.append(_Token("EOF", "", line, pos - line_start + 1))
    return tokens


class _Parser:
    def __init__(self, tokens: list[_Token]) -> None:
        self._tokens = tokens
        self._i = 0

    # --- token helpers ---

    def _peek(self, ahead: int = 0) -> _Token:
        return self._tokens[min(self._i + ahead, len(self._tokens) - 1)]

    def _fail(self, expected: str, token: _Token) -> ParseError:
        got = "end of input" if token.kind == "EOF" else repr(token.value)
        return ParseError(
            f"line {token.line}, column {token.col}: expected {expected}, got {got}"
        )

    def _take(self, kind: str, expected: str) -> _Token:
        token = self._peek()
        if token.kind != kind:
            raise self._fail(expected, token)
        self._i += 1
        return token

    def _at_word(self, word: str, ahead: int = 0) -> bool:
        token = self._peek(ahead)
        return token.kind == "IDENT" and token.value == word

    def _take_word(self, word: str) -> _Token:
        if not self._at_word(word):
            raise self._fail(f"{word!r}", self._peek())
        self._i += 1
        return self._tokens[self._i - 1]

    # --- productions ---

    def parse_policy(self) -> Policy:
        counters = self._parse_decls()
        clauses = [self._parse_clause()]
        while self._at_word("and"):
            self._take_word("and")
            clauses.append(self._parse_clause())
        token = self._peek()
        if token.kind != "EOF":
            raise self._fail("'and' or end of input", token)
        try:
            return Policy(counters=tuple(counters), clauses=tuple(clauses))
        except PolicyError as exc:
            # Structural validity (undeclared counters, duplicate caps) lives in
            # the AST, so the parser re-raises rather than duplicating the rules.
            raise ParseError(str(exc)) from exc

    def _parse_decls(self) -> list[CounterDecl]:
        decls: list[CounterDecl] = []
        while self._at_word("counter"):
            self._take_word("counter")
            name = self._take("IDENT", "a counter name").value
            self._take_word("over")
            verbs = self._parse_verbset()
            decls.append(self._build(CounterDecl, name=name, verbs=verbs))
        return decls

    def _parse_clause(self) -> Clause:
        self._take_word("always")
        self._take("(", "'('")
        if self._at_word("not"):
            return self._parse_prohibition_tail()
        name = self._take("IDENT", "a counter name or a verb").value
        token = self._peek()
        if token.kind == "<=":
            return self._parse_cap_tail(name)
        if token.kind == "(":
            return self._parse_whitelist_tail(name)
        raise self._fail("'<=' (a cap) or '(' (a whitelist)", token)

    def _parse_prohibition_tail(self) -> Prohibition:
        self._take_word("not")
        verb = self._take("IDENT", "a verb").value
        self._take(")", "')'")
        return self._build(Prohibition, verb=verb)

    def _parse_cap_tail(self, counter: str) -> Cap:
        self._take("<=", "'<='")
        bound_token = self._take("INT", "a non-negative integer bound in minor units")
        unit = None
        if self._peek().kind == "IDENT":
            unit = self._take("IDENT", "a unit").value
        self._take(")", "')'")
        return self._build(Cap, counter=counter, bound=int(bound_token.value), unit=unit)

    def _parse_whitelist_tail(self, verb: str) -> Whitelist:
        self._take("(", "'('")
        self._take_word("target")
        self._take(")", "')'")
        self._take("->", "'->'")
        self._take_word("target")
        self._take_word("in")
        allowed = self._parse_string_set()
        self._take(")", "')'")
        return self._build(Whitelist, verb=verb, allowed=allowed)

    def _parse_verbset(self) -> frozenset[str]:
        self._take("{", "'{'")
        verbs = [self._take("IDENT", "a verb").value]
        while self._peek().kind == ",":
            self._take(",", "','")
            verbs.append(self._take("IDENT", "a verb").value)
        self._take("}", "'}'")
        if len(set(verbs)) != len(verbs):
            raise ParseError(f"duplicate verb in verb set: {verbs}")
        return frozenset(verbs)

    def _parse_string_set(self) -> frozenset[str]:
        self._take("{", "'{'")
        items = [self._take("STRING", "a quoted target").value]
        while self._peek().kind == ",":
            self._take(",", "','")
            items.append(self._take("STRING", "a quoted target").value)
        self._take("}", "'}'")
        return frozenset(items)

    def _build(self, cls, **kwargs):
        """Construct an AST node, converting its validation errors to ParseError.

        Identifier rules, reserved words, and target rules are defined once, in
        `policy.ast`. The parser does not re-implement them.
        """
        token = self._peek(-1) if self._i else self._peek()
        try:
            return cls(**kwargs)
        except PolicyError as exc:
            raise ParseError(f"line {token.line}, column {token.col}: {exc}") from exc


def parse(text: str) -> Policy:
    """Parse policy text into phi. Raises `ParseError` on anything malformed.

    Total in the sense that matters: it either returns a fully validated
    `Policy` or raises. It never returns a partially built one.
    """
    if not isinstance(text, str):
        raise ParseError(f"policy text must be a string, got {type(text).__name__}")
    return _Parser(_tokenize(text)).parse_policy()
