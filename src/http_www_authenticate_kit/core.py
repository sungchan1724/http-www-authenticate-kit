"""Parser for HTTP WWW-Authenticate and Proxy-Authenticate headers (RFC 7235).

A single header value may carry multiple challenges separated by commas — but
only when the comma is not itself inside a quoted-string. Token-prefixed
parameters belong to the preceding scheme; bare parameters (no token) are
auth-params. This module splits a header into a list of Challenge objects
without delegating to a third-party HTTP library.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Challenge:
    """A single authentication challenge.

    scheme: the auth scheme token, normalised to lowercase (RFC 7230 §3.2.6
    says tokens are case-insensitive, and RFC 7235 §2.1 schemes are tokens).
    Lowercasing means a consumer can switch on scheme without worrying about
    "Basic" vs "basic".

    realm: the value of the realm parameter if present, else None. Kept on the
    object directly because it is the one parameter nearly every scheme uses
    and because RFC 7235 §2.2 makes it MAY-but-common.

    params: a dict of all auth-params (including realm, if it was present).
    Stored in the order encountered; duplicates keep the last value per RFC
    7230 §3.2.2 (a sender MUST NOT generate duplicates, a recipient MAY pick).
    """

    scheme: str
    realm: str | None = None
    params: dict[str, str] = field(default_factory=dict)


def parse_www_authenticate(header_value: str) -> list[Challenge]:
    """Parse a WWW-Authenticate header value into a list of Challenge objects."""
    return _parse(header_value)


def parse_proxy_authenticate(header_value: str) -> list[Challenge]:
    """Parse a Proxy-Authenticate header value into a list of Challenge objects.

    Structurally identical to WWW-Authenticate (RFC 7235 §4.2), so this is a
    thin alias over the same parser. Kept as a separate function so callers'
    intent is self-documenting at the call site.
    """
    return _parse(header_value)


def _parse(header_value: str) -> list[Challenge]:
    """Parse one or more auth challenges from a single header value."""
    if header_value is None:
        return []
    s = header_value.strip()
    if not s:
        return []

    challenges: list[Challenge] = []
    i = 0
    n = len(s)

    while i < n:
        # Skip leading whitespace and stray commas (comma is a valid
        # challenge separator, so multiple commas between challenges are
        # harmless).
        while i < n and (s[i].isspace() or s[i] == ","):
            i += 1
        if i >= n:
            break

        # Parse the scheme token.
        scheme_start = i
        while i < n and _is_token_char(s[i]):
            i += 1
        scheme_end = i
        if scheme_start == scheme_end:
            # Non-token character where a scheme is expected; stop here to
            # avoid silently producing garbage challenges.
            break
        scheme = s[scheme_start:scheme_end].lower()

        # Parse parameters for this scheme.
        params: dict[str, str] = {}
        while i < n:
            # Skip whitespace.
            while i < n and s[i].isspace():
                i += 1
            if i >= n:
                break
            # A comma ends this challenge and starts the next one — but only
            # if the next non-space token is a scheme (no "=" following it).
            if s[i] == ",":
                # Look ahead to decide whether the comma is a parameter
                # separator or a challenge separator.
                saved = i
                i += 1
                while i < n and s[i].isspace():
                    i += 1
                if i < n and _is_token_char(s[i]) and not _next_is_param(s, i):
                    # Next token is a scheme, so this comma was a challenge
                    # separator. Don't consume the lookahead; let the outer
                    # loop re-grab the scheme.
                    i = saved
                    break
                else:
                    # No scheme following, or end of string: treat as a stray
                    # comma and continue collecting params for the current
                    # challenge.
                    i = saved + 1
                    continue
            # Expect a token name.
            name_start = i
            while i < n and _is_token_char(s[i]):
                i += 1
            name_end = i
            if name_start == name_end:
                # Can't parse a parameter name here; bail out of this
                # challenge's params.
                break
            name = s[name_start:name_end].lower()
            # Skip whitespace.
            while i < n and s[i].isspace():
                i += 1
            # Expect "=".
            if i >= n or s[i] != "=":
                # Not a parameter — stop collecting params.
                i = name_end
                break
            i += 1  # consume "="
            while i < n and s[i].isspace():
                i += 1
            # Expect a value (token or quoted-string).
            if i >= n:
                break
            if s[i] == '"':
                value, i = _parse_quoted_string(s, i)
            else:
                value_start = i
                while i < n and _is_token_char(s[i]):
                    i += 1
                value_end = i
                if value_start == value_end:
                    # No value where one was expected; stop.
                    break
                value = s[value_start:value_end]
            params[name] = value

        realm = params.get("realm")
        challenges.append(Challenge(scheme=scheme, realm=realm, params=params))

    return challenges


def _next_is_param(s: str, start: int) -> bool:
    """Return True if the token at `start` is followed by "=" (i.e. it is a
    parameter name, not a scheme).

    Used to disambiguate whether a comma after a value starts a new challenge
    or just separates parameters. The grammar ambiguity here is real: RFC
    7235 leaves it to the reader, and the common practical resolution is
    "next token followed by = means parameter, otherwise it's a scheme".
    """
    i = start
    n = len(s)
    while i < n and _is_token_char(s[i]):
        i += 1
    while i < n and s[i].isspace():
        i += 1
    return i < n and s[i] == "="


def _parse_quoted_string(s: str, start: int) -> tuple[str, int]:
    """Parse a quoted-string beginning at s[start] (which must be '"').

    Returns the unquoted value (with backslash escapes resolved per RFC 7230
    §3.2.6) and the index just past the closing quote.
    """
    assert s[start] == '"'
    i = start + 1
    n = len(s)
    out: list[str] = []
    while i < n:
        c = s[i]
        if c == "\\":
            # Quoted-pair: backslash followed by a single character. RFC 7230
            # §3.2.6 restricts the following char to VCHAR / obs-text, but we
            # are permissive: any character is accepted and the backslash is
            # dropped. This avoids a hard failure on headers that bend the
            # rule, which is the more useful behaviour for a client.
            if i + 1 < n:
                out.append(s[i + 1])
                i += 2
            else:
                # Dangling backslash at end of string; stop.
                i += 1
                break
        elif c == '"':
            i += 1
            return "".join(out), i
        else:
            out.append(c)
            i += 1
    # Unterminated quoted-string; return what we have rather than throwing,
    # so a malformed header still yields a usable challenge.
    return "".join(out), i


# RFC 7230 §3.2.6 token characters: any VCHAR except delimiters.
# Implemented as a set lookup rather than a regex to keep this zero-dependency
# and to make the membership test obvious.
_TOKEN_CHARS = frozenset(
    "!#$%&'*+-.^_`|~"
    "0123456789"
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
)


def _is_token_char(c: str) -> bool:
    return c in _TOKEN_CHARS
