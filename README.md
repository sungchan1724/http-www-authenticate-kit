# http-www-authenticate-kit

A focused parser for HTTP `WWW-Authenticate` and `Proxy-Authenticate` headers. Returns a list of `Challenge` objects, each with a `scheme`, `realm`, and a `params` dict.

## Install / run

Standard library only. Put `src` on your `PYTHONPATH`:

```bash
PYTHONPATH=src python -m unittest discover -s tests
```

## Usage

```python
from http_www_authenticate_kit import parse_www_authenticate, parse_proxy_authenticate

challenges = parse_www_authenticate('Basic realm="Restricted", Bearer realm="api"')
for c in challenges:
    print(c.scheme, c.realm, c.params)
# basic Restricted {'realm': 'Restricted'}
# bearer api {'realm': 'api'}
```

Exported names: `Challenge` (a frozen dataclass with `scheme`, `realm`, `params` fields), `parse_www_authenticate`, and `parse_proxy_authenticate`.

## Why

RFC 7235 defines the grammar for these headers, but the grammar is ambiguous in one specific place: a comma can separate either multiple challenges or parameters within a single challenge, and the disambiguation depends on whether the token following the comma is a scheme or a parameter name. There is no third-party HTTP parser involved — this exists because pulling in a full HTTP library just to read one header is heavy, and because the disambiguation rule is worth getting right in isolation.

The trade-off: the parser is permissive. It accepts malformed quoted-strings (e.g. unterminated) and quoted-pairs with any following character, returning a best-effort value rather than raising. If you want strict validation that rejects bad headers, this is not the library for it.

## The awkward edge

The comma ambiguity is the edge. A header like `Basic realm="a, b", Bearer realm="c"` is parsed correctly because the comma inside the quoted string is preserved. But a header like `Newauth realm="x", type=1, Basic` is parsed as two challenges (`Newauth` with params `realm` and `type`, then `Basic`) — if `type` had been intended as a scheme, the grammar offers no way to tell. The rule used here: a token after a comma is a scheme unless it is followed by `=`. This matches the behaviour most HTTP clients adopt in practice.
