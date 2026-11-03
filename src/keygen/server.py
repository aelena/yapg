"""Sanic REST API over `keygen.core`. Stateless; nothing generated is logged or stored.

Run:
    keygen serve                      # or: sanic keygen.server:app
Endpoints (all GET, all accept `count` and `download=1`):
    /health
    /api-key?format=base64url&length=40&prefix=sk_live_
    /password?length=20&upper=1&lower=1&digits=1&symbols=1&exclude_ambiguous=0
    /passphrase?words=6&sep=-&lang=en&capitalize=0&digit=0
    /pronounceable?syllables=4&capitalize=0
    /pin?length=6
    /recovery-codes?count=16&length=10&groups=2

Deliberately absent: SSH/WireGuard keys, htpasswd, TOTP secrets, breach lookups.
Those belong on the machine that will use them, not on the wire.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime

from sanic import Request, Sanic, json, raw
from sanic.exceptions import BadRequest
from sanic.response import HTTPResponse

from keygen import __version__, core

app = Sanic("key-generator")

TRUE = frozenset({"1", "true", "yes", "on"})


def _bool(args, name: str, default: bool) -> bool:
    value = args.get(name)
    return default if value is None else value.strip().lower() in TRUE


def _int(args, name: str, default: int) -> int:
    value = args.get(name)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError as e:
        raise BadRequest(f"{name}: not an integer: {value!r}") from e


def _generate(fn: Callable[..., str], count: int, **kwargs) -> list[str]:
    try:
        return core.many(fn, count, **kwargs)
    except core.GenerationError as e:
        raise BadRequest(str(e)) from e


def _respond(
    request: Request, kind: str, items: list[str], header: str = "", **meta
) -> HTTPResponse:
    if not _bool(request.args, "download", False):
        return json({kind: items, "count": len(items), **meta})
    body = (header + "\n".join(items) + "\n").encode("utf-8")
    stem = kind.replace("_", "-")
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    return raw(
        body,
        content_type="text/plain; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{stem}-{ts}.txt"'},
    )


@app.get("/health")
async def health(_: Request) -> HTTPResponse:
    return json({"status": "ok", "version": __version__})


@app.get("/api-key")
async def api_key(request: Request) -> HTTPResponse:
    a = request.args
    fmt = a.get("format", "base64url")
    if fmt not in core.KEY_FORMATS:
        raise BadRequest(f"unknown format {fmt!r}; use one of {', '.join(core.KEY_FORMATS)}")
    kwargs = {"fmt": fmt, "length": _int(a, "length", 40), "prefix": a.get("prefix", "")}
    items = _generate(core.api_key, _int(a, "count", 1), **kwargs)
    return _respond(request, "keys", items, format=fmt)


@app.get("/password")
async def password(request: Request) -> HTTPResponse:
    a = request.args
    opts = {
        "upper": _bool(a, "upper", True),
        "lower": _bool(a, "lower", True),
        "digits": _bool(a, "digits", True),
        "symbols": _bool(a, "symbols", True),
        "exclude_ambiguous": _bool(a, "exclude_ambiguous", False),
    }
    length = _int(a, "length", 20)
    items = _generate(core.password, _int(a, "count", 1), length=length, **opts)
    bits = round(core.password_entropy_bits(length, **opts), 1)
    return _respond(request, "passwords", items, length=length, entropy_bits=bits, **opts)


@app.get("/passphrase")
async def passphrase(request: Request) -> HTTPResponse:
    a = request.args
    words, lang = _int(a, "words", 6), a.get("lang", "en")
    if lang not in core.LANGS:
        raise BadRequest(f"unknown language {lang!r}; use one of {', '.join(core.LANGS)}")
    kwargs = {
        "words": words,
        "separator": a.get("sep", "-"),
        "capitalize": _bool(a, "capitalize", False),
        "digit": _bool(a, "digit", False),
        "lang": lang,
    }
    items = _generate(core.passphrase, _int(a, "count", 1), **kwargs)
    bits = round(core.passphrase_entropy_bits(words, lang), 1)
    return _respond(request, "passphrases", items, words=words, lang=lang, entropy_bits=bits)


@app.get("/pronounceable")
async def pronounceable(request: Request) -> HTTPResponse:
    a = request.args
    syllables = _int(a, "syllables", 4)
    kwargs = {"syllables": syllables, "capitalize": _bool(a, "capitalize", False)}
    items = _generate(core.pronounceable, _int(a, "count", 1), **kwargs)
    bits = round(core.pronounceable_entropy_bits(syllables), 1)
    return _respond(request, "words", items, syllables=syllables, entropy_bits=bits)


@app.get("/pin")
async def pin(request: Request) -> HTTPResponse:
    a = request.args
    length = _int(a, "length", 6)
    items = _generate(core.pin, _int(a, "count", 1), length=length)
    return _respond(request, "pins", items, length=length)


@app.get("/recovery-codes")
async def recovery_codes(request: Request) -> HTTPResponse:
    a = request.args
    length, groups = _int(a, "length", 10), _int(a, "groups", 2)
    items = _generate(core.recovery_code, _int(a, "count", 16), length=length, groups=groups)
    header = "# Recovery codes. Keep these somewhere safe; each one works once.\n\n"
    bits = round(core.recovery_entropy_bits(length), 1)
    return _respond(request, "codes", items, header=header, length=length, entropy_bits=bits)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8000, debug=False, access_log=False, single_process=True)
