"""The keygen command line: key, password, passphrase, pin, recovery, serve, version."""

from __future__ import annotations

import json
import platform
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Annotated

import typer

from keygen import __version__, core

app = typer.Typer(
    help="Cryptographically secure keys, passwords, passphrases, PINs and recovery codes.",
    no_args_is_help=True,
    add_completion=False,
    rich_markup_mode=None,
)

# Options shared by every generator command, declared once.
Count = Annotated[int, typer.Option("--count", "-n", min=1, max=core.MAX_BATCH, help="How many to generate")]
Out = Annotated[Path | None, typer.Option("--out", "-o", help="Write to this file instead of stdout")]
Copy = Annotated[bool, typer.Option("--copy", "-c", help="Copy the result to the clipboard (and still print it)")]
Json = Annotated[bool, typer.Option("--json", help="Emit a JSON object instead of one value per line")]
Entropy = Annotated[bool, typer.Option("--entropy", "-e", help="Print the entropy in bits to stderr")]


def _fail(msg: str) -> None:
    typer.echo(f"error: {msg}", err=True)
    raise typer.Exit(code=1)


def _clipboard(text: str) -> None:
    cmd = {
        "Windows": ["clip"],
        "Darwin": ["pbcopy"],
    }.get(platform.system())
    if cmd is None:
        cmd = next(([c] for c in ("wl-copy", "xclip", "xsel") if shutil.which(c)), None)
        if cmd and cmd[0] == "xclip":
            cmd += ["-selection", "clipboard"]
        if cmd and cmd[0] == "xsel":
            cmd += ["--clipboard", "--input"]
    if cmd is None:
        _fail("no clipboard command found (tried clip, pbcopy, wl-copy, xclip, xsel)")
    subprocess.run(cmd, input=text.encode("utf-8"), check=True)


def _emit(
    kind: str,
    items: list[str],
    *,
    out: Path | None,
    copy: bool,
    as_json: bool,
    entropy_bits: float | None,
    header: str = "",
    **meta,
) -> None:
    if as_json:
        payload = {kind: items, "count": len(items), **meta}
        if entropy_bits is not None:
            payload["entropy_bits"] = round(entropy_bits, 1)
        text = json.dumps(payload, indent=2) + "\n"
    else:
        text = header + "\n".join(items) + "\n"
    if out is not None:
        out.write_text(text, encoding="utf-8")
        typer.echo(f"wrote {len(items)} to {out}", err=True)
    else:
        sys.stdout.write(text)
    if copy:
        _clipboard("\n".join(items) if len(items) > 1 else items[0])
        typer.echo("copied to clipboard", err=True)
    if entropy_bits is not None and not as_json:
        typer.echo(f"entropy: {entropy_bits:.1f} bits", err=True)


def _run(kind: str, fn, count: int, **kwargs) -> list[str]:
    try:
        return core.many(fn, count, **kwargs)
    except core.GenerationError as e:
        _fail(str(e))
        raise  # unreachable; keeps type checkers calm


@app.command()
def version() -> None:
    """Print the version."""
    typer.echo(f"keygen {__version__}")


@app.command()
def key(
    fmt: Annotated[str, typer.Option("--format", "-f", help="hex | base64url | alnum | uuid")] = "base64url",
    length: Annotated[int, typer.Option("--length", "-l", help="Characters after the prefix (ignored for uuid)")] = 40,
    prefix: Annotated[str, typer.Option("--prefix", "-p", help="Prepended to every key, e.g. sk_live_")] = "",
    count: Count = 1,
    out: Out = None,
    copy: Copy = False,
    as_json: Json = False,
) -> None:
    """Opaque API keys / tokens."""
    if fmt not in core.KEY_FORMATS:
        _fail(f"unknown format {fmt!r}; use one of {', '.join(core.KEY_FORMATS)}")
    items = _run("keys", core.api_key, count, fmt=fmt, length=length, prefix=prefix)
    _emit("keys", items, out=out, copy=copy, as_json=as_json, entropy_bits=None, format=fmt)


@app.command()
def password(
    length: Annotated[int, typer.Option("--length", "-l")] = 20,
    upper: Annotated[bool, typer.Option("--upper/--no-upper", help="A-Z")] = True,
    lower: Annotated[bool, typer.Option("--lower/--no-lower", help="a-z")] = True,
    digits: Annotated[bool, typer.Option("--digits/--no-digits", help="0-9")] = True,
    symbols: Annotated[bool, typer.Option("--symbols/--no-symbols", help=core.SYMBOLS)] = True,
    exclude_ambiguous: Annotated[bool, typer.Option("--exclude-ambiguous", "-x", help="Drop I l 1 O 0")] = False,
    count: Count = 1,
    out: Out = None,
    copy: Copy = False,
    as_json: Json = False,
    entropy: Entropy = False,
) -> None:
    """Random passwords with at least one character from every enabled class."""
    opts = {"upper": upper, "lower": lower, "digits": digits, "symbols": symbols, "exclude_ambiguous": exclude_ambiguous}
    items = _run("passwords", core.password, count, length=length, **opts)
    bits = core.password_entropy_bits(length, **opts) if entropy or as_json else None
    _emit("passwords", items, out=out, copy=copy, as_json=as_json, entropy_bits=bits, length=length, **opts)


@app.command()
def passphrase(
    words: Annotated[int, typer.Option("--words", "-w", help="Words per passphrase")] = 6,
    separator: Annotated[str, typer.Option("--sep", "-s", help="Between words")] = "-",
    capitalize: Annotated[bool, typer.Option("--capitalize", "-C", help="Title-case each word")] = False,
    digit: Annotated[bool, typer.Option("--digit", "-d", help="Append one random digit to one word")] = False,
    count: Count = 1,
    out: Out = None,
    copy: Copy = False,
    as_json: Json = False,
    entropy: Entropy = False,
) -> None:
    """Diceware passphrases from the EFF large wordlist (12.9 bits per word)."""
    items = _run("passphrases", core.passphrase, count, words=words, separator=separator, capitalize=capitalize, digit=digit)
    bits = core.passphrase_entropy_bits(words) if entropy or as_json else None
    _emit("passphrases", items, out=out, copy=copy, as_json=as_json, entropy_bits=bits, words=words)


@app.command()
def pin(
    length: Annotated[int, typer.Option("--length", "-l")] = 6,
    count: Count = 1,
    out: Out = None,
    copy: Copy = False,
    as_json: Json = False,
) -> None:
    """Numeric PINs."""
    items = _run("pins", core.pin, count, length=length)
    _emit("pins", items, out=out, copy=copy, as_json=as_json, entropy_bits=None, length=length)


@app.command()
def recovery(
    count: Count = 16,
    length: Annotated[int, typer.Option("--length", "-l", help="Symbols per code, excluding dashes")] = 10,
    groups: Annotated[int, typer.Option("--groups", "-g", help="Dash-separated chunks per code")] = 2,
    out: Out = None,
    copy: Copy = False,
    as_json: Json = False,
    entropy: Entropy = False,
) -> None:
    """GitHub-style one-time recovery codes."""
    items = _run("codes", core.recovery_code, count, length=length, groups=groups)
    bits = core.recovery_entropy_bits(length) if entropy or as_json else None
    header = "" if as_json else "# Recovery codes. Keep these somewhere safe; each one works once.\n\n"
    _emit("codes", items, out=out, copy=copy, as_json=as_json, entropy_bits=bits, header=header, length=length)


@app.command()
def serve(
    host: Annotated[str, typer.Option(help="Bind address")] = "127.0.0.1",
    port: Annotated[int, typer.Option(help="Port")] = 8000,
) -> None:
    """Run the REST API (needs the [api] extra: uv tool install 'key-generator[api]')."""
    try:
        from keygen.server import app as sanic_app
    except ImportError:
        _fail("sanic is not installed; install with the [api] extra")
        raise
    sanic_app.run(host=host, port=port, debug=False, access_log=False, single_process=True)


@app.command()
def web(
    port: Annotated[int, typer.Option(help="Port")] = 3000,
    directory: Annotated[Path | None, typer.Option("--dir", help="The web/ folder; defaults to the one next to the source checkout")] = None,
) -> None:
    """Serve the offline web page on localhost (plain http.server, no API)."""
    folder = directory or Path(__file__).resolve().parents[2] / "web"
    if not (folder / "index.html").is_file():
        _fail(f"no index.html in {folder}; pass --dir to point at the web/ folder")
    import http.server
    from functools import partial

    handler = partial(http.server.SimpleHTTPRequestHandler, directory=str(folder))
    typer.echo(f"serving {folder} at http://127.0.0.1:{port}  (Ctrl+C to stop)", err=True)
    with http.server.ThreadingHTTPServer(("127.0.0.1", port), handler) as httpd:
        httpd.serve_forever()
