"""The keygen command line. `keygen --help` lists everything; each command has its own help."""

from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Annotated

import typer

from keygen import __version__, core

app = typer.Typer(
    help="Cryptographically secure keys, passwords, passphrases, PINs, recovery codes, TOTP and server key material.",
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


@app.callback()
def _main() -> None:
    # Windows consoles default to a legacy code page; accented words and QR blocks need UTF-8.
    for stream in (sys.stdout, sys.stderr):
        if (stream.encoding or "").lower().replace("-", "") != "utf8" and hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")


def _fail(msg: str) -> None:
    typer.echo(f"error: {msg}", err=True)
    raise typer.Exit(code=1)


def _clipboard(text: str) -> None:
    cmd = {"Windows": ["clip"], "Darwin": ["pbcopy"]}.get(platform.system())
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
        text = json.dumps(payload, indent=2, ensure_ascii=False) + "\n"
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


def _run(fn, count: int, **kwargs) -> list[str]:
    try:
        return core.many(fn, count, **kwargs)
    except core.GenerationError as e:
        _fail(str(e))
        raise  # unreachable; keeps type checkers calm


def _write_private(path: Path, text: str) -> None:
    """Write key material readable by the owner only (POSIX); Windows inherits the folder ACL."""
    path.write_text(text, encoding="utf-8")
    if os.name == "posix":
        path.chmod(0o600)


# --- generators ----------------------------------------------------------------


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
    items = _run(core.api_key, count, fmt=fmt, length=length, prefix=prefix)
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
    items = _run(core.password, count, length=length, **opts)
    bits = core.password_entropy_bits(length, **opts) if entropy or as_json else None
    _emit("passwords", items, out=out, copy=copy, as_json=as_json, entropy_bits=bits, length=length, **opts)


@app.command()
def passphrase(
    words: Annotated[int, typer.Option("--words", "-w", help="Words per passphrase")] = 6,
    separator: Annotated[str, typer.Option("--sep", "-s", help="Between words")] = "-",
    lang: Annotated[str, typer.Option("--lang", "-L", help="Wordlist: en | es | de")] = "en",
    capitalize: Annotated[bool, typer.Option("--capitalize", "-C", help="Title-case each word")] = False,
    digit: Annotated[bool, typer.Option("--digit", "-d", help="Append one random digit to one word")] = False,
    count: Count = 1,
    out: Out = None,
    copy: Copy = False,
    as_json: Json = False,
    entropy: Entropy = False,
) -> None:
    """Diceware passphrases from a 7776-word list (12.9 bits per word). English, Spanish or German."""
    if lang not in core.LANGS:
        _fail(f"unknown language {lang!r}; use one of {', '.join(core.LANGS)}")
    items = _run(core.passphrase, count, words=words, separator=separator, capitalize=capitalize, digit=digit, lang=lang)
    bits = core.passphrase_entropy_bits(words, lang) if entropy or as_json else None
    _emit("passphrases", items, out=out, copy=copy, as_json=as_json, entropy_bits=bits, words=words, lang=lang)


@app.command()
def pronounceable(
    syllables: Annotated[int, typer.Option("--syllables", "-s", help="Syllables per word")] = 4,
    capitalize: Annotated[bool, typer.Option("--capitalize", "-C")] = False,
    count: Count = 1,
    out: Out = None,
    copy: Copy = False,
    as_json: Json = False,
    entropy: Entropy = False,
) -> None:
    """Nonsense words you can read out loud (about 11.3 bits per syllable)."""
    items = _run(core.pronounceable, count, syllables=syllables, capitalize=capitalize)
    bits = core.pronounceable_entropy_bits(syllables) if entropy or as_json else None
    _emit("words", items, out=out, copy=copy, as_json=as_json, entropy_bits=bits, syllables=syllables)


@app.command()
def pin(
    length: Annotated[int, typer.Option("--length", "-l")] = 6,
    count: Count = 1,
    out: Out = None,
    copy: Copy = False,
    as_json: Json = False,
) -> None:
    """Numeric PINs."""
    items = _run(core.pin, count, length=length)
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
    items = _run(core.recovery_code, count, length=length, groups=groups)
    bits = core.recovery_entropy_bits(length) if entropy or as_json else None
    header = "" if as_json else "# Recovery codes. Keep these somewhere safe; each one works once.\n\n"
    _emit("codes", items, out=out, copy=copy, as_json=as_json, entropy_bits=bits, header=header, length=length)


@app.command()
def preset(
    name: Annotated[str | None, typer.Argument(help="Preset name; omit to list them")] = None,
    count: Count = 1,
    out: Out = None,
    copy: Copy = False,
    as_json: Json = False,
) -> None:
    """Run a named preset (stripe, github, db, wifi, vault, ...) or list them. Yours go in ~/.config/keygen/presets.toml."""
    from keygen import presets

    try:
        table = presets.load()
    except (ValueError, OSError) as e:
        _fail(str(e))
        raise
    if name is None:
        for n, spec in table.items():
            typer.echo(presets.describe(n, spec))
        typer.echo(f"\nuser presets: {presets.user_presets_path()}", err=True)
        return
    try:
        items = presets.run(name, count, table)
    except KeyError:
        _fail(f"no preset {name!r}; run `keygen preset` to list them")
        raise
    except (ValueError, TypeError, core.GenerationError) as e:
        _fail(f"preset {name!r}: {e}")
        raise
    _emit("values", items, out=out, copy=copy, as_json=as_json, entropy_bits=None, preset=name)


# --- check ----------------------------------------------------------------------


@app.command()
def check(
    secret: Annotated[str | None, typer.Argument(help="The secret; omit to read one line from stdin")] = None,
    hibp: Annotated[bool, typer.Option("--hibp", help="Look it up in Have I Been Pwned (k-anonymity: 5 hex chars leave the machine)")] = False,
    as_json: Json = False,
) -> None:
    """Score a password or passphrase: entropy estimate, structure warnings, optional breach lookup. Exit 1 if weak or breached."""
    from keygen import check as checker

    if secret is None:
        secret = sys.stdin.readline().rstrip("\r\n")
    if not secret:
        _fail("nothing to check")
    try:
        report = checker.analyse(secret, hibp=hibp)
    except OSError as e:
        _fail(f"HIBP lookup failed: {e}")
        raise
    if as_json:
        data = asdict(report)
        data.update(bits=round(report.bits, 1), verdict=report.verdict)
        typer.echo(json.dumps(data, indent=2, ensure_ascii=False))
    else:
        typer.echo(f"length   {report.secret_length}")
        typer.echo(f"classes  {', '.join(report.classes) or 'none'}")
        typer.echo(f"entropy  {report.bits:.1f} bits ({report.verdict})")
        if report.passphrase_words:
            typer.echo(f"looks like {report.passphrase_words} words from the {report.passphrase_lang} list: {report.passphrase_bits:.1f} bits")
        if report.pwned_count is not None:
            seen = f"seen {report.pwned_count:,} times in breaches" if report.pwned_count else "not found in breaches"
            typer.echo(f"hibp     {seen}")
        for w in report.warnings:
            typer.echo(f"warning  {w}")
    if report.verdict in ("weak", "breached"):
        raise typer.Exit(code=1)


# --- totp --------------------------------------------------------------------------

totp_app = typer.Typer(help="RFC 6238 TOTP: a new secret with its otpauth:// URI and QR, or the current code.", no_args_is_help=True, rich_markup_mode=None)
app.add_typer(totp_app, name="totp")


def _print_qr(uri: str) -> None:
    try:
        import qrcode
    except ImportError:
        typer.echo("(install the [qr] extra to print a QR code here)", err=True)
        return
    qr = qrcode.QRCode(border=1)
    qr.add_data(uri)
    qr.print_ascii(invert=True)


@totp_app.command("new")
def totp_new(
    account: Annotated[str, typer.Option("--account", "-a", help="User or email shown in the app")] = "user",
    issuer: Annotated[str, typer.Option("--issuer", "-i", help="Service name shown in the app")] = "",
    digits: Annotated[int, typer.Option(min=6, max=8)] = 6,
    period: Annotated[int, typer.Option(min=15, max=120)] = 30,
    algorithm: Annotated[str, typer.Option(help="SHA1 | SHA256 | SHA512")] = "SHA1",
    qr: Annotated[bool, typer.Option("--qr/--no-qr", help="Print an ASCII QR code (needs the [qr] extra)")] = True,
    as_json: Json = False,
) -> None:
    """Generate a secret and the otpauth:// URI for it."""
    from keygen import totp

    try:
        secret = totp.totp_secret()
        uri = totp.otpauth_uri(secret, account, issuer, digits, period, algorithm)
        code = totp.totp_code(secret, digits=digits, period=period, algorithm=algorithm)
    except ValueError as e:
        _fail(str(e))
        raise
    if as_json:
        typer.echo(json.dumps({"secret": secret, "uri": uri, "current_code": code, "digits": digits, "period": period, "algorithm": algorithm}, indent=2))
        return
    typer.echo(f"secret   {secret}")
    typer.echo(f"uri      {uri}")
    typer.echo(f"current  {code}  ({totp.seconds_remaining(period)}s left)")
    if qr:
        _print_qr(uri)


@totp_app.command("code")
def totp_code_cmd(
    secret: Annotated[str, typer.Argument(help="Base32 secret")],
    digits: Annotated[int, typer.Option(min=6, max=8)] = 6,
    period: Annotated[int, typer.Option(min=15, max=120)] = 30,
    algorithm: Annotated[str, typer.Option(help="SHA1 | SHA256 | SHA512")] = "SHA1",
) -> None:
    """Print the current code for a secret (to test an integration, or as a poor man's authenticator)."""
    from keygen import totp

    try:
        typer.echo(totp.totp_code(secret, digits=digits, period=period, algorithm=algorithm))
    except (ValueError, TypeError) as e:
        _fail(f"bad secret: {e}")
    typer.echo(f"{totp.seconds_remaining(period)}s left", err=True)


# --- infra ---------------------------------------------------------------------------


@app.command()
def ssh(
    comment: Annotated[str, typer.Option("--comment", "-C", help="Comment on the public key, e.g. user@host")] = "",
    out: Annotated[Path | None, typer.Option("--out", "-o", help="Write private key here and public key to <out>.pub")] = None,
) -> None:
    """An ed25519 SSH key pair (needs the [infra] extra)."""
    from keygen import infra

    try:
        pair = infra.ssh_keypair(comment)
    except RuntimeError as e:
        _fail(str(e))
        raise
    if out is None:
        sys.stdout.write(pair.private)
        typer.echo(pair.public)
        return
    if out.exists():
        _fail(f"{out} exists; not overwriting a key")
    _write_private(out, pair.private)
    out.with_name(out.name + ".pub").write_text(pair.public + "\n", encoding="utf-8")
    typer.echo(f"wrote {out} and {out}.pub", err=True)
    typer.echo(pair.public)


@app.command()
def wireguard(
    preshared: Annotated[bool, typer.Option("--preshared", "-p", help="Also emit a PresharedKey")] = False,
    as_json: Json = False,
) -> None:
    """A WireGuard key pair, as lines you can paste into a [Interface]/[Peer] block (needs the [infra] extra)."""
    from keygen import infra

    try:
        pair = infra.wireguard_keypair()
    except RuntimeError as e:
        _fail(str(e))
        raise
    data = {"PrivateKey": pair.private, "PublicKey": pair.public}
    if preshared:
        data["PresharedKey"] = infra.wireguard_preshared()
    if as_json:
        typer.echo(json.dumps(data, indent=2))
    else:
        for k, v in data.items():
            typer.echo(f"{k} = {v}")


@app.command("jwt-secret")
def jwt_secret(
    bits: Annotated[int, typer.Option("--bits", "-b", help="256 for HS256, 384 for HS384, 512 for HS512")] = 256,
    encoding: Annotated[str, typer.Option("--encoding", "-E", help="base64url | base64 | hex")] = "base64url",
    count: Count = 1,
    out: Out = None,
    copy: Copy = False,
    as_json: Json = False,
) -> None:
    """A random HMAC signing secret for JWTs, sessions, webhooks."""
    from keygen import infra

    try:
        items = [infra.jwt_secret(bits, encoding) for _ in range(count)]
    except ValueError as e:
        _fail(str(e))
        raise
    _emit("secrets", items, out=out, copy=copy, as_json=as_json, entropy_bits=float(bits), bits=bits, encoding=encoding)


@app.command()
def htpasswd(
    user: Annotated[str, typer.Argument()],
    password_: Annotated[str | None, typer.Option("--password", "-P", help="Use this password; default generates one and prints it to stderr")] = None,
    prompt: Annotated[bool, typer.Option("--prompt", help="Ask for the password without echo")] = False,
    rounds: Annotated[int, typer.Option(min=4, max=31, help="bcrypt cost; 12 is the sensible default")] = 12,
    out: Annotated[Path | None, typer.Option("--out", "-o", help="Append the line to this file")] = None,
) -> None:
    """A bcrypt htpasswd line for nginx, Apache, Caddy or Traefik basic auth (needs the [infra] extra)."""
    from keygen import infra

    if prompt:
        password_ = typer.prompt("password", hide_input=True, confirmation_prompt=True)
    generated = password_ is None
    if generated:
        password_ = core.password(24, symbols=False)
    try:
        line = infra.htpasswd_line(user, password_, rounds)
    except (RuntimeError, ValueError) as e:
        _fail(str(e))
        raise
    if generated:
        typer.echo(f"password: {password_}", err=True)
    if out is not None:
        with out.open("a", encoding="utf-8") as f:
            f.write(line + "\n")
        typer.echo(f"appended to {out}", err=True)
    else:
        typer.echo(line)


# --- housekeeping -----------------------------------------------------------------


@app.command()
def selftest(
    samples: Annotated[int, typer.Option("--samples", "-s", min=50, max=20000, help="Draws per generator")] = 400,
) -> None:
    """Chi-squared uniformity checks and structural guarantees over every generator. Exit 1 on failure."""
    from keygen import selftest as st

    results = st.run(samples)
    for r in results:
        typer.echo(f"{'ok  ' if r.ok else 'FAIL'} {r.name:<18} {r.detail}")
    failed = [r for r in results if not r.ok]
    typer.echo(f"{len(results) - len(failed)}/{len(results)} passed", err=True)
    if failed:
        raise typer.Exit(code=1)


@app.command()
def serve(
    host: Annotated[str, typer.Option(help="Bind address")] = "127.0.0.1",
    port: Annotated[int, typer.Option(help="Port")] = 8000,
) -> None:
    """Run the REST API (needs the [api] extra)."""
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
