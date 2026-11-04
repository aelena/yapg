"""The 0.3 features: wordlists, pronounceable, check, totp, infra, presets, selftest."""

from __future__ import annotations

import json
import re

import pytest
from typer.testing import CliRunner

from keygen import check, core, presets, selftest, totp
from keygen.cli import app

runner = CliRunner(env={"NO_COLOR": "1", "TERM": "dumb", "COLUMNS": "200"})


# --- wordlists and pronounceable ---------------------------------------------


@pytest.mark.parametrize("lang", ["en", "es", "de"])
def test_wordlists_are_7776_unique_single_tokens(lang):
    words = core.wordlist(lang)
    assert len(words) == 7776 and len(set(words)) == 7776
    assert all(w and not any(c.isspace() for c in w) for w in words)


def test_passphrase_lang():
    es = core.passphrase(5, " ", lang="es").split(" ")
    assert len(es) == 5 and all(w in set(core.wordlist("es")) for w in es)
    with pytest.raises(core.GenerationError):
        core.passphrase(5, lang="fr")


def test_pronounceable():
    for _ in range(100):
        w = core.pronounceable(4)
        assert re.match(r"^[a-z]{8,24}$", w)
        assert re.search(r"[aeiou]", w)
    assert core.pronounceable(3, capitalize=True)[0].isupper()
    assert 40 < core.pronounceable_entropy_bits(4) < 50


# --- check -------------------------------------------------------------------


def test_check_random_password_is_strong():
    r = check.analyse(core.password(24))
    assert r.verdict in ("strong", "very strong") and r.passphrase_words is None


def test_check_detects_passphrase_and_caps_bits():
    phrase = core.passphrase(4, "-")
    r = check.analyse(phrase)
    assert r.passphrase_words == 4 and r.passphrase_lang == "en"
    assert r.bits == pytest.approx(4 * 12.925, abs=0.1)  # not length * log2(pool)


def test_check_warnings():
    r = check.analyse("Password1234!!!")
    joined = " ".join(r.warnings)
    assert "common" in joined and "1234" in joined and "repeated" in joined
    assert r.verdict in ("weak", "fair")
    assert check.analyse("abc").verdict == "weak"


def test_check_cli_exit_codes():
    assert runner.invoke(app, ["check", "qwerty12"]).exit_code == 1
    r = runner.invoke(app, ["check", core.password(32), "--json"])
    assert r.exit_code == 0 and json.loads(r.stdout)["verdict"] in ("strong", "very strong")
    r = runner.invoke(app, ["check"], input="mango-cactus-saline-direction\n")
    assert r.exit_code == 0 and "4 words" in r.stdout


# --- totp --------------------------------------------------------------------


def test_totp_rfc6238_vectors():
    # RFC 6238 appendix B, 8 digits, SHA1, secret "12345678901234567890".
    secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
    assert totp.totp_code(secret, at=59, digits=8) == "94287082"
    assert totp.totp_code(secret, at=1111111109, digits=8) == "07081804"
    assert totp.totp_code(secret, at=1234567890, digits=8) == "89005924"


def test_totp_secret_and_uri():
    s = totp.totp_secret()
    assert re.match(r"^[A-Z2-7]{32}$", s)
    uri = totp.otpauth_uri(s, "ana@example.com", "My App")
    assert uri.startswith("otpauth://totp/My%20App%3Aana%40example.com?secret=")
    assert "issuer=My+App" in uri


def test_totp_cli():
    r = runner.invoke(app, ["totp", "new", "-a", "me", "-i", "svc", "--no-qr", "--json"])
    assert r.exit_code == 0
    data = json.loads(r.stdout)
    assert totp.totp_code(data["secret"]) == data["current_code"]
    r = runner.invoke(app, ["totp", "code", data["secret"]])
    assert r.exit_code == 0 and re.match(r"^\d{6}$", r.stdout.strip().splitlines()[0])


# --- infra -------------------------------------------------------------------


def test_ssh_and_wireguard(tmp_path):
    pytest.importorskip("cryptography")
    from keygen import infra

    pair = infra.ssh_keypair("me@box")
    assert pair.private.startswith("-----BEGIN OPENSSH PRIVATE KEY-----")
    assert pair.public.startswith("ssh-ed25519 AAAA") and pair.public.endswith(" me@box")

    wg = infra.wireguard_keypair()
    assert len(wg.private) == 44 and len(wg.public) == 44 and wg.private != wg.public

    out = tmp_path / "id_ed25519"
    r = runner.invoke(app, ["ssh", "-C", "x", "-o", str(out)])
    assert r.exit_code == 0 and out.is_file() and out.with_name("id_ed25519.pub").is_file()
    assert runner.invoke(app, ["ssh", "-o", str(out)]).exit_code == 1  # refuses to overwrite


def test_jwt_secret():
    from keygen import infra

    assert len(infra.jwt_secret(256, "hex")) == 64
    assert len(infra.jwt_secret(512, "base64url")) == 86
    with pytest.raises(ValueError):
        infra.jwt_secret(100)
    r = runner.invoke(app, ["jwt-secret", "-b", "384", "-E", "base64"])
    assert r.exit_code == 0 and len(r.stdout.strip()) == 64


def test_htpasswd():
    bcrypt = pytest.importorskip("bcrypt")
    from keygen import infra

    line = infra.htpasswd_line("ana", "s3cret", rounds=4)
    user, digest = line.split(":", 1)
    assert user == "ana" and digest.startswith("$2y$04$")
    assert bcrypt.checkpw(b"s3cret", digest.replace("$2y$", "$2b$", 1).encode())
    r = runner.invoke(app, ["htpasswd", "ana", "--rounds", "4"])
    assert r.exit_code == 0 and r.stdout.startswith("ana:$2y$") and "password:" in r.output


# --- presets -----------------------------------------------------------------


def test_builtin_presets_all_run():
    table = presets.load()
    for name in presets.BUILTIN:
        assert len(presets.run(name, 2, table)) == 2


def test_user_presets_override(tmp_path, monkeypatch):
    f = tmp_path / "presets.toml"
    f.write_text(
        "[stripe]\ncommand = 'key'\nformat = 'hex'\nlength = 8\nprefix = 'sk_x_'\n"
        "\n[mine]\ncommand = 'pin'\nlength = 4\n"
    )
    monkeypatch.setenv("KEYGEN_PRESETS", str(f))
    table = presets.load()
    assert re.match(r"^sk_x_[0-9a-f]{8}$", presets.run("stripe", 1, table)[0])
    assert re.match(r"^\d{4}$", presets.run("mine", 1, table)[0])
    r = runner.invoke(app, ["preset"])
    assert r.exit_code == 0 and "mine" in r.stdout and "stripe" in r.stdout
    assert runner.invoke(app, ["preset", "nope"]).exit_code == 1


def test_preset_cli():
    r = runner.invoke(app, ["preset", "github", "-n", "2"])
    assert r.exit_code == 0 and all(ln.startswith("ghp_") for ln in r.stdout.splitlines())


# --- selftest ----------------------------------------------------------------


def test_selftest_passes():
    results = selftest.run(samples=200)
    assert results and all(r.ok for r in results), [r for r in results if not r.ok]


def test_selftest_cli():
    r = runner.invoke(app, ["selftest", "-s", "100"])
    assert r.exit_code == 0 and "passed" in r.output


# --- web page parity -----------------------------------------------------------


def test_web_presets_mirror_builtin():
    """web/app.js carries a hand copy of presets.BUILTIN; every built-in must be there."""
    from pathlib import Path

    js = (Path(__file__).resolve().parents[1] / "web" / "app.js").read_text(encoding="utf-8")
    for name, spec in presets.BUILTIN.items():
        assert f'"{name}": {{ command: "{spec["command"]}"' in js, name
    for group in (core.ONSETS, core.VOWELS):
        assert all(f'"{t}"' in js for t in group)
