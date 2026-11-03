"""CLI smoke tests through typer's runner."""

from __future__ import annotations

import json
import re

from typer.testing import CliRunner

from keygen import __version__
from keygen.cli import app

runner = CliRunner(env={"NO_COLOR": "1", "TERM": "dumb", "COLUMNS": "200"})


def test_version():
    r = runner.invoke(app, ["version"])
    assert r.exit_code == 0 and __version__ in r.stdout


def test_help_lists_commands():
    r = runner.invoke(app, ["--help"])
    assert r.exit_code == 0
    for cmd in ("key", "password", "passphrase", "pin", "recovery", "serve", "web", "version"):
        assert cmd in r.stdout


def test_key_default_and_count():
    r = runner.invoke(app, ["key", "-n", "3", "-l", "16", "-f", "hex", "-p", "sk_"])
    assert r.exit_code == 0
    lines = r.stdout.strip().splitlines()
    assert len(lines) == 3 and all(re.match(r"^sk_[0-9a-f]{16}$", ln) for ln in lines)


def test_key_bad_format_fails_cleanly():
    r = runner.invoke(app, ["key", "-f", "rot13"])
    assert r.exit_code == 1 and "unknown format" in r.output


def test_password_json_includes_entropy():
    r = runner.invoke(app, ["password", "--json", "-l", "24", "--no-symbols"])
    assert r.exit_code == 0
    data = json.loads(r.stdout)
    assert len(data["passwords"]) == 1 and len(data["passwords"][0]) == 24
    assert data["symbols"] is False and data["entropy_bits"] > 100


def test_password_entropy_to_stderr():
    r = runner.invoke(app, ["password", "-e"])
    assert r.exit_code == 0 and "entropy:" in r.output


def test_passphrase():
    r = runner.invoke(app, ["passphrase", "-w", "5", "-s", " "])
    assert r.exit_code == 0 and len(r.stdout.strip().split(" ")) >= 5


def test_pin_and_recovery():
    assert re.match(r"^\d{8}\n$", runner.invoke(app, ["pin", "-l", "8"]).stdout)
    r = runner.invoke(app, ["recovery", "-n", "4"])
    assert r.exit_code == 0 and r.stdout.startswith("# Recovery codes")
    assert len([ln for ln in r.stdout.splitlines() if ln and not ln.startswith("#")]) == 4


def test_out_file(tmp_path):
    target = tmp_path / "keys.txt"
    r = runner.invoke(app, ["key", "-n", "2", "-o", str(target)])
    assert r.exit_code == 0 and r.stdout == ""
    assert len(target.read_text().splitlines()) == 2


def test_no_args_shows_help():
    r = runner.invoke(app, [])
    assert "Usage" in r.output
