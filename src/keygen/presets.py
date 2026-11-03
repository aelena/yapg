"""Named presets: a generator plus its arguments, under one word.

Built-ins cover the conventions people copy most. Your own live in
`$KEYGEN_PRESETS` or `~/.config/keygen/presets.toml` and override built-ins by name:

    [stripe]
    command = "key"
    format = "alnum"
    length = 24
    prefix = "sk_live_"

    [vault]
    command = "passphrase"
    words = 7
    lang = "es"
"""

from __future__ import annotations

import os
import tomllib
from pathlib import Path
from typing import Any

from keygen import core

COMMANDS: dict[str, Any] = {
    "key": core.api_key,
    "password": core.password,
    "passphrase": core.passphrase,
    "pronounceable": core.pronounceable,
    "pin": core.pin,
    "recovery": core.recovery_code,
}

# Argument names as the generators take them (the CLI uses --format; core uses fmt).
_RENAME = {"format": "fmt", "sep": "separator"}

BUILTIN: dict[str, dict[str, Any]] = {
    "stripe": {"command": "key", "format": "alnum", "length": 24, "prefix": "sk_live_",
               "doc": "Stripe-style secret key"},
    "stripe-test": {"command": "key", "format": "alnum", "length": 24, "prefix": "sk_test_",
                    "doc": "Stripe-style test key"},
    "github": {"command": "key", "format": "alnum", "length": 36, "prefix": "ghp_",
               "doc": "GitHub-style personal access token"},
    "api-hex": {"command": "key", "format": "hex", "length": 64,
                "doc": "256-bit hex token"},
    "api-urlsafe": {"command": "key", "format": "base64url", "length": 43,
                    "doc": "256-bit base64url token"},
    "session": {"command": "key", "format": "base64url", "length": 32,
                "doc": "Session cookie value"},
    "db": {"command": "password", "length": 32, "symbols": False,
           "doc": "Database password: 32 alphanumerics, safe in connection strings"},
    "wifi": {"command": "passphrase", "words": 4, "separator": "-", "capitalize": True,
             "doc": "WPA passphrase a guest can type"},
    "vault": {"command": "passphrase", "words": 7, "separator": " ",
              "doc": "Master passphrase, about 90 bits"},
    "phone": {"command": "pronounceable", "syllables": 4, "capitalize": True,
              "doc": "Temporary password you can read out loud"},
    "pin": {"command": "pin", "length": 6, "doc": "Six-digit PIN"},
    "2fa-backup": {"command": "recovery", "length": 10, "groups": 2,
                   "doc": "Recovery code, xxxxx-xxxxx"},
}


def user_presets_path() -> Path:
    if env := os.environ.get("KEYGEN_PRESETS"):
        return Path(env)
    base = os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config"
    return Path(base) / "keygen" / "presets.toml"


def load() -> dict[str, dict[str, Any]]:
    """Built-ins overlaid with the user's file, if any."""
    merged = {k: dict(v) for k, v in BUILTIN.items()}
    path = user_presets_path()
    if path.is_file():
        with path.open("rb") as f:
            for name, spec in tomllib.load(f).items():
                if not isinstance(spec, dict) or "command" not in spec:
                    raise ValueError(f"preset {name!r} in {path} needs a 'command' key")
                merged[name] = dict(spec)
    return merged


def run(name: str, count: int = 1, presets: dict[str, dict[str, Any]] | None = None) -> list[str]:
    presets = presets if presets is not None else load()
    if name not in presets:
        raise KeyError(name)
    spec = dict(presets[name])
    command = spec.pop("command")
    spec.pop("doc", None)
    if command not in COMMANDS:
        raise ValueError(f"preset {name!r}: unknown command {command!r}")
    kwargs = {_RENAME.get(k, k): v for k, v in spec.items()}
    return core.many(COMMANDS[command], count, **kwargs)


def describe(name: str, spec: dict[str, Any]) -> str:
    args = ", ".join(f"{k}={v!r}" for k, v in spec.items() if k not in ("command", "doc"))
    doc = f"  {spec['doc']}" if spec.get("doc") else ""
    return f"{name:<14} {spec['command']:<13} {args}{doc}"
