"""Pure generators. Every function draws from `secrets` and returns a string.

Nothing here does I/O, parses arguments or knows about HTTP; the CLI and the
API are thin skins over these functions, and the web page reimplements the
same algorithms in JavaScript.
"""

from __future__ import annotations

import base64
import math
import secrets
import string
import uuid
from collections.abc import Callable
from functools import cache
from importlib import resources
from typing import Literal

KeyFormat = Literal["hex", "base64url", "alnum", "uuid"]
KEY_FORMATS: tuple[KeyFormat, ...] = ("hex", "base64url", "alnum", "uuid")

SYMBOLS = "!@#$%^&*()-_=+[]{};:,.<>?/"
AMBIGUOUS = frozenset("Il1O0")
ALNUM = string.ascii_letters + string.digits
# Crockford-inspired lowercase alphabet: no 0/O, 1/I/l. 31 symbols, ~4.95 bits each.
RECOVERY_ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789"
MAX_BATCH = 500
MAX_PREFIX = 64

LIMITS: dict[str, tuple[int, int]] = {
    "key_length": (8, 256),
    "password_length": (4, 128),
    "recovery_length": (6, 32),
    "passphrase_words": (3, 20),
    "pin_length": (4, 32),
}


class GenerationError(ValueError):
    """A request that cannot be honoured: bad format, empty alphabet, bad prefix."""


# --- helpers -----------------------------------------------------------------


def _from(alphabet: str, length: int) -> str:
    return "".join(secrets.choice(alphabet) for _ in range(length))


def _shuffle(chars: list[str]) -> list[str]:
    """Fisher-Yates with the CSPRNG; mutates and returns `chars`."""
    for i in range(len(chars) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        chars[i], chars[j] = chars[j], chars[i]
    return chars


def _check_range(name: str, value: int, lo: int, hi: int) -> int:
    if not lo <= value <= hi:
        raise GenerationError(f"{name} must be between {lo} and {hi}, got {value}")
    return value


def validate_prefix(prefix: str) -> str:
    if len(prefix) > MAX_PREFIX:
        raise GenerationError(f"prefix longer than {MAX_PREFIX} characters")
    if any(c.isspace() or not c.isprintable() for c in prefix):
        raise GenerationError("prefix must not contain whitespace or control characters")
    return prefix


@cache
def wordlist() -> tuple[str, ...]:
    """The EFF large wordlist: 7776 words, 12.9 bits each, chosen for memorability."""
    text = resources.files("keygen").joinpath("data/eff_large_wordlist.txt").read_text("utf-8")
    return tuple(text.split())


# --- generators --------------------------------------------------------------


def api_key(fmt: KeyFormat = "base64url", length: int = 40, prefix: str = "") -> str:
    """An opaque token. `length` counts characters after the prefix; ignored for uuid."""
    validate_prefix(prefix)
    if fmt == "uuid":
        return prefix + str(uuid.UUID(bytes=secrets.token_bytes(16), version=4))
    _check_range("length", length, *LIMITS["key_length"])
    match fmt:
        case "hex":
            body = secrets.token_hex((length + 1) // 2)[:length]
        case "base64url":
            raw = secrets.token_bytes(length * 3 // 4 + 3)
            body = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")[:length]
        case "alnum":
            body = _from(ALNUM, length)
        case _:
            raise GenerationError(f"unknown format {fmt!r}; use one of {', '.join(KEY_FORMATS)}")
    return prefix + body


def charsets(
    upper: bool = True,
    lower: bool = True,
    digits: bool = True,
    symbols: bool = True,
    exclude_ambiguous: bool = False,
) -> list[str]:
    """The non-empty character classes a password must draw from, in a stable order."""
    chosen = [
        s
        for on, s in (
            (upper, string.ascii_uppercase),
            (lower, string.ascii_lowercase),
            (digits, string.digits),
            (symbols, SYMBOLS),
        )
        if on
    ]
    if exclude_ambiguous:
        chosen = ["".join(c for c in s if c not in AMBIGUOUS) for s in chosen]
    chosen = [s for s in chosen if s]
    if not chosen:
        raise GenerationError("select at least one character set")
    return chosen


def password(
    length: int = 20,
    upper: bool = True,
    lower: bool = True,
    digits: bool = True,
    symbols: bool = True,
    exclude_ambiguous: bool = False,
) -> str:
    """At least one character from every selected class, the rest uniform, then shuffled."""
    _check_range("length", length, *LIMITS["password_length"])
    sets = charsets(upper, lower, digits, symbols, exclude_ambiguous)
    alphabet = "".join(sets)
    length = max(length, len(sets))
    guaranteed = [secrets.choice(s) for s in sets]
    rest = [secrets.choice(alphabet) for _ in range(length - len(sets))]
    return "".join(_shuffle(guaranteed + rest))


def password_entropy_bits(
    length: int,
    upper: bool = True,
    lower: bool = True,
    digits: bool = True,
    symbols: bool = True,
    exclude_ambiguous: bool = False,
) -> float:
    """Upper bound: length * log2(pool). The one-of-each rule costs a few bits at short lengths."""
    pool = sum(len(s) for s in charsets(upper, lower, digits, symbols, exclude_ambiguous))
    return length * math.log2(pool)


def recovery_code(length: int = 10, groups: int = 2) -> str:
    """GitHub-style one-time code: `length` symbols split into `groups` dash-separated chunks."""
    _check_range("length", length, *LIMITS["recovery_length"])
    _check_range("groups", groups, 1, length)
    raw = _from(RECOVERY_ALPHABET, length)
    size = math.ceil(length / groups)
    return "-".join(raw[i : i + size] for i in range(0, length, size))


def recovery_entropy_bits(length: int = 10) -> float:
    return length * math.log2(len(RECOVERY_ALPHABET))


def passphrase(
    words: int = 6,
    separator: str = "-",
    capitalize: bool = False,
    digit: bool = False,
) -> str:
    """Diceware-style passphrase from the EFF large list.

    `capitalize` title-cases each word; `digit` appends one random digit to a random
    word. Both exist to satisfy composition rules, not to add meaningful entropy.
    """
    _check_range("words", words, *LIMITS["passphrase_words"])
    picks = [secrets.choice(wordlist()) for _ in range(words)]
    if capitalize:
        picks = [w.capitalize() for w in picks]
    if digit:
        i = secrets.randbelow(words)
        picks[i] += str(secrets.randbelow(10))
    return separator.join(picks)


def passphrase_entropy_bits(words: int = 6) -> float:
    return words * math.log2(len(wordlist()))


def pin(length: int = 6) -> str:
    """Digits only: 3.32 bits per digit. Under 8 digits it is a lock, not a secret."""
    _check_range("length", length, *LIMITS["pin_length"])
    return _from(string.digits, length)


def many(fn: Callable[..., str], count: int, /, **kwargs) -> list[str]:
    """`count` independent draws from any generator above."""
    _check_range("count", count, 1, MAX_BATCH)
    return [fn(**kwargs) for _ in range(count)]
