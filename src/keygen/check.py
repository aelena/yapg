"""Score a secret somebody already has: entropy estimate, structure, optional breach lookup.

This is not zxcvbn. It answers three questions a developer actually asks:
how many bits does this look like, what is obviously wrong with it, and has it
been seen in a breach. The breach check uses the Have I Been Pwned range API with
k-anonymity: only the first five hex characters of the SHA-1 leave the machine.
"""

from __future__ import annotations

import hashlib
import math
import re
import string
import urllib.request
from dataclasses import dataclass, field

from keygen import core

KEYBOARD_ROWS = ("qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890")
PATTERN_PENALTY = 15.0
COMMON = {"password", "letmein", "welcome", "admin", "iloveyou", "monkey", "dragon"}


@dataclass
class Report:
    secret_length: int
    classes: list[str]
    pool_bits: float
    passphrase_words: int | None
    passphrase_lang: str | None
    passphrase_bits: float | None
    warnings: list[str] = field(default_factory=list)
    pwned_count: int | None = None  # None = not checked

    @property
    def bits(self) -> float:
        """Effective estimate: the lower of pool and passphrase bits, minus a penalty per pattern.

        A dictionary passphrase is not a random string, and a keyboard run or a common word
        is not random either. Each structural warning costs PATTERN_PENALTY bits. This is a
        heuristic, not zxcvbn; it exists to stop obvious junk from scoring "fair".
        """
        base = self.pool_bits
        if self.passphrase_bits is not None:
            base = min(base, self.passphrase_bits)
        patterns = [w for w in self.warnings if not w.startswith("shorter")]
        return max(0.0, base - PATTERN_PENALTY * len(patterns))

    @property
    def verdict(self) -> str:
        if self.pwned_count:
            return "breached"
        b = self.bits
        if b < 40:
            return "weak"
        if b < 64:
            return "fair"
        if b < 96:
            return "strong"
        return "very strong"


def _classes(secret: str) -> list[str]:
    found = []
    if any(c in string.ascii_uppercase for c in secret):
        found.append("upper")
    if any(c in string.ascii_lowercase for c in secret):
        found.append("lower")
    if any(c in string.digits for c in secret):
        found.append("digits")
    if any(c in core.SYMBOLS for c in secret):
        found.append("symbols")
    if any(c not in string.ascii_letters + string.digits + core.SYMBOLS for c in secret):
        found.append("other")
    return found


def _pool(classes: list[str], secret: str) -> int:
    size = {"upper": 26, "lower": 26, "digits": 10, "symbols": len(core.SYMBOLS)}
    pool = sum(size.get(c, 0) for c in classes)
    if "other" in classes:
        known = string.ascii_letters + string.digits + core.SYMBOLS
        pool += len({c for c in secret if c not in known})
    return max(pool, 1)


def _passphrase(secret: str) -> tuple[int, str, float] | None:
    """If every token is in one of the bundled lists, return (words, lang, bits)."""
    tokens = [t.lower().rstrip(string.digits) for t in re.split(r"[\s\-_./,;:+]+", secret) if t]
    if len(tokens) < 2:
        return None
    for lang in core.LANGS:
        words = set(core.wordlist(lang))
        if all(t in words for t in tokens):
            return len(tokens), lang, len(tokens) * math.log2(len(words))
    return None


def _warnings(secret: str) -> list[str]:
    out = []
    low = secret.lower()
    if len(secret) < 12:
        out.append("shorter than 12 characters")
    if re.search(r"(.)\1{2,}", secret):
        out.append("a character repeated three or more times in a row")
    if re.search(r"(..+)\1", low):
        out.append("a repeated substring")
    for row in KEYBOARD_ROWS:
        for i in range(len(row) - 3):
            if row[i : i + 4] in low or row[i : i + 4][::-1] in low:
                out.append(f"keyboard/sequence run '{row[i:i + 4]}'")
                break
    if re.search(r"(?:19|20)\d\d", secret):
        out.append("contains a year")
    if any(w in low for w in COMMON):
        out.append("contains a very common password word")
    alpha = "abcdefghijklmnopqrstuvwxyz"
    for i in range(len(alpha) - 3):
        if alpha[i : i + 4] in low:
            out.append(f"alphabetical run '{alpha[i:i + 4]}'")
            break
    return out


def pwned_count(secret: str, timeout: float = 5.0) -> int:
    """How many times the secret appears in Have I Been Pwned. Sends only 5 hex chars."""
    sha1 = hashlib.sha1(secret.encode("utf-8")).hexdigest().upper()  # noqa: S324 - the API is SHA-1
    head, tail = sha1[:5], sha1[5:]
    req = urllib.request.Request(
        f"https://api.pwnedpasswords.com/range/{head}",
        headers={"User-Agent": "keygen-check", "Add-Padding": "true"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - fixed https host
        body = resp.read().decode("utf-8")
    for line in body.splitlines():
        suffix, _, count = line.partition(":")
        if suffix.strip() == tail:
            return int(count)
    return 0


def analyse(secret: str, hibp: bool = False) -> Report:
    classes = _classes(secret)
    pool_bits = len(secret) * math.log2(_pool(classes, secret))
    phrase = _passphrase(secret)
    report = Report(
        secret_length=len(secret),
        classes=classes,
        pool_bits=pool_bits,
        passphrase_words=phrase[0] if phrase else None,
        passphrase_lang=phrase[1] if phrase else None,
        passphrase_bits=phrase[2] if phrase else None,
        warnings=_warnings(secret),
    )
    if hibp:
        report.pwned_count = pwned_count(secret)
    return report
