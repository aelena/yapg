"""Statistical regression guard: are the generators still uniform over their alphabets?

A chi-squared goodness-of-fit test per alphabet, plus the structural guarantees
(password classes, recovery alphabet, wordlist sizes). It cannot prove randomness,
but it catches the mistakes that matter: a truncated alphabet, modulo bias, an
off-by-one that drops the last symbol, a wordlist that lost a line.
"""

from __future__ import annotations

import math
import string
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass

from keygen import core

B64URL = string.ascii_letters + string.digits + "-_"


@dataclass(frozen=True)
class Result:
    name: str
    ok: bool
    detail: str


def _chi_squared_p(counts: Counter[str], alphabet: str, n: int) -> float:
    """p-value of the observed counts against a uniform distribution over `alphabet`."""
    expected = n / len(alphabet)
    chi2 = sum((counts.get(c, 0) - expected) ** 2 / expected for c in alphabet)
    k = len(alphabet) - 1
    # Wilson-Hilferty approximation of the chi-squared survival function.
    z = ((chi2 / k) ** (1 / 3) - (1 - 2 / (9 * k))) / math.sqrt(2 / (9 * k))
    return 0.5 * math.erfc(z / math.sqrt(2))


def _uniform(name: str, draw: Callable[[], str], alphabet: str, samples: int) -> Result:
    text = "".join(draw() for _ in range(samples))
    stray = set(text) - set(alphabet)
    if stray:
        return Result(name, False, f"characters outside alphabet: {''.join(sorted(stray))!r}")
    counts = Counter(text)
    missing = [c for c in alphabet if c not in counts]
    if missing:
        return Result(name, False, f"never produced: {''.join(missing)!r}")
    p = _chi_squared_p(counts, alphabet, len(text))
    return Result(name, p > 0.001, f"chi2 p={p:.3f} over {len(text)} symbols")


def run(samples: int = 400) -> list[Result]:
    results = [
        _uniform("hex", lambda: core.api_key("hex", 64), "0123456789abcdef", samples),
        _uniform("base64url", lambda: core.api_key("base64url", 64), B64URL, samples),
        _uniform("alnum", lambda: core.api_key("alnum", 64), core.ALNUM, samples),
        _uniform("recovery", lambda: core.recovery_code(32, 1), core.RECOVERY_ALPHABET, samples),
        _uniform("pin", lambda: core.pin(32), string.digits, samples),
        _uniform("password", lambda: core.password(64), "".join(core.charsets()), samples),
    ]

    # Structural guarantees.
    classes_ok = all(
        any(c in s for c in core.password(4)) for s in core.charsets() for _ in range(50)
    )
    results.append(Result("password classes", classes_ok, "one of each class at length 4"))

    for lang in core.LANGS:
        words = core.wordlist(lang)
        ok = len(words) == 7776 and len(set(words)) == 7776
        detail = f"{len(words)} words, {len(set(words))} unique"
        results.append(Result(f"wordlist {lang}", ok, detail))

    # Word draws should be uniform too: bucket word indexes into 16 bins.
    words = core.wordlist("en")
    index = {w: i for i, w in enumerate(words)}
    bins = "0123456789abcdef"
    drawn = [w for _ in range(samples) for w in core.passphrase(20, "\x00").split("\x00")]
    buckets = Counter(bins[index[w] * 16 // len(words)] for w in drawn)
    p = _chi_squared_p(buckets, bins, len(drawn))
    results.append(Result("passphrase draw", p > 0.001, f"chi2 p={p:.3f} over 16 buckets"))

    uuids = {core.api_key("uuid") for _ in range(samples)}
    v4 = all(u[14] == "4" and u[19] in "89ab" for u in uuids)
    ok = v4 and len(uuids) == samples
    results.append(Result("uuid v4", ok, "version/variant bits, no repeats"))
    return results
