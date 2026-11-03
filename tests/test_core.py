"""Properties every generator must hold, checked over many draws."""

from __future__ import annotations

import re
import string

import pytest

from keygen import core

N = 200  # draws per property; cheap, and enough to catch a wrong alphabet


# --- api_key -----------------------------------------------------------------


@pytest.mark.parametrize("fmt,pattern", [
    ("hex", r"^[0-9a-f]+$"),
    ("base64url", r"^[A-Za-z0-9_-]+$"),
    ("alnum", r"^[A-Za-z0-9]+$"),
])
@pytest.mark.parametrize("length", [8, 9, 40, 41, 256])
def test_api_key_alphabet_and_length(fmt, pattern, length):
    for _ in range(N):
        k = core.api_key(fmt, length)
        assert len(k) == length
        assert re.match(pattern, k)


def test_api_key_uuid_is_v4():
    for _ in range(N):
        k = core.api_key("uuid")
        assert re.match(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", k)


def test_api_key_prefix():
    assert core.api_key("hex", 16, "sk_live_").startswith("sk_live_")
    assert len(core.api_key("hex", 16, "sk_live_")) == 8 + 16


@pytest.mark.parametrize("bad", ["a b", "x" * 65, "tab\there", "nl\n"])
def test_api_key_rejects_bad_prefix(bad):
    with pytest.raises(core.GenerationError):
        core.api_key("hex", 16, bad)


def test_api_key_rejects_bad_format_and_length():
    with pytest.raises(core.GenerationError):
        core.api_key("rot13", 16)  # type: ignore[arg-type]
    with pytest.raises(core.GenerationError):
        core.api_key("hex", 7)
    with pytest.raises(core.GenerationError):
        core.api_key("hex", 257)


def test_api_keys_are_distinct():
    assert len({core.api_key("hex", 32) for _ in range(N)}) == N


# --- password ----------------------------------------------------------------


def test_password_contains_every_enabled_class():
    for _ in range(N):
        p = core.password(8)
        assert any(c in string.ascii_uppercase for c in p)
        assert any(c in string.ascii_lowercase for c in p)
        assert any(c in string.digits for c in p)
        assert any(c in core.SYMBOLS for c in p)


def test_password_respects_disabled_classes():
    for _ in range(N):
        p = core.password(20, upper=False, symbols=False)
        assert set(p) <= set(string.ascii_lowercase + string.digits)


def test_password_exclude_ambiguous():
    for _ in range(N):
        assert not (set(core.password(40, exclude_ambiguous=True)) & core.AMBIGUOUS)


def test_password_length_floor_is_number_of_classes():
    # 4 classes enabled, length 4 is the minimum and still gets one of each
    assert len(core.password(4)) == 4


def test_password_needs_a_class():
    with pytest.raises(core.GenerationError):
        core.password(12, upper=False, lower=False, digits=False, symbols=False)


def test_password_entropy_counts_only_enabled_pools():
    full = core.password_entropy_bits(10)
    lower_only = core.password_entropy_bits(10, upper=False, digits=False, symbols=False)
    assert full > lower_only
    # excluding ambiguous from lowercase removes only 'l', so one fewer symbol in the pool
    lower_no_l = core.password_entropy_bits(
        10, upper=False, digits=False, symbols=False, exclude_ambiguous=True
    )
    assert lower_no_l == pytest.approx(10 * 4.643856, abs=1e-3)


# --- recovery codes ----------------------------------------------------------


def test_recovery_code_shape():
    for _ in range(N):
        c = core.recovery_code(10)
        assert re.match(r"^[a-hj-kmnp-z2-9]{5}-[a-hj-kmnp-z2-9]{5}$", c)


def test_recovery_code_groups():
    assert core.recovery_code(12, groups=3).count("-") == 2
    assert core.recovery_code(9, groups=2) .count("-") == 1  # odd split: 5 + 4
    assert core.recovery_code(8, groups=1).count("-") == 0


def test_recovery_code_never_has_ambiguous():
    for _ in range(N):
        assert not (set(core.recovery_code(32)) & set("0O1Il"))


# --- passphrase / pin --------------------------------------------------------


def test_wordlist_is_eff_large():
    words = core.wordlist()
    assert len(words) == 7776
    assert len(set(words)) == 7776
    assert all(re.match(r"^[a-z-]+$", w) for w in words)


def test_passphrase_shape():
    for _ in range(N):
        p = core.passphrase(6)
        parts = p.split("-")
        assert len(parts) >= 6  # hyphenated words like "yo-yo" add a dash
        assert all(part.islower() for part in parts)


def test_passphrase_options():
    p = core.passphrase(4, separator=" ", capitalize=True)
    assert all(w[0].isupper() for w in p.split(" "))
    assert any(c.isdigit() for c in core.passphrase(4, separator=".", digit=True))


def test_passphrase_entropy():
    assert core.passphrase_entropy_bits(6) == pytest.approx(77.5, abs=0.1)


def test_pin():
    for _ in range(N):
        assert re.match(r"^\d{6}$", core.pin())
    with pytest.raises(core.GenerationError):
        core.pin(3)


# --- many --------------------------------------------------------------------


def test_many_bounds():
    assert len(core.many(core.pin, 500)) == 500
    with pytest.raises(core.GenerationError):
        core.many(core.pin, 0)
    with pytest.raises(core.GenerationError):
        core.many(core.pin, 501)
