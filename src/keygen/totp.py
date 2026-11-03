"""RFC 6238 TOTP: secrets, otpauth:// URIs and the codes themselves. Standard library only."""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote, urlencode

ALGORITHMS = ("SHA1", "SHA256", "SHA512")


def totp_secret(nbytes: int = 20) -> str:
    """Base32 secret without padding. 20 bytes (160 bits) is what Google Authenticator expects."""
    if not 10 <= nbytes <= 64:
        raise ValueError("secret length must be between 10 and 64 bytes")
    return base64.b32encode(secrets.token_bytes(nbytes)).decode("ascii").rstrip("=")


def otpauth_uri(
    secret: str,
    account: str,
    issuer: str = "",
    digits: int = 6,
    period: int = 30,
    algorithm: str = "SHA1",
) -> str:
    """The URI an authenticator app reads from a QR code (Key Uri Format)."""
    if algorithm not in ALGORITHMS:
        raise ValueError(f"algorithm must be one of {', '.join(ALGORITHMS)}")
    label = f"{issuer}:{account}" if issuer else account
    params = {"secret": secret, "digits": digits, "period": period, "algorithm": algorithm}
    if issuer:
        params["issuer"] = issuer
    return f"otpauth://totp/{quote(label)}?{urlencode(params)}"


def totp_code(
    secret: str,
    at: float | None = None,
    digits: int = 6,
    period: int = 30,
    algorithm: str = "SHA1",
) -> str:
    """The current (or given-time) code for a base32 secret."""
    if algorithm not in ALGORITHMS:
        raise ValueError(f"algorithm must be one of {', '.join(ALGORITHMS)}")
    padded = secret.upper().replace(" ", "") + "=" * (-len(secret) % 8)
    key = base64.b32decode(padded, casefold=True)
    counter = int((time.time() if at is None else at) // period)
    digest = hmac.new(key, struct.pack(">Q", counter), getattr(hashlib, algorithm.lower())).digest()
    offset = digest[-1] & 0x0F
    code = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(code % 10**digits).zfill(digits)


def seconds_remaining(period: int = 30, at: float | None = None) -> int:
    now = time.time() if at is None else at
    return period - int(now % period)
