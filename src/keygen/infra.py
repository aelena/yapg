"""Key material for servers: SSH and WireGuard pairs, JWT secrets, htpasswd lines.

`cryptography` and `bcrypt` are optional (the [infra] extra); each function imports
what it needs so the rest of the package stays dependency-free.
"""

from __future__ import annotations

import base64
import secrets
from dataclasses import dataclass


def _need(module: str):
    try:
        return __import__(module)
    except ImportError as e:
        raise RuntimeError(f"{module} is not installed; install the [infra] extra") from e


@dataclass(frozen=True)
class KeyPair:
    private: str
    public: str


def ssh_keypair(comment: str = "") -> KeyPair:
    """An ed25519 pair: OpenSSH private key (PEM text) and the one-line public key."""
    _need("cryptography")
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    key = Ed25519PrivateKey.generate()
    private = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.OpenSSH,
        serialization.NoEncryption(),
    ).decode("ascii")
    public = key.public_key().public_bytes(
        serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH
    ).decode("ascii")
    if comment:
        public += f" {comment}"
    return KeyPair(private, public)


def wireguard_keypair() -> KeyPair:
    """An x25519 pair, base64 as `wg genkey` / `wg pubkey` print them."""
    _need("cryptography")
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

    key = X25519PrivateKey.generate()
    raw = serialization.Encoding.Raw
    private = key.private_bytes(raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    public = key.public_key().public_bytes(raw, serialization.PublicFormat.Raw)
    return KeyPair(base64.b64encode(private).decode(), base64.b64encode(public).decode())


def wireguard_preshared() -> str:
    return base64.b64encode(secrets.token_bytes(32)).decode()


def jwt_secret(bits: int = 256, encoding: str = "base64url") -> str:
    """Random bytes for HMAC signing. HS256 wants at least 256 bits; HS512 at least 512."""
    if bits % 8 or not 128 <= bits <= 4096:
        raise ValueError("bits must be a multiple of 8 between 128 and 4096")
    raw = secrets.token_bytes(bits // 8)
    match encoding:
        case "hex":
            return raw.hex()
        case "base64":
            return base64.b64encode(raw).decode()
        case "base64url":
            return base64.urlsafe_b64encode(raw).decode().rstrip("=")
        case _:
            raise ValueError("encoding must be hex, base64 or base64url")


def htpasswd_line(user: str, password: str, rounds: int = 12) -> str:
    """A `user:$2y$...` line for Apache, nginx, Caddy or Traefik basic auth (bcrypt)."""
    bcrypt = _need("bcrypt")
    if ":" in user or not user:
        raise ValueError("user must be non-empty and contain no ':'")
    digest = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds)).decode("ascii")
    # Apache documents $2y$; bcrypt emits $2b$. They are the same algorithm and every
    # current server accepts both, but $2y$ is what the htpasswd tool itself writes.
    return f"{user}:{digest.replace('$2b$', '$2y$', 1)}"
