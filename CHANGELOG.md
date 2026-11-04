# Changelog

## 0.4.0 — 2026-11-04

- Distribution renamed to `yapg-py` for PyPI (`yapg` there is an unrelated project). The import package is still `keygen`; the commands are still `keygen` and `yapg`.
- Web page: `Pronounceable` and `Presets` tabs, so every generator the CLI offers (bar the key-material ones) is on the page too.
- Release workflow with PyPI trusted publishing, triggered by a `vX.Y.Z` tag.

## 0.3.0 — 2026-11-03

- `check`: entropy estimate, passphrase detection, keyboard/repeat/sequence penalties, optional Have I Been Pwned lookup (k-anonymity).
- `totp new` and `totp code` (RFC 6238), otpauth URI, optional ASCII QR.
- `ssh`, `wireguard`, `jwt-secret`, `htpasswd` (bcrypt, `$2y$`).
- `preset`: twelve built-ins plus a TOML file of your own.
- Spanish and German Diceware wordlists with their licences; `pronounceable`.
- `selftest`: chi-squared uniformity check per alphabet, run in CI.
- CI on ubuntu and windows, GitHub Pages deploy of `web/`, UTF-8 output on Windows.

## 0.2.0 — 2026-11-03

- Packaged as `keygen` with a Typer CLI; Sanic API moved into the package.
- Passphrases, PINs, grouped recovery codes, entropy helpers, prefix validation.
- Web page: passphrase and PIN tabs, entropy meter, inline errors.
