<p align="center">
  <img src="https://img.shields.io/badge/python-%3E%3D3.12-3776AB?logo=python&logoColor=fff" alt="Python >= 3.12" />
  <img src="https://img.shields.io/badge/cli-typer-009688" alt="CLI: Typer" />
  <img src="https://img.shields.io/badge/api-Sanic-ff69b4?logo=python&logoColor=fff" alt="API: Sanic" />
  <img src="https://img.shields.io/badge/web-vanilla%20JS-F7DF1E?logo=javascript&logoColor=000" alt="Web: Vanilla JS" />
  <img src="https://img.shields.io/badge/crypto-secrets%20%2F%20Web%20Crypto-blueviolet" alt="Crypto: secrets / Web Crypto" />
  <img src="https://img.shields.io/badge/tests-pytest-success" alt="Tests: pytest" />
  <img src="https://img.shields.io/badge/license-MIT-green" alt="License: MIT" />
</p>

# key-generator

Cryptographically secure **API keys**, **passwords**, **Diceware passphrases**, **PINs** and **GitHub-style recovery codes**. One set of generators, three skins:

| Skin | What it is | Dependencies |
|---|---|---|
| `keygen` | A CLI you install once and keep | `typer` |
| `keygen serve` | A stateless Sanic REST API | `sanic` (optional extra) |
| `web/` | A single static page, works offline, nothing leaves the browser | none |

The Python generators live in `src/keygen/core.py`. The web page reimplements the same algorithms in `web/app.js`; the two are kept in step by hand.

---

## Install the CLI

```bash
# from the repo root, as a global tool (recommended)
uv tool install --editable . --with sanic      # drop --with sanic if you never want the API

# or into any environment
pip install -e ".[api]"
```

Both put a `keygen` executable on your PATH.

## Use it

```bash
keygen key                                  # one base64url token, 40 chars
keygen key -f hex -l 64 -p sk_live_ -n 10   # ten prefixed hex keys
keygen key -f uuid --json                   # UUID v4, JSON output

keygen password                             # 20 chars, all four classes
keygen password -l 32 --no-symbols -x -e    # no symbols, no ambiguous chars, show entropy
keygen password -n 50 -o passwords.txt      # batch to a file

keygen passphrase                           # six EFF words: correct-horse-battery-...
keygen passphrase -w 5 -s " " -C -d         # five words, spaces, Title Case, one digit

keygen pin -l 8
keygen recovery                             # 16 codes, xxxxx-xxxxx
keygen recovery -n 10 -l 12 -g 3            # 10 codes, xxxx-xxxx-xxxx

keygen key -c                               # any command: -c copies to the clipboard
keygen serve --port 8000                    # the REST API
keygen web                                  # the static page on http://127.0.0.1:3000
```

Every generator command accepts `-n/--count` (1 to 500), `-o/--out FILE`, `-c/--copy` and `--json`. Values go to stdout, one per line, so they pipe cleanly; everything else (entropy, "copied", "wrote N to ...") goes to stderr.

---

## Project structure

```
key-generator/
├── src/keygen/
│   ├── core.py                   # the generators; pure, no I/O
│   ├── cli.py                    # typer app  -> `keygen`
│   ├── server.py                 # sanic app  -> `keygen serve`
│   └── data/eff_large_wordlist.txt
├── web/
│   ├── index.html                # single-page UI
│   ├── app.js                    # same algorithms in vanilla JS
│   ├── wordlist.js               # the EFF list, generated from data/
│   └── styles.css
├── api/server.py                 # compatibility shim: `python api/server.py`
├── tests/                        # pytest: core properties, CLI, API
└── pyproject.toml
```

---

## Approach

### Randomness

| Layer | Source |
|---|---|
| Python | [`secrets`](https://docs.python.org/3/library/secrets.html), backed by the OS CSPRNG |
| Browser | [`crypto.getRandomValues()`](https://developer.mozilla.org/en-US/docs/Web/API/Crypto/getRandomValues) with rejection sampling in `randInt`, so no modulo bias |

### Passwords

Always contain at least one character from each selected class (uppercase, lowercase, digits, symbols). Guaranteed characters are placed first, the rest are drawn uniformly from the combined alphabet, and the result is Fisher-Yates shuffled with the CSPRNG. The reported entropy is `length × log2(pool)`, an upper bound: the one-of-each rule costs a few bits at short lengths.

### Passphrases

Diceware from the [EFF large wordlist](https://www.eff.org/dice): 7776 words, 12.9 bits each, so six words is about 77 bits. `--capitalize` and `--digit` exist to satisfy composition rules, not to add meaningful entropy.

### Recovery codes

Modelled on GitHub's 2FA backup codes. The alphabet `abcdefghjkmnpqrstuvwxyz23456789` drops the visually ambiguous `0 O 1 I l`, which cuts transcription errors. Ten symbols is about 50 bits, enough for a code that is rate-limited and single-use.

### Limits

| | Min | Max | Default |
|---|---|---|---|
| Key length | 8 | 256 | 40 |
| Password length | 4 | 128 | 20 |
| Passphrase words | 3 | 20 | 6 |
| PIN digits | 4 | 32 | 6 |
| Recovery code length | 6 | 32 | 10 |
| Batch (`count`) | 1 | 500 | 1 (16 for recovery) |
| Prefix | | 64 chars, no whitespace or control characters | |

---

## REST API

```bash
keygen serve                      # http://127.0.0.1:8000
# or: python api/server.py
```

All endpoints are `GET`, return JSON, accept `count`, and accept `download=1` to receive a `text/plain` attachment instead. Bad parameters return `400` with a message.

| Endpoint | Parameters |
|---|---|
| `/health` | |
| `/api-key` | `format` (hex, base64url, alnum, uuid), `length`, `prefix` |
| `/password` | `length`, `upper`, `lower`, `digits`, `symbols`, `exclude_ambiguous` (0/1 each) |
| `/passphrase` | `words`, `sep`, `capitalize`, `digit` |
| `/pin` | `length` |
| `/recovery-codes` | `length`, `groups` |

```bash
curl "http://localhost:8000/api-key?prefix=sk_live_&length=32"
# {"keys":["sk_live_aBcDeFgHiJkLmNoP..."],"count":1,"format":"base64url"}

curl "http://localhost:8000/password?length=24&symbols=0"
# {"passwords":["..."],"count":1,"length":24,"entropy_bits":142.9,"upper":true,...}

curl -O -J "http://localhost:8000/recovery-codes?download=1"
```

The API binds to localhost, has no authentication and no rate limiting. It is a local convenience, not a service to expose.

---

## Web page

Open `web/index.html` in a browser, or run `keygen web`. Five tabs (API key, password, passphrase, PIN, recovery), copy and download buttons, an entropy readout. No build step and no network access.

---

## Development

```bash
uv venv && uv pip install -e ".[dev]"
pytest            # 54 tests
ruff check src tests
```

On OneDrive-synced folders, add `--link-mode=copy` to `uv pip install`.

## License

[MIT](LICENSE). The EFF large wordlist is CC-BY 3.0, © Electronic Frontier Foundation.
