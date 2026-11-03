<p align="center">
  <a href="https://github.com/aelena/yapg/actions/workflows/ci.yml"><img src="https://github.com/aelena/yapg/actions/workflows/ci.yml/badge.svg" alt="CI" /></a>
  <img src="https://img.shields.io/badge/python-%3E%3D3.12-3776AB?logo=python&logoColor=fff" alt="Python >= 3.12" />
  <img src="https://img.shields.io/badge/cli-typer-009688" alt="CLI: Typer" />
  <img src="https://img.shields.io/badge/api-Sanic-ff69b4?logo=python&logoColor=fff" alt="API: Sanic" />
  <img src="https://img.shields.io/badge/web-vanilla%20JS-F7DF1E?logo=javascript&logoColor=000" alt="Web: Vanilla JS" />
  <img src="https://img.shields.io/badge/crypto-secrets%20%2F%20Web%20Crypto-blueviolet" alt="Crypto: secrets / Web Crypto" />
  <img src="https://img.shields.io/badge/license-MIT-green" alt="License: MIT" />
</p>

# yapg

**Yet another password generator**, except it is also the key generator, the passphrase generator, the TOTP bootstrapper and the "give me an SSH key / WireGuard pair / JWT secret / htpasswd line" tool you otherwise reach for five different programs to get.

One set of cryptographically secure generators, three ways in:

| | What | Needs |
|---|---|---|
| `keygen` (alias `yapg`) | A CLI you install once and keep | Python 3.12+, `typer` |
| `keygen serve` | A stateless localhost REST API | the `[api]` extra |
| [aelena.com/yapg](https://aelena.com/yapg/) or `web/` | A single static page, works offline, nothing leaves the browser | nothing |

Every random byte comes from the operating system's CSPRNG: Python's [`secrets`](https://docs.python.org/3/library/secrets.html) on the command line, [`crypto.getRandomValues()`](https://developer.mozilla.org/en-US/docs/Web/API/Crypto/getRandomValues) in the browser. Nothing is logged, stored or sent anywhere, with one opt-in exception: `keygen check --hibp` sends five hex characters of a SHA-1 to Have I Been Pwned.

---

## Install

```bash
# everything, as a global tool (recommended)
uv tool install "yapg[all] @ git+https://github.com/aelena/yapg"

# from a checkout
uv tool install --editable ".[all]"

# or plain pip, into any environment
pip install "yapg[all] @ git+https://github.com/aelena/yapg"
```

Extras, if you want less: `[api]` adds Sanic, `[infra]` adds `cryptography` and `bcrypt` for `ssh`, `wireguard` and `htpasswd`, `[qr]` adds the ASCII QR code for `totp`. The core commands have no dependency beyond Typer.

Both `keygen` and `yapg` end up on your PATH and are the same program.

---

## Commands

```
keygen key            Opaque API keys / tokens
keygen password       Random passwords with at least one character from every enabled class
keygen passphrase     Diceware passphrases, English / Spanish / German
keygen pronounceable  Nonsense words you can read out loud
keygen pin            Numeric PINs
keygen recovery       GitHub-style one-time recovery codes
keygen preset         Named presets (stripe, github, db, wifi, vault, ...), yours included
keygen check          Score a password or passphrase you already have
keygen totp new       A TOTP secret with its otpauth:// URI and QR code
keygen totp code      The current code for a TOTP secret
keygen ssh            An ed25519 SSH key pair
keygen wireguard      A WireGuard key pair (+ preshared key)
keygen jwt-secret     An HMAC signing secret
keygen htpasswd       A bcrypt basic-auth line
keygen selftest       Chi-squared uniformity checks over every generator
keygen serve          The REST API
keygen web            The static page on localhost
keygen version
```

Every generator takes `-n/--count` (1 to 500), `-o/--out FILE`, `-c/--copy` (clipboard) and `--json`. Values go to stdout one per line so they pipe cleanly; entropy, "copied", "wrote N to file" go to stderr.

### Keys

```bash
$ keygen key
Nf3S1x4aqS-6rYbp3yz2_hMVl6o9vPZpdTkZWFR9

$ keygen key -f hex -l 64
1f6b0c3e9a7d4b2e8c5f0a1d3e6b9c2f4a7d0e3b6c9f2a5d8e1b4c7f0a3d6e9b

$ keygen key -f alnum -l 24 -p sk_live_ -n 3        # bodies shortened here
sk_live_Qm8vT2xLp9Zr4Wn...
sk_live_7Fg2KjN5tRw8XqL...
sk_live_Bz4Yn9Wk2Tq7Lx1...

$ keygen key -f uuid --json
{
  "keys": ["3f2a9c1e-7b4d-4e8a-9c2f-1a6b3d5e7f90"],
  "count": 1,
  "format": "uuid"
}
```

Formats: `hex`, `base64url` (default), `alnum`, `uuid` (v4). Length counts characters after the prefix. Prefixes are limited to 64 printable, non-whitespace characters.

### Passwords

```bash
$ keygen password
k7$Vq2!mZp9@Lw4#Rt8x

$ keygen password -l 32 --no-symbols -x -e      # no symbols, no I l 1 O 0, show entropy
Hx7kQm3NpW9vRt2YbJ4cZf8gKd6sLn5a
entropy: 186.4 bits

$ keygen password -n 50 -o passwords.txt
wrote 50 to passwords.txt

$ keygen password --json -l 16
{
  "passwords": ["p4K$mN9!xQ2@vL7w"],
  "count": 1,
  "length": 16,
  "upper": true, "lower": true, "digits": true, "symbols": true,
  "exclude_ambiguous": false,
  "entropy_bits": 104.9
}
```

Toggles: `--no-upper`, `--no-lower`, `--no-digits`, `--no-symbols`, `-x/--exclude-ambiguous`. Every enabled class is guaranteed at least once; the rest of the characters are uniform over the combined alphabet and the whole thing is Fisher-Yates shuffled.

### Passphrases

```bash
$ keygen passphrase
surpass-shredding-clanking-saline-direction-unsavory

$ keygen passphrase -w 5 -s " " -C -d          # five words, spaces, Title Case, one digit
Banana Salt Rewrap Retail3 Update

$ keygen passphrase -L es -w 4
almohada-tortuga-nevera-bosque

$ keygen passphrase -L de -w 4 -e
klinke-wolke-fahrrad-segeln
entropy: 51.7 bits
```

Three bundled 7776-word Diceware lists, 12.9 bits per word: the EFF large list (`en`), dadoware-bonito-es (`es`), dys2p wordlists-de (`de`). Sources and licences are in [src/keygen/data/WORDLISTS.md](src/keygen/data/WORDLISTS.md). `--capitalize` and `--digit` satisfy composition rules; they add negligible entropy.

### Pronounceable

```bash
$ keygen pronounceable
trobaklipuston

$ keygen pronounceable -s 3 -C -n 3 -e
Kefrilon
Bozustai
Grunopla
entropy: 34.7 bits
```

Consonant-vowel-coda syllables, about 11.6 bits each. For the password you have to say over the phone.

### PINs and recovery codes

```bash
$ keygen pin
481926

$ keygen pin -l 8 -n 3
20471139
88305162
57712904

$ keygen recovery
# Recovery codes. Keep these somewhere safe; each one works once.

t6zut-6egw7
nudhv-x9b42
...   (16 by default)

$ keygen recovery -n 4 -l 12 -g 3 -e
h67z-bjmn-nc9c
7p2k-xw4r-tf8d
mq3s-vz9b-yk5n
c8dw-rn2h-gj6p
entropy: 59.4 bits
```

Recovery codes use the alphabet `abcdefghjkmnpqrstuvwxyz23456789`: no `0 O 1 I l`, so they survive being read off paper.

### Presets

```bash
$ keygen preset
stripe         key           format='alnum', length=24, prefix='sk_live_'  Stripe-style secret key
stripe-test    key           format='alnum', length=24, prefix='sk_test_'  Stripe-style test key
github         key           format='alnum', length=36, prefix='ghp_'  GitHub-style personal access token
api-hex        key           format='hex', length=64  256-bit hex token
api-urlsafe    key           format='base64url', length=43  256-bit base64url token
session        key           format='base64url', length=32  Session cookie value
db             password      length=32, symbols=False  Database password: 32 alphanumerics, safe in connection strings
wifi           passphrase    words=4, separator='-', capitalize=True  WPA passphrase a guest can type
vault          passphrase    words=7, separator=' '  Master passphrase, about 90 bits
phone          pronounceable syllables=4, capitalize=True  Temporary password you can read out loud
pin            pin           length=6  Six-digit PIN
2fa-backup     recovery      length=10, groups=2  Recovery code, xxxxx-xxxxx

$ keygen preset db
Hx7kQm3NpW9vRt2YbJ4cZf8gKd6sLn5a

$ keygen preset github -n 2
ghp_Qm8vT2xLp9Zr4WnK1cHbYd3e...
ghp_Bz4Yn9Wk2Tq7Lx1Mr8Jv5Pd3...
```

Your own presets live in `~/.config/keygen/presets.toml` (or wherever `$KEYGEN_PRESETS` points) and override built-ins by name:

```toml
[stripe]
command = "key"
format = "alnum"
length = 24
prefix = "sk_live_"

[vault]
command = "passphrase"
words = 7
lang = "es"
separator = " "
```

`command` is any of `key`, `password`, `passphrase`, `pronounceable`, `pin`, `recovery`; the other keys are that command's options.

### Check

```bash
$ keygen check 'correct-horse-battery-staple'
length   28
classes  lower, symbols
entropy  51.7 bits (fair)
looks like 4 words from the en list: 51.7 bits

$ keygen check 'Password1234!!!'
length   15
classes  upper, lower, digits, symbols
entropy  53.3 bits (fair)
warning  a character repeated three or more times in a row
warning  keyboard/sequence run '1234'
warning  contains a very common password word

$ echo 'qwerty12' | keygen check; echo "exit $?"
length   8
classes  lower, digits
entropy  26.4 bits (weak)
warning  shorter than 12 characters
warning  keyboard/sequence run 'qwer'
exit 1

$ keygen check --hibp 'hunter2'
...
hibp     seen 17,043 times in breaches
```

The estimate is `length × log2(pool)`, capped at `words × 12.9` when every token is in one of the bundled wordlists, minus 15 bits per pattern warning. It is a heuristic, not zxcvbn: its job is to keep obvious junk from scoring "fair". Exit code 1 means weak or breached, so it works in scripts. `--hibp` uses the [k-anonymity range API](https://haveibeenpwned.com/API/v3#SearchingPwnedPasswordsByRange): only the first five hex characters of the SHA-1 leave your machine.

### TOTP

```bash
$ keygen totp new --issuer "My App" --account ana@example.com
secret   JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP
uri      otpauth://totp/My%20App%3Aana%40example.com?secret=JBSW...&digits=6&period=30&algorithm=SHA1&issuer=My+App
current  492039  (17s left)
█▀▀▀▀▀█ ▄▀ ▀▄█ █▀▀▀▀▀█
█ ███ █ ▀█▄▀▄  █ ███ █     (scan with any authenticator app)
...

$ keygen totp code JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP
492039
17s left

$ keygen totp new --no-qr --json --digits 8 --algorithm SHA256
{ "secret": "...", "uri": "otpauth://totp/...", "current_code": "48213907", ... }
```

RFC 6238, verified against the RFC's own test vectors. The QR code needs the `[qr]` extra; without it the URI is still printed. `totp code` is handy for testing a login flow you are building, or as the authenticator of last resort.

### SSH, WireGuard, JWT, htpasswd

```bash
$ keygen ssh -C ana@laptop -o ~/.ssh/id_ed25519_new
wrote ~/.ssh/id_ed25519_new and ~/.ssh/id_ed25519_new.pub
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIK... ana@laptop

$ keygen ssh                      # no -o: both keys to stdout
-----BEGIN OPENSSH PRIVATE KEY-----
...
-----END OPENSSH PRIVATE KEY-----
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIK...

$ keygen wireguard --preshared
PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
PresharedKey = FpCyhws9cxwWoV4xELtfJvjJN+zQVRPISllRWgeopVE=

$ keygen jwt-secret                # 256 bits, base64url
k3rT9xQ2mZ8vLp5wNb7cYf4dHs6gJa1eRu0iXo2tVq

$ keygen jwt-secret -b 512 -E hex
7f3a...  (128 hex chars)

$ keygen htpasswd ana              # generates the password and prints it to stderr
password: Hx7kQm3NpW9vRt2YbJ4cZf8g
ana:$2y$12$Qm8vT2xLp9Zr4WnK1cHbYeB3e7Fg2KjN5tRw8XqLm3ZpVc6HsN7uK

$ keygen htpasswd ana --prompt -o .htpasswd    # asks twice, appends the line
$ keygen htpasswd ana -P 's3cret' --rounds 10
```

`ssh` refuses to overwrite an existing file and writes the private key with mode 0600 on POSIX. `wireguard` prints lines you paste straight into `[Interface]` and `[Peer]`. `htpasswd` emits bcrypt with the `$2y$` prefix Apache documents, which nginx, Caddy and Traefik accept too. These four need the `[infra]` extra and are deliberately not exposed by the REST API.

### Self-test

```bash
$ keygen selftest
ok   hex                chi2 p=0.412 over 25600 symbols
ok   base64url          chi2 p=0.187 over 25600 symbols
ok   alnum              chi2 p=0.903 over 25600 symbols
ok   recovery           chi2 p=0.655 over 12800 symbols
ok   pin                chi2 p=0.271 over 12800 symbols
ok   password           chi2 p=0.544 over 25600 symbols
ok   password classes   one of each class at length 4
ok   wordlist en        7776 words, 7776 unique
ok   wordlist es        7776 words, 7776 unique
ok   wordlist de        7776 words, 7776 unique
ok   passphrase draw    chi2 p=0.731 over 16 buckets
ok   uuid v4            version/variant bits, no repeats
12/12 passed
```

A chi-squared goodness-of-fit test per alphabet plus the structural guarantees. It cannot prove randomness; it catches the bugs that matter (a truncated alphabet, modulo bias, a wordlist that lost a line). CI runs it on every push.

---

## REST API

```bash
keygen serve                      # http://127.0.0.1:8000
```

All endpoints are `GET`, return JSON, accept `count`, and accept `download=1` to receive a `text/plain` attachment instead. Bad parameters return `400` with a message.

| Endpoint | Parameters |
|---|---|
| `/health` | |
| `/api-key` | `format`, `length`, `prefix` |
| `/password` | `length`, `upper`, `lower`, `digits`, `symbols`, `exclude_ambiguous` (0/1) |
| `/passphrase` | `words`, `sep`, `lang` (en/es/de), `capitalize`, `digit` |
| `/pronounceable` | `syllables`, `capitalize` |
| `/pin` | `length` |
| `/recovery-codes` | `length`, `groups` |

```bash
$ curl "http://localhost:8000/api-key?prefix=sk_live_&length=32"
{"keys":["sk_live_aBcDeFgHiJkLmNoP..."],"count":1,"format":"base64url"}

$ curl "http://localhost:8000/passphrase?words=5&lang=es&sep=%20"
{"passphrases":["tortuga nevera bosque almohada faro"],"count":1,"words":5,"lang":"es","entropy_bits":64.6}

$ curl -O -J "http://localhost:8000/recovery-codes?download=1"
```

The API binds to localhost, has no authentication and no rate limiting. It is a local convenience, not a service to expose. Key material (SSH, WireGuard, htpasswd, TOTP) is CLI-only on purpose.

---

## Web page

[aelena.com/yapg](https://aelena.com/yapg/), or open `web/index.html`, or `keygen web`. Five tabs (API key, password, passphrase in three languages, PIN, recovery), copy and download buttons, an entropy meter. No build step, no network access; the wordlists ship inside the page.

The page reimplements the generators in `web/app.js` by hand; it does not call the API. Keep it in step with `src/keygen/core.py`.

---

## How it works

**Randomness.** `secrets` in Python; `crypto.getRandomValues()` in the browser with rejection sampling in `randInt`, so there is no modulo bias.

**Passwords.** One guaranteed character per enabled class, the rest uniform over the combined alphabet, then a Fisher-Yates shuffle with the CSPRNG. Reported entropy is `length × log2(pool)`, an upper bound; the one-of-each rule costs a few bits at short lengths.

**Passphrases.** Diceware: 7776 words, 12.925 bits each, six words is 77.5 bits.

**Recovery codes.** 31-symbol alphabet, 4.95 bits per symbol, ten symbols is 49.5 bits. Enough for a code that is single-use and rate-limited.

**Limits.**

| | Min | Max | Default |
|---|---|---|---|
| Key length | 8 | 256 | 40 |
| Password length | 4 | 128 | 20 |
| Passphrase words | 3 | 20 | 6 |
| Pronounceable syllables | 2 | 16 | 4 |
| PIN digits | 4 | 32 | 6 |
| Recovery code length | 6 | 32 | 10 |
| Batch (`count`) | 1 | 500 | 1 (16 for recovery) |
| Prefix | | 64 chars, printable, no whitespace | |

---

## Project layout

```
yapg/
├── src/keygen/
│   ├── core.py          the generators; pure, no I/O
│   ├── check.py         scoring + HIBP lookup
│   ├── totp.py          RFC 6238
│   ├── infra.py         ssh, wireguard, jwt-secret, htpasswd
│   ├── presets.py       built-in + user presets
│   ├── selftest.py      chi-squared checks
│   ├── cli.py           typer app  -> keygen / yapg
│   ├── server.py        sanic app  -> keygen serve
│   └── data/            wordlists + licences
├── web/                 static page, deployed to GitHub Pages
├── api/server.py        compatibility shim
├── tests/               pytest
└── .github/workflows/   CI (ubuntu + windows, 3.12 + 3.13) and Pages
```

## Development

```bash
uv venv && uv pip install -e ".[dev]"      # add --link-mode=copy on OneDrive-synced folders
pytest -p no:warnings
ruff check src tests
keygen selftest
```

## Licence

[MIT](LICENSE). Wordlists: EFF (CC-BY 3.0), dadoware-bonito-es (GFDL 1.3), dys2p (CC0); see [WORDLISTS.md](src/keygen/data/WORDLISTS.md).
