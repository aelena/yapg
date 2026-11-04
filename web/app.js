// Cryptographically secure generator using window.crypto.getRandomValues.
// No network calls: everything runs locally in your browser.
// Mirrors src/keygen/core.py; keep the two in step.

const ALNUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const LOWER = "abcdefghijklmnopqrstuvwxyz";
const DIGITS = "0123456789";
const SYMBOLS = "!@#$%^&*()-_=+[]{};:,.<>?/";
const AMBIGUOUS = "Il1O0";
// Recovery codes use a Crockford-ish lowercase alphabet (no ambiguous chars).
const RECOVERY_ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789";
const MAX_BATCH = 500;

// --- primitives ------------------------------------------------------------

// Unbiased random integer in [0, max) using rejection sampling.
function randInt(max) {
  const limit = Math.floor(0x100000000 / max) * max;
  const buf = new Uint32Array(1);
  let x;
  do {
    crypto.getRandomValues(buf);
    x = buf[0];
  } while (x >= limit);
  return x % max;
}

const pick = (alphabet) => alphabet[randInt(alphabet.length)];
const randomFromAlphabet = (alphabet, length) => Array.from({ length }, () => pick(alphabet)).join("");

function randomBytes(n) {
  const buf = new Uint8Array(n);
  crypto.getRandomValues(buf);
  return buf;
}

const toHex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");

function toBase64Url(bytes) {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function uuidv4() {
  if (crypto.randomUUID) return crypto.randomUUID();
  const b = randomBytes(16);
  b[6] = (b[6] & 0x0f) | 0x40;
  b[8] = (b[8] & 0x3f) | 0x80;
  const h = toHex(b);
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

function shuffle(chars) {
  for (let i = chars.length - 1; i > 0; i--) {
    const j = randInt(i + 1);
    [chars[i], chars[j]] = [chars[j], chars[i]];
  }
  return chars;
}

// --- generators -------------------------------------------------------------

function generateApiKey({ format, length, prefix }) {
  const body = {
    hex: () => toHex(randomBytes(Math.ceil(length / 2))).slice(0, length),
    base64url: () => toBase64Url(randomBytes(Math.ceil((length * 3) / 4) + 2)).slice(0, length),
    alnum: () => randomFromAlphabet(ALNUM, length),
    uuid: () => uuidv4(),
  }[format];
  if (!body) throw new Error(`Unknown format: ${format}`);
  return (prefix || "") + body();
}

// The non-empty character classes a password must draw from.
function charsets(opts) {
  const strip = (s) => (opts.excludeAmbiguous ? s.replace(/[Il1O0]/g, "") : s);
  const sets = [
    [opts.upper, UPPER],
    [opts.lower, LOWER],
    [opts.digits, DIGITS],
    [opts.symbols, SYMBOLS],
  ]
    .filter(([on]) => on)
    .map(([, s]) => strip(s))
    .filter(Boolean);
  if (!sets.length) throw new Error("Select at least one character set.");
  return sets;
}

// At least one from every selected class, the rest uniform, then shuffled.
function generatePassword(opts) {
  const sets = charsets(opts);
  const alphabet = sets.join("");
  const length = Math.max(opts.length, sets.length);
  const chars = sets.map(pick);
  while (chars.length < length) chars.push(pick(alphabet));
  return shuffle(chars).join("");
}

const passwordEntropyBits = (opts) => opts.length * Math.log2(charsets(opts).join("").length);

// e.g. length=10, groups=2: "a1b2c-d3e4f"
function generateRecoveryCode(length, groups = 2) {
  const raw = randomFromAlphabet(RECOVERY_ALPHABET, length);
  const size = Math.ceil(length / groups);
  const parts = [];
  for (let i = 0; i < length; i += size) parts.push(raw.slice(i, i + size));
  return parts.join("-");
}

const recoveryEntropyBits = (length) => length * Math.log2(RECOVERY_ALPHABET.length);

// Diceware from a 7776-word list (web/wordlist_<lang>.js). ~12.9 bits per word.
function generatePassphrase({ words, separator, capitalize, digit, lang }) {
  const list = WORDLISTS[lang] || WORDLISTS.en;
  let picks = Array.from({ length: words }, () => pick(list));
  if (capitalize) picks = picks.map((w) => w[0].toUpperCase() + w.slice(1));
  if (digit) {
    const i = randInt(words);
    picks[i] += String(randInt(10));
  }
  return picks.join(separator);
}

const passphraseEntropyBits = (words, lang) => words * Math.log2((WORDLISTS[lang] || WORDLISTS.en).length);

// Nonsense word from onset+vowel+coda syllables. Mirrors core.pronounceable.
const ONSETS = ["b", "d", "f", "g", "k", "l", "m", "n", "p", "r", "s", "t", "v", "z",
  "br", "dr", "fr", "gr", "kr", "pr", "tr", "bl", "fl", "gl", "kl", "pl", "st", "sk", "sp"];
const VOWELS = ["a", "e", "i", "o", "u", "ai", "au", "ei", "ou", "oa", "ia", "io"];
const CODAS = ["", "", "", "n", "s", "r", "l", "t", "m", "k"];

function generatePronounceable({ syllables, capitalize }) {
  const word = Array.from({ length: syllables }, () => pick(ONSETS) + pick(VOWELS) + pick(CODAS)).join("");
  return capitalize ? word[0].toUpperCase() + word.slice(1) : word;
}

function pronounceableEntropyBits(syllables) {
  // CODAS has duplicates on purpose: weight distinct outcomes by probability.
  const counts = {};
  for (const c of CODAS) counts[c] = (counts[c] || 0) + 1;
  const codaBits = -Object.values(counts).reduce((sum, n) => {
    const p = n / CODAS.length;
    return sum + p * Math.log2(p);
  }, 0);
  return syllables * (Math.log2(ONSETS.length) + Math.log2(VOWELS.length) + codaBits);
}

const generatePin = (length) => randomFromAlphabet(DIGITS, length);

function apiKeyEntropyBits({ format, length }) {
  if (format === "uuid") return 122;
  return length * Math.log2({ hex: 16, base64url: 64, alnum: ALNUM.length }[format]);
}

// --- presets -----------------------------------------------------------------
// Mirrors presets.BUILTIN in src/keygen/presets.py. The page has no user TOML.

const PRESETS = {
  "stripe": { command: "key", format: "alnum", length: 24, prefix: "sk_live_", doc: "Stripe-style secret key" },
  "stripe-test": { command: "key", format: "alnum", length: 24, prefix: "sk_test_", doc: "Stripe-style test key" },
  "github": { command: "key", format: "alnum", length: 36, prefix: "ghp_", doc: "GitHub-style personal access token" },
  "api-hex": { command: "key", format: "hex", length: 64, doc: "256-bit hex token" },
  "api-urlsafe": { command: "key", format: "base64url", length: 43, doc: "256-bit base64url token" },
  "session": { command: "key", format: "base64url", length: 32, doc: "Session cookie value" },
  "db": { command: "password", length: 32, symbols: false, doc: "Database password: 32 alphanumerics, safe in connection strings" },
  "wifi": { command: "passphrase", words: 4, separator: "-", capitalize: true, doc: "WPA passphrase a guest can type" },
  "vault": { command: "passphrase", words: 7, separator: " ", doc: "Master passphrase, about 90 bits" },
  "phone": { command: "pronounceable", syllables: 4, capitalize: true, doc: "Temporary password you can read out loud" },
  "pin": { command: "pin", length: 6, doc: "Six-digit PIN" },
  "2fa-backup": { command: "recovery", length: 10, groups: 2, doc: "Recovery code, xxxxx-xxxxx" },
};

// Fill in each command's defaults so a preset reads like its CLI call.
const PRESET_COMMANDS = {
  key: {
    opts: (s) => ({ format: s.format || "base64url", length: s.length || 40, prefix: s.prefix || "" }),
    gen: generateApiKey,
    entropy: apiKeyEntropyBits,
  },
  password: {
    opts: (s) => ({
      length: s.length || 20,
      upper: s.upper !== false, lower: s.lower !== false, digits: s.digits !== false, symbols: s.symbols !== false,
      excludeAmbiguous: s.exclude_ambiguous === true,
    }),
    gen: generatePassword,
    entropy: passwordEntropyBits,
  },
  passphrase: {
    opts: (s) => ({ words: s.words || 6, separator: s.separator ?? "-", capitalize: !!s.capitalize, digit: !!s.digit, lang: s.lang || "en" }),
    gen: generatePassphrase,
    entropy: (o) => passphraseEntropyBits(o.words, o.lang),
  },
  pronounceable: {
    opts: (s) => ({ syllables: s.syllables || 4, capitalize: !!s.capitalize }),
    gen: generatePronounceable,
    entropy: (o) => pronounceableEntropyBits(o.syllables),
  },
  pin: {
    opts: (s) => ({ length: s.length || 6 }),
    gen: (o) => generatePin(o.length),
    entropy: (o) => o.length * Math.log2(10),
  },
  recovery: {
    opts: (s) => ({ length: s.length || 10, groups: s.groups || 2 }),
    gen: (o) => generateRecoveryCode(o.length, o.groups),
    entropy: (o) => recoveryEntropyBits(o.length),
  },
};

function presetSpec(name) {
  const spec = PRESETS[name];
  if (!spec) throw new Error(`Unknown preset: ${name}`);
  const cmd = PRESET_COMMANDS[spec.command];
  return { cmd, opts: cmd.opts(spec) };
}

function describePreset(name) {
  const spec = PRESETS[name];
  const args = Object.entries(spec)
    .filter(([k]) => k !== "command" && k !== "doc")
    .map(([k, v]) => `${k}=${JSON.stringify(v)}`)
    .join(" ");
  return `keygen ${spec.command} ${args}`;
}

// --- helpers --------------------------------------------------------------

function clamp(n, lo, hi, fallback) {
  if (!Number.isFinite(n)) return fallback;
  return Math.min(hi, Math.max(lo, Math.floor(n)));
}

const $ = (id) => document.getElementById(id);
const num = (id, lo, hi, fallback) => clamp(parseInt($(id).value, 10), lo, hi, fallback);

function downloadText(filename, text) {
  const blob = new Blob([text], { type: "text/plain;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = Object.assign(document.createElement("a"), { href: url, download: filename });
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function timestamp() {
  const d = new Date();
  const pad = (n) => String(n).padStart(2, "0");
  return `${d.getFullYear()}${pad(d.getMonth() + 1)}${pad(d.getDate())}-${pad(d.getHours())}${pad(d.getMinutes())}${pad(d.getSeconds())}`;
}

function strengthLabel(bits) {
  if (bits < 40) return "weak";
  if (bits < 64) return "fair";
  if (bits < 96) return "strong";
  return "very strong";
}

// --- panels -------------------------------------------------------------------
// Each panel: read options from the DOM, generate one item, optionally report entropy.

const RECOVERY_HEADER = "# Recovery codes. Keep these somewhere safe; each one works once.\n\n";

const PANELS = {
  api: {
    stem: "api-keys",
    read: () => ({
      format: $("api-format").value,
      length: num("api-length", 8, 256, 40),
      prefix: $("api-prefix").value.trim(),
    }),
    gen: generateApiKey,
  },
  pwd: {
    stem: "passwords",
    read: () => ({
      length: num("pwd-length", 4, 128, 20),
      upper: $("pwd-upper").checked,
      lower: $("pwd-lower").checked,
      digits: $("pwd-digits").checked,
      symbols: $("pwd-symbols").checked,
      excludeAmbiguous: $("pwd-ambig").checked,
    }),
    gen: generatePassword,
    entropy: passwordEntropyBits,
  },
  phr: {
    stem: "passphrases",
    read: () => ({
      words: num("phr-words", 3, 20, 6),
      separator: $("phr-sep").value || "-",
      lang: $("phr-lang").value,
      capitalize: $("phr-cap").checked,
      digit: $("phr-digit").checked,
    }),
    gen: generatePassphrase,
    entropy: (o) => passphraseEntropyBits(o.words, o.lang),
  },
  pro: {
    stem: "pronounceable",
    read: () => ({ syllables: num("pro-syllables", 2, 16, 4), capitalize: $("pro-cap").checked }),
    gen: generatePronounceable,
    entropy: (o) => pronounceableEntropyBits(o.syllables),
  },
  pin: {
    stem: "pins",
    read: () => ({ length: num("pin-length", 4, 32, 6) }),
    gen: (o) => generatePin(o.length),
    entropy: (o) => o.length * Math.log2(10),
  },
  rec: {
    stem: "recovery-codes",
    header: RECOVERY_HEADER,
    read: () => ({ length: num("rec-length", 6, 32, 10), groups: num("rec-groups", 1, 4, 2) }),
    gen: (o) => generateRecoveryCode(o.length, o.groups),
    entropy: (o) => recoveryEntropyBits(o.length),
  },
  pre: {
    stem: "preset",
    read: () => presetSpec($("pre-name").value),
    gen: ({ cmd, opts }) => cmd.gen(opts),
    entropy: ({ cmd, opts }) => cmd.entropy(opts),
  },
};

const lastBatch = {};

function showError(key, message) {
  const el = $(`${key}-error`);
  el.textContent = message || "";
  el.classList.toggle("hidden", !message);
}

function updateStrength(key, bits) {
  const bar = document.querySelector(`#${key}-strength span`);
  const meta = $(`${key}-meta`);
  if (!bar) return;
  bar.style.width = Math.min(100, (bits / 128) * 100) + "%";
  bar.style.background = bits < 40 ? "var(--bad)" : bits < 64 ? "var(--warn)" : "var(--good)";
  meta.textContent = `${bits.toFixed(1)} bits of entropy (${strengthLabel(bits)})`;
}

function generate(key) {
  const panel = PANELS[key];
  const count = num(`${key}-count`, 1, MAX_BATCH, 1);
  try {
    const opts = panel.read();
    const items = Array.from({ length: count }, () => panel.gen(opts));
    const out = $(`${key}-output`);
    out.value = items.join("\n");
    out.rows = Math.min(12, Math.max(1, items.length));
    lastBatch[key] = items;
    $(`${key}-download`).disabled = false;
    showError(key, "");
    if (panel.entropy) updateStrength(key, panel.entropy(opts));
  } catch (e) {
    $(`${key}-output`).value = "";
    showError(key, e.message);
  }
}

for (const key of Object.keys(PANELS)) {
  $(`${key}-generate`).addEventListener("click", () => generate(key));
  $(`${key}-download`).addEventListener("click", () => {
    const items = lastBatch[key];
    if (!items) return;
    downloadText(`${PANELS[key].stem}-${timestamp()}.txt`, (PANELS[key].header || "") + items.join("\n") + "\n");
  });
}

// Tabs
document.querySelectorAll(".tab").forEach((tab) => {
  tab.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach((t) => t.classList.toggle("active", t === tab));
    document.querySelectorAll(".panel").forEach((p) => p.classList.toggle("hidden", p.id !== "panel-" + tab.dataset.tab));
  });
});

// Copy buttons
document.querySelectorAll(".copy").forEach((btn) => {
  btn.addEventListener("click", async () => {
    const target = $(btn.dataset.target);
    if (!target.value) return;
    try {
      await navigator.clipboard.writeText(target.value);
    } catch {
      target.select();
      document.execCommand("copy");
    }
    btn.classList.add("copied");
    btn.textContent = "Copied";
    setTimeout(() => {
      btn.classList.remove("copied");
      btn.textContent = "Copy";
    }, 1200);
  });
});

// Preset picker
{
  const sel = $("pre-name");
  for (const [name, spec] of Object.entries(PRESETS)) {
    sel.appendChild(Object.assign(document.createElement("option"), { value: name, textContent: `${name}: ${spec.doc}` }));
  }
  const show = () => ($("pre-desc").textContent = describePreset(sel.value));
  sel.addEventListener("change", show);
  show();
}

// Generate one on load.
generate("api");
