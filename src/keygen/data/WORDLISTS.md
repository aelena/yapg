# Bundled wordlists

All three are Diceware lists: exactly 7776 words, one per line, so a word is 12.925 bits.

| Code | File | Source | Licence |
|---|---|---|---|
| `en` | `wordlist_en.txt` | [EFF large wordlist](https://www.eff.org/dice) (2016), Electronic Frontier Foundation | CC-BY 3.0 |
| `es` | `wordlist_es.txt` | [dadoware-bonito-es](https://github.com/mir123/dadoware-bonito-es), DW-es-bonito.csv | GNU FDL 1.3 (`licenses/GFDL-1.3.txt`) |
| `de` | `wordlist_de.txt` | [dys2p/wordlists-de](https://github.com/dys2p/wordlists-de), de-7776-v1.txt | CC0 1.0 (`licenses/CC0-1.0.txt`), also Unlicense / BSD-3 |

Changes from the sources: the dice numbers were dropped; the Spanish list was lower-cased and
its two multi-word entries ("al menos", "tal vez") joined; the German list is used as published.
Accented characters are kept: they are part of the language and part of the entropy.

`web/wordlist_*.js` are generated from these files and must be regenerated when they change.
