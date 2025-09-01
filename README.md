# vadespamdecode

CLI tool to **decode or inspect** OVH/Vade “spam-cause” headers from email systems.
It understands the **legacy OVH obfuscation** (decodable to human-readable text) and the **newer Vade Base64 container** (`vade1{…}`), which is **inspect-only** (the actual content is encrypted and this tool cannot decrypt it).

---

## Why this exists

* **Legacy headers** like `X-OVH-SPAMCAUSE` (and `X-VR-SPAMCAUSE`) use a tiny obfuscation that can be fully reversed to text such as:

  ```
  Vade Retro 01.394.21 AS+AV+AP+RT Profile: OVH; Bailout: 300; ^ForbiddenHdr (500)
  ```
* **New Vade headers** like `X-Vade-Spamcause` often carry a **Base64-encoded binary blob** that starts with `vade1{…}`. There’s no public spec; this tool **decodes Base64** and gives **metadata + hex previews** to help with triage and escalation.

---

## Features

* **Auto-detect** header type: `legacy`, `vade1` (Base64), `base64` (generic), or `unknown`.
* **Decode legacy** OVH/Vade obfuscation with the **fixed parity-aware algorithm** (no broken variants).
* **Inspect vade1** containers: Base64 decode, entropy, sizes, `{…}` positions, zlib signature hints, hexdump.
* Accepts:

  * **Positional value** (just the header value)
  * `--file` a **single value** or a **full header blob** (folded lines supported)
  * `--eml` an **EML file** (auto-picks the relevant header)
* **JSON output** for scripting.
* Optional `--try-zlib` probes (safe/experimental).

---

## Install

Requires Python 3.8+.

```bash
# clone your repo, then:
python3 vadespamdecode.py -h
```

(You can also mark the script executable: `chmod +x vadespamdecode.py` and run `./vadespamdecode.py`.)

---

## Quick start

### 1) Legacy value (positional)

```bash
python3 vadespamdecode.py "gggruggvucftvghtrhhoucdtuddrfeelg..."
```

### 2) From a headers .txt (auto-detects and unfolds)

```bash
python3 vadespamdecode.py --file headers.txt
```

### 3) From an .eml file

```bash
python3 vadespamdecode.py --eml message.eml
```

### 4) JSON output (for automation)

```bash
python3 vadespamdecode.py --json --file headers.txt
```

### 5) Optional zlib probes on vade1 (experimental)

```bash
python3 vadespamdecode.py --try-zlib --file headers.txt
```

---

## Input types & parsing rules

* **Supported header names** (case-insensitive):

  * Legacy: `X-OVH-SPAMCAUSE`, `X-VR-SPAMCAUSE`
  * New: `X-Vade-Spamcause`
* With `--file`, the tool:

  1. Parses the text as a headers blob (supports **folded** continuation lines that begin with space/tab).
  2. If those known names aren’t found, it falls back to **any header name that contains `spamcause`** and unfolds its value.
  3. If still not found, it tries the first **Base64-ish token**; else uses the whole file content as the value.
* **Do not repeat the header name on continuation lines.** A folded header should look like:

  ```
  X-OVH-SPAMCAUSE: abcdefgh...
   continuation part...
   continuation part...
  ```

---

## Detection & modes

The tool classifies input into one of:

* `legacy` — lowercase letter pairs (even length); decodes to readable text.
* `vade1` — Base64 value whose decoded bytes start with `vade1{`.
* `base64` — Base64 value that doesn’t start with `vade1`.
* `unknown` — none of the above.

> Tip: We check **legacy before base64** so legacy strings (which are alphabetic and could “look” base64) don’t get misclassified.

---

## Examples

### Legacy decode (decoded text)

```
[Mode] legacy (fixed parity-aware decoder)

--- Decoded ---
Vade Retro 01.394.21 AS+AV+AP+RT Profile: OVH; Bailout: 300; ^ForbiddenHdr (500)
```

### vade1 inspection (no full decode)

```
[Mode] vade1 (Base64)
total_len=517  entropy≈7.624 bits/byte
has_vade1_magic=True starts_with='vade1{...'
brace_start=5 brace_end=355 inside_len=349 tail_len=161

--- Hex preview ---
00000000  76 61 64 65 31 7b ...  |vade1{...|
...
```

---

## Tests

The repo includes a **pytest** suite and sample headers as test **fixtures**.

Run:

```bash
pytest
```

---

## Known limitations

* **New `vade1` format is proprietary.** This tool **cannot fully decode** it; it only Base64-decodes and provides metadata/hex views for analysis and vendor escalation.
* **Heuristics.** `looks_legacy_value` and `is_base64ish` are best-effort; strange inputs might still be misclassified. We bias toward correctly detecting legacy first.
* **Zlib probes are experimental.** Some payloads may show zlib signatures but won’t inflate as standalone streams (likely framed/encrypted).

---

## Security & privacy

Headers can include sensitive diagnostics about email content or infrastructure. **Avoid sharing raw samples publicly.** Use the **JSON mode** with redaction when filing vendor tickets.

---

## Contributing

PRs welcome! Ideas:

* Better structure recognition for `vade1` containers. If you have any insight into the binary blob it could help.
* Additional metadata extractors, artifact saving (e.g., `--out dir`).
* Packaging for `pipx` install.

---

## License

This project is licensed under the **MIT License**.

You’re free to use, modify, and distribute this software (including commercially),
as long as you include the copyright and license notice.

See [LICENSE](./LICENSE) for the full text.

**SPDX-License-Identifier:** MIT
