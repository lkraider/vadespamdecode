#!/usr/bin/env python3
# SPDX-License-Identifier: MIT

"""
vadespamdecode: CLI to decode/inspect legacy OVH/Vade spam-cause headers and the newer Base64 'vade1' container.

Usage:
    vadespamdecode --file headers.txt

It accepts either a single header OR an entire headers blob,
and will parse and select X-Vade-Spamcause / X-OVH-SPAMCAUSE automatically.

"""

import argparse
import base64
import binascii
import collections
import email
import json
import math
import os
import re
import sys
import textwrap
import zlib
from typing import Optional, Tuple, Dict, Any

LEGACY_HEADER_NAMES = [
    "X-OVH-SPAMCAUSE",
    "X-VR-SPAMCAUSE"
]

VADE_HEADER_NAMES = [
    "X-Vade-Spamcause"
]

PRINTABLE_EXTRA = set("\r\n\t ")
HEXDUMP_WIDTH = 16


def is_base64ish(s: str) -> bool:
    ss = re.sub(r"\s+", "", s)
    return re.fullmatch(r"[A-Za-z0-9+/=]+", ss) is not None and len(ss) >= 8


def safe_b64decode(s: str) -> bytes:
    ss = re.sub(r"\s+", "", s).strip()
    ss += "=" * ((4 - len(ss) % 4) % 4)
    try:
        return base64.b64decode(ss, validate=False)
    except binascii.Error:
        return base64.b64decode(ss + "==")


def shannon_entropy(b: bytes) -> float:
    if not b:
        return 0.0
    counts = collections.Counter(b)
    n = len(b)
    ent = 0.0
    for c in counts.values():
        p = c / n
        ent -= p * math.log2(p)
    return ent


def hexdump(b: bytes, width: int = HEXDUMP_WIDTH, limit: int = 512) -> str:
    out = []
    length = min(len(b), limit)
    for i in range(0, length, width):
        chunk = b[i:i+width]
        hex_part = " ".join(f"{x:02x}" for x in chunk)
        ascii_part = "".join(chr(x) if 32 <= x <= 126 else "." for x in chunk)
        out.append(f"{i:08x}  {hex_part:<{width*3}}  |{ascii_part}|")
    if len(b) > limit:
        out.append(f"... ({len(b)-limit} bytes truncated)")
    return "\n".join(out)


def printable_ratio(s: str) -> float:
    if not s:
        return 0.0
    pr = sum(1 for ch in s if ch.isprintable() or ch in PRINTABLE_EXTRA)
    return pr / len(s)


# ---------- Legacy OVH decoder ----------

def looks_legacy_value(s: str) -> bool:
    """
    Legacy strings are typically all lowercase letters, with even length.
    """
    ss = re.sub(r"\s+", "", s)
    return bool(re.fullmatch(r"[a-z]+", ss)) and (len(ss) % 2 == 0)

def legacy_decode(msg: str) -> str:
    """
    Parity-aware decoder for legacy OVH/Vade obfuscation.
    - Remove whitespace from the source (handles folded headers).
    - Process pairs; on even pair index, swap the two characters.
    - Compute offset and char value.
    """
    msg = re.sub(r"\s+", "", msg).strip()
    out_chars = []
    pair_index = 0
    i = 0

    while i + 1 < len(msg):
        a = msg[i]
        b = msg[i+1]
        i += 2

        # Swap on even pair index
        if (pair_index % 2) == 0:
            a, b = b, a

        offset = (ord('g') - ord(a)) * 16
        val = ord(a) + ord(b) - ord('x') - offset
        try:
            out_chars.append(chr(val))
        except ValueError:
            out_chars.append('?')
        pair_index += 1

    return "".join(out_chars)


# ---------- vade1 Base64 container inspection ----------

def inspect_vade1(b: bytes, try_zlib: bool = False) -> Dict[str, Any]:
    info: Dict[str, Any] = {
        "total_len": len(b),
        "entropy_bits_per_byte": round(shannon_entropy(b), 3),
        "starts_with": b[:16].decode("ascii", errors="replace"),
        "has_vade1_magic": b.startswith(b"vade1"),
        "brace_start": None,
        "brace_end": None,
        "inside_len": None,
        "tail_len": None,
        "zlib_candidates": [],
        "hexdump_head": hexdump(b, limit=256),
    }

    brace_open = b.find(b"{", 0)
    brace_close = b.find(b"}", brace_open + 1) if brace_open != -1 else -1
    info["brace_start"] = brace_open
    info["brace_end"] = brace_close

    if brace_open != -1 and brace_close != -1 and brace_close > brace_open:
        inside = b[brace_open + 1: brace_close]
        tail = b[brace_close + 1:]
        info["inside_len"] = len(inside)
        info["tail_len"] = len(tail)
        for sig in (b"\x78\x01", b"\x78\x9c", b"\x78\xda"):
            idx = inside.find(sig)
            if idx != -1:
                info["zlib_candidates"].append({"where": "inside", "offset": idx, "sig": sig.hex()})
            idx2 = tail.find(sig)
            if idx2 != -1:
                info["zlib_candidates"].append({"where": "tail", "offset": idx2, "sig": sig.hex()})
        if try_zlib:
            for region_name, region in (("inside", inside), ("tail", tail)):
                for wbits in (15, -15, 31):
                    try:
                        z = zlib.decompressobj(wbits)
                        dec = z.decompress(region)
                        if dec:
                            info.setdefault("zlib_attempts", []).append({
                                "region": region_name,
                                "wbits": wbits,
                                "out_len": len(dec),
                                "out_preview": hexdump(dec[:128], limit=128),
                            })
                    except Exception:
                        pass

    return info


# ---------- Header extraction helpers ----------

def extract_headers_from_eml(path: str) -> Dict[str, str]:
    with open(path, "rb") as f:
        msg = email.message_from_bytes(f.read())
    headers = {}
    for k, v in msg.items():
        headers[k] = v
    return headers


def extract_headers_from_text(text: str) -> Dict[str, str]:
    """
    Parse a plain text blob of headers, handling simple folding.
    """
    headers: Dict[str, str] = {}
    last_key = None
    for raw_line in text.splitlines():
        line = raw_line.rstrip("\r\n")
        if not line:
            continue
        if line[:1].isspace() and last_key:
            headers[last_key] = headers[last_key] + " " + line.strip()
            continue
        m = re.match(r"^\s*([A-Za-z0-9\-]+)\s*:\s*(.*)$", line)
        if m:
            key = m.group(1)
            val = m.group(2).strip()
            headers[key] = val
            last_key = key
    return headers


def pick_header_value(headers: Dict[str, str]) -> Tuple[Optional[str], Optional[str]]:
    for name in VADE_HEADER_NAMES + LEGACY_HEADER_NAMES:
        for k, v in headers.items():
            if k.lower() == name.lower():
                return k, v
    return None, None


def detect_mode(value: str) -> str:
    # Returns one of: 'vade1', 'legacy', 'base64', 'unknown'
    if looks_legacy_value(value):
        return "legacy"
    if is_base64ish(value):
        try:
            raw = safe_b64decode(value)
            if raw.startswith(b"vade1"):
                return "vade1"
            else:
                return "base64"
        except Exception:
            pass
    return "unknown"


def run_on_value(value: str, mode: Optional[str], json_out: bool, try_zlib: bool, hdr_name: Optional[str] = None) -> int:
    result: Dict[str, Any] = {"mode": None}
    if hdr_name and hdr_name.lower() in [h.lower() for h in LEGACY_HEADER_NAMES]:
        detected = 'legacy'
    elif hdr_name and hdr_name.lower() in [h.lower() for h in VADE_HEADER_NAMES]:
        # Prefer vade1 if magic matches; else generic base64
        if is_base64ish(value):
            try:
                raw = safe_b64decode(value)
                detected = 'vade1' if raw.startswith(b'vade1') else 'base64'
            except Exception:
                detected = 'base64'
        else:
            detected = detect_mode(value)
    else:
        detected = detect_mode(value) if mode in (None, 'auto') else mode
    result["mode"] = detected

    if detected == "legacy":
        decoded = legacy_decode(value)
        result["legacy"] = {
            "decoded": decoded,
            "printable_ratio": round(printable_ratio(decoded), 3),
        }
        if not json_out:
            print("[Mode] legacy")
            print("\n--- Decoded ---")
            print(decoded)
    elif detected in ("vade1", "base64"):
        try:
            raw = safe_b64decode(value)
        except Exception as e:
            if not json_out:
                print(f"ERROR: Base64 decode failed: {e}", file=sys.stderr)
            return 2
        info = inspect_vade1(raw, try_zlib=try_zlib) if detected == "vade1" else {
            "total_len": len(raw),
            "entropy_bits_per_byte": round(shannon_entropy(raw), 3),
            "starts_with": raw[:16].decode("ascii", errors="replace"),
            "hexdump_head": hexdump(raw, limit=256),
        }
        result[detected] = info
        if not json_out:
            print(f"[Mode] {detected} (Base64)")
            if detected == "vade1":
                print(f"total_len={info['total_len']}  entropy≈{info['entropy_bits_per_byte']} bits/byte")
                print(f"has_vade1_magic={info['has_vade1_magic']} starts_with={info['starts_with']!r}")
                print(f"brace_start={info['brace_start']} brace_end={info['brace_end']} "
                      f"inside_len={info['inside_len']} tail_len={info['tail_len']}")
                if info.get("zlib_candidates"):
                    print("zlib_candidates:", info["zlib_candidates"])
                if info.get("zlib_attempts"):
                    print("zlib_attempts:", info["zlib_attempts"])
                print("\n--- Hex preview ---")
                print(info["hexdump_head"])
            else:
                print(f"total_len={info['total_len']}  entropy≈{info['entropy_bits_per_byte']} bits/byte")
                print(f"starts_with={info['starts_with']!r}")
                print("\n--- Hex preview ---")
                print(info["hexdump_head"])
    else:
        if not json_out:
            print("[Mode] unknown")
        result["error"] = "Could not detect mode or unsupported format"
        if not json_out:
            return 3

    if json_out:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


def main():
    p = argparse.ArgumentParser(
        prog="vadespamdecode",
        description="Decode/inspect OVH/Vade spam-cause headers (legacy obfuscation and Base64 'vade1' container).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""
        Examples:
          # From a header value (auto-detect mode):
          vadespamdecode "dgxx..."

          # Base64 vade1 header from a file of headers:
          vadespamdecode --file headers.txt

          # Read an .eml, auto-pick the spam-cause header and inspect:
          vadespamdecode --eml message.eml

          # JSON output:
          vadespamdecode --json --file headers.txt

          # Try zlib probes (experimental) on vade1 containers:
          vadespamdecode --try-zlib --file headers.txt
        """)
    )
    g = p.add_mutually_exclusive_group()
    g.add_argument("--file", help="Read from a text file. Can be a raw header value or a whole headers blob (.txt)")
    g.add_argument("--eml", help="Extract spam-cause header from a .eml file")

    p.add_argument("value", nargs="?", help="Header value (quoted) when not using --file/--eml")
    p.add_argument("--mode", choices=["auto", "legacy", "vade1", "base64"], default="auto",
                   help="Force a mode; default: auto")
    p.add_argument("--json", action="store_true", help="Output JSON")
    p.add_argument("--try-zlib", action="store_true",
                   help="For vade1: try zlib decompress probes on inner regions (experimental)")

    args = p.parse_args()

    header_value = None
    detected_name = None

    if args.file:
        with open(args.file, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()

        headers = extract_headers_from_text(content)
        name, val = pick_header_value(headers)
        if name and val:
            detected_name = name
            header_value = val
        else:
            m = re.search(
                r'(?im)^\s*([^\s:]*spamcause[^\s:]*)\s*:\s*(.*?)'   # header match with "spamcause" + first line of value
                r'(?:\r?\n[ \t].*?)*'                               # continuation lines
                r'(?=\r?\n(?![ \t])|$)',                            # until next header or EOF
                content,
            )
            if m:
                detected_name = m.group(1)
                # unfold: join continuation lines with a space
                header_value = re.sub(r'\r?\n[ \t]+', ' ', m.group(2)).strip()
            else:
                stripped = content.strip()
                if is_base64ish(stripped):
                    header_value = stripped
                else:
                    tokens = re.findall(r"[A-Za-z0-9+/=]{24,}", content)
                    if tokens:
                        header_value = tokens[0]
                    else:
                        header_value = stripped

    elif args.eml:
        headers = extract_headers_from_eml(args.eml)
        name, val = pick_header_value(headers)
        if not name:
            print("ERROR: No known spam-cause header found in .eml", file=sys.stderr)
            sys.exit(1)
        detected_name = name
        header_value = val
    elif args.value:
        header_value = args.value
    else:
        p.error("Provide a header VALUE, or use --file/--eml")

    if detected_name and not args.json:
        print(f"[Header] {detected_name}")

    rc = run_on_value(header_value, mode=args.mode, json_out=args.json, try_zlib=args.try_zlib, hdr_name=detected_name)
    sys.exit(rc)


if __name__ == "__main__":
    main()
