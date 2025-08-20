import os
import json
import subprocess
import importlib.util
import pytest

HERE = os.path.dirname(__file__)
ROOT = os.path.abspath(os.path.join(HERE, ".."))
SCRIPT = os.path.join(ROOT, "vadespamdecode.py")
FIX = os.path.join(HERE, "fixtures")

def run_cli(args, input_text=None):
    cmd = ["python3", SCRIPT] + args
    return subprocess.run(cmd, input=input_text, text=True, capture_output=True)

def need(path):
    if not os.path.exists(path):
        pytest.skip(f"missing fixture: {path}")
    return path

def load_module():
    spec = importlib.util.spec_from_file_location("vadespamdecode", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore
    return mod

# ---- Detection / Mode paths ----
def test_detect_legacy_from_value():
    mod = load_module()
    p = need(os.path.join(FIX, "headers-legacy.value.txt"))
    with open(p, "r", encoding="utf-8") as fh:
        val = fh.read()
    out = mod.legacy_decode(val)
    assert isinstance(out, str)
    assert any(tok in out for tok in ("Vade", "Retro", "Forbidden", "Hdr", "Profile"))

def test_cli_positional_legacy_value():
    p = need(os.path.join(FIX, "value-legacy.txt"))
    with open(p, "r", encoding="utf-8") as fh:
        val = fh.read().strip()
    r = run_cli([val])
    assert r.returncode == 0
    assert "[Mode] legacy" in r.stdout
    assert "Decoded" in r.stdout

def test_cli_file_headers_blob_legacy():
    p = need(os.path.join(FIX, "headers-legacy.blob.txt"))
    r = run_cli(["--file", p])
    assert r.returncode == 0
    assert "[Header]" in r.stdout
    assert "[Mode] legacy" in r.stdout
    assert "Decoded" in r.stdout

def test_cli_file_headers_blob_legacy_folded():
    p = need(os.path.join(FIX, "headers-legacy-folded.blob.txt"))
    r = run_cli(["--file", p])
    assert r.returncode == 0
    assert "[Mode] legacy" in r.stdout

def test_detect_vade1_from_value():
    p = need(os.path.join(FIX, "value-vade1.base64.txt"))
    r = run_cli(["--file", p])
    assert r.returncode == 0
    assert "[Mode] vade1" in r.stdout
    assert "has_vade1_magic=True" in r.stdout

def test_cli_file_headers_blob_vade1():
    p = need(os.path.join(FIX, "headers-vade1.blob.txt"))
    r = run_cli(["--file", p])
    assert r.returncode == 0
    assert "[Header]" in r.stdout
    assert "[Mode] vade1" in r.stdout
    assert "has_vade1_magic=True" in r.stdout

def test_cli_file_headers_blob_vade1_folded():
    p = need(os.path.join(FIX, "headers-vade1-folded.blob.txt"))
    r = run_cli(["--file", p])
    assert r.returncode == 0
    assert "[Mode] vade1" in r.stdout
    assert "brace_start=" in r.stdout

def test_cli_file_headers_blob_base64_generic_not_vade1():
    p = need(os.path.join(FIX, "headers-base64-generic.blob.txt"))
    r = run_cli(["--file", p])
    assert r.returncode == 0
    assert "[Mode] base64" in r.stdout
    assert "starts_with=" in r.stdout

def test_cli_file_value_only_legacy_auto():
    p = need(os.path.join(FIX, "headers-legacy.value.txt"))
    r = run_cli(["--file", p])
    assert r.returncode == 0
    assert "[Mode] legacy" in r.stdout

def test_cli_file_value_only_vade1_auto():
    p = need(os.path.join(FIX, "value-vade1.base64.txt"))
    r = run_cli(["--file", p])
    assert r.returncode == 0
    assert "[Mode] vade1" in r.stdout

def test_cli_file_loose_spamcause_name_matching():
    p = need(os.path.join(FIX, "headers-weird-spamcause-folded.blob.txt"))
    r = run_cli(["--file", p])
    assert r.returncode == 0
    assert "[Header]" in r.stdout
    assert "spamcause" in r.stdout.lower()

# ---- EML paths ----
def test_eml_legacy():
    p = need(os.path.join(FIX, "sample-legacy.eml"))
    r = run_cli(["--eml", p])
    assert r.returncode == 0
    assert "[Mode] legacy" in r.stdout

def test_eml_vade1():
    p = need(os.path.join(FIX, "sample-vade1.eml"))
    r = run_cli(["--eml", p])
    assert r.returncode == 0
    assert "[Mode] vade1" in r.stdout

def test_eml_no_header_error():
    p = need(os.path.join(FIX, "sample-no-header.eml"))
    r = run_cli(["--eml", p])
    assert r.returncode != 0
    assert "No known spam-cause header" in r.stderr

# ---- JSON output ----
def test_json_output_vade1():
    p = need(os.path.join(FIX, "headers-vade1.blob.txt"))
    r = run_cli(["--json", "--file", p])
    assert r.returncode == 0
    data = json.loads(r.stdout)
    assert data["mode"] in ("vade1", "base64")
    if data["mode"] == "vade1":
        assert data["vade1"]["has_vade1_magic"] is True

def test_json_output_legacy():
    p = need(os.path.join(FIX, "headers-legacy.blob.txt"))
    r = run_cli(["--json", "--file", p])
    assert r.returncode == 0
    data = json.loads(r.stdout)
    assert data["mode"] == "legacy"
    assert "decoded" in data["legacy"]

# ---- Error handling ----
def test_force_vade1_on_nonbase64_reports_error():
    p = need(os.path.join(FIX, "value-garbage.txt"))
    r = run_cli(["--mode", "vade1", "--file", p])
    assert r.returncode != 0
    assert "Base64 decode failed" in r.stderr

def test_headers_without_spamcause_uses_fallback_token_or_whole():
    p = need(os.path.join(FIX, "headers-random-no-spamcause.blob.txt"))
    r = run_cli(["--file", p])
    assert r.returncode in (0, 3)
    assert "[Mode]" in r.stdout or "unknown" in r.stdout.lower()

def test_cli_positional_unknown_value():
    # Value that is neither legacy-like nor base64-ish should trigger 'unknown'
    p = need(os.path.join(FIX, "value-garbage.txt"))
    with open(p, "r", encoding="utf-8") as fh:
        val = fh.read().strip()
    r = run_cli([val])
    assert r.returncode != 0
    assert "[Mode] unknown" in r.stdout

# ---- Optional zlib probe ----
def test_try_zlib_probe_on_vade1():
    p = need(os.path.join(FIX, "headers-vade1.blob.txt"))
    r = run_cli(["--try-zlib", "--file", p])
    assert r.returncode == 0
    assert "Hex preview" in r.stdout
