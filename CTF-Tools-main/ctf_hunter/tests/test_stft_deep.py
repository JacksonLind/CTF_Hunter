"""
Deep validation of _check_stft_matrix in analyzers/generic.py.
Tests every realistic failure mode before the feature is considered stable.

Run from ctf_hunter/ directory:
    python tests/test_stft_deep.py
"""
from __future__ import annotations

import io
import os
import re
import sys
import tempfile
import time

# Ensure stdout can handle Unicode on Windows (cp1252 would otherwise crash
# on characters like +/- and ~= used in check() output lines).
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
import wave

import numpy as np
from scipy.signal import stft as scipy_stft, istft as scipy_istft

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from analyzers.generic import GenericAnalyzer, _STFT_HEADER_RE
from core.extracted_content import extract_from_finding

ANA = GenericAnalyzer()
FLAG_RE = re.compile(r"flag\{[^}]+\}")
_results = []


def check(name: str, cond: bool, extra: str = "") -> None:
    _results.append(cond)
    tag = "PASS" if cond else "FAIL"
    line = f"  [{tag}]  {name}"
    if extra:
        line += f"  ({extra})"
    print(line)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_stft_file(
    n_fft: int = 256,
    hop: int = 128,
    fs: int = 16_000,
    n_secs: float = 0.5,
    include_header: bool = True,
    override_shape: tuple | None = None,
    fmt: str = "paren",
):
    """Return (file_bytes, Zxx, rows, cols, original_signal, fs)."""
    n = int(n_secs * fs)
    t = np.linspace(0, n_secs, n, endpoint=False)
    # Two-tone signal to ensure non-trivial STFT (avoids mono-frequency edge cases)
    sig = (np.sin(2 * np.pi * 440 * t) + 0.3 * np.sin(2 * np.pi * 880 * t)).astype(np.float32)
    _, _, Zxx = scipy_stft(sig, fs=fs, nperseg=n_fft, noverlap=n_fft - hop, nfft=n_fft)
    rows, cols = Zxx.shape

    lines = []
    if include_header:
        sh = override_shape or (rows, cols)
        lines.append(f"# STFT shape: complex64 ({sh[0]}, {sh[1]})")
    for v in Zxx.flatten():
        r, im = float(v.real), float(v.imag)
        s = f"{r}+{im}j" if im >= 0 else f"{r}{im}j"
        lines.append(f"({s})" if fmt == "paren" else s)

    return "\n".join(lines).encode(), Zxx, rows, cols, sig, fs


def run_analyzer(data: bytes, depth: str = "deep") -> list:
    fd, path = tempfile.mkstemp(suffix=".txt")
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
    try:
        return ANA.analyze(path, FLAG_RE, depth, None)
    finally:
        os.unlink(path)


def stft_findings(findings: list) -> list:
    return [
        f for f in findings
        if "stft" in f.title.lower() or "stft" in f.detail.lower()
    ]


def get_wav(finding) -> bytes | None:
    m = re.search(r"raw_hex=([0-9a-fA-F]+)", finding.detail)
    return bytes.fromhex(m.group(1)) if m else None


def wav_duration(wav_bytes: bytes) -> float:
    buf = io.BytesIO(wav_bytes)
    with wave.open(buf, "rb") as wf:
        return wf.getnframes() / wf.getframerate()


# ---------------------------------------------------------------------------
# 1. Header regex
# ---------------------------------------------------------------------------

print("\n=== 1. Header regex ===")
for s, expect_rows in [
    ("# STFT shape: complex64 (129, 1380)",  "129"),
    ("# stft shape: COMPLEX64 (129, 1380)",  "129"),  # case insensitive
    ("# STFT shape: (129, 1380)",            "129"),  # dtype optional
    ("#STFT shape: complex64 (129,1380)",    "129"),  # compact spacing
]:
    m = _STFT_HEADER_RE.search(s)
    check(f"regex: {s[:55]}", m is not None and (m.group(1) == expect_rows))

# ──────────────────────────────────────────────────────────────────────────────
print("\n=== 2. Fast mode ===")
data_fast, *_ = make_stft_file()
findings_fast = run_analyzer(data_fast, depth="fast")
sf_fast = stft_findings(findings_fast)
check("fast mode emits finding", len(sf_fast) >= 1)
check("fast mode severity is INFO", all(f.severity == "INFO" for f in sf_fast))
check("fast mode has NO raw_hex=", not any("raw_hex=" in f.detail for f in sf_fast))
check("fast mode mentions n_fft", any("n_fft" in f.detail for f in sf_fast))

# ──────────────────────────────────────────────────────────────────────────────
print("\n=== 3. Deep mode — small file (0.5s) ===")
data_small, Zxx_s, rows_s, cols_s, sig_s, fs_s = make_stft_file(n_secs=0.5)
t0 = time.time()
findings_deep = run_analyzer(data_small, depth="deep")
elapsed_small = time.time() - t0
sf_deep = stft_findings(findings_deep)
check("deep mode emits finding", len(sf_deep) >= 1)
check("deep mode severity is MEDIUM", any(f.severity == "MEDIUM" for f in sf_deep))
check("deep mode has raw_hex=", any("raw_hex=" in f.detail for f in sf_deep))
check(f"elapsed < 2s", elapsed_small < 2.0, f"{elapsed_small:.3f}s")

# ──────────────────────────────────────────────────────────────────────────────
print("\n=== 4. WAV validity ===")
wav_small = get_wav(sf_deep[0]) if sf_deep else None
check("raw_hex= decodes to bytes", wav_small is not None)
if wav_small:
    check("starts with RIFF magic", wav_small[:4] == b"RIFF")
    check("contains WAVE marker", wav_small[8:12] == b"WAVE")
    buf = io.BytesIO(wav_small)
    with wave.open(buf, "rb") as wf:
        nch, rate, sw, nf = (
            wf.getnchannels(), wf.getframerate(), wf.getsampwidth(), wf.getnframes()
        )
    check("mono (1 channel)", nch == 1)
    check("16 000 Hz sample rate", rate == 16_000)
    check("16-bit samples (swidth=2)", sw == 2)
    check("non-zero frame count", nf > 0)
    dur = nf / rate
    check(f"duration ≈ 0.5s (±15%)", abs(dur - 0.5) < 0.075, f"{dur:.3f}s")

# ──────────────────────────────────────────────────────────────────────────────
print("\n=== 5. Signal round-trip fidelity ===")
if wav_small:
    buf = io.BytesIO(wav_small)
    with wave.open(buf, "rb") as wf:
        pcm = np.frombuffer(wf.readframes(wf.getnframes()), dtype=np.int16).astype(np.float32) / 32767.0
    n = min(len(sig_s), len(pcm))
    corr = float(np.corrcoef(sig_s[:n], pcm[:n])[0, 1])
    check("correlation with original > 0.99", corr > 0.99, f"corr={corr:.6f}")

# ──────────────────────────────────────────────────────────────────────────────
print("\n=== 6. Challenge-scale file (129 x 1380, ~11s) ===")
data_big, _, rows_b, cols_b, _, _ = make_stft_file(n_secs=11.04)
print(f"    File: {len(data_big)/1024:.0f} KB, shape ({rows_b}, {cols_b}), {rows_b*cols_b} values")
t0 = time.time()
findings_big = run_analyzer(data_big, depth="deep")
elapsed_big = time.time() - t0
sf_big = stft_findings(findings_big)
check("challenge-scale emits finding", len(sf_big) >= 1, f"{elapsed_big:.2f}s")
check(f"challenge-scale elapsed < 5s", elapsed_big < 5.0, f"{elapsed_big:.2f}s")
wav_big = get_wav(sf_big[0]) if sf_big else None
if wav_big:
    dur_big = wav_duration(wav_big)
    check("challenge WAV duration > 10s", dur_big > 10.0, f"{dur_big:.2f}s")
    check("challenge WAV size > 100 KB", len(wav_big) > 100_000, f"{len(wav_big)//1024} KB")

# ──────────────────────────────────────────────────────────────────────────────
print("\n=== 7. Negative imaginary parts in complex values ===")
# Make sure the parser handles (a-bj) without stripping the sign
data_neg, *_ = make_stft_file(n_secs=0.3)
sf_neg = stft_findings(run_analyzer(data_neg, depth="deep"))
check("file with negative imag values → finding", len(sf_neg) >= 1)
check("negative imag → has raw_hex=", any("raw_hex=" in f.detail for f in sf_neg))
# Spot-check: the detail shape line should match expected rows
if sf_neg:
    expected_rows = 256 // 2 + 1  # 129
    check(f"detail mentions rows={expected_rows}",
          f"({expected_rows}," in sf_neg[0].detail or f"({expected_rows}, " in sf_neg[0].detail)

# ──────────────────────────────────────────────────────────────────────────────
print("\n=== 8. Shape inference without header ===")
data_nh, _, rows_nh, cols_nh, _, _ = make_stft_file(include_header=False)
sf_nh = stft_findings(run_analyzer(data_nh, depth="deep"))
check("no-header → finding emitted", len(sf_nh) >= 1)
check("no-header → has raw_hex=", any("raw_hex=" in f.detail for f in sf_nh))

# ──────────────────────────────────────────────────────────────────────────────
print("\n=== 9. ContentRedispatcher integration ===")
if sf_deep:
    extracted = extract_from_finding(sf_deep[0])
    check("extract_from_finding returns >=1 item", len(extracted) >= 1)
    if extracted:
        ec = extracted[0]
        check("ExtractedContent.data starts with RIFF", ec.data[:4] == b"RIFF")
        check("encoding_chain contains 'raw_hex'", "raw_hex" in ec.encoding_chain)
        check("depth == 0", ec.depth == 0)
        check("label mentions 'STFT'", "STFT" in ec.label or "stft" in ec.label.lower())

# ──────────────────────────────────────────────────────────────────────────────
print("\n=== 10. Header / value count mismatch ===")
data_mm, *_ = make_stft_file(override_shape=(999, 999))
findings_mm = run_analyzer(data_mm, depth="deep")
mismatch_f = [
    f for f in findings_mm
    if "mismatch" in f.title.lower() or "mismatch" in f.detail.lower()
]
check("mismatch finding emitted", len(mismatch_f) >= 1)
check("mismatch severity INFO", all(f.severity == "INFO" for f in mismatch_f))

# ──────────────────────────────────────────────────────────────────────────────
print("\n=== 11. Bare format (no parentheses) ===")
data_bare, *_ = make_stft_file(fmt="bare")
sf_bare = stft_findings(run_analyzer(data_bare, depth="deep"))
check("bare a+bj format → finding", len(sf_bare) >= 1)
check("bare format → has raw_hex=", any("raw_hex=" in f.detail for f in sf_bare))

# ──────────────────────────────────────────────────────────────────────────────
print("\n=== 12. Other n_fft values ===")
for n_fft_t in (512, 128, 1024):
    data_t, *_ = make_stft_file(n_fft=n_fft_t, hop=n_fft_t // 2)
    sf_t = stft_findings(run_analyzer(data_t, depth="deep"))
    check(f"n_fft={n_fft_t} → finding + WAV",
          len(sf_t) >= 1 and any("raw_hex=" in f.detail for f in sf_t))

# ──────────────────────────────────────────────────────────────────────────────
print("\n=== 13. Scientific notation values ===")
data_sci, Zxx_sci, rows_sc, cols_sc, sig_sc, fs_sc = make_stft_file()
lines_sci = [f"# STFT shape: complex64 ({rows_sc}, {cols_sc})"]
for v in Zxx_sci.flatten():
    r, im = float(v.real), float(v.imag)
    s = f"{r:.6e}+{im:.6e}j" if im >= 0 else f"{r:.6e}{im:.6e}j"
    lines_sci.append(f"({s})")
data_sci_bytes = "\n".join(lines_sci).encode()
sf_sci = stft_findings(run_analyzer(data_sci_bytes, depth="deep"))
check("scientific notation → finding", len(sf_sci) >= 1)
check("scientific notation → has raw_hex=", any("raw_hex=" in f.detail for f in sf_sci))

# ──────────────────────────────────────────────────────────────────────────────
print("\n=== 14. Graceful degradation ===")
check("binary file → no STFT finding",
      not stft_findings(run_analyzer(bytes(range(256)) * 20)))
check("plain prose → no STFT finding",
      not stft_findings(run_analyzer(b"The quick brown fox jumps over the lazy dog.\n" * 50)))
check("real-only numbers + header → no STFT finding",
      not stft_findings(run_analyzer(
          b"# STFT shape: complex64 (129, 10)\n" +
          b"\n".join(f"{i * 1.1:.4f}".encode() for i in range(1290))
      )))
check("too few lines → no STFT finding",
      not stft_findings(run_analyzer(
          b"# STFT shape: complex64 (129, 1)\n" + b"(1.0+2.0j)\n" * 8
      )))

# ──────────────────────────────────────────────────────────────────────────────
print()
passed = sum(_results)
total  = len(_results)
print(f"{passed}/{total} checks passed")
sys.exit(0 if passed == total else 1)
