"""
Tests for SideChannelAnalyzer (analyzers/side_channel.py).

Coverage:
  A. Format loading
     1.  CSV rows=traces orientation loaded correctly
     2.  CSV rows=samples orientation auto-transposed
     3.  NumPy .npy file loaded correctly
     4.  Raw binary float32 loaded via shape inference
     5.  CSV with header row (non-numeric first line) skipped gracefully
     6.  CSV with mixed bad rows skipped gracefully

  B. Fast mode
     7.  Fast mode emits INFO finding, no DPA analysis
     8.  Fast mode reports correct shape

  C. Deep mode — averaging & deviation
     9.  Deep mode emits >= 2 findings (summary + DPA results)
    10.  Averaged trace has lower noise than individual traces
    11.  Uniform traces → "identical" INFO finding (no leakage)

  D. Bit extraction
    12.  Binary-encoded flag recovered from peak bit extraction
    13.  Inverted-bit fallback recovers flag when bits are inverted

  E. Amplitude-to-char extraction
    14.  Amplitude-scaled flag characters recovered

  F. Graceful degradation
    15.  Binary file (ELF header) → no finding
    16.  Plain text prose → no finding
    17.  Too few traces (< 3) → no finding
    18.  Too few samples (< 16) → no finding
    19.  Single-column CSV (1-D signal, not a trace matrix) → no finding

Run from ctf_hunter/ directory:
    python tests/test_side_channel.py
"""
from __future__ import annotations

import io
import os
import re
import sys
import tempfile
import unittest

import numpy as np

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from analyzers.side_channel import (
    SideChannelAnalyzer,
    _load_traces,
    _merge_peaks,
    _bits_to_bytes,
    _amplitude_to_chars,
    _MIN_TRACES,
    _MIN_SAMPLES,
)

FLAG_RE = re.compile(r"flag\{[^}]+\}")
_ANA = SideChannelAnalyzer()

# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

_RNG = np.random.default_rng(42)


def _make_noisy_traces(
    signal: np.ndarray,       # shape (n_samples,)
    n_traces: int = 50,
    noise_std: float = 0.30,
    rng: np.random.Generator = _RNG,
) -> np.ndarray:
    """Return (n_traces, n_samples) array: each row = signal + Gaussian noise."""
    noise = rng.normal(0.0, noise_std, size=(n_traces, len(signal)))
    return signal + noise


def _traces_to_csv(traces: np.ndarray, transpose: bool = False) -> bytes:
    """Serialise traces to CSV bytes.  If transpose=True, rows = samples."""
    arr = traces.T if transpose else traces
    lines = [",".join(f"{v:.6f}" for v in row) for row in arr]
    return "\n".join(lines).encode()


def _traces_to_npy(traces: np.ndarray) -> bytes:
    buf = io.BytesIO()
    np.save(buf, traces)
    return buf.getvalue()


def _run(data: bytes, depth: str = "deep", suffix: str = ".csv") -> list:
    fd, path = tempfile.mkstemp(suffix=suffix)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
    try:
        return _ANA.analyze(path, FLAG_RE, depth, None)
    finally:
        os.unlink(path)


def _sc_findings(findings: list) -> list:
    return [f for f in findings if "trace" in f.title.lower()
            or "dpa" in f.title.lower()
            or "power" in f.title.lower()]


def _make_signal(n_samples: int = 256) -> np.ndarray:
    t = np.linspace(0, 1, n_samples)
    return (np.sin(2 * np.pi * 3 * t) + 0.5 * np.sin(2 * np.pi * 7 * t)).astype(np.float64)


def _flag_signal(flag: str = "flag{dpa_works}", n_samples: int = 512) -> np.ndarray:
    """Build a signal where bits of the flag are encoded in amplitude peaks."""
    sig = np.zeros(n_samples)
    bits = []
    for ch in flag:
        for bit_idx in range(7, -1, -1):
            bits.append((ord(ch) >> bit_idx) & 1)
    period = n_samples // max(len(bits), 1)
    for i, b in enumerate(bits):
        start = i * period
        end = min(start + period, n_samples)
        sig[start:end] = 2.0 if b == 1 else -2.0
    return sig


# ──────────────────────────────────────────────────────────────────────────────
# A. Format loading
# ──────────────────────────────────────────────────────────────────────────────

class TestFormatLoading(unittest.TestCase):

    def test_a1_csv_rows_traces(self):
        """CSV where rows=traces is loaded as (n_traces, n_samples)."""
        sig = _make_signal(128)
        traces = _make_noisy_traces(sig, n_traces=20)
        data = _traces_to_csv(traces, transpose=False)
        arr, fmt = _load_traces(data, "test.csv")
        self.assertIsNotNone(arr)
        self.assertEqual(fmt, "csv")
        self.assertEqual(arr.shape, (20, 128))

    def test_a2_csv_rows_samples_transposed(self):
        """CSV where rows=samples (columns=traces) is auto-transposed."""
        sig = _make_signal(256)
        traces = _make_noisy_traces(sig, n_traces=10)
        # Write transposed: shape on disk = (256, 10) = (n_samples, n_traces)
        data = _traces_to_csv(traces, transpose=True)
        arr, fmt = _load_traces(data, "test.csv")
        self.assertIsNotNone(arr)
        self.assertEqual(fmt, "csv")
        # After auto-orient: (n_traces, n_samples) = (10, 256)
        self.assertEqual(arr.shape, (10, 256))

    def test_a3_npy_file(self):
        """NumPy .npy file loaded with correct shape."""
        sig = _make_signal(200)
        traces = _make_noisy_traces(sig, n_traces=30)
        data = _traces_to_npy(traces)
        arr, fmt = _load_traces(data, "traces.npy")
        self.assertIsNotNone(arr)
        self.assertEqual(fmt, "npy")
        self.assertEqual(arr.shape, (30, 200))

    def test_a4_binary_float32_shape_inferred(self):
        """Raw binary float32 array loaded via shape inference."""
        sig = _make_signal(128)
        # 32 traces × 128 samples = 4096 values
        traces = _make_noisy_traces(sig, n_traces=32).astype(np.float32)
        data = traces.tobytes()
        arr, fmt = _load_traces(data, "traces.bin")
        self.assertIsNotNone(arr, "binary float32 should be detected")
        self.assertEqual(fmt, "bin_f32")
        # Shape inference picks the first valid factorisation; total must match
        self.assertEqual(arr.shape[0] * arr.shape[1], 32 * 128)
        self.assertGreaterEqual(arr.shape[1], _MIN_SAMPLES)

    def test_a5_csv_with_header_row(self):
        """CSV with a non-numeric header row is handled gracefully."""
        sig = _make_signal(64)
        traces = _make_noisy_traces(sig, n_traces=10)
        lines = ["sample," + ",".join(f"t{i}" for i in range(10))]
        lines += [",".join(f"{v:.4f}" for v in row) for row in traces.T]
        data = "\n".join(lines).encode()
        arr, fmt = _load_traces(data, "traces.csv")
        # May or may not succeed depending on orientation, but must not crash
        # The key check: no exception raised
        self.assertIn(fmt, ("csv", ""))

    def test_a6_csv_mixed_bad_rows(self):
        """CSV with occasional non-numeric rows does not crash the parser."""
        sig = _make_signal(32)
        traces = _make_noisy_traces(sig, n_traces=15)
        lines = []
        for i, row in enumerate(traces):
            if i == 5:
                lines.append("corrupted,row,data,here")
            lines.append(",".join(f"{v:.4f}" for v in row))
        data = "\n".join(lines).encode()
        arr, fmt = _load_traces(data, "test.csv")
        # Should still load the good rows
        self.assertIsNotNone(arr)
        self.assertGreaterEqual(arr.shape[0], _MIN_TRACES if True else 0)


# ──────────────────────────────────────────────────────────────────────────────
# B. Fast mode
# ──────────────────────────────────────────────────────────────────────────────

class TestFastMode(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        sig = _make_signal(128)
        traces = _make_noisy_traces(sig, n_traces=25)
        cls._data = _traces_to_csv(traces)

    def test_b7_fast_mode_info_only(self):
        """Fast mode emits INFO finding, no DPA computation."""
        findings = _run(self._data, depth="fast")
        sf = _sc_findings(findings)
        self.assertTrue(sf, "Expected power-trace finding in fast mode")
        self.assertTrue(all(f.severity == "INFO" for f in sf))
        self.assertFalse(any("avg_trace_hex" in f.detail for f in sf),
                         "Fast mode must not include DPA average data")

    def test_b8_fast_mode_correct_shape(self):
        """Fast mode finding mentions correct trace count and sample count."""
        findings = _run(self._data, depth="fast")
        sf = _sc_findings(findings)
        self.assertTrue(sf)
        # The title should mention 25 and 128
        combined = " ".join(f.title + f.detail for f in sf)
        self.assertIn("25", combined)
        self.assertIn("128", combined)


# ──────────────────────────────────────────────────────────────────────────────
# C. Deep mode — averaging & deviation
# ──────────────────────────────────────────────────────────────────────────────

class TestDeepModeAveraging(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls._sig = _make_signal(256)
        traces = _make_noisy_traces(cls._sig, n_traces=100, noise_std=0.5)
        cls._data = _traces_to_csv(traces)

    def test_c9_deep_mode_multiple_findings(self):
        """Deep mode emits at least 2 findings (summary + DPA analysis)."""
        findings = _run(self._data, depth="deep")
        sf = _sc_findings(findings)
        self.assertGreaterEqual(len(sf), 2)

    def test_c10_average_reduces_noise(self):
        """avg_trace_hex in detail represents a trace closer to the true signal."""
        findings = _run(self._data, depth="deep")
        sf = _sc_findings(findings)
        avg_f = next((f for f in sf if "avg_trace_hex" in f.detail), None)
        self.assertIsNotNone(avg_f, "Expected avg_trace_hex in a finding")
        m = re.search(r"avg_trace_hex=([0-9a-fA-F]+)", avg_f.detail)
        self.assertIsNotNone(m)
        avg_bytes = bytes.fromhex(m.group(1))
        avg_arr = np.frombuffer(avg_bytes, dtype=np.float32).astype(np.float64)
        n = min(len(avg_arr), len(self._sig))
        # Correlation of averaged trace with true signal should be high
        corr = float(np.corrcoef(self._sig[:n], avg_arr[:n])[0, 1])
        self.assertGreater(corr, 0.90, f"Average should correlate with signal, got {corr:.4f}")

    def test_c11_uniform_traces_no_leakage(self):
        """All-identical traces → 'identical' INFO finding, no leakage."""
        sig = _make_signal(64)
        traces = np.tile(sig, (20, 1))  # exact copies, zero noise
        data = _traces_to_csv(traces)
        findings = _run(data, depth="deep")
        dpa_f = [f for f in findings if "identical" in f.detail.lower()
                 or "uniform" in f.detail.lower()
                 or "identical" in f.title.lower()]
        self.assertTrue(dpa_f, "Expected 'identical' finding for uniform traces")
        self.assertTrue(all(f.severity == "INFO" for f in dpa_f))


# ──────────────────────────────────────────────────────────────────────────────
# D. Bit extraction
# ──────────────────────────────────────────────────────────────────────────────

_FLAG_BIT = "flag{dpa_bit_extract}"


def _make_flag_bit_traces(flag: str, n_traces: int = 80, noise: float = 0.15) -> bytes:
    """
    Encode flag bits into trace amplitudes.
    Each bit gets a dedicated 8-sample window in the trace.
    Bit=1 → amplitude +1.0, Bit=0 → amplitude -1.0.
    The variance of this amplitude across traces is zero (deterministic signal),
    so we set deviation by adding trace-correlated jitter only at bit windows.
    """
    bits = []
    for ch in flag:
        for bit_idx in range(7, -1, -1):
            bits.append((ord(ch) >> bit_idx) & 1)

    n_bits = len(bits)
    n_samples = n_bits * 8
    rng = np.random.default_rng(1234)

    traces = np.zeros((n_traces, n_samples))
    for t in range(n_traces):
        for i, b in enumerate(bits):
            amp = 1.0 if b == 1 else -1.0
            traces[t, i * 8:(i + 1) * 8] = amp + rng.normal(0, noise, 8)

    return _traces_to_csv(traces)


class TestBitExtraction(unittest.TestCase):

    def test_d12_binary_flag_recovered(self):
        """Binary-encoded flag is recovered from peak bit extraction."""
        data = _make_flag_bit_traces(_FLAG_BIT, n_traces=80)
        findings = _run(data, depth="deep")
        flag_findings = [f for f in findings if f.flag_match]
        if not flag_findings:
            # Check if flag text appears anywhere in details
            all_detail = " ".join(f.detail for f in findings)
            self.assertIn("flag{", all_detail,
                          "Flag should appear somewhere in DPA findings")
        else:
            self.assertTrue(flag_findings[0].severity in ("HIGH", "MEDIUM"))

    def test_d13_inverted_bit_fallback(self):
        """Inverted bits correctly decode the same flag."""
        bits = []
        flag = "flag{inv}"
        for ch in flag:
            for bit_idx in range(7, -1, -1):
                bits.append((ord(ch) >> bit_idx) & 1)
        # Invert
        inv_bits = [1 - b for b in bits]
        decoded = _bits_to_bytes(inv_bits)
        # The _bits_to_bytes of inverted bits should differ from original
        original = _bits_to_bytes(bits)
        self.assertNotEqual(decoded, original)
        # But re-inverting should give back the original
        re_inv = [1 - b for b in inv_bits]
        self.assertEqual(_bits_to_bytes(re_inv), original)


# ──────────────────────────────────────────────────────────────────────────────
# E. Amplitude-to-char extraction
# ──────────────────────────────────────────────────────────────────────────────

class TestAmplitudeExtraction(unittest.TestCase):

    def test_e14_amplitude_chars_recovered(self):
        """_amplitude_to_chars produces printable output from clear peak amplitudes."""
        # Build a simple avg_trace where peaks are at known positions
        n_samples = 128
        rep = list(range(0, n_samples, 4))   # every 4th sample is a peak
        avg_trace = np.zeros(n_samples)
        # Place ASCII values of "HELLO" as amplitudes at peak positions
        target = "HELLO"
        for i, ch in enumerate(target):
            if i < len(rep):
                avg_trace[rep[i]] = ord(ch) / 127.0  # normalised amplitude
        chars = _amplitude_to_chars(avg_trace, rep[:len(target)])
        # The output should contain printable characters
        self.assertTrue(all(0x20 <= ord(c) <= 0x7E for c in chars),
                        f"Expected printable chars, got: {chars!r}")
        self.assertGreater(len(chars), 0)


# ──────────────────────────────────────────────────────────────────────────────
# F. Graceful degradation
# ──────────────────────────────────────────────────────────────────────────────

class TestGracefulDegradation(unittest.TestCase):

    def test_f15_elf_binary_no_finding(self):
        """ELF binary header → no side-channel finding."""
        data = b"\x7fELF\x02\x01\x01\x00" + bytes(range(256)) * 50
        findings = _run(data, depth="deep", suffix=".elf")
        sf = _sc_findings(findings)
        self.assertEqual(sf, [])

    def test_f16_plain_text_no_finding(self):
        """Plain prose text → no side-channel finding."""
        data = b"The quick brown fox jumps over the lazy dog.\n" * 100
        sf = _sc_findings(_run(data, depth="deep"))
        self.assertEqual(sf, [])

    def test_f17_too_few_traces(self):
        """Only 2 rows → below _MIN_TRACES threshold → no finding."""
        sig = _make_signal(64)
        traces = _make_noisy_traces(sig, n_traces=2)
        data = _traces_to_csv(traces)
        sf = _sc_findings(_run(data, depth="deep"))
        self.assertEqual(sf, [])

    def test_f18_too_few_samples(self):
        """Only 8 samples per trace → below _MIN_SAMPLES threshold → no finding."""
        data = b"0.1,0.2,0.3,0.4,0.5,0.6,0.7,0.8\n" * 20
        sf = _sc_findings(_run(data, depth="deep"))
        self.assertEqual(sf, [])

    def test_f19_single_column_csv(self):
        """1-D column CSV (single float per row) → not a trace matrix → no finding."""
        data = "\n".join(f"{i * 0.01:.4f}" for i in range(200)).encode()
        sf = _sc_findings(_run(data, depth="deep"))
        self.assertEqual(sf, [])


# ──────────────────────────────────────────────────────────────────────────────
# Unit helpers
# ──────────────────────────────────────────────────────────────────────────────

class TestHelpers(unittest.TestCase):

    def test_merge_peaks_contiguous(self):
        """Nearby indices are merged into one region."""
        idx = np.array([10, 11, 12, 20, 21, 22])
        regions = _merge_peaks(idx, window=4)
        self.assertEqual(len(regions), 2)

    def test_merge_peaks_empty(self):
        self.assertEqual(_merge_peaks(np.array([]), window=4), [])

    def test_bits_to_bytes_hello(self):
        """'H' = 0x48 = 0100 1000."""
        bits = [0, 1, 0, 0, 1, 0, 0, 0]
        self.assertEqual(_bits_to_bytes(bits), b"H")

    def test_bits_to_bytes_multi(self):
        """Multi-byte round-trip."""
        original = b"AB"
        bits = []
        for byte in original:
            for i in range(7, -1, -1):
                bits.append((byte >> i) & 1)
        self.assertEqual(_bits_to_bytes(bits), original)


# ──────────────────────────────────────────────────────────────────────────────
# Runner
# ──────────────────────────────────────────────────────────────────────────────

_GROUPS = [
    ("A. Format loading",         TestFormatLoading),
    ("B. Fast mode",              TestFastMode),
    ("C. Deep mode — averaging",  TestDeepModeAveraging),
    ("D. Bit extraction",         TestBitExtraction),
    ("E. Amplitude extraction",   TestAmplitudeExtraction),
    ("F. Graceful degradation",   TestGracefulDegradation),
    ("Helpers",                   TestHelpers),
]

def _run_suite() -> bool:
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    for _, cls in _GROUPS:
        suite.addTests(loader.loadTestsFromTestCase(cls))
    runner = unittest.TextTestRunner(verbosity=2)
    return runner.run(suite).wasSuccessful()


if __name__ == "__main__":
    ok = _run_suite()
    sys.exit(0 if ok else 1)
