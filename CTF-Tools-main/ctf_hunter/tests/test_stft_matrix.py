"""
Tests for STFT matrix detection and inversion in analyzers/generic.py.

Coverage:
  A. Detection and mode gating
     1. STFT header in fast mode → INFO finding, no parse
     2. STFT header in deep mode → MEDIUM finding with raw_hex=
     3. No header, count matches common n_fft → shape inferred, finding emitted
     4. Header present but value count mismatch → mismatch INFO finding

  B. Output correctness
     5. raw_hex= decodes to valid RIFF/WAV bytes
     6. Reconstructed audio duration matches expected (±10 %)
     7. WAV contains correct sample rate (16 000 Hz) and channel count (1)

  C. Complex number format tolerance
     8. (a+bj) format parsed correctly
     9. a+bj format (no parens) parsed correctly
    10. Scientific notation values parsed correctly

  D. Graceful degradation
    11. Binary file → no finding
    12. Plain text with no complex numbers → no finding
    13. Text file with only real numbers → no finding (< 3 complex values)

Run from ctf_hunter/ directory:
    python tests/test_stft_matrix.py
"""
from __future__ import annotations

import io
import os
import re
import struct
import sys
import tempfile
import unittest
import wave

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

import numpy as np
from scipy.signal import stft as _scipy_stft

from analyzers.generic import GenericAnalyzer

FLAG_PATTERN = re.compile(r"flag\{[^}]+\}")
_ANA = GenericAnalyzer()

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_N_FFT   = 256
_HOP     = 128
_FS      = 16_000
_ROWS    = _N_FFT // 2 + 1   # 129


def _make_stft_text(
    n_seconds: float = 0.5,
    include_header: bool = True,
    header_shape: tuple | None = None,
    fmt: str = "paren",   # "paren" = (a+bj), "bare" = a+bj
    sci: bool = False,
) -> bytes:
    """Generate a synthetic STFT text file from a 440 Hz sine wave.

    Parameters
    ----------
    n_seconds:
        Duration of the synthesised signal.
    include_header:
        Whether to prepend the ``# STFT shape: ...`` comment.
    header_shape:
        Override the shape written in the header (for mismatch tests).
    fmt:
        ``"paren"`` → ``(a+bj)`` per line; ``"bare"`` → ``a+bj`` per line.
    sci:
        If True, force scientific-notation formatting.
    """
    n_samples = int(n_seconds * _FS)
    t = np.linspace(0, n_seconds, n_samples, endpoint=False)
    signal = np.sin(2 * np.pi * 440 * t).astype(np.float32)

    _, _, Zxx = _scipy_stft(
        signal,
        fs=_FS,
        nperseg=_N_FFT,
        noverlap=_N_FFT - _HOP,
        nfft=_N_FFT,
    )
    # Zxx shape: (n_freq, n_time) = (_ROWS, n_cols)
    rows, cols = Zxx.shape
    flat = Zxx.flatten()

    lines = []
    if include_header:
        shape = header_shape or (rows, cols)
        lines.append(f"# STFT shape: complex64 ({shape[0]}, {shape[1]})")
    for v in flat:
        r, i = float(v.real), float(v.imag)
        if sci:
            s = f"{r:.6e}+{i:.6e}j" if i >= 0 else f"{r:.6e}{i:.6e}j"
        else:
            s = f"{r}+{i}j" if i >= 0 else f"{r}{i}j"
        if fmt == "paren":
            lines.append(f"({s})")
        else:
            lines.append(s)
    return "\n".join(lines).encode("utf-8")


def _run(data: bytes, depth: str = "deep") -> list:
    fd, path = tempfile.mkstemp(suffix=".txt")
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
    try:
        return _ANA.analyze(path, FLAG_PATTERN, depth, None)
    finally:
        os.unlink(path)


def _stft_findings(findings) -> list:
    return [f for f in findings if "stft" in f.title.lower()]


def _raw_hex_bytes(finding) -> bytes | None:
    m = re.search(r"raw_hex=([0-9a-f]+)", finding.detail, re.IGNORECASE)
    if not m:
        return None
    return bytes.fromhex(m.group(1))


# ---------------------------------------------------------------------------
# A. Detection and mode gating
# ---------------------------------------------------------------------------

class TestDetectionAndModeGating(unittest.TestCase):

    def test_a1_fast_mode_info_only(self):
        """Fast mode: STFT header → INFO finding, no WAV reconstruction."""
        data = _make_stft_text()
        findings = _run(data, depth="fast")
        sf = _stft_findings(findings)
        self.assertTrue(sf, "Expected STFT finding in fast mode")
        self.assertTrue(all(f.severity == "INFO" for f in sf),
                        "Fast-mode STFT findings should be INFO")
        # No raw_hex= in fast mode (no WAV produced)
        self.assertFalse(
            any("raw_hex=" in f.detail for f in sf),
            "Fast mode must not embed WAV bytes",
        )

    def test_a2_deep_mode_wav_emitted(self):
        """Deep mode: STFT header → MEDIUM finding with raw_hex= WAV."""
        data = _make_stft_text()
        findings = _run(data, depth="deep")
        sf = _stft_findings(findings)
        self.assertTrue(sf, f"Expected STFT finding; got: {[f.title for f in findings]}")
        self.assertTrue(
            any("raw_hex=" in f.detail for f in sf),
            "Deep-mode STFT finding must contain raw_hex=",
        )

    def test_a3_no_header_shape_inferred(self):
        """No header but value count divisible by (n_fft/2+1) → shape inferred."""
        data = _make_stft_text(include_header=False)
        findings = _run(data, depth="deep")
        sf = _stft_findings(findings)
        self.assertTrue(sf, "Expected inferred-shape STFT finding")
        self.assertTrue(any("raw_hex=" in f.detail for f in sf))

    def test_a4_header_count_mismatch(self):
        """Header says (999, 999) but actual count differs → mismatch INFO finding."""
        data = _make_stft_text(header_shape=(999, 999))
        findings = _run(data, depth="deep")
        mismatch = [
            f for f in findings
            if "mismatch" in f.title.lower() or "mismatch" in f.detail.lower()
        ]
        self.assertTrue(mismatch, "Expected mismatch finding")


# ---------------------------------------------------------------------------
# B. Output correctness
# ---------------------------------------------------------------------------

class TestOutputCorrectness(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls._data = _make_stft_text(n_seconds=0.5)
        cls._findings = _run(cls._data, depth="deep")
        cls._sf = _stft_findings(cls._findings)
        assert cls._sf, "Setup failed: no STFT findings"
        cls._wav_bytes = _raw_hex_bytes(cls._sf[0])
        assert cls._wav_bytes, "Setup failed: no raw_hex= in finding"

    def test_b5_raw_hex_is_valid_wav(self):
        """raw_hex= decodes to a RIFF/WAV file."""
        self.assertTrue(self._wav_bytes[:4] == b"RIFF",
                        "Decoded bytes should start with RIFF")
        self.assertIn(b"WAVE", self._wav_bytes[:12])

    def test_b6_audio_duration_correct(self):
        """Reconstructed audio duration is within ±10 % of original."""
        buf = io.BytesIO(self._wav_bytes)
        with wave.open(buf, "rb") as wf:
            n_frames = wf.getnframes()
            framerate = wf.getframerate()
        duration = n_frames / framerate
        expected = 0.5
        self.assertAlmostEqual(duration, expected, delta=expected * 0.10,
                               msg=f"Duration {duration:.3f}s vs expected {expected}s")

    def test_b7_wav_params(self):
        """WAV has 1 channel and 16 000 Hz sample rate."""
        buf = io.BytesIO(self._wav_bytes)
        with wave.open(buf, "rb") as wf:
            self.assertEqual(wf.getnchannels(), 1)
            self.assertEqual(wf.getframerate(), 16_000)
            self.assertEqual(wf.getsampwidth(), 2)   # 16-bit


# ---------------------------------------------------------------------------
# C. Complex number format tolerance
# ---------------------------------------------------------------------------

class TestComplexFormatTolerance(unittest.TestCase):

    def test_c8_paren_format(self):
        """(a+bj) format parsed and inverted successfully."""
        data = _make_stft_text(fmt="paren")
        sf = _stft_findings(_run(data, depth="deep"))
        self.assertTrue(sf and any("raw_hex=" in f.detail for f in sf))

    def test_c9_bare_format(self):
        """a+bj format (no parentheses) parsed and inverted successfully."""
        data = _make_stft_text(fmt="bare")
        sf = _stft_findings(_run(data, depth="deep"))
        self.assertTrue(sf and any("raw_hex=" in f.detail for f in sf))

    def test_c10_scientific_notation(self):
        """Scientific-notation complex values parsed and inverted successfully."""
        data = _make_stft_text(sci=True)
        sf = _stft_findings(_run(data, depth="deep"))
        self.assertTrue(sf and any("raw_hex=" in f.detail for f in sf))


# ---------------------------------------------------------------------------
# D. Graceful degradation
# ---------------------------------------------------------------------------

class TestGracefulDegradation(unittest.TestCase):

    def test_d11_binary_file_no_finding(self):
        """Binary file → no STFT finding."""
        data = bytes(range(256)) * 32
        sf = _stft_findings(_run(data, depth="deep"))
        self.assertEqual(sf, [])

    def test_d12_plain_text_no_complex_no_finding(self):
        """Plain prose text → no STFT finding."""
        data = b"The quick brown fox jumps over the lazy dog.\n" * 20
        sf = _stft_findings(_run(data, depth="deep"))
        self.assertEqual(sf, [])

    def test_d13_real_numbers_only_no_finding(self):
        """File with only real-valued numbers (no imaginary parts) → no finding."""
        lines = ["# some data"] + [str(float(i) * 1.1) for i in range(200)]
        data = "\n".join(lines).encode("utf-8")
        sf = _stft_findings(_run(data, depth="deep"))
        self.assertEqual(sf, [])


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def _run_suite() -> bool:
    groups = [
        ("A. Detection and mode gating", TestDetectionAndModeGating),
        ("B. Output correctness",        TestOutputCorrectness),
        ("C. Complex format tolerance",  TestComplexFormatTolerance),
        ("D. Graceful degradation",      TestGracefulDegradation),
    ]
    loader = unittest.TestLoader()
    suite  = unittest.TestSuite()
    for _, cls in groups:
        suite.addTests(loader.loadTestsFromTestCase(cls))
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    return result.wasSuccessful()


if __name__ == "__main__":
    ok = _run_suite()
    sys.exit(0 if ok else 1)
