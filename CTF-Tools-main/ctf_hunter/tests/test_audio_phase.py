"""
Tests for AudioAnalyzer phase cancellation + spectrogram steganography.

Covers:
  A. Phase cancellation detects differing dual-track audio (Let the Penguin Live pattern)
  B. Identical dual tracks are ignored (no false positive)
  C. Single-stream spectrogram scan runs without error
  D. Graceful degradation when ffmpeg/imageio-ffmpeg is unavailable
  E. High-variance band triggers spectrogram steg candidate finding
  F. Low-variance band does not trigger (false-positive prevention)
  G. _ffprobe_stream_count fallback (no ffprobe — parses ffmpeg stderr)
  H. WAV LSB extraction (deep mode only)

Run from the ctf_hunter/ directory:
    python tests/test_audio_phase.py
"""
from __future__ import annotations

import os
import re
import struct
import sys
import tempfile
import unittest
import wave
from pathlib import Path
from typing import List
from unittest.mock import MagicMock, patch

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

# Pre-import optional native dependencies so they land in sys.modules BEFORE
# any patch.dict("sys.modules", ...) context.  patch.dict removes keys that
# were added inside its block; if scipy/numpy are first imported inside a
# patched block they get evicted on exit, and the next import attempt fails
# with "cannot load module more than once per process" on Windows.
try:
    import numpy as _np_pre          # noqa: F401
    from scipy import signal          # noqa: F401
    from scipy.io import wavfile      # noqa: F401
    from PIL import Image as _pil_pre # noqa: F401
except ImportError:
    pass

from analyzers.audio import AudioAnalyzer  # noqa: E402

FLAG_PATTERN = re.compile(r"flag\{[^}]+\}")
FLAG_TEXT    = "flag{phase_cancel}"


# ---------------------------------------------------------------------------
# WAV helpers
# ---------------------------------------------------------------------------

def make_wav(samples: list[int], rate: int = 8000, channels: int = 1) -> bytes:
    """Return a minimal 16-bit PCM WAV file as bytes."""
    buf = struct.pack(f"<{len(samples)}h", *samples)
    with tempfile.NamedTemporaryFile(suffix=".wav", delete=False) as fh:
        fname = fh.name
    with wave.open(fname, "wb") as wf:
        wf.setnchannels(channels)
        wf.setsampwidth(2)
        wf.setframerate(rate)
        wf.writeframes(buf)
    data = Path(fname).read_bytes()
    os.unlink(fname)
    return data


def _sine_samples(freq: float, duration_s: float, rate: int = 8000) -> list[int]:
    """Generate a simple sine wave as 16-bit PCM."""
    import math
    n = int(duration_s * rate)
    return [int(16000 * math.sin(2 * math.pi * freq * i / rate)) for i in range(n)]


def _write_tmp(data: bytes, suffix: str) -> str:
    """Write bytes to a temp file and return path."""
    fh = tempfile.NamedTemporaryFile(suffix=suffix, delete=False)
    fh.write(data)
    fh.close()
    return fh.name


# ---------------------------------------------------------------------------
# Mock ffmpeg helpers
# ---------------------------------------------------------------------------

def _mock_ffmpeg_extract_writes_wav(wav_data: bytes):
    """
    Returns a mock for AudioAnalyzer._ffmpeg_extract_stream that writes
    *wav_data* to the out_path argument and returns True.
    """
    def _extract(path, stream_index, out_path, ffmpeg_exe):
        Path(out_path).write_bytes(wav_data)
        return True
    return _extract


def _mock_ffprobe_returns(n: int):
    """Return a _ffprobe_stream_count mock that always returns n."""
    return MagicMock(return_value=n)


# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------

def findings_with_keyword(findings, keyword: str) -> list:
    kw = keyword.lower()
    return [f for f in findings if kw in (f.title or "").lower()
            or kw in (f.detail or "").lower()]


def run_phase_analysis(
    path: str,
    stream_count: int,
    wav_streams: list[bytes],
) -> list:
    """
    Run _phase_cancellation_analysis with mocked ffmpeg layer.
    wav_streams[i] is written to disk when stream i is extracted.

    imageio_ffmpeg is imported locally inside _phase_cancellation_analysis,
    so it must be injected via sys.modules rather than module-attribute patching.
    """
    analyzer = AudioAnalyzer()

    def _extract(src_path, idx, out_path, ffmpeg_exe):
        if idx < len(wav_streams):
            Path(out_path).write_bytes(wav_streams[idx])
            return True
        return False

    mock_iiff = MagicMock()
    mock_iiff.get_ffmpeg_exe.return_value = "/fake/ffmpeg"

    with (
        patch.object(AudioAnalyzer, "_ffprobe_stream_count",
                     staticmethod(_mock_ffprobe_returns(stream_count))),
        patch.object(AudioAnalyzer, "_ffmpeg_extract_stream",
                     staticmethod(_extract)),
        patch.dict("sys.modules", {"imageio_ffmpeg": mock_iiff}),
    ):
        findings = analyzer._phase_cancellation_analysis(path, FLAG_PATTERN)

    return findings


# ---------------------------------------------------------------------------
# A. Phase cancellation detects difference between two streams
# ---------------------------------------------------------------------------

class TestPhaseCancellationDetectsSignal(unittest.TestCase):

    def _run(self, s1_samples, s2_samples):
        wav1 = make_wav(s1_samples)
        wav2 = make_wav(s2_samples)
        with tempfile.NamedTemporaryFile(suffix=".mkv", delete=False) as f:
            f.write(b"\x1aE\xdf\xa3")  # minimal MKV-ish header
            path = f.name
        try:
            return run_phase_analysis(path, 2, [wav1, wav2])
        finally:
            os.unlink(path)

    def test_a1_different_streams_flagged(self):
        """Two streams with different content -> phase-cancellation finding."""
        s1 = _sine_samples(440, 0.5)
        s2 = _sine_samples(880, 0.5)   # different frequency
        findings = self._run(s1, s2)
        cancel = findings_with_keyword(findings, "phase cancellation")
        self.assertTrue(cancel, "Expected phase-cancellation finding for different streams")

    def test_a2_large_delta_reported(self):
        """Max sample delta is included in finding detail."""
        s1 = _sine_samples(440, 0.5)
        s2 = [0] * len(s1)  # silence vs signal -> large delta
        findings = self._run(s1, s2)
        # Only count non-INFO phase-cancellation findings (INFO = skipped/degraded)
        cancel = [f for f in findings_with_keyword(findings, "phase cancellation")
                  if f.severity != "INFO"]
        self.assertTrue(cancel)
        self.assertTrue(any("max sample delta" in (f.detail or "").lower()
                            for f in cancel))


# ---------------------------------------------------------------------------
# B. Identical streams do NOT trigger phase cancellation
# ---------------------------------------------------------------------------

class TestIdenticalStreamsIgnored(unittest.TestCase):

    def test_b1_identical_streams_no_cancel_finding(self):
        """Identical streams -> delta 0 -> no phase-cancellation finding."""
        samples = _sine_samples(440, 0.5)
        wav = make_wav(samples)
        with tempfile.NamedTemporaryFile(suffix=".mkv", delete=False) as f:
            f.write(b"\x1aE\xdf\xa3")
            path = f.name
        try:
            findings = run_phase_analysis(path, 2, [wav, wav])
            # Exclude INFO findings (e.g. "skipped — missing dependency")
            cancel = [f for f in findings_with_keyword(findings, "phase cancellation")
                      if f.severity != "INFO"]
            self.assertEqual(cancel, [],
                             "Identical streams should not produce a phase-cancel finding")
        finally:
            os.unlink(path)


# ---------------------------------------------------------------------------
# C. Single-stream spectrogram scan runs cleanly
# ---------------------------------------------------------------------------

class TestSingleStreamSpectrogram(unittest.TestCase):

    def test_c1_single_stream_no_crash(self):
        """Single audio stream runs through spectrogram code without exception."""
        samples = _sine_samples(440, 2.0)
        wav = make_wav(samples, rate=8000)
        with tempfile.NamedTemporaryFile(suffix=".wav", delete=False) as f:
            f.write(wav)
            path = f.name
        try:
            findings = run_phase_analysis(path, 1, [wav])
            # We just want no crash; the findings list may be empty (low variance)
            self.assertIsInstance(findings, list)
        finally:
            os.unlink(path)


# ---------------------------------------------------------------------------
# D. Graceful degradation — imageio-ffmpeg not installed
# ---------------------------------------------------------------------------

class TestGracefulDegradation(unittest.TestCase):

    def test_d1_no_imageio_ffmpeg_returns_info(self):
        """Missing imageio-ffmpeg -> single INFO finding, no crash."""
        analyzer = AudioAnalyzer()
        with tempfile.NamedTemporaryFile(suffix=".wav", delete=False) as f:
            f.write(b"\x00" * 44)  # tiny dummy file
            path = f.name
        try:
            with patch.dict("sys.modules", {"imageio_ffmpeg": None}):
                findings = analyzer._phase_cancellation_analysis(path, FLAG_PATTERN)
            self.assertIsInstance(findings, list)
            # Should return an INFO finding about the missing dependency
            info = [f for f in findings if f.severity == "INFO"]
            self.assertTrue(info, "Expected INFO finding when imageio-ffmpeg missing")
        finally:
            os.unlink(path)


# ---------------------------------------------------------------------------
# E. High-variance band triggers spectrogram candidate
# ---------------------------------------------------------------------------

class TestHighVarianceBandDetected(unittest.TestCase):

    def _make_high_variance_wav(self) -> bytes:
        """
        Build a WAV whose 11k–16.5k Hz band has high variance.

        Strategy: alternate 0.05 s bursts of 13 kHz tone with 0.05 s silence
        across 2 seconds.  The on/off pattern creates large time-varying power
        in the 11k–16.5k detection band, driving std-dev well above 15.
        """
        import math
        rate = 44100
        burst_len = int(0.05 * rate)  # 50 ms
        n_bursts  = 20                 # 20 × 100 ms = 2 s total
        samples: list[int] = []
        for b in range(n_bursts):
            for i in range(burst_len):
                v = int(28000 * math.sin(2 * math.pi * 13000 * i / rate))
                samples.append(max(-32768, min(32767, v)))
            samples.extend([0] * burst_len)   # silence between bursts
        return make_wav(samples, rate=rate)

    def test_e1_high_variance_band_flagged(self):
        """High-energy 11k-16.5k Hz band triggers spectrogram steg candidate."""
        wav = self._make_high_variance_wav()
        with tempfile.NamedTemporaryFile(suffix=".wav", delete=False) as f:
            f.write(wav)
            path = f.name
        try:
            findings = run_phase_analysis(path, 1, [wav])
            spect = findings_with_keyword(findings, "spectrogram")
            self.assertTrue(spect,
                            "Expected spectrogram steg candidate for high-variance band")
        finally:
            os.unlink(path)


# ---------------------------------------------------------------------------
# F. Low-variance band does NOT trigger (false-positive prevention)
# ---------------------------------------------------------------------------

class TestLowVarianceBandIgnored(unittest.TestCase):

    def test_f1_silence_no_spectrogram_finding(self):
        """All-zero (silence) WAV -> band power is constant -> no steg finding.

        The spectrogram code skips bands where b_max == b_min (prevents divide-by-zero).
        Silence produces exactly this condition across all bands, so no spectrogram
        steg candidate should be emitted.
        Note: a pure tone at any frequency CAN produce a spurious variance hit in
        other bands due to the per-band normalization stretching the noise floor to
        0-255.  Silence is the definitive 'no signal' test case.
        """
        rate = 44100
        n = int(0.5 * rate)
        wav = make_wav([0] * n, rate=rate)
        with tempfile.NamedTemporaryFile(suffix=".wav", delete=False) as f:
            f.write(wav)
            path = f.name
        try:
            findings = run_phase_analysis(path, 1, [wav])
            steg = [f for f in findings
                    if "steg candidate" in (f.title or "").lower()]
            self.assertEqual(steg, [],
                             "Silence should not trigger spectrogram steg")
        finally:
            os.unlink(path)


# ---------------------------------------------------------------------------
# G. _ffprobe_stream_count fallback path (no ffprobe, parses ffmpeg stderr)
# ---------------------------------------------------------------------------

class TestFfprobeStreamCountFallback(unittest.TestCase):

    def test_g1_ffprobe_absent_parses_stderr(self):
        """When ffprobe doesn't exist, _ffprobe_stream_count falls back to ffmpeg stderr."""
        stderr = (
            b"  Stream #0:0: Audio: pcm_s16le, 44100 Hz, stereo\n"
            b"  Stream #0:1: Audio: pcm_s16le, 44100 Hz, mono\n"
        )
        fake_result = MagicMock()
        fake_result.stderr = stderr

        with (
            patch("analyzers.audio.subprocess.run", return_value=fake_result),
            patch("analyzers.audio.Path") as mock_path,
        ):
            # Make Path(ffprobe_exe).exists() return False so we fall through to stderr
            mock_path.return_value.exists.return_value = False
            count = AudioAnalyzer._ffprobe_stream_count(
                "fake.mkv", "/fake/ffprobe", "/fake/ffmpeg"
            )
        self.assertEqual(count, 2)

    def test_g2_ffprobe_present_uses_json(self):
        """When ffprobe exists, _ffprobe_stream_count parses its JSON output."""
        import json
        fake_json = json.dumps({"streams": [{}, {}]}).encode()
        fake_result = MagicMock()
        fake_result.stdout = fake_json

        with (
            patch("analyzers.audio.subprocess.run", return_value=fake_result),
            patch("analyzers.audio.Path") as mock_path,
        ):
            mock_path.return_value.exists.return_value = True
            count = AudioAnalyzer._ffprobe_stream_count(
                "fake.mkv", "/fake/ffprobe", "/fake/ffmpeg"
            )
        self.assertEqual(count, 2)


# ---------------------------------------------------------------------------
# H. WAV LSB extraction (deep mode)
# ---------------------------------------------------------------------------

class TestWavLsbDeepMode(unittest.TestCase):

    def _make_lsb_wav(self, message: bytes) -> bytes:
        """Encode *message* as LSBs of a 16-bit mono WAV."""
        bits = []
        for byte in message:
            for i in range(7, -1, -1):
                bits.append((byte >> i) & 1)
        # Pad to multiple of 8
        while len(bits) % 8 != 0:
            bits.append(0)
        # Build samples: carrier is 1000 (arbitrary), LSB set from bits
        samples = []
        for b in bits:
            carrier = 1000
            samples.append((carrier & ~1) | b)
        # Pad to at least 21 samples for the printable check
        while len(samples) < 200:
            samples.append(1000)
        return make_wav(samples, rate=8000, channels=1)

    def test_h1_lsb_printable_text_extracted(self):
        """Deep mode: printable LSB data extracted from WAV samples."""
        msg = b"flag{lsb_test}" + b"A" * 20
        wav_data = self._make_lsb_wav(msg)
        path = _write_tmp(wav_data, ".wav")
        try:
            analyzer = AudioAnalyzer()
            findings = analyzer._check_wav_lsb(path, FLAG_PATTERN)
            self.assertTrue(findings, "Expected LSB extraction finding")
            fm_findings = [f for f in findings if f.flag_match]
            self.assertTrue(fm_findings, "Expected flag_match in LSB findings")
        finally:
            os.unlink(path)

    def test_h2_deep_mode_includes_lsb_check(self):
        """analyze() in deep mode runs LSB extraction and finds the flag."""
        msg = b"flag{lsb_deep}" + b"B" * 20
        wav_data = self._make_lsb_wav(msg)
        path = _write_tmp(wav_data, ".wav")
        try:
            with patch.object(AudioAnalyzer, "_phase_cancellation_analysis",
                              return_value=[]):
                analyzer = AudioAnalyzer()
                findings = analyzer.analyze(path, FLAG_PATTERN, "deep", None)
            fm = [f for f in findings if f.flag_match]
            self.assertTrue(fm, "deep mode should find flag in WAV LSB")
        finally:
            os.unlink(path)

    def test_h3_fast_mode_skips_lsb_check(self):
        """analyze() in fast mode does NOT run _check_lsb_samples."""
        with patch.object(AudioAnalyzer, "_check_lsb_samples") as mock_lsb, \
             patch.object(AudioAnalyzer, "_phase_cancellation_analysis",
                          return_value=[]):
            wav_data = make_wav([1000] * 100)
            path = _write_tmp(wav_data, ".wav")
            try:
                analyzer = AudioAnalyzer()
                analyzer.analyze(path, FLAG_PATTERN, "fast", None)
                mock_lsb.assert_not_called()
            finally:
                os.unlink(path)


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("Audio phase cancellation + spectrogram steg tests\n")
    loader = unittest.TestLoader()
    suite  = unittest.TestSuite()

    groups = [
        ("A. Phase cancellation detects signal",    TestPhaseCancellationDetectsSignal),
        ("B. Identical streams ignored",             TestIdenticalStreamsIgnored),
        ("C. Single-stream spectrogram",             TestSingleStreamSpectrogram),
        ("D. Graceful degradation (no ffmpeg)",      TestGracefulDegradation),
        ("E. High-variance band detected",           TestHighVarianceBandDetected),
        ("F. Low-variance band ignored",             TestLowVarianceBandIgnored),
        ("G. ffprobe stream count fallback",         TestFfprobeStreamCountFallback),
        ("H. WAV LSB extraction (deep mode)",        TestWavLsbDeepMode),
    ]

    results = []
    devnull = open(os.devnull, "w")
    for label, cls in groups:
        print(f"\n--- {label} ---")
        for test in loader.loadTestsFromTestCase(cls):
            single = unittest.TestSuite([test])
            r = unittest.TextTestRunner(verbosity=0, stream=devnull).run(single)
            status = "FAIL" if r.failures or r.errors else "PASS"
            print(f"  [{status}]  {test._testMethodName}")
            results.append(not (r.failures or r.errors))
    devnull.close()

    passed = sum(results)
    total  = len(results)
    print(f"\n{passed}/{total} passed")
    sys.exit(0 if passed == total else 1)
