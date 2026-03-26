"""
Tests for LSB steganography extraction in analyzers/image.py and analyzers/audio.py.

Coverage:
  A. Image LSB — _check_lsb_pixels()
      1.  Row-major / interleaved RGB / bit-0 / MSB-first  (canonical zsteg variant)
      2.  Row-major / interleaved RGB / bit-0 / LSB-first
      3.  Row-major / sequential RGB  / bit-0 / MSB-first
      4.  Column-major / interleaved RGB / bit-0 / MSB-first
      5.  Bit-plane 1 / row-major / interleaved / MSB-first
      6.  Alpha channel embedding (RGBA image)
      7.  No flag match on random noise image
      8.  Printable non-flag payload → MEDIUM finding emitted
      9.  1×1 image (too small) → no crash
     10.  Non-image file → no crash

  B. Audio LSB — _check_lsb_samples()
     11.  Mono 16-bit / bit-0 / MSB-first  (same as old _check_wav_lsb)
     12.  Mono 16-bit / bit-0 / LSB-first
     13.  Stereo 16-bit, flag in channel 0
     14.  Stereo 16-bit, flag in channel 1
     15.  Stereo interleaved flag (flag spread across both channels interleaved)
     16.  8-bit unsigned mono
     17.  Bit-plane 1 / mono 16-bit / MSB-first
     18.  Random audio → no flag match
     19.  Empty WAV → no crash
     20.  Non-WAV file → no crash

  C. Integration via analyze()
     21.  ImageAnalyzer deep mode finds embedded LSB flag
     22.  ImageAnalyzer fast mode does NOT run LSB extraction
     23.  AudioAnalyzer deep mode finds embedded LSB flag
     24.  AudioAnalyzer fast mode does NOT run LSB extraction

Run from ctf_hunter/ directory:
    python -m unittest tests.test_lsb_steg -v
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

import numpy as np
from PIL import Image

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from analyzers.image import ImageAnalyzer
from analyzers.audio import AudioAnalyzer

FLAG_RE = re.compile(r"flag\{[^}]+\}", re.IGNORECASE)
_IANA = ImageAnalyzer()
_AANA = AudioAnalyzer()


# ---------------------------------------------------------------------------
# Helpers — image
# ---------------------------------------------------------------------------

def _embed_lsb_image(
    flag: str,
    *,
    size: tuple = (80, 80),
    bit_plane: int = 0,
    msb_first: bool = True,
    interleaved: bool = True,
    column_major: bool = False,
    channels: list | None = None,
    mode: str = "RGB",
) -> bytes:
    """Create a PNG with *flag* embedded in the chosen LSB variant."""
    if channels is None:
        channels = [0, 1, 2]

    H, W = size
    n_ch = 4 if mode == "RGBA" else 3
    rng = np.random.RandomState(1234)
    arr = rng.randint(0, 256, (H, W, n_ch), dtype=np.uint8)

    # Build bit stream via numpy (avoids Python int overflow)
    flag_bytes = flag.encode("latin-1")
    bits = np.unpackbits(np.frombuffer(flag_bytes, dtype=np.uint8))
    if not msb_first:
        bits = bits.reshape(-1, 8)[:, ::-1].flatten()

    # Get flat pixel array in correct scan order
    if column_major:
        pix = arr.transpose(1, 0, 2).reshape(-1, n_ch).copy()
    else:
        pix = arr.reshape(-1, n_ch).copy()

    mask = np.uint8(0xFF ^ (1 << bit_plane))

    if interleaved:
        # R0G0B0R1G1B1…
        ch_vals = pix[:, channels].copy()   # (n_pixels, len(channels))
        flat = ch_vals.flatten()
    else:
        # all-R, then all-G, then all-B
        flat = np.concatenate([pix[:, c].copy() for c in channels])

    n_embed = min(len(bits), len(flat))
    flat[:n_embed] = (flat[:n_embed] & mask) | (bits[:n_embed].astype(np.uint8) << bit_plane)

    if interleaved:
        pix[:, channels] = flat[: len(pix) * len(channels)].reshape(-1, len(channels))
    else:
        offset = 0
        for c in channels:
            n = len(pix)
            pix[:, c] = flat[offset: offset + n]
            offset += n

    if column_major:
        arr = pix.reshape(W, H, n_ch).transpose(1, 0, 2)
    else:
        arr = pix.reshape(H, W, n_ch)

    img = Image.fromarray(arr.astype(np.uint8), mode=mode)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def _img_tmp(data: bytes) -> str:
    fd, path = tempfile.mkstemp(suffix=".png")
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    return path


def _run_lsb_img(data: bytes, depth: str = "deep") -> list:
    path = _img_tmp(data)
    try:
        return _IANA._check_lsb_pixels(path, FLAG_RE)
    finally:
        os.unlink(path)


def _run_analyze_img(data: bytes, depth: str = "deep") -> list:
    path = _img_tmp(data)
    try:
        findings = _IANA.analyze(path, FLAG_RE, depth, None)
        return [f for f in findings if "LSB steg" in f.title]
    finally:
        os.unlink(path)


# ---------------------------------------------------------------------------
# Helpers — audio
# ---------------------------------------------------------------------------

def _make_wav(
    samples: list,
    *,
    nchannels: int = 1,
    sampwidth: int = 2,
    framerate: int = 8000,
) -> bytes:
    """Pack samples into a WAV file (bytes). sampwidth=1→uint8, 2→int16."""
    buf = io.BytesIO()
    with wave.open(buf, "wb") as wf:
        wf.setnchannels(nchannels)
        wf.setsampwidth(sampwidth)
        wf.setframerate(framerate)
        if sampwidth == 2:
            raw = struct.pack(f"<{len(samples)}h", *samples)
        else:
            raw = bytes(samples)
        wf.writeframes(raw)
    return buf.getvalue()


def _embed_lsb_audio(
    flag: str,
    n_samples: int = 8000,
    *,
    nchannels: int = 1,
    sampwidth: int = 2,
    bit_plane: int = 0,
    msb_first: bool = True,
    target_channel: int = 0,   # for stereo, which channel carries payload
    use_interleaved: bool = False,
) -> bytes:
    """Create a WAV where *flag* is embedded in the chosen LSB variant."""
    rng = np.random.RandomState(42)
    if sampwidth == 2:
        base = rng.randint(-32768, 32767, n_samples * nchannels).astype(np.int16)
    else:
        base = rng.randint(0, 256, n_samples * nchannels).astype(np.uint8)

    flag_bytes = flag.encode("latin-1")
    bits: list[int] = []
    for b in flag_bytes:
        for i in range(8):
            bits.append((b >> (7 - i)) & 1 if msb_first else (b >> i) & 1)

    if nchannels == 1 or use_interleaved:
        # Embed into flat array (interleaved or mono)
        for i, bit in enumerate(bits[: len(base)]):
            val = int(base[i])
            base[i] = type(base[i])((val & ~(1 << bit_plane)) | (bit << bit_plane))
    else:
        # Embed into a specific channel
        for frame_idx, bit in enumerate(bits):
            flat_idx = frame_idx * nchannels + target_channel
            if flat_idx >= len(base):
                break
            val = int(base[flat_idx])
            base[flat_idx] = type(base[flat_idx])((val & ~(1 << bit_plane)) | (bit << bit_plane))

    return _make_wav(base.tolist(), nchannels=nchannels, sampwidth=sampwidth)


def _wav_tmp(data: bytes) -> str:
    fd, path = tempfile.mkstemp(suffix=".wav")
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    return path


def _run_lsb_audio(data: bytes) -> list:
    path = _wav_tmp(data)
    try:
        return _AANA._check_lsb_samples(path, FLAG_RE)
    finally:
        os.unlink(path)


def _run_analyze_audio(data: bytes, depth: str = "deep") -> list:
    path = _wav_tmp(data)
    try:
        findings = _AANA.analyze(path, FLAG_RE, depth, None)
        return [f for f in findings if "LSB steg" in f.title]
    finally:
        os.unlink(path)


# ===========================================================================
# A — Image LSB
# ===========================================================================

class TestImageLSB(unittest.TestCase):

    def test_a1_row_interleaved_rgb_msb_flag(self):
        """Row-major / interleaved RGB / bit-0 / MSB-first — canonical variant."""
        flag = "flag{lsb_row_interleaved_msb}"
        data = _embed_lsb_image(flag, msb_first=True, interleaved=True)
        findings = _run_lsb_img(data)
        self.assertTrue(any(f.flag_match for f in findings),
                        f"Flag not found; titles={[f.title for f in findings]}")

    def test_a2_row_interleaved_rgb_lsb_flag(self):
        """Row-major / interleaved RGB / bit-0 / LSB-first."""
        flag = "flag{lsb_row_interleaved_lsb}"
        data = _embed_lsb_image(flag, msb_first=False, interleaved=True)
        findings = _run_lsb_img(data)
        self.assertTrue(any(f.flag_match for f in findings),
                        f"Flag not found; titles={[f.title for f in findings]}")

    def test_a3_row_sequential_rgb_msb_flag(self):
        """Row-major / sequential RGB (all-R then all-G then all-B) / bit-0 / MSB-first."""
        flag = "flag{lsb_sequential}"
        data = _embed_lsb_image(flag, msb_first=True, interleaved=False)
        findings = _run_lsb_img(data)
        self.assertTrue(any(f.flag_match for f in findings),
                        f"Flag not found; titles={[f.title for f in findings]}")

    def test_a4_column_major_interleaved_msb_flag(self):
        """Column-major scan / interleaved RGB / bit-0 / MSB-first."""
        flag = "flag{lsb_column_major}"
        data = _embed_lsb_image(flag, msb_first=True, interleaved=True, column_major=True)
        findings = _run_lsb_img(data)
        self.assertTrue(any(f.flag_match for f in findings),
                        f"Flag not found; titles={[f.title for f in findings]}")

    def test_a5_bit_plane_1_msb_flag(self):
        """Bit-plane 1 (second LSB) / row-major / interleaved / MSB-first."""
        flag = "flag{lsb_bit_plane_1}"
        data = _embed_lsb_image(flag, bit_plane=1, msb_first=True, interleaved=True)
        findings = _run_lsb_img(data)
        self.assertTrue(any(f.flag_match for f in findings),
                        f"Flag not found; titles={[f.title for f in findings]}")

    def test_a6_rgba_alpha_channel_flag(self):
        """Alpha channel of an RGBA image carries the payload."""
        flag = "flag{lsb_alpha_channel}"
        data = _embed_lsb_image(flag, channels=[3], interleaved=True, mode="RGBA")
        findings = _run_lsb_img(data)
        self.assertTrue(any(f.flag_match for f in findings),
                        f"Flag not found in alpha channel; titles={[f.title for f in findings]}")

    def test_a7_random_noise_no_flag_match(self):
        """Purely random image must not produce a flag-match finding."""
        rng = np.random.RandomState(999)
        arr = rng.randint(0, 256, (64, 64, 3), dtype=np.uint8)
        img = Image.fromarray(arr)
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        findings = _run_lsb_img(buf.getvalue())
        flag_matches = [f for f in findings if f.flag_match]
        self.assertEqual(flag_matches, [],
                         f"False flag matches: {[f.title for f in flag_matches]}")

    def test_a8_printable_payload_medium_finding(self):
        """Non-flag printable text (≥1000 bytes) embedded → MEDIUM finding (no flag_match).

        The printable-ratio check samples byte_vals[:1000], so the payload must
        fill at least 1000 of those positions with printable data.
        """
        # "Hello CTF world! " repeated 60× = 1080 bytes, all printable, no flag{}.
        payload = ("Hello CTF world! " * 60).encode("ascii")
        # Embed using the same helper (row/interleaved/MSB) to guarantee coverage
        data = _embed_lsb_image(
            payload.decode("ascii"),
            size=(80, 80),
            msb_first=True,
            interleaved=True,
        )
        findings = _run_lsb_img(data)
        medium = [f for f in findings if not f.flag_match and f.severity == "MEDIUM"]
        self.assertTrue(len(medium) >= 1,
                        f"Expected at least one MEDIUM finding; got {[f.title for f in findings]}")

    def test_a9_single_pixel_no_crash(self):
        """1×1 image (below byte threshold) must not raise."""
        arr = np.array([[[128, 64, 32]]], dtype=np.uint8)
        img = Image.fromarray(arr)
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        try:
            _run_lsb_img(buf.getvalue())
        except Exception as exc:
            self.fail(f"1×1 image raised: {exc}")

    def test_a10_non_image_no_crash(self):
        """Non-image binary must not raise."""
        path = tempfile.mktemp(suffix=".png")
        try:
            with open(path, "wb") as f:
                f.write(b"\x00\x01\x02\x03" * 100)
            result = _IANA._check_lsb_pixels(path, FLAG_RE)
            self.assertIsInstance(result, list)
        finally:
            if os.path.exists(path):
                os.unlink(path)


# ===========================================================================
# B — Audio LSB
# ===========================================================================

class TestAudioLSB(unittest.TestCase):

    def test_b11_mono_16bit_msb_flag(self):
        """Mono 16-bit / bit-0 / MSB-first — matches old _check_wav_lsb behaviour."""
        flag = "flag{audio_mono_16_msb}"
        data = _embed_lsb_audio(flag, msb_first=True)
        findings = _run_lsb_audio(data)
        self.assertTrue(any(f.flag_match for f in findings),
                        f"Flag not found; titles={[f.title for f in findings]}")

    def test_b12_mono_16bit_lsb_flag(self):
        """Mono 16-bit / bit-0 / LSB-first."""
        flag = "flag{audio_mono_16_lsb}"
        data = _embed_lsb_audio(flag, msb_first=False)
        findings = _run_lsb_audio(data)
        self.assertTrue(any(f.flag_match for f in findings),
                        f"Flag not found; titles={[f.title for f in findings]}")

    def test_b13_stereo_16bit_ch0_flag(self):
        """Stereo 16-bit — flag embedded in channel 0."""
        flag = "flag{audio_stereo_ch0}"
        data = _embed_lsb_audio(flag, nchannels=2, target_channel=0)
        findings = _run_lsb_audio(data)
        self.assertTrue(any(f.flag_match for f in findings),
                        f"Flag not found in ch0; titles={[f.title for f in findings]}")

    def test_b14_stereo_16bit_ch1_flag(self):
        """Stereo 16-bit — flag embedded in channel 1."""
        flag = "flag{audio_stereo_ch1}"
        data = _embed_lsb_audio(flag, nchannels=2, target_channel=1)
        findings = _run_lsb_audio(data)
        self.assertTrue(any(f.flag_match for f in findings),
                        f"Flag not found in ch1; titles={[f.title for f in findings]}")

    def test_b15_stereo_interleaved_flag(self):
        """Stereo interleaved — flag spread across both channels."""
        flag = "flag{audio_interleaved}"
        data = _embed_lsb_audio(flag, nchannels=2, use_interleaved=True)
        findings = _run_lsb_audio(data)
        self.assertTrue(any(f.flag_match for f in findings),
                        f"Flag not found in interleaved; titles={[f.title for f in findings]}")

    def test_b16_8bit_unsigned_mono_flag(self):
        """8-bit unsigned PCM mono — flag in bit-0 MSB-first."""
        flag = "flag{audio_8bit}"
        data = _embed_lsb_audio(flag, sampwidth=1)
        findings = _run_lsb_audio(data)
        self.assertTrue(any(f.flag_match for f in findings),
                        f"Flag not found in 8-bit; titles={[f.title for f in findings]}")

    def test_b17_bit_plane_1_flag(self):
        """Bit-plane 1 (second LSB) / mono 16-bit / MSB-first."""
        flag = "flag{audio_bit_plane_1}"
        data = _embed_lsb_audio(flag, bit_plane=1)
        findings = _run_lsb_audio(data)
        self.assertTrue(any(f.flag_match for f in findings),
                        f"Flag not found in bit-plane 1; titles={[f.title for f in findings]}")

    def test_b18_random_audio_no_flag_match(self):
        """Purely random audio must not produce a flag-match finding."""
        rng = np.random.RandomState(55)
        samples = rng.randint(-32768, 32767, 8000).tolist()
        data = _make_wav(samples)
        findings = _run_lsb_audio(data)
        flag_matches = [f for f in findings if f.flag_match]
        self.assertEqual(flag_matches, [],
                         f"False matches: {[f.title for f in flag_matches]}")

    def test_b19_empty_wav_no_crash(self):
        """WAV with zero frames must not raise."""
        data = _make_wav([])
        try:
            _run_lsb_audio(data)
        except Exception as exc:
            self.fail(f"Empty WAV raised: {exc}")

    def test_b20_non_wav_no_crash(self):
        """Non-WAV file must not raise."""
        path = tempfile.mktemp(suffix=".wav")
        try:
            with open(path, "wb") as f:
                f.write(b"\x00\x01\x02\x03" * 100)
            result = _AANA._check_lsb_samples(path, FLAG_RE)
            self.assertIsInstance(result, list)
        finally:
            if os.path.exists(path):
                os.unlink(path)


# ===========================================================================
# C — Integration via analyze()
# ===========================================================================

class TestLSBIntegration(unittest.TestCase):

    def test_c21_image_deep_mode_finds_flag(self):
        """ImageAnalyzer.analyze() deep mode finds LSB-embedded flag."""
        flag = "flag{image_deep_integration}"
        data = _embed_lsb_image(flag, msb_first=True, interleaved=True)
        findings = _run_analyze_img(data, depth="deep")
        self.assertTrue(any(f.flag_match for f in findings),
                        f"Deep mode: flag not found; titles={[f.title for f in findings]}")

    def test_c22_image_fast_mode_no_lsb(self):
        """ImageAnalyzer.analyze() fast mode does NOT run LSB extraction."""
        flag = "flag{image_fast_skip}"
        data = _embed_lsb_image(flag, msb_first=True, interleaved=True)
        findings = _run_analyze_img(data, depth="fast")
        # LSB findings must be absent in fast mode
        self.assertEqual(findings, [],
                         f"Fast mode should skip LSB; got {[f.title for f in findings]}")

    def test_c23_audio_deep_mode_finds_flag(self):
        """AudioAnalyzer.analyze() deep mode finds LSB-embedded flag."""
        flag = "flag{audio_deep_integration}"
        data = _embed_lsb_audio(flag, msb_first=True)
        findings = _run_analyze_audio(data, depth="deep")
        self.assertTrue(any(f.flag_match for f in findings),
                        f"Deep mode: flag not found; titles={[f.title for f in findings]}")

    def test_c24_audio_fast_mode_no_lsb(self):
        """AudioAnalyzer.analyze() fast mode does NOT run LSB extraction."""
        flag = "flag{audio_fast_skip}"
        data = _embed_lsb_audio(flag, msb_first=True)
        findings = _run_analyze_audio(data, depth="fast")
        self.assertEqual(findings, [],
                         f"Fast mode should skip LSB; got {[f.title for f in findings]}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
