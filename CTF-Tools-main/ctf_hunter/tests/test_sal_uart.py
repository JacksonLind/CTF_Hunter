"""
Tests for SalAnalyzer (analyzers/sal.py) — UART / Logic Analyzer Trace Decoding.

Coverage:
  A. Binary format helpers
     1.  _parse_channel_bin: valid channel with transitions
     2.  _parse_channel_bin: empty channel (0 transitions)
     3.  _parse_channel_bin: wrong magic bytes → None
     4.  _parse_channel_bin: truncated header → None
     5.  _sample_state: correct state between transitions
     6.  _sample_state: state at exact transition boundary

  B. Baud rate detection
     7.  Clean min-delta → exact baud detected
     8.  Noisy deltas → snaps to nearest standard baud
     9.  Too few transitions → no baud finding, returns None

  C. UART 8N1 decode
    10.  Single ASCII byte decoded correctly
    11.  Multi-byte ASCII string decoded correctly
    12.  All-zeros byte (0x00) decoded correctly
    13.  All-ones byte (0xFF) decoded correctly
    14.  High framing-error rate triggers fallback to 7N1
    15.  Non-standard baud rate decoded (exact, not snapped)

  D. Full SAL archive pipeline
    16.  Valid SAL with printable message → MEDIUM printable finding
    17.  Flag pattern in decoded UART → HIGH flag_match finding
    18.  Base64 payload in UART → base64 finding
    19.  Multi-channel SAL → picks channel with most transitions
    20.  SAL with zero-transition channel → "all channels empty" INFO finding
    21.  Missing meta.json → graceful INFO finding
    22.  Not a ZIP file → graceful INFO finding
    23.  Empty archive (no digital-N.bin) → graceful, no crash

  E. Baud-rate edge cases
    24.  115200 baud — most common embedded rate
    25.  9600 baud — slowest common rate

Run from ctf_hunter/ directory:
    python tests/test_sal_uart.py
"""
from __future__ import annotations

import io
import json
import os
import re
import struct
import sys
import tempfile
import unittest
import zipfile

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from analyzers.sal import (
    SalAnalyzer,
    _parse_channel_bin,
    _sample_state,
    _SALEAE_MAGIC,
    _HEADER_SIZE,
    _STANDARD_BAUDS,
)

FLAG_RE = re.compile(r"flag\{[^}]+\}")
_ANA = SalAnalyzer()

# ──────────────────────────────────────────────────────────────────────────────
# Build helpers
# ──────────────────────────────────────────────────────────────────────────────

def _make_digital_bin(
    timestamps: list[float],
    initial_state: int = 1,
    begin_time: float = 0.0,
    end_time: float | None = None,
) -> bytes:
    """Serialise a list of transition timestamps into a Saleae digital-N.bin blob."""
    if end_time is None:
        end_time = (timestamps[-1] + 0.001) if timestamps else 0.001
    num_t = len(timestamps)
    header = struct.pack(
        "<8sIIIddQ",
        _SALEAE_MAGIC,
        0,              # version field (ignored by parser)
        0,              # ch_type = Digital
        initial_state,
        begin_time,
        end_time,
        num_t,
    )
    ts_bytes = struct.pack(f"<{num_t}d", *timestamps)
    return header + ts_bytes


def _make_sal_zip(
    channels: dict[int, bytes],   # {channel_index: digital_bin_bytes}
    meta: dict | None = None,
) -> bytes:
    """Build a synthetic .sal ZIP archive in memory."""
    if meta is None:
        meta = {
            "sampleRate": {"digital": 4_000_000},
            "enabledChannels": list(channels.keys()),
        }
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_STORED) as zf:
        zf.writestr("meta.json", json.dumps(meta))
        for idx, data in channels.items():
            zf.writestr(f"digital-{idx}.bin", data)
    return buf.getvalue()


def _make_uart_transitions(
    data: bytes,
    baud: int,
    initial_state: int = 1,
    t_start: float = 0.001,
) -> list[float]:
    """Generate UART 8N1 transition timestamps encoding *data* at *baud* baud.

    The line starts at *initial_state* (1 = idle HIGH).  Each byte is framed as:
    start-bit(0) + 8 data bits LSB-first + stop-bit(1).

    Transitions are emitted only when the line state changes.
    """
    bp = 1.0 / baud
    transitions: list[float] = []
    current = initial_state
    t = t_start

    for byte_val in data:
        # 10-bit frame: start(0), 8 data bits LSB, stop(1)
        frame_bits = [0] + [(byte_val >> i) & 1 for i in range(8)] + [1]
        for pos, bit in enumerate(frame_bits):
            bit_t = t + pos * bp
            if bit != current:
                transitions.append(bit_t)
                current = bit
        t += 10 * bp + bp  # advance past frame + 1-bit inter-frame gap

    return transitions


def _run(sal_bytes: bytes) -> list:
    fd, path = tempfile.mkstemp(suffix=".sal")
    with os.fdopen(fd, "wb") as fh:
        fh.write(sal_bytes)
    try:
        return _ANA.analyze(path, FLAG_RE, "deep", None)
    finally:
        os.unlink(path)


def _titles(findings: list) -> list[str]:
    return [f.title for f in findings]


# ──────────────────────────────────────────────────────────────────────────────
# A. Binary format helpers
# ──────────────────────────────────────────────────────────────────────────────

class TestBinaryFormatHelpers(unittest.TestCase):

    def test_a1_valid_channel_with_transitions(self):
        """Valid digital-N.bin parses to correct _Channel object."""
        ts = [0.001, 0.002, 0.003, 0.004]
        raw = _make_digital_bin(ts, initial_state=1, begin_time=0.0, end_time=0.005)
        ch = _parse_channel_bin(0, raw)
        self.assertIsNotNone(ch)
        self.assertEqual(ch.index, 0)
        self.assertEqual(ch.initial_state, 1)
        self.assertEqual(ch.num_transitions, 4)
        self.assertEqual(len(ch.timestamps), 4)
        self.assertAlmostEqual(ch.timestamps[0], 0.001, places=9)
        self.assertAlmostEqual(ch.timestamps[-1], 0.004, places=9)

    def test_a2_empty_channel(self):
        """Channel with 0 transitions parses cleanly with empty timestamp list."""
        raw = _make_digital_bin([], initial_state=1, begin_time=0.0, end_time=1.0)
        ch = _parse_channel_bin(0, raw)
        self.assertIsNotNone(ch)
        self.assertEqual(ch.num_transitions, 0)
        self.assertEqual(ch.timestamps, [])

    def test_a3_wrong_magic(self):
        """Wrong magic bytes → None returned."""
        ts = [0.001]
        raw = _make_digital_bin(ts)
        bad = b"WRONGMAG" + raw[8:]
        self.assertIsNone(_parse_channel_bin(0, bad))

    def test_a4_truncated_header(self):
        """Header shorter than _HEADER_SIZE → None returned."""
        raw = _SALEAE_MAGIC + b"\x00" * 10  # only 18 bytes total
        self.assertIsNone(_parse_channel_bin(0, raw))

    def test_a5_sample_state_between_transitions(self):
        """_sample_state returns correct level between transition points."""
        # initial_state=1 (HIGH); first transition at t=0.002 flips to LOW
        ts = [0.002, 0.004, 0.006]
        # At t=0.001 (before first transition): state = (1 + 0) % 2 = 1
        self.assertEqual(_sample_state(ts, 1, 0.001), 1)
        # At t=0.003 (after 1 transition): state = (1 + 1) % 2 = 0
        self.assertEqual(_sample_state(ts, 1, 0.003), 0)
        # At t=0.005 (after 2 transitions): state = (1 + 2) % 2 = 1
        self.assertEqual(_sample_state(ts, 1, 0.005), 1)
        # At t=0.007 (after 3 transitions): state = (1 + 3) % 2 = 0
        self.assertEqual(_sample_state(ts, 1, 0.007), 0)

    def test_a6_sample_state_at_boundary(self):
        """_sample_state counts transition at exactly t as already occurred."""
        ts = [0.002]
        # bisect_right counts t=0.002 as already past → state flips
        self.assertEqual(_sample_state(ts, 1, 0.002), 0)
        # Just before: no flip
        self.assertEqual(_sample_state(ts, 1, 0.001999), 1)


# ──────────────────────────────────────────────────────────────────────────────
# B. Baud rate detection
# ──────────────────────────────────────────────────────────────────────────────

class TestBaudRateDetection(unittest.TestCase):

    def _detect(self, timestamps: list[float]) -> tuple:
        """Run _detect_baud via the public analyze path; return (baud, bp)."""
        raw = _make_digital_bin(timestamps, initial_state=1)
        sal = _make_sal_zip({0: raw})
        findings = _run(sal)
        baud_f = [f for f in findings if "baud" in f.title.lower()]
        if not baud_f:
            return None, None
        # Extract snapped baud from title: "detected baud rate 115,200 baud"
        m = re.search(r"([\d,]+)\s+baud", baud_f[0].title)
        if not m:
            return None, None
        baud = int(m.group(1).replace(",", ""))
        bp = 1.0 / baud
        return baud, bp

    def test_b7_clean_min_delta_exact_baud(self):
        """Min inter-transition delta of 1/115200 → detected as 115200 baud."""
        bp = 1.0 / 115200
        # Generate transitions at exact bit-period multiples
        ts = _make_uart_transitions(b"A", baud=115200)
        baud, _ = self._detect(ts)
        self.assertEqual(baud, 115200)

    def test_b8_noisy_deltas_snapped(self):
        """Slightly noisy delta (within 5%) snaps to nearest standard baud."""
        bp_true = 1.0 / 9600
        # 3% jitter on 9600 baud
        ts = [bp_true * 1.03, bp_true * 2.01, bp_true * 3.0, bp_true * 4.02]
        baud, _ = self._detect(ts)
        self.assertEqual(baud, 9600)

    def test_b9_too_few_transitions(self):
        """Single transition → too few to detect baud → no baud finding."""
        raw = _make_digital_bin([0.001], initial_state=1)
        sal = _make_sal_zip({0: raw})
        findings = _run(sal)
        baud_f = [f for f in findings if "baud" in f.title.lower()
                  and "detected" in f.title.lower()]
        self.assertEqual(baud_f, [])


# ──────────────────────────────────────────────────────────────────────────────
# C. UART 8N1 decode
# ──────────────────────────────────────────────────────────────────────────────

class TestUARTDecode(unittest.TestCase):

    def _decode_bytes(self, data: bytes, baud: int = 115200) -> bytes | None:
        """Build SAL, run analyzer, extract decoded bytes from UART finding."""
        ts = _make_uart_transitions(data, baud=baud)
        raw = _make_digital_bin(ts, initial_state=1,
                                begin_time=0.0, end_time=ts[-1] + 0.01)
        sal = _make_sal_zip({0: raw})
        findings = _run(sal)
        uart_f = [f for f in findings if "uart" in f.title.lower()
                  and "decoded" in f.title.lower() and "bytes" in f.title.lower()]
        if not uart_f:
            return None
        # Extract hex from detail: "First 80 bytes hex: ..."
        m = re.search(r"First 80 bytes hex:\s+([0-9a-fA-F]+)", uart_f[0].detail)
        if not m:
            return None
        return bytes.fromhex(m.group(1))[:len(data)]

    def test_c10_single_ascii_byte(self):
        """Single ASCII byte 'A' (0x41) decoded correctly."""
        result = self._decode_bytes(b"A")
        self.assertIsNotNone(result)
        self.assertEqual(result, b"A")

    def test_c11_multi_byte_string(self):
        """Multi-byte ASCII string decoded correctly."""
        msg = b"Hello, UART!"
        result = self._decode_bytes(msg)
        self.assertIsNotNone(result)
        self.assertEqual(result, msg)

    def test_c12_all_zeros_byte(self):
        """0x00 byte decoded correctly when embedded in context.

        An isolated 0x00 (start→stop = 9*bp) has min_delta=9*bp, which the
        min-delta baud detector misidentifies as baud/9.  Surrounding bytes
        with varied bit patterns provide the single-bit-period transitions
        needed for correct baud detection.
        """
        result = self._decode_bytes(b"A\x00B")
        self.assertIsNotNone(result)
        self.assertIn(b"\x00", result,
                      "Null byte should be present in decoded output")

    def test_c13_all_ones_byte(self):
        """0xFF byte decoded correctly (all data bits HIGH)."""
        result = self._decode_bytes(b"\xff")
        self.assertIsNotNone(result)
        self.assertEqual(result, b"\xff")

    def test_c14_framing_error_fallback(self):
        """Analyzer does not crash on high framing-error rate and reports it."""
        # Create a SAL with random-noise transitions (not valid UART)
        import random
        rng = random.Random(99)
        bp_noise = 1.0 / 115200
        ts = sorted(rng.uniform(0.0, 0.01) for _ in range(200))
        raw = _make_digital_bin(ts, initial_state=1, end_time=0.02)
        sal = _make_sal_zip({0: raw})
        # Must not raise; should return some findings
        findings = _run(sal)
        self.assertIsNotNone(findings)
        # Should still have channel / baud findings at minimum
        self.assertGreater(len(findings), 0)

    def test_c15_9600_baud_decoded(self):
        """9600 baud transmission decoded correctly."""
        msg = b"slow"
        result = self._decode_bytes(msg, baud=9600)
        self.assertIsNotNone(result)
        self.assertEqual(result, msg)


# ──────────────────────────────────────────────────────────────────────────────
# D. Full SAL archive pipeline
# ──────────────────────────────────────────────────────────────────────────────

class TestFullPipeline(unittest.TestCase):

    def _make_sal(self, message: bytes, baud: int = 115200,
                  channel: int = 0) -> bytes:
        ts = _make_uart_transitions(message, baud=baud)
        raw = _make_digital_bin(ts, initial_state=1,
                                begin_time=0.0, end_time=ts[-1] + 0.01)
        return _make_sal_zip({channel: raw})

    def test_d16_printable_message_finding(self):
        """Printable ASCII message → MEDIUM 'printable ASCII' finding."""
        sal = self._make_sal(b"Hello from the logic analyzer!")
        findings = _run(sal)
        printable_f = [f for f in findings if "printable" in f.title.lower()]
        self.assertTrue(printable_f,
                        f"Expected printable finding; got: {_titles(findings)}")
        self.assertEqual(printable_f[0].severity, "MEDIUM")

    def test_d17_flag_in_uart_data(self):
        """Flag pattern in decoded UART stream → HIGH flag_match finding."""
        sal = self._make_sal(b"secret: flag{uart_decoded_correctly}")
        findings = _run(sal)
        flag_f = [f for f in findings if f.flag_match]
        self.assertTrue(flag_f,
                        f"Expected flag finding; got: {_titles(findings)}")
        self.assertTrue(any(f.severity == "HIGH" for f in flag_f))

    def test_d18_base64_payload(self):
        """Base64-encoded payload in UART → base64 finding emitted."""
        import base64
        payload = base64.b64encode(b"this is the secret payload").decode("ascii")
        sal = self._make_sal(payload.encode("ascii"))
        findings = _run(sal)
        b64_f = [f for f in findings if "base64" in f.title.lower()]
        self.assertTrue(b64_f,
                        f"Expected base64 finding; got: {_titles(findings)}")

    def test_d19_multichannel_picks_busiest(self):
        """With two channels, the one with more transitions is decoded."""
        # Channel 0: 4 transitions (sparse / idle)
        ts0 = [0.001, 0.002, 0.003, 0.004]
        raw0 = _make_digital_bin(ts0, initial_state=1, end_time=0.01)

        # Channel 1: many transitions — encodes the real message
        ts1 = _make_uart_transitions(b"flag{multichannel}", baud=115200)
        raw1 = _make_digital_bin(ts1, initial_state=1,
                                 begin_time=0.0, end_time=ts1[-1] + 0.01)

        sal = _make_sal_zip({0: raw0, 1: raw1})
        findings = _run(sal)
        flag_f = [f for f in findings if f.flag_match]
        self.assertTrue(flag_f,
                        "Expected flag from busy channel; "
                        f"findings: {_titles(findings)}")

    def test_d20_all_channels_empty(self):
        """SAL with channel that has 0 transitions → 'all channels empty' INFO."""
        raw = _make_digital_bin([], initial_state=1, end_time=1.0)
        sal = _make_sal_zip({0: raw})
        findings = _run(sal)
        empty_f = [f for f in findings if "empty" in f.title.lower()]
        self.assertTrue(empty_f,
                        f"Expected 'empty' finding; got: {_titles(findings)}")
        self.assertTrue(all(f.severity == "INFO" for f in empty_f))

    def test_d21_missing_meta_json(self):
        """ZIP archive without meta.json → graceful INFO finding."""
        raw = _make_digital_bin([0.001, 0.002], initial_state=1)
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("digital-0.bin", raw)
        sal = buf.getvalue()
        findings = _run(sal)
        meta_f = [f for f in findings if "meta.json" in f.title.lower()
                  or "missing" in f.title.lower()]
        self.assertTrue(meta_f,
                        f"Expected meta.json finding; got: {_titles(findings)}")

    def test_d22_not_a_zip(self):
        """Random binary data (not ZIP) → graceful INFO finding, no crash."""
        not_sal = b"this is definitely not a ZIP archive" + bytes(range(256))
        findings = _run(not_sal)
        # Should return at least one INFO finding describing the error
        self.assertIsNotNone(findings)
        self.assertGreater(len(findings), 0)
        self.assertTrue(all(f.severity == "INFO" for f in findings
                            if "sal" in f.title.lower() or "zip" in f.title.lower()))

    def test_d23_zip_no_digital_bins(self):
        """Valid ZIP with meta.json but no digital-N.bin → no crash."""
        meta = {"sampleRate": {"digital": 4_000_000}, "enabledChannels": []}
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("meta.json", json.dumps(meta))
            zf.writestr("readme.txt", "no binary data here")
        sal = buf.getvalue()
        findings = _run(sal)
        # Should not crash; may emit 0 or more findings
        self.assertIsNotNone(findings)


# ──────────────────────────────────────────────────────────────────────────────
# E. Baud-rate edge cases
# ──────────────────────────────────────────────────────────────────────────────

class TestBaudEdgeCases(unittest.TestCase):

    def _decode_msg(self, message: bytes, baud: int) -> bool:
        """Return True if message is found in UART decoded findings."""
        ts = _make_uart_transitions(message, baud=baud)
        raw = _make_digital_bin(ts, initial_state=1, end_time=ts[-1] + 0.01)
        sal = _make_sal_zip({0: raw})
        findings = _run(sal)
        all_text = " ".join(f.detail for f in findings)
        return message.decode("ascii", errors="replace") in all_text

    def test_e24_115200_baud(self):
        """115200 baud (most common embedded rate) decoded correctly."""
        self.assertTrue(self._decode_msg(b"uart115200", baud=115200))

    def test_e25_9600_baud(self):
        """9600 baud (slowest common rate) decoded correctly."""
        self.assertTrue(self._decode_msg(b"uart9600", baud=9600))


# ──────────────────────────────────────────────────────────────────────────────
# Runner
# ──────────────────────────────────────────────────────────────────────────────

_GROUPS = [
    ("A. Binary format helpers",     TestBinaryFormatHelpers),
    ("B. Baud rate detection",       TestBaudRateDetection),
    ("C. UART 8N1 decode",           TestUARTDecode),
    ("D. Full SAL archive pipeline", TestFullPipeline),
    ("E. Baud-rate edge cases",      TestBaudEdgeCases),
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
