"""
Tests for the encoding chain BFS auto-solver in analyzers/generic.py.

Coverage:
  A. Individual transform functions
      1.  _chain_b64: correct decode
      2.  _chain_b64: returns None for non-B64 input
      3.  _chain_b64url: handles '-' and '_' chars
      4.  _chain_b32: decodes correctly
      5.  _chain_hex: decodes hex string
      6.  _chain_url: decodes %XX percent-encoding
      7.  _chain_rot13: self-inverse
      8.  _chain_atbash: correct letter mapping
      9.  _chain_reverse: reverses; returns None for palindrome
     10.  _chain_xor_brute: finds key for single-byte XOR'd text
     11.  _chain_zlib: decompresses zlib data
     12.  _chain_binary: decodes 8-bit binary string

  B. Multi-step chain BFS
     13.  Double base64 encoded flag found
     14.  Hex → base64 → flag
     15.  Rot13 → base64 → flag
     16.  Xor → hex → flag
     17.  URL → base64 → flag

  C. Depth / mode behaviour
     18.  Chain longer than _CHAIN_MAX_DEPTH not explored
     19.  Fast mode (depth=4) skips a depth-5 chain but deep finds it
     20.  _chain_is_interesting correctly gates encoding patterns

  D. Integration via _check_encoding_chain
     21.  Single base64-encoded flag in file → finding emitted
     22.  Triple-encoded flag found in deep mode
     23.  Plain English file with no encoding → no false flag match

  E. Edge cases
     24.  Empty byte content → no crash
     25.  Circular rot13 (applied twice) does not loop infinitely
     26.  _chain_xor_brute returns None or a str (never raises)
     27.  _chain_b64 returns None for very short inputs (< 4 chars)

Run from ctf_hunter/ directory:
    python -m unittest tests.test_encoding_chain -v
"""
from __future__ import annotations

import base64
import os
import re
import sys
import tempfile
import unittest
import urllib.parse
import zlib

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from analyzers.generic import (
    GenericAnalyzer,
    _chain_b64,
    _chain_b64url,
    _chain_b32,
    _chain_hex,
    _chain_url,
    _chain_rot13,
    _chain_atbash,
    _chain_reverse,
    _chain_xor_brute,
    _chain_zlib,
    _chain_gzip,
    _chain_binary,
    _chain_is_interesting,
    _CHAIN_MAX_DEPTH,
)

FLAG_RE = re.compile(r"flag\{[^}]+\}", re.IGNORECASE)
_ANA = GenericAnalyzer()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _tmp(content: bytes, suffix: str = ".bin") -> str:
    fd, path = tempfile.mkstemp(suffix=suffix)
    with os.fdopen(fd, "wb") as fh:
        fh.write(content)
    return path


def _run_chain(content: bytes, depth: str = "deep") -> list:
    path = _tmp(content)
    try:
        return _ANA._check_encoding_chain(path, content, FLAG_RE, depth)
    finally:
        os.unlink(path)


def _run_full(content: bytes, depth: str = "deep") -> list:
    path = _tmp(content)
    try:
        all_f = _ANA.analyze(path, FLAG_RE, depth, None)
        return [f for f in all_f if "Encoding chain" in f.title]
    finally:
        os.unlink(path)


def _b64(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


def _hex(s: str) -> str:
    return s.encode().hex()


def _rot13(s: str) -> str:
    return s.translate(str.maketrans(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm",
    ))


def _xor(s: str, key: int) -> bytes:
    return bytes(b ^ key for b in s.encode("latin-1"))


# ===========================================================================
# A — Individual transform functions
# ===========================================================================

class TestIndividualTransforms(unittest.TestCase):

    def test_a1_b64_correct_decode(self):
        plain = "flag{test_base64}"
        result = _chain_b64(_b64(plain))
        self.assertIsNotNone(result)
        self.assertIn(plain, result)

    def test_a2_b64_none_for_non_b64(self):
        self.assertIsNone(_chain_b64("!@#$%^&*()"))

    def test_a3_b64url_handles_dash_underscore(self):
        # Force URL-safe B64 output that contains - or _
        raw = b"\xfb\xef\xbe" + b"flag{url_safe}"
        encoded = base64.urlsafe_b64encode(raw).decode()
        self.assertTrue("-" in encoded or "_" in encoded,
                        "Test setup: encoded must contain - or _")
        result = _chain_b64url(encoded)
        self.assertIsNotNone(result)
        self.assertIn("flag{url_safe}", result)

    def test_a4_b32_decodes_correctly(self):
        plain = "flag{base32}"
        encoded = base64.b32encode(plain.encode()).decode().rstrip("=")
        result = _chain_b32(encoded)
        self.assertIsNotNone(result)
        self.assertIn(plain, result)

    def test_a5_hex_decodes_hex_string(self):
        plain = "flag{hex_decode}"
        result = _chain_hex(_hex(plain))
        self.assertIsNotNone(result)
        self.assertIn(plain, result)

    def test_a6_url_decodes_percent_xx(self):
        plain = "flag{url encoded}"
        encoded = urllib.parse.quote(plain)
        self.assertIn("%", encoded)
        result = _chain_url(encoded)
        self.assertIsNotNone(result)
        self.assertIn(plain, result)

    def test_a7_rot13_is_self_inverse(self):
        original = "flag{rot13_roundtrip}"
        rot13d = _chain_rot13(original)
        self.assertIsNotNone(rot13d)
        restored = _chain_rot13(rot13d)
        self.assertEqual(restored, original)

    def test_a8_atbash_correct_mapping(self):
        # 'a'→'z', 'b'→'y', 'c'→'x', 'z'→'a'
        result = _chain_atbash("abcz")
        self.assertIsNotNone(result)
        self.assertEqual(result.lower(), "zyxa")

    def test_a9_reverse_and_palindrome(self):
        self.assertEqual(_chain_reverse("hello"), "olleh")
        self.assertIsNone(_chain_reverse("racecar"))

    def test_a10_xor_brute_returns_printable_result(self):
        """_chain_xor_brute returns a ≥70% printable string for XOR-obfuscated text.

        The function returns whichever single-byte key yields the highest printable
        ratio — it is not guaranteed to recover the *specific* key used for encryption.
        The contract is: if the plaintext is printable, some key will produce a
        printable result above the threshold.
        """
        plain = "flag{xor_brute_force_works_here_long_enough}"
        key = 0x5A
        xored_str = _xor(plain, key).decode("latin-1")
        result = _chain_xor_brute(xored_str)
        self.assertIsNotNone(result, "Expected a printable result for XOR-obfuscated text")
        printable = sum(1 for c in result if 0x20 <= ord(c) <= 0x7E) / len(result)
        self.assertGreaterEqual(printable, 0.70,
                                f"Result not ≥70% printable: {result!r}")

    def test_a11_zlib_decompresses(self):
        plain = "flag{zlib_compressed}"
        compressed_str = zlib.compress(plain.encode()).decode("latin-1")
        result = _chain_zlib(compressed_str)
        self.assertIsNotNone(result)
        self.assertIn(plain, result)

    def test_a12_binary_decodes_binary_string(self):
        plain = "flag"
        binary = "".join(f"{ord(c):08b}" for c in plain)
        result = _chain_binary(binary)
        self.assertIsNotNone(result)
        self.assertEqual(result, plain)


# ===========================================================================
# B — Multi-step chain BFS
# ===========================================================================

class TestMultiStepChain(unittest.TestCase):

    def test_b13_double_base64_flag(self):
        """flag → b64 → b64: BFS must find it in 2 steps."""
        double = _b64(_b64("flag{double_b64}"))
        findings = _run_chain(double.encode(), depth="deep")
        self.assertTrue(any(f.flag_match for f in findings),
                        f"findings={[f.title for f in findings]}")
        chain_titles = [f.title for f in findings if f.flag_match]
        self.assertTrue(any(t.count("base64") >= 2 for t in chain_titles),
                        f"Expected double-base64 in chain title; got {chain_titles}")

    def test_b14_hex_then_base64_flag(self):
        """flag → b64 → hex: BFS finds via hex → base64."""
        encoded = _hex(_b64("flag{hex_then_b64}"))
        findings = _run_chain(encoded.encode(), depth="deep")
        self.assertTrue(any(f.flag_match for f in findings),
                        f"findings={[f.title for f in findings]}")

    def test_b15_rot13_then_base64_flag(self):
        """flag → b64 → rot13: BFS finds via rot13 → base64."""
        encoded = _rot13(_b64("flag{rot13_then_b64}"))
        findings = _run_chain(encoded.encode(), depth="deep")
        self.assertTrue(any(f.flag_match for f in findings),
                        f"findings={[f.title for f in findings]}")

    def test_b16_xor_then_hex_flag(self):
        """flag → xor(0x42) → hex: BFS finds via hex → xor."""
        xored = _xor("flag{xor_hex_chain}", 0x42)
        encoded = xored.hex()
        findings = _run_chain(encoded.encode(), depth="deep")
        self.assertTrue(any(f.flag_match for f in findings),
                        f"findings={[f.title for f in findings]}")

    def test_b17_url_then_base64_flag(self):
        """flag → b64 → url: BFS finds via url → base64."""
        encoded = urllib.parse.quote(_b64("flag{url_then_b64}"))
        findings = _run_chain(encoded.encode(), depth="deep")
        self.assertTrue(any(f.flag_match for f in findings),
                        f"findings={[f.title for f in findings]}")


# ===========================================================================
# C — Depth / mode behaviour
# ===========================================================================

class TestDepthBehaviour(unittest.TestCase):

    def test_c18_beyond_max_depth_not_explored(self):
        """A chain requiring depth > _CHAIN_MAX_DEPTH must not be found."""
        text = "flag{too_deep}"
        for _ in range(_CHAIN_MAX_DEPTH + 1):   # 9 layers
            text = _b64(text)
        findings = _run_chain(text.encode(), depth="deep")
        self.assertFalse(any(f.flag_match for f in findings),
                         "BFS must not explore beyond max_depth")

    def test_c19_fast_mode_skips_depth5(self):
        """Fast mode (depth=4) skips 5-layer chain; deep mode finds it."""
        text = "flag{five_layers}"
        for _ in range(5):
            text = _b64(text)
        content = text.encode()
        # Fast: must not find
        self.assertFalse(any(f.flag_match for f in _run_chain(content, depth="fast")),
                         "Fast mode must not find depth-5 chain")
        # Deep: must find
        self.assertTrue(any(f.flag_match for f in _run_chain(content, depth="deep")),
                        "Deep mode must find depth-5 chain")

    def test_c20_is_interesting_gates(self):
        """_chain_is_interesting correctly identifies explorable states."""
        # Base64-looking → interesting
        self.assertTrue(_chain_is_interesting(_b64("hello world test string")))
        # Hex string → interesting
        self.assertTrue(_chain_is_interesting("deadbeef0123456789abcdef"))
        # Binary string → interesting
        self.assertTrue(_chain_is_interesting("0110011001101100011000010110011101111011"))
        # Printable text → interesting
        self.assertTrue(_chain_is_interesting("flag{plaintext_is_interesting}"))
        # Non-printable garbage → not interesting
        garbage = "".join(chr(i) for i in range(1, 9)) * 20
        self.assertFalse(_chain_is_interesting(garbage))
        # Empty string → not interesting
        self.assertFalse(_chain_is_interesting(""))


# ===========================================================================
# D — Integration via _check_encoding_chain / analyze()
# ===========================================================================

class TestIntegration(unittest.TestCase):

    def test_d21_single_b64_flag_in_file(self):
        """Single base64-encoded flag in a file → chain finding emitted."""
        encoded = _b64("flag{single_b64_integration}")
        content = f"Preamble text here\n{encoded}\nTrailing text\n".encode()
        findings = _run_full(content, depth="fast")
        self.assertTrue(any(f.flag_match for f in findings),
                        f"Expected flag_match; got {[f.title for f in findings]}")

    def test_d22_triple_encoded_flag_deep_mode(self):
        """Triple base64-encoded flag found only in deep mode."""
        text = "flag{triple_encode}"
        for _ in range(3):
            text = _b64(text)
        content = text.encode()
        findings = _run_full(content, depth="deep")
        self.assertTrue(any(f.flag_match for f in findings),
                        f"Deep mode must find triple-encoded flag; got {[f.title for f in findings]}")

    def test_d23_plain_english_no_false_flag_match(self):
        """Plain English text does not produce any false flag-match chain findings."""
        plain = (
            "The quick brown fox jumps over the lazy dog. "
            "This is a completely normal sentence with no hidden data. "
            "Nothing to see here.\n"
        ) * 10
        findings = _run_full(plain.encode(), depth="deep")
        flag_matches = [f for f in findings if f.flag_match]
        self.assertEqual(flag_matches, [],
                         f"False flag matches: {[f.title for f in flag_matches]}")


# ===========================================================================
# E — Edge cases
# ===========================================================================

class TestEdgeCases(unittest.TestCase):

    def test_e24_empty_content_no_crash(self):
        """Empty byte content must not raise."""
        try:
            _run_chain(b"", depth="deep")
        except Exception as exc:
            self.fail(f"Empty content raised: {exc}")

    def test_e25_circular_rot13_terminates(self):
        """rot13 applied twice yields the original — visited set prevents infinite loop."""
        # A string that passes the rot13 alpha gate but won't match the flag pattern
        text = "uryybjbeyqknzrfgnoyr"   # rot13 of "helloworldnamestable"
        try:
            _run_chain(text.encode(), depth="deep")
        except Exception as exc:
            self.fail(f"Circular rot13 caused exception: {exc}")
        # Completion without hanging or exception is the assertion

    def test_e26_xor_brute_returns_none_or_str(self):
        """_chain_xor_brute never raises and always returns str or None."""
        # Control chars 0x01-0x08 — very unlikely to produce printable XOR output
        raw = bytes(range(1, 9)) * 20
        text = raw.decode("latin-1")
        result = _chain_xor_brute(text)
        self.assertIsInstance(result, (str, type(None)))

    def test_e27_b64_none_for_short_input(self):
        """_chain_b64 returns None for inputs shorter than 4 chars."""
        for short in ["", "A", "AB", "ABC", "   "]:
            self.assertIsNone(_chain_b64(short), f"Expected None for {short!r}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
