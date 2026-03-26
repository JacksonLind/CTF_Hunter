"""
Tests for Custom Rotation / Substitution Alphabet Brute-Force
(analyzers/classical_cipher.py)

Coverage:
  A. Module-level helpers
      1.  _rotate: identity (rot=0)
      2.  _rotate: basic rotation
      3.  _rotate: B64 roundtrip
      4.  _mod_inverse: known values for all valid affine a
      5.  _affine_decrypt: identity (a=1, b=0)
      6.  _affine_decrypt: equivalent to Caesar shift
      7.  _affine_decrypt: full encrypt/decrypt roundtrip for all valid (a,b)
      8.  _keyword_alpha: produces 26-char permutation
      9.  _keyword_alpha: keyword letters appear first
     10.  _grey_decode: known 4-bit Grey code table
     11.  _grey_decode: encode → decode roundtrip for 0..31

  B. _check_rotation_brute
     12.  B64-std rotation: flag match found at correct rotation
     13.  Plain English text: no false positive
     14.  Low B64 coverage text: no findings
     15.  B64-URL rotation: flag match

  C. _check_affine
     16.  Affine flag match (a=7, b=3)
     17.  Identity key (a=1,b=0) not reported in title
     18.  Keyword substitution: flag match with "secret"
     19.  Random text: no high-confidence false positive
     20.  ROT13 (a=1,b=13) not reported in title

  D. _check_grey_rotation
     21.  Grey-encoded text: flag match
     22.  Grey + Caesar rotation: flag match
     23.  Short text (<6 chars): no findings
     24.  Grey roundtrip for all 26 letter positions

  E. Integration (_analyze_string)
     25.  Affine-encrypted flag found via _analyze_string
     26.  Grey-encoded flag found via _analyze_string

  F. Edge cases
     27.  _rotate single-char alphabet
     28.  _affine_decrypt preserves non-alpha chars
     29.  _keyword_alpha: no duplicates
     30.  _grey_decode(0) == 0
     31.  _check_affine on empty/digit-only text
     32.  _check_rotation_brute on empty text

Run from ctf_hunter/ directory:
    python -m unittest tests.test_rotation_brute -v
"""
from __future__ import annotations

import re
import string
import sys
import os
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from analyzers.classical_cipher import (
    _rotate,
    _mod_inverse,
    _affine_decrypt,
    _keyword_alpha,
    _grey_decode,
    _score_english_freq,
    ClassicalCipherAnalyzer,
    _B64_STD,
    _B64_URL,
    _CTF_KEYWORDS,
    _AFFINE_VALID_A,
)

FLAG_RE = re.compile(r"flag\{[^}]+\}", re.IGNORECASE)
_analyzer = ClassicalCipherAnalyzer()


def _affine_encrypt(text: str, a: int, b: int) -> str:
    """Affine encryption E(x) = (a*x + b) mod 26."""
    result = []
    for c in text:
        if c.isalpha():
            x = ord(c.lower()) - ord('a')
            y = (a * x + b) % 26
            result.append(chr(y + (ord('a') if c.islower() else ord('A'))))
        else:
            result.append(c)
    return ''.join(result)


def _grey_encode_text(t: str) -> str:
    """Map each letter's position through n^(n>>1) Grey encoding mod 26."""
    result = []
    for c in t:
        if c.isalpha():
            pos = ord(c.lower()) - ord('a')
            grey = pos ^ (pos >> 1)
            encoded = chr(grey % 26 + ord('a'))
            result.append(encoded.upper() if c.isupper() else encoded)
        else:
            result.append(c)
    return ''.join(result)


# ===========================================================================
# A — Module-level helpers
# ===========================================================================

class TestHelpers(unittest.TestCase):

    def test_a1_rotate_identity(self):
        self.assertEqual(_rotate("ABCDE", 0), "ABCDE")
        self.assertEqual(_rotate("ABCDE", 5), "ABCDE")
        self.assertEqual(_rotate("ABCDE", 10), "ABCDE")

    def test_a2_rotate_basic(self):
        self.assertEqual(_rotate("ABCDE", 1), "BCDEA")
        self.assertEqual(_rotate("ABCDE", 2), "CDEAB")
        self.assertEqual(_rotate("ABCDE", 4), "EABCD")

    def test_a3_rotate_b64_roundtrip(self):
        for n in [1, 10, 32, 63]:
            rotated = _rotate(_B64_STD, n)
            recovered = _rotate(rotated, len(_B64_STD) - n)
            self.assertEqual(recovered, _B64_STD, f"roundtrip failed for n={n}")

    def test_a4_mod_inverse_known(self):
        pairs = [
            (1, 1), (3, 9), (5, 21), (7, 15), (9, 3), (11, 19),
            (15, 7), (17, 23), (19, 11), (21, 5), (23, 17), (25, 25),
        ]
        for a, expected in pairs:
            inv = _mod_inverse(a, 26)
            self.assertEqual(inv, expected, f"_mod_inverse({a},26)={inv}, expected {expected}")
            self.assertEqual((a * inv) % 26, 1, f"{a}×{inv} mod 26 != 1")

    def test_a5_affine_decrypt_identity(self):
        text = "HelloWorld"
        self.assertEqual(_affine_decrypt(text, 1, 0), text)

    def test_a6_affine_decrypt_is_caesar(self):
        from analyzers.classical_cipher import _caesar_decrypt
        text = "ThequickbrownfoxjumpsoverTHElazydog"
        for shift in [3, 7, 13]:
            self.assertEqual(
                _affine_decrypt(text, 1, shift),
                _caesar_decrypt(text, shift),
                f"shift={shift}",
            )

    def test_a7_affine_roundtrip(self):
        text = "ThequickbrownFOXjumps"
        for a in _AFFINE_VALID_A:
            for b in [0, 5, 13, 25]:
                encrypted = _affine_encrypt(text, a, b)
                decrypted = _affine_decrypt(encrypted, a, b)
                self.assertEqual(decrypted, text, f"a={a},b={b}")

    def test_a8_keyword_alpha_structure(self):
        for kw in _CTF_KEYWORDS:
            alpha = _keyword_alpha(kw)
            self.assertEqual(len(alpha), 26, f"kw='{kw}'")
            self.assertEqual(sorted(alpha), list(string.ascii_lowercase), f"kw='{kw}'")

    def test_a9_keyword_alpha_starts_with_keyword(self):
        alpha = _keyword_alpha("secret")
        # Unique letters of "secret" in order: s,e,c,r,t
        self.assertEqual(alpha[:5], "secrt")

    def test_a10_grey_decode_known(self):
        table = {
            0: 0, 1: 1, 3: 2, 2: 3, 6: 4, 7: 5, 5: 6, 4: 7,
            12: 8, 13: 9, 15: 10, 14: 11, 10: 12, 11: 13, 9: 14, 8: 15,
        }
        for grey, binary in table.items():
            self.assertEqual(_grey_decode(grey), binary, f"_grey_decode({grey})")

    def test_a11_grey_encode_decode_roundtrip(self):
        for n in range(32):
            grey = n ^ (n >> 1)
            self.assertEqual(_grey_decode(grey), n, f"n={n}")


# ===========================================================================
# B — _check_rotation_brute
# ===========================================================================

class TestRotationBrute(unittest.TestCase):

    def test_b12_b64std_flag_match(self):
        rot = 7
        plain = "flag{rotation_works}"
        cipher_chars = []
        rotated_alpha = _rotate(_B64_STD, rot)
        for c in plain:
            idx = _B64_STD.find(c)
            cipher_chars.append(rotated_alpha[idx] if idx >= 0 else c)
        ciphertext = ''.join(cipher_chars)

        findings = _analyzer._check_rotation_brute("x.bin", ciphertext, FLAG_RE)
        self.assertTrue(
            any(f.flag_match for f in findings),
            f"No flag match; cipher={ciphertext!r}, findings={[f.title for f in findings]}",
        )

    def test_b13_plain_english_no_false_flag_match(self):
        """Plain English text does not produce false *flag-match* rotation findings."""
        text = "The quick brown fox jumps over the lazy dog"
        findings = _analyzer._check_rotation_brute("x.txt", text, FLAG_RE)
        flag_matches = [f for f in findings if f.flag_match]
        self.assertEqual(flag_matches, [])

    def test_b14_low_b64_coverage_no_findings(self):
        # Only 8 of 14 printable chars are in B64_STD (66 % < 75 %)
        text = "AAAA BBBB !!!! ----"
        findings = _analyzer._check_rotation_brute("x.bin", text, FLAG_RE)
        self.assertEqual(findings, [])

    def test_b15_b64url_flag_match(self):
        rot = 3
        plain = "flag{url_safe_b64}"
        rotated = _rotate(_B64_URL, rot)
        cipher_chars = []
        for c in plain:
            idx = _B64_URL.find(c)
            cipher_chars.append(rotated[idx] if idx >= 0 else c)
        ciphertext = ''.join(cipher_chars)

        findings = _analyzer._check_rotation_brute("x.bin", ciphertext, FLAG_RE)
        self.assertTrue(any(f.flag_match for f in findings))


# ===========================================================================
# C — _check_affine
# ===========================================================================

class TestCheckAffine(unittest.TestCase):

    def test_c16_affine_flag_match(self):
        a, b = 7, 3
        ciphertext = _affine_encrypt("flag{affine_cipher_test}", a, b)
        findings = _analyzer._check_affine("x.bin", ciphertext, FLAG_RE)
        self.assertTrue(
            any(f.flag_match for f in findings),
            f"cipher={ciphertext!r}, findings={[f.title for f in findings]}",
        )

    def test_c17_identity_not_in_titles(self):
        text = "thequickbrownfoxjumpsoverthelazydog"
        findings = _analyzer._check_affine("x.txt", text, FLAG_RE)
        for f in findings:
            self.assertNotIn("a=1, b=0", f.title)

    def test_c18_keyword_substitution_flag_match(self):
        kw = "secret"
        sub_alpha = _keyword_alpha(kw)
        enc_trans = str.maketrans(string.ascii_lowercase, sub_alpha)
        ciphertext = "flag{keyword_sub}".lower().translate(enc_trans)

        findings = _analyzer._check_affine("x.bin", ciphertext, FLAG_RE)
        self.assertTrue(
            any(f.flag_match for f in findings),
            f"cipher={ciphertext!r}, findings={[f.title for f in findings]}",
        )

    def test_c19_no_false_flag_match(self):
        """Random text does not produce false flag-match findings from affine."""
        import random as _rnd
        _rnd.seed(42)
        text = ''.join(_rnd.choice(string.ascii_letters) for _ in range(60))
        findings = _analyzer._check_affine("x.bin", text, FLAG_RE)
        flag_matches = [f for f in findings if f.flag_match]
        self.assertEqual(flag_matches, [], f"False flag matches: {[f.title for f in flag_matches]}")

    def test_c20_rot13_not_in_titles(self):
        text = "uryybjbeyq"
        findings = _analyzer._check_affine("x.txt", text, FLAG_RE)
        for f in findings:
            self.assertNotIn("a=1, b=13", f.title)


# ===========================================================================
# D — _check_grey_rotation
# ===========================================================================

class TestGreyRotation(unittest.TestCase):

    def test_d21_grey_flag_match(self):
        ciphertext = _grey_encode_text("flag{grey_code_works}")
        findings = _analyzer._check_grey_rotation("x.bin", ciphertext, FLAG_RE)
        self.assertTrue(
            any(f.flag_match for f in findings),
            f"cipher={ciphertext!r}, findings={[f.title for f in findings]}",
        )

    def test_d22_grey_plus_caesar_flag_match(self):
        rot = 5

        def encode(t, rot):
            result = []
            for c in t:
                if c.isalpha():
                    pos = ord(c.lower()) - ord('a')
                    grey = pos ^ (pos >> 1)
                    result.append(chr((grey % 26 + rot) % 26 + ord('a')))
                else:
                    result.append(c)
            return ''.join(result)

        ciphertext = encode("flag{grey_plus_rot}", rot)
        findings = _analyzer._check_grey_rotation("x.bin", ciphertext, FLAG_RE)
        self.assertTrue(
            any(f.flag_match for f in findings),
            f"rot={rot}, cipher={ciphertext!r}",
        )

    def test_d23_short_text_skipped(self):
        findings = _analyzer._check_grey_rotation("x.txt", "abc", FLAG_RE)
        self.assertEqual(findings, [])

    def test_d24_grey_roundtrip_all_letters(self):
        for pos in range(26):
            grey = pos ^ (pos >> 1)
            decoded = _grey_decode(grey) % 26
            self.assertEqual(decoded, pos, f"pos={pos}")


# ===========================================================================
# E — Integration (_analyze_string)
# ===========================================================================

class TestIntegration(unittest.TestCase):

    def test_e25_affine_via_analyze_string(self):
        ciphertext = _affine_encrypt("flag{integrated_affine_check}", 5, 8)
        findings = _analyzer._analyze_string("x.bin", ciphertext, FLAG_RE, "fast")
        self.assertTrue(
            any(f.flag_match for f in findings),
            f"findings={[f.title for f in findings]}",
        )

    def test_e26_grey_via_analyze_string(self):
        ciphertext = _grey_encode_text("flag{grey_integrated}")
        findings = _analyzer._analyze_string("x.bin", ciphertext, FLAG_RE, "fast")
        self.assertTrue(
            any(f.flag_match for f in findings),
            f"findings={[f.title for f in findings]}",
        )


# ===========================================================================
# F — Edge cases
# ===========================================================================

class TestEdgeCases(unittest.TestCase):

    def test_f27_rotate_single_char(self):
        for n in [0, 1, 99]:
            self.assertEqual(_rotate("X", n), "X")

    def test_f28_affine_preserves_nonalpha(self):
        text = "flag{1234 test!}"
        result = _affine_decrypt(text, 5, 3)
        self.assertEqual(result[4], '{')
        self.assertEqual(result[9], ' ')
        self.assertEqual(result[-1], '}')

    def test_f29_keyword_alpha_no_duplicates(self):
        for kw in _CTF_KEYWORDS + ["aabbcc", "zzz"]:
            alpha = _keyword_alpha(kw)
            self.assertEqual(len(set(alpha)), 26, f"Dup in kw='{kw}'")

    def test_f30_grey_decode_zero(self):
        self.assertEqual(_grey_decode(0), 0)

    def test_f31_affine_empty_and_digits(self):
        for text in ["", "   ", "12345"]:
            findings = _analyzer._check_affine("x.txt", text, FLAG_RE)
            flag_matches = [f for f in findings if f.flag_match]
            self.assertEqual(flag_matches, [])

    def test_f32_rotation_empty_text(self):
        findings = _analyzer._check_rotation_brute("x.bin", "", FLAG_RE)
        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
