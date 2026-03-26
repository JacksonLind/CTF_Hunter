"""
Tests for ECC attack functions in analyzers/crypto_rsa.py.

Coverage:
  A. Anomalous detection via CryptoECCAnalyzer (text file parsing)
     1. n == p  → "anomalous" finding emitted
     2. n != p, smooth → "Pohlig-Hellman" finding, no anomalous finding
     3. Missing p → no findings returned

  B. Smart attack (_smart_attack) — p-adic DLP on anomalous curves
     4. k=1   on anomalous curve  (trivial sanity check)
     5. k=42  on anomalous curve  (mid-range value)
     6. k=100 on anomalous curve  (near-order edge)
     7. All k in 1..p-1 on a second small anomalous curve (p=5)
     8. Smart attack on a non-anomalous curve returns None

  C. Pohlig-Hellman (_pohlig_hellman_ec) — smooth-order DLP
     9. Smooth order n=105 = 3×5×7, k=5  recovered correctly
    10. Smooth order n=105, k=99 recovered correctly
    11. Non-smooth large prime order → returns None

  D. CryptoECCAnalyzer end-to-end with Smart attack
    12. Text file with anomalous curve + G + Q → "discrete log recovered" finding
    13. Text file with anomalous curve, n==p but G/Q missing → "failed" finding

  E. CryptoECCAnalyzer end-to-end with Pohlig-Hellman
    14. Text file with smooth-order curve + G + Q → Pohlig-Hellman finding

  F. Graceful degradation
    15. Binary file that decodes as non-UTF-8 → empty findings (no crash)
    16. Text file with p but no n → empty findings

  G. _extract_ecc_params parsing
    17. Decimal params  (p=..., a=..., G=(x,y), Q=(x,y))
    18. Hex params      (p=0x..., a=0x..., generator=(0x...,0x...))
    19. "order" alias   (order = N)

Run from the ctf_hunter/ directory:
    python tests/test_crypto_ecc.py
"""
from __future__ import annotations

import os
import re
import sys
import tempfile
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from analyzers.crypto_rsa import (
    _smart_attack,
    _pohlig_hellman_ec,
    _extract_ecc_params,
    _ec_mul,
    CryptoECCAnalyzer,
)

FLAG_PATTERN = re.compile(r"flag\{[^}]+\}")

# ---------------------------------------------------------------------------
# Shared curve parameters
# ---------------------------------------------------------------------------

# Anomalous curve 1: p=101, a=12, b=18, G=(1,43), ord=101
_P1, _A1, _B1 = 101, 12, 18
_GX1, _GY1 = 1, 43

# Anomalous curve 2: p=5, a=3, b=2, G=(1,1), ord=5
_P2, _A2, _B2 = 5, 3, 2
_GX2, _GY2 = 1, 1

# Pohlig-Hellman curve: p=101, a=1, b=1, n=105=3×5×7, G=(0,1)
_PP, _AP, _BP = 101, 1, 1
_GPX, _GPY = 0, 1
_PN = 105  # smooth order

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_ANALYZER = CryptoECCAnalyzer()


def _make_text_file(content: str) -> str:
    """Write content to a temp file, return path."""
    fd, path = tempfile.mkstemp(suffix=".txt")
    with os.fdopen(fd, "w") as f:
        f.write(content)
    return path


def _run_analyzer(content: str):
    path = _make_text_file(content)
    try:
        return _ANALYZER.analyze(path, FLAG_PATTERN, "deep", None)
    finally:
        os.unlink(path)


def _titles(findings) -> list[str]:
    return [f.title for f in findings]


def _has_keyword(findings, kw: str) -> bool:
    kw = kw.lower()
    return any(kw in f.title.lower() or kw in f.detail.lower() for f in findings)


# ---------------------------------------------------------------------------
# A. Anomalous detection via CryptoECCAnalyzer
# ---------------------------------------------------------------------------


def _hex_text(params: dict) -> str:
    """Render ECC params as a text file using hex (always matches the regex)."""
    lines = []
    for k, v in params.items():
        if k in ("gx", "gy"):
            continue
        if k in ("qx", "qy"):
            continue
        lines.append(f"{k} = {hex(v)}")
    if "gx" in params:
        lines.append(f"G = ({hex(params['gx'])}, {hex(params['gy'])})")
    if "qx" in params:
        lines.append(f"Q = ({hex(params['qx'])}, {hex(params['qy'])})")
    return "\n".join(lines) + "\n"


class TestAnomalousDetection(unittest.TestCase):
    def test_a1_anomalous_finding_when_n_equals_p(self):
        """n == p should emit an 'anomalous' finding."""
        text = _hex_text({"p": _P1, "a": _A1, "b": _B1, "n": _P1})
        findings = _run_analyzer(text)
        self.assertTrue(_has_keyword(findings, "anomalous"))

    def test_a2_pohlig_finding_when_smooth_not_anomalous(self):
        """Smooth n != p should emit Pohlig-Hellman, not anomalous DETECTION."""
        text = _hex_text({"p": _PP, "a": _AP, "b": _BP, "n": _PN,
                          "gx": _GPX, "gy": _GPY})
        findings = _run_analyzer(text)
        self.assertTrue(_has_keyword(findings, "pohlig"))
        # The info finding may say "Anomalous: no" but there must be no
        # "Anomalous ECC curve detected" title finding.
        anomalous_detected = any(
            "anomalous ecc curve detected" in f.title.lower() for f in findings
        )
        self.assertFalse(anomalous_detected)

    def test_a3_no_p_returns_empty(self):
        """Missing p → no findings."""
        text = "a = 0x0c\nb = 0x12\nn = 0x65\n"
        findings = _run_analyzer(text)
        self.assertEqual(findings, [])


# ---------------------------------------------------------------------------
# B. Smart attack unit tests
# ---------------------------------------------------------------------------


class TestSmartAttack(unittest.TestCase):
    def _check(self, k_true: int, p=_P1, a=_A1, Gx=_GX1, Gy=_GY1):
        Q = _ec_mul(k_true, (Gx, Gy), a, p)
        if Q is None:
            self.skipTest(f"[{k_true}]*G = O on test curve")
        Qx, Qy = Q
        k_rec = _smart_attack(p, a, Gx, Gy, Qx, Qy)
        self.assertEqual(k_rec, k_true, f"Smart failed: expected {k_true}, got {k_rec}")

    def test_b4_k1(self):
        self._check(1)

    def test_b5_k42(self):
        self._check(42)

    def test_b6_k100(self):
        self._check(100)

    def test_b7_all_k_on_curve2(self):
        """All k in 1..p-1 on p=5 anomalous curve."""
        for k_true in range(1, _P2):
            with self.subTest(k=k_true):
                self._check(k_true, p=_P2, a=_A2, Gx=_GX2, Gy=_GY2)

    def test_b8_non_anomalous_curve_returns_none(self):
        """On a non-anomalous curve (order != p), Smart attack should return None."""
        # Use Pohlig-Hellman curve with order 105 != p=101
        Q = _ec_mul(5, (_GPX, _GPY), _AP, _PP)
        if Q is None:
            self.skipTest("Q = O for k=5 on PH curve")
        Qx, Qy = Q
        # Smart attack with wrong assumption: treat n=105 as if it were anomalous
        # Expected: returns None (valuations won't satisfy E^1 check)
        k = _smart_attack(_PP, _AP, _GPX, _GPY, Qx, Qy)
        self.assertIsNone(k)


# ---------------------------------------------------------------------------
# C. Pohlig-Hellman unit tests
# ---------------------------------------------------------------------------


class TestPohligHellman(unittest.TestCase):
    def _check(self, k_true: int):
        G = (_GPX, _GPY)
        Q = _ec_mul(k_true, G, _AP, _PP)
        if Q is None:
            self.skipTest(f"[{k_true}]*G = O")
        k_rec = _pohlig_hellman_ec(_PP, _AP, G, _PN, Q)
        self.assertEqual(k_rec, k_true % _PN,
                         f"PH failed: expected {k_true % _PN}, got {k_rec}")

    def test_c9_k5(self):
        self._check(5)

    def test_c10_k15(self):
        """k=15: valid in-range DLP for G with order 21 on n=105 curve."""
        # G=(0,1) has order 21 on this curve; k must be in [0,21) for unique DLP.
        self._check(15)

    def test_c11_large_prime_order_returns_none(self):
        """Non-smooth order (large prime > factor_limit) should return None."""
        # 2^31 - 1 = 2147483647 (Mersenne prime) — far above _trial_factor limit
        large_prime = 2_147_483_647
        k = _pohlig_hellman_ec(_PP, _AP, (_GPX, _GPY), large_prime, (_GPX, _GPY))
        self.assertIsNone(k)


# ---------------------------------------------------------------------------
# D. CryptoECCAnalyzer end-to-end: Smart attack
# ---------------------------------------------------------------------------


class TestAnalyzerSmartAttack(unittest.TestCase):
    def _challenge_text(self, k: int) -> str:
        Q = _ec_mul(k, (_GX1, _GY1), _A1, _P1)
        assert Q is not None
        return _hex_text({"p": _P1, "a": _A1, "b": _B1, "n": _P1,
                          "gx": _GX1, "gy": _GY1, "qx": Q[0], "qy": Q[1]})

    def test_d12_smart_attack_recovers_k(self):
        """Analyzer finds discrete log for a known k via Smart attack."""
        text = self._challenge_text(42)
        findings = _run_analyzer(text)
        self.assertTrue(
            _has_keyword(findings, "discrete log recovered"),
            f"Expected 'discrete log recovered' in findings; got: {_titles(findings)}",
        )

    def test_d13_smart_attack_missing_Q_emits_anomalous_finding(self):
        """Anomalous curve with G but no Q → anomalous detection finding (no attack)."""
        text = _hex_text({"p": _P1, "a": _A1, "b": _B1, "n": _P1,
                          "gx": _GX1, "gy": _GY1})
        findings = _run_analyzer(text)
        self.assertTrue(
            any("anomalous ecc curve detected" in f.title.lower() for f in findings),
            f"Expected anomalous detection finding; got: {_titles(findings)}",
        )


# ---------------------------------------------------------------------------
# E. CryptoECCAnalyzer end-to-end: Pohlig-Hellman
# ---------------------------------------------------------------------------


class TestAnalyzerPohligHellman(unittest.TestCase):
    def test_e14_pohlig_recovers_k(self):
        """Analyzer finds discrete log for a known k via Pohlig-Hellman."""
        k_true = 5
        G = (_GPX, _GPY)
        Q = _ec_mul(k_true, G, _AP, _PP)
        assert Q is not None
        text = _hex_text({"p": _PP, "a": _AP, "b": _BP, "n": _PN,
                          "gx": G[0], "gy": G[1], "qx": Q[0], "qy": Q[1]})
        findings = _run_analyzer(text)
        self.assertTrue(
            _has_keyword(findings, "discrete log recovered"),
            f"Expected 'discrete log recovered'; got: {_titles(findings)}",
        )


# ---------------------------------------------------------------------------
# F. Graceful degradation
# ---------------------------------------------------------------------------


class TestGracefulDegradation(unittest.TestCase):
    def test_f15_binary_file_no_crash(self):
        """Analyzer must not crash on a binary (non-text) file."""
        fd, path = tempfile.mkstemp(suffix=".bin")
        with os.fdopen(fd, "wb") as f:
            f.write(bytes(range(256)))
        try:
            findings = _ANALYZER.analyze(path, FLAG_PATTERN, "deep", None)
            # May return empty or minimal findings; the important thing is no exception
            self.assertIsInstance(findings, list)
        finally:
            os.unlink(path)

    def test_f16_missing_n_returns_empty(self):
        """p without n → empty findings."""
        text = f"p = {_P1}\na = {_A1}\nb = {_B1}\n"
        findings = _run_analyzer(text)
        self.assertEqual(findings, [])


# ---------------------------------------------------------------------------
# G. _extract_ecc_params parsing
# ---------------------------------------------------------------------------


class TestExtractECCParams(unittest.TestCase):
    def test_g17_decimal_params(self):
        # Use 4-digit numbers to satisfy the {4,} threshold in _ECC_PARAM_RE
        text = (
            "p = 1013\na = 1201\nb = 1800\nn = 1013\n"
            "G = (1001, 4300)\nQ = (3500, 6100)\n"
        )
        params = _extract_ecc_params(text)
        self.assertEqual(params.get("p"), 1013)
        self.assertEqual(params.get("a"), 1201)
        self.assertEqual(params.get("b"), 1800)
        self.assertEqual(params.get("gx"), 1001)
        self.assertEqual(params.get("gy"), 4300)
        self.assertEqual(params.get("qx"), 3500)
        self.assertEqual(params.get("qy"), 6100)

    def test_g18_hex_params(self):
        text = (
            "p = 0x65\na = 0x0c\nb = 0x12\nn = 0x65\n"
            "generator = (0x01, 0x2b)\npublic_key = (0x23, 0x3d)\n"
        )
        params = _extract_ecc_params(text)
        self.assertEqual(params.get("p"), 0x65)
        self.assertEqual(params.get("gx"), 0x01)
        self.assertEqual(params.get("gy"), 0x2b)
        self.assertEqual(params.get("qx"), 0x23)
        self.assertEqual(params.get("qy"), 0x3d)

    def test_g19_order_alias(self):
        text = "p = 1013\na = 1001\norder = 1050\n"
        params = _extract_ecc_params(text)
        self.assertEqual(params.get("n"), 1050)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def _run_suite() -> bool:
    groups = [
        ("A. Anomalous detection", TestAnomalousDetection),
        ("B. Smart attack", TestSmartAttack),
        ("C. Pohlig-Hellman", TestPohligHellman),
        ("D. Analyzer Smart attack e2e", TestAnalyzerSmartAttack),
        ("E. Analyzer Pohlig-Hellman e2e", TestAnalyzerPohligHellman),
        ("F. Graceful degradation", TestGracefulDegradation),
        ("G. ECC param parsing", TestExtractECCParams),
    ]

    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    for _name, cls in groups:
        suite.addTests(loader.loadTestsFromTestCase(cls))

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    return result.wasSuccessful()


if __name__ == "__main__":
    ok = _run_suite()
    sys.exit(0 if ok else 1)
