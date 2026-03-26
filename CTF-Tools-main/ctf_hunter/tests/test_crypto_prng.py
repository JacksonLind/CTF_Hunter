"""
Tests for CryptoPRNGAnalyzer and MT19937 primitives in analyzers/crypto_prng.py.

Coverage:
  A. MT19937 primitives
     1. _mt19937_untemper inverts _mt19937_temper for 100 known values
     2. _mt19937_recover_state + _mt19937_generate predicts correct next outputs

  B. CryptoPRNGAnalyzer.analyze — weak PRNG detection
     3. Python source with random.randint() → MEDIUM finding
     4. Python source with random.getrandbits() → MEDIUM finding
     5. C source with srand() / rand() → MEDIUM finding
     6. Clean file with no PRNG calls → no finding
     7. Fast mode: weak PRNG finding present but recovery skipped

  C. MT19937 full state recovery (deep mode)
     8. File containing 624 getrandbits(32) outputs → HIGH finding with predicted values
     9. Predicted values match actual next getrandbits(32) calls from same seed
    10. raw_hex= token present and decodes to struct-packed predicted values

  D. Small-seed brute-force (deep mode)
    11. File containing 3 outputs from seed=42 → seed recovered, correct predictions
    12. File with outputs from seed=999999 (near limit) → recovered
    13. File with only 1 value → no brute-force attempt (too few)

  E. Graceful degradation
    14. Binary file → empty findings (no crash)
    15. File with only small integers (< 2^20) → no recovery attempt

Run from ctf_hunter/ directory:
    python tests/test_crypto_prng.py
"""
from __future__ import annotations

import os
import random
import re
import struct
import sys
import tempfile
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from analyzers.crypto_prng import (
    CryptoPRNGAnalyzer,
    _mt19937_temper,
    _mt19937_untemper,
    _mt19937_recover_state,
    _mt19937_generate,
    _MT_N,
    _PREDICT_N,
)

FLAG_PATTERN = re.compile(r"flag\{[^}]+\}")
_ANALYZER = CryptoPRNGAnalyzer()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write_text(content: str, suffix: str = ".txt") -> str:
    fd, path = tempfile.mkstemp(suffix=suffix)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(content)
    return path


def _run(content: str, depth: str = "deep", suffix: str = ".txt") -> list:
    path = _write_text(content, suffix=suffix)
    try:
        return _ANALYZER.analyze(path, FLAG_PATTERN, depth, None)
    finally:
        os.unlink(path)


def _has_kw(findings, kw: str) -> bool:
    kw = kw.lower()
    return any(kw in f.title.lower() or kw in f.detail.lower() for f in findings)


def _rng_outputs(seed: int, n: int) -> list[int]:
    rng = random.Random(seed)
    return [rng.getrandbits(32) for _ in range(n)]


# ---------------------------------------------------------------------------
# A. MT19937 primitives
# ---------------------------------------------------------------------------


class TestMT19937Primitives(unittest.TestCase):

    def test_a1_untemper_inverts_temper(self):
        """_mt19937_untemper(_mt19937_temper(x)) == x for 100 values."""
        rng = random.Random(0)
        for _ in range(100):
            x = rng.getrandbits(32)
            tempered = _mt19937_temper(x)
            recovered = _mt19937_untemper(tempered)
            self.assertEqual(recovered, x, f"Untemper failed for x={x:#010x}")

    def test_a2_recover_state_predicts_next_outputs(self):
        """recover_state(624 outputs) + generate() matches actual next outputs."""
        seed = 12345
        rng = random.Random(seed)
        outputs = [rng.getrandbits(32) for _ in range(_MT_N)]
        actual_next = [rng.getrandbits(32) for _ in range(_PREDICT_N)]

        state = _mt19937_recover_state(outputs)
        self.assertIsNotNone(state)
        predicted = _mt19937_generate(state, _PREDICT_N)
        self.assertEqual(predicted, actual_next)


# ---------------------------------------------------------------------------
# B. Weak PRNG detection
# ---------------------------------------------------------------------------


class TestWeakPRNGDetection(unittest.TestCase):

    def test_b3_randint_detected(self):
        content = "import random\npassword = random.randint(0, 10**9)\n"
        findings = _run(content)
        self.assertTrue(_has_kw(findings, "weak prng"))

    def test_b4_getrandbits_detected(self):
        content = "key = random.getrandbits(128)\n"
        findings = _run(content)
        self.assertTrue(_has_kw(findings, "weak prng"))

    def test_b5_c_srand_detected(self):
        content = "#include <stdlib.h>\nsrand(time(NULL));\nint x = rand();\n"
        findings = _run(content, suffix=".c")
        self.assertTrue(_has_kw(findings, "weak prng"))

    def test_b6_clean_file_no_finding(self):
        content = "import secrets\ntoken = secrets.token_bytes(32)\n"
        findings = _run(content)
        self.assertFalse(_has_kw(findings, "weak prng"))

    def test_b7_fast_mode_detection_but_no_recovery(self):
        """Fast mode: weak PRNG finding emitted but no state/seed recovery."""
        outputs = _rng_outputs(42, _MT_N)
        content = "import random\nrandom.seed(42)\n"
        content += "\n".join(str(v) for v in outputs) + "\n"
        findings = _run(content, depth="fast")
        self.assertTrue(_has_kw(findings, "weak prng"), "Should detect weak PRNG in fast mode")
        # No finding whose TITLE says "state recovered" or "seed recovered"
        recovery_in_title = any(
            "state recovered" in f.title.lower() or "seed recovered" in f.title.lower()
            for f in findings
        )
        self.assertFalse(recovery_in_title, "Should NOT attempt recovery in fast mode")


# ---------------------------------------------------------------------------
# C. Full state recovery (deep mode)
# ---------------------------------------------------------------------------


class TestFullStateRecovery(unittest.TestCase):

    def _make_output_file(self, seed: int, n: int = _MT_N + 76) -> str:
        # Generate MT_N + 76 values so there are 77 candidate windows,
        # each with a validation value following the window.
        outputs = _rng_outputs(seed, n)
        return "\n".join(str(v) for v in outputs) + "\n"

    def test_c8_624_outputs_high_finding(self):
        """700 outputs → HIGH finding mentioning 'recovered'."""
        content = self._make_output_file(seed=7777)
        findings = _run(content)
        self.assertTrue(
            _has_kw(findings, "recovered"),
            f"Expected recovery finding; got: {[f.title for f in findings]}",
        )
        recovery_findings = [f for f in findings if "recovered" in f.title.lower()]
        self.assertTrue(any(f.severity == "HIGH" for f in recovery_findings))

    def test_c9_predicted_values_correct(self):
        """Predicted values from recovery match actual next getrandbits(32)."""
        seed = 54321
        rng = random.Random(seed)
        # Generate MT_N outputs + 1 validation value + PREDICT_N ground truth
        outputs = [rng.getrandbits(32) for _ in range(_MT_N + 1)]
        rng2 = random.Random(seed)
        _ = [rng2.getrandbits(32) for _ in range(_MT_N)]  # advance past the window
        actual_next = [rng2.getrandbits(32) for _ in range(_PREDICT_N)]

        content = "\n".join(str(v) for v in outputs) + "\n"
        findings = _run(content)
        recovery = [f for f in findings if "state recovered" in f.title.lower()]
        self.assertTrue(recovery, "No state recovery finding emitted")

        # Extract predicted values from the detail: lines like "  [0] 3834589234 (0x...)"
        detail = recovery[0].detail
        predicted_values = [
            int(m.group(1))
            for m in re.finditer(r"\[\d+\]\s+(\d+)\s+\(0x", detail)
        ]
        self.assertEqual(predicted_values, actual_next,
                         "Predicted values do not match actual next outputs")

    def test_c10_raw_hex_decodes_correctly(self):
        """raw_hex= in detail decodes to struct-packed big-endian predicted values."""
        seed = 99
        rng = random.Random(seed)
        outputs = [rng.getrandbits(32) for _ in range(_MT_N + 1)]
        rng2 = random.Random(seed)
        _ = [rng2.getrandbits(32) for _ in range(_MT_N)]
        actual_next = [rng2.getrandbits(32) for _ in range(_PREDICT_N)]

        content = "\n".join(str(v) for v in outputs) + "\n"
        findings = _run(content)
        recovery = [f for f in findings if "state recovered" in f.title.lower()]
        self.assertTrue(recovery)

        hex_match = re.search(r"raw_hex=([0-9a-f]+)", recovery[0].detail)
        self.assertIsNotNone(hex_match, "raw_hex= token missing from detail")
        raw = bytes.fromhex(hex_match.group(1))
        n_vals = len(raw) // 4
        unpacked = list(struct.unpack(f">{n_vals}I", raw))
        self.assertEqual(unpacked, actual_next)


# ---------------------------------------------------------------------------
# D. Small-seed brute-force
# ---------------------------------------------------------------------------


class TestSeedBruteForce(unittest.TestCase):

    def test_d11_seed_42_recovered(self):
        """3 outputs from seed=42 → seed recovered with correct predictions."""
        outputs = _rng_outputs(42, 3)
        content = "\n".join(str(v) for v in outputs) + "\n"
        findings = _run(content)
        recovery = [f for f in findings if "seed" in f.title.lower() and "recovered" in f.title.lower()]
        self.assertTrue(recovery, f"No seed recovery finding; got: {[f.title for f in findings]}")
        self.assertIn("seed=42", recovery[0].title)

    def test_d12_seed_near_limit(self):
        """3 outputs from seed=999999 (near 2^20 limit) → recovered."""
        seed = 999999
        outputs = _rng_outputs(seed, 3)
        content = "\n".join(str(v) for v in outputs) + "\n"
        findings = _run(content)
        recovery = [f for f in findings if "seed" in f.title.lower() and "recovered" in f.title.lower()]
        self.assertTrue(recovery)
        self.assertIn(f"seed={seed}", recovery[0].title)

    def test_d13_single_value_no_brute(self):
        """Only 1 extracted value → no brute-force attempt."""
        outputs = _rng_outputs(42, 1)
        content = str(outputs[0]) + "\n"
        findings = _run(content)
        self.assertFalse(
            any("seed" in f.title.lower() and "recovered" in f.title.lower() for f in findings),
            "Should not attempt brute-force with only 1 value",
        )


# ---------------------------------------------------------------------------
# E. Graceful degradation
# ---------------------------------------------------------------------------


class TestGracefulDegradation(unittest.TestCase):

    def test_e14_binary_file_no_crash(self):
        """Binary (non-text) file → empty findings, no exception."""
        fd, path = tempfile.mkstemp(suffix=".bin")
        with os.fdopen(fd, "wb") as f:
            f.write(bytes(range(256)) * 4)
        try:
            findings = _ANALYZER.analyze(path, FLAG_PATTERN, "deep", None)
            self.assertIsInstance(findings, list)
        finally:
            os.unlink(path)

    def test_e15_small_integers_no_recovery(self):
        """File with only values < 2^20 → no recovery attempt."""
        content = "\n".join(str(i * 100 + 1) for i in range(700)) + "\n"
        findings = _run(content)
        self.assertFalse(
            _has_kw(findings, "recovered"),
            "Small integers should not trigger MT19937 recovery",
        )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def _run_suite() -> bool:
    groups = [
        ("A. MT19937 primitives", TestMT19937Primitives),
        ("B. Weak PRNG detection", TestWeakPRNGDetection),
        ("C. Full state recovery", TestFullStateRecovery),
        ("D. Seed brute-force", TestSeedBruteForce),
        ("E. Graceful degradation", TestGracefulDegradation),
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
