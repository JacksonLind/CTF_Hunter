"""
Python MT19937 PRNG Analyzer for CTF Hunter.

Detects weak PRNG usage and attempts to recover state from observed outputs:

  1. Weak-PRNG pattern scan — flags calls to random.seed/randint/getrandbits/
     random/choice/shuffle and C-level srand/rand.  Always runs (fast + deep).

  2. Integer sequence extraction — pulls 32-bit integers from text content and
     filters to values likely to be PRNG outputs (> 2^20).

  3. MT19937 full state recovery — if 624+ consecutive getrandbits(32) outputs
     are found, untempers them to reconstruct the full state and predicts the
     next 32 outputs.  Results embedded as raw_hex= for re-dispatch.

  4. Small-seed brute-force — if fewer than 624 values are found but at least 2
     are present, tries seeds 0..2^20 (≈1 M candidates) and verifies each
     against the extracted sequence.  Reports seed + next predicted values.

Graceful degradation: non-text (non-UTF-8) files return empty findings.
Fast mode: only the weak-PRNG pattern scan runs; recovery is deep-only.
"""
from __future__ import annotations

import re
import struct
from pathlib import Path
from typing import List, Optional

from core.report import Finding
from core.ai_client import AIClient
from .base import Analyzer


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_MT_N = 624          # MT19937 state size (words)
_MT_M = 397
_MT_A = 0x9908B0DF
_MT_UPPER = 0x80000000
_MT_LOWER = 0x7FFFFFFF

# Only consider values above this threshold as candidate PRNG outputs
# (eliminates most small integers found in source/config files)
_MIN_PRNG_VALUE = 1 << 20       # 2^20 ≈ 1 million

# Maximum integers to extract from a single file (performance guard)
_MAX_EXTRACT = 1200

# Brute-force seed range for small-seed recovery
_MAX_SEED_BRUTE = 1 << 20       # 2^20 = 1,048,576 seeds

# Number of future values to predict and embed in the finding
_PREDICT_N = 32


# ---------------------------------------------------------------------------
# MT19937 primitives
# ---------------------------------------------------------------------------

def _mt19937_temper(y: int) -> int:
    """Apply MT19937 output tempering to a state word."""
    y ^= y >> 11
    y ^= (y << 7) & 0x9D2C5680
    y ^= (y << 15) & 0xEFC60000
    y ^= y >> 18
    return y & 0xFFFFFFFF


def _mt19937_untemper(y: int) -> int:
    """Invert the MT19937 output tempering transformation."""
    # Undo y ^= (y >> 18)  — self-inverse for 32-bit
    y ^= y >> 18
    # Undo y ^= (y << 15) & 0xEFC60000  — self-inverse (bottom 15 bits unchanged)
    y ^= (y << 15) & 0xEFC60000
    # Undo y ^= (y << 7) & 0x9D2C5680  — iterative (bottom 7 bits unchanged each round)
    t = y
    for _ in range(4):
        t = y ^ ((t << 7) & 0x9D2C5680)
    y = t & 0xFFFFFFFF
    # Undo y ^= (y >> 11)  — iterative (top 11 bits unchanged each round)
    t = y
    for _ in range(3):
        t = y ^ (t >> 11)
    return t & 0xFFFFFFFF


def _mt19937_twist(state: List[int]) -> List[int]:
    """Generate the next MT19937 state array from the current one."""
    new_state = [0] * _MT_N
    for i in range(_MT_N):
        y = (state[i] & _MT_UPPER) | (state[(i + 1) % _MT_N] & _MT_LOWER)
        new_state[i] = state[(i + _MT_M) % _MT_N] ^ (y >> 1)
        if y & 1:
            new_state[i] ^= _MT_A
    return new_state


def _mt19937_generate(state: List[int], n: int = _PREDICT_N) -> List[int]:
    """Twist the state once and return the first n tempered outputs."""
    next_state = _mt19937_twist(state)
    return [_mt19937_temper(next_state[i]) for i in range(min(n, _MT_N))]


def _mt19937_recover_state(outputs: List[int]) -> Optional[List[int]]:
    """
    Recover MT19937 internal state from exactly 624 consecutive 32-bit outputs.

    Returns the state array, or None if inputs are out of 32-bit range.
    """
    if len(outputs) < _MT_N:
        return None
    state = []
    for val in outputs[:_MT_N]:
        if not (0 <= val <= 0xFFFFFFFF):
            return None
        state.append(_mt19937_untemper(val))
    return state


def _mt19937_brute_seed(
    outputs: List[int],
    max_seed: int = _MAX_SEED_BRUTE,
) -> Optional[int]:
    """
    Try seeds 0..max_seed-1 against a list of observed getrandbits(32) outputs.

    Returns the seed on the first match, or None if no seed matches.
    Requires at least 2 outputs to keep false-positive rate negligible.
    """
    if len(outputs) < 2:
        return None

    import random as _random

    rng = _random.Random()
    n = len(outputs)
    for seed in range(max_seed):
        rng.seed(seed)
        for i, expected in enumerate(outputs):
            if rng.getrandbits(32) != expected:
                break
        else:
            return seed
    return None


# ---------------------------------------------------------------------------
# Regex helpers
# ---------------------------------------------------------------------------

# Weak PRNG usage in Python / C / JavaScript source
_WEAK_PRNG_RE = re.compile(
    r"\b(?:"
    r"random\.(?:seed|randint|random|getrandbits|choice|choices|sample|shuffle"
    r"|uniform|randrange|randbytes)"
    r"|srand\s*\("
    r"|rand\s*\(\)"
    r"|Math\.random\s*\("
    r")\b",
    re.IGNORECASE,
)

# Any non-negative integer (used for ordered, full-sequence extraction)
_ANY_INT_RE = re.compile(r"(?<![0-9])([0-9]+)(?![0-9])")

# Decimal integers with 7–10 digits (range 1 000 000 – 9 999 999 999,
# capturing typical 32-bit PRNG outputs while skipping small constants)
_DECIMAL_INT_RE = re.compile(r"(?<!\w)([1-9][0-9]{6,9})(?!\w)")

# Hex integers 0x with 5–8 hex digits (0x100000 – 0xFFFFFFFF)
_HEX_INT_RE = re.compile(r"\b0x([0-9a-fA-F]{5,8})\b", re.IGNORECASE)


def _extract_32bit_ordered(text: str) -> List[int]:
    """Extract ALL non-negative integers ≤ 2^32 in file order (no dedup).

    Used for MT19937 state recovery where the complete ordered sequence matters.
    """
    values: List[int] = []
    for m in _ANY_INT_RE.finditer(text):
        v = int(m.group(1))
        if 0 <= v <= 0xFFFFFFFF:
            values.append(v)
        if len(values) >= _MAX_EXTRACT:
            break
    return values


def _extract_candidate_values(text: str) -> List[int]:
    """Extract large, deduplicated integers likely to be MT19937 outputs.

    Used for small-seed brute-force where sequence order matters less than
    having a clean set of large-valued outputs.
    """
    values: List[int] = []
    seen: set = set()

    for m in _DECIMAL_INT_RE.finditer(text):
        v = int(m.group(1))
        if _MIN_PRNG_VALUE <= v <= 0xFFFFFFFF and v not in seen:
            seen.add(v)
            values.append(v)
        if len(values) >= _MAX_EXTRACT:
            break

    for m in _HEX_INT_RE.finditer(text):
        v = int(m.group(1), 16)
        if _MIN_PRNG_VALUE <= v <= 0xFFFFFFFF and v not in seen:
            seen.add(v)
            values.append(v)
        if len(values) >= _MAX_EXTRACT:
            break

    return values


# ---------------------------------------------------------------------------
# Analyzer
# ---------------------------------------------------------------------------

class CryptoPRNGAnalyzer(Analyzer):
    """
    Detects weak PRNG usage and attempts MT19937 state / seed recovery.

    Always runs on every file type; recovery checks are deep-only.
    """

    def analyze(
        self,
        path: str,
        flag_pattern: re.Pattern,
        depth: str,
        ai_client: Optional[AIClient],
        **_kw,
    ) -> List[Finding]:
        findings: List[Finding] = []

        # Read file as text — silently skip binary files
        try:
            text = Path(path).read_text(encoding="utf-8", errors="strict")
        except (UnicodeDecodeError, IsADirectoryError):
            try:
                text = Path(path).read_text(encoding="latin-1", errors="replace")
                # Skip files that look overwhelmingly binary
                non_print = sum(1 for c in text[:2000] if ord(c) < 9 or ord(c) == 11 or ord(c) == 12 or (14 <= ord(c) <= 31))
                if non_print > len(text[:2000]) * 0.30:
                    return []
            except Exception:
                return []
        except Exception:
            return []

        # ── Always: weak PRNG pattern detection ──────────────────────────
        findings.extend(self._check_weak_prng(path, text))

        if depth == "fast":
            return findings

        # ── Deep: MT19937 state recovery (ordered, no filter) ────────────
        all_ordered = _extract_32bit_ordered(text)
        recovery_findings: List[Finding] = []
        if len(all_ordered) >= _MT_N:
            recovery_findings = self._try_full_recovery(path, all_ordered, flag_pattern)
            findings.extend(recovery_findings)

        # ── Deep: seed brute-force if full recovery didn't fire ──────────
        if not recovery_findings:
            large_values = _extract_candidate_values(text)
            if len(large_values) >= 2:
                findings.extend(self._try_seed_brute(path, large_values, flag_pattern))

        return findings

    # ------------------------------------------------------------------

    def _check_weak_prng(self, path: str, text: str) -> List[Finding]:
        matches = _WEAK_PRNG_RE.findall(text)
        if not matches:
            return []
        unique = list(dict.fromkeys(m.lower().rstrip("(") for m in matches))
        call_list = ", ".join(f"`{c}`" for c in unique[:8])
        return [self._finding(
            path,
            f"Weak PRNG usage: {len(matches)} call(s) to {call_list}",
            f"Python's random module (MT19937) is not cryptographically secure.\n"
            f"Calls found ({len(matches)} total): {call_list}\n"
            "Replace with the secrets module for security-sensitive values.\n"
            "MT19937 internal state is fully reconstructible from 624 consecutive outputs.",
            severity="MEDIUM",
            confidence=0.75,
        )]

    def _try_full_recovery(
        self,
        path: str,
        all_ordered: List[int],
        flag_pattern: re.Pattern,
    ) -> List[Finding]:
        """Attempt full MT19937 state recovery from 624+ ordered values.

        For each 624-length window, recovers the state and predicts the next
        value.  If a 625th value follows in the file and matches the prediction,
        the window is validated and we emit a high-confidence finding.  If no
        625th value exists (file has exactly 624 values), we emit a slightly
        lower-confidence finding without validation.
        """
        findings: List[Finding] = []
        windows = min(len(all_ordered) - _MT_N + 1, 77)
        for start in range(windows):
            window = all_ordered[start:start + _MT_N]
            state = _mt19937_recover_state(window)
            if state is None:
                continue
            predicted = _mt19937_generate(state, _PREDICT_N)

            # Validate against the next value in the file if one exists
            next_idx = start + _MT_N
            if next_idx < len(all_ordered):
                if all_ordered[next_idx] != predicted[0]:
                    continue  # wrong window — skip
                confidence = 0.92
            else:
                # No validation value available.  Only proceed if the window
                # looks like genuine PRNG output: require ≥ 75% of values to
                # exceed 2^16, ruling out arithmetic/index sequences.
                large = sum(1 for v in window if v > 65536)
                if large < len(window) * 0.75:
                    continue
                confidence = 0.75

            pred_bytes = struct.pack(f">{_PREDICT_N}I", *predicted)
            pred_hex = pred_bytes.hex()
            fm = self._check_flag(pred_bytes.decode("latin-1", errors="replace"), flag_pattern)
            detail = (
                f"MT19937 state reconstructed from {_MT_N} consecutive 32-bit outputs "
                f"(window start index {start}).\n"
                f"Next {_PREDICT_N} predicted getrandbits(32) values:\n"
                + "\n".join(f"  [{i}] {v} (0x{v:08x})" for i, v in enumerate(predicted))
                + f"\nraw_hex={pred_hex}"
            )
            findings.append(self._finding(
                path,
                f"MT19937 state recovered — next {_PREDICT_N} outputs predicted",
                detail,
                severity="HIGH",
                flag_match=fm,
                confidence=confidence,
            ))
            break
        return findings

    def _try_seed_brute(
        self,
        path: str,
        values: List[int],
        flag_pattern: re.Pattern,
    ) -> List[Finding]:
        """Brute-force small MT19937 seed from 2–623 extracted values."""
        findings: List[Finding] = []
        seed = _mt19937_brute_seed(values, _MAX_SEED_BRUTE)
        if seed is None:
            return findings

        import random as _random
        rng = _random.Random(seed)
        # Advance past the matched outputs
        for _ in values:
            rng.getrandbits(32)
        predicted = [rng.getrandbits(32) for _ in range(_PREDICT_N)]
        pred_bytes = struct.pack(f">{_PREDICT_N}I", *predicted)
        pred_hex = pred_bytes.hex()
        fm = self._check_flag(pred_bytes.decode("latin-1", errors="replace"), flag_pattern)
        detail = (
            f"MT19937 seed recovered by brute-force: seed = {seed} (0x{seed:x})\n"
            f"Matched against {len(values)} extracted output(s).\n"
            f"Next {_PREDICT_N} predicted getrandbits(32) values:\n"
            + "\n".join(f"  [{i}] {v} (0x{v:08x})" for i, v in enumerate(predicted))
            + f"\nraw_hex={pred_hex}"
        )
        findings.append(self._finding(
            path,
            f"MT19937 seed recovered: seed={seed}",
            detail,
            severity="HIGH" if fm else "HIGH",
            flag_match=fm,
            confidence=0.92,
        ))
        return findings
