"""
Classical Cipher Detection & Decryption analyzer.

For every extracted string of 8+ alphabetic characters:
- Computes Index of Coincidence (IC)
- Computes bigram/trigram frequency distributions
- Attempts Caesar, ROT13, Atbash, Vigenère, Beaufort, Rail Fence,
  Columnar Transposition, Playfair detection, and Substitution cipher.
"""
from __future__ import annotations

import math
import random
import re
import string
from collections import Counter
from typing import List, Optional, Tuple

from core.report import Finding
from core.ai_client import AIClient
from core.external import run_strings
from .base import Analyzer

# ---------------------------------------------------------------------------
# English language reference data
# ---------------------------------------------------------------------------

_ENG_FREQ: dict[str, float] = {
    'e': 0.1270, 't': 0.0906, 'a': 0.0817, 'o': 0.0751, 'i': 0.0697,
    'n': 0.0675, 's': 0.0633, 'h': 0.0609, 'r': 0.0599, 'd': 0.0425,
    'l': 0.0403, 'c': 0.0278, 'u': 0.0276, 'm': 0.0241, 'w': 0.0234,
    'f': 0.0223, 'g': 0.0202, 'y': 0.0197, 'p': 0.0193, 'b': 0.0149,
    'v': 0.0098, 'k': 0.0077, 'j': 0.0015, 'x': 0.0015, 'q': 0.0010,
    'z': 0.0007,
}

_ENG_BIGRAMS: dict[str, float] = {
    'th': 0.0356, 'he': 0.0307, 'in': 0.0243, 'er': 0.0205, 'an': 0.0199,
    're': 0.0185, 'on': 0.0176, 'en': 0.0175, 'at': 0.0149, 'es': 0.0145,
    'ed': 0.0145, 'te': 0.0135, 'ti': 0.0134, 'or': 0.0128, 'st': 0.0125,
    'ar': 0.0121, 'nd': 0.0117, 'to': 0.0117, 'nt': 0.0117, 'is': 0.0113,
    'it': 0.0111, 'ng': 0.0109, 'ha': 0.0104, 'se': 0.0103, 'ou': 0.0100,
    'of': 0.0100, 'le': 0.0098, 'sa': 0.0097, 'ne': 0.0091, 'as': 0.0087,
    'ly': 0.0080, 'ro': 0.0079, 'fo': 0.0072, 'de': 0.0069, 'ea': 0.0067,
    'ho': 0.0065, 'la': 0.0063, 've': 0.0063, 'co': 0.0062, 'me': 0.0061,
}

# Score threshold above which text looks English-like
_ENGLISH_FREQ_THRESHOLD = 0.35
_ENGLISH_BIGRAM_THRESHOLD = 0.012


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def _index_of_coincidence(text: str) -> float:
    """Compute the Index of Coincidence for alphabetic characters in *text*."""
    alpha = [c.lower() for c in text if c.isalpha()]
    n = len(alpha)
    if n < 2:
        return 0.0
    counts = Counter(alpha)
    return sum(c * (c - 1) for c in counts.values()) / (n * (n - 1))


def _score_english_freq(text: str) -> float:
    """Score text by English letter frequency (higher = more English-like)."""
    alpha = [c.lower() for c in text if c.isalpha()]
    if not alpha:
        return 0.0
    counts = Counter(alpha)
    total = len(alpha)
    score = 0.0
    for ch, freq in _ENG_FREQ.items():
        observed = counts.get(ch, 0) / total
        score += min(observed, freq)
    return score


def _score_bigrams(text: str) -> float:
    """Score text by English bigram frequency (higher = more English-like)."""
    alpha = ''.join(c.lower() for c in text if c.isalpha())
    total = len(alpha) - 1
    if total < 1:
        return 0.0
    score = sum(_ENG_BIGRAMS.get(alpha[i:i + 2], 0.0) for i in range(total))
    return score / total


# ---------------------------------------------------------------------------
# Cipher implementations
# ---------------------------------------------------------------------------

def _caesar_decrypt(text: str, shift: int) -> str:
    result = []
    for c in text:
        if c.isalpha():
            base = ord('a') if c.islower() else ord('A')
            result.append(chr((ord(c) - base - shift) % 26 + base))
        else:
            result.append(c)
    return ''.join(result)


def _atbash(text: str) -> str:
    result = []
    for c in text:
        if c.islower():
            result.append(chr(ord('z') - (ord(c) - ord('a'))))
        elif c.isupper():
            result.append(chr(ord('Z') - (ord(c) - ord('A'))))
        else:
            result.append(c)
    return ''.join(result)


def _vigenere_decrypt(text: str, key: str) -> str:
    key = key.lower()
    result = []
    k_idx = 0
    for c in text:
        if c.isalpha():
            shift = ord(key[k_idx % len(key)]) - ord('a')
            base = ord('a') if c.islower() else ord('A')
            result.append(chr((ord(c.lower()) - ord('a') - shift) % 26 + base))
            k_idx += 1
        else:
            result.append(c)
    return ''.join(result)


def _beaufort_decrypt(text: str, key: str) -> str:
    key = key.lower()
    result = []
    k_idx = 0
    for c in text:
        if c.isalpha():
            shift = ord(key[k_idx % len(key)]) - ord('a')
            result.append(chr((shift - (ord(c.lower()) - ord('a'))) % 26 + ord('a')))
            k_idx += 1
        else:
            result.append(c)
    return ''.join(result)


def _kasiski_key_lengths(text: str, max_key: int = 20) -> list[int]:
    """Estimate Vigenère key length via Kasiski examination."""
    alpha = ''.join(c.lower() for c in text if c.isalpha())
    if len(alpha) < 20:
        return list(range(2, min(max_key + 1, 9)))

    factor_counts: Counter = Counter()
    for seq_len in range(3, 6):
        seqs: dict[str, int] = {}
        for i in range(len(alpha) - seq_len):
            seq = alpha[i:i + seq_len]
            if seq in seqs:
                spacing = i - seqs[seq]
                for f in range(2, min(spacing + 1, max_key + 1)):
                    if spacing % f == 0:
                        factor_counts[f] += 1
            else:
                seqs[seq] = i

    if not factor_counts:
        return list(range(2, min(max_key + 1, 9)))
    return [f for f, _ in factor_counts.most_common(5)]


def _vigenere_crack_key(text: str, key_len: int) -> str:
    """Recover Vigenère key using index of coincidence per column."""
    alpha = ''.join(c.lower() for c in text if c.isalpha())
    key = []
    for col in range(key_len):
        column = alpha[col::key_len]
        if not column:
            key.append('a')
            continue
        best_shift, best_score = 0, -1.0
        for shift in range(26):
            decrypted = ''.join(
                chr((ord(c) - ord('a') - shift) % 26 + ord('a')) for c in column
            )
            score = _score_english_freq(decrypted)
            if score > best_score:
                best_score = score
                best_shift = shift
        key.append(chr(best_shift + ord('a')))
    return ''.join(key)


def _rail_fence_decrypt(text: str, rails: int) -> str:
    """Decrypt Rail Fence cipher with given number of rails."""
    n = len(text)
    if rails <= 1 or rails >= n:
        return text
    pattern = list(range(rails)) + list(range(rails - 2, 0, -1))
    period = len(pattern)
    rail_lengths = [0] * rails
    for i in range(n):
        rail_lengths[pattern[i % period]] += 1
    rails_content: list[list[str]] = []
    idx = 0
    for length in rail_lengths:
        rails_content.append(list(text[idx:idx + length]))
        idx += length
    rail_indices = [0] * rails
    result = []
    for i in range(n):
        r = pattern[i % period]
        result.append(rails_content[r][rail_indices[r]])
        rail_indices[r] += 1
    return ''.join(result)


def _columnar_decrypt(text: str, key_order: list[int]) -> str:
    """Decrypt Columnar Transposition cipher with given column order."""
    num_cols = len(key_order)
    if num_cols == 0:
        return text
    num_rows = math.ceil(len(text) / num_cols)
    extra = num_rows * num_cols - len(text)
    col_lengths = [num_rows] * num_cols
    sorted_key = sorted(range(num_cols), key=lambda x: key_order[x])
    for i in range(extra):
        col_lengths[sorted_key[-(i + 1)]] -= 1
    cols: dict[int, list[str]] = {}
    idx = 0
    for col_pos in sorted_key:
        cols[col_pos] = list(text[idx:idx + col_lengths[col_pos]])
        idx += col_lengths[col_pos]
    result = []
    for row in range(num_rows):
        for col in range(num_cols):
            if row < len(cols[col]):
                result.append(cols[col][row])
    return ''.join(result)


# ---------------------------------------------------------------------------
# Analyzer class
# ---------------------------------------------------------------------------

class ClassicalCipherAnalyzer(Analyzer):
    """Detect and attempt to decrypt classical ciphers in extracted strings."""

    def analyze(
        self,
        path: str,
        flag_pattern: re.Pattern,
        depth: str,
        ai_client: Optional[AIClient],
        **_kw,
    ) -> List[Finding]:
        findings: List[Finding] = []
        strings = run_strings(path, min_len=8)
        seen_strings: set[str] = set()

        for s in strings[:100]:
            alpha_only = re.sub(r'[^a-zA-Z]', '', s)
            if len(alpha_only) < 8 or alpha_only in seen_strings:
                continue
            seen_strings.add(alpha_only)
            findings.extend(self._analyze_string(path, s, flag_pattern, depth))

        return findings

    # ------------------------------------------------------------------

    def _analyze_string(
        self, path: str, text: str, flag_pattern: re.Pattern, depth: str
    ) -> List[Finding]:
        findings: List[Finding] = []
        alpha_text = ''.join(c for c in text if c.isalpha())
        if len(alpha_text) < 8:
            return []

        ic = _index_of_coincidence(alpha_text)

        if ic > 0.065:
            cipher_hint = "monoalphabetic/Caesar"
        elif 0.045 <= ic <= 0.065:
            cipher_hint = "polyalphabetic (Vigenère)"
        else:
            cipher_hint = "transposition or modern"

        # --- Caesar: try all 25 shifts ---
        caesar_results: list[tuple[float, int, str]] = []
        for shift in range(1, 26):
            decrypted = _caesar_decrypt(text, shift)
            score = _score_english_freq(decrypted)
            if self._check_flag(decrypted, flag_pattern):
                findings.append(self._finding(
                    path,
                    f"Caesar cipher (shift={shift}) — flag pattern match",
                    f"IC={ic:.4f} | Shift: {shift}\nPlaintext: {decrypted[:200]}",
                    severity="HIGH",
                    flag_match=True,
                    confidence=0.95,
                ))
            caesar_results.append((score, shift, decrypted))

        caesar_results.sort(reverse=True)
        top3 = caesar_results[:3]
        if top3 and top3[0][0] > _ENGLISH_FREQ_THRESHOLD and ic > 0.055:
            detail_parts = [
                f"  Shift {s} (score={sc:.3f}): {d[:80]}"
                for sc, s, d in top3
            ]
            findings.append(self._finding(
                path,
                f"Possible Caesar cipher — IC={ic:.4f} ({cipher_hint})",
                "Top 3 shifts:\n" + "\n".join(detail_parts),
                severity="MEDIUM",
                confidence=min(top3[0][0], 0.85),
            ))

        # --- ROT13 (Caesar shift=13) ---
        rot13 = _caesar_decrypt(text, 13)
        if self._check_flag(rot13, flag_pattern):
            findings.append(self._finding(
                path, "ROT13 — flag pattern match",
                f"Plaintext: {rot13[:200]}",
                severity="HIGH", flag_match=True, confidence=0.95,
            ))
        elif _score_english_freq(rot13) > _ENGLISH_FREQ_THRESHOLD:
            findings.append(self._finding(
                path, "ROT13 — probable English text",
                f"Plaintext: {rot13[:200]}",
                severity="MEDIUM", confidence=0.70,
            ))

        # --- Atbash ---
        atbash = _atbash(text)
        if self._check_flag(atbash, flag_pattern):
            findings.append(self._finding(
                path, "Atbash cipher — flag pattern match",
                f"Plaintext: {atbash[:200]}",
                severity="HIGH", flag_match=True, confidence=0.95,
            ))
        elif _score_english_freq(atbash) > _ENGLISH_FREQ_THRESHOLD:
            findings.append(self._finding(
                path, "Atbash cipher — probable English text",
                f"Plaintext: {atbash[:200]}",
                severity="MEDIUM", confidence=0.65,
            ))

        # --- Vigenère and Beaufort ---
        if len(alpha_text) >= 20:
            key_lengths = _kasiski_key_lengths(text)
            best_vig_score = 0.0
            best_vig: Optional[tuple[str, str, int]] = None

            for kl in key_lengths[:5]:
                if kl >= len(alpha_text):
                    continue
                key = _vigenere_crack_key(text, kl)
                decrypted = _vigenere_decrypt(text, key)
                score = _score_english_freq(decrypted)
                if self._check_flag(decrypted, flag_pattern):
                    findings.append(self._finding(
                        path, f"Vigenère cipher — flag pattern match (key='{key}')",
                        f"Key: {key}\nPlaintext: {decrypted[:200]}",
                        severity="HIGH", flag_match=True, confidence=0.90,
                    ))
                if score > best_vig_score:
                    best_vig_score = score
                    best_vig = (key, decrypted, kl)

            if best_vig and best_vig_score > _ENGLISH_FREQ_THRESHOLD:
                key, dec, kl = best_vig
                sev = "MEDIUM" if 0.045 <= ic <= 0.065 else "INFO"
                findings.append(self._finding(
                    path,
                    f"Possible Vigenère cipher (key_len={kl}, key='{key}')",
                    f"IC={ic:.4f} | Key: {key}\nPlaintext: {dec[:200]}",
                    severity=sev,
                    confidence=best_vig_score,
                ))

                # Beaufort (same key recovery, different formula)
                beau = _beaufort_decrypt(text, key)
                if self._check_flag(beau, flag_pattern):
                    findings.append(self._finding(
                        path, f"Beaufort cipher — flag pattern match (key='{key}')",
                        f"Key: {key}\nPlaintext: {beau[:200]}",
                        severity="HIGH", flag_match=True, confidence=0.85,
                    ))
                elif _score_english_freq(beau) > _ENGLISH_FREQ_THRESHOLD:
                    findings.append(self._finding(
                        path, f"Possible Beaufort cipher (key='{key}')",
                        f"Key: {key}\nPlaintext: {beau[:200]}",
                        severity="MEDIUM", confidence=0.55,
                    ))

        # --- Rail Fence ---
        max_rails = min(11, len(alpha_text) // 2 + 1)
        for rails in range(2, max_rails):
            decrypted = _rail_fence_decrypt(text, rails)
            if self._check_flag(decrypted, flag_pattern):
                findings.append(self._finding(
                    path, f"Rail Fence cipher (rails={rails}) — flag match",
                    f"Rails: {rails}\nPlaintext: {decrypted[:200]}",
                    severity="HIGH", flag_match=True, confidence=0.90,
                ))
            elif _score_english_freq(decrypted) > 0.45:
                findings.append(self._finding(
                    path, f"Possible Rail Fence cipher (rails={rails})",
                    f"Rails: {rails}\nPlaintext: {decrypted[:200]}",
                    severity="MEDIUM", confidence=0.55,
                ))

        # --- Columnar Transposition (key lengths 2–8, random sample of orderings) ---
        alpha_only = ''.join(c.lower() for c in text if c.isalpha())
        for key_len in range(2, min(9, len(alpha_only) // 2 + 1)):
            best_score = 0.0
            best_dec = ""
            num_tries = min(50, math.factorial(key_len))
            seen_orders: set[tuple[int, ...]] = set()
            for _ in range(num_tries * 3):
                if len(seen_orders) >= num_tries:
                    break
                order = list(range(key_len))
                random.shuffle(order)
                key_tuple = tuple(order)
                if key_tuple in seen_orders:
                    continue
                seen_orders.add(key_tuple)
                try:
                    dec = _columnar_decrypt(alpha_only, order)
                    score = _score_bigrams(dec)
                    if score > best_score:
                        best_score = score
                        best_dec = dec
                except Exception:
                    pass
            if best_dec and self._check_flag(best_dec, flag_pattern):
                findings.append(self._finding(
                    path, f"Columnar transposition (key_len={key_len}) — flag match",
                    f"Plaintext: {best_dec[:200]}",
                    severity="HIGH", flag_match=True, confidence=0.85,
                ))

        # --- Playfair detection ---
        alpha_len = len(alpha_text)
        if alpha_len % 2 == 0 and alpha_len >= 8:
            digrams = [alpha_text[i:i + 2].lower() for i in range(0, alpha_len - 1, 2)]
            if len(set(digrams)) == len(digrams):
                findings.append(self._finding(
                    path,
                    "Possible Playfair cipher (even-length, no repeated digrams)",
                    f"IC={ic:.4f} | Length={alpha_len} | No repeated digrams detected",
                    severity="MEDIUM" if ic > 0.045 else "INFO",
                    confidence=0.40,
                ))

        # --- Substitution cipher via hill-climbing (deep mode, longer texts) ---
        if depth == "deep" and len(alpha_text) >= 50:
            sub_key, sub_dec = self._hill_climb_substitution(text)
            if self._check_flag(sub_dec, flag_pattern):
                findings.append(self._finding(
                    path,
                    "Substitution cipher — flag pattern match (hill-climbing)",
                    f"Key: {sub_key}\nPlaintext: {sub_dec[:200]}",
                    severity="HIGH", flag_match=True, confidence=0.80,
                ))
            elif _score_bigrams(sub_dec) > _ENGLISH_BIGRAM_THRESHOLD:
                findings.append(self._finding(
                    path,
                    "Possible substitution cipher (hill-climbing)",
                    f"Key: {sub_key}\nPlaintext: {sub_dec[:200]}",
                    severity="MEDIUM", confidence=0.50,
                ))

        # --- IC anomaly fallback ---
        if not findings and (ic < 0.040 or ic > 0.070):
            findings.append(self._finding(
                path,
                f"IC anomaly: {ic:.4f} ({cipher_hint})",
                f"IC={ic:.4f} | Text length={len(alpha_text)} | Hint: {cipher_hint}",
                severity="MEDIUM",
                confidence=0.35,
            ))

        return findings

    def _hill_climb_substitution(
        self, text: str, iterations: int = 1000
    ) -> tuple[str, str]:
        """Recover substitution cipher key using bigram frequency hill-climbing."""
        alpha_text = ''.join(c.lower() for c in text if c.isalpha())

        key = list(string.ascii_lowercase)
        random.shuffle(key)

        def apply_key(t: str, k: list[str]) -> str:
            table = str.maketrans(string.ascii_lowercase, ''.join(k))
            return t.translate(table)

        best_key = key[:]
        best_dec = apply_key(alpha_text, key)
        best_score = _score_bigrams(best_dec)

        for _ in range(iterations):
            i, j = random.sample(range(26), 2)
            new_key = key[:]
            new_key[i], new_key[j] = new_key[j], new_key[i]
            dec = apply_key(alpha_text, new_key)
            score = _score_bigrams(dec)
            if score > best_score:
                best_score = score
                best_key = new_key[:]
                key = new_key[:]
                best_dec = dec

        return ''.join(best_key), best_dec
