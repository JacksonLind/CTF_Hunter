"""
Encoding analyzer: Base64/32/85, hex, ROT13, morse, binary, XOR key guesser.
Extended with Polybius square, Tap code, Baconian, Baudot, Rail fence,
and fuzzy encoding detector using cosine similarity.
"""
from __future__ import annotations

import base64
import binascii
import math
import re
import string
from collections import Counter
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from core.report import Finding
from core.ai_client import AIClient
from core.external import run_strings
from .base import Analyzer

_MORSE_MAP = {
    ".-": "A", "-...": "B", "-.-.": "C", "-..": "D", ".": "E",
    "..-.": "F", "--.": "G", "....": "H", "..": "I", ".---": "J",
    "-.-": "K", ".-..": "L", "--": "M", "-.": "N", "---": "O",
    ".--.": "P", "--.-": "Q", ".-.": "R", "...": "S", "-": "T",
    "..-": "U", "...-": "V", ".--": "W", "-..-": "X", "-.--": "Y",
    "--..": "Z", "-----": "0", ".----": "1", "..---": "2",
    "...--": "3", "....-": "4", ".....": "5", "-....": "6",
    "--...": "7", "---..": "8", "----.": "9",
}

# Matches a string of 8-bit binary groups separated by single whitespace characters,
# e.g. "01100110 01101100 01100001 01100111".  Used to detect space-separated binary
# output from multi-layer decoding pipelines (e.g. after a Base85 decode stage).
SPACE_BINARY_RE = re.compile(r'^([01]{8})(\s[01]{8})+$')


def _is_printable(text: str, threshold: float = 0.85) -> bool:
    if not text:
        return False
    printable_chars = sum(1 for c in text if c in string.printable)
    return printable_chars / len(text) >= threshold


def _decode_base64(s: str) -> Optional[str]:
    try:
        padded = s + "=" * (4 - len(s) % 4)
        decoded = base64.b64decode(padded, validate=False)
        return decoded.decode("utf-8", errors="replace")
    except Exception:
        return None


def _decode_base32(s: str) -> Optional[str]:
    try:
        padded = s.upper() + "=" * ((8 - len(s) % 8) % 8)
        decoded = base64.b32decode(padded, casefold=True)
        return decoded.decode("utf-8", errors="replace")
    except Exception:
        return None


def _decode_base85(s: str) -> Optional[str]:
    try:
        decoded = base64.b85decode(s)
        return decoded.decode("utf-8", errors="replace")
    except Exception:
        return None


def _decode_hex(s: str) -> Optional[str]:
    clean = re.sub(r"\s+", "", s)
    if len(clean) % 2 != 0 or not all(c in "0123456789abcdefABCDEF" for c in clean):
        return None
    try:
        return bytes.fromhex(clean).decode("utf-8", errors="replace")
    except Exception:
        return None


def _rot13(s: str) -> str:
    return s.translate(str.maketrans(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm"
    ))


def _decode_morse(s: str) -> Optional[str]:
    s = s.strip()
    if not re.match(r"^[\.\-\s/]+$", s):
        return None
    words = s.split("/")
    result = []
    for word in words:
        chars = word.strip().split()
        decoded_word = ""
        for code in chars:
            decoded_word += _MORSE_MAP.get(code, "?")
        result.append(decoded_word)
    decoded = " ".join(result)
    if "?" in decoded and decoded.count("?") / len(decoded) > 0.3:
        return None
    return decoded


def _decode_binary(s: str) -> Optional[str]:
    clean = re.sub(r"\s+", "", s)
    if not all(c in "01" for c in clean):
        return None
    if len(clean) % 8 != 0:
        return None
    try:
        result = ""
        for i in range(0, len(clean), 8):
            result += chr(int(clean[i:i+8], 2))
        return result
    except Exception:
        return None


def _decode_space_binary(s: str) -> Optional[str]:
    """Decode a space-separated 8-bit binary string to ASCII text.

    Each whitespace-delimited token must be exactly 8 binary digits (0/1).
    Returns the joined character string, or *None* if any token is invalid.
    """
    groups = s.strip().split()
    if not groups:
        return None
    try:
        return "".join(chr(int(b, 2)) for b in groups)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Polybius square (5x5 and 6x6 variants)
# ---------------------------------------------------------------------------

_POLYBIUS_5x5 = {
    (1, 1): "A", (1, 2): "B", (1, 3): "C", (1, 4): "D", (1, 5): "E",
    (2, 1): "F", (2, 2): "G", (2, 3): "H", (2, 4): "I", (2, 5): "K",
    (3, 1): "L", (3, 2): "M", (3, 3): "N", (3, 4): "O", (3, 5): "P",
    (4, 1): "Q", (4, 2): "R", (4, 3): "S", (4, 4): "T", (4, 5): "U",
    (5, 1): "V", (5, 2): "W", (5, 3): "X", (5, 4): "Y", (5, 5): "Z",
}

_POLYBIUS_6x6_CHARS = string.ascii_uppercase + string.digits


def _decode_polybius_5x5(s: str) -> Optional[str]:
    """Decode a Polybius square 5x5 ciphertext (pairs of digits 1-5)."""
    digits = re.sub(r"\s+", "", s)
    if not re.match(r"^[1-5]+$", digits) or len(digits) % 2 != 0:
        return None
    result = []
    for i in range(0, len(digits), 2):
        r, c = int(digits[i]), int(digits[i + 1])
        ch = _POLYBIUS_5x5.get((r, c))
        if ch is None:
            return None
        result.append(ch)
    return "".join(result)


def _decode_polybius_6x6(s: str) -> Optional[str]:
    """Decode a Polybius square 6x6 ciphertext (pairs of digits 1-6)."""
    digits = re.sub(r"\s+", "", s)
    if not re.match(r"^[1-6]+$", digits) or len(digits) % 2 != 0:
        return None
    result = []
    for i in range(0, len(digits), 2):
        r, c = int(digits[i]) - 1, int(digits[i + 1]) - 1
        idx = r * 6 + c
        if idx >= len(_POLYBIUS_6x6_CHARS):
            return None
        result.append(_POLYBIUS_6x6_CHARS[idx])
    return "".join(result)


# ---------------------------------------------------------------------------
# Tap code
# ---------------------------------------------------------------------------

_TAP_MAP = _POLYBIUS_5x5  # Same layout as Polybius 5x5


def _decode_tap_code(s: str) -> Optional[str]:
    """Decode tap code (groups of two numbers separated by spaces/dashes)."""
    # Expect pattern like: "1 1 1 2 ..." or "1-1 1-2 ..."
    s = s.strip()
    groups = re.split(r"[\s,;]+", s)
    if len(groups) < 2:
        return None
    result = []
    for group in groups:
        parts = re.split(r"[-\s]+", group.strip())
        if len(parts) != 2:
            return None
        try:
            r, c = int(parts[0]), int(parts[1])
        except ValueError:
            return None
        ch = _TAP_MAP.get((r, c))
        if ch is None:
            return None
        result.append(ch)
    return "".join(result) if result else None


# ---------------------------------------------------------------------------
# Baconian cipher
# ---------------------------------------------------------------------------

_BACONIAN_MAP = {
    "AAAAA": "A", "AAAAB": "B", "AAABA": "C", "AAABB": "D", "AABAA": "E",
    "AABAB": "F", "AABBA": "G", "AABBB": "H", "ABAAA": "I", "ABAAB": "J",
    "ABABA": "K", "ABABB": "L", "ABBAA": "M", "ABBAB": "N", "ABBBA": "O",
    "ABBBB": "P", "BAAAA": "Q", "BAAAB": "R", "BAABA": "S", "BAABB": "T",
    "BABAA": "U", "BABAB": "V", "BABBA": "W", "BABBB": "X", "BBAAA": "Y",
    "BBAAB": "Z",
}


def _decode_baconian(s: str) -> Optional[str]:
    """Decode Baconian cipher (A/B or 0/1 groups of 5)."""
    s = s.strip().upper()
    # Normalize 0/1 to A/B
    s = s.replace("0", "A").replace("1", "B")
    # Remove anything that's not A/B/space
    clean = re.sub(r"[^AB\s]", "", s).strip()
    groups = re.split(r"\s+", clean)
    if len(groups) < 2:
        # Try splitting into fixed 5-char groups
        flat = clean.replace(" ", "")
        if len(flat) % 5 != 0:
            return None
        groups = [flat[i:i+5] for i in range(0, len(flat), 5)]
    result = []
    for g in groups:
        ch = _BACONIAN_MAP.get(g)
        if ch is None:
            return None
        result.append(ch)
    return "".join(result) if result else None


# ---------------------------------------------------------------------------
# Baudot / ITA2 (punched card)
# ---------------------------------------------------------------------------

_BAUDOT_LTRS = {
    0b00000: "\x00", 0b00001: "E", 0b00010: "\n", 0b00011: "A",
    0b00100: " ", 0b00101: "S", 0b00110: "I", 0b00111: "U",
    0b01000: "\r", 0b01001: "D", 0b01010: "R", 0b01011: "J",
    0b01100: "N", 0b01101: "F", 0b01110: "C", 0b01111: "K",
    0b10000: "T", 0b10001: "Z", 0b10010: "L", 0b10011: "W",
    0b10100: "H", 0b10101: "Y", 0b10110: "P", 0b10111: "Q",
    0b11000: "O", 0b11001: "B", 0b11010: "G", 0b11011: "\x1b",
    0b11100: "M", 0b11101: "X", 0b11110: "V", 0b11111: "\x1a",
}


def _decode_baudot(s: str) -> Optional[str]:
    """Decode a 5-bit Baudot/ITA2 binary string (space-separated 5-bit groups)."""
    groups = s.strip().split()
    if not groups:
        return None
    result = []
    for g in groups:
        if not re.match(r"^[01]{5}$", g):
            return None
        val = int(g, 2)
        ch = _BAUDOT_LTRS.get(val)
        if ch is None:
            return None
        if ch not in ("\x00", "\x1b", "\x1a"):
            result.append(ch)
    return "".join(result) if result else None


# ---------------------------------------------------------------------------
# Rail fence (extended to rails 2-8, scored by English IC)
# ---------------------------------------------------------------------------

def _rail_fence_decode(s: str, rails: int) -> str:
    """Decode a rail fence cipher with the given number of rails."""
    n = len(s)
    if n == 0 or rails < 2:
        return s

    # Calculate the length of each rail
    rail_lengths = [0] * rails
    direction = 1
    rail = 0
    for _ in range(n):
        rail_lengths[rail] += 1
        if rail == 0:
            direction = 1
        elif rail == rails - 1:
            direction = -1
        rail += direction

    # Split the ciphertext into rails
    rail_strs: List[str] = []
    pos = 0
    for length in rail_lengths:
        rail_strs.append(s[pos:pos + length])
        pos += length

    # Read off by interleaving
    result = []
    rail_iters = [iter(r) for r in rail_strs]
    direction = 1
    rail = 0
    for _ in range(n):
        try:
            result.append(next(rail_iters[rail]))
        except StopIteration:
            break
        if rail == 0:
            direction = 1
        elif rail == rails - 1:
            direction = -1
        rail += direction
    return "".join(result)


def _english_ic(text: str) -> float:
    """Compute the Index of Coincidence for text (English IC ≈ 0.065)."""
    text = re.sub(r"[^A-Za-z]", "", text.upper())
    n = len(text)
    if n < 2:
        return 0.0
    freq = Counter(text)
    ic = sum(f * (f - 1) for f in freq.values()) / (n * (n - 1))
    return ic


def _decode_rail_fence_best(s: str, max_rails: int = 8) -> Tuple[Optional[str], int]:
    """
    Try rail counts 2..max_rails and return the (decoded, rail_count) with highest IC.
    """
    best_decoded = None
    best_rails = 2
    best_ic = 0.0
    for rails in range(2, max_rails + 1):
        decoded = _rail_fence_decode(s, rails)
        ic = _english_ic(decoded)
        if ic > best_ic:
            best_ic = ic
            best_decoded = decoded
            best_rails = rails
    # Only return if IC is plausibly English (threshold ~0.04)
    if best_ic >= 0.04:
        return best_decoded, best_rails
    return None, 0


# ---------------------------------------------------------------------------
# Fuzzy encoding detector using cosine similarity
# ---------------------------------------------------------------------------

# Reference character frequency distributions for known encodings
_ENCODING_FREQ_PROFILES: Dict[str, Dict[str, float]] = {
    "Base64": {c: 1.0 for c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="},
    "Base32": {c: 1.0 for c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567="},
    "Hex (lowercase)": {c: 1.0 for c in "0123456789abcdef"},
    "Hex (uppercase)": {c: 1.0 for c in "0123456789ABCDEF"},
    "Polybius 5x5": {c: 1.0 for c in "12345 "},
    "Polybius 6x6": {c: 1.0 for c in "123456 "},
    "Baconian": {c: 1.0 for c in "AB "},
    "Baudot": {c: 1.0 for c in "01 "},
    "Morse": {c: 1.0 for c in ".- /"},
    "Binary": {c: 1.0 for c in "01 "},
    "URL encoded": {c: 1.0 for c in "%0123456789ABCDEFabcdef+"},
}


def _char_freq_vector(s: str) -> Dict[str, float]:
    if not s:
        return {}
    total = len(s)
    freq_counts = Counter(s)
    return {ch: count / total for ch, count in freq_counts.items()}


def _cosine_similarity(v1: Dict[str, float], v2: Dict[str, float]) -> float:
    keys = set(v1) | set(v2)
    dot = sum(v1.get(k, 0.0) * v2.get(k, 0.0) for k in keys)
    mag1 = math.sqrt(sum(x * x for x in v1.values()))
    mag2 = math.sqrt(sum(x * x for x in v2.values()))
    if mag1 == 0 or mag2 == 0:
        return 0.0
    return dot / (mag1 * mag2)


def _fuzzy_encoding_candidates(s: str) -> List[Tuple[str, float]]:
    """
    For an unrecognized encoded-looking string, compute character frequency
    distribution and compare against known encoding alphabets using cosine similarity.
    Returns top 3 candidate encodings with similarity scores.
    """
    freq = _char_freq_vector(s)
    scores: List[Tuple[str, float]] = []
    for enc_name, profile in _ENCODING_FREQ_PROFILES.items():
        profile_freq: Dict[str, float] = {}
        for ch in s:
            profile_freq[ch] = 1.0 if ch in profile else 0.0
        sim = _cosine_similarity(freq, profile_freq)
        scores.append((enc_name, sim))
    scores.sort(key=lambda x: -x[1])
    return scores[:3]


class EncodingAnalyzer(Analyzer):
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

        for s in strings[:2000]:  # cap to avoid excessive processing
            s_stripped = s.strip()
            if len(s_stripped) < 8:
                continue

            # Base64
            if re.match(r"^[A-Za-z0-9+/=]{16,}$", s_stripped):
                decoded = _decode_base64(s_stripped)
                if decoded and _is_printable(decoded):
                    fm = self._check_flag(decoded, flag_pattern)
                    findings.append(self._finding(
                        path,
                        f"Base64 decoded string",
                        f"Input: {s_stripped[:60]!r} → {decoded[:200]}",
                        severity="HIGH" if fm else "MEDIUM",
                        flag_match=fm,
                        confidence=0.80 if fm else 0.55,
                    ))
                    continue

            # Base32
            if re.match(r"^[A-Z2-7=]{16,}$", s_stripped.upper()):
                decoded = _decode_base32(s_stripped)
                if decoded and _is_printable(decoded):
                    fm = self._check_flag(decoded, flag_pattern)
                    findings.append(self._finding(
                        path,
                        "Base32 decoded string",
                        f"Input: {s_stripped[:60]!r} → {decoded[:200]}",
                        severity="HIGH" if fm else "MEDIUM",
                        flag_match=fm,
                        confidence=0.78 if fm else 0.52,
                    ))
                    continue

            # Hex
            if re.match(r"^[0-9a-fA-F]{16,}$", s_stripped):
                decoded = _decode_hex(s_stripped)
                if decoded and _is_printable(decoded):
                    fm = self._check_flag(decoded, flag_pattern)
                    findings.append(self._finding(
                        path,
                        "Hex decoded string",
                        f"Input: {s_stripped[:60]!r} → {decoded[:200]}",
                        severity="HIGH" if fm else "MEDIUM",
                        flag_match=fm,
                        confidence=0.78 if fm else 0.52,
                    ))
                    continue

            # Morse
            if re.match(r"^[\.\-\s/]{8,}$", s_stripped):
                decoded = _decode_morse(s_stripped)
                if decoded and _is_printable(decoded):
                    fm = self._check_flag(decoded, flag_pattern)
                    findings.append(self._finding(
                        path,
                        "Morse code decoded",
                        f"Input: {s_stripped[:60]!r} → {decoded[:200]}",
                        severity="HIGH" if fm else "MEDIUM",
                        flag_match=fm,
                        confidence=0.72 if fm else 0.48,
                    ))
                    continue

            # Binary
            # Space-separated 8-bit binary (must be checked before compact binary)
            if SPACE_BINARY_RE.match(s_stripped):
                decoded = _decode_space_binary(s_stripped)
                if decoded and _is_printable(decoded):
                    fm = self._check_flag(decoded, flag_pattern)
                    findings.append(self._finding(
                        path,
                        "Space-binary decoded string",
                        f"Input: {s_stripped[:60]!r} → {decoded[:200]}",
                        severity="HIGH" if fm else "MEDIUM",
                        flag_match=fm,
                        confidence=0.75 if fm else 0.50,
                    ))
                    continue

            if re.match(r"^[01\s]{16,}$", s_stripped):
                decoded = _decode_binary(s_stripped)
                if decoded and _is_printable(decoded):
                    fm = self._check_flag(decoded, flag_pattern)
                    findings.append(self._finding(
                        path,
                        "Binary-to-ASCII decoded",
                        f"Input: {s_stripped[:60]!r} → {decoded[:200]}",
                        severity="HIGH" if fm else "MEDIUM",
                        flag_match=fm,
                        confidence=0.72 if fm else 0.48,
                    ))
                    continue

            # ROT13
            rot = _rot13(s_stripped)
            if rot != s_stripped:
                fm = self._check_flag(rot, flag_pattern)
                if fm:
                    findings.append(self._finding(
                        path,
                        f"ROT13 decoded flag match",
                        f"Input: {s_stripped[:60]!r} → {rot[:200]}",
                        severity="HIGH",
                        flag_match=True,
                        confidence=0.90,
                    ))

        # XOR key guesser on the raw file bytes
        if depth == "deep":
            findings.extend(self._xor_guesser(path, flag_pattern))

        # New ciphers: Polybius, Tap, Baconian, Baudot, Rail Fence
        for s in strings[:2000]:
            s_stripped = s.strip()
            if len(s_stripped) < 8:
                continue

            # Polybius 5x5
            if re.match(r"^[1-5\s]{8,}$", s_stripped):
                decoded = _decode_polybius_5x5(s_stripped)
                if decoded and _is_printable(decoded):
                    fm = self._check_flag(decoded, flag_pattern)
                    findings.append(self._finding(
                        path,
                        "Polybius 5x5 decoded string",
                        f"Input: {s_stripped[:60]!r} → {decoded[:200]}",
                        severity="HIGH" if fm else "MEDIUM",
                        flag_match=fm,
                        confidence=0.72 if fm else 0.45,
                    ))

            # Polybius 6x6
            elif re.match(r"^[1-6\s]{8,}$", s_stripped):
                decoded = _decode_polybius_6x6(s_stripped)
                if decoded and _is_printable(decoded):
                    fm = self._check_flag(decoded, flag_pattern)
                    findings.append(self._finding(
                        path,
                        "Polybius 6x6 decoded string",
                        f"Input: {s_stripped[:60]!r} → {decoded[:200]}",
                        severity="HIGH" if fm else "MEDIUM",
                        flag_match=fm,
                        confidence=0.70 if fm else 0.43,
                    ))

            # Tap code (pairs of digits 1-5 with separators)
            if re.match(r"^[1-5][\s\-][1-5]", s_stripped):
                decoded = _decode_tap_code(s_stripped)
                if decoded and decoded and _is_printable(decoded):
                    fm = self._check_flag(decoded, flag_pattern)
                    findings.append(self._finding(
                        path,
                        "Tap code decoded string",
                        f"Input: {s_stripped[:60]!r} → {decoded[:200]}",
                        severity="HIGH" if fm else "MEDIUM",
                        flag_match=fm,
                        confidence=0.68 if fm else 0.40,
                    ))

            # Baconian cipher
            if re.match(r"^[ABab01\s]{10,}$", s_stripped):
                decoded = _decode_baconian(s_stripped)
                if decoded and _is_printable(decoded):
                    fm = self._check_flag(decoded, flag_pattern)
                    findings.append(self._finding(
                        path,
                        "Baconian cipher decoded string",
                        f"Input: {s_stripped[:60]!r} → {decoded[:200]}",
                        severity="HIGH" if fm else "MEDIUM",
                        flag_match=fm,
                        confidence=0.70 if fm else 0.42,
                    ))

            # Baudot (5-bit groups)
            if re.match(r"^([01]{5}\s+){2,}", s_stripped):
                decoded = _decode_baudot(s_stripped)
                if decoded and _is_printable(decoded):
                    fm = self._check_flag(decoded, flag_pattern)
                    findings.append(self._finding(
                        path,
                        "Baudot/ITA2 decoded string",
                        f"Input: {s_stripped[:60]!r} → {decoded[:200]}",
                        severity="HIGH" if fm else "MEDIUM",
                        flag_match=fm,
                        confidence=0.65 if fm else 0.38,
                    ))

            # Rail fence (try all rail counts, pick by best IC)
            if len(s_stripped) >= 20 and re.match(r"^[A-Za-z0-9]+$", s_stripped):
                decoded, best_rails = _decode_rail_fence_best(s_stripped)
                if decoded and _is_printable(decoded) and decoded != s_stripped:
                    fm = self._check_flag(decoded, flag_pattern)
                    findings.append(self._finding(
                        path,
                        f"Rail fence ({best_rails} rails) decoded string",
                        f"Input: {s_stripped[:60]!r} → {decoded[:200]}",
                        severity="HIGH" if fm else "MEDIUM",
                        flag_match=fm,
                        confidence=0.60 if fm else 0.35,
                    ))

        # Header context: force-attempt Base85 decode when file declares it
        findings.extend(self._header_context_decode(path, flag_pattern))

        # Fuzzy encoding detector (deep mode or for unrecognized encoded-looking strings)
        if depth == "deep":
            findings.extend(self._fuzzy_detect(path, strings))

        return findings

    def _header_context_decode(self, path: str, flag_pattern: re.Pattern) -> List[Finding]:
        """Scan the file as text for 'Encoding: ... base85' header lines and
        force-attempt base64.b85decode() on the payload block that follows,
        regardless of what the character-frequency heuristic would score.
        """
        findings: List[Finding] = []
        try:
            text = Path(path).read_text(errors="replace")
        except Exception:
            return findings

        lines = text.splitlines()
        i = 0
        while i < len(lines):
            if re.search(r"(?i)encoding[:\s]+.*base85", lines[i]):
                # Found a base85 header context; collect the payload block below.
                # Scan forward for an explicit "payload:" label within a small window.
                payload_lines: List[str] = []
                window_end = min(i + 20, len(lines))
                payload_label_idx: Optional[int] = None
                for k in range(i + 1, window_end):
                    if re.match(r"(?i)payload\s*:", lines[k].strip()):
                        payload_label_idx = k
                        break

                if payload_label_idx is not None:
                    # Collect content lines after the "payload:" label
                    j = payload_label_idx + 1
                    while j < len(lines):
                        stripped = lines[j].strip()
                        if not stripped or re.match(r"^\[", stripped):
                            break
                        payload_lines.append(stripped)
                        j += 1
                else:
                    # No explicit label: grab the first non-empty, non-header line
                    for j in range(i + 1, window_end):
                        stripped = lines[j].strip()
                        if stripped and not re.match(r"^\[", stripped):
                            payload_lines.append(stripped)
                            break

                payload = "".join(payload_lines)
                if payload:
                    decoded = _decode_base85(payload)
                    if decoded and _is_printable(decoded):
                        fm = self._check_flag(decoded, flag_pattern)
                        findings.append(self._finding(
                            path,
                            "Base85 force-decoded (header context)",
                            f"Encoding header triggered Base85 decode → {decoded[:200]}",
                            severity="HIGH" if fm else "MEDIUM",
                            flag_match=fm,
                            confidence=0.85 if fm else 0.60,
                        ))
                        # Further decode if the Base85 payload is space-separated 8-bit binary
                        if SPACE_BINARY_RE.match(decoded.strip()):
                            further = _decode_space_binary(decoded.strip())
                            if further:
                                fm2 = self._check_flag(further, flag_pattern)
                                findings.append(self._finding(
                                    path,
                                    "Space-binary decoded (from Base85 payload)",
                                    f"Binary groups decoded → {further[:200]}",
                                    severity="HIGH" if fm2 else "MEDIUM",
                                    flag_match=fm2,
                                    confidence=0.87 if fm2 else 0.62,
                                ))
            i += 1

        return findings

    def _xor_guesser(self, path: str, flag_pattern: re.Pattern) -> List[Finding]:
        findings: List[Finding] = []
        try:
            data = Path(path).read_bytes()
        except Exception:
            return []

        # Only operate on high-entropy blobs
        from analyzers.generic import GenericAnalyzer
        ga = GenericAnalyzer()
        ent = ga._shannon_entropy(data)
        if ent < 6.0:
            return []

        # Single-byte XOR
        sample = data[:4096]
        for key in range(256):
            xored = bytes(b ^ key for b in sample)
            try:
                text = xored.decode("utf-8", errors="replace")
            except Exception:
                continue
            if _is_printable(text, 0.75):
                fm = self._check_flag(text, flag_pattern)
                findings.append(self._finding(
                    path,
                    f"XOR key 0x{key:02x} produces printable data",
                    f"Key=0x{key:02x}: {text[:200]}",
                    severity="HIGH" if fm else "MEDIUM",
                    flag_match=fm,
                    confidence=0.80 if fm else 0.55,
                ))

        # Common multi-byte keys
        common_keys = [b"key", b"flag", b"secret", b"xor", b"\xde\xad\xbe\xef"]
        for key in common_keys:
            xored = bytes(sample[i] ^ key[i % len(key)] for i in range(len(sample)))
            try:
                text = xored.decode("utf-8", errors="replace")
            except Exception:
                continue
            if _is_printable(text, 0.80):
                fm = self._check_flag(text, flag_pattern)
                findings.append(self._finding(
                    path,
                    f"XOR with key {key!r} produces printable data",
                    f"Key={key!r}: {text[:200]}",
                    severity="HIGH" if fm else "MEDIUM",
                    flag_match=fm,
                    confidence=0.78 if fm else 0.53,
                ))

        return findings

    def _fuzzy_detect(self, path: str, strings: List[str]) -> List[Finding]:
        """
        For any unrecognized encoded-looking string, compute character frequency
        distribution and compare against known encoding alphabets using cosine
        similarity.  Report top 3 candidate encodings with similarity scores.
        """
        findings: List[Finding] = []
        # Only look at strings that don't match common patterns
        for s in strings[:500]:
            s_stripped = s.strip()
            if len(s_stripped) < 16:
                continue
            # Skip strings that look like regular English text
            alpha_ratio = sum(1 for c in s_stripped if c.isalpha()) / len(s_stripped)
            if alpha_ratio > 0.70:
                continue
            # Skip if already matched by obvious patterns above
            if re.match(r"^[A-Za-z0-9+/=]{16,}$", s_stripped):
                continue
            if re.match(r"^[0-9a-fA-F]{16,}$", s_stripped):
                continue

            candidates = _fuzzy_encoding_candidates(s_stripped)
            # Only report if top candidate has high similarity
            if candidates and candidates[0][1] >= 0.80:
                top_str = ", ".join(
                    f"{enc} ({sim:.2f})" for enc, sim in candidates
                )
                findings.append(self._finding(
                    path,
                    f"Fuzzy encoding detector: probable {candidates[0][0]}",
                    f"String: {s_stripped[:60]!r}\nTop candidates: {top_str}",
                    severity="INFO",
                    confidence=candidates[0][1] * 0.6,
                ))
        return findings
