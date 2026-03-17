"""
Generic analyzer: entropy, magic/extension mismatch, strings, null bytes.
Runs on every file regardless of type.
"""
from __future__ import annotations

import math
import re
from collections import Counter
from pathlib import Path
from typing import List, Optional

from core.report import Finding
from core.ai_client import AIClient
from core.external import run_strings
from .base import Analyzer

# Known extension → expected leading magic bytes
_EXT_MAGIC: dict[str, list[bytes]] = {
    ".png":  [b"\x89PNG"],
    ".jpg":  [b"\xff\xd8\xff"],
    ".jpeg": [b"\xff\xd8\xff"],
    ".gif":  [b"GIF87a", b"GIF89a"],
    ".bmp":  [b"BM"],
    ".zip":  [b"PK\x03\x04", b"PK\x05\x06"],
    ".gz":   [b"\x1f\x8b"],
    ".pdf":  [b"%PDF"],
    ".elf":  [b"\x7fELF"],
    ".exe":  [b"MZ"],
    ".mp3":  [b"ID3", b"\xff\xfb"],
    ".wav":  [b"RIFF"],
    ".ogg":  [b"OggS"],
    ".flac": [b"fLaC"],
    ".sqlite": [b"SQLite format 3"],
    ".db":   [b"SQLite format 3"],
}


class GenericAnalyzer(Analyzer):
    def analyze(
        self,
        path: str,
        flag_pattern: re.Pattern,
        depth: str,
        ai_client: Optional[AIClient],
        **_kw,
    ) -> List[Finding]:
        findings: List[Finding] = []
        try:
            data = Path(path).read_bytes()
        except Exception as exc:
            return [self._finding(path, "Read error", str(exc), severity="INFO", confidence=0.1)]

        # --- Entropy ---
        findings.extend(self._check_entropy(path, data))

        # --- Magic / extension mismatch ---
        findings.extend(self._check_magic_mismatch(path, data))

        # --- Null byte clusters ---
        findings.extend(self._check_null_clusters(path, data))

        # --- String extraction + flag pattern ---
        findings.extend(self._check_strings(path, data, flag_pattern, depth))

        # --- Zero-width character steganography ---
        findings.extend(self._check_zero_width_steg(path, data, flag_pattern))

        return findings

    # ------------------------------------------------------------------

    def _shannon_entropy(self, data: bytes) -> float:
        if not data:
            return 0.0
        counts = Counter(data)
        length = len(data)
        return -sum((c / length) * math.log2(c / length) for c in counts.values())

    def _check_entropy(self, path: str, data: bytes) -> List[Finding]:
        if len(data) < 64:
            return []
        ent = self._shannon_entropy(data)
        if ent > 7.2:
            return [self._finding(
                path,
                f"High Shannon entropy: {ent:.3f}",
                "Entropy >7.2 suggests encryption or packing.",
                severity="HIGH",
                confidence=0.75,
            )]
        if ent > 6.5:
            return [self._finding(
                path,
                f"Elevated Shannon entropy: {ent:.3f}",
                "Entropy >6.5 may indicate compression or encoding.",
                severity="MEDIUM",
                confidence=0.55,
            )]
        return []

    def _check_magic_mismatch(self, path: str, data: bytes) -> List[Finding]:
        suffix = Path(path).suffix.lower()
        expected = _EXT_MAGIC.get(suffix)
        if not expected:
            return []
        if not any(data.startswith(m) for m in expected):
            actual = data[:8].hex()
            return [self._finding(
                path,
                f"Magic/extension mismatch for {suffix}",
                f"Expected magic for {suffix}, got 0x{actual}",
                severity="HIGH",
                confidence=0.85,
            )]
        return []

    def _check_null_clusters(self, path: str, data: bytes) -> List[Finding]:
        findings: List[Finding] = []
        MIN_CLUSTER = 64
        i = 0
        while i < len(data):
            if data[i] == 0:
                j = i
                while j < len(data) and data[j] == 0:
                    j += 1
                cluster_len = j - i
                if cluster_len >= MIN_CLUSTER:
                    findings.append(self._finding(
                        path,
                        f"Null byte cluster at 0x{i:x} ({cluster_len} bytes)",
                        "Large null-byte region may indicate hidden data or steganography.",
                        severity="MEDIUM",
                        offset=i,
                        confidence=0.5,
                    ))
                i = j
            else:
                i += 1
        return findings

    def _check_strings(
        self,
        path: str,
        data: bytes,
        flag_pattern: re.Pattern,
        depth: str,
    ) -> List[Finding]:
        findings: List[Finding] = []
        strings = run_strings(path, min_len=4)
        flag_hits = []
        for s in strings:
            if self._check_flag(s, flag_pattern):
                flag_hits.append(s)
        if flag_hits:
            for hit in flag_hits[:20]:  # cap at 20 shown
                # Find offset in raw bytes
                offset = data.find(hit.encode("latin-1", errors="replace"))
                findings.append(self._finding(
                    path,
                    f"Flag pattern match in strings: {hit[:80]}",
                    f"Matched flag pattern: {hit}",
                    severity="HIGH",
                    offset=offset,
                    flag_match=True,
                    confidence=0.95,
                ))
        return findings

    def _check_zero_width_steg(
        self,
        path: str,
        data: bytes,
        flag_pattern: re.Pattern,
    ) -> List[Finding]:
        """Detect zero-width character steganography using \\u200b, \\u200c, \\u200d.

        Collects all occurrences of ZERO WIDTH SPACE (\\u200b), ZERO WIDTH
        NON-JOINER (\\u200c), and ZERO WIDTH JOINER (\\u200d) in order, maps
        each to a bit under two common schemes, converts to bytes, and stores
        the result as ``raw_hex=`` in the finding detail.
        """
        # Only attempt on UTF-8 decodable content
        try:
            text = data.decode("utf-8", errors="strict")
        except (UnicodeDecodeError, ValueError):
            return []

        _ZW_CHARS = ("\u200b", "\u200c", "\u200d")
        positions = [(i, ch) for i, ch in enumerate(text) if ch in _ZW_CHARS]
        if len(positions) < 8:
            return []

        findings: List[Finding] = []

        # Scheme 1: ZWSP (\u200b) = 0; ZWNJ (\u200c) or ZWJ (\u200d) = 1
        bits1 = [0 if ch == "\u200b" else 1 for _, ch in positions]

        # Scheme 2: ZWSP (\u200b) or ZWNJ (\u200c) = 0; ZWJ (\u200d) = 1
        bits2 = [1 if ch == "\u200d" else 0 for _, ch in positions]

        for scheme, bits in (
            ("zwsp=0/zwnj-zwj=1", bits1),
            ("zwsp-zwnj=0/zwj=1", bits2),
        ):
            if len(bits) < 8:
                continue

            # Convert bits to bytes (MSB first)
            raw = bytearray()
            for i in range(0, len(bits) - 7, 8):
                byte_val = 0
                for j in range(8):
                    byte_val |= (bits[i + j] & 1) << (7 - j)
                raw.append(byte_val)
            raw_bytes = bytes(raw)
            if not raw_bytes:
                continue

            raw_hex = raw_bytes.hex()

            # Check flag pattern against decoded text
            try:
                decoded_text = raw_bytes.decode("utf-8", errors="replace")
            except Exception:
                decoded_text = raw_bytes.decode("latin-1", errors="replace")
            flag_hit = self._check_flag(decoded_text, flag_pattern)

            printable_ratio = sum(
                1 for b in raw_bytes if 0x20 <= b <= 0x7E or b in (9, 10, 13)
            ) / len(raw_bytes)
            is_printable = printable_ratio >= 0.80

            if not flag_hit and not is_printable:
                continue

            findings.append(self._finding(
                path,
                f"Zero-width char stego ({len(positions)} ZW chars, scheme={scheme})",
                (
                    f"raw_hex={raw_hex}"
                    f" | positions={[p for p, _ in positions[:10]]}"
                ),
                severity="HIGH" if flag_hit else "MEDIUM",
                offset=positions[0][0],
                flag_match=flag_hit,
                confidence=0.95 if flag_hit else 0.70,
            ))

        return findings
