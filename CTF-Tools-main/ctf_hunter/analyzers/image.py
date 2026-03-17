"""
Image analyzer: LSB chi-square, appended data, EXIF, palette anomalies.
"""
from __future__ import annotations

import re
import struct
from pathlib import Path
from typing import List, Optional

from core.report import Finding
from core.ai_client import AIClient
from core.external import run_exiftool
from .base import Analyzer


class ImageAnalyzer(Analyzer):
    def analyze(
        self,
        path: str,
        flag_pattern: re.Pattern,
        depth: str,
        ai_client: Optional[AIClient],
        **_kw,
    ) -> List[Finding]:
        findings: List[Finding] = []

        # EXIF metadata
        findings.extend(self._check_exif(path, flag_pattern))

        # Appended data after image end marker
        findings.extend(self._check_appended(path, flag_pattern))

        if depth == "deep":
            # LSB chi-square test
            findings.extend(self._check_lsb_chisquare(path))
            # Palette anomalies
            findings.extend(self._check_palette(path))

        return findings

    # ------------------------------------------------------------------

    def _check_exif(self, path: str, flag_pattern: re.Pattern) -> List[Finding]:
        findings: List[Finding] = []
        try:
            meta = run_exiftool(path)
        except Exception:
            return []
        for key, value in meta.items():
            s = str(value)
            if self._check_flag(s, flag_pattern):
                findings.append(self._finding(
                    path,
                    f"Flag pattern in EXIF field '{key}'",
                    f"{key}: {s}",
                    severity="HIGH",
                    flag_match=True,
                    confidence=0.95,
                ))
            elif key.lower() in ("comment", "usercomment", "imagedescription", "xpcomment",
                                  "software", "artist", "copyright", "description"):
                if s.strip():
                    findings.append(self._finding(
                        path,
                        f"Interesting EXIF field '{key}'",
                        f"{key}: {s[:200]}",
                        severity="MEDIUM",
                        confidence=0.5,
                    ))
        return findings

    def _check_appended(self, path: str, flag_pattern: re.Pattern) -> List[Finding]:
        try:
            data = Path(path).read_bytes()
        except Exception:
            return []

        markers = {
            b"\x89PNG\r\n\x1a\n": b"IEND\xaeB`\x82",
            b"\xff\xd8\xff":       b"\xff\xd9",
            b"GIF87a":             b"\x3b",
            b"GIF89a":             b"\x3b",
        }
        for start_sig, end_sig in markers.items():
            if data.startswith(start_sig):
                idx = data.rfind(end_sig)
                if idx != -1:
                    after = data[idx + len(end_sig):]
                    if len(after) > 4:
                        fm = self._check_flag(after.decode("latin-1", errors="replace"), flag_pattern)
                        findings = [self._finding(
                            path,
                            f"Appended data after image end ({len(after)} bytes)",
                            f"Data after end marker at offset 0x{idx + len(end_sig):x}: "
                            f"{after[:64].hex()}",
                            severity="HIGH" if fm else "MEDIUM",
                            offset=idx + len(end_sig),
                            flag_match=fm,
                            confidence=0.85 if fm else 0.70,
                        )]
                        return findings
        return []

    def _check_lsb_chisquare(self, path: str) -> List[Finding]:
        """Chi-square test for LSB steganography on R, G, B channels."""
        try:
            from PIL import Image
            import math
            img = Image.open(path).convert("RGB")
            pixels = list(img.getdata())
        except Exception:
            return []

        findings: List[Finding] = []
        channel_names = ["R", "G", "B"]
        for ch_idx, ch_name in enumerate(channel_names):
            values = [p[ch_idx] & 1 for p in pixels]
            if not values:
                continue
            n = len(values)
            ones = sum(values)
            zeros = n - ones
            expected = n / 2
            if expected == 0:
                continue
            chi2 = ((ones - expected) ** 2 + (zeros - expected) ** 2) / expected
            # For LSB stego the chi-square should be very small (<3.84 at p=0.05 for df=1)
            if chi2 < 1.0:
                findings.append(self._finding(
                    path,
                    f"LSB chi-square anomaly in channel {ch_name} (χ²={chi2:.3f})",
                    f"Very uniform LSB distribution in {ch_name} channel suggests LSB steganography.",
                    severity="HIGH",
                    confidence=0.80,
                ))
        return findings

    def _check_palette(self, path: str) -> List[Finding]:
        try:
            from PIL import Image
            img = Image.open(path)
            if img.mode != "P":
                return []
            palette = img.getpalette()
            if palette is None:
                return []
            # Count unique colors
            triples = [(palette[i], palette[i+1], palette[i+2])
                       for i in range(0, len(palette), 3)]
            unique = len(set(triples))
            if unique > 200 or unique < 2:
                palette_hex = bytes(palette).hex()
                return [self._finding(
                    path,
                    f"Abnormal palette size: {unique} unique colors",
                    f"Palette images with unusual color counts may hide data in palette entries.\nraw_hex={palette_hex}",
                    severity="MEDIUM",
                    confidence=0.55,
                )]
        except Exception:
            pass
        return []
