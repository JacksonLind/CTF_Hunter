"""
Image analyzer: LSB chi-square, appended data, EXIF, palette anomalies,
and QR code repair / decode pipeline.
"""
from __future__ import annotations

import re
import struct
from pathlib import Path
from typing import List, Optional, Tuple

try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False

try:
    import cv2 as _cv2
    HAS_CV2 = True
except ImportError:
    HAS_CV2 = False

try:
    from pyzbar import pyzbar as _pyzbar
    HAS_PYZBAR = True
except ImportError:
    HAS_PYZBAR = False

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

        # QR code repair pipeline (always run — fast and high-value for CTFs)
        findings.extend(self._check_qr(path, flag_pattern))

        if depth == "deep":
            # LSB chi-square test
            findings.extend(self._check_lsb_chisquare(path))
            # LSB pixel extraction (multiple scan/channel/packing variants)
            findings.extend(self._check_lsb_pixels(path, flag_pattern))
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

    # ------------------------------------------------------------------
    # QR code repair pipeline
    # ------------------------------------------------------------------

    # All 8 standard QR mask patterns (row, col) -> bool
    _QR_MASKS = [
        lambda r, c: (r + c) % 2 == 0,
        lambda r, c: r % 2 == 0,
        lambda r, c: c % 3 == 0,
        lambda r, c: (r + c) % 3 == 0,
        lambda r, c: (r // 2 + c // 3) % 2 == 0,
        lambda r, c: (r * c) % 2 + (r * c) % 3 == 0,
        lambda r, c: ((r * c) % 2 + (r * c) % 3) % 2 == 0,
        lambda r, c: ((r + c) % 2 + (r * c) % 3) % 2 == 0,
    ]

    def _check_qr(self, path: str, flag_pattern: re.Pattern) -> List[Finding]:
        """QR code decode with a repair pipeline for mangled QR images.

        Pipeline:
          1. Standard decode attempt on the raw image.
          2. Assess whether the image is QR-like (square, binary).
          3. Detect module size via first-row transition analysis.
          4. For each of 16 transform variants (± invert × 8 QR masks plus
             ± invert alone), majority-vote resample to remove spatial
             distortion, add a quiet-zone border, and attempt decode.

        Requires at least one of: cv2, pyzbar.
        Without a decoder, emits an INFO finding when a damaged QR is suspected.
        """
        if not HAS_NUMPY:
            return []

        findings: List[Finding] = []
        try:
            from PIL import Image
            with Image.open(path) as _raw:
                img = _raw.convert("L")
        except Exception:
            return []

        try:
            import numpy as np
            arr = np.array(img, dtype=np.uint8)
        except Exception:
            return []

        # 1. Standard decode of the raw image.
        raw_text = self._qr_decode(arr)
        if raw_text:
            fm = self._check_flag(raw_text, flag_pattern)
            findings.append(self._finding(
                path,
                f"QR code decoded: {raw_text[:80]}",
                raw_text,
                severity="HIGH" if fm else "MEDIUM",
                flag_match=fm,
                confidence=0.97 if fm else 0.80,
            ))
            return findings

        # 2. QR-like heuristic: must be roughly square and mostly black/white.
        h, w = arr.shape
        if abs(h - w) > max(h, w) * 0.2:
            return []
        extreme = int(((arr < 55) | (arr > 200)).sum())
        if extreme < h * w * 0.50:
            return []  # not binary enough

        # 3. Detect module size.
        module_size = self._qr_detect_module_size(arr)
        if module_size < 2:
            return []
        n_modules = round(w / module_size)
        if n_modules < 10 or n_modules > 200:
            return []

        # No decoder available — flag as suspect and provide repair hints.
        if not HAS_CV2 and not HAS_PYZBAR:
            findings.append(self._finding(
                path,
                f"Suspected damaged QR code (~{n_modules}x{n_modules} modules, "
                f"module size ~{module_size}px) — decoder unavailable",
                "Install cv2 (opencv-python-headless) or pyzbar for automatic repair.\n"
                f"Detected module size: {module_size}px, grid: {n_modules}x{n_modules}.\n"
                "Try: invert + XOR QR mask 0 ((r+c)%2==0) + majority-vote resample + quiet zone.",
                severity="MEDIUM",
                confidence=0.60,
            ))
            return findings

        # 4. Transform candidates: (invert_first, mask_id_or_None)
        candidates: List[Tuple[bool, Optional[int]]] = [
            (False, None),
            (True,  None),
        ]
        for mask_id in range(8):
            candidates.append((False, mask_id))
            candidates.append((True,  mask_id))

        import numpy as np
        for invert, mask_id in candidates:
            # Apply pixel-level transforms on the thresholded binary grid.
            binary = (arr > 127).astype(np.uint8)  # 1=white, 0=black
            if invert:
                binary = 1 - binary
            if mask_id is not None:
                mask_fn = self._QR_MASKS[mask_id]
                for r in range(h):
                    for c in range(w):
                        mr = r // module_size
                        mc = c // module_size
                        if mask_fn(mr, mc):
                            binary[r, c] ^= 1

            # Majority-vote resample: removes spatial warps and distortions.
            clean_grid = self._qr_majority_vote(binary, module_size, n_modules)
            if clean_grid is None:
                continue

            # Render clean grid at fixed scale with 4-module quiet zone.
            scale = max(4, 300 // n_modules)
            border = 4 * scale
            size = n_modules * scale + 2 * border
            canvas = np.ones((size, size), dtype=np.uint8) * 255
            for r in range(n_modules):
                for c in range(n_modules):
                    val = 0 if clean_grid[r, c] == 0 else 255
                    canvas[
                        border + r * scale: border + (r + 1) * scale,
                        border + c * scale: border + (c + 1) * scale,
                    ] = val

            decoded = self._qr_decode(canvas)
            if decoded:
                transform_desc = []
                if invert:
                    transform_desc.append("color-invert")
                if mask_id is not None:
                    transform_desc.append(f"QR-mask-{mask_id}")
                transform_desc.append("majority-vote-resample")
                transform_str = " + ".join(transform_desc) if transform_desc else "majority-vote-resample"
                fm = self._check_flag(decoded, flag_pattern)
                findings.append(self._finding(
                    path,
                    f"Damaged QR repaired and decoded: {decoded[:80]}",
                    f"Transforms applied: {transform_str}\nDecoded: {decoded}",
                    severity="HIGH" if fm else "MEDIUM",
                    flag_match=fm,
                    confidence=0.95 if fm else 0.82,
                ))
                return findings  # stop on first successful repair

        # No repair succeeded — still flag as a damaged QR.
        findings.append(self._finding(
            path,
            f"Suspected damaged QR code (~{n_modules}x{n_modules} modules) — "
            "all 16 repair variants failed",
            f"Module size: {module_size}px. "
            "The QR may use a non-standard encoding or multi-layer obfuscation.",
            severity="MEDIUM",
            confidence=0.55,
        ))
        return findings

    @staticmethod
    def _qr_decode(arr) -> Optional[str]:
        """Try cv2 then pyzbar to decode a QR code from a uint8 greyscale array."""
        if HAS_CV2:
            try:
                detector = _cv2.QRCodeDetector()
                data, _, _ = detector.detectAndDecode(arr)
                if data:
                    return data
            except Exception:
                pass
        if HAS_PYZBAR:
            try:
                from PIL import Image
                import numpy as np
                results = _pyzbar.decode(Image.fromarray(arr))
                if results:
                    return results[0].data.decode("utf-8", errors="replace")
            except Exception:
                pass
        return None

    @staticmethod
    def _qr_detect_module_size(arr) -> int:
        """Estimate QR module size (pixels per module) from row transition analysis.

        Scans up to 40 evenly-spaced rows across the full image height to avoid
        being fooled by solid quiet-zone rows at the top (which have no transitions
        in normal QR codes and confuse detectors on inverted images).
        """
        import numpy as np
        h, w = arr.shape
        step = max(1, h // 40)
        best = 0
        for row_idx in range(0, h, step):
            binary = (arr[row_idx] > 127).astype(np.int8)
            transitions = np.where(np.diff(binary))[0] + 1
            if len(transitions) < 4:
                continue
            gaps = np.diff(transitions).astype(int)
            valid = gaps[gaps >= 2]
            if len(valid) == 0:
                continue
            ms = int(valid.min())
            if ms >= 2:
                best = ms if best == 0 else min(best, ms)
        return best

    @staticmethod
    def _qr_majority_vote(binary, module_size: int, n_modules: int):
        """Return an (n_modules x n_modules) grid via majority-vote patch sampling."""
        import numpy as np
        h, w = binary.shape
        if h < n_modules * module_size or w < n_modules * module_size:
            return None
        grid = np.zeros((n_modules, n_modules), dtype=np.uint8)
        for r in range(n_modules):
            for c in range(n_modules):
                patch = binary[
                    r * module_size: (r + 1) * module_size,
                    c * module_size: (c + 1) * module_size,
                ]
                grid[r, c] = 0 if patch.mean() < 0.5 else 1
        return grid

    def _check_lsb_chisquare(self, path: str) -> List[Finding]:
        """Chi-square test for LSB steganography on R, G, B channels."""
        if not HAS_NUMPY:
            return []
        try:
            import numpy as np
            from PIL import Image
            with Image.open(path) as _raw:
                arr = np.array(_raw.convert("RGB"), dtype=np.uint8)
        except Exception:
            return []

        findings: List[Finding] = []
        channel_names = ["R", "G", "B"]
        for ch_idx, ch_name in enumerate(channel_names):
            values = arr[:, :, ch_idx].flatten() & 1
            n = len(values)
            if n == 0:
                continue
            ones = int(values.sum())
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

    def _check_lsb_pixels(self, path: str, flag_pattern: re.Pattern) -> List[Finding]:
        """Extract LSB planes from image pixels across multiple variants.

        Variants tried (combinatorially):
          Bit plane  : 0 (LSB), 1
          Pixel scan : row-major, column-major
          Channels   : RGB (and RGBA / alpha-only when alpha present)
          Interleave : interleaved (R0G0B0…), sequential (all-R then all-G then all-B)
          Bit packing: MSB-first, LSB-first

        Findings emitted:
          HIGH + flag_match=True  → flag pattern found in extracted bytes
          MEDIUM                  → ≥70% printable ASCII (no flag pattern)

        Deduplication: first 256 bytes of extracted output keyed in a seen-set.
        """
        if not HAS_NUMPY:
            return []
        try:
            from PIL import Image as _PILImage
            import numpy as np
            with _PILImage.open(path) as _raw:
                has_alpha = _raw.mode in ("RGBA", "LA", "PA")
                arr = np.array(_raw.convert("RGBA" if has_alpha else "RGB"), dtype=np.uint8)
        except Exception:
            return []

        H, W, C = arr.shape
        n_pixels = H * W

        # Cap at 10 MP to avoid excessive memory use
        if n_pixels > 10_000_000:
            scale = int(np.sqrt(n_pixels / 10_000_000)) + 1
            arr = arr[::scale, ::scale]
            H, W, C = arr.shape
            n_pixels = H * W

        findings: List[Finding] = []
        seen: set = set()

        # Channel index groups to try
        ch_configs: List[Tuple[str, List[int]]] = [("RGB", [0, 1, 2])]
        if C == 4:
            ch_configs.append(("RGBA", [0, 1, 2, 3]))
            ch_configs.append(("A",    [3]))

        # Pixel orderings
        row_pix = arr.reshape(n_pixels, C)
        col_pix = arr.transpose(1, 0, 2).reshape(n_pixels, C)
        scan_orders: List[Tuple[str, object]] = [("row", row_pix), ("col", col_pix)]

        msb_weights = np.array([128, 64, 32, 16, 8, 4, 2, 1], dtype=np.uint16)
        lsb_weights = np.array([  1,  2,  4,  8, 16, 32, 64, 128], dtype=np.uint16)

        for plane in (0, 1):
            for scan_name, pix in scan_orders:
                plane_bits = (pix >> plane) & 1  # (n_pixels, C)
                for ch_name, ch_idx in ch_configs:
                    ch_bits = plane_bits[:, ch_idx]  # (n_pixels, len(ch_idx))
                    interleave_modes = [
                        ("interleaved", ch_bits.flatten()),
                        ("sequential",  np.concatenate([ch_bits[:, i] for i in range(ch_bits.shape[1])])),
                    ]
                    for ilv_name, bits in interleave_modes:
                        for pack_name, weights in (("MSB", msb_weights), ("LSB", lsb_weights)):
                            n = (len(bits) // 8) * 8
                            if n < 64:
                                continue
                            byte_vals = (
                                bits[:n].reshape(-1, 8).astype(np.uint16) * weights
                            ).sum(axis=1).astype(np.uint8)

                            dedup_key = bytes(byte_vals[:256])
                            if dedup_key in seen:
                                continue
                            seen.add(dedup_key)

                            text = byte_vals.tobytes().decode("latin-1")
                            fm = self._check_flag(text, flag_pattern)
                            label = f"{scan_name}/{ch_name}/{ilv_name}/bit{plane}/{pack_name}"

                            if fm:
                                findings.append(self._finding(
                                    path,
                                    f"LSB steg: flag found ({label})",
                                    f"Variant: {label}\n"
                                    f"Decoded: {text[:300]}\n"
                                    f"raw_hex={byte_vals[:64].tobytes().hex()}",
                                    severity="HIGH",
                                    flag_match=True,
                                    confidence=0.95,
                                ))
                            else:
                                sample = byte_vals[:1000]
                                printable = int(
                                    np.sum((sample >= 0x20) & (sample <= 0x7E))
                                    + np.sum(np.isin(sample, [9, 10, 13]))
                                )
                                if len(sample) > 0 and printable / len(sample) >= 0.70:
                                    preview = byte_vals[:200].tobytes().decode("ascii", errors="replace")
                                    findings.append(self._finding(
                                        path,
                                        f"LSB steg: printable payload ({label})",
                                        f"Variant: {label}\n"
                                        f"Printable ratio: {printable/len(sample):.2f}\n"
                                        f"Preview: {preview[:200]}\n"
                                        f"raw_hex={byte_vals[:64].tobytes().hex()}",
                                        severity="MEDIUM",
                                        confidence=0.60,
                                    ))
        return findings

    def _check_palette(self, path: str) -> List[Finding]:
        try:
            from PIL import Image
            with Image.open(path) as img:
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
