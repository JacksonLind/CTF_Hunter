"""
Steganalysis analyzer: comprehensive steganography detection and extraction engine.

Supports image (PNG, BMP, JPG, GIF), audio (WAV, MP3), video (MP4, AVI),
text, PDF/document, ZIP, and generic binary files.

Every technique both detects the anomaly AND attempts to extract hidden data,
reporting raw bytes (hex), decoded text, and flag-pattern match status.

Extraction post-processing (applied to all extracted data):
  Base64 -> hex -> ROT13 -> single-byte XOR brute-force ->
  byte reversal -> zlib decompress -> flag-pattern check at every stage.

Fast mode  : LSB chi-square, metadata inspection, appended data checks.
Deep mode  : all of the above plus frequency domain, phase coding, echo hiding,
             cross-channel analysis, and AI hypothesis generation.
"""
from __future__ import annotations

import base64
import math
import re
import struct
import zlib
from collections import Counter
from pathlib import Path
from typing import List, Optional, Tuple

from core.report import Finding
from core.ai_client import AIClient
from .base import Analyzer

_FLAG_CONF   = 0.95
_PRINT_CONF  = 0.80
_STAT_CONF   = 0.60
_STRUCT_CONF = 0.40

_IMAGE_EXTS = {".png", ".bmp", ".jpg", ".jpeg", ".gif", ".tiff", ".tif", ".webp"}
_AUDIO_EXTS = {".wav", ".mp3", ".flac", ".ogg", ".aiff", ".aif"}
_VIDEO_EXTS = {".mp4", ".avi", ".mkv", ".mov", ".wmv", ".flv"}
_TEXT_EXTS  = {".txt", ".csv", ".md", ".rst", ".html", ".htm", ".xml",
               ".json", ".py", ".js", ".c", ".cpp", ".h", ".java", ".sh", ".bat"}
_DOC_EXTS   = {".pdf", ".docx", ".doc", ".xlsx", ".xls", ".pptx", ".ppt", ".odt"}
_ZIP_EXTS   = {".zip"}

_PVD_RANGES = [(0, 7, 3), (8, 15, 3), (16, 31, 4), (32, 63, 5), (64, 255, 6)]


def _is_printable(data: bytes, threshold: float = 0.80) -> bool:
    if not data:
        return False
    printable = sum(1 for b in data if 0x20 <= b <= 0x7E or b in (9, 10, 13))
    return printable / len(data) >= threshold


def _try_b64(data: bytes) -> Optional[bytes]:
    try:
        s = data.decode("ascii", errors="ignore").strip()
        padded = s + "=" * ((4 - len(s) % 4) % 4)
        return base64.b64decode(padded, validate=False)
    except Exception:
        return None


def _try_hex(data: bytes) -> Optional[bytes]:
    try:
        s = re.sub(rb"\s+", b"", data).decode("ascii", errors="ignore")
        if len(s) % 2 != 0 or not all(c in "0123456789abcdefABCDEF" for c in s):
            return None
        return bytes.fromhex(s)
    except Exception:
        return None


def _try_rot13(data: bytes) -> bytes:
    table = str.maketrans(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm",
    )
    try:
        return data.decode("latin-1").translate(table).encode("latin-1")
    except Exception:
        return data


def _try_zlib(data: bytes) -> Optional[bytes]:
    for offset in range(min(len(data), 16)):
        try:
            return zlib.decompress(data[offset:])
        except Exception:
            continue
    return None


def _bits_to_bytes(bits: List[int]) -> bytes:
    result = bytearray()
    for i in range(0, len(bits) - 7, 8):
        byte_val = 0
        for j in range(8):
            byte_val |= (bits[i + j] & 1) << (7 - j)
        result.append(byte_val)
    return bytes(result)


_PHASE_CODING_WINDOW = 512  # samples per FFT window for phase coding detection
_MIN_IMAGE_COMPLEXITY_STD = 10.0  # minimum pixel std dev to enable bit plane analysis


def _int_to_bits(value: int, n_bits: int) -> List[int]:
    return [(value >> (n_bits - 1 - i)) & 1 for i in range(n_bits)]


def _decode_id3v2_synchsafe(b: bytes) -> int:
    """Decode a 4-byte ID3v2 synchsafe integer."""
    return (
        ((b[0] & 0x7F) << 21)
        | ((b[1] & 0x7F) << 14)
        | ((b[2] & 0x7F) << 7)
        | (b[3] & 0x7F)
    )


def _binary_entropy(p: float) -> float:
    if p <= 0 or p >= 1:
        return 0.0
    q = 1.0 - p
    return -(p * math.log2(p) + q * math.log2(q))

def _printable_prefix(data: bytes, min_len: int = 8) -> bytes:
    """Return the longest leading run of printable bytes in data."""
    for i in range(len(data), 0, -1):
        chunk = data[:i]
        if _is_printable(chunk):
            return chunk
    return b""


def decode_pipeline(raw: bytes, flag_pattern: re.Pattern) -> Tuple[bool, float, str]:
    """Apply full decode pipeline. Returns (flag_match, confidence, detail)."""
    if not raw:
        return False, 0.0, ""

    candidates: List[Tuple[str, bytes]] = [("raw", raw)]

    b64 = _try_b64(raw)
    if b64:
        candidates.append(("base64", b64))
    hexd = _try_hex(raw)
    if hexd:
        candidates.append(("hex", hexd))
    rot = _try_rot13(raw)
    if rot and rot != raw:
        candidates.append(("rot13", rot))
    candidates.append(("reversed", bytes(reversed(raw))))
    zd = _try_zlib(raw)
    if zd:
        candidates.append(("zlib", zd))

    parts: List[str] = [f"raw_hex={raw[:64].hex()}"]
    flag_match = False
    confidence = _STRUCT_CONF

    for name, candidate in candidates:
        try:
            text = candidate.decode("utf-8", errors="replace")
        except Exception:
            text = candidate.decode("latin-1", errors="replace")
        if flag_pattern.search(text):
            flag_match = True
            confidence = _FLAG_CONF
        elif _is_printable(candidate) and len(candidate) > 8:
            confidence = max(confidence, _PRINT_CONF)

    # XOR brute-force if no flag found yet
    if not flag_match:
        # Sample beginning and a middle section to catch flags at any position
        xor_sample = raw[:2048]
        if len(raw) > 4096:
            xor_sample += raw[len(raw)//2:len(raw)//2 + 2048]
        for key in range(256):
            xored = bytes(b ^ key for b in xor_sample)
            try:
                text = xored.decode("utf-8", errors="replace")
            except Exception:
                continue
            if flag_pattern.search(text):
                flag_match = True
                confidence = _FLAG_CONF
                break
            if _is_printable(xored, 0.85) and key > 0:
                confidence = max(confidence, _PRINT_CONF)
                break

    return flag_match, confidence, " | ".join(parts)


class SteganalysisAnalyzer(Analyzer):
    """Comprehensive steganalysis - dispatches to per-file-type sub-analyzers."""

    def analyze(
        self,
        path: str,
        flag_pattern: re.Pattern,
        depth: str,
        ai_client: Optional[AIClient],
        session=None,
        dispatcher_module=None,
    ) -> List[Finding]:
        findings: List[Finding] = []
        ext = Path(path).suffix.lower()

        findings.extend(self._generic_binary_stego(path, flag_pattern, depth))

        try:
            header = Path(path).read_bytes()[:16]
        except Exception:
            return findings

        is_image = (
            ext in _IMAGE_EXTS
            or header.startswith(b"\x89PNG")
            or header.startswith(b"\xff\xd8\xff")
            or header.startswith(b"GIF8")
            or header.startswith(b"BM")
        )
        is_audio = (
            ext in _AUDIO_EXTS
            or header.startswith(b"RIFF")
            or header.startswith(b"ID3")
            or header[:2] == b"\xff\xfb"
            or header.startswith(b"fLaC")
        )
        is_video  = ext in _VIDEO_EXTS
        is_text   = ext in _TEXT_EXTS
        is_doc    = (ext in _DOC_EXTS
                     or header.startswith(b"%PDF")
                     or header[:4] == b"PK")
        is_zip    = ext in _ZIP_EXTS or header.startswith(b"PK")

        if is_image:
            findings.extend(self._analyze_image(path, flag_pattern, depth))
        if is_audio:
            findings.extend(self._analyze_audio(path, flag_pattern, depth))
        if is_video:
            findings.extend(self._analyze_video(path, flag_pattern, depth))
        if is_text:
            findings.extend(self._analyze_text(path, flag_pattern, depth))
        if is_doc:
            findings.extend(self._analyze_document(path, flag_pattern, depth))
        if is_zip:
            findings.extend(self._analyze_zip(path, flag_pattern, depth))

        if depth == "deep" and ai_client and ai_client.available and findings:
            summary = "\n".join(
                f"[{f.severity}] {f.title}: {f.detail[:100]}" for f in findings[:20]
            )
            hypothesis = ai_client.analyze_findings(path, summary, "")
            if hypothesis:
                findings.append(self._finding(
                    path, "AI steganography hypothesis", hypothesis[:1000],
                    severity="INFO", confidence=0.50,
                ))

        self._run_redispatch_hook(findings, session, dispatcher_module)
        return findings

    # ===================================================================
    # IMAGE stego
    # ===================================================================

    def _analyze_image(self, path: str, flag_pattern: re.Pattern, depth: str) -> List[Finding]:
        findings: List[Finding] = []
        findings.extend(self._img_lsb_extraction(path, flag_pattern))
        findings.extend(self._img_lsb_interleaved_rgb(path, flag_pattern))
        findings.extend(self._img_channel_sequential_lsb(path, flag_pattern))
        findings.extend(self._img_appended_data(path, flag_pattern))
        findings.extend(self._img_metadata_stego(path, flag_pattern))
        if depth == "deep":
            findings.extend(self._img_multibit_planes(path, flag_pattern))
            findings.extend(self._img_dct_analysis(path, flag_pattern))
            findings.extend(self._img_palette_manipulation(path, flag_pattern))
            findings.extend(self._img_alpha_channel(path, flag_pattern))
            findings.extend(self._img_pixel_pattern(path, flag_pattern))
            findings.extend(self._img_channel_isolation(path, flag_pattern))
            findings.extend(self._img_histogram_analysis(path, flag_pattern))
            findings.extend(self._img_pixel_coordinate_encoding(path, flag_pattern))
        return findings

    def _img_lsb_extraction(self, path: str, flag_pattern: re.Pattern) -> List[Finding]:
        """LSB extraction in multiple channel orders and pixel orderings with chi-square test."""
        findings: List[Finding] = []
        try:
            from PIL import Image
            import numpy as np
        except ImportError:
            return findings
        try:
            img = Image.open(path)
            arr = np.array(img)
        except Exception:
            return findings

        if arr.ndim < 2:
            return findings

        mode = img.mode
        if arr.ndim == 2:
            channel_orders = [("L", [0])]
        elif mode == "RGBA":
            channel_orders = [
                ("RGB",  [0, 1, 2]),
                ("RGBA", [0, 1, 2, 3]),
                ("BGR",  [2, 1, 0]),
                ("BGRA", [2, 1, 0, 3]),
            ]
        elif mode == "RGB":
            channel_orders = [("RGB", [0, 1, 2]), ("BGR", [2, 1, 0])]
        else:
            channel_orders = [("ch0", [0])]

        seen_hashes: set = set()

        for order_name, order in channel_orders:
            for pix_order in ("row", "col"):
                bits: List[int] = []
                if arr.ndim == 2:
                    flat = arr.flatten() if pix_order == "row" else arr.T.flatten()
                    bits = [int(v) & 1 for v in flat[:100000]]
                else:
                    if pix_order == "row":
                        pixels = arr.reshape(-1, arr.shape[2])
                    else:
                        pixels = arr.transpose(1, 0, 2).reshape(-1, arr.shape[2])
                    n_px = min(len(pixels), 100000 // max(len(order), 1))
                    for px in pixels[:n_px]:
                        for ch in order:
                            if ch < px.shape[0]:
                                bits.append(int(px[ch]) & 1)

                if len(bits) < 8:
                    continue

                sig = bytes(bits[:32])
                if sig in seen_hashes:
                    continue
                seen_hashes.add(sig)

                ones = sum(bits[:min(len(bits), 10000)])
                total = min(len(bits), 10000)
                deviation = abs(ones / total - 0.5) if total > 0 else 0

                raw = _bits_to_bytes(bits)
                flag_match, confidence, detail = decode_pipeline(raw, flag_pattern)

                if flag_match:
                    severity = "HIGH"
                elif deviation > 0.15:
                    severity, confidence = "HIGH", max(confidence, _STAT_CONF)
                elif deviation > 0.05:
                    severity, confidence = "MEDIUM", max(confidence, _STAT_CONF)
                elif _is_printable(raw):
                    severity, confidence = "MEDIUM", max(confidence, _PRINT_CONF)
                else:
                    continue

                findings.append(self._finding(
                    path,
                    f"LSB extraction ch={order_name} order={pix_order} deviation={deviation:.3f}",
                    detail, severity=severity, offset=0,
                    flag_match=flag_match, confidence=confidence,
                ))

        return findings

    def _img_lsb_interleaved_rgb(self, path: str, flag_pattern: re.Pattern) -> List[Finding]:
        """Interleaved RGB LSB extraction: bits are read R→G→B→R→G→B pixel by pixel, stopping at null."""
        findings: List[Finding] = []
        try:
            from PIL import Image
            import numpy as np
        except ImportError:
            return findings
        try:
            img = Image.open(path)
            arr = np.array(img)
        except Exception:
            return findings

        # Only applicable to images with at least three channels (R, G, B)
        if arr.ndim < 3:
            return findings
        if arr.shape[2] < 3:
            return findings

        # Flatten pixels in row-major order, then interleave LSBs: R0,G0,B0,R1,G1,B1,...
        pixels = arr.reshape(-1, arr.shape[2])
        result = bytearray()
        bit_buf: int = 0
        bit_count: int = 0
        stop = False
        for px in pixels:
            for ch in (0, 1, 2):
                bit_buf = (bit_buf << 1) | (int(px[ch]) & 1)
                bit_count += 1
                if bit_count == 8:
                    if bit_buf == 0:
                        stop = True
                        break
                    result.append(bit_buf)
                    bit_buf = 0
                    bit_count = 0
            if stop:
                break

        if not result:
            return findings

        raw = bytes(result)

        try:
            flag_match = bool(flag_pattern.search(raw.decode("latin-1")))
        except Exception:
            flag_match = False

        # If stop=True we have a clean null boundary — use full payload.
        # If not, find the longest printable prefix so a flag not followed
        # by a null byte isn't discarded due to trailing image noise.
        if stop:
            check_bytes = raw
        else:
            check_bytes = _printable_prefix(raw)

        if flag_match or (check_bytes and len(check_bytes) >= 8):
            report_text = check_bytes.decode("latin-1", errors="replace")
            null_note = " (null-terminated)" if stop else f" (printable prefix {len(check_bytes)}b)"
            detail = f"Interleaved RGB LSB{null_note}: {report_text!r}  hex={check_bytes[:64].hex()}"
            findings.append(self._finding(
                path,
                "Interleaved RGB LSB extraction (R→G→B per pixel, null-terminated)",
                detail,
                severity="HIGH",
                offset=0,
                flag_match=flag_match,
                confidence=_FLAG_CONF if flag_match else _PRINT_CONF,
            ))
        return findings

    def _img_channel_sequential_lsb(self, path: str, flag_pattern: re.Pattern) -> List[Finding]:
        """Channel-sequential LSB extraction.

        Unlike the interleaved approach (R0,G0,B0,R1,G1,B1,...), this technique
        reads *all* LSBs from one channel across the entire image first, then all
        LSBs from the next channel, and so on.  The three bit-streams are
        concatenated and reassembled into bytes; a null byte terminates the message.

        All six channel orderings (RGB, RBG, GRB, GBR, BRG, BGR) are tried, plus
        each single channel (R, G, B) in isolation, to cover every possible
        embedding strategy.
        """
        findings: List[Finding] = []
        try:
            from PIL import Image
            import numpy as np
        except ImportError:
            return findings
        try:
            img = Image.open(path).convert("RGB")
            arr = np.array(img)
        except Exception:
            return findings

        # Need at least three channels (R, G, B)
        if arr.ndim < 3 or arr.shape[2] < 3:
            return findings

        pixels = arr.reshape(-1, arr.shape[2])

        # All six tri-channel orderings plus three single-channel orderings
        orderings = [
            ("RGB",  [0, 1, 2]),
            ("RBG",  [0, 2, 1]),
            ("GRB",  [1, 0, 2]),
            ("GBR",  [1, 2, 0]),
            ("BRG",  [2, 0, 1]),
            ("BGR",  [2, 1, 0]),
            ("R",    [0]),
            ("G",    [1]),
            ("B",    [2]),
        ]

        seen_results: set = set()

        for order_name, ch_indices in orderings:
            # Build the bit-stream: all LSBs from channel ch_indices[0], then
            # all LSBs from ch_indices[1], etc.
            bits: List[int] = []
            for ch in ch_indices:
                if ch >= arr.shape[2]:
                    continue
                channel_flat = pixels[:, ch]
                bits.extend(int(v) & 1 for v in channel_flat)

            if len(bits) < 8:
                continue

            # Reassemble bytes; stop at the first null byte
            result = bytearray()
            stopped = False
            for i in range(0, len(bits) - 7, 8):
                byte_val = 0
                for j in range(8):
                    byte_val |= bits[i + j] << (7 - j)
                if byte_val == 0:
                    stopped = True
                    break
                result.append(byte_val)

            if not result:
                continue

            raw = bytes(result)

            # Deduplicate identical payloads across orderings
            dedup_key = raw[:256]
            if dedup_key in seen_results:
                continue
            seen_results.add(dedup_key)

            try:
                text = raw.decode("latin-1")
            except Exception:
                text = ""

            try:
                flag_match = bool(flag_pattern.search(text))
            except Exception:
                flag_match = False

            if stopped:
                check_bytes = raw
            else:
                check_bytes = _printable_prefix(raw)
            
            if flag_match or (check_bytes and len(check_bytes) >= 8):
                null_note = " (null-terminated)" if stopped else f" (printable prefix {len(check_bytes)}b)"
                report_text = check_bytes.decode("latin-1", errors="replace")
                detail = (
                    f"Channel-sequential LSB order={order_name}{null_note}: "
                    f"{report_text!r}  hex={check_bytes[:64].hex()}"
                )
                findings.append(self._finding(
                    path,
                    f"Channel-sequential LSB extraction (order={order_name})",
                    detail,
                    severity="HIGH",
                    offset=0,
                    flag_match=flag_match,
                    confidence=_FLAG_CONF if flag_match else _PRINT_CONF,
                ))
        return findings

    def _img_multibit_planes(self, path: str, flag_pattern: re.Pattern) -> List[Finding]:
        """Extract and test each bit plane of each channel for non-random structure."""
        findings: List[Finding] = []
        try:
            from PIL import Image
            import numpy as np
            img = Image.open(path)
            arr = np.array(img)
        except Exception:
            return findings

        # Skip bit plane analysis for uniform/solid-colour images: they always
        # produce false positives.  Use the standard deviation of pixel values
        # across all channels as a proxy for image complexity.
        if float(np.std(arr.astype(float))) < _MIN_IMAGE_COMPLEXITY_STD:
            return findings

        if arr.ndim == 2:
            channels = [("L", arr)]
        elif arr.ndim == 3:
            mode = img.mode
            names = list(mode) if len(mode) == arr.shape[2] else [str(i) for i in range(arr.shape[2])]
            channels = [(names[i], arr[:, :, i]) for i in range(arr.shape[2])]
        else:
            return findings

        for ch_name, channel in channels:
            for bit in range(8):
                plane = ((channel >> bit) & 1).astype("uint8")
                flat = plane.flatten()
                if flat.size == 0:
                    continue
                ones_ratio = float(flat.sum()) / flat.size
                entropy = _binary_entropy(ones_ratio)

                should_report = (bit > 1 and entropy < 6.0) or (bit == 0 and abs(ones_ratio - 0.5) < 0.02)
                if should_report:
                    raw = _bits_to_bytes(flat[:100000].tolist())
                    flag_match, confidence, detail = decode_pipeline(raw, flag_pattern)
                    findings.append(self._finding(
                        path,
                        f"Non-random bit plane {bit} channel {ch_name} (entropy={entropy:.2f} ratio={ones_ratio:.4f})",
                        detail, severity="HIGH" if flag_match else "MEDIUM", offset=0,
                        flag_match=flag_match,
                        confidence=confidence if flag_match else _STAT_CONF,
                    ))

        return findings

    def _img_dct_analysis(self, path: str, flag_pattern: re.Pattern) -> List[Finding]:
        """Approximate DCT LSB extraction for JPEG (JSteg-style)."""
        findings: List[Finding] = []
        if Path(path).suffix.lower() not in (".jpg", ".jpeg"):
            return findings
        try:
            from PIL import Image
            import numpy as np
            img = Image.open(path).convert("L")
            arr = np.array(img, dtype=float)
            h, w = arr.shape
            bits: List[int] = []
            coeff_vals: List[int] = []
            for row in range(0, h - 7, 8):
                for col in range(0, w - 7, 8):
                    dct = np.fft.fft2(arr[row:row+8, col:col+8]).real.flatten()
                    for i, val in enumerate(dct):
                        ival = int(round(val))
                        coeff_vals.append(ival)
                        if i > 0 and ival != 0:
                            bits.append(ival & 1)

            if len(bits) >= 8:
                raw = _bits_to_bytes(bits)
                flag_match, confidence, detail = decode_pipeline(raw, flag_pattern)
                if flag_match or _is_printable(raw):
                    findings.append(self._finding(
                        path, "DCT AC coefficient LSB extraction (JSteg-style)",
                        detail, severity="HIGH" if flag_match else "MEDIUM", offset=0,
                        flag_match=flag_match,
                        confidence=confidence if flag_match else _PRINT_CONF,
                    ))

            if coeff_vals:
                vals = list(Counter(coeff_vals).values())
                if len(vals) > 10:
                    mx, mn = max(vals), min(vals)
                    flatness = (mx - mn) / mx if mx > 0 else 0
                    if flatness < 0.3:
                        findings.append(self._finding(
                            path,
                            f"Flat DCT coefficient histogram (flatness={flatness:.3f}) — JSteg/OutGuess indicator",
                            "Suspiciously uniform DCT histogram.",
                            severity="MEDIUM", offset=0, flag_match=False, confidence=_STAT_CONF,
                        ))
        except Exception:
            pass
        return findings

    def _img_palette_manipulation(self, path: str, flag_pattern: re.Pattern) -> List[Finding]:
        """Detect unused/duplicate palette entries and ASCII-decodable RGB values."""
        findings: List[Finding] = []
        try:
            from PIL import Image
            import numpy as np
            img = Image.open(path)
            if img.mode != "P":
                return findings
            palette = img.getpalette()
            if palette is None:
                return findings
            arr = np.array(img)
            usage = Counter(arr.flatten().tolist())
        except Exception:
            return findings

        triples = [(palette[i], palette[i+1], palette[i+2]) for i in range(0, min(len(palette), 768), 3)]
        anomalies: List[str] = []
        seen_colors: dict = {}
        anomalous_indices: set = set()

        for idx, color in enumerate(triples):
            if usage.get(idx, 0) == 0:
                anomalies.append(f"Unused palette[{idx}]={color}")
                anomalous_indices.add(idx)
            if color in seen_colors:
                anomalies.append(f"Duplicate palette[{idx}]=palette[{seen_colors[color]}]={color}")
                anomalous_indices.add(idx)
            else:
                seen_colors[color] = idx
            for byte_val in color:
                if 0x20 <= byte_val <= 0x7E:
                    anomalies.append(f"palette[{idx}] printable 0x{byte_val:02x}=chr({byte_val})")
                    anomalous_indices.add(idx)
                    break

        if anomalies:
            raw = bytes(palette[:768])
            anomaly_bytes = bytearray()
            for i in sorted(anomalous_indices):
                r, g, b = triples[i]
                anomaly_bytes.extend([r, g, b])
            flag_match, confidence, detail = decode_pipeline(raw, flag_pattern)
            findings.append(self._finding(
                path,
                f"Palette anomalies: {len(anomalies)} suspicious entries",
                detail + " | " + "; ".join(anomalies[:10]) + f"\nraw_hex={anomaly_bytes.hex()}",
                severity="HIGH" if flag_match else "MEDIUM", offset=0,
                flag_match=flag_match,
                confidence=confidence if flag_match else _STAT_CONF,
            ))

        return findings

    def _img_alpha_channel(self, path: str, flag_pattern: re.Pattern) -> List[Finding]:
        """Extract and analyse the alpha channel for hidden data."""
        findings: List[Finding] = []
        try:
            from PIL import Image
            import numpy as np
            img = Image.open(path)
            if "A" not in img.mode and img.mode != "RGBA":
                return findings
            arr = np.array(img.convert("RGBA"))
        except Exception:
            return findings

        alpha = arr[:, :, 3].flatten()
        non_binary = [int(v) for v in alpha if v not in (0, 255)]

        if non_binary:
            raw_alpha = bytes(alpha[:100000].tolist())
            flag_match, confidence, detail = decode_pipeline(raw_alpha, flag_pattern)
            findings.append(self._finding(
                path,
                f"Alpha channel has {len(non_binary)} non-binary values",
                detail, severity="HIGH" if flag_match else "MEDIUM", offset=0,
                flag_match=flag_match,
                confidence=confidence if flag_match else _STAT_CONF,
            ))

        bits = [int(v) & 1 for v in alpha[:100000]]
        if bits:
            raw = _bits_to_bytes(bits)
            flag_match, confidence, detail = decode_pipeline(raw, flag_pattern)
            if flag_match or _is_printable(raw):
                findings.append(self._finding(
                    path, "LSB extraction from alpha channel",
                    detail, severity="HIGH" if flag_match else "MEDIUM", offset=0,
                    flag_match=flag_match,
                    confidence=confidence if flag_match else _PRINT_CONF,
                ))

        return findings

    def _img_pixel_pattern(self, path: str, flag_pattern: re.Pattern) -> List[Finding]:
        """Low-variance row detection and PVD (Pixel Value Differencing) extraction."""
        findings: List[Finding] = []
        try:
            from PIL import Image
            import numpy as np
            img = Image.open(path).convert("RGB")
            arr = np.array(img, dtype=int)
        except Exception:
            return findings

        low_var_rows = [
            row_idx for row_idx in range(arr.shape[0])
            if float(np.var(arr[row_idx, :, :].flatten())) < 0.5
        ]
        if low_var_rows:
            findings.append(self._finding(
                path,
                f"Low-variance rows: {len(low_var_rows)} rows (variance < 0.5)",
                f"Rows: {low_var_rows[:10]}",
                severity="MEDIUM", offset=0, flag_match=False, confidence=_STAT_CONF,
            ))

        bits: List[int] = []
        flat = arr[:, :, 0].flatten()
        for i in range(0, len(flat) - 1, 2):
            d = abs(int(flat[i]) - int(flat[i+1]))
            for lo, hi, nbits in _PVD_RANGES:
                if lo <= d <= hi:
                    bits.extend(_int_to_bits(d - lo, nbits))
                    break

        if len(bits) >= 8:
            raw = _bits_to_bytes(bits)
            flag_match, confidence, detail = decode_pipeline(raw, flag_pattern)
            if flag_match or _is_printable(raw):
                findings.append(self._finding(
                    path, "PVD (Pixel Value Differencing) extraction",
                    detail, severity="HIGH" if flag_match else "MEDIUM", offset=0,
                    flag_match=flag_match,
                    confidence=confidence if flag_match else _PRINT_CONF,
                ))

        return findings

    def _img_appended_data(self, path: str, flag_pattern: re.Pattern) -> List[Finding]:
        """Detect and extract data appended after image end markers."""
        findings: List[Finding] = []
        try:
            data = Path(path).read_bytes()
        except Exception:
            return findings

        end_markers = [
            (b"\x89PNG\r\n\x1a\n", b"IEND\xaeB`\x82"),
            (b"\xff\xd8\xff",            b"\xff\xd9"),
            (b"GIF87a",                  b"\x3b"),
            (b"GIF89a",                  b"\x3b"),
        ]
        for start_sig, end_sig in end_markers:
            if data.startswith(start_sig):
                idx = data.rfind(end_sig)
                if idx == -1:
                    continue
                end_offset = idx + len(end_sig)
                after = data[end_offset:]
                if len(after) > 4:
                    flag_match, confidence, detail = decode_pipeline(after, flag_pattern)
                    findings.append(self._finding(
                        path,
                        f"Appended data after image end marker ({len(after)} bytes at 0x{end_offset:x})",
                        detail, severity="HIGH" if flag_match else "MEDIUM",
                        offset=end_offset, flag_match=flag_match,
                        confidence=confidence if flag_match else 0.70,
                    ))
                break

        if data.startswith(b"BM") and len(data) >= 6:
            try:
                declared_size = struct.unpack_from("<I", data, 2)[0]
                if declared_size < len(data):
                    after = data[declared_size:]
                    if len(after) > 4:
                        flag_match, confidence, detail = decode_pipeline(after, flag_pattern)
                        findings.append(self._finding(
                            path,
                            f"BMP appended data beyond declared size ({len(after)} bytes at 0x{declared_size:x})",
                            detail, severity="HIGH" if flag_match else "MEDIUM",
                            offset=declared_size, flag_match=flag_match,
                            confidence=confidence if flag_match else 0.70,
                        ))
            except Exception:
                pass

        return findings

    def _img_metadata_stego(self, path: str, flag_pattern: re.Pattern) -> List[Finding]:
        """Inspect EXIF, PNG tEXt/zTXt/iTXt, and JPEG COM markers for hidden data."""
        findings: List[Finding] = []
        try:
            from PIL import Image
            from PIL.ExifTags import TAGS
            img = Image.open(path)
            exif_data = img.getexif()
            for tag_id, value in exif_data.items():
                tag_name = TAGS.get(tag_id, str(tag_id))
                s = str(value)
                raw_bytes = s.encode("utf-8", errors="replace")
                flag_match, confidence, detail = decode_pipeline(raw_bytes, flag_pattern)
                if flag_match:
                    findings.append(self._finding(
                        path, f"Flag in EXIF field '{tag_name}'",
                        detail, severity="HIGH", offset=0,
                        flag_match=True, confidence=_FLAG_CONF,
                    ))
                elif len(s) > 64 or re.search(r"[A-Za-z0-9+/]{20,}={0,2}$", s):
                    findings.append(self._finding(
                        path, f"Suspicious EXIF field '{tag_name}' (len={len(s)})",
                        detail, severity="MEDIUM", offset=0,
                        flag_match=False, confidence=_STAT_CONF,
                    ))
        except Exception:
            pass

        ext = Path(path).suffix.lower()
        if ext == ".png":
            findings.extend(self._png_text_chunks(path, flag_pattern))
        if ext in (".jpg", ".jpeg"):
            findings.extend(self._jpeg_com_markers(path, flag_pattern))
        return findings

    def _png_text_chunks(self, path: str, flag_pattern: re.Pattern) -> List[Finding]:
        findings: List[Finding] = []
        try:
            data = Path(path).read_bytes()
        except Exception:
            return findings
        offset = 8
        while offset + 12 <= len(data):
            try:
                length = struct.unpack_from(">I", data, offset)[0]
                chunk_type = data[offset+4:offset+8]
                chunk_data = data[offset+8:offset+8+length]
            except Exception:
                break
            chunk_offset = offset
            offset += 12 + length
            if chunk_type in (b"tEXt", b"zTXt", b"iTXt"):
                if chunk_type == b"zTXt":
                    # zTXt chunks are zlib-compressed; try decompression first
                    # before the standard decode pipeline.
                    data_to_decode = chunk_data
                    try:
                        null_pos = chunk_data.index(b"\x00")
                        # +1 skips the null separator, +1 skips the compression
                        # method byte (0x00 = zlib deflate).
                        # Guard against malformed chunks that end at the null byte.
                        if null_pos + 2 <= len(chunk_data):
                            compressed = chunk_data[null_pos + 2:]
                            data_to_decode = zlib.decompress(compressed)
                    except Exception:
                        pass
                    flag_match, confidence, detail = decode_pipeline(data_to_decode, flag_pattern)
                else:
                    flag_match, confidence, detail = decode_pipeline(chunk_data, flag_pattern)
                findings.append(self._finding(
                    path, f"PNG {chunk_type.decode()} chunk text data",
                    detail, severity="HIGH" if flag_match else "MEDIUM",
                    offset=chunk_offset, flag_match=flag_match,
                    confidence=confidence if flag_match else _STAT_CONF,
                ))
        return findings

    def _jpeg_com_markers(self, path: str, flag_pattern: re.Pattern) -> List[Finding]:
        findings: List[Finding] = []
        try:
            data = Path(path).read_bytes()
        except Exception:
            return findings
        i = 0
        while i < len(data) - 3:
            if data[i] == 0xFF and data[i+1] == 0xFE:
                try:
                    length = struct.unpack_from(">H", data, i+2)[0]
                    comment = data[i+4:i+2+length]
                    flag_match, confidence, detail = decode_pipeline(comment, flag_pattern)
                    findings.append(self._finding(
                        path, "JPEG COM (comment) marker",
                        detail, severity="HIGH" if flag_match else "MEDIUM",
                        offset=i, flag_match=flag_match,
                        confidence=confidence if flag_match else _STAT_CONF,
                    ))
                    i += 2 + length
                    continue
                except Exception:
                    pass
            i += 1
        return findings

    def _img_channel_isolation(self, path: str, flag_pattern: re.Pattern) -> List[Finding]:
        """Detect channel entropy anomalies (> 1.5 bit difference) and extract anomalous channel."""
        findings: List[Finding] = []
        try:
            from PIL import Image
            import numpy as np
            arr = np.array(Image.open(path).convert("RGB"), dtype=float)
        except Exception:
            return findings

        entropies: dict = {}
        for ch_idx, ch_name in enumerate(["R", "G", "B"]):
            channel = arr[:, :, ch_idx].flatten().astype(int)
            counts = np.bincount(channel, minlength=256)
            total = counts.sum()
            probs = counts[counts > 0] / total
            entropies[ch_name] = float(-np.sum(probs * np.log2(probs))) if len(probs) > 0 else 0.0

        if len(entropies) >= 2:
            max_ent = max(entropies.values())
            min_ent = min(entropies.values())
            if max_ent - min_ent > 1.5:
                anomalous = min(entropies, key=entropies.get)
                ch_idx = ["R", "G", "B"].index(anomalous)
                try:
                    from PIL import Image
                    import numpy as np
                    arr_int = np.array(Image.open(path).convert("RGB"))
                    raw = bytes(arr_int[:, :, ch_idx].flatten().astype("uint8").tolist())
                    flag_match, confidence, detail = decode_pipeline(raw[:4096], flag_pattern)
                    findings.append(self._finding(
                        path,
                        f"Channel entropy anomaly: {anomalous} ent={entropies[anomalous]:.2f} delta={max_ent-min_ent:.2f}",
                        detail, severity="HIGH" if flag_match else "MEDIUM", offset=0,
                        flag_match=flag_match,
                        confidence=confidence if flag_match else _STAT_CONF,
                    ))
                except Exception:
                    pass

        return findings

    def _img_histogram_analysis(self, path: str, flag_pattern: re.Pattern) -> List[Finding]:
        """Detect comb-pattern histograms and isolated zero-count bins."""
        findings: List[Finding] = []
        try:
            from PIL import Image
            import numpy as np
            arr = np.array(Image.open(path).convert("RGB"))
        except Exception:
            return findings

        for ch_idx, ch_name in enumerate(["R", "G", "B"]):
            counts = np.bincount(arr[:, :, ch_idx].flatten().astype(int), minlength=256)
            pair_diffs = [abs(int(counts[i]) - int(counts[i+1])) for i in range(0, 254, 2)]
            avg_diff = sum(pair_diffs) / len(pair_diffs) if pair_diffs else 0
            avg_count = float(counts.mean()) + 1e-10

            if avg_diff / avg_count < 0.05:
                findings.append(self._finding(
                    path,
                    f"Comb-pattern histogram in channel {ch_name} (pair_diff/avg={avg_diff/avg_count:.4f})",
                    "Classic LSB embedding signature.",
                    severity="MEDIUM", offset=0, flag_match=False, confidence=_STAT_CONF,
                ))

            zeros_in_range = [i for i in range(1, 255)
                              if counts[i] == 0 and counts[i-1] > 0 and counts[i+1] > 0]
            if len(zeros_in_range) > 5:
                findings.append(self._finding(
                    path,
                    f"Isolated zero-count histogram bins in channel {ch_name} ({len(zeros_in_range)} bins)",
                    f"Bins: {zeros_in_range[:20]}",
                    severity="MEDIUM", offset=0, flag_match=False, confidence=_STAT_CONF,
                ))

        return findings

    def _img_pixel_coordinate_encoding(self, path: str, flag_pattern: re.Pattern) -> List[Finding]:
        """Check if first N pixel values directly encode ASCII/flag data."""
        findings: List[Finding] = []
        try:
            from PIL import Image
            pixels = list(Image.open(path).convert("RGB").getdata())
        except Exception:
            return findings
        raw = bytes(v for px in pixels[:512] for v in px)
        flag_match, confidence, detail = decode_pipeline(raw, flag_pattern)
        if flag_match or _is_printable(raw[:64]):
            findings.append(self._finding(
                path, "Pixel coordinate encoding: first pixel values as bytes",
                detail, severity="HIGH" if flag_match else "MEDIUM", offset=0,
                flag_match=flag_match,
                confidence=confidence if flag_match else _PRINT_CONF,
            ))
        return findings

    # ===================================================================
    # AUDIO stego
    # ===================================================================

    def _analyze_audio(self, path: str, flag_pattern: re.Pattern, depth: str) -> List[Finding]:
        findings: List[Finding] = []
        findings.extend(self._audio_lsb_wav(path, flag_pattern))
        findings.extend(self._audio_mp3_metadata(path, flag_pattern))
        findings.extend(self._audio_silence_blocks(path, flag_pattern))
        if depth == "deep":
            findings.extend(self._audio_echo_hiding(path, flag_pattern))
            findings.extend(self._audio_phase_coding(path, flag_pattern))
            findings.extend(self._audio_frequency_domain(path, flag_pattern))
            findings.extend(self._audio_mp3_frame_stego(path, flag_pattern))
        return findings

    def _audio_lsb_wav(self, path: str, flag_pattern: re.Pattern) -> List[Finding]:
        """Extract LSBs from WAV PCM samples (stride 1,2,3,4,8) with chi-square test."""
        findings: List[Finding] = []
        try:
            import wave
            with wave.open(path, "rb") as wf:
                sampwidth = wf.getsampwidth()
                nframes = min(wf.getnframes(), 200000)
                raw = wf.readframes(nframes)
        except Exception:
            return findings

        if sampwidth not in (1, 2):
            return findings

        fmt = "<" + ("b" if sampwidth == 1 else "h") * (len(raw) // sampwidth)
        try:
            samples = struct.unpack(fmt, raw[:len(raw) - len(raw) % sampwidth])
        except Exception:
            return findings

        for stride in [1, 2, 3, 4, 8]:
            strided = samples[::stride]
            bits = [s & 1 for s in strided[:100000]]
            if len(bits) < 8:
                continue
            ones = sum(bits[:min(len(bits), 10000)])
            total = min(len(bits), 10000)
            deviation = abs(ones / total - 0.5) if total > 0 else 0

            raw_bytes = _bits_to_bytes(bits)
            flag_match, confidence, detail = decode_pipeline(raw_bytes, flag_pattern)

            if flag_match:
                severity = "HIGH"
            elif deviation > 0.15:
                severity, confidence = "HIGH", max(confidence, _STAT_CONF)
            elif deviation > 0.05:
                severity, confidence = "MEDIUM", max(confidence, _STAT_CONF)
            elif _is_printable(raw_bytes):
                severity, confidence = "MEDIUM", max(confidence, _PRINT_CONF)
            else:
                continue

            findings.append(self._finding(
                path, f"WAV LSB extraction stride={stride} deviation={deviation:.3f}",
                detail, severity=severity, offset=0,
                flag_match=flag_match, confidence=confidence,
            ))

        return findings

    def _audio_echo_hiding(self, path: str, flag_pattern: re.Pattern) -> List[Finding]:
        """Detect echo hiding via autocorrelation and extract encoded bitstream."""
        findings: List[Finding] = []
        try:
            import wave, numpy as np
            with wave.open(path, "rb") as wf:
                if wf.getsampwidth() != 2 or wf.getnchannels() != 1:
                    return findings
                nframes = min(wf.getnframes(), 100000)
                raw = wf.readframes(nframes)
                framerate = wf.getframerate()
        except Exception:
            return findings

        try:
            samples = np.array(struct.unpack(f"<{len(raw)//2}h", raw), dtype=float)
            n = len(samples)
            autocorr = np.correlate(samples, samples, mode="full")[n-1:]
            autocorr /= autocorr[0] + 1e-10

            peaks = []
            for lag in range(1, min(n // 2, framerate)):
                if (autocorr[lag] > 0.1
                        and (lag < 2 or autocorr[lag] > autocorr[lag-1])
                        and (lag + 1 >= len(autocorr) or autocorr[lag] > autocorr[lag+1])):
                    peaks.append((lag, float(autocorr[lag])))
            peaks.sort(key=lambda x: -x[1])

            if peaks:
                delay_samples, strength = peaks[0]
                segment_size = max(delay_samples * 2, 512)
                bits: List[int] = []
                for start in range(0, n - segment_size, segment_size):
                    seg = samples[start:start+segment_size]
                    seg_ac = np.correlate(seg, seg, mode="full")
                    mid = len(seg_ac) // 2
                    if mid + delay_samples < len(seg_ac):
                        echo_str = abs(seg_ac[mid + delay_samples]) / (abs(seg_ac[mid]) + 1e-10)
                        bits.append(1 if echo_str > 0.05 else 0)

                if len(bits) >= 8:
                    raw_bytes = _bits_to_bytes(bits)
                    flag_match, confidence, detail = decode_pipeline(raw_bytes, flag_pattern)
                    findings.append(self._finding(
                        path,
                        f"Echo hiding detected (delay={delay_samples} samples strength={strength:.3f})",
                        detail, severity="HIGH" if flag_match else "MEDIUM", offset=0,
                        flag_match=flag_match,
                        confidence=confidence if flag_match else _STAT_CONF,
                    ))
        except Exception:
            pass

        return findings

    def _audio_phase_coding(self, path: str, flag_pattern: re.Pattern) -> List[Finding]:
        """Detect phase coding: extract bits from quantized first-segment phase values."""
        findings: List[Finding] = []
        try:
            import wave, numpy as np
            with wave.open(path, "rb") as wf:
                if wf.getsampwidth() != 2 or wf.getnchannels() != 1:
                    return findings
                nframes = min(wf.getnframes(), 200000)
                raw = wf.readframes(nframes)
        except Exception:
            return findings

        try:
            samples = np.array(struct.unpack(f"<{len(raw)//2}h", raw), dtype=float)
            if len(samples) < _PHASE_CODING_WINDOW:
                return findings
            first_phase = np.angle(np.fft.fft(samples[:_PHASE_CODING_WINDOW]))
            bits = [1 if p > 0 else 0 for p in first_phase[:_PHASE_CODING_WINDOW // 2]]
            if len(bits) >= 8:
                raw_bytes = _bits_to_bytes(bits)
                flag_match, confidence, detail = decode_pipeline(raw_bytes, flag_pattern)
                if flag_match or _is_printable(raw_bytes):
                    findings.append(self._finding(
                        path, "Phase coding extraction (first segment phase quantization)",
                        detail, severity="HIGH" if flag_match else "MEDIUM", offset=0,
                        flag_match=flag_match,
                        confidence=confidence if flag_match else _PRINT_CONF,
                    ))
        except Exception:
            pass

        return findings

    def _audio_frequency_domain(self, path: str, flag_pattern: re.Pattern) -> List[Finding]:
        """Flag ultrasonic (>18kHz) and sub-bass (<20Hz) energy; extract amplitude bytes."""
        findings: List[Finding] = []
        try:
            import wave, numpy as np
            with wave.open(path, "rb") as wf:
                sampwidth = wf.getsampwidth()
                framerate = wf.getframerate()
                nframes = min(wf.getnframes(), 200000)
                raw = wf.readframes(nframes)
        except Exception:
            return findings

        try:
            if sampwidth == 2:
                samples = np.array(struct.unpack(f"<{len(raw)//2}h", raw), dtype=float)
            elif sampwidth == 1:
                samples = np.array(struct.unpack(f"{len(raw)}B", raw), dtype=float) - 128
            else:
                return findings

            n = len(samples)
            magnitudes = np.abs(np.fft.rfft(samples))
            freqs = np.fft.rfftfreq(n, 1.0 / framerate)

            ultrasonic = freqs > 18000
            if ultrasonic.any():
                ultra_e = float(magnitudes[ultrasonic].mean())
                normal_e = float(magnitudes[~ultrasonic].mean()) + 1e-10
                if ultra_e / normal_e > 0.1:
                    raw_bytes = bytes(min(int(v) % 256, 255) for v in magnitudes[ultrasonic][:256])
                    flag_match, confidence, detail = decode_pipeline(raw_bytes, flag_pattern)
                    findings.append(self._finding(
                        path,
                        f"Ultrasonic energy detected (>18kHz ratio={ultra_e/normal_e:.3f})",
                        detail, severity="HIGH" if flag_match else "MEDIUM", offset=0,
                        flag_match=flag_match,
                        confidence=confidence if flag_match else _STAT_CONF,
                    ))

            subbass = freqs < 20
            if subbass.any():
                sb = magnitudes[subbass]
                if float(sb.std()) / (float(sb.mean()) + 1e-10) > 2.0:
                    raw_bytes = bytes(min(int(v) % 256, 255) for v in sb[:256])
                    flag_match, confidence, detail = decode_pipeline(raw_bytes, flag_pattern)
                    findings.append(self._finding(
                        path, "Non-uniform sub-bass (<20Hz) spectral distribution",
                        detail, severity="HIGH" if flag_match else "MEDIUM", offset=0,
                        flag_match=flag_match,
                        confidence=confidence if flag_match else _STAT_CONF,
                    ))
        except Exception:
            pass

        return findings

    def _audio_mp3_metadata(self, path: str, flag_pattern: re.Pattern) -> List[Finding]:
        """Inspect ID3v1 and ID3v2 tag blocks for hidden data."""
        findings: List[Finding] = []
        try:
            data = Path(path).read_bytes()
        except Exception:
            return findings

        if len(data) >= 128 and data[-128:-125] == b"TAG":
            flag_match, confidence, detail = decode_pipeline(data[-128:], flag_pattern)
            if flag_match:
                findings.append(self._finding(
                    path, "Flag match in MP3 ID3v1 tag",
                    detail, severity="HIGH", offset=len(data) - 128,
                    flag_match=True, confidence=_FLAG_CONF,
                ))

        if data[:3] == b"ID3" and len(data) >= 10:
            id3_size = _decode_id3v2_synchsafe(data[6:10]) + 10
            block = data[:min(id3_size, len(data))]
            flag_match, confidence, detail = decode_pipeline(block, flag_pattern)
            if flag_match:
                findings.append(self._finding(
                    path, "Flag match in MP3 ID3v2 tag block",
                    detail, severity="HIGH", offset=0,
                    flag_match=True, confidence=_FLAG_CONF,
                ))

        return findings

    def _audio_mp3_frame_stego(self, path: str, flag_pattern: re.Pattern) -> List[Finding]:
        """Scan between MP3 sync words for inter-frame data."""
        findings: List[Finding] = []
        try:
            data = Path(path).read_bytes()
        except Exception:
            return findings

        if not (data.startswith(b"ID3") or data[:2] == b"\xff\xfb"):
            return findings

        inter = bytearray()
        i = 0
        while i < len(data) - 1:
            if data[i] == 0xFF and (data[i+1] & 0xE0) == 0xE0:
                i += 1
            elif data[i] not in (0x00, 0xFF):
                inter.append(data[i])
                i += 1
            else:
                i += 1

        if len(inter) > 8:
            flag_match, confidence, detail = decode_pipeline(bytes(inter), flag_pattern)
            if flag_match or _is_printable(bytes(inter)):
                findings.append(self._finding(
                    path, f"MP3 inter-frame data ({len(inter)} bytes)",
                    detail, severity="HIGH" if flag_match else "MEDIUM", offset=0,
                    flag_match=flag_match,
                    confidence=confidence if flag_match else _PRINT_CONF,
                ))

        return findings

    def _audio_silence_blocks(self, path: str, flag_pattern: re.Pattern) -> List[Finding]:
        """Detect silence blocks > 0.5s; extract LSBs from silence regions."""
        findings: List[Finding] = []
        try:
            import wave
            with wave.open(path, "rb") as wf:
                sampwidth = wf.getsampwidth()
                framerate = wf.getframerate()
                nchannels = wf.getnchannels()
                raw = wf.readframes(wf.getnframes())
        except Exception:
            return findings

        if sampwidth not in (1, 2):
            return findings

        max_amp = (1 << (sampwidth * 8 - 1)) - 1
        threshold = max(int(max_amp * 0.01), 1)
        frame_bytes = sampwidth * nchannels
        min_frames = framerate // 2  # 0.5 s

        silence_start = None
        silence_lsbs: List[int] = []
        all_lsbs: List[int] = []

        for fidx in range(len(raw) // frame_bytes):
            off = fidx * frame_bytes
            fdata = raw[off:off + frame_bytes]
            if len(fdata) < frame_bytes:
                break
            amp = abs(struct.unpack_from("<h", fdata)[0]) if sampwidth == 2 else abs(fdata[0] - 128)
            lsb = fdata[0] & 1

            if amp <= threshold:
                if silence_start is None:
                    silence_start = fidx
                silence_lsbs.append(lsb)
            else:
                if silence_start is not None:
                    dur = fidx - silence_start
                    if dur >= min_frames:
                        all_lsbs.extend(silence_lsbs)
                        findings.append(self._finding(
                            path,
                            f"Silence block at frame {silence_start} ({dur/framerate:.1f}s)",
                            f"LSBs: {_bits_to_bytes(silence_lsbs).hex()[:64]}",
                            severity="MEDIUM", offset=silence_start * frame_bytes,
                            flag_match=False, confidence=_STRUCT_CONF,
                        ))
                    silence_start = None
                    silence_lsbs = []

        if len(all_lsbs) >= 8:
            raw_bytes = _bits_to_bytes(all_lsbs)
            flag_match, confidence, detail = decode_pipeline(raw_bytes, flag_pattern)
            if flag_match or _is_printable(raw_bytes):
                findings.append(self._finding(
                    path, "LSB extraction from silence blocks combined",
                    detail, severity="HIGH" if flag_match else "MEDIUM", offset=0,
                    flag_match=flag_match,
                    confidence=confidence if flag_match else _PRINT_CONF,
                ))

        return findings

    # ===================================================================
    # VIDEO stego
    # ===================================================================

    def _analyze_video(self, path: str, flag_pattern: re.Pattern, depth: str) -> List[Finding]:
        findings: List[Finding] = []
        findings.extend(self._video_container_metadata(path, flag_pattern))
        findings.extend(self._video_appended_data(path, flag_pattern))
        findings.extend(self._video_frame_stego(path, flag_pattern, depth))
        return findings

    def _video_container_metadata(self, path: str, flag_pattern: re.Pattern) -> List[Finding]:
        """Parse MP4/AVI atoms; flag non-standard atom types and extract content."""
        findings: List[Finding] = []
        try:
            data = Path(path).read_bytes()
        except Exception:
            return findings

        known_atoms = {
            b"ftyp", b"moov", b"mdat", b"free", b"skip", b"udta",
            b"trak", b"mdia", b"minf", b"stbl", b"mvhd", b"tkhd",
            b"mdhd", b"hdlr", b"vmhd", b"dinf", b"stsd", b"stts",
            b"stsc", b"stsz", b"stco", b"ctts", b"smhd", b"mp4a",
            b"avc1", b"esds", b"pasp", b"colr", b"edts", b"elst",
            b"wide", b"moof", b"mfhd", b"traf", b"tfhd", b"tfdt",
            b"trun", b"meta", b"ilst", b"data", b"name", b"mean",
        }

        i = 0
        while i + 8 <= len(data):
            try:
                atom_size = struct.unpack_from(">I", data, i)[0]
                atom_type = data[i+4:i+8]
                if atom_size < 8 or atom_size > len(data) - i:
                    break
                if atom_type not in known_atoms:
                    atom_data = data[i+8:i+atom_size]
                    flag_match, confidence, detail = decode_pipeline(atom_data[:4096], flag_pattern)
                    findings.append(self._finding(
                        path,
                        f"Non-standard video atom {atom_type.decode(errors='replace')!r} ({atom_size} bytes)",
                        detail, severity="HIGH" if flag_match else "MEDIUM",
                        offset=i, flag_match=flag_match,
                        confidence=confidence if flag_match else _STAT_CONF,
                    ))
                i += atom_size
            except Exception:
                break

        return findings

    def _video_frame_stego(self, path: str, flag_pattern: re.Pattern, depth: str) -> List[Finding]:
        """Extract video frames via ffmpeg and apply image stego pipeline."""
        findings: List[Finding] = []
        frame_step = 1 if depth == "deep" else 10
        try:
            import subprocess, tempfile, os
            # Validate path contains no shell metacharacters before using in subprocess
            if not os.path.isfile(path):
                return findings
            with tempfile.TemporaryDirectory() as tmpdir:
                frame_out = os.path.join(tmpdir, "frame_%04d.png")
                subprocess.run(
                    ["ffmpeg", "-i", path,
                     "-vf", f"select='not(mod(n\\,{frame_step}))'",
                     "-vsync", "vfr", frame_out, "-y"],
                    capture_output=True, timeout=30,
                )
                for frame_file in sorted(f for f in os.listdir(tmpdir) if f.endswith(".png"))[:20]:
                    fp = os.path.join(tmpdir, frame_file)
                    try:
                        frame_num = int(frame_file.split("_")[1].split(".")[0])
                    except Exception:
                        frame_num = 0
                    for f in self._img_lsb_extraction(fp, flag_pattern):
                        f.title = f"[Frame {frame_num * frame_step}] {f.title}"
                        f.file = path
                        findings.append(f)
                    for f in self._img_appended_data(fp, flag_pattern):
                        f.title = f"[Frame {frame_num * frame_step}] {f.title}"
                        f.file = path
                        findings.append(f)
        except Exception:
            pass
        return findings

    def _video_appended_data(self, path: str, flag_pattern: re.Pattern) -> List[Finding]:
        """Detect data appended after the last video container atom."""
        findings: List[Finding] = []
        try:
            data = Path(path).read_bytes()
        except Exception:
            return findings

        last_end = 0
        i = 0
        while i + 8 <= len(data):
            try:
                atom_size = struct.unpack_from(">I", data, i)[0]
                if atom_size < 8 or atom_size > len(data) - i:
                    break
                last_end = i + atom_size
                i += atom_size
            except Exception:
                break

        if last_end > 0 and last_end < len(data) - 4:
            after = data[last_end:]
            flag_match, confidence, detail = decode_pipeline(after, flag_pattern)
            findings.append(self._finding(
                path,
                f"Video appended data ({len(after)} bytes after last atom at 0x{last_end:x})",
                detail, severity="HIGH" if flag_match else "MEDIUM",
                offset=last_end, flag_match=flag_match,
                confidence=confidence if flag_match else 0.70,
            ))

        return findings

    # ===================================================================
    # TEXT stego
    # ===================================================================

    def _analyze_text(self, path: str, flag_pattern: re.Pattern, depth: str) -> List[Finding]:
        findings: List[Finding] = []
        try:
            text = Path(path).read_text(encoding="utf-8", errors="replace")
        except Exception:
            return findings
        findings.extend(self._text_zero_width(path, text, flag_pattern))
        findings.extend(self._text_whitespace_stego(path, text, flag_pattern))
        findings.extend(self._text_acrostic(path, text, flag_pattern))
        if depth == "deep":
            findings.extend(self._text_homoglyph(path, text, flag_pattern))
        return findings

    def _text_zero_width(self, path: str, text: str, flag_pattern: re.Pattern) -> List[Finding]:
        """Detect zero-width character steganography and decode embedded bitstream."""
        ZW = {"​", "‌", "‍", "﻿", "⁠", "­"}
        positions = [(i, ch) for i, ch in enumerate(text) if ch in ZW]
        if not positions:
            return []

        bits1 = [0 if ch == "​" else 1
                 for _, ch in positions if ch in ("​", "‍")]
        bits2 = [ord(ch) % 2 for _, ch in positions]

        findings: List[Finding] = []
        for scheme, bits in [("ZWSP=0/ZWJ=1", bits1), ("codepoint_mod2", bits2)]:
            if len(bits) < 8:
                continue
            raw = _bits_to_bytes(bits)
            flag_match, confidence, detail = decode_pipeline(raw, flag_pattern)
            if flag_match or _is_printable(raw):
                findings.append(self._finding(
                    path,
                    f"Zero-width char stego ({len(positions)} chars scheme={scheme})",
                    detail + f" | positions={[p for p,_ in positions[:10]]}",
                    severity="HIGH" if flag_match else "MEDIUM",
                    offset=positions[0][0], flag_match=flag_match,
                    confidence=confidence if flag_match else _PRINT_CONF,
                ))
        return findings

    def _text_whitespace_stego(self, path: str, text: str, flag_pattern: re.Pattern) -> List[Finding]:
        """Detect trailing space/tab encoding and word-gap width encoding."""
        findings: List[Finding] = []
        lines = text.splitlines()

        trailing_bits: List[int] = []
        for line in lines:
            stripped = line.rstrip(" 	")
            for ch in line[len(stripped):]:
                trailing_bits.append(0 if ch == " " else 1)

        if len(trailing_bits) >= 8:
            raw = _bits_to_bytes(trailing_bits)
            flag_match, confidence, detail = decode_pipeline(raw, flag_pattern)
            if flag_match or _is_printable(raw):
                findings.append(self._finding(
                    path, "Whitespace stego: trailing space/tab encoding",
                    detail, severity="HIGH" if flag_match else "MEDIUM", offset=0,
                    flag_match=flag_match,
                    confidence=confidence if flag_match else _PRINT_CONF,
                ))

        gap_bits: List[int] = []
        for line in lines:
            for part in re.split(r"( +)", line):
                if part.startswith(" "):
                    gap_bits.append(0 if len(part) == 1 else 1)

        if len(gap_bits) >= 8:
            raw = _bits_to_bytes(gap_bits)
            flag_match, confidence, detail = decode_pipeline(raw, flag_pattern)
            if flag_match or _is_printable(raw):
                findings.append(self._finding(
                    path, "Whitespace stego: word gap width encoding",
                    detail, severity="HIGH" if flag_match else "MEDIUM", offset=0,
                    flag_match=flag_match,
                    confidence=confidence if flag_match else _PRINT_CONF,
                ))

        return findings

    def _text_acrostic(self, path: str, text: str, flag_pattern: re.Pattern) -> List[Finding]:
        """Extract first-letter-of-line, first-word-of-line, first-letter-of-sentence acrostics."""
        findings: List[Finding] = []
        lines = [l for l in text.splitlines() if l.strip()]
        first_letters = "".join(l.lstrip()[0] for l in lines if l.lstrip())
        first_words = " ".join(l.split()[0] for l in lines if l.split())
        first_sent = "".join(s.strip()[0] for s in re.split(r"[.!?]+", text) if s.strip())

        for label, seq in [
            ("first-letter-of-lines", first_letters),
            ("first-word-of-lines",   first_words),
            ("first-letter-of-sentences", first_sent),
        ]:
            if not seq:
                continue
            raw = seq.encode("utf-8", errors="replace")
            flag_match, confidence, detail = decode_pipeline(raw, flag_pattern)
            if flag_match:
                findings.append(self._finding(
                    path, f"Acrostic ({label}): flag match",
                    detail, severity="HIGH", offset=0,
                    flag_match=True, confidence=_FLAG_CONF,
                ))
            elif len(seq) > 4 and _is_printable(raw):
                findings.append(self._finding(
                    path, f"Acrostic ({label}): {seq[:80]!r}",
                    detail, severity="INFO", offset=0,
                    flag_match=False, confidence=_STRUCT_CONF,
                ))

        return findings

    def _text_homoglyph(self, path: str, text: str, flag_pattern: re.Pattern) -> List[Finding]:
        """Detect Unicode homoglyph substitutions and reconstruct encoded bits."""
        findings: List[Finding] = []
        HOMOGLYPHS: dict = {
            "а": "a", "à": "a", "á": "a",
            "е": "e", "è": "e", "é": "e",
            "о": "o", "ò": "o", "ó": "o",
            "і": "i", "ì": "i", "í": "i",
            "с": "c", "ç": "c",
            "р": "p", "х": "x",
            "у": "y", "ý": "y",
            "ѕ": "s",
        }
        positions = [(i, ch, HOMOGLYPHS[ch]) for i, ch in enumerate(text) if ch in HOMOGLYPHS]
        if not positions:
            return []

        ascii_set = set(HOMOGLYPHS.values())
        bits: List[int] = []
        for ch in text:
            if ch in HOMOGLYPHS:
                bits.append(1)
            elif ch in ascii_set:
                bits.append(0)

        if len(bits) >= 8:
            raw = _bits_to_bytes(bits)
            flag_match, confidence, detail = decode_pipeline(raw, flag_pattern)
            findings.append(self._finding(
                path,
                f"Homoglyph substitution ({len(positions)} homoglyphs)",
                detail + f" | positions={[p for p,_,_ in positions[:10]]}",
                severity="HIGH" if flag_match else "MEDIUM",
                offset=positions[0][0], flag_match=flag_match,
                confidence=confidence if flag_match else _STAT_CONF,
            ))

        return findings

    # ===================================================================
    # PDF / Document stego
    # ===================================================================

    def _analyze_document(self, path: str, flag_pattern: re.Pattern, depth: str) -> List[Finding]:
        findings: List[Finding] = []
        try:
            header = Path(path).read_bytes()[:8]
        except Exception:
            return findings

        if header.startswith(b"%PDF"):
            try:
                data = Path(path).read_bytes()
            except Exception:
                return findings
            findings.extend(self._pdf_object_streams(path, data, flag_pattern))
            findings.extend(self._pdf_white_text(path, data, flag_pattern))
            findings.extend(self._pdf_metadata(path, flag_pattern))

        if header[:4] == b"PK":
            findings.extend(self._docx_hidden_content(path, flag_pattern))

        if header[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
            findings.extend(self._ole_streams(path, flag_pattern))

        return findings

    def _pdf_object_streams(self, path: str, data: bytes, flag_pattern: re.Pattern) -> List[Finding]:
        """Decompress and scan all PDF object streams for flag patterns and unknown filters."""
        findings: List[Finding] = []
        known_filters = {
            b"FlateDecode", b"LZWDecode", b"ASCII85Decode",
            b"ASCIIHexDecode", b"RunLengthDecode",
            b"CCITTFaxDecode", b"DCTDecode", b"JPXDecode",
        }
        for m in re.finditer(rb"(\d+ \d+ obj.*?)endobj", data, re.DOTALL):
            obj_data = m.group(1)
            sm = re.search(rb"stream\r?\n(.*?)\r?\nendstream", obj_data, re.DOTALL)
            if not sm:
                continue
            stream = sm.group(1)
            if b"/FlateDecode" in obj_data:
                dec = _try_zlib(stream)
                if dec:
                    stream = dec
            flag_match, confidence, detail = decode_pipeline(stream[:4096], flag_pattern)
            if flag_match:
                findings.append(self._finding(
                    path, "Flag pattern in PDF object stream",
                    detail, severity="HIGH", offset=m.start(),
                    flag_match=True, confidence=_FLAG_CONF,
                ))
            else:
                for f in re.findall(rb"/(\w+Decode)", obj_data):
                    if f not in known_filters:
                        findings.append(self._finding(
                            path,
                            f"PDF object with unknown filter /{f.decode(errors='replace')}",
                            detail, severity="MEDIUM", offset=m.start(),
                            flag_match=False, confidence=_STAT_CONF,
                        ))
        return findings

    def _pdf_white_text(self, path: str, data: bytes, flag_pattern: re.Pattern) -> List[Finding]:
        """Find white or zero-size text in PDF content streams (invisible text)."""
        findings: List[Finding] = []
        text = data.decode("latin-1", errors="replace")
        patterns = [
            (r"""1\s+1\s+1\s+rg\s+(.*?)(Tj|TJ|'|\")""", "white RGB text"),
            (r"""0\s+g\s+(.*?)(Tj|TJ|'|\")""",           "grayscale-0 text"),
            (r"""/F\w+\s+[01]\s+Tf\s+(.*?)(Tj|TJ|'|\")""", "font-size-0/1 text"),
        ]
        for pat, label in patterns:
            for m in re.finditer(pat, text, re.DOTALL):
                content = re.sub(r"[\(\)]", "", m.group(1)).strip()
                if content:
                    raw = content.encode("utf-8", errors="replace")
                    flag_match, confidence, detail = decode_pipeline(raw, flag_pattern)
                    findings.append(self._finding(
                        path,
                        f"PDF hidden text ({label}): {content[:80]!r}",
                        detail, severity="HIGH" if flag_match else "MEDIUM",
                        offset=m.start(), flag_match=flag_match,
                        confidence=confidence if flag_match else _STAT_CONF,
                    ))
        return findings

    def _pdf_metadata(self, path: str, flag_pattern: re.Pattern) -> List[Finding]:
        """Extract and analyse PDF XMP/Info metadata fields."""
        findings: List[Finding] = []
        try:
            import fitz
            doc = fitz.open(path)
            meta = doc.metadata or {}
            doc.close()
        except Exception:
            return findings

        for key, value in meta.items():
            if not value:
                continue
            s = str(value)
            raw = s.encode("utf-8", errors="replace")
            flag_match, confidence, detail = decode_pipeline(raw, flag_pattern)
            if flag_match or len(s) > 64 or re.search(r"[A-Za-z0-9+/]{20,}={0,2}", s):
                findings.append(self._finding(
                    path, f"PDF metadata field '{key}' (len={len(s)})",
                    detail, severity="HIGH" if flag_match else "MEDIUM", offset=0,
                    flag_match=flag_match,
                    confidence=confidence if flag_match else _STAT_CONF,
                ))

        return findings

    def _docx_hidden_content(self, path: str, flag_pattern: re.Pattern) -> List[Finding]:
        """Scan DOCX XML parts for white text, hidden text (w:vanish), and tiny fonts."""
        findings: List[Finding] = []
        try:
            import zipfile
            with zipfile.ZipFile(path, "r") as zf:
                for name in zf.namelist():
                    if not (name.endswith(".xml") or name.endswith(".rels")):
                        continue
                    try:
                        content = zf.read(name)
                    except Exception:
                        continue
                    xml_text = content.decode("utf-8", errors="replace")

                    if re.search(r'w:color\s+w:val\s*=\s*["\'\s]?FFFFFF', xml_text, re.IGNORECASE):
                        flag_match, confidence, detail = decode_pipeline(content, flag_pattern)
                        findings.append(self._finding(
                            path, f"DOCX white text (w:color=FFFFFF) in {name}",
                            detail, severity="HIGH" if flag_match else "MEDIUM", offset=0,
                            flag_match=flag_match,
                            confidence=confidence if flag_match else _STAT_CONF,
                        ))

                    if "w:vanish" in xml_text:
                        findings.append(self._finding(
                            path, f"DOCX hidden text (w:vanish) in {name}",
                            "Hidden text style detected.",
                            severity="MEDIUM", offset=0,
                            flag_match=False, confidence=_STAT_CONF,
                        ))

                    if re.search(r'w:sz\s+w:val\s*=\s*["\'\s]?[12]["\'\s]?', xml_text):
                        findings.append(self._finding(
                            path, f"DOCX tiny font size (w:sz=1 or 2) in {name}",
                            "Font size 1pt may be invisible.",
                            severity="MEDIUM", offset=0,
                            flag_match=False, confidence=_STAT_CONF,
                        ))

                    flag_match, confidence, detail = decode_pipeline(content, flag_pattern)
                    if flag_match:
                        findings.append(self._finding(
                            path, f"Flag pattern in DOCX component {name}",
                            detail, severity="HIGH", offset=0,
                            flag_match=True, confidence=_FLAG_CONF,
                        ))

                    if "docProps/custom.xml" in name:
                        for pm in re.finditer(r"<vt:lpwstr>(.*?)</vt:lpwstr>", xml_text, re.DOTALL):
                            val = pm.group(1)
                            raw = val.encode("utf-8", errors="replace")
                            fm2, conf2, det2 = decode_pipeline(raw, flag_pattern)
                            if fm2 or len(val) > 32:
                                findings.append(self._finding(
                                    path,
                                    f"DOCX custom property: {val[:60]!r}",
                                    det2, severity="HIGH" if fm2 else "MEDIUM", offset=0,
                                    flag_match=fm2,
                                    confidence=conf2 if fm2 else _STAT_CONF,
                                ))
        except Exception:
            pass
        return findings

    def _ole_streams(self, path: str, flag_pattern: re.Pattern) -> List[Finding]:
        """Scan OLE compound document streams for flag patterns and printable data."""
        findings: List[Finding] = []
        try:
            import olefile
            if not olefile.isOleFile(path):
                return findings
            ole = olefile.OleFileIO(path)
            for stream in ole.listdir():
                sp = "/".join(stream)
                try:
                    sdata = ole.openstream(stream).read()
                except Exception:
                    continue
                flag_match, confidence, detail = decode_pipeline(sdata[:4096], flag_pattern)
                if flag_match:
                    findings.append(self._finding(
                        path, f"Flag match in OLE stream '{sp}'",
                        detail, severity="HIGH", offset=0,
                        flag_match=True, confidence=_FLAG_CONF,
                    ))
                elif _is_printable(sdata[:256]) and len(sdata) > 8:
                    findings.append(self._finding(
                        path, f"Printable OLE stream '{sp}' ({len(sdata)} bytes)",
                        detail, severity="INFO", offset=0,
                        flag_match=False, confidence=_STRUCT_CONF,
                    ))
            ole.close()
        except ImportError:
            pass
        except Exception:
            pass
        return findings

    # ===================================================================
    # ZIP comment stego
    # ===================================================================

    def _analyze_zip(self, path: str, flag_pattern: re.Pattern, depth: str) -> List[Finding]:
        """Extract and analyse ZIP comment field and inter-file data."""
        findings: List[Finding] = []
        try:
            import zipfile
            with zipfile.ZipFile(path, "r") as zf:
                comment = zf.comment
                if comment:
                    flag_match, confidence, detail = decode_pipeline(comment, flag_pattern)
                    findings.append(self._finding(
                        path, f"ZIP comment field ({len(comment)} bytes)",
                        detail, severity="HIGH" if flag_match else "MEDIUM", offset=0,
                        flag_match=flag_match,
                        confidence=confidence if flag_match else _STAT_CONF,
                    ))
        except Exception:
            pass

        try:
            data = Path(path).read_bytes()
            inter = bytearray()
            i = 0
            while i < len(data) - 3:
                if data[i:i+4] == b"PK" and len(data) >= i + 30:
                    fname_len = struct.unpack_from("<H", data, i+26)[0]
                    extra_len = struct.unpack_from("<H", data, i+28)[0]
                    comp_size = struct.unpack_from("<I", data, i+18)[0]
                    skip = 30 + fname_len + extra_len + comp_size
                    i += max(skip, 1)
                else:
                    if data[i] != 0x00:
                        inter.append(data[i])
                    i += 1
            if len(inter) > 8:
                flag_match, confidence, detail = decode_pipeline(bytes(inter), flag_pattern)
                if flag_match or _is_printable(bytes(inter)):
                    findings.append(self._finding(
                        path, f"ZIP inter-file data ({len(inter)} bytes)",
                        detail, severity="HIGH" if flag_match else "MEDIUM", offset=0,
                        flag_match=flag_match,
                        confidence=confidence if flag_match else _PRINT_CONF,
                    ))
        except Exception:
            pass

        return findings

    # ===================================================================
    # Generic binary stego (always runs)
    # ===================================================================

    def _generic_binary_stego(self, path: str, flag_pattern: re.Pattern, depth: str) -> List[Finding]:
        """Generic LSB extraction, inter-block LSB, and embedded magic-byte detection."""
        findings: List[Finding] = []
        try:
            data = Path(path).read_bytes()
        except Exception:
            return findings

        if len(data) < 8:
            return findings

        bits = [b & 1 for b in data[:100000]]
        ones = sum(bits[:min(len(bits), 10000)])
        total = min(len(bits), 10000)
        deviation = abs(ones / total - 0.5) if total > 0 else 0

        if deviation > 0.05 or len(data) < 1024:
            raw = _bits_to_bytes(bits)
            flag_match, confidence, detail = decode_pipeline(raw, flag_pattern)
            if flag_match or _is_printable(raw):
                findings.append(self._finding(
                    path,
                    f"Generic binary LSB extraction (chi_deviation={deviation:.3f})",
                    detail, severity="HIGH" if flag_match else "MEDIUM", offset=0,
                    flag_match=flag_match,
                    confidence=confidence if flag_match else _PRINT_CONF,
                ))

        if depth == "deep" and len(data) >= 64:
            inter_bits = [data[i * 8] & 1 for i in range(min(len(data) // 8, 100000))]
            if len(inter_bits) >= 8:
                raw2 = _bits_to_bytes(inter_bits)
                fm2, conf2, det2 = decode_pipeline(raw2, flag_pattern)
                if fm2 or _is_printable(raw2):
                    findings.append(self._finding(
                        path, "Generic inter-block LSB (every 8 bytes -> 1 bit)",
                        det2, severity="HIGH" if fm2 else "MEDIUM", offset=0,
                        flag_match=fm2,
                        confidence=conf2 if fm2 else _PRINT_CONF,
                    ))

        _MAGIC_SIGS = [
            b"\x89PNG", b"\xff\xd8\xff", b"GIF8", b"PK",
            b"%PDF", b"ELF", b"MZ", b"RIFF", b"ID3",
        ]
        for sig in _MAGIC_SIGS:
            idx = data.find(sig, len(sig))
            if idx > 0:
                after = data[idx:]
                fm3, conf3, det3 = decode_pipeline(after[:4096], flag_pattern)
                findings.append(self._finding(
                    path,
                    f"Embedded file signature {sig.hex()} at offset 0x{idx:x}",
                    det3, severity="HIGH" if fm3 else "MEDIUM",
                    offset=idx, flag_match=fm3,
                    confidence=conf3 if fm3 else _STAT_CONF,
                ))

        return findings
