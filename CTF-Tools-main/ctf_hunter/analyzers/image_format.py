"""
Image Format Deep Parser analyzer.

Parses the raw binary structure of PNG, JPEG, GIF, and BMP files,
independent of Pillow, looking for structural anomalies that hide
data outside normal pixel values.
"""
from __future__ import annotations

import re
import struct
import zlib
from pathlib import Path
from typing import List, Optional

from core.report import Finding
from core.ai_client import AIClient
from .base import Analyzer

# Known valid PNG chunk types (4-byte ASCII)
_PNG_KNOWN_CHUNKS = {
    b"IHDR", b"PLTE", b"IDAT", b"IEND",
    b"tEXt", b"zTXt", b"iTXt", b"bKGD", b"cHRM", b"gAMA",
    b"hIST", b"pHYs", b"sBIT", b"sPLT", b"sRGB", b"tIME",
    b"tRNS", b"eXIf", b"iCCP", b"acTL", b"fcTL", b"fdAT",
    b"oFFs", b"pCAL", b"sCAL", b"sTER", b"vpAg",
}

# Recognized JPEG APP marker identifiers
_JPEG_APP_IDS = {
    b"JFIF\x00", b"Exif\x00\x00", b"Adobe", b"Photoshop 3.0\x00",
    b"ICC_PROFILE\x00", b"XMP", b"FPXR",
}

# Recognized GIF application extensions
_GIF_APP_IDS = {b"NETSCAPE2.0", b"ANIMEXTS1.0"}


def _decode_attempt(data: bytes) -> Optional[str]:
    """Try to decode bytes as UTF-8 or latin-1."""
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        pass
    try:
        return data.decode("latin-1")
    except Exception:
        return None


class ImageFormatAnalyzer(Analyzer):
    """Parse raw image binary structure for steganographic anomalies."""

    def analyze(
        self,
        path: str,
        flag_pattern: re.Pattern,
        depth: str,
        ai_client: Optional[AIClient],
        **_kw,
    ) -> List[Finding]:
        try:
            data = Path(path).read_bytes()
        except Exception:
            return []

        if data.startswith(b"\x89PNG\r\n\x1a\n"):
            return self._parse_png(path, data, flag_pattern)
        elif data.startswith(b"\xff\xd8\xff"):
            return self._parse_jpeg(path, data, flag_pattern)
        elif data.startswith((b"GIF87a", b"GIF89a")):
            return self._parse_gif(path, data, flag_pattern)
        elif data.startswith(b"BM"):
            return self._parse_bmp(path, data, flag_pattern)
        return []

    # ------------------------------------------------------------------
    # PNG parser
    # ------------------------------------------------------------------

    def _parse_png(self, path: str, data: bytes, flag_pattern: re.Pattern) -> List[Finding]:
        findings: List[Finding] = []
        offset = 8  # skip PNG signature
        saw_ihdr = False
        ihdr_count = 0
        saw_iend = False
        chunk_types_seen: list[bytes] = []

        while offset + 12 <= len(data):
            length = struct.unpack_from(">I", data, offset)[0]
            chunk_type = data[offset + 4:offset + 8]

            # Bounds check before reading chunk data and CRC
            if offset + 8 + length + 4 > len(data):
                findings.append(self._finding(
                    path,
                    f"PNG chunk '{chunk_type.decode('latin-1', errors='replace')}' "
                    f"length exceeds file bounds",
                    f"Offset: 0x{offset:x} | Declared length: {length}",
                    severity="MEDIUM",
                    offset=offset,
                    confidence=0.85,
                ))
                break

            chunk_data = data[offset + 8:offset + 8 + length]
            stored_crc = struct.unpack_from(">I", data, offset + 8 + length)[0]

            # Compute and verify CRC
            computed_crc = zlib.crc32(chunk_type + chunk_data) & 0xFFFFFFFF
            if computed_crc != stored_crc:
                findings.append(self._finding(
                    path,
                    f"PNG chunk '{chunk_type.decode('latin-1', errors='replace')}' "
                    f"has invalid CRC",
                    f"Offset: 0x{offset:x} | Expected: 0x{computed_crc:08x} | "
                    f"Stored: 0x{stored_crc:08x}",
                    severity="MEDIUM",
                    offset=offset,
                    confidence=0.80,
                ))

            # Unknown chunk types
            if chunk_type not in _PNG_KNOWN_CHUNKS:
                decoded = _decode_attempt(chunk_data[:200]) or ""
                sev = "HIGH" if self._check_flag(decoded, flag_pattern) else "MEDIUM"
                findings.append(self._finding(
                    path,
                    f"Unknown PNG chunk type: '{chunk_type.decode('latin-1', errors='replace')}'",
                    f"Offset: 0x{offset:x} | Length: {length} | "
                    f"Data preview: {chunk_data[:32].hex()} | Decoded: {decoded[:100]}",
                    severity=sev,
                    offset=offset,
                    flag_match=(sev == "HIGH"),
                    confidence=0.75,
                ))

            # Chunks after IEND
            if saw_iend:
                decoded = _decode_attempt(chunk_data) or chunk_data[:32].hex()
                sev = "HIGH" if self._check_flag(decoded, flag_pattern) else "MEDIUM"
                findings.append(self._finding(
                    path,
                    f"PNG data after IEND: chunk "
                    f"'{chunk_type.decode('latin-1', errors='replace')}'",
                    f"Offset: 0x{offset:x} | Length: {length} | "
                    f"Content: {decoded[:200]}",
                    severity=sev,
                    offset=offset,
                    flag_match=(sev == "HIGH"),
                    confidence=0.90,
                ))

            # Multiple IHDR
            if chunk_type == b"IHDR":
                ihdr_count += 1
                if ihdr_count > 1:
                    findings.append(self._finding(
                        path,
                        f"Multiple IHDR chunks in PNG (count: {ihdr_count})",
                        f"Offset: 0x{offset:x}",
                        severity="MEDIUM",
                        offset=offset,
                        confidence=0.85,
                    ))
                saw_ihdr = True

            if chunk_type == b"IEND":
                saw_iend = True
                chunk_types_seen.append(chunk_type)
                offset += 12 + length
                break  # Exit loop; any remaining bytes are handled as trailer below

            # Text chunks
            if chunk_type == b"tEXt" and chunk_data:
                parts = chunk_data.split(b"\x00", 1)
                keyword = parts[0].decode("latin-1", errors="replace")
                value = parts[1].decode("latin-1", errors="replace") if len(parts) > 1 else ""
                sev = "HIGH" if self._check_flag(value, flag_pattern) else "INFO"
                findings.append(self._finding(
                    path,
                    f"PNG tEXt chunk: keyword='{keyword}'",
                    f"Offset: 0x{offset:x} | Value: {value[:300]}",
                    severity=sev,
                    offset=offset,
                    flag_match=(sev == "HIGH"),
                    confidence=0.70,
                ))

            elif chunk_type == b"zTXt" and chunk_data:
                parts = chunk_data.split(b"\x00", 2)
                keyword = parts[0].decode("latin-1", errors="replace")
                compressed = parts[2] if len(parts) > 2 else b""
                try:
                    decompressed = zlib.decompress(compressed)
                    value = _decode_attempt(decompressed) or decompressed[:64].hex()
                    sev = "HIGH" if self._check_flag(value, flag_pattern) else "INFO"
                    findings.append(self._finding(
                        path,
                        f"PNG zTXt chunk: keyword='{keyword}'",
                        f"Offset: 0x{offset:x} | Decompressed: {value[:300]}",
                        severity=sev,
                        offset=offset,
                        flag_match=(sev == "HIGH"),
                        confidence=0.75,
                    ))
                except zlib.error:
                    findings.append(self._finding(
                        path,
                        f"PNG zTXt chunk with invalid compressed data: '{keyword}'",
                        f"Offset: 0x{offset:x} | Raw: {compressed[:32].hex()}",
                        severity="MEDIUM",
                        offset=offset,
                        confidence=0.70,
                    ))

            elif chunk_type == b"iTXt" and chunk_data:
                null_idx = chunk_data.find(b"\x00")
                keyword = chunk_data[:null_idx].decode("latin-1", errors="replace") if null_idx > 0 else ""
                rest = chunk_data[null_idx + 4:] if null_idx >= 0 else chunk_data
                value = _decode_attempt(rest) or rest[:64].hex()
                sev = "HIGH" if self._check_flag(value, flag_pattern) else "INFO"
                findings.append(self._finding(
                    path,
                    f"PNG iTXt chunk: keyword='{keyword}'",
                    f"Offset: 0x{offset:x} | Value: {value[:300]}",
                    severity=sev,
                    offset=offset,
                    flag_match=(sev == "HIGH"),
                    confidence=0.70,
                ))

            # IDAT: check scanline filter bytes (value > 4 is non-standard)
            elif chunk_type == b"IDAT" and chunk_data:
                try:
                    raw = zlib.decompress(chunk_data)
                    # Simple heuristic: sample every 64th byte from first 1KB
                    sample = raw[:1024]
                    non_standard = [b for b in sample[::64] if b > 4]
                    if non_standard:
                        findings.append(self._finding(
                            path,
                            "PNG IDAT contains non-standard filter bytes",
                            f"Offset: 0x{offset:x} | Non-standard bytes: {non_standard[:10]}",
                            severity="MEDIUM",
                            offset=offset,
                            confidence=0.60,
                        ))
                except zlib.error:
                    pass

            chunk_types_seen.append(chunk_type)
            offset += 12 + length

        # Data after last chunk
        if offset < len(data):
            trailer = data[offset:]
            decoded = _decode_attempt(trailer) or trailer.hex()
            sev = "HIGH" if self._check_flag(decoded, flag_pattern) else "MEDIUM"
            findings.append(self._finding(
                path,
                f"PNG data after final chunk ({len(trailer)} bytes)",
                f"Offset: 0x{offset:x} | Data: {decoded[:200]}",
                severity=sev,
                offset=offset,
                flag_match=(sev == "HIGH"),
                confidence=0.85,
            ))

        return findings

    # ------------------------------------------------------------------
    # JPEG parser
    # ------------------------------------------------------------------

    def _parse_jpeg(self, path: str, data: bytes, flag_pattern: re.Pattern) -> List[Finding]:
        findings: List[Finding] = []
        offset = 0
        saw_eoi = False
        sof_count = 0

        while offset + 2 <= len(data):
            if data[offset] != 0xFF:
                if saw_eoi:
                    trailer = data[offset:]
                    decoded = _decode_attempt(trailer) or trailer[:64].hex()
                    sev = "HIGH" if self._check_flag(decoded, flag_pattern) else "MEDIUM"
                    findings.append(self._finding(
                        path,
                        f"JPEG data after EOI ({len(trailer)} bytes)",
                        f"Offset: 0x{offset:x} | Data: {decoded[:200]}",
                        severity=sev,
                        offset=offset,
                        flag_match=(sev == "HIGH"),
                        confidence=0.90,
                    ))
                break

            marker = data[offset + 1]
            offset += 2

            # Markers without length fields
            if marker in (0xD8, 0xD9):  # SOI, EOI
                if marker == 0xD9:
                    saw_eoi = True
                    if offset < len(data):
                        # Data after EOI
                        trailer = data[offset:]
                        if trailer:
                            decoded = _decode_attempt(trailer) or trailer[:64].hex()
                            sev = "HIGH" if self._check_flag(decoded, flag_pattern) else "MEDIUM"
                            findings.append(self._finding(
                                path,
                                f"JPEG data after EOI marker ({len(trailer)} bytes)",
                                f"Offset: 0x{offset:x} | Data: {decoded[:200]}",
                                severity=sev,
                                offset=offset,
                                flag_match=(sev == "HIGH"),
                                confidence=0.90,
                            ))
                    break
                continue

            if offset + 2 > len(data):
                break
            length = struct.unpack_from(">H", data, offset)[0]
            payload = data[offset + 2:offset + length]
            offset += length

            # SOF markers (0xC0–0xC3, 0xC5–0xCF)
            if 0xC0 <= marker <= 0xCF and marker not in (0xC4, 0xC8, 0xCC):
                sof_count += 1
                if sof_count > 1:
                    findings.append(self._finding(
                        path,
                        f"Multiple SOF markers in JPEG (count: {sof_count})",
                        f"Offset: 0x{offset - length:x} | Marker: 0xFF{marker:02X}",
                        severity="MEDIUM",
                        offset=offset - length,
                        confidence=0.80,
                    ))

            # APP markers (0xE0–0xEF)
            elif 0xE0 <= marker <= 0xEF:
                app_num = marker - 0xE0
                identifier = payload[:min(12, len(payload))]
                recognized = any(payload.startswith(known) for known in _JPEG_APP_IDS)
                if not recognized:
                    decoded = _decode_attempt(payload) or payload[:64].hex()
                    sev = "HIGH" if self._check_flag(decoded, flag_pattern) else "MEDIUM"
                    findings.append(self._finding(
                        path,
                        f"JPEG APP{app_num} with unrecognized identifier",
                        f"Offset: 0x{offset - length:x} | "
                        f"Identifier: {identifier!r} | "
                        f"Content: {decoded[:200]}",
                        severity=sev,
                        offset=offset - length,
                        flag_match=(sev == "HIGH"),
                        confidence=0.70,
                    ))
                else:
                    # Still extract and attempt decode for recognized APPs
                    decoded = _decode_attempt(payload[6:]) or ""
                    if decoded and self._check_flag(decoded, flag_pattern):
                        findings.append(self._finding(
                            path,
                            f"JPEG APP{app_num} payload matches flag pattern",
                            f"Offset: 0x{offset - length:x} | Content: {decoded[:200]}",
                            severity="HIGH",
                            offset=offset - length,
                            flag_match=True,
                            confidence=0.90,
                        ))

            # COM marker
            elif marker == 0xFE:
                decoded = _decode_attempt(payload) or payload[:64].hex()
                sev = "HIGH" if self._check_flag(decoded, flag_pattern) else "INFO"
                findings.append(self._finding(
                    path,
                    "JPEG COM (comment) marker",
                    f"Offset: 0x{offset - length:x} | Content: {decoded[:300]}",
                    severity=sev,
                    offset=offset - length,
                    flag_match=(sev == "HIGH"),
                    confidence=0.80,
                ))

            # DQT: quantization tables
            elif marker == 0xDB:
                # Standard luminance table values (DC coefficients) for reference
                if len(payload) >= 65:
                    table_id = payload[0] & 0x0F
                    table_data = payload[1:65]
                    # Check if all values are 1 (trivial table = possible watermark)
                    if all(b == 1 for b in table_data) or all(b == table_data[0] for b in table_data):
                        findings.append(self._finding(
                            path,
                            f"JPEG DQT table {table_id} has unusual uniform values",
                            f"Offset: 0x{offset - length:x} | Table: {table_data[:16].hex()}",
                            severity="MEDIUM",
                            offset=offset - length,
                            confidence=0.65,
                        ))

        return findings

    # ------------------------------------------------------------------
    # GIF parser
    # ------------------------------------------------------------------

    def _parse_gif(self, path: str, data: bytes, flag_pattern: re.Pattern) -> List[Finding]:
        findings: List[Finding] = []
        if len(data) < 13:
            return []

        # Header (6) + Logical Screen Descriptor (7)
        lsd_flags = data[10]
        has_gct = bool(lsd_flags & 0x80)
        gct_size = 3 * (2 ** ((lsd_flags & 0x07) + 1)) if has_gct else 0
        offset = 13 + gct_size
        saw_trailer = False

        while offset < len(data):
            introducer = data[offset]

            if saw_trailer:
                trailer_data = data[offset:]
                decoded = _decode_attempt(trailer_data) or trailer_data[:64].hex()
                sev = "HIGH" if self._check_flag(decoded, flag_pattern) else "MEDIUM"
                findings.append(self._finding(
                    path,
                    f"GIF data after trailer ({len(trailer_data)} bytes)",
                    f"Offset: 0x{offset:x} | Data: {decoded[:200]}",
                    severity=sev,
                    offset=offset,
                    flag_match=(sev == "HIGH"),
                    confidence=0.90,
                ))
                break

            # Trailer
            if introducer == 0x3B:
                saw_trailer = True
                offset += 1
                continue

            # Extension
            if introducer == 0x21:
                if offset + 1 >= len(data):
                    break
                ext_label = data[offset + 1]
                offset += 2

                # Comment extension
                if ext_label == 0xFE:
                    comment = self._read_gif_blocks(data, offset)
                    decoded = _decode_attempt(comment) or comment[:64].hex()
                    sev = "HIGH" if self._check_flag(decoded, flag_pattern) else "INFO"
                    findings.append(self._finding(
                        path,
                        "GIF comment extension block",
                        f"Offset: 0x{offset:x} | Content: {decoded[:300]}",
                        severity=sev,
                        offset=offset,
                        flag_match=(sev == "HIGH"),
                        confidence=0.80,
                    ))

                # Plain text extension
                elif ext_label == 0x01:
                    if offset + 12 < len(data):
                        block_size = data[offset]
                        plain_text = self._read_gif_blocks(data, offset + 1 + block_size)
                        decoded = _decode_attempt(plain_text) or plain_text[:64].hex()
                        sev = "HIGH" if self._check_flag(decoded, flag_pattern) else "INFO"
                        findings.append(self._finding(
                            path,
                            "GIF plain text extension block",
                            f"Offset: 0x{offset:x} | Content: {decoded[:300]}",
                            severity=sev,
                            offset=offset,
                            flag_match=(sev == "HIGH"),
                            confidence=0.75,
                        ))

                # Application extension
                elif ext_label == 0xFF:
                    if offset + 1 < len(data):
                        block_size = data[offset]
                        app_id = data[offset + 1:offset + 1 + block_size]
                        if app_id not in _GIF_APP_IDS:
                            sub_data = self._read_gif_blocks(data, offset + 1 + block_size)
                            decoded = _decode_attempt(sub_data) or sub_data[:32].hex()
                            sev = "HIGH" if self._check_flag(decoded, flag_pattern) else "MEDIUM"
                            findings.append(self._finding(
                                path,
                                f"GIF non-standard application extension: {app_id!r}",
                                f"Offset: 0x{offset:x} | Data: {decoded[:200]}",
                                severity=sev,
                                offset=offset,
                                flag_match=(sev == "HIGH"),
                                confidence=0.70,
                            ))
                else:
                    # Unknown extension
                    sub_data = self._read_gif_blocks(data, offset)
                    decoded = _decode_attempt(sub_data) or sub_data[:32].hex()
                    findings.append(self._finding(
                        path,
                        f"GIF unknown extension label: 0x{ext_label:02X}",
                        f"Offset: 0x{offset:x} | Data: {decoded[:100]}",
                        severity="MEDIUM",
                        offset=offset,
                        confidence=0.65,
                    ))

                # Skip sub-blocks
                while offset < len(data):
                    block_size = data[offset]
                    offset += 1
                    if block_size == 0:
                        break
                    offset += block_size

            # Image descriptor
            elif introducer == 0x2C:
                if offset + 10 > len(data):
                    break
                offset += 10
                lct_flags = data[offset - 1] if offset > 0 else 0
                has_lct = bool(lct_flags & 0x80)
                lct_size = 3 * (2 ** ((lct_flags & 0x07) + 1)) if has_lct else 0
                offset += lct_size + 1  # skip LCT + LZW min code size
                # Skip sub-blocks
                while offset < len(data):
                    block_size = data[offset]
                    offset += 1
                    if block_size == 0:
                        break
                    offset += block_size
            else:
                # Unknown introducer
                findings.append(self._finding(
                    path,
                    f"GIF unknown block introducer: 0x{introducer:02X}",
                    f"Offset: 0x{offset:x}",
                    severity="MEDIUM",
                    offset=offset,
                    confidence=0.70,
                ))
                break

        return findings

    def _read_gif_blocks(self, data: bytes, offset: int) -> bytes:
        """Read GIF sub-blocks and return concatenated data."""
        result = bytearray()
        while offset < len(data):
            size = data[offset]
            offset += 1
            if size == 0:
                break
            result.extend(data[offset:offset + size])
            offset += size
        return bytes(result)

    # ------------------------------------------------------------------
    # BMP parser
    # ------------------------------------------------------------------

    def _parse_bmp(self, path: str, data: bytes, flag_pattern: re.Pattern) -> List[Finding]:
        findings: List[Finding] = []

        if len(data) < 54:
            return []

        # BITMAPFILEHEADER (14 bytes)
        bf_type = data[0:2]
        bf_size = struct.unpack_from("<I", data, 2)[0]
        bf_reserved1 = struct.unpack_from("<H", data, 6)[0]
        bf_reserved2 = struct.unpack_from("<H", data, 8)[0]
        bf_off_bits = struct.unpack_from("<I", data, 10)[0]

        # Check declared size vs actual
        actual_size = len(data)
        if bf_size != actual_size:
            findings.append(self._finding(
                path,
                "BMP declared file size mismatch",
                f"Declared: {bf_size} | Actual: {actual_size}",
                severity="MEDIUM",
                confidence=0.80,
            ))

        # Reserved fields
        if bf_reserved1 != 0 or bf_reserved2 != 0:
            hidden = struct.pack("<HH", bf_reserved1, bf_reserved2)
            decoded = _decode_attempt(hidden) or hidden.hex()
            sev = "HIGH" if self._check_flag(decoded, flag_pattern) else "MEDIUM"
            findings.append(self._finding(
                path,
                "BMP non-zero reserved fields (possible hidden data)",
                f"Reserved1: 0x{bf_reserved1:04X} | Reserved2: 0x{bf_reserved2:04X} | "
                f"Decoded: {decoded!r}",
                severity=sev,
                offset=6,
                flag_match=(sev == "HIGH"),
                confidence=0.85,
            ))

        # Gap between headers and pixel data
        header_end = 14  # BITMAPFILEHEADER size
        if len(data) >= 18:
            bi_size = struct.unpack_from("<I", data, 14)[0]
            info_end = 14 + bi_size
            if bf_off_bits > info_end and bf_off_bits <= len(data):
                gap = data[info_end:bf_off_bits]
                if gap:
                    decoded = _decode_attempt(gap) or gap[:64].hex()
                    sev = "HIGH" if self._check_flag(decoded, flag_pattern) else "MEDIUM"
                    findings.append(self._finding(
                        path,
                        f"BMP gap between header and pixel data ({len(gap)} bytes)",
                        f"Offset: 0x{info_end:x}–0x{bf_off_bits:x} | "
                        f"Content: {decoded[:200]}",
                        severity=sev,
                        offset=info_end,
                        flag_match=(sev == "HIGH"),
                        confidence=0.85,
                    ))

            # BITMAPINFOHEADER
            if len(data) >= info_end:
                bi_compression = struct.unpack_from("<I", data, 30)[0] if len(data) >= 34 else 0
                bi_clr_used = struct.unpack_from("<I", data, 46)[0] if len(data) >= 50 else 0

                # Abnormally large color table for BI_RGB (0)
                if bi_compression == 0 and bi_clr_used > 256:
                    findings.append(self._finding(
                        path,
                        f"BMP BI_RGB with abnormally large color table ({bi_clr_used} entries)",
                        f"Offset: 0x{info_end:x} | Color table entries: {bi_clr_used}",
                        severity="MEDIUM",
                        offset=info_end,
                        confidence=0.75,
                    ))

        # Data after declared pixel data
        if len(data) > 54:
            bi_size_img = struct.unpack_from("<I", data, 34)[0] if len(data) >= 38 else 0
            pixel_end = bf_off_bits + bi_size_img
            if bi_size_img > 0 and pixel_end < len(data):
                appended = data[pixel_end:]
                decoded = _decode_attempt(appended) or appended[:64].hex()
                sev = "HIGH" if self._check_flag(decoded, flag_pattern) else "MEDIUM"
                findings.append(self._finding(
                    path,
                    f"BMP data appended after pixel data ({len(appended)} bytes)",
                    f"Offset: 0x{pixel_end:x} | Content: {decoded[:200]}",
                    severity=sev,
                    offset=pixel_end,
                    flag_match=(sev == "HIGH"),
                    confidence=0.85,
                ))

        return findings
