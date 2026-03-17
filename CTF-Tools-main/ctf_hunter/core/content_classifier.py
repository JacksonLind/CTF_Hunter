"""
Content classifier for CTF Hunter.

Takes an :class:`~ctf_hunter.core.extracted_content.ExtractedContent` blob
and returns a :class:`ClassificationResult` describing its detected type,
encoding, suggested analyzers, and any immediate flag match.

Detection order
---------------
1. Flag pattern (always checked first, result carried through all paths)
2. Magic-byte file-type identification
3. Text-encoding detection (base64, hex, binary, morse, polybius, tap code,
   baconian, IC-based Caesar/Vigenère, ROT13)
4. Shannon-entropy routing (> 7.5 → encrypted/compressed, 3.5–7.5 → encoded,
   < 3.5 → plaintext/simple)
"""
from __future__ import annotations

import math
import re
import zlib
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .extracted_content import ExtractedContent

# ---------------------------------------------------------------------------
# Flag pattern – must be checked before any other classification step
# ---------------------------------------------------------------------------
# Matches CTF flag conventions such as CTF{...}, flag{...}, picoCTF{...}, etc.
_FLAG_RE = re.compile(rb"[A-Za-z0-9_]+\{[^\}]{3,50}\}")

# ---------------------------------------------------------------------------
# Magic-byte table
# Each entry: (signature_bytes, byte_offset, mime_type, analyzer_keys)
# Analyzer key names must exactly match ctf_hunter/core/dispatcher.py
# ---------------------------------------------------------------------------
_MAGIC: list[tuple[bytes, int, str, list[str]]] = [
    # Images
    (b"\x89PNG",               0, "image/png",  ["image", "steganalysis", "image_format"]),
    (b"\xff\xd8\xff",          0, "image/jpeg", ["image", "steganalysis", "image_format"]),
    (b"GIF87a",                0, "image/gif",  ["image", "steganalysis", "image_format"]),
    (b"GIF89a",                0, "image/gif",  ["image", "steganalysis", "image_format"]),
    (b"GIF8",                  0, "image/gif",  ["image", "steganalysis", "image_format"]),
    (b"BM",                    0, "image/bmp",  ["image", "steganalysis", "image_format"]),
    # Archives
    (b"PK\x03\x04",           0, "application/zip",     ["archive"]),
    (b"\x1f\x8b",             0, "application/gzip",    ["archive"]),
    (b"\x78\x9c",             0, "application/zlib",    ["archive"]),
    (b"\x78\xda",             0, "application/zlib",    ["archive"]),
    (b"\x78\x01",             0, "application/zlib",    ["archive"]),
    (b"BZh",                  0, "application/x-bzip2", ["archive"]),
    (b"\xfd7zXZ\x00",         0, "application/x-xz",   ["archive"]),
    # Executables
    (b"\x7fELF",              0, "application/x-elf",     ["binary", "disassembly"]),
    (b"MZ",                   0, "application/x-dosexec", ["binary", "disassembly"]),
    # Documents
    (b"%PDF",                 0, "application/pdf",  ["document"]),
    # Audio (non-RIFF)
    (b"ID3",                  0, "audio/mpeg", ["audio"]),
    (b"\xff\xfb",             0, "audio/mpeg", ["audio"]),
    # PCAP (big-endian and little-endian magic)
    (b"\xa1\xb2\xc3\xd4",    0, "application/vnd.tcpdump.pcap", ["pcap"]),
    (b"\xd4\xc3\xb2\xa1",    0, "application/vnd.tcpdump.pcap", ["pcap"]),
    # Database
    (b"SQLite format 3\x00",  0, "application/x-sqlite3", ["database"]),
]

# ---------------------------------------------------------------------------
# Character-set helpers for text encoding detection
# ---------------------------------------------------------------------------
_PRINTABLE: frozenset[int] = frozenset(range(0x20, 0x7F)) | frozenset([0x09, 0x0A, 0x0D])
_B64_CHARS: frozenset[int] = frozenset(
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
)
_HEX_CHARS: frozenset[int] = frozenset(b"0123456789abcdefABCDEF")
_BINARY_CHARS: frozenset[int] = frozenset(b"01 \n\r\t")
_MORSE_CHARS: frozenset[int] = frozenset(b".-/ \n\r\t")
_POLYBIUS_CHARS: frozenset[int] = frozenset(b"12345 \n\r\t")

# ---------------------------------------------------------------------------
# Numeric thresholds
# ---------------------------------------------------------------------------
# Minimum printable-ASCII ratio for content to be treated as text
_PRINTABLE_RATIO_TEXT_THRESHOLD: float = 0.90
# Shannon entropy (bits/byte) thresholds for routing binary blobs
_ENTROPY_HIGH_THRESHOLD: float = 7.5   # > this → likely encrypted / compressed
_ENTROPY_MEDIUM_THRESHOLD: float = 3.5  # > this → likely encoded; ≤ → plaintext
# Index-of-Coincidence bands (English IC ≈ 0.065, random ≈ 0.038)
_IC_CAESAR_MIN: float = 0.058
_IC_CAESAR_MAX: float = 0.072
_IC_VIGENERE_MIN: float = 0.040
_IC_VIGENERE_MAX: float = 0.058  # upper bound == CAESAR_MIN
_BACONIAN_CHARS: frozenset[int] = frozenset(b"ABab \n\r\t")

_ROT13_TABLE = str.maketrans(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
    "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm",
)

# MIME type → file extension for virtual filename generation
_EXT_MAP: dict[str, str] = {
    "image/png":                        ".png",
    "image/jpeg":                       ".jpg",
    "image/gif":                        ".gif",
    "image/bmp":                        ".bmp",
    "image/webp":                       ".webp",
    "audio/wav":                        ".wav",
    "audio/mpeg":                       ".mp3",
    "application/zip":                  ".zip",
    "application/gzip":                 ".gz",
    "application/x-bzip2":             ".bz2",
    "application/x-xz":                ".xz",
    "application/zlib":                ".zlib",
    "application/x-elf":               ".elf",
    "application/x-dosexec":           ".exe",
    "application/pdf":                  ".pdf",
    "application/vnd.tcpdump.pcap":    ".pcap",
    "application/x-sqlite3":           ".db",
}


# ---------------------------------------------------------------------------
# Public dataclass
# ---------------------------------------------------------------------------

@dataclass
class ClassificationResult:
    """Result of classifying an ExtractedContent blob."""

    mime_type: str
    confidence: float
    virtual_filename: str
    suggested_analyzers: list[str]
    is_text: bool
    is_binary: bool
    encoding_detected: str   # "base64" | "hex" | "binary" | "morse" | "polybius" |
                             # "tap_code" | "baconian" | "caesar" | "vigenere" |
                             # "rot13" | "zlib" | "raw" | ""
    flag_match: str          # non-empty string if flag pattern found directly in data


# ---------------------------------------------------------------------------
# Classifier
# ---------------------------------------------------------------------------

class ContentClassifier:
    """Classify an :class:`~ctf_hunter.core.extracted_content.ExtractedContent`
    blob and return a :class:`ClassificationResult`."""

    def classify(
        self,
        content: "ExtractedContent",
        flag_re: "re.Pattern | None" = None,
    ) -> ClassificationResult:
        data: bytes = content.data

        # ------------------------------------------------------------------ #
        # 0. Flag pattern – always checked first; when found, the match is     #
        #    preserved but classification continues through all remaining       #
        #    detection paths to determine proper MIME type and analyzers.       #
        # ------------------------------------------------------------------ #
        flag_re = flag_re if flag_re is not None else _FLAG_RE
        flag_match = _check_flag(data, flag_re)

        # ------------------------------------------------------------------ #
        # 1. Magic bytes                                                        #
        # ------------------------------------------------------------------ #
        mime, analyzers = _magic_classify(data)
        if mime:
            is_text = mime.startswith("text/")
            return ClassificationResult(
                mime_type=mime,
                confidence=0.95,
                virtual_filename=_virtual_filename(content, mime),
                suggested_analyzers=analyzers,
                is_text=is_text,
                is_binary=not is_text,
                encoding_detected="raw",
                flag_match=flag_match,
            )

        # ------------------------------------------------------------------ #
        # 2. Printable-ratio → try text encoding detection first               #
        # ------------------------------------------------------------------ #
        printable_ratio = (
            sum(1 for b in data if b in _PRINTABLE) / len(data)
            if data else 0.0
        )
        entropy = _shannon_entropy(data)

        if printable_ratio > _PRINTABLE_RATIO_TEXT_THRESHOLD:
            try:
                text = data.decode("utf-8")
            except UnicodeDecodeError:
                text = data.decode("latin-1")

            encoding, enc_analyzers, enc_confidence = self._detect_text_encoding(
                data, text, entropy, flag_re=flag_re
            )
            return ClassificationResult(
                mime_type="text/plain",
                confidence=enc_confidence,
                virtual_filename=content.virtual_filename or "content.txt",
                suggested_analyzers=enc_analyzers,
                is_text=True,
                is_binary=False,
                encoding_detected=encoding,
                flag_match=flag_match,
            )

        # ------------------------------------------------------------------ #
        # 3. Entropy routing for binary data                                   #
        # ------------------------------------------------------------------ #
        if entropy > _ENTROPY_HIGH_THRESHOLD:
            decompressed = _try_decompress(data)
            if decompressed:
                return ClassificationResult(
                    mime_type="application/octet-stream",
                    confidence=0.80,
                    virtual_filename=content.virtual_filename or "decompressed.bin",
                    suggested_analyzers=["encoding", "archive"],
                    is_text=False,
                    is_binary=True,
                    encoding_detected="zlib",
                    flag_match=flag_match,
                )
            return ClassificationResult(
                mime_type="application/octet-stream",
                confidence=0.70,
                virtual_filename=content.virtual_filename or "encrypted.bin",
                suggested_analyzers=["crypto", "crypto_rsa"],
                is_text=False,
                is_binary=True,
                encoding_detected="",
                flag_match=flag_match,
            )

        if entropy >= _ENTROPY_MEDIUM_THRESHOLD:
            return ClassificationResult(
                mime_type="application/octet-stream",
                confidence=0.60,
                virtual_filename=content.virtual_filename or "encoded.bin",
                suggested_analyzers=["encoding", "steganalysis", "classical_cipher"],
                is_text=False,
                is_binary=True,
                encoding_detected="",
                flag_match=flag_match,
            )

        # entropy < 3.5 → plaintext / simple encoding
        return ClassificationResult(
            mime_type="text/plain",
            confidence=0.55,
            virtual_filename=content.virtual_filename or "content.txt",
            suggested_analyzers=["encoding", "classical_cipher"],
            is_text=True,
            is_binary=False,
            encoding_detected="raw",
            flag_match=flag_match,
        )

    # ---------------------------------------------------------------------- #
    # Text-encoding detection                                                  #
    # ---------------------------------------------------------------------- #

    def _detect_text_encoding(
        self, data: bytes, text: str, entropy: float, flag_re: re.Pattern = _FLAG_RE
    ) -> tuple[str, list[str], float]:
        """Detect text encoding; return (encoding_name, analyzers, confidence).

        Checks are ordered from most-restrictive charset to least-restrictive so
        that narrower alphabets (e.g. binary ⊂ hex ⊂ base64) do not shadow each
        other:

            binary → baconian → polybius → tap_code → morse → hex → base64 → IC
        """
        stripped = text.strip()
        n = len(stripped)
        if n == 0:
            return "raw", ["encoding"], 0.50

        no_ws = stripped.replace(" ", "").replace("\n", "").replace("\r", "").replace("\t", "")

        # Binary string (0 / 1 / whitespace, groups of 8 bits) ---------------
        # Must come before hex: '0' and '1' are valid hex digits.
        bin_ratio = sum(1 for c in stripped if ord(c) in _BINARY_CHARS) / n
        if (
            bin_ratio > 0.95
            and len(no_ws) % 8 == 0
            and set(no_ws) <= {"0", "1"}
        ):
            return "binary", ["encoding", "classical_cipher"], 0.85

        # Baconian (only A/B characters) --------------------------------------
        # Must come before hex: 'A' and 'B' are valid hex digits.
        if no_ws and set(no_ws.upper()) <= {"A", "B"} and len(no_ws) >= 5:
            return "baconian", ["encoding", "classical_cipher"], 0.80

        # Polybius (2-digit tokens 1-5, separated by whitespace) ---------------
        # Must come before hex: digits 1-5 are valid hex digits.
        # Distinguished from tap code by token length: each Polybius token is
        # exactly 2 digits (e.g. "13 42 51"), whereas tap code uses single digits.
        tokens = stripped.split()
        if (
            tokens
            and all(len(t) == 2 and set(t) <= set("12345") for t in tokens)
        ):
            return "polybius", ["encoding", "classical_cipher"], 0.80

        # Tap code (single digits 1-5 separated by whitespace) ----------------
        tap_match = re.fullmatch(r"[1-5](\s+[1-5])*", stripped)
        if tap_match:
            return "tap_code", ["encoding", "classical_cipher"], 0.75

        # Morse ----------------------------------------------------------------
        morse_ratio = sum(1 for c in stripped if ord(c) in _MORSE_CHARS) / n
        if morse_ratio > 0.95 and ("." in stripped or "-" in stripped):
            return "morse", ["encoding", "classical_cipher"], 0.85

        # Hex ------------------------------------------------------------------
        # Must come before base64: hex chars are a strict subset of base64 chars.
        hex_body = no_ws  # already stripped of whitespace
        hex_ratio = sum(1 for c in hex_body if ord(c) in _HEX_CHARS) / max(len(hex_body), 1)
        if hex_ratio > 0.95 and len(hex_body) % 2 == 0:
            return "hex", ["encoding", "steganalysis"], 0.85

        # Base64 ---------------------------------------------------------------
        b64_ratio = sum(1 for c in no_ws if ord(c) in _B64_CHARS) / max(len(no_ws), 1)
        if b64_ratio > 0.95 and len(no_ws) % 4 == 0:
            return "base64", ["encoding", "classical_cipher"], 0.85

        # IC-based (Caesar / Vigenère) ----------------------------------------
        ic = _index_of_coincidence(text)
        if _IC_CAESAR_MIN <= ic <= _IC_CAESAR_MAX:
            # English-like IC – check if ROT13 reveals a flag first
            rot13 = text.translate(_ROT13_TABLE)
            if flag_re.search(rot13.encode("utf-8", errors="ignore")):
                return "rot13", ["encoding", "classical_cipher"], 0.90
            return "caesar", ["classical_cipher", "encoding"], 0.75

        if _IC_VIGENERE_MIN <= ic < _IC_VIGENERE_MAX:
            return "vigenere", ["classical_cipher", "encoding"], 0.70

        # High printable ratio but IC not recognised – last-chance ROT13 flag
        rot13 = text.translate(_ROT13_TABLE)
        if flag_re.search(rot13.encode("utf-8", errors="ignore")):
            return "rot13", ["encoding", "classical_cipher"], 0.90

        # Fallback
        if entropy < _ENTROPY_MEDIUM_THRESHOLD:
            return "raw", ["encoding", "classical_cipher"], 0.60
        return "raw", ["encoding", "classical_cipher"], 0.55


# ---------------------------------------------------------------------------
# Module-level helpers (pure functions, no state)
# ---------------------------------------------------------------------------

def _check_flag(data: bytes, flag_re: re.Pattern = _FLAG_RE) -> str:
    """Return the first flag-pattern match as a string, or empty string."""
    m = flag_re.search(data)
    if m:
        try:
            return m.group(0).decode("utf-8", errors="replace")
        except Exception:
            return m.group(0).decode("latin-1", errors="replace")
    return ""


def _magic_classify(data: bytes) -> tuple[str, list[str]]:
    """Return (mime_type, analyzer_keys) from magic bytes, or ('', [])."""
    # RIFF sub-type detection (WAV vs WebP) – must come before generic table
    if data[:4] == b"RIFF" and len(data) >= 12:
        subtype = data[8:12]
        if subtype == b"WAVE":
            return "audio/wav", ["audio"]
        if subtype == b"WEBP":
            return "image/webp", ["image", "steganalysis", "image_format"]

    for sig, offset, mime, analyzers in _MAGIC:
        chunk = data[offset: offset + len(sig)]
        if chunk == sig:
            return mime, list(analyzers)

    return "", []


def _shannon_entropy(data: bytes) -> float:
    """Compute Shannon entropy in bits per byte."""
    if not data:
        return 0.0
    freq: dict[int, int] = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _try_decompress(data: bytes) -> bytes | None:
    """Attempt zlib / gzip / raw-deflate decompression; return bytes or None."""
    for wbits in (15, 47, -15):  # zlib, gzip-auto, raw deflate
        try:
            return zlib.decompress(data, wbits)
        except Exception:
            pass
    return None


def _index_of_coincidence(text: str) -> float:
    """Compute Index of Coincidence over alphabetic characters only."""
    letters = [c.upper() for c in text if c.isalpha()]
    n = len(letters)
    if n < 2:
        return 0.0
    freq: dict[str, int] = {}
    for c in letters:
        freq[c] = freq.get(c, 0) + 1
    return sum(v * (v - 1) for v in freq.values()) / (n * (n - 1))


def _virtual_filename(content: "ExtractedContent", mime: str) -> str:
    """Return a virtual filename with an appropriate extension."""
    if content.virtual_filename:
        return content.virtual_filename
    ext = _EXT_MAP.get(mime, ".bin")
    return f"content{ext}"
