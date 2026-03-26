"""
Generic analyzer: entropy, magic/extension mismatch, strings, null bytes.
Runs on every file regardless of type.
"""
from __future__ import annotations

import base64
import io
import math
import re
import string
import struct
import urllib.parse
import wave
import zlib
from collections import Counter
from pathlib import Path
from typing import List, Optional

from core.report import Finding
from core.ai_client import AIClient
from core.external import run_strings
from .base import Analyzer

# STFT header: "# STFT shape: complex64 (129, 1380)"
_STFT_HEADER_RE = re.compile(
    r"#\s*STFT\s+shape\s*:.*?\(\s*(\d+)\s*,\s*(\d+)\s*\)",
    re.IGNORECASE,
)

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


# ---------------------------------------------------------------------------
# Encoding chain BFS — constants, helpers, and transform functions
# ---------------------------------------------------------------------------

_CHAIN_MAX_DEPTH = 8
_CHAIN_MAX_QUEUE = 2000
_CHAIN_PRINTABLE_THRESHOLD = 0.70
# Skip whole-file inputs larger than this — large strings (ROT13/atbash/reverse)
# produce equally large BFS children that can explode queue cost on multi-MB files.
_CHAIN_MAX_INPUT_CHARS = 65_536

_CHAIN_B64_RE = re.compile(r"^[A-Za-z0-9+/=]+$")
_CHAIN_B32_RE = re.compile(r"^[A-Z2-7=]+$")
_CHAIN_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_CHAIN_BIN_RE = re.compile(r"^[01]+$")


def _chain_is_interesting(text: str) -> bool:
    """True if *text* is worth expanding in the BFS.

    A state is interesting when it is ≥70% printable ASCII or looks like a
    recognised encoding format (base64, base32, hex, binary, URL-encoded).
    """
    if not text:
        return False
    printable_ratio = sum(1 for c in text if c in string.printable) / len(text)
    if printable_ratio >= _CHAIN_PRINTABLE_THRESHOLD:
        return True
    t = text.strip()
    if _CHAIN_B64_RE.match(t) and len(t) >= 4:
        return True
    if _CHAIN_B32_RE.match(t.upper()) and len(t) >= 4:
        return True
    if _CHAIN_HEX_RE.match(t) and len(t) % 2 == 0:
        return True
    if _CHAIN_BIN_RE.match(t.replace(" ", "")) and len(t.replace(" ", "")) % 8 == 0:
        return True
    if "%" in t:
        return True
    return False


def _chain_b64(text: str) -> Optional[str]:
    """Standard base64 decode. Gate: `[A-Za-z0-9+/=]+`, length ≥ 4."""
    t = text.strip()
    if len(t) < 4 or not _CHAIN_B64_RE.match(t):
        return None
    try:
        padding = (4 - len(t) % 4) % 4
        decoded = base64.b64decode(t + "=" * padding, validate=False)
        return decoded.decode("latin-1")
    except Exception:
        return None


def _chain_b64url(text: str) -> Optional[str]:
    """URL-safe base64 decode. Gate: must contain '-' or '_'."""
    t = text.strip()
    if "-" not in t and "_" not in t:
        return None
    try:
        padding = (4 - len(t) % 4) % 4
        decoded = base64.urlsafe_b64decode(t + "=" * padding)
        return decoded.decode("latin-1")
    except Exception:
        return None


def _chain_b32(text: str) -> Optional[str]:
    """Base32 decode. Gate: `[A-Z2-7=]+`, length ≥ 8."""
    t = text.strip().upper()
    if len(t) < 8 or not _CHAIN_B32_RE.match(t):
        return None
    try:
        padding = (8 - len(t) % 8) % 8
        decoded = base64.b32decode(t + "=" * padding, casefold=True)
        return decoded.decode("latin-1")
    except Exception:
        return None


def _chain_hex(text: str) -> Optional[str]:
    """Hex string → bytes. Gate: all hex chars, even length, ≥ 2 chars."""
    t = re.sub(r"\s+", "", text)
    if t.lower().startswith("0x"):
        t = t[2:]
    if len(t) < 2 or len(t) % 2 != 0 or not _CHAIN_HEX_RE.match(t):
        return None
    try:
        return bytes.fromhex(t).decode("latin-1")
    except Exception:
        return None


def _chain_url(text: str) -> Optional[str]:
    """Percent-decode. Gate: '%' present in text."""
    if "%" not in text:
        return None
    try:
        decoded = urllib.parse.unquote(text)
        return decoded if decoded != text else None
    except Exception:
        return None


def _chain_rot13(text: str) -> Optional[str]:
    """ROT13. Gate: ≥ 4 alpha chars. Skip if output equals input."""
    if sum(1 for c in text if c.isalpha()) < 4:
        return None
    result = text.translate(str.maketrans(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm",
    ))
    return result if result != text else None


def _chain_atbash(text: str) -> Optional[str]:
    """Atbash cipher. Gate: ≥ 4 alpha chars."""
    if sum(1 for c in text if c.isalpha()) < 4:
        return None
    result = []
    for c in text:
        if c.isupper():
            result.append(chr(ord('Z') - (ord(c) - ord('A'))))
        elif c.islower():
            result.append(chr(ord('z') - (ord(c) - ord('a'))))
        else:
            result.append(c)
    r = "".join(result)
    return r if r != text else None


def _chain_reverse(text: str) -> Optional[str]:
    """Reverse the string. Returns None for palindromes."""
    r = text[::-1]
    return r if r != text else None


def _chain_xor_brute(text: str) -> Optional[str]:
    """XOR every byte with each key 1–255; return result with highest printable ratio.

    Returns None if no key achieves ≥ _CHAIN_PRINTABLE_THRESHOLD printable chars.
    Capped at 4096 bytes for performance.
    """
    raw = text.encode("latin-1", errors="replace")[:4096]
    if len(raw) < 4:
        return None
    best_score = 0.0
    best: Optional[bytes] = None
    for key in range(1, 256):
        xored = bytes(b ^ key for b in raw)
        score = sum(1 for b in xored if 0x20 <= b <= 0x7E) / len(xored)
        if score > best_score:
            best_score = score
            best = xored
    if best_score < _CHAIN_PRINTABLE_THRESHOLD or best is None:
        return None
    return best.decode("latin-1", errors="replace")


def _chain_zlib(text: str) -> Optional[str]:
    """Zlib / raw-deflate / gzip decompress. Tries wbits 15, -15, 47."""
    raw = text.encode("latin-1", errors="replace")
    for wbits in (15, -15, 47):
        try:
            out = zlib.decompress(raw, wbits)
            return out.decode("latin-1")
        except Exception:
            pass
    return None


def _chain_gzip(text: str) -> Optional[str]:
    """Gzip decompress. Gate: starts with \\x1f\\x8b magic."""
    raw = text.encode("latin-1", errors="replace")
    if not raw.startswith(b"\x1f\x8b"):
        return None
    try:
        import gzip
        return gzip.decompress(raw).decode("latin-1")
    except Exception:
        return None


def _chain_binary(text: str) -> Optional[str]:
    """Binary string → ASCII bytes. Gate: only [01], length divisible by 8."""
    t = re.sub(r"\s+", "", text)
    if len(t) < 8 or len(t) % 8 != 0 or not _CHAIN_BIN_RE.match(t):
        return None
    try:
        result = bytes(int(t[i:i + 8], 2) for i in range(0, len(t), 8))
        decoded = result.decode("latin-1")
        return decoded if decoded != text else None
    except Exception:
        return None


# Ordered by CTF frequency (most common transforms first)
_CHAIN_TRANSFORMS: list[tuple[str, object]] = [
    ("base64",    _chain_b64),
    ("base64url", _chain_b64url),
    ("base32",    _chain_b32),
    ("hex",       _chain_hex),
    ("url",       _chain_url),
    ("rot13",     _chain_rot13),
    ("atbash",    _chain_atbash),
    ("reverse",   _chain_reverse),
    ("xor_1byte", _chain_xor_brute),
    ("zlib",      _chain_zlib),
    ("gzip",      _chain_gzip),
    ("binary",    _chain_binary),
]


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

        # --- STFT matrix inversion ---
        findings.extend(self._check_stft_matrix(path, data, flag_pattern, depth))

        # --- Encoding chain BFS ---
        findings.extend(self._check_encoding_chain(path, data, flag_pattern, depth))

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

    def _check_stft_matrix(
        self,
        path: str,
        data: bytes,
        flag_pattern: re.Pattern,
        depth: str,
    ) -> List[Finding]:
        """Detect and invert STFT complex-number matrices serialised as text.

        Looks for a header comment of the form::

            # STFT shape: complex64 (rows, cols)

        followed by one complex literal per line (``(a+bj)`` or ``a+bj``).

        Fast mode: header detection only — emits INFO to alert the analyst.
        Deep mode: parses the full matrix, runs ``scipy.signal.istft``, writes
        a 16-bit mono WAV and embeds it as ``raw_hex=`` for ContentRedispatcher
        re-dispatch (triggers AudioAnalyzer on the reconstructed audio).

        STFT parameter inference::

            n_fft       = (rows - 1) * 2        (rows = n_fft/2 + 1)
            hop_length  = n_fft // 2            (common default)
            sample_rate = 16 000 Hz             (standard speech)
        """
        # --- Decode text (skip obvious binary files) ---
        try:
            text = data.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            try:
                text = data.decode("latin-1", errors="replace")
                non_print = sum(
                    1 for c in text[:2000]
                    if ord(c) < 9 or ord(c) == 11 or ord(c) == 12 or (14 <= ord(c) <= 31)
                )
                if non_print > len(text[:2000]) * 0.30:
                    return []
            except Exception:
                return []

        # --- Fast pre-check: look for STFT header ---
        header_match = _STFT_HEADER_RE.search(text)

        if depth == "fast":
            if not header_match:
                return []
            rows = int(header_match.group(1))
            cols = int(header_match.group(2))
            n_fft = (rows - 1) * 2
            return [self._finding(
                path,
                f"STFT matrix detected ({rows}\u00d7{cols}) \u2014 use deep mode to reconstruct",
                f"Shape: ({rows}, {cols}) | Inferred n_fft={n_fft}, hop={n_fft // 2}, fs=16000 Hz",
                severity="INFO",
                confidence=0.85,
            )]

        # --- Deep mode: parse values ---
        try:
            import numpy as np
            from scipy.signal import istft as _scipy_istft
        except ImportError:
            return []

        lines = [
            ln.strip()
            for ln in text.splitlines()
            if ln.strip() and not ln.strip().startswith("#")
        ]
        if len(lines) < 16:
            return []

        # Quick sanity: sample values spread across the whole file.
        # The STFT matrix is row-major so the first N lines are all from the
        # DC row (row 0), which scipy forces to be purely real for real signals.
        # Sampling a spread catches non-DC rows which are genuinely complex.
        _sample_step = max(1, len(lines) // 50)
        _n_parsed = 0
        _n_complex = 0
        for _i in range(0, len(lines), _sample_step):
            try:
                _v = complex(lines[_i].strip("()"))
                _n_parsed += 1
                if _v.imag != 0.0:
                    _n_complex += 1
            except (ValueError, TypeError):
                pass
        if _n_parsed < 5 or _n_complex < 3:
            return []

        # Parse all values (cap at 1 M to bound memory)
        values: List[complex] = []
        for ln in lines[:1_000_000]:
            try:
                values.append(complex(ln.strip("()")))
            except (ValueError, TypeError):
                pass  # skip non-numeric lines

        if len(values) < 16:
            return []

        # --- Determine shape ---
        if header_match:
            rows = int(header_match.group(1))
            cols = int(header_match.group(2))
            if rows * cols != len(values):
                return [self._finding(
                    path,
                    "STFT header/value count mismatch",
                    f"Header says ({rows}, {cols}) = {rows * cols} values; "
                    f"found {len(values)}",
                    severity="INFO",
                    confidence=0.5,
                )]
        else:
            # Infer shape from common n_fft values (power-of-2)
            rows, cols = 0, 0
            for candidate_n_fft in (256, 512, 128, 1024, 64, 2048):
                r = candidate_n_fft // 2 + 1
                if len(values) % r == 0:
                    rows, cols = r, len(values) // r
                    break
            if rows == 0:
                return []

        # --- ISTFT ---
        n_fft = (rows - 1) * 2
        hop   = n_fft // 2
        fs    = 16_000

        try:
            matrix = np.array(values, dtype=np.complex64).reshape(rows, cols)
            _, audio = _scipy_istft(
                matrix,
                fs=fs,
                nperseg=n_fft,
                noverlap=n_fft - hop,
                nfft=n_fft,
            )
            audio = audio.astype(np.float32)
            peak = float(np.max(np.abs(audio)))
            if peak > 0.0:
                audio /= peak
        except Exception as exc:
            return [self._finding(
                path,
                "STFT matrix found but ISTFT failed",
                f"Shape: ({rows}, {cols}) n_fft={n_fft} error: {exc}",
                severity="INFO",
                confidence=0.5,
            )]

        # --- Write 16-bit PCM mono WAV ---
        try:
            pcm = (audio * 32767.0).astype(np.int16)
            wav_buf = io.BytesIO()
            with wave.open(wav_buf, "wb") as wf:
                wf.setnchannels(1)
                wf.setsampwidth(2)
                wf.setframerate(fs)
                wf.writeframes(pcm.tobytes())
            wav_bytes = wav_buf.getvalue()
        except Exception as exc:
            return [self._finding(
                path,
                "STFT inverted but WAV write failed",
                f"Shape: ({rows}, {cols}) samples={len(audio)} error: {exc}",
                severity="INFO",
                confidence=0.5,
            )]

        duration_s = len(audio) / fs
        fm = self._check_flag(
            wav_bytes.decode("latin-1", errors="replace"), flag_pattern
        )
        detail = (
            f"STFT shape: ({rows}, {cols}) | n_fft={n_fft}, hop={hop}, fs={fs} Hz\n"
            f"Reconstructed {len(audio)} samples ({duration_s:.2f}s) | "
            f"WAV: {len(wav_bytes)} bytes\n"
            f"Re-dispatching WAV for audio analysis\n"
            f"raw_hex={wav_bytes.hex()}"
        )
        return [self._finding(
            path,
            f"STFT matrix inverted \u2014 {duration_s:.1f}s audio reconstructed",
            detail,
            severity="HIGH" if fm else "MEDIUM",
            flag_match=fm,
            confidence=0.92 if fm else 0.82,
        )]

    # ------------------------------------------------------------------
    # Encoding chain BFS
    # ------------------------------------------------------------------

    def _check_encoding_chain(
        self,
        path: str,
        data: bytes,
        flag_pattern: re.Pattern,
        depth: str,
    ) -> List[Finding]:
        """BFS over encoding transforms; emit HIGH finding when a flag is found.

        Collects candidate input strings from the raw file bytes and from
        ``run_strings()``, then runs :meth:`_run_encoding_bfs` on each.
        """
        max_depth = 4 if depth == "fast" else _CHAIN_MAX_DEPTH

        inputs: list[str] = []
        try:
            inputs.append(data.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            try:
                inputs.append(data.decode("latin-1"))
            except Exception:
                pass

        try:
            for s in run_strings(path, min_len=12)[:100]:
                inputs.append(s)
        except Exception:
            pass

        seen_inputs: set[str] = set()
        findings: List[Finding] = []
        for raw_input in inputs:
            t = raw_input.strip()
            if not t or t in seen_inputs:
                continue
            # Skip inputs that are too large for the BFS.  Transforms like
            # ROT13/atbash/reverse have no size guard and produce same-size
            # children, causing queue explosion on multi-MB files.
            if len(t) > _CHAIN_MAX_INPUT_CHARS:
                continue
            seen_inputs.add(t)
            try:
                findings.extend(
                    self._run_encoding_bfs(path, t, flag_pattern, max_depth)
                )
            except Exception:
                pass

        return findings

    def _run_encoding_bfs(
        self,
        path: str,
        start: str,
        flag_pattern: re.Pattern,
        max_depth: int,
    ) -> List[Finding]:
        """BFS worker: explore encoding transform chains from *start*.

        Returns a Finding for every path that ends in a flag-pattern match.
        """
        from collections import deque

        findings: List[Finding] = []
        queue: deque[tuple[str, list[str]]] = deque([(start, [])])
        visited: set[str] = {start[:500]}

        while queue:
            if len(queue) > _CHAIN_MAX_QUEUE:
                break

            current, chain = queue.popleft()
            if len(chain) >= max_depth:
                continue

            for name, fn in _CHAIN_TRANSFORMS:
                try:
                    result = fn(current)  # type: ignore[operator]
                except Exception:
                    continue

                if result is None or result == current:
                    continue

                new_chain = chain + [name]

                try:
                    flag_found = self._check_flag(result, flag_pattern)
                except Exception:
                    flag_found = False

                if flag_found:
                    chain_str = " → ".join(new_chain)
                    preview = (start[:42] + "...") if len(start) > 42 else start
                    findings.append(self._finding(
                        path,
                        f"Encoding chain decoded: {chain_str}",
                        f"Input ({len(start)} chars): {preview}\n"
                        f"Chain: {chain_str}\n"
                        f"Decoded: {result[:300]}",
                        severity="HIGH",
                        flag_match=True,
                        confidence=0.95,
                    ))
                    continue  # flag found — don't explore further from this result

                result_key = result[:500]
                if result_key in visited or not _chain_is_interesting(result):
                    continue
                visited.add(result_key)
                queue.append((result, new_chain))

        return findings
