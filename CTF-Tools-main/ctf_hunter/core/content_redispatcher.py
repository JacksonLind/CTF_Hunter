"""
Content Re-Dispatcher for CTF Hunter.

:class:`ContentRedispatcher` is the core of the recursive extraction pipeline.
It classifies each :class:`~ctf_hunter.core.extracted_content.ExtractedContent`
blob, checks for flag patterns, unwraps detected encodings, and re-dispatches
the result through the full existing analyzer suite.

Processing steps
----------------
A. Classify the blob using :class:`~ctf_hunter.core.content_classifier.ContentClassifier`.
B. If a flag pattern is found directly in the data, emit a HIGH finding and continue.
C. If an encoding is detected, decode / decrypt the data and recurse on the result.
   Also try XOR brute-force (single-byte and multi-byte rotating key) on any blob.
D. Re-dispatch the blob as a virtual file through all suggested analyzers.
E. Recursion guards:
   * Never re-process a content hash already seen (``session._seen_content_hashes``).
   * Never exceed depth 5.
   * Never spend more than 45 seconds in total per root ``process()`` call.
     After the timer fires, emit one WARNING finding listing how many objects
     were left in the queue.
"""
from __future__ import annotations

import base64
import bz2
import gzip
import hashlib
import io
import lzma
import os
import re
import tempfile
import threading
import zlib
from typing import Optional

from .content_classifier import ContentClassifier, _FLAG_RE, _EXT_MAP
from .extracted_content import ExtractedContent, MAX_DEPTH
from .report import Finding, Session

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_TIMEOUT_SECONDS: float = 45.0         # per-root-call time budget (spec requirement)
_XOR_SINGLE_QUALITY_THRESHOLD: float = 0.85   # min (printable_ratio + flag_bonus) to recurse
_XOR_MULTI_PRINTABLE_THRESHOLD: float = 0.90  # min printable ratio for multi-byte XOR result

# English unigram frequencies (used for Vigenère hill-climbing)
_ENGLISH_FREQ: dict[str, float] = {
    "A": 0.082, "B": 0.015, "C": 0.028, "D": 0.043, "E": 0.127, "F": 0.022,
    "G": 0.020, "H": 0.061, "I": 0.070, "J": 0.002, "K": 0.008, "L": 0.040,
    "M": 0.024, "N": 0.067, "O": 0.075, "P": 0.019, "Q": 0.001, "R": 0.060,
    "S": 0.063, "T": 0.091, "U": 0.028, "V": 0.010, "W": 0.024, "X": 0.002,
    "Y": 0.020, "Z": 0.001,
}

# Morse code table: symbol → character
_MORSE_TABLE: dict[str, str] = {
    ".-": "A", "-...": "B", "-.-.": "C", "-..": "D", ".": "E",
    "..-.": "F", "--.": "G", "....": "H", "..": "I", ".---": "J",
    "-.-": "K", ".-..": "L", "--": "M", "-.": "N", "---": "O",
    ".--.": "P", "--.-": "Q", ".-.": "R", "...": "S", "-": "T",
    "..-": "U", "...-": "V", ".--": "W", "-..-": "X", "-.--": "Y",
    "--..": "Z", "-----": "0", ".----": "1", "..---": "2", "...--": "3",
    "....-": "4", ".....": "5", "-....": "6", "--...": "7", "---..": "8",
    "----.": "9", ".-.-.-": ".", "--..--": ",", "..--..": "?",
}

# Baconian: 5-letter A/B group → character
_BACONIAN_TABLE: dict[str, str] = {
    "AAAAA": "A", "AAAAB": "B", "AAABA": "C", "AAABB": "D", "AABAA": "E",
    "AABAB": "F", "AABBA": "G", "AABBB": "H", "ABAAA": "I", "ABAAB": "J",
    "ABABA": "K", "ABABB": "L", "ABBAA": "M", "ABBAB": "N", "ABBBA": "O",
    "ABBBB": "P", "BAAAA": "Q", "BAAAB": "R", "BAABA": "S", "BAABB": "T",
    "BABAA": "U", "BABAB": "V", "BABBA": "W", "BABBB": "X", "BBAAA": "Y",
    "BBAAB": "Z",
}

# Polybius square: "RC" → letter  (I and J share cell 24→I)
_letters_polybius = "ABCDEFGHIKLMNOPQRSTUVWXYZ"  # 25 letters, I/J merged
_POLYBIUS_TABLE: dict[str, str] = {}
for _idx, _ch in enumerate(_letters_polybius):
    _r, _c = divmod(_idx, 5)
    _POLYBIUS_TABLE[f"{_r + 1}{_c + 1}"] = _ch


# ---------------------------------------------------------------------------
# Internal timeout context
# ---------------------------------------------------------------------------


def _compile_session_flag_re(session: "Session") -> re.Pattern:
    """Return a *bytes* regex compiled from ``session.flag_pattern``.

    Falls back to the module-level :data:`_FLAG_RE` if the session attribute is
    absent, empty, or contains an invalid regex pattern.  This ensures that the
    caller's custom ``--flag`` pattern (or GUI-configured pattern) is honoured
    everywhere inside :class:`ContentRedispatcher` rather than using the
    hard-coded default.
    """
    raw = getattr(session, "flag_pattern", None)
    if not raw:
        return _FLAG_RE
    # session.flag_pattern is a str; compile it as a bytes pattern so it can be
    # used directly against raw bytes blobs inside _process / _unwrap.
    try:
        pattern_bytes = raw.encode("utf-8") if isinstance(raw, str) else raw
        return re.compile(pattern_bytes)
    except (re.error, UnicodeEncodeError):
        return _FLAG_RE


class _TimeoutContext:
    """Tracks the 45-second recursion budget for a single root ``process()`` call."""

    def __init__(self, seconds: float = _TIMEOUT_SECONDS) -> None:
        self._event = threading.Event()
        self._skipped: int = 0
        self._timer = threading.Timer(seconds, self._event.set)
        self._timer.daemon = True

    # ------------------------------------------------------------------
    def start(self) -> None:
        self._timer.start()

    def cancel(self) -> None:
        self._timer.cancel()

    @property
    def expired(self) -> bool:
        return self._event.is_set()

    def skip(self) -> None:
        self._skipped += 1

    @property
    def skipped(self) -> int:
        return self._skipped


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class ContentRedispatcher:
    """Recursively classify, decode, and re-dispatch extracted content blobs."""

    def __init__(self) -> None:
        self._classifier = ContentClassifier()

    # ---------------------------------------------------------------------- #
    # Public entry-point                                                       #
    # ---------------------------------------------------------------------- #

    def process(
        self,
        content: ExtractedContent,
        session: "Session",
        dispatcher,
    ) -> list[Finding]:
        """Classify *content* and recursively produce findings.

        Args:
            content: The blob to process.
            session: Active analysis session.  A ``_seen_content_hashes`` set
                is created on *session* if one does not already exist.
            dispatcher: Module (or object) with an ``analyze_file`` callable
                matching the signature used by :mod:`ctf_hunter.core.dispatcher`.

        Returns:
            List of new :class:`~ctf_hunter.core.report.Finding` objects.
        """
        # Lazily attach the dedup-set to the session
        if not hasattr(session, "_seen_content_hashes"):
            session._seen_content_hashes = set()

        ctx = _TimeoutContext()
        ctx.start()
        try:
            findings = self._process(content, session, dispatcher, ctx)
        finally:
            ctx.cancel()

        if ctx.skipped:
            findings.append(Finding(
                file=content.virtual_filename or "<extracted>",
                analyzer="ContentRedispatcher",
                title="Recursion timeout: content objects skipped",
                severity="WARNING",
                detail=(
                    f"{ctx.skipped} content object(s) were not processed because the "
                    f"45-second recursion time limit was reached."
                ),
                confidence=1.0,
            ))

        return findings

    # ---------------------------------------------------------------------- #
    # Internal recursive step                                                  #
    # ---------------------------------------------------------------------- #

    def _process(
        self,
        content: ExtractedContent,
        session: "Session",
        dispatcher,
        ctx: _TimeoutContext,
    ) -> list[Finding]:
        # ── Step E: recursion guards ──────────────────────────────────────────
        if ctx.expired:
            ctx.skip()
            return []

        if content.content_hash in session._seen_content_hashes:
            return []

        session._seen_content_hashes.add(content.content_hash)

        if content.depth > MAX_DEPTH:
            return []

        # ── Step A: classify ─────────────────────────────────────────────────
        # Compile the session's flag_pattern so classifier and sub-steps use the
        # same (possibly custom) pattern rather than the module-level default.
        flag_re = _compile_session_flag_re(session)
        classification = self._classifier.classify(content, flag_re=flag_re)
        findings: list[Finding] = []

        # ── Step B: flag check ───────────────────────────────────────────────
        if classification.flag_match:
            chain_str = (
                " → ".join(content.encoding_chain) if content.encoding_chain else "raw"
            )
            findings.append(Finding(
                file=content.virtual_filename or "<extracted>",
                analyzer="ContentRedispatcher",
                title="Flag found in extracted content",
                severity="HIGH",
                detail=(
                    f"Flag: {classification.flag_match}\n"
                    f"Encoding chain: {chain_str}\n"
                    f"Source finding: {content.source_finding_id}"
                ),
                flag_match=True,
                confidence=0.99,
            ))

        # ── Step C: encoding unwrap → recurse ────────────────────────────────
        children = self._unwrap(content, classification, flag_re=flag_re)
        for child in children:
            if ctx.expired:
                ctx.skip()
                continue
            findings.extend(self._process(child, session, dispatcher, ctx))

        # ── Step D: full re-dispatch as virtual file ──────────────────────────
        if classification.suggested_analyzers and not ctx.expired:
            findings.extend(
                self._redispatch(content, classification, session, dispatcher)
            )

        return findings

    # ---------------------------------------------------------------------- #
    # Step C helpers                                                           #
    # ---------------------------------------------------------------------- #

    def _unwrap(
        self,
        content: ExtractedContent,
        classification,
        flag_re: re.Pattern = _FLAG_RE,
    ) -> list[ExtractedContent]:
        """Produce child ExtractedContent objects by decoding the detected encoding."""
        enc = classification.encoding_detected
        data = content.data
        results: list[ExtractedContent] = []

        if enc == "base64":
            dec = _try_b64(data)
            if dec:
                results.append(self._child(content, dec, "base64"))

        elif enc == "hex":
            dec = _try_hex(data)
            if dec:
                results.append(self._child(content, dec, "hex"))

        elif enc == "binary":
            dec = _try_binary(data)
            if dec:
                results.append(self._child(content, dec, "binary"))

        elif enc == "space_binary":
            dec = _try_space_binary(data)
            if dec:
                results.append(self._child(content, dec, "space_binary"))

        elif enc == "morse":
            dec = _try_morse(data)
            if dec:
                results.append(self._child(content, dec, "morse"))

        elif enc == "rot13":
            dec = _try_rot13(data)
            if dec:
                results.append(self._child(content, dec, "rot13"))

        elif enc == "caesar":
            results.extend(self._try_all_caesar(content, flag_re=flag_re))

        elif enc == "vigenere":
            results.extend(self._try_vigenere(content))

        elif enc == "polybius":
            dec = _try_polybius(data)
            if dec:
                results.append(self._child(content, dec, "polybius"))

        elif enc == "tap_code":
            dec = _try_tap(data)
            if dec:
                results.append(self._child(content, dec, "tap_code"))

        elif enc == "baconian":
            dec = _try_baconian(data)
            if dec:
                results.append(self._child(content, dec, "baconian"))

        elif enc == "zlib" or classification.mime_type in (
            "application/zlib",
            "application/gzip",
            "application/x-bzip2",
            "application/x-xz",
        ):
            for fmt, fn in (
                ("zlib", _try_zlib),
                ("gzip", _try_gzip_decompress),
                ("bzip2", _try_bzip2),
                ("xz", _try_xz),
            ):
                dec = fn(data)
                if dec:
                    child = self._child(content, dec, fmt)
                    if child:
                        results.append(child)
                    break

        # Space-binary: always attempted unconditionally.
        # ContentClassifier may label a space-separated binary blob as "binary"
        # or "unknown" (because _try_binary previously stripped spaces), so we
        # cannot rely solely on enc == "space_binary".  Attempting it here
        # ensures the decode fires even when classification misses it.
        if enc != "space_binary":   # avoid double-processing if classifier caught it
            dec = _try_space_binary(data)
            if dec:
                child = self._child(content, dec, "space_binary")
                if child:
                    results.append(child)

        # XOR brute-force: always attempted on any blob
        results.extend(self._try_xor_single(content, flag_re=flag_re))
        results.extend(self._try_xor_multi(content))

        return [r for r in results if r is not None]

    # -- Caesar / ROT --

    def _try_all_caesar(
        self,
        content: ExtractedContent,
        flag_re: re.Pattern = _FLAG_RE,
    ) -> list[ExtractedContent]:
        """Try all 25 Caesar shifts; return children that produce a flag match."""
        try:
            text = content.data.decode("ascii", errors="ignore")
        except Exception:
            return []
        children: list[ExtractedContent] = []
        for shift in range(1, 26):
            shifted = _caesar_shift(text, shift)
            shifted_bytes = shifted.encode("ascii", errors="ignore")
            if flag_re.search(shifted_bytes):
                child = self._child(content, shifted_bytes, f"caesar_{shift}")
                if child:
                    children.append(child)
        return children

    # -- Vigenère --

    def _try_vigenere(self, content: ExtractedContent) -> list[ExtractedContent]:
        """Estimate key via IC + unigram hill-climb; return decrypted child."""
        try:
            text = content.data.decode("ascii", errors="ignore")
        except Exception:
            return []
        letters = [c.upper() for c in text if c.isalpha()]
        if len(letters) < 20:
            return []

        # Find best key length via average IC across sub-sequences
        best_keylen, best_ic = 1, -1.0
        for keylen in range(1, 17):
            sub_ics: list[float] = []
            for pos in range(keylen):
                sub = letters[pos::keylen]
                if len(sub) >= 2:
                    sub_ics.append(_ic_letters(sub))
            if sub_ics:
                avg = sum(sub_ics) / len(sub_ics)
                if avg > best_ic:
                    best_ic, best_keylen = avg, keylen

        # For each key position find best shift by unigram frequency score
        key_shifts: list[int] = []
        for pos in range(best_keylen):
            sub = letters[pos::best_keylen]
            best_shift, best_score = 0, -1.0
            for shift in range(26):
                dec = [(ord(c) - ord("A") - shift) % 26 for c in sub]
                score = sum(_ENGLISH_FREQ.get(chr(v + ord("A")), 0.0) for v in dec)
                if score > best_score:
                    best_score, best_shift = score, shift
            key_shifts.append(best_shift)

        # Decrypt
        result_chars: list[str] = []
        key_pos = 0
        for c in text:
            if c.isalpha():
                shift = key_shifts[key_pos % best_keylen]
                base = ord("A") if c.isupper() else ord("a")
                result_chars.append(chr((ord(c) - base - shift) % 26 + base))
                key_pos += 1
            else:
                result_chars.append(c)
        decrypted = "".join(result_chars).encode("ascii", errors="ignore")
        key_str = "".join(chr(s + ord("A")) for s in key_shifts)
        child = self._child(content, decrypted, f"vigenere_key_{key_str}")
        return [child] if child else []

    # -- XOR single-byte brute-force --

    def _try_xor_single(
        self,
        content: ExtractedContent,
        flag_re: re.Pattern = _FLAG_RE,
    ) -> list[ExtractedContent]:
        """Try XOR with every possible single byte; recurse on best if score > 0.85."""
        data = content.data
        if not data:
            return []

        best_key, best_score, best_data = 0, -1.0, b""
        for key in range(256):
            dec = bytes(b ^ key for b in data)
            printable = sum(1 for b in dec if 0x20 <= b < 0x7F) / len(dec)
            flag_bonus = 1.0 if flag_re.search(dec) else 0.0
            combined = printable + flag_bonus
            if combined > best_score:
                best_key, best_score, best_data = key, combined, dec

        if best_score > _XOR_SINGLE_QUALITY_THRESHOLD and best_data:
            child = self._child(content, best_data, f"xor_0x{best_key:02x}")
            return [child] if child else []
        return []

    # -- XOR multi-byte rotating key --

    def _try_xor_multi(self, content: ExtractedContent) -> list[ExtractedContent]:
        """IC-based key-length detection + per-position printable-ratio attack."""
        data = content.data
        if len(data) < 16:
            return []

        # Find key length with highest average IC
        best_keylen, best_ic = 2, -1.0
        for keylen in range(2, 17):
            sub_ics: list[float] = []
            for pos in range(keylen):
                sub = bytes(data[i] for i in range(pos, len(data), keylen))
                if len(sub) >= 2:
                    sub_ics.append(_ic_bytes(sub))
            if sub_ics:
                avg = sum(sub_ics) / len(sub_ics)
                if avg > best_ic:
                    best_ic, best_keylen = avg, keylen

        # For each key position, find byte that maximises printable ratio
        key = bytearray()
        for pos in range(best_keylen):
            sub = bytes(data[i] for i in range(pos, len(data), best_keylen))
            best_byte, best_ratio = 0, -1.0
            for b in range(256):
                dec = bytes(x ^ b for x in sub)
                ratio = sum(1 for x in dec if 0x20 <= x < 0x7F) / max(len(dec), 1)
                if ratio > best_ratio:
                    best_ratio, best_byte = ratio, b
            key.append(best_byte)

        result = bytes(data[i] ^ key[i % len(key)] for i in range(len(data)))
        printable_ratio = sum(1 for b in result if 0x20 <= b < 0x7F) / len(result)
        if printable_ratio > _XOR_MULTI_PRINTABLE_THRESHOLD:
            child = self._child(content, result, f"xor_key_{key.hex()}")
            return [child] if child else []
        return []

    # ---------------------------------------------------------------------- #
    # Step D helper                                                            #
    # ---------------------------------------------------------------------- #

    def _redispatch(
        self,
        content: ExtractedContent,
        classification,
        session: "Session",
        dispatcher,
    ) -> list[Finding]:
        """Write *content* to a temp file and run suggested analyzers on it."""
        ext = _EXT_MAP.get(classification.mime_type, ".bin")
        if content.virtual_filename:
            _, detected_ext = os.path.splitext(content.virtual_filename)
            suffix = detected_ext or ext
        else:
            suffix = ext

        tmp_path: Optional[str] = None
        try:
            with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
                tmp.write(content.data)
                tmp_path = tmp.name

            findings: list[Finding] = dispatcher.analyze_file(
                tmp_path,
                session,
                analyzers=classification.suggested_analyzers,
                virtual_name=content.virtual_filename or f"content{ext}",
            )

            # Tag each finding with the originating source finding ID
            for f in findings:
                f.source_finding_id = content.source_finding_id
                tag = f"Source finding: {content.source_finding_id}"
                f.detail = f"{f.detail}\n{tag}" if f.detail else tag

            return findings

        except Exception as exc:
            return [Finding(
                file=content.virtual_filename or "<extracted>",
                analyzer="ContentRedispatcher",
                title=f"Re-dispatch error: {type(exc).__name__}",
                severity="INFO",
                detail=str(exc),
                confidence=0.1,
            )]
        finally:
            if tmp_path:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass

    # ---------------------------------------------------------------------- #
    # Child content factory                                                    #
    # ---------------------------------------------------------------------- #

    def _child(
        self,
        parent: ExtractedContent,
        data: bytes,
        encoding_step: str,
    ) -> Optional[ExtractedContent]:
        """Create a child ExtractedContent from decoded bytes; returns None if invalid."""
        if not data:
            return None
        new_depth = parent.depth + 1
        if new_depth > MAX_DEPTH:
            return None
        return ExtractedContent(
            data=data,
            label=f"{parent.label} → {encoding_step}",
            source_finding_id=parent.source_finding_id,
            source_analyzer=parent.source_analyzer,
            encoding_chain=parent.encoding_chain + [encoding_step],
            content_hash=hashlib.sha256(data).hexdigest(),
            depth=new_depth,
            mime_hint="",
            virtual_filename="",
        )


# ---------------------------------------------------------------------------
# Pure decoding helpers (module-level, no state)
# ---------------------------------------------------------------------------

def _try_b64(data: bytes) -> Optional[bytes]:
    """Attempt standard and URL-safe base64 decode."""
    text = data.strip()
    for fn in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            return fn(text)
        except Exception:
            pass
    return None


def _try_hex(data: bytes) -> Optional[bytes]:
    text = data.decode("ascii", errors="ignore").strip().replace(" ", "").replace("\n", "")
    try:
        return bytes.fromhex(text)
    except Exception:
        return None


def _try_binary(data: bytes) -> Optional[bytes]:
    """Convert a compact (no-space) binary string to bytes.

    Explicitly rejects space-separated binary (e.g. "01001000 01101001") so that
    _try_space_binary can handle that format.  Previously this function stripped
    all whitespace before validating, which caused it to silently consume
    space-binary blobs and produce incorrectly-lengthed output — preventing the
    space_binary classifier branch from ever being reached.
    """
    text = data.decode("ascii", errors="ignore").strip()
    # Reject if the input contains spaces — that's space-binary, handled separately
    if " " in text:
        return None
    bits = text.replace("\n", "").replace("\r", "").replace("\t", "")
    if not bits or len(bits) % 8 != 0 or not set(bits) <= {"0", "1"}:
        return None
    return bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits), 8))


# Matches space-separated 8-bit binary groups, e.g. "01100110 01101100 01100001 01100111".
# Distinct from the compact-binary pattern (no embedded spaces).
_SPACE_BINARY_RE = re.compile(rb'^([01]{8})( [01]{8})+$')


def _try_space_binary(data: bytes) -> Optional[bytes]:
    """Convert a space-separated 8-bit binary string to its ASCII byte representation.

    Each space-delimited token must be exactly 8 binary digits (0 or 1).
    Returns the decoded bytes, or *None* if the input does not match the pattern.
    """
    stripped = data.strip()
    if not _SPACE_BINARY_RE.match(stripped):
        return None
    groups = stripped.decode("ascii").split(" ")
    try:
        return bytes(int(g, 2) for g in groups)
    except Exception:
        return None


def _try_morse(data: bytes) -> Optional[bytes]:
    """Decode Morse code (letters separated by spaces, words by '/' or double space)."""
    text = data.decode("ascii", errors="ignore").strip()
    # Prefer '/' as word separator; fall back to double-space
    if "/" in text:
        words = text.split("/")
    else:
        words = text.split("  ")
    decoded_words: list[str] = []
    for word in words:
        letters = word.strip().split()
        word_str = ""
        for code in letters:
            ch = _MORSE_TABLE.get(code.strip())
            if ch is None:
                return None
            word_str += ch
        decoded_words.append(word_str)
    return " ".join(decoded_words).encode("ascii")


def _try_rot13(data: bytes) -> Optional[bytes]:
    """Apply ROT-13."""
    import codecs
    try:
        return codecs.decode(data.decode("ascii", errors="ignore"), "rot_13").encode("ascii", errors="ignore")
    except Exception:
        return None


def _try_polybius(data: bytes) -> Optional[bytes]:
    """Decode a Polybius-square ciphertext (two-digit tokens, each in 1–5)."""
    text = data.decode("ascii", errors="ignore").strip()
    tokens = text.split()
    result: list[str] = []
    for token in tokens:
        if len(token) != 2 or not all(c in "12345" for c in token):
            return None
        ch = _POLYBIUS_TABLE.get(token)
        if ch is None:
            return None
        result.append(ch)
    return "".join(result).encode("ascii")


def _try_tap(data: bytes) -> Optional[bytes]:
    """Decode a tap-code message (single digit pairs from 1–5 separated by spaces)."""
    text = data.decode("ascii", errors="ignore").strip()
    tokens = text.split()
    if len(tokens) % 2 != 0:
        return None
    result: list[str] = []
    for i in range(0, len(tokens), 2):
        pair = tokens[i] + tokens[i + 1]
        if len(pair) != 2 or not all(c in "12345" for c in pair):
            return None
        ch = _POLYBIUS_TABLE.get(pair)
        if ch is None:
            return None
        result.append(ch)
    return "".join(result).encode("ascii")


def _try_baconian(data: bytes) -> Optional[bytes]:
    """Decode a Baconian cipher (groups of 5 A/B characters)."""
    text = data.decode("ascii", errors="ignore").upper().strip()
    chars_only = "".join(c for c in text if c in "AB")
    if len(chars_only) % 5 != 0:
        return None
    result: list[str] = []
    for i in range(0, len(chars_only), 5):
        group = chars_only[i:i + 5]
        ch = _BACONIAN_TABLE.get(group)
        if ch is None:
            return None
        result.append(ch)
    return "".join(result).encode("ascii")


def _try_zlib(data: bytes) -> Optional[bytes]:
    """Attempt zlib / gzip-auto / raw-deflate decompression."""
    for wbits in (15, 47, -15):
        try:
            return zlib.decompress(data, wbits)
        except Exception:
            pass
    return None


def _try_gzip_decompress(data: bytes) -> Optional[bytes]:
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(data)) as gz:
            return gz.read()
    except Exception:
        return None


def _try_bzip2(data: bytes) -> Optional[bytes]:
    try:
        return bz2.decompress(data)
    except Exception:
        return None


def _try_xz(data: bytes) -> Optional[bytes]:
    try:
        return lzma.decompress(data)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Cryptanalysis utilities
# ---------------------------------------------------------------------------

def _caesar_shift(text: str, shift: int) -> str:
    """Apply a Caesar shift to all alphabetic characters."""
    result: list[str] = []
    for c in text:
        if c.isalpha():
            base = ord("A") if c.isupper() else ord("a")
            result.append(chr((ord(c) - base + shift) % 26 + base))
        else:
            result.append(c)
    return "".join(result)


def _ic_letters(letters: list[str]) -> float:
    """Index of Coincidence for a list of uppercase letter characters."""
    n = len(letters)
    if n < 2:
        return 0.0
    freq: dict[str, int] = {}
    for c in letters:
        freq[c] = freq.get(c, 0) + 1
    return sum(v * (v - 1) for v in freq.values()) / (n * (n - 1))


def _ic_bytes(data: bytes) -> float:
    """Index of Coincidence for a byte sequence."""
    n = len(data)
    if n < 2:
        return 0.0
    freq: dict[int, int] = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    return sum(v * (v - 1) for v in freq.values()) / (n * (n - 1))