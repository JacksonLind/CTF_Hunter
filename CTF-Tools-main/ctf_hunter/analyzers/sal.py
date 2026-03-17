"""
Saleae Logic 2 .sal file analyzer.

A .sal file is a ZIP archive containing:
  meta.json        — capture metadata (sample rate, enabled channels)
  digital-N.bin    — binary transition data for channel N

Steps:
  1. Unpack and validate the archive structure.
  2. Parse the Saleae binary header for each digital-N.bin.
  3. Auto-detect baud rate from minimum inter-transition delta.
  4. Decode UART 8N1 (with 7N1 / 8E2 fallbacks on high framing-error rate).
  5. Post-decode pipeline: flag match → base64/image → printable → hex.
"""
from __future__ import annotations

import base64
import bisect
import json
import os
import re
import string
import struct
import tempfile
import zipfile
from pathlib import Path
from typing import List, Optional, Tuple

from core.report import Finding
from core.ai_client import AIClient
from .base import Analyzer

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_SALEAE_MAGIC   = b"<SALEAE>"
_HEADER_SIZE    = 44

_STANDARD_BAUDS = [
    300, 1200, 2400, 4800, 9600, 19200,
    38400, 57600, 115200, 230400, 460800, 921600,
]

_BASE64_CHARS = set(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    "0123456789+/=\r\n"
)
_PRINTABLE = set(string.printable)
_HEX_RE    = re.compile(r"^[0-9a-fA-F\r\n\s]+$")

_PNG_MAGIC  = b"\x89PNG\r\n\x1a\n"
_JPEG_MAGIC = b"\xff\xd8\xff"


# ---------------------------------------------------------------------------
# Internal data container
# ---------------------------------------------------------------------------

class _Channel:
    __slots__ = (
        "index", "initial_state", "begin_time", "end_time",
        "num_transitions", "timestamps",
    )

    def __init__(
        self,
        index: int,
        initial_state: int,
        begin_time: float,
        end_time: float,
        num_transitions: int,
        timestamps: List[float],
    ) -> None:
        self.index           = index
        self.initial_state   = initial_state
        self.begin_time      = begin_time
        self.end_time        = end_time
        self.num_transitions = num_transitions
        self.timestamps      = timestamps


# ---------------------------------------------------------------------------
# Analyzer
# ---------------------------------------------------------------------------

class SalAnalyzer(Analyzer):

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
        tmp_files: List[str] = []

        try:
            # Step 1 + 2: unpack and parse channels
            channels, meta_findings = self._unpack(path)
            findings.extend(meta_findings)
            if not channels:
                return findings

            active = [c for c in channels if c.num_transitions > 0]
            if not active:
                findings.append(self._finding(
                    path,
                    "Saleae .sal — all channels empty (zero transitions)",
                    f"{len(channels)} channel(s) parsed, none had transitions.",
                    severity="INFO",
                    confidence=0.50,
                ))
                return findings

            findings.append(self._finding(
                path,
                f"Saleae .sal — {len(active)} active channel(s) of {len(channels)}",
                "\n".join(
                    f"  ch{c.index}: {c.num_transitions} transitions, "
                    f"duration {c.end_time - c.begin_time:.3f}s"
                    for c in active
                ),
                severity="INFO",
                confidence=0.70,
            ))

            # Step 3: baud rate detection on channel with most transitions
            best_ch = max(active, key=lambda c: c.num_transitions)
            baud, bp, baud_findings = self._detect_baud(path, best_ch)
            findings.extend(baud_findings)
            if baud is None or bp is None:
                return findings

            # Step 4: UART 8N1 decode
            decoded, error_rate, uart_findings = self._uart_decode(
                path, best_ch, bp, framing="8N1"
            )
            findings.extend(uart_findings)

            if error_rate > 0.20:
                findings.append(self._finding(
                    path,
                    f"UART 8N1 framing error rate {error_rate*100:.1f}% — "
                    "trying fallback framings (7N1, 8E2)",
                    "",
                    severity="INFO",
                    confidence=0.60,
                ))
                for framing in ("7N1", "8E2"):
                    fb_bytes, fb_err, fb_findings = self._uart_decode(
                        path, best_ch, bp, framing=framing
                    )
                    findings.extend(fb_findings)
                    if fb_bytes and fb_err < error_rate:
                        decoded    = fb_bytes
                        error_rate = fb_err
                        findings.append(self._finding(
                            path,
                            f"UART {framing} produced lower error rate "
                            f"({fb_err*100:.1f}%) — using this framing",
                            "",
                            severity="INFO",
                            confidence=0.65,
                        ))
                        break

            if not decoded:
                return findings

            # Step 5: post-decode pipeline
            findings.extend(
                self._post_decode(path, decoded, flag_pattern, tmp_files)
            )

        finally:
            for f in tmp_files:
                try:
                    os.unlink(f)
                except OSError:
                    pass

        self._run_redispatch_hook(findings, session, dispatcher_module)
        return findings

    # ------------------------------------------------------------------
    # Step 1 + 2 — unpack and parse
    # ------------------------------------------------------------------

    def _unpack(self, path: str) -> Tuple[List[_Channel], List[Finding]]:
        findings: List[Finding] = []
        channels: List[_Channel] = []

        try:
            zf = zipfile.ZipFile(path, "r")
        except zipfile.BadZipFile as exc:
            findings.append(self._finding(
                path,
                f"Saleae .sal — not a valid ZIP archive: {exc}",
                "",
                severity="INFO",
                confidence=0.30,
            ))
            return channels, findings

        with zf:
            names = zf.namelist()

            if "meta.json" not in names:
                findings.append(self._finding(
                    path,
                    "Saleae .sal — meta.json missing from archive",
                    f"Archive contents: {', '.join(names[:20])}",
                    severity="INFO",
                    confidence=0.40,
                ))
                return channels, findings

            # Parse meta.json
            try:
                meta        = json.loads(zf.read("meta.json").decode("utf-8"))
                sr_block    = meta.get("sampleRate", {})
                sample_rate = int(sr_block.get("digital", 0)) or None
                enabled     = meta.get("enabledChannels", [])
                findings.append(self._finding(
                    path,
                    f"Saleae .sal metadata — {sample_rate} Hz digital, "
                    f"{len(enabled)} enabled channel(s)",
                    json.dumps(meta, indent=2)[:600],
                    severity="INFO",
                    confidence=0.80,
                ))
            except Exception as exc:
                findings.append(self._finding(
                    path,
                    f"Saleae .sal — meta.json parse error: {exc}",
                    "",
                    severity="INFO",
                    confidence=0.30,
                ))
                return channels, findings

            # Parse each digital-N.bin present in the archive
            for name in sorted(names):
                m = re.match(r"digital-(\d+)\.bin$", name)
                if not m:
                    continue
                ch_idx = int(m.group(1))
                try:
                    raw = zf.read(name)
                    ch  = _parse_channel_bin(ch_idx, raw)
                    if ch is not None:
                        channels.append(ch)
                except Exception as exc:
                    findings.append(self._finding(
                        path,
                        f"Saleae .sal — error parsing {name}: {exc}",
                        "",
                        severity="INFO",
                        confidence=0.30,
                    ))

        return channels, findings

    # ------------------------------------------------------------------
    # Step 3 — baud rate detection
    # ------------------------------------------------------------------

    def _detect_baud(
        self, path: str, ch: _Channel
    ) -> Tuple[Optional[int], Optional[float], List[Finding]]:
        findings: List[Finding] = []
        ts = ch.timestamps

        if len(ts) < 2:
            findings.append(self._finding(
                path,
                f"Saleae .sal — channel {ch.index}: too few transitions "
                "to detect baud rate",
                f"{len(ts)} transition(s).",
                severity="INFO",
                confidence=0.40,
            ))
            return None, None, findings

        deltas = [
            ts[i] - ts[i - 1]
            for i in range(1, len(ts))
            if ts[i] - ts[i - 1] > 1e-12
        ]
        if not deltas:
            return None, None, findings

        min_delta = min(deltas)
        if min_delta <= 0:
            return None, None, findings

        raw_baud = round(1.0 / min_delta)

        # Snap to nearest standard baud rate within 5 %
        snapped = raw_baud
        for std in _STANDARD_BAUDS:
            if abs(raw_baud - std) / std <= 0.05:
                snapped = std
                break

        bp = 1.0 / snapped

        findings.append(self._finding(
            path,
            f"Saleae .sal — detected baud rate {snapped:,} baud",
            f"Channel {ch.index}: {len(ts)} transitions\n"
            f"Min inter-transition delta: {min_delta:.9f}s\n"
            f"Raw baud: {raw_baud:,}  →  Snapped: {snapped:,}\n"
            f"Bit period: {bp:.9f}s",
            severity="MEDIUM",
            confidence=0.85,
        ))

        return snapped, bp, findings

    # ------------------------------------------------------------------
    # Step 4 — UART decode
    # ------------------------------------------------------------------

    def _uart_decode(
        self,
        path: str,
        ch: _Channel,
        bp: float,
        framing: str = "8N1",
    ) -> Tuple[Optional[bytes], float, List[Finding]]:
        """Decode UART from transition timestamps.

        Returns (decoded_bytes, framing_error_rate, findings).
        """
        findings: List[Finding] = []
        ts         = ch.timestamps
        init_state = ch.initial_state

        data_bits  = 7 if framing.startswith("7") else 8
        has_parity = framing.endswith("E1") or framing.endswith("O1")

        decoded_bytes : List[int] = []
        framing_errors: int       = 0
        total_frames  : int       = 0

        # Walk transition list looking for falling edges (HIGH → LOW = start bit)
        i = 0
        n = len(ts)

        while i < n:
            # State immediately before transition i has fired:
            # init_state XOR parity(i) where i = number of transitions so far
            state_before = (init_state + i) % 2
            state_after  = 1 - state_before   # this transition flips it

            # Falling edge: 1 → 0
            if not (state_before == 1 and state_after == 0):
                i += 1
                continue

            start_t      = ts[i]
            total_frames += 1

            # Sample data bits LSB-first
            byte_val = 0
            for bit_pos in range(data_bits):
                sample_t = start_t + bp * (1.5 + bit_pos)
                bit      = _sample_state(ts, init_state, sample_t)
                byte_val |= (bit << bit_pos)

            # Stop bit: after data bits (and optional parity bit)
            stop_offset = data_bits + (1 if has_parity else 0)
            stop_t      = start_t + bp * (1.5 + stop_offset)
            stop_ok     = _sample_state(ts, init_state, stop_t) == 1

            if stop_ok:
                decoded_bytes.append(byte_val & 0xFF)
            else:
                framing_errors += 1

            # Advance past the full 10-bit frame
            frame_end_t = start_t + bp * 10
            while i < n and ts[i] < frame_end_t:
                i += 1

        if not decoded_bytes:
            findings.append(self._finding(
                path,
                f"UART {framing} — no bytes decoded "
                f"({total_frames} frames, {framing_errors} errors)",
                "",
                severity="INFO",
                confidence=0.40,
            ))
            return None, 1.0, findings

        error_rate = framing_errors / total_frames if total_frames else 0.0
        result     = bytes(decoded_bytes)

        findings.append(self._finding(
            path,
            f"UART {framing} decoded {len(result):,} bytes "
            f"({total_frames} frames, {framing_errors} framing errors, "
            f"{error_rate*100:.1f}% error rate)",
            f"First 80 bytes hex:   {result[:80].hex()}\n"
            f"First 80 bytes ascii: "
            f"{result[:80].decode('ascii', errors='replace')}",
            severity="MEDIUM",
            confidence=0.80,
        ))

        return result, error_rate, findings

    # ------------------------------------------------------------------
    # Step 5 — post-decode pipeline
    # ------------------------------------------------------------------

    def _post_decode(
        self,
        path: str,
        data: bytes,
        flag_pattern: re.Pattern,
        tmp_files: List[str],
        _depth: int = 0,
    ) -> List[Finding]:
        """Check decoded bytes for flags, base64, images, printable text, hex."""
        findings: List[Finding] = []
        text = data.decode("latin-1", errors="replace")

        # 1. Direct flag match
        if self._check_flag(text, flag_pattern):
            findings.append(self._finding(
                path,
                "Flag found in UART decoded data",
                text[:500],
                severity="HIGH",
                flag_match=True,
                confidence=0.99,
            ))

        # 2. Base64 detection
        b64_ratio = sum(1 for c in text if c in _BASE64_CHARS) / max(len(text), 1)
        if b64_ratio >= 0.90:
            try:
                clean = "".join(c for c in text if c not in "\r\n ")
                decoded_b64 = base64.b64decode(clean + "==")

                if decoded_b64.startswith(_PNG_MAGIC) or decoded_b64.startswith(_JPEG_MAGIC):
                    ext      = ".png" if decoded_b64.startswith(_PNG_MAGIC) else ".jpg"
                    fd, img  = tempfile.mkstemp(suffix=ext, prefix="ctfhunter_sal_")
                    tmp_files.append(img)
                    with os.fdopen(fd, "wb") as fh:
                        fh.write(decoded_b64)
                    findings.append(self._finding(
                        path,
                        f"Image decoded from UART base64 stream "
                        f"({len(decoded_b64):,} bytes, {ext.upper()})",
                        f"Saved to: {img}",
                        severity="HIGH",
                        confidence=0.95,
                    ))
                else:
                    inner = decoded_b64.decode("latin-1", errors="replace")
                    if self._check_flag(inner, flag_pattern):
                        findings.append(self._finding(
                            path,
                            "Flag found in base64-decoded UART data",
                            inner[:500],
                            severity="HIGH",
                            flag_match=True,
                            confidence=0.99,
                        ))
                    elif len(decoded_b64) > 4:
                        findings.append(self._finding(
                            path,
                            f"Base64 payload in UART stream "
                            f"({len(decoded_b64):,} bytes decoded)",
                            inner[:300],
                            severity="MEDIUM",
                            confidence=0.75,
                        ))
            except Exception:
                pass

        # 3. Printability check
        printable_ratio = sum(1 for c in text if c in _PRINTABLE) / max(len(text), 1)
        if printable_ratio >= 0.80:
            findings.append(self._finding(
                path,
                f"UART decoded data is printable ASCII "
                f"({printable_ratio*100:.0f}% printable, {len(data):,} bytes)",
                text[:500],
                severity="MEDIUM",
                confidence=0.70,
            ))

        # 4. Hex string — recurse once
        if _depth == 0 and _HEX_RE.match(text.strip()):
            try:
                hex_decoded = bytes.fromhex(re.sub(r"\s+", "", text.strip()))
                findings.append(self._finding(
                    path,
                    f"Hex string in UART data decoded to {len(hex_decoded):,} bytes",
                    hex_decoded[:80].hex(),
                    severity="MEDIUM",
                    confidence=0.72,
                ))
                findings.extend(
                    self._post_decode(
                        path, hex_decoded, flag_pattern, tmp_files, _depth=1
                    )
                )
            except Exception:
                pass

        return findings


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------

def _parse_channel_bin(index: int, raw: bytes) -> Optional[_Channel]:
    """Parse a Saleae digital-N.bin blob. Returns None if invalid."""
    if len(raw) < _HEADER_SIZE:
        return None
    if raw[:8] != _SALEAE_MAGIC:
        return None

    ch_type = struct.unpack_from("<I", raw, 12)[0]
    if ch_type != 0:      # must be Digital (0)
        return None

    initial_state   = struct.unpack_from("<I", raw, 16)[0]
    begin_time      = struct.unpack_from("<d", raw, 20)[0]
    end_time        = struct.unpack_from("<d", raw, 28)[0]
    num_transitions = struct.unpack_from("<Q", raw, 36)[0]

    if num_transitions == 0:
        return _Channel(index, initial_state, begin_time, end_time, 0, [])

    ts_data    = raw[_HEADER_SIZE:]
    n          = min(num_transitions, len(ts_data) // 8)
    timestamps = list(struct.unpack_from(f"<{n}d", ts_data))

    return _Channel(
        index, initial_state, begin_time, end_time, num_transitions, timestamps
    )


def _sample_state(timestamps: List[float], initial_state: int, t: float) -> int:
    """Return the signal state at time t via binary search.

    State = initial_state XOR (number of transitions up to and including t) % 2.
    bisect_right counts transitions at exactly t as already occurred.
    """
    n = bisect.bisect_right(timestamps, t)
    return (initial_state + n) % 2
