"""
Audio analyzer: LSB in WAV samples, ID3 metadata, silence blocks.
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


class AudioAnalyzer(Analyzer):
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

        # ID3 / metadata
        findings.extend(self._check_id3(path, flag_pattern))

        # Silence blocks
        findings.extend(self._check_silence(path))

        if depth == "deep":
            # LSB in WAV PCM
            findings.extend(self._check_wav_lsb(path, flag_pattern))

        self._run_redispatch_hook(findings, session, dispatcher_module)
        return findings

    # ------------------------------------------------------------------

    def _check_id3(self, path: str, flag_pattern: re.Pattern) -> List[Finding]:
        findings: List[Finding] = []
        try:
            import mutagen
            audio = mutagen.File(path, easy=False)
            if audio is None:
                return []
            tags = audio.tags
            if tags is None:
                return []
            for key in tags.keys():
                value = str(tags[key])
                if self._check_flag(value, flag_pattern):
                    findings.append(self._finding(
                        path,
                        f"Flag pattern in audio tag '{key}'",
                        f"{key}: {value}",
                        severity="HIGH",
                        flag_match=True,
                        confidence=0.95,
                    ))
                elif len(value) > 2:
                    findings.append(self._finding(
                        path,
                        f"Audio metadata tag: {key}",
                        f"{key}: {value[:200]}",
                        severity="INFO",
                        confidence=0.4,
                    ))
        except Exception:
            # fallback to exiftool
            try:
                meta = run_exiftool(path)
                for k, v in meta.items():
                    s = str(v)
                    if self._check_flag(s, flag_pattern):
                        findings.append(self._finding(
                            path,
                            f"Flag pattern in audio metadata '{k}'",
                            f"{k}: {s}",
                            severity="HIGH",
                            flag_match=True,
                            confidence=0.9,
                        ))
            except Exception:
                pass
        return findings

    def _check_silence(self, path: str) -> List[Finding]:
        """Detect silence blocks > 1 second in WAV files."""
        try:
            import wave
            with wave.open(path, "rb") as wf:
                framerate = wf.getframerate()
                nchannels = wf.getnchannels()
                sampwidth = wf.getsampwidth()
                nframes = wf.getnframes()
                raw = wf.readframes(nframes)
        except Exception:
            return []

        findings: List[Finding] = []
        SILENCE_THRESHOLD = 128  # for 16-bit samples near zero
        BLOCK_SIZE = framerate   # 1 second worth of samples
        SAMPLE_BYTES = sampwidth * nchannels

        i = 0
        silence_start = None
        while i + SAMPLE_BYTES <= len(raw):
            # Read one interleaved multi-channel frame; check each channel at its
            # correct byte offset and take the max amplitude across all channels.
            frame = raw[i:i + SAMPLE_BYTES]
            if sampwidth == 1:
                amplitude = max(abs(frame[c] - 128) for c in range(nchannels))
            else:
                amplitude = max(
                    abs(struct.unpack_from("<h", frame, c * sampwidth)[0])
                    for c in range(nchannels)
                )
            is_silent = amplitude < SILENCE_THRESHOLD
            if is_silent:
                if silence_start is None:
                    silence_start = i
            else:
                if silence_start is not None:
                    duration_frames = (i - silence_start) // SAMPLE_BYTES
                    duration_sec = duration_frames / framerate
                    if duration_sec > 1.0:
                        findings.append(self._finding(
                            path,
                            f"Silence block at 0x{silence_start:x} ({duration_sec:.1f}s)",
                            "Long silence block may conceal data.",
                            severity="MEDIUM",
                            offset=silence_start,
                            confidence=0.55,
                        ))
                    silence_start = None
            i += SAMPLE_BYTES
        return findings

    def _check_wav_lsb(self, path: str, flag_pattern: re.Pattern) -> List[Finding]:
        """Extract LSBs from 16-bit PCM WAV samples and check for printable data."""
        try:
            import wave
            with wave.open(path, "rb") as wf:
                if wf.getsampwidth() != 2 or wf.getnchannels() != 1:
                    return []
                nframes = min(wf.getnframes(), 100000)  # limit to 100k samples
                raw = wf.readframes(nframes)
        except Exception:
            return []

        samples = struct.unpack(f"<{len(raw)//2}h", raw)
        bits = [s & 1 for s in samples]
        # Pack bits into bytes
        lsb_bytes = bytearray()
        for i in range(0, len(bits) - 7, 8):
            byte_val = 0
            for bit_idx in range(8):
                byte_val |= bits[i + bit_idx] << (7 - bit_idx)
            lsb_bytes.append(byte_val)

        printable = bytes(b for b in lsb_bytes if 0x20 <= b <= 0x7E or b in (9, 10, 13))
        if len(printable) > 20:
            text = printable.decode("ascii", errors="replace")[:500]
            fm = self._check_flag(text, flag_pattern)
            hex_str = lsb_bytes.hex()
            return [self._finding(
                path,
                "LSB data extracted from WAV samples",
                f"Extracted {len(printable)} printable bytes: {text[:200]}\nraw_hex={hex_str}",
                severity="HIGH" if fm else "MEDIUM",
                flag_match=fm,
                confidence=0.75 if fm else 0.55,
            )]
        return []
