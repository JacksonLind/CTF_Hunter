"""
Audio analyzer: LSB in WAV samples, ID3 metadata, silence blocks.
"""
from __future__ import annotations

import json
import os
import re
import struct
import subprocess
import tempfile
from pathlib import Path
from typing import List, Optional, Tuple

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
            # LSB in WAV PCM (extended: multi-channel, bit planes, packing variants)
            findings.extend(self._check_lsb_samples(path, flag_pattern))

        # Phase cancellation + spectrogram steg (always run — too valuable to gate on deep)
        findings.extend(self._phase_cancellation_analysis(path, flag_pattern))

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

    def _check_lsb_samples(self, path: str, flag_pattern: re.Pattern) -> List[Finding]:
        """Extended LSB extraction from WAV samples.

        Variants tried (combinatorially):
          Channels   : each channel individually + interleaved (all channels)
          Bit plane  : 0 (LSB), 1
          Bit packing: MSB-first, LSB-first
          Sample widths: 8-bit unsigned, 16-bit signed

        Findings emitted:
          HIGH + flag_match=True  → flag pattern in extracted bytes
          MEDIUM                  → ≥70% printable ASCII

        Deduplication: first 256 bytes of each variant keyed in a seen-set.
        Requires numpy; silently skips if unavailable.
        """
        try:
            import wave as _wave
            with _wave.open(path, "rb") as wf:
                sampwidth  = wf.getsampwidth()
                nchannels  = wf.getnchannels()
                nframes    = min(wf.getnframes(), 500_000)
                raw        = wf.readframes(nframes)
        except Exception:
            return []

        if sampwidth not in (1, 2):
            return []

        try:
            import numpy as np
        except ImportError:
            return []

        try:
            if sampwidth == 2:
                arr = np.frombuffer(raw, dtype=np.int16)
            else:
                arr = np.frombuffer(raw, dtype=np.uint8)
        except Exception:
            return []

        # Shape: (nframes, nchannels); handle mono without reshape error
        if nchannels > 1:
            arr = arr[:len(arr) - len(arr) % nchannels].reshape(-1, nchannels)
        else:
            arr = arr.reshape(-1, 1)

        # Channel configs: individual channels + interleaved
        channel_configs: List[Tuple[str, object]] = [
            (f"ch{c}", arr[:, c]) for c in range(nchannels)
        ]
        channel_configs.append(("interleaved", arr.flatten()))

        findings: List[Finding] = []
        seen: set = set()
        msb_weights = np.array([128, 64, 32, 16, 8, 4, 2, 1], dtype=np.uint16)
        lsb_weights = np.array([  1,  2,  4,  8, 16, 32, 64, 128], dtype=np.uint16)

        for ch_label, ch_arr in channel_configs:
            for plane in (0, 1):
                bits = (ch_arr >> plane) & 1
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
                    label = f"{ch_label}/bit{plane}/{pack_name}"

                    if fm:
                        findings.append(self._finding(
                            path,
                            f"LSB steg: flag found in audio ({label})",
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
                        total = len(sample)
                        if total > 0 and printable / total >= 0.70:
                            preview = byte_vals[:200].tobytes().decode("ascii", errors="replace")
                            findings.append(self._finding(
                                path,
                                f"LSB steg: printable payload in audio ({label})",
                                f"Variant: {label}\n"
                                f"Printable ratio: {printable/total:.2f}\n"
                                f"Preview: {preview[:200]}\n"
                                f"raw_hex={byte_vals[:64].tobytes().hex()}",
                                severity="MEDIUM",
                                confidence=0.60,
                            ))

        return findings

    # ------------------------------------------------------------------
    # Phase cancellation + spectrogram steganography
    # ------------------------------------------------------------------

    def _phase_cancellation_analysis(
        self, path: str, flag_pattern: re.Pattern
    ) -> List[Finding]:
        """Detect spectral steganography via phase cancellation and spectrogram analysis.

        Steps:
        1. Use ffprobe to count audio streams.
        2. Extract each stream to a temp WAV with ffmpeg.
        3. Subtract stream pairs (phase cancellation) to isolate hidden signal.
        4. Run spectrogram on diff (or single stream) across multiple frequency
           bands and time windows — high-variance bands indicate rendered text.
        5. Save spectrogram images as findings so the UI can display them.
        6. Clean up all temp files in a finally block.
        """
        findings: List[Finding] = []
        tmp_dir = tempfile.mkdtemp(prefix="ctfhunter_audio_")
        tmp_files: List[str] = []

        try:
            # --- dependency check -------------------------------------------
            try:
                import numpy as np
                from scipy import signal as scipy_signal
                from scipy.io import wavfile
                from PIL import Image
            except ImportError as e:
                findings.append(self._finding(
                    path,
                    "Phase cancellation skipped — missing dependency",
                    f"Install required packages: scipy numpy Pillow\nError: {e}",
                    severity="INFO",
                    confidence=0.0,
                ))
                return findings

            # --- ffmpeg availability check ----------------------------------
            try:
                import imageio_ffmpeg
                ffmpeg_exe  = imageio_ffmpeg.get_ffmpeg_exe()
                ffprobe_exe = str(Path(ffmpeg_exe).parent / "ffprobe")
                # On Windows the binary has no extension check — try with .exe too
                if not Path(ffprobe_exe).exists():
                    ffprobe_exe = str(Path(ffmpeg_exe).parent / "ffprobe.exe")
                if not Path(ffprobe_exe).exists():
                    # imageio-ffmpeg only bundles ffmpeg, not ffprobe — fall back
                    # to using ffmpeg itself for stream detection via stderr parse
                    ffprobe_exe = None
            except ImportError:
                findings.append(self._finding(
                    path,
                    "Phase cancellation skipped — imageio-ffmpeg not installed",
                    "Run: pip install imageio-ffmpeg",
                    severity="INFO",
                    confidence=0.0,
                ))
                return findings

            # --- Step 1: count audio streams --------------------------------
            stream_count = self._ffprobe_stream_count(path, ffprobe_exe, ffmpeg_exe)

            # --- Step 2: extract streams to WAV -----------------------------
            wav_paths: List[str] = []
            if stream_count >= 2:
                for idx in range(stream_count):
                    out = os.path.join(tmp_dir, f"stream_{idx}.wav")
                    ok = self._ffmpeg_extract_stream(path, idx, out, ffmpeg_exe)
                    if ok:
                        wav_paths.append(out)
                        tmp_files.append(out)
            else:
                # Single stream — extract directly for spectrogram scan
                out = os.path.join(tmp_dir, "stream_0.wav")
                ok = self._ffmpeg_extract_stream(path, 0, out, ffmpeg_exe)
                if ok:
                    wav_paths.append(out)
                    tmp_files.append(out)

            if not wav_paths:
                return findings

            # --- Step 3: phase cancellation on all pairs --------------------
            diff_signals: List[Tuple[str, object, int]] = []  # (label, array, rate)

            if len(wav_paths) >= 2:
                for i in range(len(wav_paths)):
                    for j in range(i + 1, len(wav_paths)):
                        try:
                            rate1, s1 = wavfile.read(wav_paths[i])
                            rate2, s2 = wavfile.read(wav_paths[j])
                        except Exception:
                            continue

                        # Ensure same length
                        min_len = min(len(s1), len(s2))
                        s1 = s1[:min_len]
                        s2 = s2[:min_len]

                        diff = s1.astype(np.int32) - s2.astype(np.int32)
                        max_delta = int(np.max(np.abs(diff)))

                        if max_delta < 10:
                            # Streams are identical — no hidden signal
                            continue

                        label = f"stream{i}_minus_stream{j}"
                        findings.append(self._finding(
                            path,
                            f"Phase cancellation: streams {i} and {j} differ "
                            f"(max delta {max_delta})",
                            f"Pair: stream {i} − stream {j}\n"
                            f"Max sample delta: {max_delta}\n"
                            f"Range hint: {'subtle hidden signal' if max_delta <= 10000 else 'large difference'}",
                            severity="MEDIUM",
                            confidence=0.70,
                        ))
                        diff_signals.append((label, diff, rate1))

            # Also add raw streams for single-stream spectrogram scan
            if not diff_signals:
                for idx, wp in enumerate(wav_paths):
                    try:
                        rate, data = wavfile.read(wp)
                        diff_signals.append((f"stream{idx}_raw", data, rate))
                    except Exception:
                        continue

            # --- Step 4: spectrogram scan -----------------------------------
            BANDS = [
                ("11k-16.5k",  11000, 16500),
                ("16.5k-20k",  16500, 20000),
                ("8k-11k",      8000, 11000),
            ]

            for sig_label, sig_data, rate in diff_signals:
                # Use first channel only
                if sig_data.ndim > 1:
                    channel = sig_data[:, 0].astype(np.float32)
                else:
                    channel = sig_data.astype(np.float32)

                total_samples = len(channel)
                duration_sec = total_samples / rate if rate > 0 else 0

                # Time windows: full track + fixed 30-second slices
                windows: List[Tuple[str, int, int]] = [("full", 0, total_samples)]
                for win_start_sec in (0, 20, 50):
                    win_end_sec = win_start_sec + 30
                    s = int(win_start_sec * rate)
                    e = int(win_end_sec * rate)
                    if s < total_samples and e - s > rate:  # at least 1s of data
                        e = min(e, total_samples)
                        windows.append((
                            f"{win_start_sec}s-{win_end_sec}s", s, e
                        ))

                for win_label, win_s, win_e in windows:
                    segment = channel[win_s:win_e]
                    if len(segment) < 512:
                        continue

                    try:
                        f_arr, _t, Sxx = scipy_signal.spectrogram(
                            segment, rate,
                            nperseg=512,
                            noverlap=480,
                        )
                    except Exception:
                        continue

                    power_db = 10.0 * np.log10(np.abs(Sxx) + 1e-12)

                    for band_label, f_lo_hz, f_hi_hz in BANDS:
                        if f_hi_hz > rate / 2:
                            continue  # band above Nyquist for this file

                        idx_lo = int(np.searchsorted(f_arr, f_lo_hz))
                        idx_hi = int(np.searchsorted(f_arr, f_hi_hz))
                        if idx_hi <= idx_lo:
                            continue

                        band = power_db[idx_lo:idx_hi, :]
                        if band.size == 0:
                            continue

                        # Normalise to 0-255 and flip frequency axis
                        b_min, b_max = band.min(), band.max()
                        if b_max == b_min:
                            continue
                        normed = ((band - b_min) / (b_max - b_min) * 255).astype(np.uint8)
                        normed = normed[::-1]  # low freq at bottom

                        variance = float(np.std(normed))
                        is_suspicious = variance > 15.0

                        img_path = os.path.join(
                            tmp_dir,
                            f"spect_{sig_label}_{win_label}_{band_label}.png",
                        )
                        tmp_files.append(img_path)
                        try:
                            Image.fromarray(normed).save(img_path)
                        except Exception:
                            img_path = ""

                        if is_suspicious:
                            findings.append(self._finding(
                                path,
                                f"Spectrogram steg candidate: {band_label} Hz "
                                f"[{sig_label}] [{win_label}] "
                                f"(variance={variance:.1f})",
                                f"Signal: {sig_label}\n"
                                f"Window: {win_label} "
                                f"({win_s/rate:.1f}s–{win_e/rate:.1f}s)\n"
                                f"Band: {f_lo_hz}–{f_hi_hz} Hz\n"
                                f"Pixel std-dev: {variance:.1f} "
                                f"(>15 indicates non-noise content)\n"
                                f"Spectrogram image: {img_path}",
                                severity="HIGH",
                                confidence=0.82,
                            ))

                            # OCR: attempt to read text rendered in the
                            # spectrogram image — this is how the flag is
                            # extracted from spectral steganography.
                            if img_path:
                                findings.extend(
                                    self._ocr_spectrogram(
                                        path, img_path, normed,
                                        flag_pattern, band_label,
                                        sig_label, win_label,
                                        win_s, win_e, rate,
                                    )
                                )

        finally:
            # Step 4 — cleanup all temp files
            for f in tmp_files:
                try:
                    os.unlink(f)
                except OSError:
                    pass
            try:
                os.rmdir(tmp_dir)
            except OSError:
                pass

        return findings

    # ------------------------------------------------------------------
    # Spectrogram OCR
    # ------------------------------------------------------------------

    def _ocr_spectrogram(
        self,
        path: str,
        img_path: str,
        normed_array,
        flag_pattern: re.Pattern,
        band_label: str,
        sig_label: str,
        win_label: str,
        win_s: int,
        win_e: int,
        rate: int,
    ) -> List[Finding]:
        """Run OCR on a normalised spectrogram image to extract hidden text.

        Tries multiple image pre-processing passes to maximise readability:
        - Raw image (as-is)
        - Vertically flipped (some tools render text upside-down)
        - Contrast-stretched version (histogram equalisation)
        - Inverted (white text on black background)

        Uses pytesseract if available. Gracefully skips and emits an INFO
        finding if pytesseract or its Tesseract binary is not installed.
        """
        findings: List[Finding] = []
        try:
            import pytesseract
            from PIL import Image, ImageOps, ImageFilter
            import numpy as np
        except ImportError:
            findings.append(self._finding(
                path,
                "Spectrogram OCR skipped — pytesseract not installed",
                "Run: pip install pytesseract  "
                "(also requires Tesseract: https://github.com/tesseract-ocr/tesseract)",
                severity="INFO",
                confidence=0.0,
            ))
            return findings

        # Build a set of image variants to try OCR on
        try:
            base_img = Image.fromarray(normed_array)
        except Exception:
            return findings

        # Scale up — Tesseract works much better on larger images
        w, h = base_img.size
        scale = max(1, 400 // max(h, 1))
        if scale > 1:
            base_img = base_img.resize((w * scale, h * scale), Image.NEAREST)

        variants = [
            ("raw",      base_img),
            ("flipped",  base_img.transpose(Image.FLIP_TOP_BOTTOM)),
            ("inverted", ImageOps.invert(base_img)),
            ("equalized", ImageOps.equalize(base_img)),
        ]

        seen_texts: set = set()
        for variant_label, img_variant in variants:
            try:
                # PSM 6 = assume a single uniform block of text
                ocr_text = pytesseract.image_to_string(
                    img_variant,
                    config="--psm 6 --oem 3",
                ).strip()
            except Exception:
                continue

            if not ocr_text or ocr_text in seen_texts:
                continue
            seen_texts.add(ocr_text)

            # Clean up common OCR noise
            cleaned = re.sub(r"[^\x20-\x7E]", "", ocr_text).strip()
            if len(cleaned) < 3:
                continue

            fm = self._check_flag(cleaned, flag_pattern)
            findings.append(self._finding(
                path,
                f"Spectrogram OCR text extracted ({band_label} Hz, "
                f"{variant_label})",
                f"Signal: {sig_label}\n"
                f"Window: {win_label} "
                f"({win_s/rate:.1f}s–{win_e/rate:.1f}s)\n"
                f"Band: {band_label}\n"
                f"Variant: {variant_label}\n"
                f"OCR output: {cleaned[:300]}",
                severity="HIGH" if fm else "MEDIUM",
                flag_match=fm,
                confidence=0.90 if fm else 0.65,
            ))

            # Stop trying variants once we get a flag match
            if fm:
                break

        return findings

    # ------------------------------------------------------------------
    # ffprobe / ffmpeg helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _ffprobe_stream_count(
        path: str,
        ffprobe_exe: Optional[str],
        ffmpeg_exe: str,
    ) -> int:
        """Return the number of audio streams in *path*.

        Uses ffprobe when available (bundled alongside imageio-ffmpeg's ffmpeg
        on most platforms).  Falls back to parsing ffmpeg's stderr stream list
        when ffprobe is absent — imageio-ffmpeg only guarantees ffmpeg itself.
        """
        # Try ffprobe first (most reliable)
        if ffprobe_exe and Path(ffprobe_exe).exists():
            try:
                result = subprocess.run(
                    [
                        ffprobe_exe, "-v", "quiet",
                        "-print_format", "json",
                        "-show_streams",
                        "-select_streams", "a",
                        path,
                    ],
                    capture_output=True,
                    timeout=30,
                )
                data = json.loads(result.stdout)
                return len(data.get("streams", []))
            except Exception:
                pass

        # Fallback: parse ffmpeg stderr which lists streams on startup
        try:
            result = subprocess.run(
                [ffmpeg_exe, "-i", path],
                capture_output=True,
                timeout=30,
            )
            # ffmpeg prints stream info to stderr even when it errors out
            stderr = result.stderr.decode("utf-8", errors="replace")
            # Count lines matching "Stream #0:N: Audio:"
            audio_streams = len(re.findall(r"Stream #\d+:\d+.*?Audio:", stderr))
            return audio_streams if audio_streams > 0 else 1
        except Exception:
            return 1

    @staticmethod
    def _ffmpeg_extract_stream(
        path: str,
        stream_index: int,
        out_path: str,
        ffmpeg_exe: str,
    ) -> bool:
        """Extract audio stream *stream_index* from *path* to a 2-channel WAV.
        Uses the ffmpeg binary resolved by imageio-ffmpeg. Returns True on success.
        """
        try:
            result = subprocess.run(
                [
                    ffmpeg_exe, "-y",
                    "-i", path,
                    "-map", f"0:a:{stream_index}",
                    "-ac", "2",
                    "-ar", "44100",
                    out_path,
                ],
                capture_output=True,
                timeout=120,
            )
            return result.returncode == 0 and Path(out_path).exists()
        except Exception:
            return False