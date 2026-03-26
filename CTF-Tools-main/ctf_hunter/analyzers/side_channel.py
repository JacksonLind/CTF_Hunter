"""
Side-channel / DPA (Differential Power Analysis) analyzer.

Detects power trace files and performs trace averaging + leakage analysis.

Supported input formats
    CSV      — rows = traces OR rows = samples (orientation inferred)
    NumPy    — .npy array, shape (n_traces, n_samples) or transposed
    Raw binary — packed float32 or float64 values (flat or 2-D)
               Only attempted when the file is NOT valid printable text.

Fast mode
    Detect shape, report trace count / sample count, mean power level.

Deep mode
    1. Average all traces  → noise cancellation (SNR improves as √N).
    2. Compute per-sample standard deviation → leakage proxy.
    3. Normalise deviation; locate "peak regions" (top-30% deviation).
    4. Window decode: threshold averaged trace in fixed-width windows
       and decode each window as a bit (handles uniform-noise challenges
       where all traces carry the same signal — e.g., CTF "Power Leak").
    5. Deviation-peak bit extraction: classify each peak sample as 0/1
       by comparing mean amplitude to global mean (key-dependent leakage).
    6. Amplitude-to-char extraction: scale mean amplitudes at peak
       positions into printable-ASCII range; check for flag pattern.
    7. Emit decoded bytes as raw_hex= for ContentRedispatcher.
"""
from __future__ import annotations

import io
import re
import struct
from pathlib import Path
from typing import List, Optional, Tuple

import numpy as np

from core.report import Finding
from core.ai_client import AIClient
from .base import Analyzer

# ──────────────────────────────────────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────────────────────────────────────

_MIN_TRACES   = 3       # fewer traces → meaningless average
_MIN_SAMPLES  = 16      # fewer samples → not a trace file
_MAX_ROWS     = 50_000  # guard against loading enormous CSVs
_MAX_COLS     = 50_000
_PEAK_THRESH  = 0.70    # normalised deviation threshold for "leakage peak"
_MERGE_WIN    = 4       # merge peaks within this many samples of each other


# ──────────────────────────────────────────────────────────────────────────────
# Public analyzer class
# ──────────────────────────────────────────────────────────────────────────────

class SideChannelAnalyzer(Analyzer):
    """Detect power-trace files and run DPA averaging / leakage extraction."""

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
            return [self._finding(path, "Read error", str(exc),
                                  severity="INFO", confidence=0.1)]

        traces, fmt = _load_traces(data, path)
        if traces is None:
            return []

        n_traces, n_samples = traces.shape
        if n_traces < _MIN_TRACES or n_samples < _MIN_SAMPLES:
            return []

        mean_power = float(traces.mean())
        findings.append(self._finding(
            path,
            f"Power trace file detected — {n_traces} traces × {n_samples} samples [{fmt}]",
            (
                f"Format: {fmt} | Shape: ({n_traces}, {n_samples}) | "
                f"Mean power: {mean_power:.6f}\n"
                f"Use deep mode for DPA averaging and leakage extraction."
            ),
            severity="INFO",
            confidence=0.70,
        ))

        if depth != "deep":
            return findings

        findings.extend(self._dpa_analysis(path, traces, fmt, flag_pattern))
        return findings

    # ──────────────────────────────────────────────────────────────────────

    def _dpa_analysis(
        self,
        path: str,
        traces: np.ndarray,
        fmt: str,
        flag_pattern: re.Pattern,
    ) -> List[Finding]:
        n_traces, n_samples = traces.shape

        # 1. Average trace — noise cancels, signal remains
        avg_trace = traces.mean(axis=0)          # shape (n_samples,)
        dev_trace = traces.std(axis=0)           # per-sample standard deviation

        # 2. Check for degenerate (uniform / identical) traces
        dmin, dmax = float(dev_trace.min()), float(dev_trace.max())
        sig_scale = float(np.abs(avg_trace).mean()) + 1e-15
        if dmax < 1e-6 or (dmax / sig_scale) < 1e-4:
            return [self._finding(
                path,
                "DPA: uniform deviation — traces appear identical",
                f"All {n_traces} traces have identical power at every sample. "
                "No information leakage detected.",
                severity="INFO",
                confidence=0.30,
            )]

        # 3. Normalise deviation to [0, 1]
        dev_norm = (dev_trace - dmin) / (dmax - dmin)

        # 4. Peak detection — high-deviation positions signal key dependence
        peak_mask = dev_norm >= _PEAK_THRESH
        peak_indices = np.where(peak_mask)[0]
        peak_regions = _merge_peaks(peak_indices, window=_MERGE_WIN)

        # Representative sample per region: highest deviation within region
        rep_samples = [
            int(region[int(np.argmax(dev_norm[region]))])
            for region in peak_regions
        ]

        global_mean = float(avg_trace.mean())

        # 5. Deviation-peak bit extraction
        peak_bits = [1 if avg_trace[s] >= global_mean else 0 for s in rep_samples]

        # 6. Amplitude-to-char extraction
        amp_chars = _amplitude_to_chars(avg_trace, rep_samples)

        # ── Summary finding ───────────────────────────────────────────────
        top_str = ", ".join(str(s) for s in rep_samples[:12])
        if len(rep_samples) > 12:
            top_str += f" (+{len(rep_samples) - 12} more)"
        summary_detail = (
            f"Traces: {n_traces} x {n_samples} samples | fmt={fmt}\n"
            f"Mean power: {global_mean:.6f} | deviation range: [{dmin:.6f}, {dmax:.6f}]\n"
            f"Leakage peak regions: {len(peak_regions)} | "
            f"representative samples: [{top_str}]\n"
            f"avg_trace_hex={avg_trace.astype(np.float32).tobytes().hex()}"
        )
        findings: List[Finding] = [self._finding(
            path,
            f"DPA averaging — {len(peak_regions)} leakage peaks, "
            f"{n_traces} traces averaged",
            summary_detail,
            severity="MEDIUM",
            confidence=0.80,
        )]

        # ── Window decode on averaged trace (handles uniform-noise encoding) ─
        for wf in self._window_decode(path, avg_trace, n_traces, n_samples,
                                      fmt, flag_pattern):
            findings.append(wf)

        # ── Deviation-peak bit findings ───────────────────────────────────
        for bit_seq, label in (
            (peak_bits, "peak-normal"),
            ([1 - b for b in peak_bits], "peak-inverted"),
        ):
            f = self._try_decode(path, bit_seq, label, "bit",
                                 n_traces, n_samples, fmt, len(peak_regions),
                                 flag_pattern)
            if f:
                findings.append(f)

        # ── Amplitude-to-char findings ────────────────────────────────────
        if amp_chars:
            fm = self._check_flag(amp_chars, flag_pattern)
            raw = amp_chars.encode("latin-1", errors="replace")
            detail = (
                f"Amplitude-to-char: scale avg_trace[peaks] to printable ASCII\n"
                f"Decoded ({len(amp_chars)} chars): {amp_chars[:200]}\n"
                f"raw_hex={raw.hex()}"
            )
            findings.append(self._finding(
                path,
                f"DPA amplitude decode — {len(amp_chars)} chars",
                detail,
                severity="HIGH" if fm else "MEDIUM",
                flag_match=fm,
                confidence=0.88 if fm else 0.55,
            ))

        return findings

    # ──────────────────────────────────────────────────────────────────────

    def _window_decode(
        self,
        path: str,
        avg_trace: np.ndarray,
        n_traces: int,
        n_samples: int,
        fmt: str,
        flag_pattern: re.Pattern,
    ) -> List[Finding]:
        """Decode the averaged trace as bit-encoded data with varying window sizes.

        Handles challenges where ALL traces carry the same signal (e.g., same
        operation repeated N times to cancel noise).  Each window of W samples
        encodes one bit: segment mean >= trace mean → 1, else → 0.
        """
        global_mean = float(avg_trace.mean())
        found: List[Finding] = []
        seen: set[bytes] = set()

        for window in (4, 6, 8, 10, 12, 16, 24, 32, 48, 64):
            n_bits = n_samples // window
            if n_bits < 8:
                continue
            bits = []
            for i in range(n_bits):
                seg_mean = float(avg_trace[i * window:(i + 1) * window].mean())
                bits.append(1 if seg_mean >= global_mean else 0)

            for bit_seq, label in (
                (bits, f"window{window}"),
                ([1 - b for b in bits], f"window{window}-inv"),
            ):
                decoded = _bits_to_bytes(bit_seq)
                if not decoded or decoded in seen:
                    continue
                try:
                    text = decoded.decode("utf-8", errors="replace")
                except Exception:
                    text = decoded.decode("latin-1", errors="replace")
                printable = sum(1 for b in decoded if 0x20 <= b <= 0x7E or b in (9, 10, 13))
                pr = printable / len(decoded)
                fm = self._check_flag(text, flag_pattern)
                if not fm and pr < 0.50:
                    continue
                seen.add(decoded)
                detail = (
                    f"Window decode ({label}): window={window} samples/bit, "
                    f"{n_traces} traces averaged\n"
                    f"Bits: {len(bit_seq)} | Decoded bytes: {len(decoded)} "
                    f"(printable={pr:.0%})\n"
                    f"Text: {text[:200]}\n"
                    f"raw_hex={decoded.hex()}"
                )
                found.append(self._finding(
                    path,
                    f"DPA window decode — {len(decoded)} bytes ({label})",
                    detail,
                    severity="HIGH" if fm else "MEDIUM",
                    flag_match=fm,
                    confidence=0.92 if fm else 0.60,
                ))

        return found

    # ──────────────────────────────────────────────────────────────────────

    def _try_decode(
        self,
        path: str,
        bits: list,
        label: str,
        method: str,
        n_traces: int,
        n_samples: int,
        fmt: str,
        n_peaks: int,
        flag_pattern: re.Pattern,
    ) -> Optional[Finding]:
        if len(bits) < 8:
            return None
        decoded = _bits_to_bytes(bits)
        if not decoded:
            return None
        try:
            text = decoded.decode("utf-8", errors="replace")
        except Exception:
            text = decoded.decode("latin-1", errors="replace")
        printable = sum(1 for b in decoded if 0x20 <= b <= 0x7E or b in (9, 10, 13))
        pr = printable / len(decoded)
        fm = self._check_flag(text, flag_pattern)
        if not fm and pr < 0.40:
            return None
        detail = (
            f"DPA {method} extraction ({label}): "
            f"{n_traces} traces x {n_samples} samples | fmt={fmt}\n"
            f"Peak regions: {n_peaks} | bits: {len(bits)} | "
            f"decoded bytes: {len(decoded)} (printable={pr:.0%})\n"
            f"Text: {text[:200]}\n"
            f"raw_hex={decoded.hex()}"
        )
        return self._finding(
            path,
            f"DPA {method} decode — {len(decoded)} bytes ({label})",
            detail,
            severity="HIGH" if fm else "MEDIUM",
            flag_match=fm,
            confidence=0.92 if fm else 0.65,
        )


# ──────────────────────────────────────────────────────────────────────────────
# Module-level helpers
# ──────────────────────────────────────────────────────────────────────────────

def _load_traces(
    data: bytes, path: str
) -> Tuple[Optional[np.ndarray], str]:
    """Attempt to load a power-trace array from *data*.

    Returns ``(array, fmt)`` where ``array`` has shape ``(n_traces, n_samples)``
    and ``fmt`` is one of ``"npy"``, ``"csv"``, ``"bin_f32"``, ``"bin_f64"``.
    Returns ``(None, "")`` if the data does not look like a trace file.

    Text files (valid UTF-8 or printable Latin-1) are never interpreted as
    raw binary floats — if text CSV parsing fails, returns ``(None, "")``.
    """
    # ── NumPy .npy ────────────────────────────────────────────────────────
    if data[:6] == b"\x93NUMPY" or path.lower().endswith(".npy"):
        try:
            arr = np.load(io.BytesIO(data), allow_pickle=False)
            arr = arr.astype(np.float64)
            if arr.ndim == 1:
                arr = arr.reshape(1, -1)
            elif arr.ndim > 2:
                arr = arr.reshape(-1, arr.shape[-1])
            arr = _orient_traces(arr)
            return arr, "npy"
        except Exception:
            pass

    # ── Text decode ───────────────────────────────────────────────────────
    # CSV/trace text files use only ASCII characters (bytes 0x00-0x7F).
    # Binary float data contains many bytes > 0x7F (high mantissa/exponent
    # bits).  We count non-ASCII bytes as the primary discriminator:
    # if > 5 % of the first 2 KB are > 0x7F, treat the file as binary.
    text: Optional[str] = None
    _sample = data[:2048]
    non_ascii = sum(1 for b in _sample if b > 0x7F)
    _is_text_candidate = non_ascii < len(_sample) * 0.05

    if _is_text_candidate:
        try:
            text = data.decode("utf-8", errors="strict")
        except (UnicodeDecodeError, ValueError):
            try:
                text = data.decode("latin-1")
            except Exception:
                pass

    if text is not None:
        # Successfully decoded as text — try CSV parse and stop here.
        # Never fall through to binary float detection for text files.
        arr = _parse_csv(text)
        if arr is not None:
            return arr, "csv"
        return None, ""

    # ── Raw binary float32 (only for non-text files) ──────────────────────
    if len(data) >= 64 and len(data) % 4 == 0:
        try:
            vals = np.frombuffer(data, dtype=np.float32).astype(np.float64)
            if _looks_like_trace_values(vals):
                arr = _infer_binary_shape(vals)
                if arr is not None:
                    return arr, "bin_f32"
        except Exception:
            pass

    # ── Raw binary float64 (only for non-text files) ──────────────────────
    if len(data) >= 128 and len(data) % 8 == 0:
        try:
            vals = np.frombuffer(data, dtype=np.float64)
            if _looks_like_trace_values(vals):
                arr = _infer_binary_shape(vals)
                if arr is not None:
                    return arr, "bin_f64"
        except Exception:
            pass

    return None, ""


def _parse_csv(text: str) -> Optional[np.ndarray]:
    """Parse CSV/TSV text into a 2-D float array.  Returns None on failure.

    Accepts rows with at least _MIN_TRACES values (not _MIN_SAMPLES) so that
    transposed trace files (rows=time-samples, cols=traces) are not rejected
    during parsing.  The orientation heuristic in _orient_traces and a final
    _MIN_SAMPLES check on the sample axis handle the rest.
    """
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    if len(lines) < _MIN_TRACES:
        return None

    rows: list[list[float]] = []
    for i, ln in enumerate(lines[:_MAX_ROWS]):
        parts = re.split(r"[,\t ]+", ln)
        try:
            row = [float(p) for p in parts if p]
            if len(row) >= _MIN_TRACES:   # accept short rows (transposed files)
                rows.append(row)
        except ValueError:
            if i == 0:
                continue  # likely header row
            # skip malformed interior rows

    if len(rows) < _MIN_TRACES:
        return None

    # Trim to common length
    min_len = min(len(r) for r in rows)
    min_len = min(min_len, _MAX_COLS)
    rows = [r[:min_len] for r in rows]

    try:
        arr = np.array(rows, dtype=np.float64)
    except Exception:
        return None

    if arr.ndim != 2:
        return None

    arr = _orient_traces(arr)

    # After orientation, the sample axis must have >= _MIN_SAMPLES
    if arr.shape[1] < _MIN_SAMPLES:
        return None

    return arr


def _orient_traces(arr: np.ndarray) -> np.ndarray:
    """Ensure arr has shape (n_traces, n_samples).

    Heuristic: the trace axis is usually shorter.  Transpose when n_rows
    is more than 4× n_cols AND n_cols >= MIN_TRACES (i.e., traces stored
    as columns, samples as rows).
    """
    r, c = arr.shape
    if r > c * 4 and c >= _MIN_TRACES:
        return arr.T   # (n_samples, n_traces) → (n_traces, n_samples)
    return arr


def _looks_like_trace_values(vals: np.ndarray) -> bool:
    """Quick sanity: values should be finite floats with some variance."""
    if not np.all(np.isfinite(vals)):
        return False
    if vals.std() == 0.0:
        return False
    # Reject if all values are tiny non-negative integers (likely not float data)
    if vals.min() >= 0 and vals.max() <= 255 and np.all(vals == vals.astype(int)):
        return False
    return True


def _infer_binary_shape(vals: np.ndarray) -> Optional[np.ndarray]:
    """Try common trace shapes for a flat float array."""
    n = len(vals)
    for n_traces in (8, 16, 32, 50, 64, 100, 128, 200, 256):
        if n % n_traces == 0:
            n_samples = n // n_traces
            if n_samples >= _MIN_SAMPLES:
                arr = vals.reshape(n_traces, n_samples)
                return _orient_traces(arr)
    return None


def _merge_peaks(indices: np.ndarray, window: int) -> list[np.ndarray]:
    """Merge nearby peak indices into contiguous regions."""
    if len(indices) == 0:
        return []
    regions: list[list[int]] = [[int(indices[0])]]
    for idx in indices[1:]:
        if int(idx) - regions[-1][-1] <= window:
            regions[-1].append(int(idx))
        else:
            regions.append([int(idx)])
    return [np.array(r) for r in regions]


def _bits_to_bytes(bits: list[int]) -> bytes:
    """Convert a list of bits (MSB first, 8 bits per byte) to bytes."""
    n_bytes = len(bits) // 8
    out = bytearray(n_bytes)
    for i in range(n_bytes):
        byte = 0
        for j in range(8):
            byte = (byte << 1) | (bits[i * 8 + j] & 1)
        out[i] = byte
    return bytes(out)


def _amplitude_to_chars(avg_trace: np.ndarray, rep_samples: list[int]) -> str:
    """Scale average-trace amplitudes at peak positions to printable ASCII."""
    if not rep_samples:
        return ""
    amps = np.array([avg_trace[s] for s in rep_samples], dtype=np.float64)
    a_min, a_max = amps.min(), amps.max()
    if a_max == a_min:
        return ""
    # Scale to printable ASCII: 0x20 (32) to 0x7E (126)
    scaled = ((amps - a_min) / (a_max - a_min) * (0x7E - 0x20) + 0x20).round().astype(int)
    chars = "".join(chr(v) for v in scaled if 0x20 <= v <= 0x7E)
    if len(chars) < len(rep_samples) * 0.40:
        return ""
    return chars
