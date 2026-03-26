"""
Binary analyzer: ELF/PE headers, packed sections, overlay data, suspicious imports.
Extended with comprehensive flag decoding: XOR brute-force, Base64, ROT13, hex,
reversed bytes, cross-section reconstruction, entropy/decompression, and debug strings.
Extended further with ROP gadget scanner, format string detector, and optional angr integration.
"""
from __future__ import annotations

import base64
import codecs
import logging
import lzma
import math
import re
import struct
import zlib
from collections import Counter
from pathlib import Path
from typing import List, NamedTuple, Optional, Set, Tuple

from core.report import Finding
from core.ai_client import AIClient
from core.external import run_strings
from .base import Analyzer

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Optional imports — graceful degradation
# ---------------------------------------------------------------------------
try:
    import capstone as _capstone
    _CAPSTONE_AVAILABLE = True
except ImportError:
    _CAPSTONE_AVAILABLE = False
    logger.info("capstone not installed; ROP gadget scanner disabled.")

try:
    import angr as _angr
    _ANGR_AVAILABLE = True
except ImportError:
    _ANGR_AVAILABLE = False
    logger.info("angr not installed; symbolic execution disabled.")

_SUSPICIOUS_IMPORTS = {    "VirtualAlloc", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
    "WinExec", "ShellExecute", "ShellExecuteA", "ShellExecuteW",
    "system", "exec", "popen", "execve", "execl",
    "InternetOpenUrl", "URLDownloadToFile", "WinHttpOpen",
    "CryptEncrypt", "CryptDecrypt",
}

# Sections scanned in Fast mode
_FAST_MODE_SECTIONS: Set[str] = {".rodata", ".data"}

# Maximum number of RET sites to scan for ROP gadgets (performance guard)
_MAX_RET_SITES = 500

# Named multi-byte XOR keys
_NAMED_XOR_KEYS: List[bytes] = [
    bytes([0xDE, 0xAD]),
    bytes([0xBE, 0xEF]),
    bytes([0xCA, 0xFE]),
    bytes([0xBA, 0xBE]),
]

# All 2-byte combinations where one byte is 0x00
_ZERO_BYTE_XOR_KEYS: List[bytes] = (
    [bytes([0x00, n]) for n in range(1, 256)]
    + [bytes([n, 0x00]) for n in range(1, 256)]
)

_MULTI_BYTE_XOR_KEYS: List[bytes] = _NAMED_XOR_KEYS + _ZERO_BYTE_XOR_KEYS

# Minimum printable ASCII run length to consider meaningful
_MIN_PRINTABLE = 6

# Base64 character run pattern (at least 8 chars, valid padding)
_BASE64_RE = re.compile(rb"[A-Za-z0-9+/]{8,}={0,2}")

# Hex character run pattern (at least 12 chars, even length enforced at decode time)
_HEX_RE = re.compile(rb"[0-9a-fA-F]{12,}")

# UPX magic marker
_UPX_MAGIC = b"UPX!"

# ELF section header sizes (bytes)
_ELF32_SHDR_SIZE = 40
_ELF64_SHDR_SIZE = 64

# Maximum sections to parse per binary (prevents pathological inputs)
_MAX_SECTIONS_PARSED = 64

# CodeView debug info header: 4-byte signature + 16-byte GUID + 4-byte age
_CODEVIEW_HEADER_SIZE = 24

# PE resource type constant for raw binary data blobs
_RT_RCDATA = 10


# ---------------------------------------------------------------------------
# Module-level helper functions
# ---------------------------------------------------------------------------

class _SectionInfo(NamedTuple):
    """Parsed binary section."""
    name: str
    fmt: str        # "ELF" or "PE"
    data: bytes
    file_offset: int


def _extract_printable_strings(data: bytes, min_len: int = _MIN_PRINTABLE) -> List[Tuple[int, str]]:
    """Return list of (byte_offset, string) for printable ASCII runs in *data*."""
    results: List[Tuple[int, str]] = []
    start = -1
    for i, b in enumerate(data):
        if 0x20 <= b <= 0x7E:
            if start == -1:
                start = i
        else:
            if start != -1 and (i - start) >= min_len:
                results.append((start, data[start:i].decode("ascii")))
            start = -1
    if start != -1 and (len(data) - start) >= min_len:
        results.append((start, data[start:].decode("ascii")))
    return results


def _apply_xor(data: bytes, key: bytes) -> bytes:
    """XOR *data* with repeating *key*."""
    key_len = len(key)
    return bytes(b ^ key[i % key_len] for i, b in enumerate(data))


def _rot13(text: str) -> str:
    return codecs.encode(text, "rot_13")


def _compute_confidence(text: str, flag_pattern: re.Pattern) -> float:
    """Return confidence score based on flag match and printable run length."""
    if flag_pattern.search(text):
        return 0.95
    longest = max((len(m) for m in re.findall(r"[ -~]{6,}", text)), default=0)
    if longest > 20:
        return 0.70
    if longest > 10:
        return 0.50
    return 0.0


def _rva_to_file_offset(rva: int, sections_raw: List[Tuple[int, int, int]]) -> int:
    """Convert a PE RVA to a file offset using (virtual_addr, raw_offset, raw_size) tuples."""
    for va, raw_off, raw_size in sections_raw:
        if va <= rva < va + raw_size:
            return raw_off + (rva - va)
    return -1


# ---------------------------------------------------------------------------
# BinaryAnalyzer
# ---------------------------------------------------------------------------

class BinaryAnalyzer(Analyzer):
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
            return [self._finding(path, "Read error", str(exc), confidence=0.1)]

        fmt = ""
        sections: List[_SectionInfo] = []

        if data[:4] == b"\x7fELF":
            fmt = "ELF"
            findings.extend(self._elf_header_finding(path, data))
            sections = self._parse_elf_sections(data)
        elif data[:2] == b"MZ":
            fmt = "PE"
            pe_hdr = self._pe_header_finding(path, data)
            if pe_hdr:
                findings.append(pe_hdr)
            sections = self._parse_pe_sections(data)

        # Apply decoding techniques to sections
        if sections:
            seen: Set[Tuple[str, int]] = set()
            # Fast mode: only specific sections; Deep mode: all sections
            active_sections = (
                [s for s in sections if s.name in _FAST_MODE_SECTIONS]
                if depth == "fast" else sections
            )
            for sec in active_sections:
                findings.extend(self._apply_techniques(
                    path, sec, flag_pattern, depth, seen,
                    fast_only=(depth == "fast"),
                ))
            # Deep mode extras
            if depth != "fast":
                findings.extend(self._decode_cross_section(
                    path, fmt, sections, flag_pattern, seen,
                ))
                if fmt == "ELF":
                    debug_strs = self._extract_elf_debug_strings(data, sections)
                else:
                    debug_strs = self._extract_pe_debug_strings(data)
                findings.extend(self._decode_debug_strings(
                    path, fmt, debug_strs, flag_pattern, seen,
                ))

        # PE RCDATA resource extraction for re-dispatch (deep mode only)
        if fmt == "PE" and depth != "fast":
            findings.extend(self._extract_pe_rcdata(path, data, flag_pattern))

        # Overlay data (PE specific, kept from original)
        findings.extend(self._check_overlay(path, data, flag_pattern))

        # Suspicious imports via strings
        findings.extend(self._check_imports(path, flag_pattern))

        # ROP gadget scanner (deep mode or ELF/PE binaries)
        if sections and (depth == "deep" or fmt in ("ELF", "PE")):
            findings.extend(self._scan_rop_gadgets(path, sections, fmt))

        # Format string vulnerability detector
        strings_all = run_strings(path, min_len=3) if depth == "deep" else run_strings(path, min_len=4)
        findings.extend(self._detect_format_strings(path, strings_all, data, sections, fmt))

        # angr symbolic execution (deep mode only, optional)
        if depth == "deep" and fmt == "ELF":
            findings.extend(self._angr_analysis(path))

        return findings

    # ------------------------------------------------------------------
    # Header info findings (previously part of _analyze_elf/_analyze_pe)
    # ------------------------------------------------------------------

    def _elf_header_finding(self, path: str, data: bytes) -> List[Finding]:
        if len(data) < 64:
            return []
        ei_class = data[4]
        ei_data = data[5]
        e_type = struct.unpack_from("<H", data, 16)[0]
        type_map = {1: "Relocatable", 2: "Executable", 3: "Shared Object", 4: "Core"}
        elf_type = type_map.get(e_type, f"Unknown({e_type})")
        return [self._finding(
            path,
            f"ELF binary: {'32-bit' if ei_class == 1 else '64-bit'} {elf_type}",
            f"EI_CLASS={ei_class}, EI_DATA={ei_data}, e_type={e_type}",
            severity="INFO",
            confidence=0.7,
        )]

    def _pe_header_finding(self, path: str, data: bytes) -> Optional[Finding]:
        if len(data) < 64:
            return None
        try:
            pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
            if pe_offset + 24 > len(data):
                return self._finding(path, "PE header truncated", "", severity="INFO", confidence=0.4)
            pe_sig = data[pe_offset:pe_offset + 4]
            if pe_sig != b"PE\x00\x00":
                return self._finding(
                    path, "MZ file but invalid PE signature",
                    f"Got {pe_sig.hex()} at 0x{pe_offset:x}",
                    severity="MEDIUM", confidence=0.6,
                )
            machine = struct.unpack_from("<H", data, pe_offset + 4)[0]
            machine_map = {0x14c: "x86", 0x8664: "x64", 0x1c0: "ARM", 0xaa64: "ARM64"}
            arch = machine_map.get(machine, f"unknown(0x{machine:x})")
            num_sections = struct.unpack_from("<H", data, pe_offset + 6)[0]
            return self._finding(
                path,
                f"PE binary: {arch}, {num_sections} sections",
                f"Machine=0x{machine:x}, Sections={num_sections}",
                severity="INFO",
                confidence=0.7,
            )
        except Exception as exc:
            return self._finding(path, "PE parse error", str(exc), confidence=0.2)

    # ------------------------------------------------------------------
    # Section parsers
    # ------------------------------------------------------------------

    def _parse_elf_sections(self, data: bytes) -> List[_SectionInfo]:
        """Parse ELF section table for both 32-bit and 64-bit, LE and BE."""
        sections: List[_SectionInfo] = []
        if len(data) < 64:
            return sections
        try:
            ei_class = data[4]   # 1=32bit, 2=64bit
            ei_data = data[5]    # 1=LE, 2=BE
            end = "<" if ei_data == 1 else ">"

            if ei_class == 1:
                # 32-bit: e_shoff@32, e_shentsize@46, e_shnum@48, e_shstrndx@50
                e_shoff = struct.unpack_from(f"{end}I", data, 32)[0]
                e_shentsize = struct.unpack_from(f"{end}H", data, 46)[0]
                e_shnum = struct.unpack_from(f"{end}H", data, 48)[0]
                e_shstrndx = struct.unpack_from(f"{end}H", data, 50)[0]
                hdr_size = _ELF32_SHDR_SIZE

                def _sh32(i: int) -> Optional[Tuple[int, int, int, int]]:
                    off = e_shoff + i * e_shentsize
                    if off + hdr_size > len(data):
                        return None
                    sn = struct.unpack_from(f"{end}I", data, off)[0]
                    st = struct.unpack_from(f"{end}I", data, off + 4)[0]
                    so = struct.unpack_from(f"{end}I", data, off + 16)[0]
                    ss = struct.unpack_from(f"{end}I", data, off + 20)[0]
                    return sn, st, so, ss

                get_sh = _sh32
            elif ei_class == 2:
                # 64-bit: e_shoff@40, e_shentsize@58, e_shnum@60, e_shstrndx@62
                e_shoff = struct.unpack_from(f"{end}Q", data, 40)[0]
                e_shentsize = struct.unpack_from(f"{end}H", data, 58)[0]
                e_shnum = struct.unpack_from(f"{end}H", data, 60)[0]
                e_shstrndx = struct.unpack_from(f"{end}H", data, 62)[0]
                hdr_size = _ELF64_SHDR_SIZE

                def _sh64(i: int) -> Optional[Tuple[int, int, int, int]]:
                    off = e_shoff + i * e_shentsize
                    if off + hdr_size > len(data):
                        return None
                    sn = struct.unpack_from(f"{end}I", data, off)[0]
                    st = struct.unpack_from(f"{end}I", data, off + 4)[0]
                    so = struct.unpack_from(f"{end}Q", data, off + 24)[0]
                    ss = struct.unpack_from(f"{end}Q", data, off + 32)[0]
                    return sn, st, so, ss

                get_sh = _sh64
            else:
                return sections

            # Retrieve .shstrtab for section name lookup
            shstrtab = b""
            if 0 < e_shstrndx < e_shnum:
                hdr = get_sh(e_shstrndx)
                if hdr:
                    _, _, soff, ssz = hdr
                    if soff + ssz <= len(data):
                        shstrtab = data[soff:soff + ssz]

            for i in range(min(e_shnum, _MAX_SECTIONS_PARSED)):
                hdr = get_sh(i)
                if not hdr:
                    break
                name_idx, _sh_type, sh_offset, sh_size = hdr
                if sh_size == 0 or sh_offset == 0:
                    continue
                if sh_offset + sh_size > len(data):
                    continue
                # Decode name from string table
                name = f"section_{i}"
                if shstrtab and name_idx < len(shstrtab):
                    null = shstrtab.find(b"\x00", name_idx)
                    end_idx = null if null != -1 else len(shstrtab)
                    name = shstrtab[name_idx:end_idx].decode("latin-1", errors="replace")
                sec_data = data[sh_offset:sh_offset + sh_size]
                sections.append(_SectionInfo(
                    name=name, fmt="ELF", data=sec_data, file_offset=sh_offset,
                ))
        except Exception:
            pass
        return sections

    def _parse_pe_sections(self, data: bytes) -> List[_SectionInfo]:
        """Parse PE section table and append overlay section if present."""
        sections: List[_SectionInfo] = []
        if len(data) < 64:
            return sections
        try:
            pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
            if pe_offset + 24 > len(data):
                return sections
            if data[pe_offset:pe_offset + 4] != b"PE\x00\x00":
                return sections
            num_sections = struct.unpack_from("<H", data, pe_offset + 6)[0]
            opt_header_size = struct.unpack_from("<H", data, pe_offset + 20)[0]
            section_table_offset = pe_offset + 24 + opt_header_size
            for i in range(min(num_sections, _MAX_SECTIONS_PARSED)):
                sec_off = section_table_offset + i * 40
                if sec_off + 40 > len(data):
                    break
                sec_name = (
                    data[sec_off:sec_off + 8]
                    .decode("latin-1", errors="replace")
                    .rstrip("\x00")
                )
                raw_size = struct.unpack_from("<I", data, sec_off + 16)[0]
                raw_offset = struct.unpack_from("<I", data, sec_off + 20)[0]
                if raw_size > 0 and raw_offset > 0 and raw_offset + raw_size <= len(data):
                    sec_data = data[raw_offset:raw_offset + raw_size]
                    sections.append(_SectionInfo(
                        name=sec_name or f"section_{i}",
                        fmt="PE",
                        data=sec_data,
                        file_offset=raw_offset,
                    ))
            # Overlay section
            if sections:
                last_end = max(s.file_offset + len(s.data) for s in sections)
                if last_end < len(data) - 4:
                    sections.append(_SectionInfo(
                        name="[overlay]", fmt="PE",
                        data=data[last_end:], file_offset=last_end,
                    ))
        except Exception:
            pass
        return sections

    # ------------------------------------------------------------------
    # Entropy helper
    # ------------------------------------------------------------------

    def _shannon_entropy(self, data: bytes) -> float:
        if not data:
            return 0.0
        counts = Counter(data)
        length = len(data)
        return -sum((c / length) * math.log2(c / length) for c in counts.values())

    # ------------------------------------------------------------------
    # Per-section technique dispatcher
    # ------------------------------------------------------------------

    def _apply_techniques(
        self,
        path: str,
        sec: _SectionInfo,
        flag_pattern: re.Pattern,
        depth: str,
        seen: Set[Tuple[str, int]],
        fast_only: bool = False,
    ) -> List[Finding]:
        findings: List[Finding] = []
        findings.extend(self._decode_xor_single(path, sec, flag_pattern, seen))
        findings.extend(self._decode_base64(path, sec, flag_pattern, seen))
        findings.extend(self._decode_rot13(path, sec, flag_pattern, seen))
        findings.extend(self._decode_hex(path, sec, flag_pattern, seen))
        findings.extend(self._decode_reversed(path, sec, flag_pattern, seen))
        if not fast_only:
            findings.extend(self._decode_xor_multi(path, sec, flag_pattern, seen))
            findings.extend(self._decode_entropy(path, sec, flag_pattern, depth, seen))
        return findings

    # ------------------------------------------------------------------
    # Technique implementations
    # ------------------------------------------------------------------

    def _emit(
        self,
        path: str,
        sec: _SectionInfo,
        technique: str,
        decoded: str,
        within_offset: int,
        flag_pattern: re.Pattern,
        seen: Set[Tuple[str, int]],
    ) -> Optional[Finding]:
        """Create a finding if it passes deduplication and confidence threshold."""
        conf = _compute_confidence(decoded, flag_pattern)
        if conf < 0.50:
            return None
        dedup_key = (decoded.lower(), sec.file_offset + within_offset)
        if dedup_key in seen:
            return None
        seen.add(dedup_key)
        fm = conf >= 0.95
        file_off = sec.file_offset + within_offset
        title = (
            f"[{sec.fmt}/{sec.name}] {technique}: {decoded[:60]}"
        )
        detail = (
            f"Format={sec.fmt}, Section={sec.name}, Technique={technique}, "
            f"FileOffset=0x{file_off:x} (within-section: 0x{within_offset:x}), "
            f"Decoded={decoded[:200]}"
        )
        return self._finding(
            path, title, detail,
            severity="HIGH" if fm else "MEDIUM",
            offset=file_off,
            flag_match=fm,
            confidence=conf,
        )

    def _decode_xor_single(
        self,
        path: str,
        sec: _SectionInfo,
        flag_pattern: re.Pattern,
        seen: Set[Tuple[str, int]],
    ) -> List[Finding]:
        """Try all 256 single-byte XOR keys against section data."""
        findings: List[Finding] = []
        data = sec.data
        for key in range(256):
            xored = _apply_xor(data, bytes([key]))
            for off, s in _extract_printable_strings(xored):
                f = self._emit(path, sec, f"XOR(0x{key:02x})", s, off, flag_pattern, seen)
                if f:
                    findings.append(f)
        return findings

    def _decode_xor_multi(
        self,
        path: str,
        sec: _SectionInfo,
        flag_pattern: re.Pattern,
        seen: Set[Tuple[str, int]],
    ) -> List[Finding]:
        """Try common multi-byte XOR keys."""
        findings: List[Finding] = []
        data = sec.data
        for key in _MULTI_BYTE_XOR_KEYS:
            xored = _apply_xor(data, key)
            key_hex = key.hex()
            for off, s in _extract_printable_strings(xored):
                f = self._emit(
                    path, sec, f"XOR(0x{key_hex})", s, off, flag_pattern, seen,
                )
                if f:
                    findings.append(f)
        return findings

    def _decode_base64(
        self,
        path: str,
        sec: _SectionInfo,
        flag_pattern: re.Pattern,
        seen: Set[Tuple[str, int]],
    ) -> List[Finding]:
        """Scan section for Base64 runs and attempt decode."""
        findings: List[Finding] = []
        for m in _BASE64_RE.finditer(sec.data):
            candidate = m.group(0)
            # Pad to multiple of 4 if needed
            padded = candidate + b"=" * ((4 - len(candidate) % 4) % 4)
            try:
                decoded_bytes = base64.b64decode(padded)
                decoded = decoded_bytes.decode("latin-1", errors="replace")
                within_off = m.start()
                f = self._emit(path, sec, "Base64", decoded, within_off, flag_pattern, seen)
                if f:
                    findings.append(f)
            except Exception:
                pass
        return findings

    def _decode_rot13(
        self,
        path: str,
        sec: _SectionInfo,
        flag_pattern: re.Pattern,
        seen: Set[Tuple[str, int]],
    ) -> List[Finding]:
        """Apply ROT13 to every printable string extracted from the section."""
        findings: List[Finding] = []
        for off, s in _extract_printable_strings(sec.data):
            rotated = _rot13(s)
            f = self._emit(path, sec, "ROT13", rotated, off, flag_pattern, seen)
            if f:
                findings.append(f)
        return findings

    def _decode_hex(
        self,
        path: str,
        sec: _SectionInfo,
        flag_pattern: re.Pattern,
        seen: Set[Tuple[str, int]],
    ) -> List[Finding]:
        """Scan for hex runs of even length ≥12 and decode."""
        findings: List[Finding] = []
        for m in _HEX_RE.finditer(sec.data):
            raw = m.group(0)
            if len(raw) % 2 != 0:
                raw = raw[:-1]  # trim to even length
            if len(raw) < 12:
                continue
            try:
                decoded_bytes = bytes.fromhex(raw.decode("ascii"))
                decoded = decoded_bytes.decode("latin-1", errors="replace")
                within_off = m.start()
                f = self._emit(path, sec, "HexDecode", decoded, within_off, flag_pattern, seen)
                if f:
                    findings.append(f)
            except Exception:
                pass
        return findings

    def _decode_reversed(
        self,
        path: str,
        sec: _SectionInfo,
        flag_pattern: re.Pattern,
        seen: Set[Tuple[str, int]],
    ) -> List[Finding]:
        """Reverse entire section bytes and reverse each individual string."""
        findings: List[Finding] = []
        # Reverse entire section
        rev = sec.data[::-1]
        rev_sec = _SectionInfo(
            name=sec.name, fmt=sec.fmt, data=rev, file_offset=sec.file_offset,
        )
        for off, s in _extract_printable_strings(rev):
            # Within-section offset maps back to original reversed position
            orig_off = len(sec.data) - off - len(s)
            f = self._emit(path, rev_sec, "ReversedSection", s, orig_off, flag_pattern, seen)
            if f:
                findings.append(f)
        # Reverse each individual string
        for off, s in _extract_printable_strings(sec.data):
            rev_s = s[::-1]
            f = self._emit(path, sec, "ReversedString", rev_s, off, flag_pattern, seen)
            if f:
                findings.append(f)
        return findings

    def _decode_entropy(
        self,
        path: str,
        sec: _SectionInfo,
        flag_pattern: re.Pattern,
        depth: str,
        seen: Set[Tuple[str, int]],
    ) -> List[Finding]:
        """Check section entropy; in Deep mode attempt UPX/zlib/lzma decompression."""
        findings: List[Finding] = []
        ent = self._shannon_entropy(sec.data)
        if ent <= 6.8:
            return findings

        # Emit high-entropy finding
        title = f"[{sec.fmt}/{sec.name}] High entropy (H={ent:.3f})"
        detail = (
            f"Format={sec.fmt}, Section={sec.name}, Technique=EntropyCheck, "
            f"FileOffset=0x{sec.file_offset:x}, Entropy={ent:.3f}"
        )
        findings.append(self._finding(
            path, title, detail,
            severity="HIGH", offset=sec.file_offset, confidence=0.75,
        ))

        if depth == "fast":
            return findings

        # UPX magic detection
        if _UPX_MAGIC in sec.data:
            findings.append(self._finding(
                path,
                f"[{sec.fmt}/{sec.name}] UPX magic found",
                f"Format={sec.fmt}, Section={sec.name}, Technique=UPXDetect, "
                f"FileOffset=0x{sec.file_offset:x}",
                severity="HIGH", offset=sec.file_offset, confidence=0.80,
            ))

        # Attempt decompression and re-run techniques on result
        for decomp_name, decompress_fn in [
            ("zlib", zlib.decompress),
            ("lzma", lzma.decompress),
        ]:
            try:
                decompressed = decompress_fn(sec.data)
                if not decompressed:
                    continue
                decomp_sec = _SectionInfo(
                    name=f"{sec.name}[{decomp_name}]",
                    fmt=sec.fmt,
                    data=decompressed,
                    file_offset=sec.file_offset,
                )
                findings.append(self._finding(
                    path,
                    f"[{sec.fmt}/{sec.name}] {decomp_name} decompression succeeded "
                    f"({len(decompressed)} bytes)",
                    f"Format={sec.fmt}, Section={sec.name}, Technique={decomp_name}Decompress, "
                    f"FileOffset=0x{sec.file_offset:x}",
                    severity="HIGH", offset=sec.file_offset, confidence=0.80,
                ))
                # Re-run all techniques on decompressed data
                findings.extend(self._apply_techniques(
                    path, decomp_sec, flag_pattern, depth, seen, fast_only=False,
                ))
            except Exception:
                pass

        return findings

    def _decode_cross_section(
        self,
        path: str,
        fmt: str,
        sections: List[_SectionInfo],
        flag_pattern: re.Pattern,
        seen: Set[Tuple[str, int]],
    ) -> List[Finding]:
        """Attempt to reconstruct the flag from strings spanning multiple sections."""
        findings: List[Finding] = []
        # Collect all strings per section in order
        section_strings: List[Tuple[str, List[str]]] = []
        for sec in sections:
            strs = [s for _, s in _extract_printable_strings(sec.data)]
            if strs:
                section_strings.append((sec.name, strs))

        if not section_strings:
            return findings

        all_strings = [s for _, strs in section_strings for s in strs]
        contributing = [name for name, strs in section_strings for _ in strs]

        def _check(candidate: str, technique: str, sec_names: str) -> None:
            conf = _compute_confidence(candidate, flag_pattern)
            if conf < 0.95:
                return
            dedup_key = (candidate.lower(), -1)
            if dedup_key in seen:
                return
            seen.add(dedup_key)
            findings.append(self._finding(
                path,
                f"[{fmt}/cross-section] {technique}: {candidate[:60]}",
                f"Format={fmt}, Sections={sec_names}, Technique={technique}, "
                f"Decoded={candidate[:200]}",
                severity="HIGH", offset=-1, flag_match=True, confidence=conf,
            ))

        # (a) Concatenate all strings in section order
        _check("".join(all_strings), "CrossSection-Concat",
               "+".join(n for n, _ in section_strings))

        # (b) Interleave characters from pairs of sections
        for i, (name_a, strs_a) in enumerate(section_strings):
            for j, (name_b, strs_b) in enumerate(section_strings):
                if j <= i:
                    continue
                text_a = "".join(strs_a)
                text_b = "".join(strs_b)
                interleaved = "".join(a + b for a, b in zip(text_a, text_b))
                _check(interleaved, "CrossSection-Interleave", f"{name_a}+{name_b}")

        # (c) Every Nth string (N from 2 to min(8, len(all_strings)//2))
        max_n = min(8, max(len(all_strings) // 2, 2))
        for n in range(2, max_n + 1):
            joined = "".join(all_strings[i] for i in range(0, len(all_strings), n))
            sec_names = "+".join(contributing[i] for i in range(0, len(contributing), n))
            _check(joined, f"CrossSection-Every{n}th", sec_names)

        return findings

    # ------------------------------------------------------------------
    # Debug string extraction
    # ------------------------------------------------------------------

    def _extract_elf_debug_strings(
        self, data: bytes, sections: List[_SectionInfo],
    ) -> List[str]:
        """Extract null-terminated strings from ELF .debug_str and .debug_info."""
        strings: List[str] = []
        for sec in sections:
            if sec.name not in (".debug_str", ".debug_info"):
                continue
            # Split on null bytes to get null-terminated strings
            for part in sec.data.split(b"\x00"):
                s = part.decode("latin-1", errors="replace").strip()
                if len(s) >= _MIN_PRINTABLE:
                    strings.append(s)
        return strings

    def _extract_pe_debug_strings(self, data: bytes) -> List[str]:
        """Extract strings from PE debug directory and .rdata section."""
        strings: List[str] = []
        if len(data) < 64:
            return strings
        try:
            pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
            if pe_offset + 24 > len(data):
                return strings
            if data[pe_offset:pe_offset + 4] != b"PE\x00\x00":
                return strings

            opt_hdr_off = pe_offset + 24
            if opt_hdr_off + 2 > len(data):
                return strings
            opt_magic = struct.unpack_from("<H", data, opt_hdr_off)[0]
            # PE32=0x10b → debug dir at opt+144; PE32+=0x20b → debug dir at opt+160
            if opt_magic == 0x10B:
                dbg_dir_off = opt_hdr_off + 144
            elif opt_magic == 0x20B:
                dbg_dir_off = opt_hdr_off + 160
            else:
                dbg_dir_off = -1

            # Build VA-to-file offset map from section table
            num_sections = struct.unpack_from("<H", data, pe_offset + 6)[0]
            opt_header_size = struct.unpack_from("<H", data, pe_offset + 20)[0]
            section_table_offset = pe_offset + 24 + opt_header_size
            sections_raw: List[Tuple[int, int, int]] = []
            for i in range(min(num_sections, _MAX_SECTIONS_PARSED)):
                sec_off = section_table_offset + i * 40
                if sec_off + 40 > len(data):
                    break
                virt_addr = struct.unpack_from("<I", data, sec_off + 12)[0]
                raw_sz = struct.unpack_from("<I", data, sec_off + 16)[0]
                raw_off = struct.unpack_from("<I", data, sec_off + 20)[0]
                if raw_sz > 0 and raw_off > 0:
                    sections_raw.append((virt_addr, raw_off, raw_sz))
                # Collect all .rdata strings
                sec_name = (
                    data[sec_off:sec_off + 8]
                    .decode("latin-1", errors="replace")
                    .rstrip("\x00")
                )
                if sec_name == ".rdata" and raw_sz > 0 and raw_off + raw_sz <= len(data):
                    rdata = data[raw_off:raw_off + raw_sz]
                    for _, s in _extract_printable_strings(rdata):
                        strings.append(s)

            # Parse debug directory for CodeView/PDB path strings
            if dbg_dir_off != -1 and dbg_dir_off + 8 <= len(data):
                dbg_rva = struct.unpack_from("<I", data, dbg_dir_off)[0]
                dbg_sz = struct.unpack_from("<I", data, dbg_dir_off + 4)[0]
                if dbg_rva and dbg_sz:
                    dbg_file_off = _rva_to_file_offset(dbg_rva, sections_raw)
                    if dbg_file_off != -1:
                        entry_count = dbg_sz // 28
                        for ei in range(entry_count):
                            eoff = dbg_file_off + ei * 28
                            if eoff + 28 > len(data):
                                break
                            dbg_type = struct.unpack_from("<I", data, eoff + 12)[0]
                            dbg_data_sz = struct.unpack_from("<I", data, eoff + 16)[0]
                            dbg_ptr = struct.unpack_from("<I", data, eoff + 24)[0]
                            if dbg_type == 2 and dbg_ptr and dbg_data_sz:  # CodeView
                                cv_end = dbg_ptr + dbg_data_sz
                                if cv_end <= len(data):
                                    cv_data = data[dbg_ptr:cv_end]
                                    # Skip 4-byte signature + 16-byte GUID + 4-byte age
                                    pdb_path_start = _CODEVIEW_HEADER_SIZE if len(cv_data) > _CODEVIEW_HEADER_SIZE else 0
                                    pdb_null = cv_data.find(b"\x00", pdb_path_start)
                                    pdb_end = pdb_null if pdb_null != -1 else len(cv_data)
                                    pdb_path = cv_data[pdb_path_start:pdb_end].decode(
                                        "latin-1", errors="replace"
                                    )
                                    if len(pdb_path) >= _MIN_PRINTABLE:
                                        strings.append(pdb_path)
        except Exception:
            pass
        return strings

    def _decode_debug_strings(
        self,
        path: str,
        fmt: str,
        debug_strings: List[str],
        flag_pattern: re.Pattern,
        seen: Set[Tuple[str, int]],
    ) -> List[Finding]:
        """Apply decoding techniques to individual debug strings."""
        findings: List[Finding] = []
        for s in debug_strings:
            s_bytes = s.encode("latin-1", errors="replace")
            fake_sec = _SectionInfo(name="[debug]", fmt=fmt, data=s_bytes, file_offset=0)
            # XOR single-byte
            findings.extend(self._decode_xor_single(path, fake_sec, flag_pattern, seen))
            # Base64
            findings.extend(self._decode_base64(path, fake_sec, flag_pattern, seen))
            # ROT13
            rotated = _rot13(s)
            f = self._emit(path, fake_sec, "ROT13", rotated, 0, flag_pattern, seen)
            if f:
                findings.append(f)
            # Hex decode
            findings.extend(self._decode_hex(path, fake_sec, flag_pattern, seen))
            # Reversed string
            rev = s[::-1]
            f = self._emit(path, fake_sec, "ReversedString", rev, 0, flag_pattern, seen)
            if f:
                findings.append(f)
            # Direct flag check on the raw string
            conf = _compute_confidence(s, flag_pattern)
            if conf >= 0.95:
                f = self._emit(path, fake_sec, "DebugStringDirect", s, 0, flag_pattern, seen)
                if f:
                    findings.append(f)
        return findings

    # ------------------------------------------------------------------
    # Preserved original helpers
    # ------------------------------------------------------------------

    def _check_overlay(self, path: str, data: bytes, flag_pattern: re.Pattern) -> List[Finding]:
        """Check for data appended after last PE section."""
        findings: List[Finding] = []
        if len(data) < 64 or data[:2] != b"MZ":
            return []
        try:
            pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
            if data[pe_offset:pe_offset + 4] != b"PE\x00\x00":
                return []
            num_sections = struct.unpack_from("<H", data, pe_offset + 6)[0]
            opt_header_size = struct.unpack_from("<H", data, pe_offset + 20)[0]
            section_table_offset = pe_offset + 24 + opt_header_size
            last_end = 0
            for i in range(num_sections):
                sec_off = section_table_offset + i * 40
                if sec_off + 40 > len(data):
                    break
                raw_offset = struct.unpack_from("<I", data, sec_off + 20)[0]
                raw_size = struct.unpack_from("<I", data, sec_off + 16)[0]
                end = raw_offset + raw_size
                if end > last_end:
                    last_end = end
            if last_end > 0 and last_end < len(data) - 4:
                overlay = data[last_end:]
                text = overlay.decode("latin-1", errors="replace")
                fm = self._check_flag(text, flag_pattern)
                findings.append(self._finding(
                    path,
                    f"PE overlay data: {len(overlay)} bytes after last section",
                    f"Overlay at 0x{last_end:x}: {overlay[:64].hex()}",
                    severity="HIGH" if fm else "MEDIUM",
                    offset=last_end,
                    flag_match=fm,
                    confidence=0.80 if fm else 0.65,
                ))
        except Exception:
            pass
        return findings

    def _check_imports(self, path: str, flag_pattern: re.Pattern) -> List[Finding]:
        findings: List[Finding] = []
        strings = run_strings(path, min_len=4)
        hits = [s for s in strings if any(imp in s for imp in _SUSPICIOUS_IMPORTS)]
        if hits:
            findings.append(self._finding(
                path,
                f"Suspicious imported symbols: {len(hits)} found",
                ", ".join(hits[:20]),
                severity="HIGH",
                confidence=0.75,
            ))
        # Flag in strings
        for s in strings:
            if self._check_flag(s, flag_pattern):
                findings.append(self._finding(
                    path,
                    f"Flag pattern in binary strings: {s[:80]}",
                    s,
                    severity="HIGH",
                    flag_match=True,
                    confidence=0.95,
                ))
        return findings

    # ------------------------------------------------------------------
    # ROP gadget scanner
    # ------------------------------------------------------------------

    def _scan_rop_gadgets(
        self,
        path: str,
        sections: List[_SectionInfo],
        fmt: str,
    ) -> List[Finding]:
        """
        Walk executable sections for ret/jmp/call gadgets.
        Reports count, density, and top 20 most useful gadgets.
        Requires capstone; gracefully degrades if not available.
        """
        findings: List[Finding] = []

        if not _CAPSTONE_AVAILABLE:
            findings.append(self._finding(
                path,
                "ROP gadget scan skipped (capstone not installed)",
                "Install capstone: pip install capstone",
                severity="INFO",
                confidence=0.3,
            ))
            return findings

        try:
            import capstone as cs
        except ImportError:
            return findings

        # Determine architecture from magic / section format
        if fmt == "ELF":
            md = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64)
        elif fmt == "PE":
            md = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_32)
        else:
            md = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64)
        md.detail = True

        all_gadgets: List[str] = []
        total_bytes = 0

        # Useful gadget patterns (mnemonic, op_str hint)
        useful_patterns = {
            ("pop", "ret"),     # pop reg; ret
            ("syscall", ""),    # syscall; ret
            ("int", "0x80"),    # int 0x80; ret
            ("mov", "ret"),     # mov reg; ret
        }

        for sec in sections:
            # Only executable sections
            exec_names = {".text", ".plt", ".init", ".fini"}
            if sec.name not in exec_names and sec.fmt != "PE":
                # For PE, scan all sections; for ELF only known exec sections
                if fmt == "ELF":
                    continue

            data = sec.data
            total_bytes += len(data)
            offset = sec.file_offset

            # Find all RET instructions and walk back up to 5 bytes for gadgets
            ret_offsets = [i for i, b in enumerate(data) if b == 0xC3]  # RET
            for ret_off in ret_offsets[:_MAX_RET_SITES]:
                for look_back in range(1, 6):
                    start = ret_off - look_back
                    if start < 0:
                        continue
                    chunk = data[start:ret_off + 1]
                    try:
                        insns = list(md.disasm(chunk, offset + start))
                        if not insns or insns[-1].mnemonic not in ("ret", "retn"):
                            continue
                        gadget_str = "; ".join(f"{i.mnemonic} {i.op_str}".strip() for i in insns)
                        all_gadgets.append(gadget_str)
                    except Exception:
                        pass

        if not all_gadgets:
            return findings

        # Count and density
        unique_gadgets = list(dict.fromkeys(all_gadgets))
        density = len(all_gadgets) / max(total_bytes, 1) * 1000  # per KB

        # Score gadgets by usefulness
        def _gadget_score(g: str) -> int:
            score = 0
            if "pop" in g and "ret" in g:
                score += 3
            if "syscall" in g or "int 0x80" in g:
                score += 5
            if "mov" in g and "ret" in g:
                score += 2
            if "xor" in g and "ret" in g:
                score += 2
            return score

        top_20 = sorted(unique_gadgets, key=_gadget_score, reverse=True)[:20]

        findings.append(self._finding(
            path,
            f"ROP gadgets found: {len(unique_gadgets)} unique ({density:.1f}/KB)",
            (
                f"Total gadget instances: {len(all_gadgets)}\n"
                f"Unique gadgets: {len(unique_gadgets)}\n"
                f"Density: {density:.2f} per KB\n\n"
                f"Top 20 useful gadgets:\n"
                + "\n".join(f"  {g}" for g in top_20)
            ),
            severity="HIGH" if density > 5 else "MEDIUM",
            confidence=0.75,
        ))

        return findings

    # ------------------------------------------------------------------
    # Format string detector
    # ------------------------------------------------------------------

    _FORMAT_STRING_PATTERNS = [
        re.compile(r"%n"),
        re.compile(r"(%s){3,}"),
        re.compile(r"(%x){3,}"),
        re.compile(r"(%d){3,}"),
        re.compile(r"(%p){2,}"),
    ]

    _FORMAT_CALL_FUNCS = re.compile(
        r"\b(printf|fprintf|sprintf|snprintf|syslog|vprintf|vfprintf"
        r"|vsprintf|vsnprintf|wprintf|fwprintf)\b"
    )

    def _detect_format_strings(
        self,
        path: str,
        strings: List[str],
        data: bytes,
        sections: List[_SectionInfo],
        fmt: str,
    ) -> List[Finding]:
        """
        Scan strings section and extracted strings for dangerous format string patterns.
        Flag suspected vulnerable call sites in disassembly output.
        """
        findings: List[Finding] = []
        suspect_strings: List[str] = []

        for s in strings:
            for pat in self._FORMAT_STRING_PATTERNS:
                if pat.search(s):
                    suspect_strings.append(s)
                    break

        if not suspect_strings:
            return findings

        # Check if binary uses printf-family functions
        all_text = " ".join(strings)
        has_format_funcs = bool(self._FORMAT_CALL_FUNCS.search(all_text))

        detail = (
            f"Suspicious format strings found ({len(suspect_strings)} total):\n"
            + "\n".join(f"  {s[:80]!r}" for s in suspect_strings[:10])
        )
        if has_format_funcs:
            detail += "\n\nBinary also contains printf-family function references → possible format string vulnerability."
            severity = "HIGH"
            confidence = 0.82
        else:
            severity = "MEDIUM"
            confidence = 0.60

        findings.append(self._finding(
            path,
            f"Format string vulnerability pattern detected ({len(suspect_strings)} strings)",
            detail,
            severity=severity,
            confidence=confidence,
        ))

        return findings

    # ------------------------------------------------------------------
    # angr symbolic execution (optional)
    # ------------------------------------------------------------------

    def _angr_analysis(self, path: str) -> List[Finding]:
        """
        Use angr to find paths to win/flag/system functions and report
        symbolic constraints on stdin.  Gracefully degrades if angr is not installed.
        """
        findings: List[Finding] = []

        if not _ANGR_AVAILABLE:
            findings.append(self._finding(
                path,
                "Symbolic execution skipped (angr not installed)",
                "Install angr: pip install angr",
                severity="INFO",
                confidence=0.2,
            ))
            return findings

        try:
            proj = _angr.Project(path, auto_load_libs=False)
            cfg = proj.analyses.CFGFast()

            # Look for functions named win, flag, system, execve, etc.
            target_names = {"win", "flag", "system", "execve", "shell", "get_flag"}
            targets = []
            for func in cfg.kb.functions.values():
                if func.name and any(t in func.name.lower() for t in target_names):
                    targets.append(func)

            if not targets:
                findings.append(self._finding(
                    path,
                    "angr: no obvious win/flag function found",
                    "CFG analysis completed; no functions matching win/flag/system pattern.",
                    severity="INFO",
                    confidence=0.3,
                ))
                return findings

            for target_func in targets[:3]:
                state = proj.factory.entry_state(
                    stdin=_angr.SimFileStream,
                )
                simgr = proj.factory.simgr(state)
                try:
                    simgr.explore(find=target_func.addr, num_find=1)
                except Exception:
                    pass

                if simgr.found:
                    found_state = simgr.found[0]
                    try:
                        stdin_bytes = found_state.posix.stdin.load(0, found_state.posix.stdin.size)
                        stdin_concrete = found_state.solver.eval(stdin_bytes, cast_to=bytes)
                        constraint_str = stdin_concrete.decode("utf-8", errors="replace")[:200]
                    except Exception:
                        constraint_str = "(could not concretize stdin)"

                    findings.append(self._finding(
                        path,
                        f"angr: path found to {target_func.name}() at 0x{target_func.addr:x}",
                        f"Stdin constraint: {constraint_str!r}",
                        severity="HIGH",
                        confidence=0.85,
                    ))

        except Exception as exc:
            findings.append(self._finding(
                path,
                "angr analysis failed",
                str(exc),
                severity="INFO",
                confidence=0.1,
            ))

        return findings

    # ------------------------------------------------------------------
    # PE RCDATA resource extraction
    # ------------------------------------------------------------------

    def _extract_pe_rcdata(
        self,
        path: str,
        data: bytes,
        flag_pattern: re.Pattern,
    ) -> List[Finding]:
        """Parse the PE .rsrc section and emit RCDATA (type 10) blobs for re-dispatch.

        Each RCDATA leaf is emitted as a Finding whose detail contains a
        ``raw_hex=<hex>`` token so that ``extract_from_finding`` (and the
        ContentRedispatcher) can automatically re-analyze the blob through
        the full analyzer pipeline.

        Only blobs >= 4 bytes are emitted to avoid noise from tiny padding entries.
        A guard of 256 entries per directory level prevents infinite loops on
        malformed or hand-crafted PE resources.
        """
        findings: List[Finding] = []
        if len(data) < 64 or data[:2] != b"MZ":
            return findings
        try:
            pe_off = struct.unpack_from("<I", data, 0x3C)[0]
            if pe_off + 28 > len(data) or data[pe_off:pe_off + 4] != b"PE\x00\x00":
                return findings

            num_sections = struct.unpack_from("<H", data, pe_off + 6)[0]
            opt_hdr_size = struct.unpack_from("<H", data, pe_off + 20)[0]
            opt_off = pe_off + 24
            if opt_off + 2 > len(data):
                return findings
            opt_magic = struct.unpack_from("<H", data, opt_off)[0]

            # DataDirectory[2] = Resource directory RVA and size
            # PE32  (0x10B): opt + 96 + 2×8 = opt + 112
            # PE32+ (0x20B): opt + 112 + 2×8 = opt + 128
            if opt_magic == 0x10B:
                rsrc_dd_off = opt_off + 112
            elif opt_magic == 0x20B:
                rsrc_dd_off = opt_off + 128
            else:
                return findings

            if rsrc_dd_off + 8 > len(data):
                return findings
            rsrc_rva = struct.unpack_from("<I", data, rsrc_dd_off)[0]
            rsrc_sz = struct.unpack_from("<I", data, rsrc_dd_off + 4)[0]
            if rsrc_rva == 0 or rsrc_sz == 0:
                return findings

            # Build section VA → file offset table
            sec_tab_off = pe_off + 24 + opt_hdr_size
            sections_raw: List[Tuple[int, int, int]] = []
            for i in range(min(num_sections, _MAX_SECTIONS_PARSED)):
                off = sec_tab_off + i * 40
                if off + 40 > len(data):
                    break
                va = struct.unpack_from("<I", data, off + 12)[0]
                raw_sz = struct.unpack_from("<I", data, off + 16)[0]
                raw_off = struct.unpack_from("<I", data, off + 20)[0]
                if raw_sz > 0 and raw_off > 0:
                    sections_raw.append((va, raw_off, raw_sz))

            rsrc_base = _rva_to_file_offset(rsrc_rva, sections_raw)
            if rsrc_base < 0:
                return findings

            _MAX_DIR_ENTRIES = 256  # guard against malformed directories

            def _parse_dir(
                dir_file_off: int,
                level: int,
                res_type: int,
                res_id: int,
            ) -> None:
                if dir_file_off + 16 > len(data):
                    return
                named_n = struct.unpack_from("<H", data, dir_file_off + 12)[0]
                id_n = struct.unpack_from("<H", data, dir_file_off + 14)[0]
                entries_off = dir_file_off + 16
                for _ in range(min(named_n + id_n, _MAX_DIR_ENTRIES)):
                    if entries_off + 8 > len(data):
                        break
                    name_id_field = struct.unpack_from("<I", data, entries_off)[0]
                    offset_field = struct.unpack_from("<I", data, entries_off + 4)[0]
                    entries_off += 8

                    cur_type = res_type
                    cur_id = res_id
                    if level == 1:
                        cur_type = name_id_field & 0x7FFFFFFF
                        if cur_type != _RT_RCDATA:
                            continue  # skip non-RCDATA type entries
                    elif level == 2:
                        cur_id = name_id_field & 0x7FFFFFFF

                    if offset_field & 0x80000000:
                        # Points to a subdirectory
                        sub_off = rsrc_base + (offset_field & 0x7FFFFFFF)
                        _parse_dir(sub_off, level + 1, cur_type, cur_id)
                    else:
                        # Leaf: IMAGE_RESOURCE_DATA_ENTRY (16 bytes)
                        leaf_off = rsrc_base + offset_field
                        if leaf_off + 16 > len(data):
                            continue
                        data_rva = struct.unpack_from("<I", data, leaf_off)[0]
                        data_size = struct.unpack_from("<I", data, leaf_off + 4)[0]
                        if data_rva == 0 or data_size == 0 or data_size > 0x1000000:
                            continue
                        file_off = _rva_to_file_offset(data_rva, sections_raw)
                        if file_off < 0 or file_off + data_size > len(data):
                            continue
                        blob = data[file_off:file_off + data_size]
                        if len(blob) < 4:
                            continue
                        text = blob.decode("latin-1", errors="replace")
                        fm = self._check_flag(text, flag_pattern)
                        findings.append(self._finding(
                            path,
                            f"PE RCDATA resource #{cur_id} ({data_size} bytes)",
                            f"ResourceID={cur_id}, FileOffset=0x{file_off:x}, "
                            f"Size={data_size}, raw_hex={blob.hex()}",
                            severity="HIGH" if fm else "MEDIUM",
                            offset=file_off,
                            flag_match=fm,
                            confidence=0.85 if fm else 0.60,
                        ))

            _parse_dir(rsrc_base, 1, 0, 0)

        except Exception:
            pass
        return findings
