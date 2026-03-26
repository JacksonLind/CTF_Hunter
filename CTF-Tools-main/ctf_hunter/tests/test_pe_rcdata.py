"""
Tests for PE RCDATA resource extraction in analyzers/binary.py.

Coverage:
  1. RCDATA blob is found in a well-formed PE32 with .rsrc section
  2. Flag pattern inside RCDATA blob → HIGH severity, flag_match=True
  3. Non-flag RCDATA blob → MEDIUM severity, flag_match=False
  4. raw_hex= token present in Finding.detail for re-dispatch
  5. Non-RCDATA resource type (e.g. RT_STRING = 6) is ignored
  6. Non-PE binary (ELF magic) → empty findings from _extract_pe_rcdata
  7. PE without .rsrc section (empty resource DataDirectory) → empty findings
  8. Blob < 4 bytes → skipped (too small)
  9. Fast mode → RCDATA extraction skipped in analyze()
 10. Deep mode + PE → RCDATA finding present in analyze() output

Run from ctf_hunter/ directory:
    python tests/test_pe_rcdata.py
"""
from __future__ import annotations

import os
import re
import struct
import sys
import tempfile
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from analyzers.binary import BinaryAnalyzer, _RT_RCDATA

FLAG_PATTERN = re.compile(r"flag\{[^}]+\}")

_ANALYZER = BinaryAnalyzer()

# ---------------------------------------------------------------------------
# Minimal PE32 builder
# ---------------------------------------------------------------------------

def _make_pe32_rsrc(blob: bytes, res_type: int = _RT_RCDATA, res_id: int = 1) -> bytes:
    """Build a minimal PE32 binary that has a single resource of *res_type*
    with ID *res_id* containing *blob* as its data.

    Layout
    ------
    0x000 – 0x03F  : DOS header (e_magic=MZ, e_lfanew=0x40)
    0x040 – 0x043  : PE signature
    0x044 – 0x057  : COFF header (1 section, SizeOfOptionalHeader=0xe0)
    0x058 – 0x137  : Optional header PE32 (magic=0x010b)
    0x138 – 0x15F  : Section table (.rsrc entry)
    0x160 – 0x1FF  : Padding
    0x200 – ...    : .rsrc section raw data
    """
    RSRC_VA = 0x1000
    RSRC_FILE_OFF = 0x200
    PE_OFF = 0x40
    OPT_HDR_SIZE = 0xe0  # PE32 standard optional header

    # ----- Build .rsrc section data -----
    # The resource tree is:
    #   Level 1 dir  (offset 0x00): 1 ID entry → res_type
    #   Level 2 dir  (offset 0x18): 1 ID entry → res_id
    #   Level 3 dir  (offset 0x30): 1 ID entry → language 0x409
    #   DATA_ENTRY   (offset 0x48): RVA → RSRC_VA + 0x58, Size → len(blob)
    #   Raw blob     (offset 0x58)
    BLOB_RSRC_OFF = 0x58

    def _dir(named: int, ids: int) -> bytes:
        return struct.pack("<IIHHHH", 0, 0, 0, 0, named, ids)  # 16 bytes

    rsrc = bytearray()
    rsrc += _dir(0, 1)                              # root dir @0x00
    rsrc += struct.pack("<II", res_type, 0x80000018)  # entry: type, subdir@0x18
    rsrc += _dir(0, 1)                              # name dir @0x18
    rsrc += struct.pack("<II", res_id, 0x80000030)  # entry: id, subdir@0x30
    rsrc += _dir(0, 1)                              # lang dir @0x30
    rsrc += struct.pack("<II", 0x409, 0x48)         # entry: lang, leaf@0x48
    blob_rva = RSRC_VA + BLOB_RSRC_OFF
    rsrc += struct.pack("<IIII", blob_rva, len(blob), 0, 0)  # DATA_ENTRY @0x48
    rsrc += blob                                    # raw data @0x58

    rsrc_size = len(rsrc)

    # ----- Assemble PE binary -----
    total_size = RSRC_FILE_OFF + rsrc_size
    buf = bytearray(total_size)

    # DOS header
    struct.pack_into("<H", buf, 0, 0x5A4D)      # e_magic = "MZ"
    struct.pack_into("<I", buf, 0x3C, PE_OFF)   # e_lfanew

    # PE signature @ 0x40
    buf[PE_OFF:PE_OFF + 4] = b"PE\x00\x00"

    # COFF header @ 0x44
    coff = PE_OFF + 4
    struct.pack_into("<H", buf, coff,      0x014C)        # Machine = i386
    struct.pack_into("<H", buf, coff + 2,  1)             # NumberOfSections
    struct.pack_into("<H", buf, coff + 16, OPT_HDR_SIZE)  # SizeOfOptionalHeader
    struct.pack_into("<H", buf, coff + 18, 0x0102)        # Characteristics

    # Optional header @ 0x58
    opt = PE_OFF + 24
    struct.pack_into("<H", buf, opt,        0x010B)         # Magic = PE32
    struct.pack_into("<I", buf, opt + 28,   0x00400000)     # ImageBase
    struct.pack_into("<I", buf, opt + 32,   0x1000)         # SectionAlignment
    struct.pack_into("<I", buf, opt + 36,   0x200)          # FileAlignment
    struct.pack_into("<I", buf, opt + 56,   0x10000)        # SizeOfImage
    struct.pack_into("<I", buf, opt + 60,   RSRC_FILE_OFF)  # SizeOfHeaders
    struct.pack_into("<I", buf, opt + 92,   16)             # NumberOfRvaAndSizes
    # DataDirectory[2] = Resource @ opt + 112
    struct.pack_into("<I", buf, opt + 112,  RSRC_VA)        # RVA
    struct.pack_into("<I", buf, opt + 116,  rsrc_size)      # Size

    # Section table @ 0x138  (PE_OFF + 24 + OPT_HDR_SIZE = 0x40 + 24 + 0xe0)
    sec = PE_OFF + 24 + OPT_HDR_SIZE
    buf[sec:sec + 8] = b".rsrc\x00\x00\x00"
    struct.pack_into("<I", buf, sec + 8,   rsrc_size)       # VirtualSize
    struct.pack_into("<I", buf, sec + 12,  RSRC_VA)         # VirtualAddress
    struct.pack_into("<I", buf, sec + 16,  rsrc_size)       # SizeOfRawData
    struct.pack_into("<I", buf, sec + 20,  RSRC_FILE_OFF)   # PointerToRawData

    # .rsrc raw data @ 0x200
    buf[RSRC_FILE_OFF:RSRC_FILE_OFF + rsrc_size] = rsrc

    return bytes(buf)


def _make_pe32_no_rsrc() -> bytes:
    """PE32 with ResourceDirectory RVA = 0 (no .rsrc section)."""
    return _make_pe32_rsrc(b"\x00\x00\x00\x00")[:0x200] + _make_pe32_rsrc(b"\x00\x00\x00\x00")[0x200:]


def _write_tmp(data: bytes, suffix: str = ".exe") -> str:
    fd, path = tempfile.mkstemp(suffix=suffix)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    return path


def _run_method(pe_bytes: bytes) -> list:
    path = _write_tmp(pe_bytes)
    try:
        return _ANALYZER._extract_pe_rcdata(path, pe_bytes, FLAG_PATTERN)
    finally:
        os.unlink(path)


def _run_analyze(pe_bytes: bytes, depth: str = "deep") -> list:
    path = _write_tmp(pe_bytes)
    try:
        return _ANALYZER.analyze(path, FLAG_PATTERN, depth, None)
    finally:
        os.unlink(path)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestPeRcdataExtraction(unittest.TestCase):

    def test_1_rcdata_blob_found(self):
        """RCDATA blob is detected in a well-formed PE32."""
        blob = b"Hello, RCDATA!"
        findings = _run_method(_make_pe32_rsrc(blob))
        rcdata = [f for f in findings if "RCDATA" in f.title]
        self.assertGreater(len(rcdata), 0, "Expected at least one RCDATA finding")

    def test_2_flag_in_rcdata_is_high_severity(self):
        """Flag pattern inside RCDATA blob → HIGH severity and flag_match=True."""
        blob = b"flag{hidden_in_rsrc}"
        findings = _run_method(_make_pe32_rsrc(blob))
        rcdata = [f for f in findings if "RCDATA" in f.title]
        self.assertTrue(rcdata, "No RCDATA finding emitted")
        f = rcdata[0]
        self.assertTrue(f.flag_match, "flag_match should be True")
        self.assertEqual(f.severity, "HIGH")

    def test_3_no_flag_rcdata_is_medium_severity(self):
        """Non-flag RCDATA blob → MEDIUM severity, flag_match=False."""
        blob = b"This is just some arbitrary binary data 1234"
        findings = _run_method(_make_pe32_rsrc(blob))
        rcdata = [f for f in findings if "RCDATA" in f.title]
        self.assertTrue(rcdata, "No RCDATA finding emitted")
        f = rcdata[0]
        self.assertFalse(f.flag_match)
        self.assertEqual(f.severity, "MEDIUM")

    def test_4_raw_hex_in_detail(self):
        """Finding.detail must contain raw_hex= token for re-dispatch."""
        blob = b"redispatch_me_1234"
        findings = _run_method(_make_pe32_rsrc(blob))
        rcdata = [f for f in findings if "RCDATA" in f.title]
        self.assertTrue(rcdata)
        self.assertIn("raw_hex=", rcdata[0].detail)
        # Verify the hex round-trips back to the original blob
        hex_match = re.search(r"raw_hex=([0-9a-f]+)", rcdata[0].detail)
        self.assertIsNotNone(hex_match)
        self.assertEqual(bytes.fromhex(hex_match.group(1)), blob)

    def test_5_non_rcdata_type_ignored(self):
        """Resource type != 10 (e.g. RT_STRING = 6) should not appear as RCDATA."""
        blob = b"string resource data here!"
        findings = _run_method(_make_pe32_rsrc(blob, res_type=6))
        rcdata = [f for f in findings if "RCDATA" in f.title]
        self.assertEqual(rcdata, [], "Non-RCDATA type should produce no RCDATA finding")

    def test_6_non_pe_binary_empty(self):
        """ELF binary → _extract_pe_rcdata returns empty list."""
        elf_bytes = b"\x7fELF" + b"\x00" * 60
        findings = _ANALYZER._extract_pe_rcdata("/fake/path.elf", elf_bytes, FLAG_PATTERN)
        self.assertEqual(findings, [])

    def test_7_pe_without_rsrc_empty(self):
        """PE32 with resource RVA=0 → empty findings."""
        pe = _make_pe32_rsrc(b"dummy data here")
        # Zero out DataDirectory[2] RVA (opt + 112 = 0x58 + 0x70 = 0xC8)
        pe_off = 0x40
        opt_off = pe_off + 24
        buf = bytearray(pe)
        struct.pack_into("<I", buf, opt_off + 112, 0)  # RVA = 0
        struct.pack_into("<I", buf, opt_off + 116, 0)  # Size = 0
        findings = _run_method(bytes(buf))
        rcdata = [f for f in findings if "RCDATA" in f.title]
        self.assertEqual(rcdata, [])

    def test_8_small_blob_skipped(self):
        """Blobs < 4 bytes are silently skipped."""
        blob = b"\xde\xad"  # 2 bytes
        findings = _run_method(_make_pe32_rsrc(blob))
        rcdata = [f for f in findings if "RCDATA" in f.title]
        self.assertEqual(rcdata, [], "Blob < 4 bytes should be skipped")

    def test_9_fast_mode_no_rcdata(self):
        """analyze() in fast mode must not call _extract_pe_rcdata."""
        blob = b"flag{should_not_be_found_in_fast_mode}"
        findings = _run_analyze(_make_pe32_rsrc(blob), depth="fast")
        rcdata = [f for f in findings if "RCDATA" in f.title]
        self.assertEqual(rcdata, [], "RCDATA extraction must be skipped in fast mode")

    def test_10_deep_mode_rcdata_present(self):
        """analyze() in deep mode emits RCDATA finding for a PE with .rsrc."""
        blob = b"some_resource_data_content_here"
        findings = _run_analyze(_make_pe32_rsrc(blob), depth="deep")
        rcdata = [f for f in findings if "RCDATA" in f.title]
        self.assertGreater(len(rcdata), 0, "RCDATA finding expected in deep mode")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def _run_suite() -> bool:
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(TestPeRcdataExtraction)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    return result.wasSuccessful()


if __name__ == "__main__":
    ok = _run_suite()
    sys.exit(0 if ok else 1)
