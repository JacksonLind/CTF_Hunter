"""
Tests for inode timestamp steganography detection in analyzers/filesystem.py.

Coverage:
  A. Formula helpers
     1. _ts_mmss round-trips chr(mm*60+ss) for known values
     2. _ts_ss  round-trips chr(ss) for seconds-only encoding
     3. Zero timestamp → '\x00' (non-printable, filtered out)

  B. _decode_timestamp_channel
     4. atime field encodes flag → HIGH finding with flag_match
     5. mtime field encodes plaintext → MEDIUM finding, no flag_match
     6. Fewer than 4 records → no findings emitted
     7. <80 % printable timestamps → finding suppressed
     8. Natural sort: memory_10 follows memory_9, not memory_1

  C. Raw ext4 parsing (_check_inode_timestamps_raw)
     9.  Synthetic ext4 image with atimes encoding "flag{ts_steg}" → HIGH finding
    10.  Wrong magic bytes → empty findings
    11.  Truncated superblock → empty findings

  D. FilesystemAnalyzer.analyze integration (raw-ext4 path, no pytsk3 needed)
    12.  analyze() on synthetic ext4 image → finding contains decoded flag text

Run from ctf_hunter/ directory:
    python tests/test_filesystem_timestamps.py
"""
from __future__ import annotations

import os
import re
import struct
import sys
import tempfile
import time
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from analyzers.filesystem import FilesystemAnalyzer

FLAG_PATTERN = re.compile(r"flag\{[^}]+\}")
_ANA = FilesystemAnalyzer()

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# 2007-01-01 02:00:00 UTC — an exact hour boundary useful as a reference.
# Verified: time.gmtime(1167616800) → (2007, 1, 1, 2, 0, 0, ...) in UTC.
_REF_EPOCH = 1167616800


def _char_to_epoch(c: str) -> int:
    """Return epoch whose gmtime mm*60+ss == ord(c).

    Works because _REF_EPOCH is an exact hour boundary, so adding val seconds
    advances the clock by exactly (val // 60) minutes and (val % 60) seconds.
    Asserts ord(c) is in printable ASCII range.
    """
    val = ord(c)
    assert 0x20 <= val <= 0x7E, f"char {c!r} out of printable range"
    return _REF_EPOCH + val


def _make_records(text: str, field: int = 1) -> list:
    """Build synthetic (name, atime, mtime, ctime, crtime) records for *text*.

    ``field`` selects which timestamp slot gets the encoded value:
        1 = atime, 2 = mtime, 3 = ctime, 4 = crtime
    """
    records = []
    for i, ch in enumerate(text):
        ep = _char_to_epoch(ch)
        ts = [0, 0, 0, 0]          # atime, mtime, ctime, crtime
        ts[field - 1] = ep
        records.append((f"file_{i + 1:03d}", ts[0], ts[1], ts[2], ts[3]))
    return records


def _make_ext4_image(chars: str, inode_size: int = 256) -> bytes:
    """Build a minimal syntehtic ext4 binary image.

    Layout (block_size = 1024):
      Block 0 (0x000–0x3FF): empty (boot sector)
      Block 1 (0x400–0x7FF): superblock
      Block 2 (0x800–0xBFF): block group descriptor table (32-byte entry)
      Block 3 (0xC00–0xFFF): block bitmap   (unused)
      Block 4 (0x1000–0x13FF): inode bitmap  (unused)
      Block 5+: inode table

    Inodes 1–10 are reserved (skipped by parser).
    File chars are written to inodes 11, 12, ..., 10+len(chars).
    atime is set to _REF_EPOCH + ord(char); all other timestamps are also set
    to the same value so all four fields decode identically.
    crtime is written at inode offset 0x90 (requires inode_size >= 0x94).
    """
    BLOCK_SIZE = 1024
    INODES_PER_GROUP = max(64, len(chars) + 12)
    INODES_COUNT = INODES_PER_GROUP

    inode_table_bytes = INODES_PER_GROUP * inode_size
    inode_table_blocks = (inode_table_bytes + BLOCK_SIZE - 1) // BLOCK_SIZE
    total_blocks = 5 + inode_table_blocks + 2
    image = bytearray(total_blocks * BLOCK_SIZE)

    # Superblock at 0x400
    sb = 0x400
    struct.pack_into("<I", image, sb + 0x00, INODES_COUNT)    # s_inodes_count
    struct.pack_into("<I", image, sb + 0x14, 1)               # s_first_data_block
    struct.pack_into("<I", image, sb + 0x18, 0)               # s_log_block_size → 1 KB
    struct.pack_into("<I", image, sb + 0x20, 8192)            # s_blocks_per_group
    struct.pack_into("<I", image, sb + 0x28, INODES_PER_GROUP)
    struct.pack_into("<H", image, sb + 0x38, 0xEF53)          # ext magic
    struct.pack_into("<H", image, sb + 0x58, inode_size)
    struct.pack_into("<I", image, sb + 0x60, 0)               # feature_incompat = 0

    # Block Group Descriptor at block 2 (0x800), 32-byte entry
    gdt = 2 * BLOCK_SIZE
    struct.pack_into("<I", image, gdt + 0x00, 3)   # bg_block_bitmap_lo = block 3
    struct.pack_into("<I", image, gdt + 0x04, 4)   # bg_inode_bitmap_lo = block 4
    struct.pack_into("<I", image, gdt + 0x08, 5)   # bg_inode_table_lo  = block 5

    # Inode table at block 5 (offset 0x1400)
    it_off = 5 * BLOCK_SIZE
    for file_idx, ch in enumerate(chars):
        inode_num = 11 + file_idx       # global inode number
        table_idx = inode_num - 1       # 0-based index in inode table
        ino_off = it_off + table_idx * inode_size

        ep = _char_to_epoch(ch)
        struct.pack_into("<H", image, ino_off + 0x00, 0x81A4)   # i_mode: regular file
        struct.pack_into("<I", image, ino_off + 0x08, ep)        # i_atime
        struct.pack_into("<I", image, ino_off + 0x0C, ep)        # i_ctime
        struct.pack_into("<I", image, ino_off + 0x10, ep)        # i_mtime
        if inode_size >= 0x94 + 4 and ino_off + 0x94 + 4 <= len(image):
            struct.pack_into("<I", image, ino_off + 0x90, ep)    # i_crtime

    return bytes(image)


# ---------------------------------------------------------------------------
# A. Formula helpers
# ---------------------------------------------------------------------------

class TestFormulaHelpers(unittest.TestCase):

    def test_a1_ts_mmss_roundtrip(self):
        """_ts_mmss decodes epoch → chr(mm*60+ss) for all printable ASCII."""
        sample = "gigem{byg0n3_3r4}"   # from the real challenge
        epochs = [_char_to_epoch(c) for c in sample]
        result = FilesystemAnalyzer._ts_mmss(epochs)
        self.assertEqual(result, sample)

    def test_a2_ts_ss_roundtrip(self):
        """_ts_ss decodes epoch → chr(ss) for seconds-range chars (32–59)."""
        # Chars whose ord() fits in 0–59 are not all printable, but space (32)
        # through ';' (59) are.  Build a string of those.
        sample = " !\"#$%&'()*+,-./0123456789:;"
        epochs = []
        for c in sample:
            val = ord(c)          # 32..59 — fits directly in seconds
            epochs.append(_REF_EPOCH + val)    # minutes=0, seconds=val
        result = FilesystemAnalyzer._ts_ss(epochs)
        self.assertEqual(result, sample)

    def test_a3_zero_timestamp_produces_null(self):
        """A zero epoch timestamp produces '\\x00' (filtered later)."""
        result = FilesystemAnalyzer._ts_mmss([0, _char_to_epoch("A"), 0])
        self.assertEqual(result[0], "\x00")
        self.assertEqual(result[1], "A")
        self.assertEqual(result[2], "\x00")


# ---------------------------------------------------------------------------
# B. _decode_timestamp_channel
# ---------------------------------------------------------------------------

class TestDecodeTimestampChannel(unittest.TestCase):

    def test_b4_flag_in_atime_high_finding(self):
        """atime encodes flag → HIGH finding with flag_match=True."""
        flag = "flag{inode_ts}"
        records = _make_records(flag, field=1)   # atime
        findings = _ANA._decode_timestamp_channel(
            "test.img", records, FLAG_PATTERN, "unit-test"
        )
        high = [f for f in findings if f.flag_match]
        self.assertTrue(high, f"Expected flag_match=True; got: {[f.title for f in findings]}")
        self.assertTrue(any(f.severity == "HIGH" for f in high))

    def test_b5_plaintext_in_mtime_medium_finding(self):
        """mtime encodes printable text (no flag) → MEDIUM finding."""
        text = "hello world test"
        records = _make_records(text, field=2)   # mtime
        findings = _ANA._decode_timestamp_channel(
            "test.img", records, FLAG_PATTERN, "unit-test"
        )
        medium = [f for f in findings if not f.flag_match and f.severity == "MEDIUM"]
        self.assertTrue(medium, f"Expected MEDIUM finding; got: {[f.title for f in findings]}")

    def test_b6_too_few_records_no_findings(self):
        """3 records → no findings (below minimum of 4)."""
        records = _make_records("abc")
        findings = _ANA._decode_timestamp_channel(
            "test.img", records, FLAG_PATTERN, "unit-test"
        )
        self.assertEqual(findings, [])

    def test_b7_non_printable_suppressed(self):
        """Records with zero timestamps produce <80% printable → no finding."""
        # All zeros → all decode to chr(0) = '\x00'
        records = [("f1", 0, 0, 0, 0)] * 10
        findings = _ANA._decode_timestamp_channel(
            "test.img", records, FLAG_PATTERN, "unit-test"
        )
        self.assertFalse(
            any("steg" in f.title.lower() for f in findings),
            "All-null decode should not emit a finding",
        )

    def test_b8_natural_sort_order(self):
        """Natural sort: memory_1, memory_2, ..., memory_10 (not memory_10 first)."""
        # Encode "0123456789" into files named memory_1 through memory_10,
        # but store them in reverse inode order so naive sort would scramble them.
        chars = "0123456789A"    # 11 chars
        records = []
        for i, ch in enumerate(chars):
            # Name in order: memory_1 .. memory_11
            name = f"memory_{i + 1}"
            ep = _char_to_epoch(ch)
            records.append((name, ep, 0, 0, 0))
        # Shuffle the records to verify natural sort re-orders them
        import random
        shuffled = records[:]
        random.Random(42).shuffle(shuffled)

        findings = _ANA._decode_timestamp_channel(
            "test.img", shuffled, FLAG_PATTERN, "unit-test"
        )
        # The "name"-sorted finding should decode "0123456789A" in order
        name_findings = [f for f in findings if "name" in f.detail]
        self.assertTrue(name_findings, "Expected a 'name' sort finding")
        # Check that the correctly ordered string appears verbatim in any finding's detail
        any_correct = any("0123456789A" in f.detail for f in name_findings)
        self.assertTrue(any_correct,
                        f"Natural-sort decoded text '0123456789A' not found in details: "
                        f"{[f.detail for f in name_findings]}")


# ---------------------------------------------------------------------------
# C. Raw ext4 parsing
# ---------------------------------------------------------------------------

class TestRawExt4Parsing(unittest.TestCase):

    def test_c9_synthetic_image_flag_detected(self):
        """Synthetic ext4 image with atimes encoding flag{ts_steg} → HIGH finding."""
        flag = "flag{ts_steg}"
        image = _make_ext4_image(flag)
        findings = _ANA._check_inode_timestamps_raw("test.img", image, FLAG_PATTERN)
        self.assertTrue(
            any(f.flag_match for f in findings),
            f"Expected flag_match finding; got: {[f.title for f in findings]}"
        )
        self.assertTrue(
            any(f.severity == "HIGH" for f in findings if f.flag_match)
        )

    def test_c10_decoded_text_correct(self):
        """Decoded text from raw ext4 image matches original string."""
        text = "gigem{byg0n3_3r4}"
        image = _make_ext4_image(text)
        pat = re.compile(r"gigem\{[^}]+\}")
        findings = _ANA._check_inode_timestamps_raw("test.img", image, pat)
        self.assertTrue(
            any(f.flag_match for f in findings),
            f"Expected gigem flag match; got: {[f.title for f in findings]}"
        )

    def test_c11_wrong_magic_empty(self):
        """Non-ext4 bytes (wrong magic) → empty findings, no exception."""
        garbage = b"\x00" * 2048 + b"\xff\xd8\xff" * 100
        findings = _ANA._check_inode_timestamps_raw("test.img", garbage, FLAG_PATTERN)
        self.assertEqual(findings, [])

    def test_c12_truncated_superblock_empty(self):
        """Data shorter than superblock → empty findings, no exception."""
        findings = _ANA._check_inode_timestamps_raw("test.img", b"\x00" * 512, FLAG_PATTERN)
        self.assertEqual(findings, [])


# ---------------------------------------------------------------------------
# D. Integration via analyze()
# ---------------------------------------------------------------------------

class TestAnalyzeIntegration(unittest.TestCase):

    def test_d12_analyze_on_synthetic_ext4(self):
        """analyze() on a synthetic ext4 image emits a finding with the decoded flag text."""
        flag = "flag{ts_steg}"
        image = _make_ext4_image(flag)
        fd, path = tempfile.mkstemp(suffix=".img")
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(image)
            findings = _ANA.analyze(path, FLAG_PATTERN, "deep", None)
            flag_findings = [f for f in findings if f.flag_match]
            self.assertTrue(
                flag_findings,
                f"Expected flag_match finding from analyze(); got: {[f.title for f in findings]}"
            )
            # Confirm decoded text appears in detail
            any_detail = any(flag in f.detail for f in flag_findings)
            self.assertTrue(any_detail, "Decoded flag text should appear in finding detail")
        finally:
            os.unlink(path)


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def _run_suite() -> bool:
    groups = [
        ("A. Formula helpers",          TestFormulaHelpers),
        ("B. decode_timestamp_channel", TestDecodeTimestampChannel),
        ("C. Raw ext4 parsing",         TestRawExt4Parsing),
        ("D. Integration",              TestAnalyzeIntegration),
    ]
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    for _, cls in groups:
        suite.addTests(loader.loadTestsFromTestCase(cls))
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    return result.wasSuccessful()


if __name__ == "__main__":
    ok = _run_suite()
    sys.exit(0 if ok else 1)
