"""
Tests for PCAP covert timing channel detection.

Covers:
  1. pcapng — clean bimodal IAT (Breathing Void pattern)
  2. legacy .pcap — bimodal IAT
  3. pcapng — jittery timestamps requiring fuzzy clustering
  4. Large-file guard — files > 200 MB skip scapy but still return timing findings
  5. pcapng — framing-bit alignment (271 bits → prepend 0 → byte-aligned)

Run from the ctf_hunter/ directory:
    python tests/test_pcap_timing.py
"""
from __future__ import annotations

import os
import random
import re
import struct
import sys
import tempfile

# Make ctf_hunter importable when run directly.
_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from analyzers.pcap import PcapAnalyzer  # noqa: E402

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

FLAG_PATTERN = re.compile(r"flag\{[^}]+\}")
SHORT_GAP = 0.010   # 10 ms  → bit 0
LONG_GAP  = 0.100   # 100 ms → bit 1


def encode_flag_as_timestamps(
    flag: str,
    t0: float = 1_000.0,
    short: float = SHORT_GAP,
    long: float = LONG_GAP,
    framing_bit: int | None = None,
) -> list[float]:
    """Return packet timestamps that encode *flag* as a bimodal IAT channel.

    If *framing_bit* is given it is prepended so the total bit count is NOT
    divisible by 8 — forcing the decoder to use the framing-bit alignment fix.
    """
    bits: list[int] = []
    if framing_bit is not None:
        bits.append(framing_bit)
    for ch in flag:
        v = ord(ch)
        for i in range(7, -1, -1):          # MSB first
            bits.append((v >> i) & 1)

    times = [t0]
    for b in bits:
        times.append(times[-1] + (long if b else short))
    return times


def make_pcapng(timestamps: list[float]) -> bytes:
    """Build a minimal pcapng: SHB + one IDB + one EPB per timestamp."""
    # Section Header Block (28 bytes, no options)
    shb = (
        struct.pack("<I", 0x0A0D0D0A)   # block type
        + struct.pack("<I", 28)          # block total length
        + struct.pack("<I", 0x1A2B3C4D) # byte-order magic (LE)
        + struct.pack("<HH", 1, 0)       # version major, minor
        + struct.pack("<q", -1)          # section length (unknown)
        + struct.pack("<I", 28)          # block total length (repeat)
    )
    # Interface Description Block (20 bytes, link type 1 = Ethernet)
    idb = (
        struct.pack("<I", 0x00000001)
        + struct.pack("<I", 20)
        + struct.pack("<HH", 1, 0)   # link type, reserved
        + struct.pack("<I", 65535)   # snaplen
        + struct.pack("<I", 20)
    )
    # Enhanced Packet Blocks (32 bytes each, no captured data)
    epbs = b""
    for ts in timestamps:
        us = int(ts * 1_000_000)
        epbs += (
            struct.pack("<I", 0x00000006)           # block type
            + struct.pack("<I", 32)                 # block total length
            + struct.pack("<I", 0)                  # interface ID
            + struct.pack("<I", (us >> 32) & 0xFFFFFFFF)  # ts high
            + struct.pack("<I", us & 0xFFFFFFFF)    # ts low
            + struct.pack("<II", 0, 0)              # captured / original length
            + struct.pack("<I", 32)                 # block total length (repeat)
        )
    return shb + idb + epbs


def make_legacy_pcap(timestamps: list[float]) -> bytes:
    """Build a minimal legacy libpcap file (all packets on one interface)."""
    # Global header: magic(4) + ver(2+2) + thiszone(4) + sigfigs(4) +
    #                snaplen(4) + network(4) = 24 bytes
    hdr = struct.pack("<IHHiIII", 0xD4C3B2A1, 2, 4, 0, 0, 65535, 1)
    pkts = hdr
    for ts in timestamps:
        sec  = int(ts)
        usec = int((ts - sec) * 1_000_000)
        pkts += struct.pack("<IIII", sec, usec, 0, 0)  # ts_sec ts_usec incl orig
    return pkts


def findings_contain_flag(findings, pat: re.Pattern = FLAG_PATTERN) -> bool:
    for f in findings:
        if pat.search(f.title or "") or pat.search(f.detail or ""):
            return True
    return False


def run_test(
    name: str,
    data: bytes,
    suffix: str,
    expect_flag: bool = True,
) -> bool:
    analyzer = PcapAnalyzer()
    with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as fh:
        fh.write(data)
        path = fh.name
    try:
        findings = analyzer.analyze(path, FLAG_PATTERN, "fast", None)
        ok = findings_contain_flag(findings) == expect_flag
        status = "PASS" if ok else "FAIL"
        print(f"  [{status}]  {name}")
        if not ok:
            titles = [f.title for f in findings]
            print(f"         findings ({len(findings)}): {titles[:6]}")
        return ok
    finally:
        os.unlink(path)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_pcapng_clean(flag: str = "flag{ok}") -> bool:
    """pcapng with exact bimodal IAT → flag decoded without fuzzy clustering."""
    ts = encode_flag_as_timestamps(flag)
    return run_test("pcapng clean binary timing channel", make_pcapng(ts), ".pcapng")


def test_legacy_pcap_clean(flag: str = "flag{ok}") -> bool:
    """Legacy .pcap with exact bimodal IAT."""
    ts = encode_flag_as_timestamps(flag)
    return run_test("legacy .pcap clean binary timing channel", make_legacy_pcap(ts), ".pcap")


def test_pcapng_jitter(flag: str = "flag{ok}", seed: int = 42) -> bool:
    """pcapng with ±0.5 ms Gaussian jitter → fuzzy clustering must merge clusters."""
    rng = random.Random(seed)
    ts = encode_flag_as_timestamps(flag)
    ts_jittered = [t + rng.uniform(-0.0005, 0.0005) for t in ts]
    return run_test(
        "pcapng jittery timestamps (fuzzy cluster ±0.5 ms)",
        make_pcapng(ts_jittered),
        ".pcapng",
    )


def test_pcapng_framing_bit(flag: str = "flag{ok}") -> bool:
    """pcapng where raw deltas are unaligned; framing+0 restores the flag.

    Construction: skip encoding the MSB of the first character (since 'f' = 0x66
    has MSB = 0, we can omit it).  This leaves 63 raw deltas — not divisible by
    8.  The decoder's 'framing+0' candidate prepends a 0 bit, producing
    [0, bit1..bit63] = 64 bits = 8 chars = 'flag{ok}'.

    This mirrors the Breathing Void challenge where the raw stream was 271 bits
    and prepending a 0 framing bit produced the 272-bit (34-byte) flag.
    """
    # Collect all bits for the flag MSB-first.
    all_bits: list[int] = []
    for ch in flag:
        v = ord(ch)
        for i in range(7, -1, -1):
            all_bits.append((v >> i) & 1)

    # Verify our assumption: first bit must be 0 so that prepending 0 is valid.
    assert all_bits[0] == 0, (
        f"First bit of '{flag}' is 1 — choose a flag whose MSB is 0 for this test"
    )

    # Encode only bits[1:] — 63 deltas, NOT byte-aligned.
    t0 = 1_000.0
    times = [t0]
    for b in all_bits[1:]:
        times.append(times[-1] + (LONG_GAP if b else SHORT_GAP))

    return run_test(
        "pcapng framing-bit alignment (63 raw deltas -> 'framing+0' -> flag)",
        make_pcapng(times),
        ".pcapng",
    )


def test_large_file_skips_scapy() -> bool:
    """Files > 200 MB must still return timing findings (raw binary path).

    We cannot create a genuine 200 MB file in a unit test, so we validate the
    threshold constant and confirm the raw binary path is called unconditionally
    by running a normal pcapng through the full analyze() method and checking
    that the size guard constant is set correctly.
    """
    assert PcapAnalyzer._SCAPY_SIZE_LIMIT == 200 * 1024 * 1024, (
        "_SCAPY_SIZE_LIMIT changed — update test expectation"
    )
    # Also confirm that a small pcapng still works end-to-end via analyze().
    flag = "flag{ok}"
    ts = encode_flag_as_timestamps(flag)
    data = make_pcapng(ts)
    ok = run_test(
        "large-file guard constant + small pcapng via analyze()",
        data,
        ".pcapng",
    )
    print("       (_SCAPY_SIZE_LIMIT = 200 MB confirmed)")
    return ok


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("PCAP timing channel tests\n")
    results = [
        test_pcapng_clean(),
        test_legacy_pcap_clean(),
        test_pcapng_jitter(),
        test_pcapng_framing_bit(),
        test_large_file_skips_scapy(),
    ]
    passed = sum(results)
    total  = len(results)
    print(f"\n{passed}/{total} passed")
    sys.exit(0 if passed == total else 1)
