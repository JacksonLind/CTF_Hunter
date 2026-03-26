# Breathing Void — Network Forensics / Covert Timing Channel

**CTF:** EH4X  
**Category:** Network Forensics  
**Points:** 500  
**Author:** N0nchalantAc1d  
**Flag:** `EH4X{pc@p5_@re_of+en_mo5+1y_noi5e}`

---

## Challenge Overview

> *"1GB of dead vacuum. Can you find any life."*

| Field | Value |
|---|---|
| **File** | `Breathing_Void.tar` → `Breathing_Void.pcap` |
| **File size** | ~1 GB (1,146 MB pcapng) |
| **Total packets** | 4,198,284 (4,198,011 Ethernet + 273 Raw IPv4) |

The challenge provides a 1 GB tar archive containing a single pcapng file. Almost all traffic is noise — a covert timing channel is hidden inside a merged capture file containing deliberate decoy traffic.

---

## Initial Recon

### Extracting the Archive

```bash
tar -xzf Breathing_Void.tar
# Produces: Breathing_Void.pcap (pcapng format despite .pcap extension)
```

### capinfos — The Key Clue

```bash
capinfos Breathing_Void.pcap
```

The capture **comment** reveals everything:

```
Capture comment: File created by merging:
  File1: massive.pcap
  File2: decoy_trap.pcap
  File3: covert_timing_2.pcap

Number of interfaces in file: 3
  Interface #0: Ethernet (4,198,011 packets)  <- the noise
  Interface #1: Raw IPv4 (1 packet)           <- decoy
  Interface #2: Raw IPv4 (272 packets)        <- covert channel
```

Interface #2 (`covert_timing_2.pcap`) contains only **272 packets** — and its name makes the approach obvious.

### Why Normal Tools Caused Problems

Standard approaches like `strings`, `xxd`, or `tshark` display filters scan all 4.2 million packets before filtering. The correct approach is to extract the 272-packet interface directly using Python's raw binary parsing, bypassing tshark entirely.

---

## Extracting the Covert Channel

### Failed Approaches

- `grep -a "EH4X{"` — returned 0 matches. Flag is not stored in plaintext.
- `tshark -Y "frame.interface_id == 2"` — works but scans all 4.2M packets first.
- `editcap -F pcap` — fails due to multiple encapsulations (Ethernet + Raw IPv4).
- `tcpdump -r` — can't read pcapng format.

### Solution: Direct pcapng Binary Parsing

Parse the pcapng binary format directly in Python, reading only Enhanced Packet Blocks (type `0x00000006`) belonging to interface ID 2:

```python
import struct, sys

def parse_pcapng(filename):
    times = []
    with open(filename, 'rb') as f:
        data = f.read()
    pos = 0
    iface_tsresol = {}
    while pos < len(data):
        if pos + 8 > len(data): break
        bt = struct.unpack_from('<I', data, pos)[0]
        bl = struct.unpack_from('<I', data, pos+4)[0]
        if bl < 12 or pos + bl > len(data): break
        # Interface Description Block -> record timestamp resolution
        if bt == 0x00000001:
            iface_tsresol[len(iface_tsresol)] = 1e-6
        # Enhanced Packet Block -> extract timestamp if interface == 2
        elif bt == 0x00000006:
            iface_id = struct.unpack_from('<I', data, pos+8)[0]
            if iface_id == 2:
                ts_high = struct.unpack_from('<I', data, pos+12)[0]
                ts_low  = struct.unpack_from('<I', data, pos+16)[0]
                ts_raw  = (ts_high << 32) | ts_low
                times.append(ts_raw * iface_tsresol.get(iface_id, 1e-6))
        pos += bl
    return times

times = parse_pcapng('Breathing_Void.pcap')
print(f'Found {len(times)} covert packets', file=sys.stderr)
for i in range(1, len(times)):
    print(f'{times[i]-times[i-1]:.6f}')
```

**Output:** "Found 272 covert packets" — 271 inter-arrival time deltas written to `deltas.txt`.

---

## Decoding the Timing Channel

### Analysing the Deltas

Inspecting `deltas.txt` reveals only **two distinct values**:

```
0.100000  <- 'long' gap  = bit 1
0.010000  <- 'short' gap = bit 0
```

| Delta | Bit |
|---|---|
| 0.100000s (100ms) | 1 |
| 0.010000s (10ms) | 0 |

### Bit Alignment — The Framing Bit

271 bits is not divisible by 8. **Prepending a single `0` bit** (treating the first delta as a framing marker) produces 272 bits = **34 valid ASCII bytes**.

### Decoding Script

```python
deltas = [float(x) for x in open('deltas.txt')]

# Map to bits: 0.1s = 1, 0.01s = 0
bits = [1 if d > 0.05 else 0 for d in deltas]

# Prepend framing bit 0 to align to byte boundary
bits = [0] + bits

# Decode MSB-first, 8 bits per character
result = ''
for i in range(0, len(bits), 8):
    byte = bits[i:i+8]
    if len(byte) == 8:
        val = int(''.join(map(str, byte)), 2)
        result += chr(val) if 32 <= val < 127 else f'[{val}]'

print(result)
# Output: EH4X{pc@p5_@re_of+en_mo5+1y_noi5e}
```

### Decoded Bitstream

```
01000101 01001000 00110100 01011000  ->  E H 4 X
01111011 01110000 01100011 01000000  ->  { p c @
01110000 00110101 01011111 01000000  ->  p 5 _ @
01110010 01100101 01011111 01101111  ->  r e _ o
01100110 00101011 01100101 01101110  ->  f + e n
00101111 01101101 01101111 01110011  ->  _ m o s
00101011 00110001 01111001 01011111  ->  + 1 y _
01101110 01101111 01101001 00110101  ->  n o i 5
01100101 01111101                   ->  e }
```

---

## Summary

| Stat | Value |
|---|---|
| Signal packets | 272 out of 4,198,284 total (0.006% of traffic) |
| Encoding | Inter-packet delay: 100ms = 1, 10ms = 0 |
| Bit order | MSB first, 8 bits per character |
| Framing | 1 leading sync bit (prepend `0` to align) |
| Message | `EH4X{pc@p5_@re_of+en_mo5+1y_noi5e}` |

The solve path:
1. `capinfos` reveals the pcapng was built by merging three files — the comment names them.
2. Interface #2 holds only 272 packets. The filename `covert_timing_2.pcap` confirms the target.
3. Direct pcapng binary parsing in Python extracts only the 272 EPBs without scanning the full 1GB.
4. Inter-arrival deltas are exactly 0.100s or 0.010s — binary 1 and 0.
5. 271 deltas is not byte-aligned; prepending a `0` framing bit yields 272 bits = 34 ASCII chars.
6. Standard 8-bit MSB-first ASCII decoding produces the flag.

---

**Flag:** `EH4X{pc@p5_@re_of+en_mo5+1y_noi5e}`  
*"pcaps are often mostly noise"*
