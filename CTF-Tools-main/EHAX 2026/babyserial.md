# babyserial — Hardware / Logic Analysis

**CTF:** EH4X  
**Category:** Hardware / Logic Analyzer / Forensics  
**Points:** 50  
**Author:** Anonimbus  
**Flag:** `EH4X{...}` *(contained in decoded PNG image)*

---

## Challenge Overview

> *"Joe was trying to sniff the data over a serial communication. Was he successful?"*

We were given a `.sal` file — a Saleae Logic 2 capture — and had to extract the transmitted data from the raw digital signal.

---

## Tools Used

- Python 3 — custom signal parser and UART decoder
- Saleae Logic 2 — to inspect the `.sal` file format and read `meta.json`
- Standard library: `struct`, `base64`, `collections`

---

## Reconnaissance

### Unpacking the .sal File

A `.sal` file is simply a ZIP archive. Extracting it reveals:

```
meta.json          <- capture metadata
digital-0.bin      <- Channel 0 data (496 KB — all the data)
digital-1.bin      <- Channel 1 data (44 bytes — empty)
digital-2.bin ... digital-7.bin  <- all empty
```

Channels 1–7 contained only the Saleae header with zero transitions. The signal of interest was entirely on **Channel 0**.

### Reading meta.json

Key fields extracted:

```json
"name": "babyserial"
"sampleRate": { "digital": 1000000 }  // 1 MHz sample rate
"enabledChannels": [0, 1, 2, 3, 4, 5, 6, 7]
```

The **1 MHz sample rate** is critical — each timestamp represents microsecond-precision data.

### Saleae Binary Format

Each `digital-N.bin` follows a fixed header structure:

```
Bytes  0– 7 : Magic '<SALEAE>'
Bytes  8–11 : Version (uint32 LE)
Bytes 12–15 : Type (0 = Digital)
Bytes 16–19 : Initial state (0 or 1)
Bytes 20–27 : Begin time (double)
Bytes 28–35 : End time (double)
Bytes 36–43 : Num transitions (uint64)
Bytes 44+   : Transition timestamps (array of doubles)
```

Each timestamp marks the moment the signal changed state.

---

## Signal Analysis

### Measuring Pulse Widths

Computing time deltas between consecutive transitions revealed:

```
~8–9 µs  (1×) — 40,798 occurrences
~17–18 µs (2×) — 13,491 occurrences
~26–27 µs (3×) —  4,627 occurrences
~35 µs   (4×) —  2,047 occurrences
~43–44 µs (5×) —  1,046 occurrences
```

All intervals are clean multiples of **~8.68 µs**, which is the bit period for 115200 baud:

```
1 / 115200 ≈ 8.68 µs
```

### Protocol Identification: UART 115200 8N1

- Idle state HIGH
- Start bit = falling edge (HIGH → LOW)
- 8 data bits, LSB first
- Stop bit = HIGH
- No parity bit (8N1)

---

## UART Decoding

### Decoder Implementation

1. Parse the Saleae binary header to extract the initial state and all transition timestamps.
2. Reconstruct the signal as a list of `(timestamp, state)` pairs.
3. Scan for falling edges (HIGH→LOW transitions) — these are UART start bits.
4. For each start bit, sample 8 data bits at the centre of each bit period (`start + 1.5×bp`, `2.5×bp`, ... `8.5×bp`).
5. Validate the stop bit (must be HIGH), then append the decoded byte.

### Decoder Code

```python
bp = 1.0 / 115200  # bit period in seconds
i = 1
while i < len(states) - 1:
    ts, s = states[i]
    prev_s = states[i-1][1]
    if prev_s == 1 and s == 0:  # falling edge = start bit
        start_t = ts
        byte_val = 0
        for bit in range(8):
            sample_t = start_t + bp * (1.5 + bit)
            b = get_state(sample_t)
            byte_val |= (b << bit)  # LSB first
        stop_t = start_t + bp * 9.5
        if get_state(stop_t) == 1:  # valid stop bit
            chars.append(byte_val)
        end_t = start_t + bp * 10
        while states[i][0] < end_t:
            i += 1
        continue
    i += 1
```

### Result

The decoder produced **9,508 bytes** with zero framing errors. The first bytes:

```
iVBORw0KGgoAAAANSUhEUgAAAqsAAAGACAMAAAC9Rtur...
```

`iVBORw0KGgo` is the base64 encoding of the PNG magic bytes `\x89PNG\r\n\x1a\n` — the transmitted data was a **PNG image encoded in base64 over UART**.

---

## Extracting the Flag

### Base64 Decode

```python
import base64
clean = ''.join(c for c in text if c in BASE64_CHARS)
img_bytes = base64.b64decode(clean)  # -> 6946 bytes
# Magic: b'\x89PNG\r\n\x1a\n' confirmed PNG
```

The resulting **6,946-byte PNG image** was saved and opened, revealing the flag.

---

## Key Takeaways

- **`.sal` files** are ZIP archives — always unzip and check `meta.json` first for sample rate and channel info.
- **Saleae binary format** stores signal transitions as an array of double-precision timestamps, not raw samples.
- **Baud rate identification**: compute inter-transition intervals, find the minimum — this is one bit period. `8.68 µs → 115200 baud`.
- **Sampling jitter**: at 1 MHz capturing 115200 baud, each bit alternates between 8 and 9 samples — expect ±1 µs noise.
- **UART 8N1 decoding**: sample at centre of each bit period (`start_edge + 1.5×bp`, `2.5×bp` ... `8.5×bp`), LSB first.
- **Data-in-data**: the flag was a PNG hidden inside base64, transmitted as plaintext over UART — check all encodings on decoded output.

---

**Flag:** contained in the decoded PNG image
