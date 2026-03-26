# Challenge 7 — Reverse Engineering Writeup

**Category:** Rev
**Flag:** `gigem{this_will_be_the_flag_for_challenge_7}`

---

## Overview

`challenge7` is a stripped 64-bit PIE ELF binary with a custom JIT-based flag checker. It reads a flag from stdin, builds machine code dynamically in an RWX mmap region, then executes that code to verify the input. Anti-debugging measures (TracerPid check, `getenv("LD_PRELOAD")`) guard against easy dynamic analysis.

---

## Recon

```
file challenge7
# ELF 64-bit LSB pie executable, x86-64, stripped
checksec --file=challenge7
# PIE, NX, no canary, partial RELRO
strings -n 8 challenge7 | grep -iE 'gigem|flag|correct|wrong'
# "correct", "wrong" visible — binary is a keygen-style checker
```

---

## Architecture

The binary has four major components:

### 1. Anti-Debug
- Reads `/proc/self/status` and checks `TracerPid`
- Calls `getenv("LD_PRELOAD")` and exits if set
- Both bypassed with an LD_PRELOAD hook (`hook2.so`) that fakes `/proc/self/status` and returns NULL for `LD_PRELOAD`

### 2. Integrity Key (Key = 0)
The binary computes `SHA-256(.text section)` at runtime and XORs it with 32 bytes stored at `[0x106e0]` to produce a 32-byte key. Analysis showed the XOR constants at `[0x106e0]` are **identical** to `SHA-256(.text)`, so the key is always 32 zero bytes regardless of the binary's content.

```python
sha256_text = hashlib.sha256(text_section_bytes).digest()
xor_constants = data[0x106e0:0x10700]  # == sha256_text
key = bytes(a ^ b for a, b in zip(sha256_text, xor_constants))
# key = b'\x00' * 32
```

### 3. State Machine (0x4240)
A 952-entry table drives the program's control flow. Each 52-byte entry:

| Offset | Size | Field |
|--------|------|-------|
| 0x00 | 32 B | Expected SHA-256 hash |
| 0x20 | 4 B | Dispatch type (`field_20`, 0–5) |
| 0x24 | 4 B | `mmap_offset` |
| 0x28 | 4 B | `entry_type` |
| 0x2c | 4 B | `next_state` (new counter) |
| 0x30 | 4 B | `data_table_idx` |

At each step, the binary computes `SHA-256(mmap_bytes || counter_bytes || key_bytes)` and finds the matching entry. Dispatch on `field_20`:
- **0–3:** State machine navigation / JIT byte writing
- **4:** Call the JIT function with the user's flag
- **5+:** Invalid → fail

### 4. JIT Code Generation
Function `0x2fa0` builds machine code into the RWX mmap region (0x1f60 bytes) by XORing raw data table bytes with the current SHA-256 context message buffer. Since key = 0, the SHA-256 context message buffer is all zeros, so **JIT bytes = raw data table bytes** (XOR identity). The JIT code grows downward from offset `0xfb0`, ending at `0xeeb` after all entries are processed.

---

## Capturing the JIT Code

An LD_PRELOAD hook (`hook2.so`) intercepted `mmap` to record the RWX region's base address, then dumped its contents at `munmap` time:

```c
void *mmap(void *addr, size_t length, int prot, ...) {
    void *ret = real_mmap(...);
    if (prot == (PROT_READ|PROT_WRITE|PROT_EXEC) && length == 0x1f60)
        jit_base = ret;
    return ret;
}
int munmap(void *addr, size_t length) {
    if (addr == jit_base) {
        FILE *f = fopen("/tmp/jit_dump.bin", "wb");
        fwrite(jit_base, 1, jit_size, f); fclose(f);
    }
    return real_munmap(addr, length);
}
```

```bash
LD_PRELOAD=./hook2.so ./challenge7 <<< "gigem{aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa}"
# dumps /tmp/jit_dump.bin (8032 bytes)
```

The JIT code occupied bytes `0xeeb–0x117a` (656 bytes) of the dump.

---

## Reversing the JIT Function

Disassembling `jit_code.bin` (entry at offset 0) revealed a flag validator with this signature:

```c
int jit_check(const char *flag, size_t len, uint32_t counter, void *ctx);
// returns 1 = correct, 0 = wrong
```

### Format Check (offset 0x200)
For a 44-character flag, it verifies the `gigem{...}` wrapper:
```
flag[0..5]  == "gigem{"
flag[43]    == '}'
len         == 44
```

### Rolling Hash Loop (offsets 0x70–0x173)
Processes `flag[6]` through `flag[42]` (37 characters). Per-iteration:

```python
# r9 update (Fibonacci-like mixing)
eax = (r9 + r11 - 0x61c88647) & 0xffffffff
r9  = rol32(eax, 5) ^ ror32(eax, 3)

# eax2: hash of position + state + flag char
eax2 = (17*i ^ r9 ^ (r9>>8) ^ c + (r9>>16) + ebx) & 0xff

# key byte from embedded table (R14_TABLE)
key_byte = R14_TABLE[i//8] >> ((i%8)*8) & 0xff

# validity + key check accumulate into ebp
r10d = (key_byte ^ eax2) | (0 if char_is_valid else 1)
ebp |= r10d

# edx update
esi  = rol32(i ^ eax2 ^ edx, 3)
edx  = eax2 + (eax2*3)*4 + 0x1020304 + esi
```

Where `R14_TABLE` (embedded in JIT code):
```
[i ≤  7]: 0x2b48b515d43f4140
[i ≤ 15]: 0x35bcb75507c270f7
[i ≤ 23]: 0x841e959c29c8f1e7
[i ≤ 31]: 0x1e7c68fc9ce020c2
[i ≥ 32]: 0x000000daf7d998de
```

### Success Condition (offset 0x186)
```asm
xor esi, 0x80741d49   ; esi = 0 iff edx == 0x80741d49
or  esi, ebp          ; both must be zero
setz al               ; al = 1 if success
ret
```

**Both constraints must hold:**
1. `edx == 0x80741d49` after all 37 iterations
2. `ebp == 0` — requires at each position: char is valid **and** `eax2 == key_byte[i]`

---

## Solving for the Flag

### Key Insight: `ebp` forces `eax2 = key_byte[i]`

For `ebp` to stay 0, every iteration must satisfy:
- Flag char is valid: `[0-9a-z_]`
- `key_byte[i] == eax2`

Since `eax2 = ((17*i ^ r9 ^ (r9>>8) ^ c) + (r9>>16) + ebx) & 0xff`, and we need `eax2 = key_byte[i]`, the required character is uniquely determined:

```python
A_lo   = (17*i ^ r9 ^ (r9>>8)) & 0xff
ecx_lo = ((r9>>16) + ebx) & 0xff
c      = A_lo ^ ((key_byte[i] - ecx_lo) & 0xff)
```

### Finding the Counter

The counter (`rdx` argument to the JIT) comes from `[rsp+0x74]`, which is the upper 32 bits of `[0x10710]` in the binary:

```python
val = struct.unpack_from('<Q', data, 0x10710)[0]
counter = val >> 32  # = 0x1337c0de
```

Initial state: `r9 = counter ^ 0xc0def00d = 0xd3e930d3`

### Reconstruction

With `counter = 0x1337c0de`, `r9`, `r11`, `ebx` evolving per the update rules, each position yields a valid printable character:

```
[0]  → 't'    [1]  → 'h'    [2]  → 'i'    [3]  → 's'
[4]  → '_'    [5]  → 'w'    [6]  → 'i'    [7]  → 'l'
[8]  → 'l'    [9]  → '_'    [10] → 'b'    [11] → 'e'
[12] → '_'    [13] → 't'    [14] → 'h'    [15] → 'e'
[16] → '_'    [17] → 'f'    [18] → 'l'    [19] → 'a'
[20] → 'g'    [21] → '_'    [22] → 'f'    [23] → 'o'
[24] → 'r'    [25] → '_'    [26] → 'c'    [27] → 'h'
[28] → 'a'    [29] → 'l'    [30] → 'l'    [31] → 'e'
[32] → 'n'    [33] → 'g'    [34] → 'e'    [35] → '_'
[36] → '7'
```

### Verification

```bash
echo "gigem{this_will_be_the_flag_for_challenge_7}" | LD_PRELOAD=./hook2.so ./challenge7
# flag> correct
```

---

## Solver Script

```python
import struct

R14_TABLE = [
    0x2b48b515d43f4140, 0x35bcb75507c270f7,
    0x841e959c29c8f1e7, 0x1e7c68fc9ce020c2,
    0x000000daf7d998de,
]

def get_key_byte(i):
    table = [0,1,2,3,4]
    tbl_idx = min(i // 8, 4)
    idx = i - tbl_idx * 8
    return (R14_TABLE[tbl_idx] >> (idx * 8)) & 0xff

def M32(x): return x & 0xffffffff
def ror32(x, n): x &= 0xffffffff; return ((x >> n) | (x << (32-n))) & 0xffffffff
def rol32(x, n): x &= 0xffffffff; return ((x << n) | (x >> (32-n))) & 0xffffffff

counter = 0x1337c0de
r9  = M32(counter ^ 0xc0def00d)
r11, ebx, edx = 0, 0, 0x31415926

body = []
for i in range(37):
    eax = M32(r9 + r11 - 0x61c88647)
    r9  = M32(rol32(eax, 5) ^ ror32(eax, 3))
    kb  = get_key_byte(i)
    A   = (M32(17*i) ^ r9 ^ (r9>>8)) & 0xff
    B   = (M32((r9>>16) + ebx)) & 0xff
    c   = A ^ ((kb - B) & 0xff)
    body.append(chr(c))
    if i < 36:
        r11 = M32(r11 + 0x045d9f3b)
        ebx = M32(ebx + 0xb)

print("gigem{" + "".join(body) + "}")
```

---

## Tools Used

- `objdump` / `ndisasm` — disassembly
- Custom LD_PRELOAD hooks — anti-debug bypass, JIT code capture
- Python — binary analysis, state machine parsing, algebraic solver
