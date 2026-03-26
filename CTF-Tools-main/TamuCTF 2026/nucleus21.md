# nucleus21.exe — CTF Writeup

**Category:** Reverse Engineering
**Flag:** `gigem{RCD4Ta_i5_N3aT}`
**Hint:** *"This lab specimen is mysterious... it seems to be evolving. Get to the bottom of it for me, will you?"*

---

## Initial Recon

```
file nucleus21.exe
# PE32+ executable for MS Windows 6.00 (console), x86-64, 6 sections

strings -n 8 nucleus21.exe | grep -iE 'gigem|flag'
# (nothing)
```

No flag in plain strings. Checking imports:

```
strings -n 8 nucleus21.exe
```

Key imports stand out immediately:

```
GetModuleFileNameA
ReadFile
CopyFileA
BeginUpdateResourceA
UpdateResourceA
EndUpdateResourceW
```

These are Windows PE resource editing APIs. The binary reads itself and writes a modified version — classic self-replicating / "evolving" binary behavior, matching the hint perfectly.

---

## PE Structure

Parsing the section table reveals an enormous `.rsrc` section:

| Section | Raw Offset | Raw Size |
|---------|-----------|---------|
| .text   | 0x400     | 0x1400  |
| .rdata  | 0x1800    | 0x1400  |
| .data   | 0x2c00    | 0x200   |
| .rsrc   | **0x3000**| **0x47000** (~287 KB) |

A `.rsrc` section almost 10× larger than the code section is a major red flag.

---

## Resource Directory Analysis

Parsing the PE resource directory:

```
Type 10 (RT_RCDATA) → ID 101 → 0x46c00 bytes at rsrc offset 0xa0
Type 24 (Manifest)  → ID 1   → 0x17d bytes
```

The `RCDATA` resource is **289,792 bytes** — essentially the entire `.rsrc` section. This is the "specimen" inside the nucleus.

---

## XOR Encoding

Dumping the first bytes of the RCDATA resource:

```
30 27 ed 7d 7e 7d 7d 7d 79 7d 7d 7d ...
```

Most bytes are `0x7D` (`}`). Testing XOR with `0x7D`:

```
30 XOR 7D = 4D  →  'M'
27 XOR 7D = 5A  →  'Z'
```

**MZ signature** — the resource is an XOR-encoded PE file with key `0x7D`.

The key is self-describing: `resource[0] XOR 0x4D` gives the key for any generation, since byte 0 of a valid PE is always `0x4D` (`M`).

---

## The Evolutionary Chain

Decoding the resource yields another valid PE — which also has an oversized `.rsrc` section containing *another* XOR-encoded PE. This nests 21 levels deep:

```
nucleus21.exe
  └─ RCDATA (XOR key=0x7D) → nucleus20.exe
       └─ RCDATA (XOR key=0x54) → nucleus19.exe
            └─ RCDATA (XOR key=0x61) → nucleus18.exe
                 └─ ... (21 total generations)
                      └─ nucleus0.exe  (no RCDATA — the innermost core)
```

Extraction script:

```python
import struct

def get_rcdata_resource(data):
    e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
    num_sections = struct.unpack_from('<H', data, e_lfanew+6)[0]
    opt_header_size = struct.unpack_from('<H', data, e_lfanew+20)[0]
    sections_offset = e_lfanew + 24 + opt_header_size

    rsrc_vaddr = rsrc_rawoff = None
    for i in range(num_sections):
        off = sections_offset + i * 40
        name = data[off:off+8].rstrip(b'\x00').decode('latin-1')
        if name == '.rsrc':
            rsrc_vaddr = struct.unpack_from('<I', data, off+12)[0]
            rsrc_rawoff = struct.unpack_from('<I', data, off+20)[0]
            break

    rsrc = data[rsrc_rawoff:]

    def find_data(rsrc, offset, depth):
        num_named, num_id = struct.unpack_from('<HH', rsrc, offset+12)
        entry_off = offset + 16
        for i in range(num_named + num_id):
            name_id, ptr = struct.unpack_from('<II', rsrc, entry_off + i*8)
            is_dir = (ptr & 0x80000000) != 0
            actual_id = name_id & 0x7FFFFFFF
            if depth == 0 and actual_id == 10:   # RT_RCDATA
                return find_data(rsrc, ptr & 0x7FFFFFFF, 1)
            elif depth == 1 and actual_id == 101: # resource ID
                return find_data(rsrc, ptr & 0x7FFFFFFF, 2)
            elif depth == 2 and not is_dir:
                rva, size, _, _ = struct.unpack_from('<IIII', rsrc, ptr)
                off = rsrc_rawoff + (rva - rsrc_vaddr)
                return data[off:off+size]
        return None

    return find_data(rsrc, 0, 0)

current = open('nucleus21.exe', 'rb').read()
generation = 21
keys = []

while True:
    resource = get_rcdata_resource(current)
    if resource is None:
        break
    key = resource[0] ^ 0x4D  # derive key from MZ signature
    keys.append((generation, key))
    current = bytes(b ^ key for b in resource)
    generation -= 1
```

---

## The Flag

Each generation's XOR key is a single ASCII character. Reading the keys from **generation 1 → 21** (innermost to outermost) spells the flag directly:

| Gen | Key  | Char |
|-----|------|------|
| 1   | 0x67 | `g`  |
| 2   | 0x69 | `i`  |
| 3   | 0x67 | `g`  |
| 4   | 0x65 | `e`  |
| 5   | 0x6d | `m`  |
| 6   | 0x7b | `{`  |
| 7   | 0x52 | `R`  |
| 8   | 0x43 | `C`  |
| 9   | 0x44 | `D`  |
| 10  | 0x34 | `4`  |
| 11  | 0x54 | `T`  |
| 12  | 0x61 | `a`  |
| 13  | 0x5f | `_`  |
| 14  | 0x69 | `i`  |
| 15  | 0x35 | `5`  |
| 16  | 0x5f | `_`  |
| 17  | 0x4e | `N`  |
| 18  | 0x33 | `3`  |
| 19  | 0x61 | `a`  |
| 20  | 0x54 | `T`  |
| 21  | 0x7d | `}`  |

```
gigem{RCD4Ta_i5_N3aT}
```

"RCDATA is neat" — a nod to the `RT_RCDATA` resource type used to smuggle every generation.

---

## Summary

1. `nucleus21.exe` contains 21 nested PE files, each XOR-encoded and stored as a `RCDATA` resource.
2. Each generation's XOR key is derived from `resource[0] XOR 0x4D` (the `M` in `MZ`).
3. The 21 keys, read innermost-to-outermost, are ASCII characters spelling the flag.
4. The binary's "evolution" is the peel-away of each layer — the specimen grows younger with each decode.
