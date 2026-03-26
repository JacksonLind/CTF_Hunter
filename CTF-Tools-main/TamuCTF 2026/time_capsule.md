# Time Capsule — CTF Writeup

**Competition:** TAMUctf 2026
**Category:** Forensics
**Flag:** `gigem{byg0n3_3r4}`

---

## Challenge Description

> My friend Bob found an old drive of his with a bunch of images from his childhood dated back to 2007. You could almost call it a time capsule of sorts. To motivate people to go through the images, he has hidden a flag somewhere. Do you think you could try to find it for me?

**Given:** `time-capsule.img`

---

## Initial Recon

```bash
file time-capsule.img
# Linux rev 1.0 ext4 filesystem data, UUID=53831e12-4f87-40e6-96f3-060db86e5d16
```

It's a raw ext4 disk image. Use `7z` to list its contents without needing root to mount:

```bash
7z l time-capsule.img
```

Output reveals `home/bob/nostalgia/` containing 17 image files (`memory_1.jpg` through `memory_17.jpg/png/webp/avif`), all with timestamps of **2007-01-01**. This matches the challenge description about childhood photos from 2007.

---

## Dead Ends

Standard forensics instincts first:

**Strings / grep for flag text:**
```bash
strings -n 8 time-capsule.img | grep -iE 'gigem|flag'
# (no output)
```

**EXIF metadata:**
```bash
exiftool -a -u home/bob/nostalgia/*
# Nothing suspicious — standard image metadata, one Getty Images watermark
```

**Embedded files / appended data:**
```bash
binwalk home/bob/nostalgia/*
# All images are clean — no embedded archives or appended payloads
```

**Data after JPEG EOI markers:**
```python
# Check for bytes after 0xFFD9 in every JPEG
for fname in jpgs:
    data = open(fname, 'rb').read()
    idx = data.rfind(b'\xff\xd9')
    if idx + 2 < len(data):
        print(fname, "has trailing data")
# All clean
```

**Deleted files:**
```bash
fls -r time-capsule.img
# Shows 3 OrphanFiles (inodes 33, 34, 35)
icat time-capsule.img 33   # empty
icat time-capsule.img 34   # empty
icat time-capsule.img 35   # empty
```

The orphan inodes exist but contain no data — just empty shells from a deletion.

**LSB steganography:**
```python
from PIL import Image
img = Image.open('memory_5.png').convert('RGB')
# Extract LSBs from all pixels → no readable plaintext, no flag
```

**Unallocated blocks:**
```bash
blkls time-capsule.img | strings -n 8 | grep -i gigem
# (no output)
```

---

## The Key Insight

The challenge description emphasizes two things: the images are "dated back to **2007**" and it's a "**time capsule**". Every image in the filesystem shares the same fake date: `2007-01-01`. But the **times** differ by image.

Use `istat` from Sleuth Kit to dump the raw inode data for each file:

```bash
for i in $(seq 16 32); do
    istat time-capsule.img $i | grep "Accessed:"
done
```

```
Accessed:  2007-01-01 02:01:43  (memory_1.jpg)
Accessed:  2007-01-01 02:01:45  (memory_2.jpg)
Accessed:  2007-01-01 02:01:43  (memory_3.jpg)
Accessed:  2007-01-01 02:01:41  (memory_4.jpg)
Accessed:  2007-01-01 02:01:49  (memory_5.png)
Accessed:  2007-01-01 02:02:03  (memory_6.jpg)
Accessed:  2007-01-01 02:01:38  (memory_7.jpg)
Accessed:  2007-01-01 02:02:01  (memory_8.jpg)
Accessed:  2007-01-01 02:01:43  (memory_9.webp)
Accessed:  2007-01-01 02:00:48  (memory_10.jpg)
Accessed:  2007-01-01 02:01:50  (memory_11.jpg)
Accessed:  2007-01-01 02:00:51  (memory_12.webp)
Accessed:  2007-01-01 02:01:35  (memory_13.jpg)
Accessed:  2007-01-01 02:00:51  (memory_14.jpg)
Accessed:  2007-01-01 02:01:54  (memory_15.jpg)
Accessed:  2007-01-01 02:00:52  (memory_16.avif)
Accessed:  2007-01-01 02:02:05  (memory_17.jpg)
```

The hour is always `02`. The minutes and seconds vary. The encoding is:

```
ASCII value = minutes × 60 + seconds
```

---

## Decoding the Flag

```python
timestamps = [
    (1,43), (1,45), (1,43), (1,41), (1,49),  # memory 1-5
    (2, 3), (1,38), (2, 1), (1,43), (0,48),  # memory 6-10
    (1,50), (0,51), (1,35), (0,51), (1,54),  # memory 11-15
    (0,52), (2, 5),                            # memory 16-17
]

flag = ''.join(chr(m * 60 + s) for m, s in timestamps)
print(flag)
```

| # | Time | MM×60+SS | Char |
|---|------|----------|------|
| 1 | 01:43 | 103 | `g` |
| 2 | 01:45 | 105 | `i` |
| 3 | 01:43 | 103 | `g` |
| 4 | 01:41 | 101 | `e` |
| 5 | 01:49 | 109 | `m` |
| 6 | 02:03 | 123 | `{` |
| 7 | 01:38 |  98 | `b` |
| 8 | 02:01 | 121 | `y` |
| 9 | 01:43 | 103 | `g` |
| 10 | 00:48 |  48 | `0` |
| 11 | 01:50 | 110 | `n` |
| 12 | 00:51 |  51 | `3` |
| 13 | 01:35 |  95 | `_` |
| 14 | 00:51 |  51 | `3` |
| 15 | 01:54 | 114 | `r` |
| 16 | 00:52 |  52 | `4` |
| 17 | 02:05 | 125 | `}` |

`byg0n3_3r4` = "bygone era" — a nod to the challenge's nostalgia theme.

---

## Flag

```
gigem{byg0n3_3r4}
```

---

## Takeaways

- When a challenge description overemphasizes a detail ("dated back to 2007"), treat it as a direct hint about where the data is hidden.
- Filesystem **inode timestamps** are a low-noise steganographic channel — they survive extraction and aren't checked by most automated steg tools.
- Always enumerate **all four inode timestamps** (atime, mtime, ctime, crtime) when every other avenue is clean. The data was right there in the directory listing, hiding in plain sight.
