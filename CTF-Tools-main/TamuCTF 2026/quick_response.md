# Quick Response — CTF Writeup

**Challenge:** Quick Response  
**Category:** Misc / Steganography  
**Flag:** `gigem{d1d_y0u_n0t1c3_th3_t1m1n9_b175}`  
**Hint:** *"If you're bored, check this one out!"*

---

## Overview

We're given a single PNG file named `quick-response.png`. It looks like a QR code, but scanning it with any standard QR reader fails. The image has an obvious visual distortion in the center — a bulge/warp effect — and the overall color scheme looks slightly "off."

---

## Initial Analysis

Opening the image, a few things stand out immediately:

1. The QR code has a **spherical/bump distortion** applied to the center.
2. The image color scheme is **inverted** — the background is dark instead of white.
3. Standard QR decoders (phone cameras, online tools, OpenCV) all fail.

The challenge name "Quick Response" and the hint about being "bored" both point at the QR format itself — specifically its internal structure.

---

## Step 1: Understanding the Module Grid

Using OpenCV, we find the first row of transitions in the thresholded image:

```
32, 64, 96, 128, 160, 192, 256 ...
```

Transitions occur every **32 pixels**. The image is 928×928, giving us:

```
928 / 32 = 29 modules
```

A **29×29 QR code** is a **Version 3** QR code. This is useful to know for later.

---

## Step 2: Identifying the Transformations

Sampling the center of each module, we reconstruct the raw binary grid and inspect the **finder patterns** — the three 7×7 squares that appear in the top-left, top-right, and bottom-left corners of every valid QR code.

What we see:

```
█ █ █ █
  █ █  
███ ███
   █   
███ ███
  █ █  
█ █ █ █
```

This is clearly wrong. A valid finder pattern looks like:

```
███████
█     █
█ ███ █
█ ███ █
█ ███ █
█     █
███████
```

The observed pattern is the valid finder pattern **XOR'd with a checkerboard** and then **color-inverted**. This gives us our two transforms to reverse.

---

## Step 3: Reversing the Checkerboard XOR

QR codes use internal **data masking** to prevent large uniform regions. One of the 8 standard QR mask patterns (Mask Pattern 0) is exactly a checkerboard: a module at position (row, col) is flipped if `(row + col) % 2 == 0`.

In this challenge, that mask has been applied globally to the *entire* image (not just the data region as the QR spec intends), destroying the finder and timing patterns along with the data.

We XOR every module with a checkerboard at module-level resolution:

```python
for r in range(29):
    for c in range(29):
        if (r + c) % 2 == 0:
            # flip this module
```

After XOR, we invert the entire image. Checking the finder pattern now:

```
███████
█     █
█ ███ █
█ ███ █
█ ███ █
█     █
███████
```

Correct finder pattern restored.

---

## Step 4: Correcting the Spatial Distortion

Even after fixing the mask and inversion, the center of the QR is still spatially warped. Feeding the image directly to OpenCV's `QRCodeDetector` still fails because the warp corrupts module boundaries in the center of the code.

The fix: instead of decoding the distorted pixel image directly, we **re-render a clean version** by sampling each module via majority vote across its 32×32 pixel area:

```python
for r in range(29):
    for c in range(29):
        module_pixels = fixed[r*32:(r+1)*32, c*32:(c+1)*32]
        grid[r, c] = 0 if module_pixels.mean() < 128 else 255
```

This produces a perfectly crisp 29×29 grid that is immune to the spatial distortion.

---

## Step 5: Decoding

We scale the clean grid up for rendering and add a **quiet zone** (4-module white border, required by the QR spec):

```python
bordered = np.ones((n*scale + 4*scale, n*scale + 4*scale), dtype=np.uint8) * 255
bordered[2*scale:2*scale+n*scale, 2*scale:2*scale+n*scale] = clean
```

OpenCV decodes it successfully:

```
gigem{d1d_y0u_n0t1c3_th3_t1m1n9_b175}
```

---

## Summary of Transforms Applied to the QR

| # | Transform | How to Reverse |
|---|-----------|----------------|
| 1 | Spatial bulge/warp on center | Majority-vote module sampling |
| 2 | Global checkerboard XOR (QR Mask 0) | XOR all modules where `(r+c) % 2 == 0` |
| 3 | Full image color inversion | `bitwise_not` |
| 4 | Missing quiet zone | Add 4-module white border |

---

## The Flag's Meaning

`d1d_y0u_n0t1c3_th3_t1m1n9_b175` — *"Did you notice the timing bits?"*

The **timing pattern** in a QR code is the alternating black-white strip running between the finder patterns (row 6 and column 6). It's literally a checkerboard strip — which is exactly the mask pattern used to obfuscate the QR. The challenge author hid the answer in the flag itself.

---

## Full Solve Script

```python
import cv2
import numpy as np

img = cv2.imread('quick-response.png')
gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
_, thresh = cv2.threshold(gray, 127, 255, cv2.THRESH_BINARY)

module_size = 32
n = 29

# Build checkerboard mask at module level
checkerboard = np.zeros_like(thresh)
for r in range(n):
    for c in range(n):
        if (r + c) % 2 == 0:
            checkerboard[r*module_size:(r+1)*module_size,
                         c*module_size:(c+1)*module_size] = 255

# Reverse XOR mask and inversion
fixed = cv2.bitwise_not(cv2.bitwise_xor(thresh, checkerboard))

# Re-render clean grid via majority vote (removes spatial distortion)
scale = 30
clean = np.zeros((n * scale, n * scale), dtype=np.uint8)
for r in range(n):
    for c in range(n):
        module = fixed[r*module_size:(r+1)*module_size,
                       c*module_size:(c+1)*module_size]
        val = 0 if module.mean() < 128 else 255
        clean[r*scale:(r+1)*scale, c*scale:(c+1)*scale] = val

# Add quiet zone border
bordered = np.ones((n*scale + 4*scale, n*scale + 4*scale), dtype=np.uint8) * 255
bordered[2*scale:2*scale+n*scale, 2*scale:2*scale+n*scale] = clean

# Decode
detector = cv2.QRCodeDetector()
data, _, _ = detector.detectAndDecode(bordered)
print(data)
# gigem{d1d_y0u_n0t1c3_th3_t1m1n9_b175}
```
