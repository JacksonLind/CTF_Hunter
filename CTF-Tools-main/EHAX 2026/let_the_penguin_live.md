# let-the-penguin-live — Steganography / Audio Forensics

**CTF:** EH4X  
**Category:** Steganography / Audio Forensics  
**Difficulty:** Medium  
**File:** `challenge.mkv`  
**Flag:** `EH4X{0n3_tr4ck_m1nd_tw0_tr4ck_F1les}`

---

## Challenge Description

> *"In a colony of many, one penguin's path is an anomaly. Silence the crowd to hear the individual."*

---

## Step 1 — Initial Recon

Run `ffprobe` to inspect the MKV stream structure:

```bash
ffprobe -v quiet -print_format json -show_streams challenge.mkv
```

This revealed **two audio streams** — both FLAC, both stereo at 44,100 Hz, but with suspicious labelling:

- **Stream 1:** English (Stereo) — default track
- **Stream 2:** English (5.1 Surround) — non-default, but encoded as 2-channel stereo — **immediately suspicious**

The file metadata also contained a `COMMENT` tag with the value `EH4X{k33p_try1ng}` — an obvious **red herring**.

---

## Step 2 — Extracting the Audio Streams

Both audio streams were extracted as WAV files:

```bash
ffmpeg -i challenge.mkv -map 0:1 -ac 2 stream1.wav
ffmpeg -i challenge.mkv -map 0:2 -ac 2 stream2.wav
```

Comparing the two streams showed they were **not identical** — there was a subtle difference with a maximum delta of only ~153 sample units. This tiny discrepancy was the hidden signal.

---

## Step 3 — Phase Cancellation

> *"Silence the crowd to hear the individual"*

The hint pointed directly at **phase cancellation**: subtracting one audio track from the other removes the common signal (the crowd) and isolates what is unique (the individual).

```python
import numpy as np
import scipy.io.wavfile as wav

rate, s1 = wav.read('stream1.wav')
_,   s2 = wav.read('stream2.wav')

diff = s1.astype(np.int32) - s2.astype(np.int32)
```

The resulting difference signal had energy concentrated in the **11–16.5 kHz frequency range** — well above normal audio content, a classic indicator of spectral steganography.

---

## Step 4 — Spectrogram Analysis

The difference signal was converted to a spectrogram. Three parameters were critical to making the hidden text legible:

- **Time window:** 20–30 seconds into the track
- **Frequency band:** 11–16.5 kHz (extended to 8 kHz to capture full character height)
- **Resolution:** `nperseg=512` with high overlap (`noverlap=480`) for strong time resolution

```python
from scipy import signal
from PIL import Image

f, t, Sxx = signal.spectrogram(
    diff[start:end, 0], rate,
    nperseg=512, noverlap=480
)

# Isolate 11–16.5 kHz band
f_lo = np.searchsorted(f, 11000)
f_hi = np.searchsorted(f, 16500)
band = 10 * np.log10(np.abs(Sxx[f_lo:f_hi]) + 1e-12)

# Flip frequency axis (low freq at bottom) and render
img = Image.fromarray(band[::-1])
```

Rendering this as an image revealed **text hidden in the spectrogram** — a technique where audio is synthesised to draw an image when viewed as a frequency/time plot. Extending the view down to 8 kHz captured the full height of the characters and made the flag clearly legible.

---

## Key Techniques

| Technique | Purpose |
|---|---|
| `ffprobe` stream inspection | Identifying the suspicious second audio track |
| Phase cancellation (stream subtraction) | Isolating the hidden signal from the crowd |
| Spectrogram analysis (11–16.5 kHz) | Revealing the flag rendered as audio art |
| Red herring recognition | Ignoring `EH4X{k33p_try1ng}` in the metadata |

## Tools Used

- `ffprobe` / `ffmpeg` — stream inspection and audio extraction
- `numpy` — sample-level subtraction for phase cancellation
- `scipy.signal.spectrogram` — frequency/time analysis
- `PIL` (Pillow) — rendering the spectrogram as an image

---

**Flag:** `EH4X{0n3_tr4ck_m1nd_tw0_tr4ck_F1les}`  
*"One track mind, two track files" — a nod to the dual audio tracks used to hide the message.*
