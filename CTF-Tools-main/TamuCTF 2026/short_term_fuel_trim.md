# short-term-fuel-trim — CTF Writeup

**Category:** Forensics / Signal Processing
**Flag:** `gigem{fft_is_50_0p}`

## Overview

The challenge provides a file `numbers.txt` containing a large list of complex numbers with the header:

```
# STFT shape: complex64 (129, 1380)
```

The challenge name "short-term-fuel-trim" is a pun on **STFT** (Short-Time Fourier Transform). The file contains the complex frequency-domain representation of an audio signal that, when inverted back to the time domain, spells out the flag letter by letter.

## Solution

### 1. Parse the STFT Data

The file contains 178,020 complex values (exactly 129 × 1380), stored in Python complex literal format:

```
(real+imagj)
```

Parse and reshape into a (129, 1380) matrix:

```python
import numpy as np

data = []
with open('numbers.txt', 'r') as f:
    for line in f:
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        data.append(complex(line.strip()))

stft_matrix = np.array(data, dtype=np.complex64).reshape(129, 1380)
```

### 2. Reconstruct the Audio via ISTFT

The STFT parameters:
- **n_fft = 256** (since 129 = n_fft/2 + 1)
- **hop_length = 128** (common default of n_fft/2)
- **Sample rate = 16000 Hz** (standard speech rate)

```python
from scipy.signal import istft

n_fft = 256
fs = 16000
hop = 128

_, audio = istft(stft_matrix, fs=fs, nperseg=n_fft, noverlap=n_fft-hop, nfft=n_fft)
audio = audio.astype(np.float32)
audio /= np.max(np.abs(audio))
```

### 3. Transcribe the Audio

The reconstructed audio contains a voice spelling out the flag character by character (e.g., "G-I-G-E-M left curly bracket F-F-T underscore I-S underscore five zero underscore zero P right curly bracket").

Using OpenAI Whisper (large model) for transcription:

```python
import whisper
from scipy.signal import resample_poly
from math import gcd

model = whisper.load_model("large")

# Resample to 16kHz for Whisper
g = gcd(16000, fs)
audio_16k = resample_poly(audio, 16000 // g, fs // g).astype(np.float32)

result = model.transcribe(audio_16k, language='en', temperature=0)
print(result['text'])
# → "G I G E M left curly bracket F F T underscore I S underscore
#    five zero underscore zero P right curly bracket"
```

### 4. Decode the Flag

| Spoken | Decoded |
|--------|---------|
| G I G E M | `gigem` |
| left curly bracket | `{` |
| F F T | `fft` |
| underscore | `_` |
| I S | `is` |
| underscore | `_` |
| five zero | `50` |
| underscore | `_` |
| zero P | `0p` |
| right curly bracket | `}` |

**Flag: `gigem{fft_is_50_0p}`**

## Tools Used

- Python 3 + NumPy + SciPy (`istft`)
- OpenAI Whisper (`large` model) for speech-to-text
- SpeechRecognition + Google STT (initial recon)
