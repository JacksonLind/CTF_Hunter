# CTF Hunter — Next Upgrades

High-frequency techniques that fire across a wide range of CTF categories.
Ordered by expected hit rate and implementation effort.

---

## Tier 1 — High ROI, Broad Coverage

### 1. Hash Identification + Crack Attempt
**What it is:** Identify hash types by length and character set (MD5, SHA-1, SHA-256, SHA-512,
bcrypt, NTLM, etc.). For MD5/SHA-1/SHA-256, attempt a wordlist lookup against rockyou top-1000
and a small built-in rainbow table of common CTF strings ("flag", "admin", "password123", etc.).
Report hash type, candidate plaintext if found, and a `hashcat` invocation template.
**Analyzer:** `analyzers/generic.py` — add `_check_hashes()` (or split into `analyzers/hash.py`)
**Complexity:** Low

---

### 2. PCAP: DNS Exfil + HTTP Credential Extraction
**What it is:** Extends the existing `pcap.py` analyzer:
- **DNS exfil:** reassemble TXT/subdomain labels from DNS queries; detect high-entropy
  subdomain sequences; base64/hex-decode the reassembled payload.
- **HTTP creds:** extract `Authorization: Basic` headers and decode them; scrape form
  POST bodies for `username=`/`password=` patterns; surface any `Set-Cookie` session tokens.
**Analyzer:** `analyzers/pcap.py` — add `_check_dns_exfil()` and `_check_http_creds()`
**Dependencies:** `scapy` (already optional in pcap.py)
**Complexity:** Medium

---

## Skipped / Deferred

These were considered and rejected for low ROI or being out of scope.

| Technique | Why Skipped |
|-----------|-------------|
| RNG state-steering DP solver | Requires challenge-specific cost function; can't be automated without challenge source |
| Sprague-Grundy / Nim variant solver | Too challenge-specific; mechanics vary too much per challenge |
| LD_PRELOAD JIT dump template | Template generator, not an analyzer; requires C compiler on target |
| Web API mode enumeration | Too application-specific; ffuf/gobuster already handle this |
| Path traversal payload generator | Covered by existing tools; out of scope for file analyzer |
| ROP chain builder | pwntools handles this; auto-generation is out of scope |
| Game-protocol exploit | Single-challenge, requires network interaction |

---

## Already Implemented (Do Not Reimplement)

| Technique | Analyzer | Tests |
|-----------|----------|-------|
| JWT Analyzer | `analyzers/jwt.py` | `tests/test_jwt.py` (28 tests) |
| LSB Steganography (image + audio) | `analyzers/image.py`, `analyzers/audio.py` | `tests/test_lsb_steg.py` (24 tests) |
| Encoding Chain Auto-Solver | `analyzers/generic.py` | `tests/test_encoding_chain.py` (27 tests) |
| Custom rotation / substitution alphabet brute-force | `analyzers/classical_cipher.py` | `tests/test_rotation_brute.py` (32 tests) |
| Git Repository Forensics | `analyzers/git_forensics.py` | `tests/test_git_forensics.py` (22 tests) |
| UART / Logic Analyzer Trace Decoding | `analyzers/sal.py` | `tests/test_sal_uart.py` (25 tests) |
| DPA / Side-channel trace averaging | `analyzers/side_channel.py` | `tests/test_side_channel.py` (23 tests) |
| STFT/ISTFT audio reconstruction | `analyzers/generic.py` | `tests/test_stft_matrix.py` + `test_stft_deep.py` (61 checks) |
| Smart attack on anomalous ECC curves (Smart/Pohlig-Hellman) | `analyzers/crypto_rsa.py` | `tests/test_crypto_ecc.py` (19 tests) |
| QR code repair pipeline (mask reversal + majority-vote resample) | `analyzers/image.py` | `tests/test_qr_repair.py` (14 tests) |
| Audio phase analysis / phase cancellation | `analyzers/audio.py` | `tests/test_audio_phase.py` (12 tests) |
| PE `.rsrc` RCDATA extraction + re-dispatch | `analyzers/binary.py` | `tests/test_pe_rcdata.py` (10 tests) |
| MT19937 state recovery + small-seed brute-force | `analyzers/crypto_prng.py` | `tests/test_crypto_prng.py` (15 tests) |
| pcapng inter-arrival timing channel decoder | `analyzers/pcap.py` | `tests/test_pcap_timing.py` (5 tests) |
| ZIP / 7z / RAR password spray + KeyRegistry integration | `analyzers/archive.py` | `tests/test_archive_password.py` (20 tests) |
