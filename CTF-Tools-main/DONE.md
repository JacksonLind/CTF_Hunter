# CTF Hunter — Completed Upgrades

---

## ZIP / 7z / RAR Archive Password Spray
**Motivated by:** Common CTF challenge pattern — encrypted archives with weak/known passwords
**Implemented:** `analyzers/archive.py` — extended `ArchiveAnalyzer`.
- **ZIP** (AES-256 via pyzipper, ZipCrypto fallback): `_crack_passwords` now prepends KeyRegistry passwords before rockyou top-1000, so passwords discovered in other session files are tried first; cracked passwords are registered back into the KeyRegistry for cross-file correlation. `pyzipper.AESZipFile` used as opener when available (handles both AES and ZipCrypto); stdlib `zipfile` fallback when not installed.
- **7z** (optional, `py7zr`): `_check_7z` / `_crack_7z` — lists contents of unencrypted archives in fast mode; extracts + embeds `raw_hex=` for re-dispatch in deep mode; cracks encrypted archives against rockyou + KeyRegistry.
- **RAR** (optional, `rarfile` + `unrar` binary): `_check_rar` / `_crack_rar` — same flow as 7z.
- All three format paths gracefully degrade (INFO finding) when optional libraries are not installed.
- `_register_password` / `_get_registry_passwords` helpers manage KeyRegistry read/write.
- 7z magic bytes (`\x37\x7a\xbc\xaf\x27\x1c`) added to `_MAGIC_MAP` in `dispatcher.py`; `.7z` and `.rar` extension fallbacks also added.
- `py7zr` and `rarfile` listed as optional in `requirements.txt`.
**Tests:** `tests/test_archive_password.py` — 20 tests (16 run + 4 skipped without py7zr), all pass. Covers ZIP cracking (a1–a6), KeyRegistry integration (b7–b11), 7z cracking (c12–c15, conditional), RAR degradation (d16–d18), dispatcher routing (e19–e20).

---

## Git Repository Forensics
**Motivated by:** TamuCTF: Phantom
**Implemented:** `analyzers/git_forensics.py` — `GitForensicsAnalyzer`. Accepts `.bundle` files (clones to temp dir), `.git` directories, repo roots, and text files containing GitHub/GitLab URLs. Enumerates all refs (`show-ref` + `for-each-ref`) including PR refs (`refs/pull/*/head`), scans commit messages for flag patterns, runs `git fsck --unreachable` to surface dangling objects, reports stash entries. Deep mode: inspects dangling commit/blob content via `git cat-file`, scans full commit diffs, queries the GitHub Events API for deleted-branch push events. All subprocess calls use list args, no `shell=True`. Routed via `.bundle` extension and GitHub/GitLab URL detection in file content.
**Tests:** `tests/test_git_forensics.py` — 22 tests, all pass. Covers helper functions, URL extraction, local repo scanning (commits, refs, fsck, stash), bundle clone+scan, dispatcher routing, and graceful degradation.

---

## UART / Logic Analyzer Trace Decoding
**Motivated by:** EHAX: babyserial
**Implemented:** `analyzers/sal.py` — `SalAnalyzer`. Unpacks Saleae `.sal` ZIP archives (meta.json + digital-N.bin), parses the 44-byte binary header and float64 transition timestamps. Detects baud rate from minimum inter-transition delta and snaps to nearest standard rate (300–921600). Decodes UART 8N1 with automatic fallback to 7N1/8E2 on high framing-error rate. Post-decode pipeline: direct flag match, base64 decode (with PNG/JPEG detection), printability check, hex-string recursion.
**Tests:** `tests/test_sal_uart.py` — 25 tests, all pass. Covers binary format, baud detection, 8N1 decode (including isolated 0xFF, multi-byte strings, 9600 and 115200 baud), full archive pipeline (flag, base64, multi-channel, error cases).

---

## DPA / Side-Channel Trace Averaging
**Motivated by:** EHAX: Power Leak
**Implemented:** `analyzers/side_channel.py` — `SideChannelAnalyzer`. Detects power trace files (CSV rows=traces or rows=samples, NumPy .npy, raw binary float32/float64). Fast mode reports shape. Deep mode: averages all traces (noise cancellation, SNR ∝ √N), computes per-sample deviation for leakage peaks, window-decodes the averaged trace at multiple bit-widths (handles uniform-noise CTF encoding), applies deviation-peak bit extraction, and amplitude-to-char scaling. Registered as always-run with fast rejection for non-trace files. Non-ASCII byte ratio used to prevent binary float data from being misidentified as text.
**Tests:** `tests/test_side_channel.py` — 23 tests, all pass.

---

## STFT/ISTFT Audio Reconstruction
**Motivated by:** TamuCTF: Short Term Fuel Trim
**Implemented:** `analyzers/generic.py` — `_check_stft_matrix`. Detects `# STFT shape: (rows, cols)` header in text files (or infers shape from value count for common n_fft values). Fast mode emits INFO. Deep mode parses all complex literals (`(a+bj)` / `a+bj` / scientific notation), runs `scipy.signal.istft` with inferred parameters (`n_fft=(rows-1)*2`, `hop=n_fft//2`, `fs=16000`), normalises audio, writes 16-bit mono WAV, and embeds it as `raw_hex=` for ContentRedispatcher re-dispatch to AudioAnalyzer.
**Tests:** `tests/test_stft_matrix.py` — 13 tests, all pass. `tests/test_stft_deep.py` — 48 checks, all pass.

---

## Ext4 Inode Timestamp Steganography
**Motivated by:** TamuCTF: Time Capsule
**Implemented:** `analyzers/filesystem.py` — `_check_inode_timestamps_tsk` (pytsk3 path),
`_check_inode_timestamps_raw` (raw ext4 binary path, no pytsk3 needed), `_decode_timestamp_channel`,
`_ts_mmss`, `_ts_ss`, `_parse_ext4_inodes`.
Tries atime/mtime/ctime/crtime × mm×60+ss and ss-only formulas × name/inode-order sort.
**Tests:** `tests/test_filesystem_timestamps.py` — 13 tests, all pass.

---

## pcapng Inter-Arrival Timing Channel Decoder
**Motivated by:** EHAX: Breathing Void
**Implemented:** `analyzers/pcap.py` — `_timing_channel_analysis`, `_timing_scan`,
`_extract_times_pcapng`, `_extract_times_legacy_pcap`, `_cluster_deltas`,
`_decode_binary_timing`, `_decode_basen_timing`.
Supports pcapng + legacy pcap, bimodal/base-4 encoding, MSB/LSB ordering,
framing-bit alignment, and files up to 200 MB via raw mmap path.
**Tests:** `tests/test_pcap_timing.py` — 5 tests, all pass.

---

## Smart Attack on Anomalous ECC Curves (Pohlig-Hellman + p-adic)
**Motivated by:** TamuCTF: Abnormal Ellipse
**Implemented:** `analyzers/crypto_rsa.py` — `CryptoECCAnalyzer`, `_smart_attack`, `_pohlig_hellman_ec`.
**Tests:** `tests/test_crypto_ecc.py` — 19 tests, all pass.

---

## QR Code Repair Pipeline
**Motivated by:** TamuCTF: Quick Response
**Implemented:** `analyzers/image.py` — `_check_qr`, 16 transform variants, majority-vote resample.
**Tests:** `tests/test_qr_repair.py` — 14 tests, all pass.

---

## Audio Phase Analysis / Phase Cancellation
**Motivated by:** EHAX: Let the Penguin Live
**Implemented:** `analyzers/audio.py`.
**Tests:** `tests/test_audio_phase.py` — 12 tests, all pass.

---

## PE `.rsrc` RCDATA Extraction + Re-dispatch
**Motivated by:** TamuCTF: Nucleus21
**Implemented:** `analyzers/binary.py` — `_extract_pe_rcdata`.
**Tests:** `tests/test_pe_rcdata.py` — 10 tests, all pass.

---

## MT19937 State Recovery + Small-Seed Brute-Force
**Motivated by:** TamuCTF: Random Password
**Implemented:** `analyzers/crypto_prng.py` — `CryptoPRNGAnalyzer`, `_mt19937_recover_state`,
`_mt19937_brute_seed`.
**Tests:** `tests/test_crypto_prng.py` — 15 tests, all pass.

---

## Encoding Chain Auto-Solver
**Motivated by:** Extremely common across all CTF categories (multi-layer encoding)
**Implemented:** `analyzers/generic.py` — `_check_encoding_chain()` + `_run_encoding_bfs()` + 12 module-level transform functions.
- Transforms: `base64`, `base64url`, `base32`, `hex`, `url`, `rot13`, `atbash`, `reverse`, `xor_1byte`, `zlib`, `gzip`, `binary`
- BFS with visited-state deduplication; depth 4 (fast) / 8 (deep); hard queue cap 2000
- `_chain_is_interesting()` prunes states: ≥70% printable OR looks like known encoding
- Reports only on flag-pattern match; chains up to 8 steps deep
- `_chain_xor_brute`: tries all 256 single-byte keys, returns highest-printable-ratio result (≥70% threshold)
**Tests:** `tests/test_encoding_chain.py` — 27 tests, all pass.

---

## JWT Analyzer
**Motivated by:** Common in web CTF categories; tokens appear in config files, captured traffic, challenge descriptions
**Implemented:** `analyzers/jwt.py` — `JWTAnalyzer`. Always-run; scans any file for `eyJ…` JWT pattern (up to 10 tokens, 1 MB cap).
- Decodes header + payload (pure stdlib base64/JSON, no pyjwt)
- Timestamp anomalies: expired `exp`, future `iat` (>60 s ahead), not-yet-valid `nbf`
- `alg:none` bypass: forges a token with `alg=none` and empty signature
- HMAC brute-force (HS256/HS384/HS512): 20 CTF extras + rockyou top-1000; short-circuits on first match
- RS256→HS256 key-confusion: uses public key from `KeyRegistry` as HMAC secret (deep mode only)
- Module-level helpers exported: `_b64url_decode`, `_b64url_encode`, `_forge_alg_none`
Registered in `core/dispatcher.py` as always-run.
**Tests:** `tests/test_jwt.py` — 28 tests, all pass. Covers helpers (a1–a4), token analysis/flag match (b5–b8), timestamp anomalies (c9–c12), alg:none (d13–d15), HMAC brute (e16–e20), file scanning (f21–f25), edge cases (g26–g28).

---

## LSB Steganography (Image + Audio)
**Motivated by:** Common across image/audio CTF categories
**Implemented:**
- `analyzers/image.py` — `_check_lsb_pixels()`. Converts to RGB/RGBA, tries 2 bit planes × 2 scan orders (row/col) × channel groups (RGB, RGBA, A) × 2 interleave modes (interleaved/sequential) × 2 bit packings (MSB/LSB). Deduplicates by first-256-byte key. Emits HIGH on flag match, MEDIUM on ≥70% printable. Capped at 10 MP. Gated on `depth == "deep"`.
- `analyzers/audio.py` — `_check_lsb_samples()`. Replaces `_check_wav_lsb`. Handles 8-bit unsigned and 16-bit signed PCM, any channel count. Tries each channel individually + interleaved, bit planes 0 and 1, MSB/LSB packing. Capped at 500k frames. Gated on `depth == "deep"`.
**Tests:** `tests/test_lsb_steg.py` — 24 tests, all pass. Covers image variants (a1–a10), audio variants (b11–b20), integration fast/deep gating (c21–c24).

---

## Custom Rotation / Substitution Alphabet Brute-Force
**Motivated by:** EHAX: #808080 (Grey code rotation)
**Implemented:** `analyzers/classical_cipher.py` — extended `ClassicalCipherAnalyzer` with three new methods and six module-level helpers.
- `_rotate(alphabet, n)` — cyclic rotation
- `_mod_inverse(a, m)` — multiplicative inverse mod m (brute-force, m≤26)
- `_affine_decrypt(text, a, b)` — decrypts affine cipher E(x) = (ax+b) mod 26
- `_keyword_alpha(keyword)` — builds keyword-substitution alphabet (deduplicated keyword + remaining letters)
- `_grey_decode(grey)` — converts reflected-binary Grey code to binary integer
- `_check_rotation_brute` — tries all N cyclic rotations of Base64-std and Base64-url alphabets as substitution keys; scores by English frequency
- `_check_affine` — tries all 12×26 = 312 valid affine cipher keys plus 14 common CTF keyword-substitution alphabets
- `_check_grey_rotation` — Grey-decodes each letter position, checks flag match; also tries all 25 pre-shift variants (correct inverse: `plain = grey_decode((cipher - rot) mod 26)`)
All three methods wired into `_analyze_string` before the IC anomaly fallback.
**Tests:** `tests/test_rotation_brute.py` — 32 tests, all pass. Covers helpers (a1–a11), rotation brute (b12–b15), affine/keyword (c16–c20), Grey code (d21–d24), integration (e25–e26), edge cases (f27–f32).
