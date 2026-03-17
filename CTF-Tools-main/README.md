# CTF Hunter

A desktop GUI tool for analyzing CTF (Capture The Flag) challenge files. CTF Hunter automatically detects file types and runs 19 specialized analyzers to uncover flags, hidden data, cryptographic patterns, steganography, and forensic artifacts. An integrated intelligence pipeline then scores every finding by confidence, correlates results across files, generates attack hypotheses, and can auto-produce exploit scripts — all without leaving the application.

---

## Features

### Automatic File Analysis
Drop any file into CTF Hunter and it immediately identifies the file type via magic bytes and MIME detection, then dispatches the relevant analyzers. Five analyzers always run regardless of file type (Generic, Encoding, Crypto, Classical Cipher, and Forensics Timeline), while the remaining analyzers are selected based on the detected file format.

### Analyzers

| Analyzer | Triggered By | What It Does |
|----------|-------------|--------------|
| **Generic** | Always | Shannon entropy detection, magic/extension mismatch, null-byte clusters, string extraction with flag pattern matching, zero-width character steganography detection (U+200B/U+200C/U+200D, two encoding schemes) |
| **Encoding** | Always | Base64/32/85, hex, ROT13, Morse code, binary-to-ASCII, Polybius 5×5/6×6, Tap code, Baconian alphabet, Baudot code, Rail Fence; single-byte XOR key guessing; fuzzy encoding detection via character frequency vectors and cosine similarity scoring |
| **Classical Cipher** | Always | Caesar (frequency scoring), ROT13, Atbash, Vigenère with Kasiski key-length examination, Beaufort, Rail Fence, Columnar Transposition, Playfair, Substitution cipher with hill-climbing optimization using bigram frequency analysis and Index of Coincidence |
| **Crypto** | Always | MD5, SHA1, SHA256, SHA512, NTLM, MySQL, bcrypt hash identification and cracking; Cisco Type 7 XOR-decoding; known-plaintext XOR recovery using common CTF flag prefixes |
| **Forensics Timeline** | Always | Extracts timestamps from filesystem metadata, EXIF (via exiftool), PDF, DOCX, OLE, and ZIP; reconstructs a unified chronological timeline; detects suspicious timestamps (future dates, Y2K era) |
| **RSA Crypto** | PEM/DER files, files containing large integers | Small public-exponent attacks (e=3, Håstad broadcast), Wiener's attack (continued fractions), common-modulus attack, factordb.com API lookup, LSB oracle hint; recovers plaintext when an attack succeeds |
| **Binary** | ELF, PE executables | ELF/PE header parsing (32/64-bit), packed section detection (UPX, entropy-based), overlay data, suspicious imports, ROP gadget scanning via Capstone, format string vulnerability detection, single- and multi-byte rotating XOR brute-force, Base64/ROT13/hex flag decoding, entropy-guided LZMA/zlib decompression, cross-section data reconstruction, CodeView debug info extraction (PDB path, GUID, age) |
| **Image** | PNG, JPEG, GIF, BMP | EXIF metadata extraction (via exiftool), appended data detection, LSB chi-square testing (Deep), palette anomaly detection (Deep) |
| **Image Format** | PNG, JPEG, GIF, BMP | Deep PNG chunk parsing, JPEG APP marker analysis (ICC, EXIF, XMP, Photoshop), GIF animation/application extension parsing, BMP header deep parsing, TIFF directory inspection, extra data after image end detection |
| **Audio** | WAV, MP3 | ID3/metadata extraction (via mutagen), silence block detection, WAV LSB extraction (Deep), exiftool fallback |
| **Steganalysis** | Images, audio, video, PDF, ZIP, text, binary | LSB chi-square analysis, phase coding detection, echo hiding detection, frequency domain inspection (Deep), metadata inspection, appended data; post-processing pipeline (Base64 → hex → ROT13 → XOR → reversal → zlib decompression) applied at every extraction stage; supports PNG/BMP/JPG/GIF/TIFF/WebP, WAV/MP3/FLAC/OGG/AIFF, MP4/AVI/MKV/MOV/WMV/FLV, PDF, ZIP, and binary |
| **Archive** | ZIP and compressed files | ZIP comment extraction, encrypted entry detection, password cracking (via pyzipper), path traversal detection, nested archive recursive extraction (Deep) |
| **Document** | PDF, DOCX, DOC, XLS, PPT | PDF JavaScript/embedded-stream and suspicious-action detection (/AA, /OpenAction, /Launch, /URI, /SubmitForm, /RichMedia), PDF text extraction (PyMuPDF), DOCX macro/VBA analysis, OLE object parsing |
| **Filesystem** | Disk images | Disk image forensics via Sleuth Kit (pytsk3), deleted file recovery, hidden partition detection, raw file carving; degrades gracefully without pytsk3 |
| **PCAP** | Packet captures | Protocol summary, TCP stream reassembly, HTTP extraction, credential sniffing (HTTP Basic auth, login forms), file carving, flag pattern search, DNS covert channel detection; tshark fallback when scapy unavailable |
| **Database** | SQLite databases | Table enumeration, schema inspection (PRAGMA table_info), row-by-row flag pattern search across all fields (up to 10,000 rows per table) |
| **Disassembly** | ELF, PE executables | Radare2 (r2pipe) primary engine: per-function CFG, pseudo-C decompilation, xref-mapped string extraction, `.so`-specific analysis (DWARF debug info, constructors, LD_PRELOAD hooks), crypto constant fingerprinting (AES S-box, DES tables, SHA constants), symbol map (imports, exports, GOT); Capstone linear fallback when radare2 unavailable; x86/x64/ARM support; optional AI-powered assembly summary |
| **Binary (static)** | ELF, PE executables | See Binary analyzer above |
| **Dynamic (Frida)** | ELF, PE executables — *explicit only* | Runtime instrumentation via Frida: hooks dangerous imports (`system`, `execve`, `gets`, `strcpy`, `printf`, `read`, `mmap`, `mprotect`), detects self-modifying/RWX memory regions, traces file opens and exported `.so` function calls; 60-second wall-clock timeout; requires `frida` and `frida-tools` (optional) |

### Analysis Modes
- **Fast** – Runs only the most targeted checks for quick results; skips expensive brute-force and entropy operations.
- **Deep** – Runs exhaustive checks including brute-force decoding, extended steganography analysis, nested archive extraction, LSB chi-square testing, WAV LSB extraction, frequency domain inspection, and broader entropy scanning.
- **Auto** – Runs Fast first, then selectively re-runs Deep-only checks on high-confidence regions without repeating the full fast pass.

### Intelligence Pipeline

After the analyzers finish, CTF Hunter runs a multi-stage intelligence pipeline on the collected findings:

1. **Confidence Scoring** – Every finding is scored 0–1 based on corroboration (multiple independent analyzers flagging the same byte range receive a boost), flag-pattern matches in decoded output (+0.20), entropy reduction after decoding (+0.10), and penalties for high-entropy or non-printable garbage (−0.15). Score is capped at 0.99.

2. **Content Re-dispatch** – Extracted blobs (decoded Base64 strings, decompressed streams, carved files, etc.) are classified by magic bytes and encoding, then re-routed through the appropriate analyzers automatically with up to 5 levels of recursion and a 45-second timeout guard, enabling multi-layer analysis without any manual steps. Duplicate content is suppressed via SHA256 hashing.

3. **Key Extraction & Registry** – Keys discovered by any analyzer (Vigenère/Beaufort keys, XOR bytes, ZIP passwords, AES key candidates) are stored in a session-scoped `KeyRegistry`. The registry enables cross-finding key correlation, so a password found in a text file can automatically be tried against an encrypted archive in the same session.

4. **Hypothesis Engine** – Applies 30 built-in CTF attack-pattern rules to the scored findings, producing ranked attack hypotheses without requiring an API key. Each hypothesis includes:
   - A category badge (pwn, rev, crypto, steg, forensics, web)
   - A confidence score
   - The findings that support it
   - What to look for next to confirm it
   - Concrete shell commands / tool invocations
   - An ordered transform-pipeline suggestion

5. **Exploit Generator** – When a `pwn`-category hypothesis reaches ≥ 0.6 confidence, CTF Hunter automatically generates a ready-to-run pwntools exploit script. Generated scripts are validated with `py_compile` before display. Supported vulnerability classes:
   - Stack buffer overflow with ROP chain (win-function or ret2libc)
   - Format string exploitation
   - RSA attacks (small-e cube-root, factorable-N decryption, common-modulus recovery)

6. **Workspace Correlator** – Runs pairwise cross-file analysis on all loaded files to surface relationships such as verbatim shared strings, hash values that appear in a companion file, and password hints that match encrypted archives in the same session.

### AI Integration (Optional)
When configured with a Claude API key, CTF Hunter extends the intelligence pipeline:
- The **Hypothesis Engine** sends the top 15 findings to Claude for additional AI-generated hypotheses beyond the 30 built-in rules.
- The **Challenge Panel** generates a structured attack plan from a free-text challenge description.
- The **Disassembly** analyzer produces a human-readable AI summary of disassembled code.

### External Tool Suggestions
After analysis, CTF Hunter maps its findings to 30+ relevant external CTF tools (e.g., `zsteg`, `steghide`, `john`, `fcrackzip`, `upx`, `ghidra`) and shows which ones are installed on your system along with suggested usage commands.

### UI Panels and Tabs

| Panel / Tab | What It Does |
|-------------|--------------|
| **Findings Tree** | All findings organized by file and severity (HIGH → MEDIUM → LOW → INFO); click any finding to inspect its detail and optionally pin it to the Transform Pipeline for further decoding |
| **Flag Summary** | Aggregates all flag-match findings with copy-to-clipboard access |
| **Attack Plan** | Ranked hypothesis cards with category badge, confidence bar, present/missing findings, suggested commands, and a **Generate Exploit** button for pwn-category hypotheses |
| **Hex Viewer** | Byte-level display with ASCII sidebar, color highlighting, and offset navigation |
| **Steg Viewer** | Visualizes LSB bit-planes and steganographic extractions |
| **File Intel** | Per-file MD5/SHA1/SHA256/SHA512 hashes (computed in background thread), interactive entropy chart, configurable strings extractor, and a quick-decode playground |
| **Transform Pipeline** | Chainable encoding transforms with live hex+ASCII preview; supports Base64 encode/decode, Hex encode/decode, XOR (hex or text key), ROT-N, Zlib compress/decompress, AES-ECB/CBC decrypt, Reverse Bytes, integer base conversion, URL encode/decode, and Regex Extract; pipelines can be saved/loaded as JSON |
| **Timeline** | Chronological visualization of all extracted timestamps across loaded files |
| **Network Console** | Packet inspection for PCAP analysis with protocol display and TCP stream reassembly; auto-decodes Base64/hex/ROT-13/XOR in received data and highlights flag matches |
| **Tool Suggester** | Shows relevant external tools for current findings, with install status and usage examples |
| **Challenge Panel** | Free-text input for AI-generated attack plans from challenge descriptions (requires Claude API key) |
| **Session Diff** | Side-by-side comparison of two saved sessions; new findings highlighted green, removed in red, modified in yellow |
| **Help** | In-app user guide covering every tab, toolbar control, and workflow with keyboard shortcuts |

### Additional Features
- **Watch Folder** – Monitors a directory and automatically analyzes new files as they appear.
- **Session Save/Load** – Save a full analysis session (files, findings, notes, flag pattern) to a `.ctfs` JSON file and reload it later.
- **Session Diff** – Compare any two saved `.ctfs` sessions side-by-side to identify what changed between runs.
- **Export** – Export all findings from the toolbar to **Markdown**, **CSV**, or **HTML** reports.
- **Flag format presets** – One-click flag regex presets for common competition formats (CTF{}, HTB{}, picoCTF{}, etc.) plus a Custom entry field.
- **Drag-and-drop** file loading, plus **Add Files** and **Add Folder** buttons for bulk loading.
- **Background threading** – All analysis runs in a thread pool; the UI stays responsive and shows per-analyzer progress.
- **Dynamic analysis** – An explicit **Run Dynamic Analysis** button in the Binary analyzer tab launches Frida instrumentation on ELF/PE files (requires optional `frida` and `frida-tools` packages).

---

## Supported File Types

Images (PNG, JPEG, GIF, BMP, TIFF, WebP), audio (WAV, MP3, FLAC, OGG, AIFF), video (MP4, AVI, MKV, MOV, WMV, FLV), archives (ZIP, gzip, zlib, bz2, LZMA), documents (PDF, DOCX, DOC, XLS, PPT), executables (ELF, PE), shared libraries (.so), packet captures (PCAP), SQLite databases, PEM/DER crypto key files, disk images, and generic binary files.

---

## Installation

**Requirements:** Python 3.9+

```bash
cd ctf_hunter
pip install -r requirements.txt
```

### Dependencies

| Package | Purpose |
|---------|---------|
| `PyQt6` | Desktop GUI |
| `Pillow` | Image processing for steganalysis |
| `mutagen` | Audio metadata extraction |
| `python-magic` | File-type detection via magic bytes |
| `numpy` | Entropy and statistical analysis |
| `scapy` | PCAP parsing and protocol analysis |
| `capstone` | x86/x64/ARM disassembly |
| `r2pipe` | Radare2 Python bindings (the `radare2` binary must also be installed at the system level: `apt install radare2` or `brew install radare2`) |
| `anthropic` | Claude AI client |
| `watchdog` | Watch-folder directory monitoring |
| `pyzipper` | ZIP archive analysis and cracking |
| `olefile` | OLE/Office file parsing |
| `PyMuPDF` | PDF parsing |
| `pyinstaller` | Standalone executable packaging |
| `bcrypt` | bcrypt hash cracking |

### Optional Dependencies

These are **not** installed by default. Edit `requirements.txt` to enable them:

| Package | Enables |
|---------|---------|
| `pycryptodome` | RSA key parsing and AES-ECB/CBC transforms in the Transform Pipeline; the RSA analyzer and AES transforms degrade gracefully without it |
| `frida`, `frida-tools` | Dynamic binary instrumentation (Frida analyzer) |
| `pytsk3` | Disk image forensics via The Sleuth Kit |

---

## Usage

### GUI Mode (default)

```bash
cd ctf_hunter
python main.py
```

This launches the GUI. Load files by dragging and dropping them onto the file list, or use the **Add Files** / **Add Folder** buttons in the toolbar. Click **▶ Analyze All** to run all applicable analyzers. Results appear in the Findings Tree, organized by severity (HIGH, MEDIUM, LOW, INFO).

### CLI Mode (headless)

Run CTF Hunter from the command line without opening the GUI. This enables scripted workflows, CI/CD pipelines, and integration with other tools.

```bash
cd ctf_hunter
python main.py --cli [options] <files or directories...>
```

#### Examples

```bash
# Analyze a single file
python main.py --cli challenge.bin

# Deep analysis with a custom flag pattern
python main.py --cli --depth deep --flag 'HTB\{[^}]+\}' challenge.png

# Analyze a folder and output JSON
python main.py --cli --format json --output results.json challenges/

# Show only flag matches with high confidence
python main.py --cli --flags-only --min-confidence 0.8 *.bin

# Quiet mode (suppress progress on stderr), CSV output to file
python main.py --cli --quiet --format csv -o report.csv challenge1.png challenge2.zip

# Filter by severity (show only HIGH and MEDIUM findings)
python main.py --cli --severity MEDIUM files/
```

#### CLI Options

| Option | Short | Description |
|--------|-------|-------------|
| `--depth {fast,deep,auto}` | `-d` | Analysis depth (default: `fast`) |
| `--flag PATTERN` | `-f` | Flag regex pattern (default: `CTF\{[^}]+\}`) |
| `--format {text,json,markdown,csv,html}` | `-F` | Output format (default: `text`) |
| `--output FILE` | `-o` | Write output to a file instead of stdout |
| `--quiet` | `-q` | Suppress progress messages on stderr |
| `--flags-only` | | Only show findings that match the flag pattern |
| `--min-confidence N` | | Minimum confidence threshold, 0.0–1.0 (default: 0.0) |
| `--severity {HIGH,MEDIUM,LOW,INFO}` | | Minimum severity filter |

### Workflow

1. **Load files** – Drag files onto the file list or click **Add Files** / **Add Folder**. Multiple files can be loaded at once; the Workspace Correlator will cross-reference them automatically.
2. **Set flag pattern** – Choose a preset (CTF{}, HTB{}, picoCTF{}, etc.) from the Flag Format drop-down, or select **Custom…** and enter the competition's regex (e.g. `picoCTF\{[^}]+\}`) so every analyzer uses the correct pattern.
3. **Choose analysis mode** – Select **Fast**, **Deep**, or **Auto** from the toolbar.
4. **Analyze** – Click **▶ Analyze All**. Progress is shown per-analyzer in the status bar.
5. **Review findings** – Browse the Findings Tree. Click a finding to inspect its detail and optionally pin it to the Transform Pipeline for further decoding.
6. **Check Attack Plan** – Open the **Attack Plan** tab to see ranked hypotheses and suggested next steps. For pwn-category hypotheses, click **Generate Exploit** to produce a pwntools script.
7. **Use Transform Pipeline** – Chain encoding transforms (Base64 → XOR → Zlib, etc.) to manually decode suspicious data.
8. **Export results** – Use the **📤 Export** toolbar button to save all findings as Markdown, CSV, or HTML.

### Optional: AI features

1. Open **Settings** from the toolbar.
2. Enter your [Anthropic API key](https://console.anthropic.com/).
3. The Challenge Panel, Hypothesis Engine, and Disassembly analyzer will now include AI-generated insights.

### Optional: Custom wordlist for hash/archive cracking

By default, CTF Hunter uses a bundled `rockyou_top1000.txt` wordlist (top 1,000 RockYou passwords). To use a full RockYou list or any custom wordlist, set the path in **Settings**.

### Optional: Dynamic Analysis with Frida

1. Install Frida: `pip install frida frida-tools`
2. Load an ELF or PE binary.
3. Run a standard analysis first; then click **Run Dynamic Analysis** in the Binary analyzer panel.
4. CTF Hunter spawns the binary under Frida, injects a JavaScript agent, and reports dangerous function calls, RWX memory regions, file opens, and exported function invocations as findings (60-second timeout).

---

## Building a Standalone Executable

```bash
cd ctf_hunter
python build.py
```

This uses PyInstaller to produce a single-file executable in `dist/` (e.g., `dist/ctf_hunter` on Linux/macOS or `dist/ctf_hunter.exe` on Windows). The wordlist is bundled automatically. Frida is attempted as an optional inclusion but the build succeeds without it.

---

## Project Structure

```
ctf_hunter/
├── main.py                        # Entry point – launches GUI or CLI based on arguments
├── cli.py                         # Command-line interface for headless analysis
├── build.py                       # PyInstaller packaging script
├── requirements.txt               # Python dependencies
├── core/
│   ├── dispatcher.py              # File-type detection, analyzer routing, Fast/Deep/Auto mode logic
│   ├── ai_client.py               # Claude API integration (claude-sonnet-4)
│   ├── confidence.py              # Confidence scoring: corroboration, flag match, entropy, garbage penalties
│   ├── content_classifier.py      # Classifies extracted blobs by magic bytes, encoding, and entropy level
│   ├── content_redispatcher.py    # Recursively re-routes extracted content through appropriate analyzers
│   ├── deduplicator.py            # Removes and merges duplicate findings
│   ├── exploit_generator.py       # Auto-generates pwntools and RSA exploit scripts (validated via py_compile)
│   ├── extracted_content.py       # Data class for content extracted by analyzers
│   ├── external.py                # Subprocess wrappers for strings, file, exiftool, tshark
│   ├── hypothesis_engine.py       # 30-rule attack-path hypothesis engine (+ optional AI path)
│   ├── key_extractor.py           # Extracts crypto key candidates (Vigenère, XOR, ZIP, AES) from findings
│   ├── key_registry.py            # Session-scoped registry for cross-finding key correlation
│   ├── report.py                  # Finding and Session data classes
│   ├── session_diff.py            # Diffs two .ctfs sessions to surface new/removed/changed findings
│   ├── tool_suggester.py          # Maps findings to 30+ external CTF tool recommendations
│   ├── watchfolder.py             # Directory monitoring (watchdog)
│   └── workspace_correlator.py    # Cross-file pairwise finding correlation
├── analyzers/
│   ├── base.py                    # Analyzer base class
│   ├── archive.py                 # ZIP / compressed-file analysis and password cracking
│   ├── audio.py                   # Audio metadata and WAV LSB extraction
│   ├── binary.py                  # ELF/PE static analysis, ROP gadgets, format-string detection
│   ├── classical_cipher.py        # Classical cipher detection and hill-climbing solving
│   ├── crypto.py                  # Hash identification, cracking, Cisco Type 7, XOR recovery
│   ├── crypto_rsa.py              # RSA attack suite (Wiener, small-e, Håstad, common-modulus, factordb)
│   ├── database.py                # SQLite enumeration and flag search
│   ├── disassembly.py             # Radare2 + Capstone disassembly, CFG, decompilation, AI summary
│   ├── document.py                # PDF / Office document analysis
│   ├── dynamic_frida.py           # Runtime Frida instrumentation (explicit button only)
│   ├── encoding.py                # Encoding detection: Base64/32/85, hex, Morse, Polybius, Tap, Baconian, Baudot
│   ├── filesystem.py              # Disk image forensics via Sleuth Kit (pytsk3)
│   ├── forensics_timeline.py      # Timestamp extraction and chronological timeline reconstruction
│   ├── generic.py                 # Universal entropy/string/flag analysis, zero-width char steg
│   ├── image.py                   # Image EXIF, appended data, LSB chi-square, palette anomalies
│   ├── image_format.py            # Deep PNG/JPEG/GIF/BMP/TIFF format parsing
│   ├── pcap.py                    # Packet capture: protocol summary, TCP streams, HTTP, credentials, DNS
│   └── steganalysis.py            # LSB, phase coding, echo hiding, frequency domain steg detection
├── ui/
│   ├── main_window.py             # Main window: 3-panel layout, toolbar, background analysis threads
│   ├── attack_plan_tab.py         # Hypothesis cards with confidence bars and exploit generation
│   ├── challenge_panel.py         # AI attack-plan input panel (requires Claude API key)
│   ├── diff_view.py               # Syntax-highlighted diff widget
│   ├── file_intel.py              # File hashes, entropy chart, strings extractor, decode playground
│   ├── flag_summary.py            # Aggregated flag matches with copy-to-clipboard
│   ├── help_tab.py                # In-app user guide and keyboard shortcuts
│   ├── hex_viewer.py              # Byte-level hex + ASCII viewer with offset navigation
│   ├── network_console.py         # Packet inspection, TCP stream view, auto-decode for PCAP files
│   ├── result_panel.py            # Findings tree with severity grouping and finding-to-pipeline pinning
│   ├── session.py                 # Session save/load (.ctfs JSON)
│   ├── session_diff_panel.py      # Side-by-side session comparison (new/removed/modified highlighting)
│   ├── settings_dialog.py         # API key, wordlist path, and preferences
│   ├── steg_viewer.py             # LSB bit-plane and steg-extraction visualizer
│   ├── timeline_tab.py            # Chronological timestamp visualization
│   ├── tool_suggester_panel.py    # External tool recommendations with install status
│   └── transform_pipeline.py     # Chainable encoding-transform pipeline (save/load as JSON)
└── wordlists/
    └── rockyou_top1000.txt        # Bundled password list for hash and archive cracking
```
