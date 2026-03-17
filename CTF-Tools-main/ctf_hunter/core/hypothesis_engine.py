"""
Hypothesis Engine for CTF Hunter.

After confidence scoring completes, this module runs regardless of whether AI is
configured, providing rule-based hypotheses about the most likely attack path.

Rule-based path (always runs, no API key required):
  - Implements 30 CTF attack-pattern rules organised in _RULES list
  - Each rule inspects session findings and returns a Hypothesis or None
  - Confidence is proportional to how many corroborating signals are present

AI-augmented path (runs additionally if API key configured):
  - Serializes top 15 findings by confidence score into compact JSON
  - Sends to Claude with a strict CTF-solver system prompt
  - Parses strict JSON response into AI Hypothesis objects
  - Invalid / non-JSON responses are discarded silently (WARNING logged)
"""
from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .report import Finding, Session
from .challenge_fingerprinter import ChallengeFingerprinter

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Hypothesis dataclass
# ---------------------------------------------------------------------------


@dataclass
class Hypothesis:
    """A structured hypothesis about a CTF challenge attack path."""

    title: str
    confidence: float
    category: str                          # e.g. "pwn", "rev", "crypto", "steg", "forensics", "web"
    present_findings: List[str]            # finding *titles* already in session that support this
    missing_findings: List[str]            # what to look for next to confirm
    suggested_commands: List[str]          # concrete shell commands or tool invocations
    suggested_transforms: List[str]        # transform pipeline steps in order
    source: str = "rules"                  # "rules" | "ai"
    reasoning: str = ""                    # optional human-readable explanation (used by UI)


# ---------------------------------------------------------------------------
# Rule helpers
# ---------------------------------------------------------------------------

@dataclass
class _Rule:
    """A single pattern rule in the decision tree."""
    title: str
    category: str
    match_fn: object        # callable(findings) -> Optional[tuple(float, List[Finding])]
    missing: List[str]
    commands: List[str]
    transforms: List[str] = field(default_factory=list)


def _matches_title(findings: List[Finding], keywords: List[str]) -> List[Finding]:
    """Return findings whose title or detail contains any of the keywords (case-insensitive)."""
    hits = []
    for f in findings:
        combined = (f.title + " " + f.detail).lower()
        if any(kw.lower() in combined for kw in keywords):
            hits.append(f)
    return hits


def _conf(n_hits: int, *, weak: float = 0.35, strong: float = 0.80) -> float:
    """Scale confidence from weak (1 signal) to strong (≥3 signals)."""
    if n_hits >= 3:
        return strong
    if n_hits == 2:
        return (weak + strong) / 2
    return weak


def _strip_markdown_fences(text: str) -> str:
    """Remove markdown code fences (``` … ```) that models sometimes emit.

    Despite the system prompt saying "no markdown", models occasionally wrap
    their JSON response in triple-backtick fences.  Stripping them before
    json.loads() is a practical defence.
    """
    text = text.strip()
    # Remove opening fence line: ```json or just ```
    text = re.sub(r"^```[a-zA-Z]*\n?", "", text)
    # Remove closing fence
    text = re.sub(r"\n?```\s*$", "", text)
    return text.strip()


# ---------------------------------------------------------------------------
# 30 attack-pattern rule functions
# ---------------------------------------------------------------------------

# Rule 1
def _r01_png_high_entropy_zip(findings: List[Finding]):
    entropy_hits = _matches_title(findings, ["high entropy", "entropy anomaly"])
    appended_hits = _matches_title(findings, ["appended", "overlay", "after eof", "after end"])
    zip_hits = _matches_title(findings, ["zip magic", "pk magic", "zip header", "embedded zip", "zip archive"])
    if (entropy_hits or appended_hits) and zip_hits:
        all_hits = list({f.id: f for f in entropy_hits + appended_hits + zip_hits}.values())
        return (_conf(len(all_hits), weak=0.40, strong=0.85), all_hits)
    return None


# Rule 2
def _r02_png_high_entropy_no_zip(findings: List[Finding]):
    entropy_hits = _matches_title(findings, ["high entropy", "entropy anomaly"])
    steg_hints = _matches_title(findings, ["lsb", "steganography", "steganalysis", "chi-square"])
    zip_hits = _matches_title(findings, ["zip magic", "pk magic", "zip header", "embedded zip"])
    if (entropy_hits or steg_hints) and not zip_hits:
        all_hits = list({f.id: f for f in entropy_hits + steg_hints}.values())
        if not all_hits:
            return None
        return (_conf(len(all_hits), weak=0.35, strong=0.75), all_hits)
    return None


# Rule 3
def _r03_jpeg_appended(findings: List[Finding]):
    appended = _matches_title(findings, ["appended", "overlay", "after eof", "after end", "jfif", "jpeg"])
    exif_hints = _matches_title(findings, ["exif", "metadata", "comment", "password"])
    if appended:
        all_hits = list({f.id: f for f in appended + exif_hints}.values())
        return (_conf(len(all_hits), weak=0.38, strong=0.80), all_hits)
    return None


# Rule 4
def _r04_wav_lsb(findings: List[Finding]):
    wav_hits = _matches_title(findings, ["wav", "audio", "lsb anomaly", "lsb"])
    if wav_hits:
        return (_conf(len(wav_hits), weak=0.38, strong=0.78), wav_hits)
    return None


# Rule 5
def _r05_audio_silence(findings: List[Finding]):
    silence = _matches_title(findings, ["silence", "silent block", "dtmf", "morse"])
    if silence:
        return (_conf(len(silence), weak=0.35, strong=0.72), silence)
    return None


# Rule 6
def _r06_zip_encrypted_passwords(findings: List[Finding]):
    enc = _matches_title(findings, ["encrypted entr", "password-protected", "encrypted zip"])
    pwcands = _matches_title(findings, ["password candidate", "strings", "wordlist"])
    if enc and pwcands:
        all_hits = list({f.id: f for f in enc + pwcands}.values())
        return (_conf(len(all_hits), weak=0.55, strong=0.82), all_hits)
    if enc:
        return (0.40, enc)
    return None


# Rule 7
def _r07_zip_comment(findings: List[Finding]):
    hits = _matches_title(findings, ["zip comment", "archive comment", "comment non-empty", "comment:"])
    if hits:
        return (_conf(len(hits), weak=0.38, strong=0.72), hits)
    return None


# Rule 8
def _r08_elf_stack_overflow(findings: List[Finding]):
    danger = _matches_title(findings, ["gets", "strcpy", "strcat", "dangerous import", "unsafe function"])
    no_canary = _matches_title(findings, ["no canary", "canary: no", "stack canary not found", "nx: no"])
    if danger:
        all_hits = list({f.id: f for f in danger + no_canary}.values())
        return (_conf(len(all_hits), weak=0.40, strong=0.82), all_hits)
    return None


# Rule 9
def _r09_elf_format_string(findings: List[Finding]):
    printf_hits = _matches_title(findings, ["printf", "fprintf", "sprintf"])
    fmtstr_hints = _matches_title(findings, ["format string", "%n", "%p", "%s%s", "user-controlled format"])
    if printf_hits and fmtstr_hints:
        all_hits = list({f.id: f for f in printf_hits + fmtstr_hints}.values())
        return (_conf(len(all_hits), weak=0.55, strong=0.85), all_hits)
    if printf_hits:
        return (0.35, printf_hits)
    return None


# Rule 10
def _r10_rsa_small_e(findings: List[Finding]):
    small_e = _matches_title(findings, ["e=3", "e = 3", "small exponent", "small public exponent"])
    rsa = _matches_title(findings, ["rsa"])
    if small_e or (rsa and small_e):
        all_hits = list({f.id: f for f in small_e + rsa}.values())
        return (_conf(len(all_hits), weak=0.45, strong=0.82), all_hits)
    return None


# Rule 11
def _r11_rsa_factorable(findings: List[Finding]):
    factored = _matches_title(findings, ["factored", "factordb", "factorable", "factor found"])
    ct = _matches_title(findings, ["ciphertext", "encrypted message"])
    if factored:
        all_hits = list({f.id: f for f in factored + ct}.values())
        return (_conf(len(all_hits), weak=0.65, strong=0.92), all_hits)
    return None


# Rule 12
def _r12_rsa_common_modulus(findings: List[Finding]):
    hits = _matches_title(findings, ["common modulus", "shared modulus", "hastad", "broadcast attack"])
    if hits:
        return (_conf(len(hits), weak=0.55, strong=0.88), hits)
    return None


# Rule 13
def _r13_elf_upx_packed(findings: List[Finding]):
    upx_hits = _matches_title(findings, ["upx", "packed", "packer detected", "upx magic"])
    entropy = _matches_title(findings, ["high entropy"])
    if upx_hits:
        all_hits = list({f.id: f for f in upx_hits + entropy}.values())
        return (_conf(len(all_hits), weak=0.60, strong=0.88), all_hits)
    return None


# Rule 14
def _r14_elf_rwx_shellcode(findings: List[Finding]):
    rwx = _matches_title(findings, ["rwx", "executable stack", "rwx segment", "writable executable"])
    frida = _matches_title(findings, ["frida", "dynamic", "hook"])
    if rwx:
        all_hits = list({f.id: f for f in rwx + frida}.values())
        return (_conf(len(all_hits), weak=0.45, strong=0.80), all_hits)
    return None


# Rule 15
def _r15_xor_key_detected(findings: List[Finding]):
    xor_key = _matches_title(findings, ["xor key", "key length detected", "xor with key"])
    xor_generic = _matches_title(findings, ["xor"])
    if xor_key:
        all_hits = list({f.id: f for f in xor_key + xor_generic}.values())
        return (_conf(len(all_hits), weak=0.60, strong=0.85), all_hits)
    if xor_generic:
        return (0.38, xor_generic)
    return None


# Rule 16
def _r16_base64_to_binary(findings: List[Finding]):
    b64_magic = _matches_title(findings, ["base64", "decoded magic", "base64 decodes to"])
    magic = _matches_title(findings, ["magic bytes", "file signature", "magic mismatch"])
    if b64_magic:
        all_hits = list({f.id: f for f in b64_magic + magic}.values())
        if len(all_hits) >= 2:
            return (0.75, all_hits)
        return (0.40, all_hits)
    return None


# Rule 17
def _r17_ic_english_classical(findings: List[Finding]):
    ic = _matches_title(findings, ["index of coincidence", "ic:", "ic =", "ic near 0.065"])
    caesar = _matches_title(findings, ["caesar", "rot", "shift cipher"])
    if ic or caesar:
        all_hits = list({f.id: f for f in ic + caesar}.values())
        return (_conf(len(all_hits), weak=0.40, strong=0.72), all_hits)
    return None


# Rule 18
def _r18_ic_flat_vigenere(findings: List[Finding]):
    vig = _matches_title(findings, ["vigenere", "vigenère", "kasiski", "flat ic", "ic near 0.045"])
    transposition = _matches_title(findings, ["transposition", "columnar", "rail fence"])
    if vig or transposition:
        all_hits = list({f.id: f for f in vig + transposition}.values())
        return (_conf(len(all_hits), weak=0.40, strong=0.75), all_hits)
    return None


# Rule 19
def _r19_pdf_javascript(findings: List[Finding]):
    js = _matches_title(findings, ["javascript", "embedded js", "/js", "/javascript"])
    launch = _matches_title(findings, ["/launch", "launch action", "openaction"])
    pdf = _matches_title(findings, ["pdf"])
    if js and pdf:
        all_hits = list({f.id: f for f in js + launch + pdf}.values())
        return (_conf(len(all_hits), weak=0.42, strong=0.80), all_hits)
    return None


# Rule 20
def _r20_dns_exfil(findings: List[Finding]):
    dns = _matches_title(findings, ["dns exfil", "dns tunnel", "non-standard subdomain", "dns query"])
    subdomain = _matches_title(findings, ["subdomain", "base64 label", "encoded label"])
    if dns or subdomain:
        all_hits = list({f.id: f for f in dns + subdomain}.values())
        return (_conf(len(all_hits), weak=0.42, strong=0.78), all_hits)
    return None


# Rule 21
def _r21_pcap_http_transfer(findings: List[Finding]):
    http = _matches_title(findings, ["http file", "file transfer", "multipart", "content-disposition"])
    carved = _matches_title(findings, ["carved file", "extracted file", "reassembled"])
    if http:
        all_hits = list({f.id: f for f in http + carved}.values())
        return (_conf(len(all_hits), weak=0.40, strong=0.78), all_hits)
    return None


# Rule 22
def _r22_pcap_tcp_covert(findings: List[Finding]):
    covert = _matches_title(findings, ["repeated payload", "identical payload", "tcp covert", "covert channel"])
    timing = _matches_title(findings, ["timing", "inter-arrival", "packet timing"])
    if covert:
        all_hits = list({f.id: f for f in covert + timing}.values())
        return (_conf(len(all_hits), weak=0.38, strong=0.72), all_hits)
    return None


# Rule 23
def _r23_sqlite_blobs(findings: List[Finding]):
    blob = _matches_title(findings, ["blob", "blob column", "binary blob", "sqlite blob"])
    sqlite = _matches_title(findings, ["sqlite", "database"])
    if blob:
        all_hits = list({f.id: f for f in blob + sqlite}.values())
        return (_conf(len(all_hits), weak=0.42, strong=0.78), all_hits)
    return None


# Rule 24
def _r24_disk_deleted_inodes(findings: List[Finding]):
    deleted = _matches_title(findings, ["deleted inode", "deleted file", "unallocated", "tsk_recover"])
    disk = _matches_title(findings, ["disk image", "filesystem", "partition", "ext2", "ext4", "fat32"])
    if deleted:
        all_hits = list({f.id: f for f in deleted + disk}.values())
        return (_conf(len(all_hits), weak=0.45, strong=0.82), all_hits)
    return None


# Rule 25
def _r25_elf_aes_ciphertext(findings: List[Finding]):
    aes = _matches_title(findings, ["aes", "aes constant", "aes s-box", "crypto constant"])
    ct = _matches_title(findings, ["ciphertext", "ciphertext-shaped", "encrypted input"])
    if aes and ct:
        all_hits = list({f.id: f for f in aes + ct}.values())
        return (_conf(len(all_hits), weak=0.55, strong=0.85), all_hits)
    if aes:
        return (0.38, aes)
    return None


# Rule 26
def _r26_high_entropy_no_magic(findings: List[Finding]):
    entropy = _matches_title(findings, ["high entropy"])
    no_magic = _matches_title(findings, ["no magic", "unknown format", "unrecognized magic", "magic mismatch"])
    if entropy and no_magic:
        all_hits = list({f.id: f for f in entropy + no_magic}.values())
        return (_conf(len(all_hits), weak=0.42, strong=0.78), all_hits)
    return None


# Rule 27
def _r27_hidden_text_layer(findings: List[Finding]):
    hidden = _matches_title(findings, ["hidden text", "invisible text", "white-on-white", "occlusion",
                                       "hidden layer", "watermark"])
    doc = _matches_title(findings, ["docx", "pdf", "document"])
    if hidden:
        all_hits = list({f.id: f for f in hidden + doc}.values())
        return (_conf(len(all_hits), weak=0.42, strong=0.78), all_hits)
    return None


# Rule 28
def _r28_palette_anomaly(findings: List[Finding]):
    palette = _matches_title(findings, ["palette anomaly", "palette", "color table", "clut"])
    if palette:
        return (_conf(len(palette), weak=0.38, strong=0.72), palette)
    return None


# Rule 29
def _r29_elf_constructor(findings: List[Finding]):
    ctor = _matches_title(findings, ["constructor", ".init", "init_array", "preinit_array", "ctor function"])
    frida = _matches_title(findings, ["frida", "hook", "dynamic"])
    if ctor:
        all_hits = list({f.id: f for f in ctor + frida}.values())
        return (_conf(len(all_hits), weak=0.38, strong=0.72), all_hits)
    return None


# Rule 30
def _r30_ctf_framework_strings(findings: List[Finding]):
    ctf_strings = _matches_title(findings, ["pwntools", "flag{", "ctf{", "picoctf{", "ductf{",
                                             "flag pattern", "flag match"])
    if ctf_strings:
        return (_conf(len(ctf_strings), weak=0.55, strong=0.90), ctf_strings)
    return None


# Rule 31
def _r31_inline_pipeline_declaration(findings: List[Finding]):
    """Match an 'Encoding: <pipeline>' inline declaration found in findings."""
    pipeline_hits = _matches_title(findings, [
        "base85 force-decoded", "base85", "pipeline", "encoding header",
        "inline pipeline", "encoding:",
    ])
    if pipeline_hits:
        return (_conf(len(pipeline_hits), weak=0.55, strong=0.88), pipeline_hits)
    return None


# ---------------------------------------------------------------------------
# _RULES list  (31 rules)
# ---------------------------------------------------------------------------

_RULES: List[_Rule] = [
    # 1
    _Rule(
        title="PNG high-entropy tail with appended ZIP — binwalk extraction",
        category="steg",
        match_fn=_r01_png_high_entropy_zip,
        missing=["Confirm ZIP PK magic at file tail", "Check strings output for archive password"],
        commands=[
            "binwalk --extract --carve suspicious.png",
            "strings suspicious.png | grep -i pass",
        ],
        transforms=["binwalk-extract", "strings-filter"],
    ),
    # 2
    _Rule(
        title="PNG high-entropy tail (no ZIP) — check steghide / LSB tools",
        category="steg",
        match_fn=_r02_png_high_entropy_no_zip,
        missing=["Try steghide without password", "Run zsteg -a", "Check chi-square for LSB"],
        commands=[
            "zsteg -a image.png",
            "steghide extract -sf image.png -p ''",
            "outguess -r image.png output.txt",
        ],
        transforms=["lsb-extract-r", "lsb-extract-g", "lsb-extract-b"],
    ),
    # 3
    _Rule(
        title="JPEG with appended data — binwalk, foremost, EXIF password hint",
        category="steg",
        match_fn=_r03_jpeg_appended,
        missing=["Check EXIF comment field for password", "Inspect appended byte sequence"],
        commands=[
            "binwalk -e image.jpg",
            "foremost -i image.jpg -o extracted/",
            "exiftool image.jpg | grep -i comment",
        ],
        transforms=["binwalk-extract"],
    ),
    # 4
    _Rule(
        title="Audio WAV with LSB anomaly — extract LSB payload",
        category="steg",
        match_fn=_r04_wav_lsb,
        missing=["Determine bit depth and channel count", "Check for image or text magic in LSB stream"],
        commands=[
            "python3 -c \""
            "import wave, struct; w=wave.open('audio.wav'); "
            "frames=w.readframes(w.getnframes()); "
            "lsb=bytes(b&1 for b in frames); "
            "open('lsb_out.bin','wb').write(lsb)\"",
            "file lsb_out.bin",
        ],
        transforms=["wav-lsb-extract"],
    ),
    # 5
    _Rule(
        title="Audio with silence blocks — check for Morse or DTMF",
        category="steg",
        match_fn=_r05_audio_silence,
        missing=["Identify tone frequencies (DTMF: 697–1633 Hz)", "Map silence/tone pattern to Morse"],
        commands=[
            "sox audio.wav -n stat 2>&1 | grep -i silence",
            "multimon-ng -a DTMF -t wav audio.wav",
            "python3 -c \"import pydub; # analyse silence blocks\"",
        ],
        transforms=["morse-decode", "dtmf-decode"],
    ),
    # 6
    _Rule(
        title="ZIP encrypted entries + password candidates — fcrackzip",
        category="forensics",
        match_fn=_r06_zip_encrypted_passwords,
        missing=["Extract candidate passwords from strings findings", "Check ZIP comment for password hint"],
        commands=[
            "fcrackzip -u -D -p rockyou.txt archive.zip",
            "strings archive.zip | tee candidates.txt && fcrackzip -u -D -p candidates.txt archive.zip",
        ],
        transforms=["base64-decode"],
    ),
    # 7
    _Rule(
        title="ZIP comment non-empty — inspect for base64 or flag pattern",
        category="forensics",
        match_fn=_r07_zip_comment,
        missing=["Decode comment if base64", "Check for embedded flag or password"],
        commands=[
            "python3 -c \"import zipfile; z=zipfile.ZipFile('archive.zip'); print(z.comment)\"",
            "python3 -c \"import zipfile,base64; z=zipfile.ZipFile('archive.zip'); "
            "print(base64.b64decode(z.comment))\"",
        ],
        transforms=["base64-decode"],
    ),
    # 8
    _Rule(
        title="ELF with dangerous imports and no stack canary — classic stack overflow",
        category="pwn",
        match_fn=_r08_elf_stack_overflow,
        missing=["Determine exact offset with cyclic()", "Identify win/flag function or libc gadgets"],
        commands=[
            "checksec --file=binary",
            "ROPgadget --binary binary --rop | head -30",
            "python3 -c \"from pwn import *; print(cyclic(256))\" | ./binary",
        ],
        transforms=[],
    ),
    # 9
    _Rule(
        title="ELF with printf + format string pattern — format string exploit",
        category="pwn",
        match_fn=_r09_elf_format_string,
        missing=["Find format string offset with %N$p probe", "Identify target GOT entry to overwrite"],
        commands=[
            "python3 -c \"from pwn import *; p=process('./binary'); p.sendline(b'%7$p'); print(p.recvline())\"",
            "checksec --file=binary",
        ],
        transforms=[],
    ),
    # 10
    _Rule(
        title="RSA small exponent (e=3) — Håstad broadcast or direct cube root",
        category="crypto",
        match_fn=_r10_rsa_small_e,
        missing=["Collect three ciphertexts if Håstad applies", "Verify m^3 < n (direct root)"],
        commands=[
            "python3 -c \"import gmpy2; m,exact=gmpy2.iroot(c,3); print(m.to_bytes(128,'big') if exact else 'Need CRT')\"",
            "python3 RsaCtfTool.py --attack hastads -n N1,N2,N3 -e 3 -c C1,C2,C3",
        ],
        transforms=[],
    ),
    # 11
    _Rule(
        title="RSA public key + ciphertext + factorable N — direct decryption",
        category="crypto",
        match_fn=_r11_rsa_factorable,
        missing=["Retrieve factors from factordb.com"],
        commands=[
            "python3 -c \""
            "p,q=FACTORS; n=p*q; e=65537; "
            "d=pow(e,-1,(p-1)*(q-1)); "
            "print(pow(c,d,n).to_bytes(256,'big').lstrip(b'\\x00'))\"",
            "python3 RsaCtfTool.py --publickey key.pem --uncipherfile cipher.bin",
        ],
        transforms=[],
    ),
    # 12
    _Rule(
        title="RSA common modulus across two keypairs — common modulus attack",
        category="crypto",
        match_fn=_r12_rsa_common_modulus,
        missing=["Confirm same n used with two different e values", "Obtain both ciphertexts"],
        commands=[
            "python3 RsaCtfTool.py --attack commonmodulus",
            "python3 -c \""
            "# Extended Euclidean: find s1,s2 such that s1*e1 + s2*e2 = 1, then m = pow(c1,s1,n)*pow(c2,s2,n)%n; "
            "from math import gcd; "
            "def egcd(a,b): return (a,1,0) if b==0 else (lambda g,x,y:(g,y,x-a//b*y))(*egcd(b,a%b)); "
            "g,s1,s2=egcd(e1,e2); "
            "m=(pow(c1,s1,n)*pow(c2,s2,n))%n; "
            "print(m.to_bytes(256,'big').lstrip(b'\\\\x00'))\"",
        ],
        transforms=[],
    ),
    # 13
    _Rule(
        title="ELF packed with UPX — unpack first",
        category="rev",
        match_fn=_r13_elf_upx_packed,
        missing=["Verify stub signature", "Re-run analysis after unpacking"],
        commands=[
            "upx -d packed_binary -o unpacked_binary",
            "file unpacked_binary && strings unpacked_binary | head -40",
        ],
        transforms=[],
    ),
    # 14
    _Rule(
        title="ELF with RWX segment (Frida detected) — dump and re-analyze as shellcode",
        category="rev",
        match_fn=_r14_elf_rwx_shellcode,
        missing=["Identify address range of RWX segment", "Capture dumped bytes at runtime"],
        commands=[
            "frida-trace -n PROCESS -i 'mmap'",
            "frida -n PROCESS -e \"Process.enumerateRanges('rwx').forEach(r => console.log(JSON.stringify(r)))\"",
        ],
        transforms=[],
    ),
    # 15
    _Rule(
        title="XOR-encoded region with detected key length — decode and re-analyze",
        category="crypto",
        match_fn=_r15_xor_key_detected,
        missing=["Confirm key by checking decoded output for printable text or magic bytes"],
        commands=[
            "python3 -c \""
            "data=open('file','rb').read(); key=b'KEY'; "
            "out=bytes(data[i]^key[i%len(key)] for i in range(len(data))); "
            "open('decoded.bin','wb').write(out)\"",
            "file decoded.bin && strings decoded.bin | head -20",
        ],
        transforms=["xor-decode", "hex-view"],
    ),
    # 16
    _Rule(
        title="Base64 string decodes to binary magic bytes — treat as new file",
        category="forensics",
        match_fn=_r16_base64_to_binary,
        missing=["Identify magic bytes in decoded output", "Re-analyze decoded file with appropriate analyzer"],
        commands=[
            "python3 -c \"import base64; open('decoded.bin','wb').write(base64.b64decode(open('input.txt').read()))\"",
            "file decoded.bin",
        ],
        transforms=["base64-decode", "file-type-detect"],
    ),
    # 17
    _Rule(
        title="Classical cipher — IC near English (0.065): likely Caesar/ROT",
        category="crypto",
        match_fn=_r17_ic_english_classical,
        missing=["Try all 25 ROT shifts", "Check for ROT13 specifically"],
        commands=[
            "python3 -c \""
            "ct=open('cipher.txt').read().upper(); "
            "[print(f'ROT{i}:', ''.join(chr((ord(c)-65+i)%26+65) if c.isalpha() else c for c in ct)) "
            "for i in range(26)]\"",
        ],
        transforms=["rot-bruteforce"],
    ),
    # 18
    _Rule(
        title="Classical cipher — IC near flat (0.045): likely Vigenère/transposition",
        category="crypto",
        match_fn=_r18_ic_flat_vigenere,
        missing=["Run Kasiski examination to find key length", "Try columnar transposition"],
        commands=[
            "python3 -c \""
            "# Kasiski: find repeated trigrams and GCD their distances"
            "import re; ct=open('cipher.txt').read().upper(); "
            "trigrams={}; "
            "[trigrams.setdefault(ct[i:i+3],[]).append(i) for i in range(len(ct)-2)]; "
            "print({k:v for k,v in trigrams.items() if len(v)>1})\"",
        ],
        transforms=["vigenere-kasiski", "vigenere-decode"],
    ),
    # 19
    _Rule(
        title="PDF with embedded JavaScript — extract and analyze JS, check /Launch",
        category="forensics",
        match_fn=_r19_pdf_javascript,
        missing=["Check for /Launch actions", "Look for obfuscated JS eval() calls"],
        commands=[
            "pdf-parser.py --search javascript suspicious.pdf",
            "peepdf suspicious.pdf",
            "pdfid.py suspicious.pdf",
        ],
        transforms=[],
    ),
    # 20
    _Rule(
        title="PCAP DNS exfiltration — reconstruct from non-standard subdomain labels",
        category="forensics",
        match_fn=_r20_dns_exfil,
        missing=["Identify base domain", "Reconstruct payload from ordered labels"],
        commands=[
            "tshark -r capture.pcap -Y 'dns' -T fields -e dns.qry.name | sort -u",
            "python3 -c \""
            "import scapy.all as s; pkts=s.rdpcap('capture.pcap'); "
            "[print(p[s.DNS].qd.qname) for p in pkts if p.haslayer(s.DNS) and p[s.DNS].qd]\"",
        ],
        transforms=["base64-decode"],
    ),
    # 21
    _Rule(
        title="PCAP HTTP file transfer — carve and re-analyze transferred file",
        category="forensics",
        match_fn=_r21_pcap_http_transfer,
        missing=["Identify Content-Type of transfer", "Re-analyze carved file"],
        commands=[
            "tshark -r capture.pcap --export-objects http,exported/",
            "foremost -i capture.pcap -o carved/",
        ],
        transforms=["file-type-detect"],
    ),
    # 22
    _Rule(
        title="PCAP repeated identical TCP payloads — covert channel encoding",
        category="forensics",
        match_fn=_r22_pcap_tcp_covert,
        missing=["Analyse payload bit patterns", "Check inter-arrival timing for binary encoding"],
        commands=[
            "tshark -r capture.pcap -Y tcp -T fields -e data.data | sort | uniq -c | sort -rn | head",
            "python3 -c \""
            "import scapy.all as s; pkts=s.rdpcap('capture.pcap'); "
            "[print(bytes(p[s.TCP].payload)) for p in pkts if p.haslayer(s.TCP)]\"",
        ],
        transforms=[],
    ),
    # 23
    _Rule(
        title="SQLite with blob columns — extract blobs and re-analyze",
        category="forensics",
        match_fn=_r23_sqlite_blobs,
        missing=["Identify table/column containing blobs", "Re-analyze each blob as a file"],
        commands=[
            "sqlite3 database.db '.tables'",
            "python3 -c \""
            "import sqlite3; con=sqlite3.connect('database.db'); "
            "for row in con.execute('SELECT * FROM tablename'): "
            "  open(f'blob_{row[0]}.bin','wb').write(row[1])\"",
        ],
        transforms=["file-type-detect"],
    ),
    # 24
    _Rule(
        title="Disk image with deleted inodes — recover with tsk_recover",
        category="forensics",
        match_fn=_r24_disk_deleted_inodes,
        missing=["List deleted inodes", "Re-analyze each recovered file"],
        commands=[
            "tsk_recover -e disk.img recovered/",
            "fls -r -d disk.img",
            "icat disk.img INODE_NUM > recovered_file",
        ],
        transforms=["file-type-detect"],
    ),
    # 25
    _Rule(
        title="ELF/SO with AES constants + ciphertext-shaped input — try AES modes",
        category="rev",
        match_fn=_r25_elf_aes_ciphertext,
        missing=["Locate key and IV in binary strings or fixed bytes", "Try ECB, CBC, CTR modes"],
        commands=[
            "python3 -c \""
            "from Crypto.Cipher import AES; "
            "key=b'KEYKEYKEYKEY1234'; iv=b'\\x00'*16; "
            "ct=open('ciphertext.bin','rb').read(); "
            "print(AES.new(key,AES.MODE_CBC,iv).decrypt(ct))\"",
            "strings binary | xxd | grep -A2 'AES'",
        ],
        transforms=[],
    ),
    # 26
    _Rule(
        title="High entropy binary with no recognizable magic — decompress or XOR-deobfuscate",
        category="forensics",
        match_fn=_r26_high_entropy_no_magic,
        missing=["Try all common compression formats", "Brute-force single-byte XOR first"],
        commands=[
            "python3 -c \""
            "data=open('file','rb').read(); "
            "[open(f'xor_{k}.bin','wb').write(bytes(b^k for b in data)) for k in range(256)]\"",
            "zlib-flate -uncompress < file > out.bin 2>/dev/null || true",
            "python3 -c \"import gzip,bz2,lzma; data=open('file','rb').read(); "
            "[print(f,d[:40]) for f,fn in [('gzip',gzip.decompress),('bz2',bz2.decompress),('lzma',lzma.decompress)] "
            "for d in [fn(data)] if d]\"",
        ],
        transforms=["zlib-decompress", "gzip-decompress", "xor-brute"],
    ),
    # 27
    _Rule(
        title="DOCX/PDF with hidden text or white-on-white layer — extract raw streams",
        category="forensics",
        match_fn=_r27_hidden_text_layer,
        missing=["Diff visible vs raw text content", "Check font color == background color"],
        commands=[
            "python3 -m docx2txt document.docx | cat",
            "pdftotext -layout suspicious.pdf -",
            "python3 -c \""
            "import fitz; doc=fitz.open('suspicious.pdf'); "
            "[print(p.get_text()) for p in doc]\"",
        ],
        transforms=["text-extract"],
    ),
    # 28
    _Rule(
        title="Image with palette anomaly — check palette entries for hidden data",
        category="steg",
        match_fn=_r28_palette_anomaly,
        missing=["Print all palette RGBA entries", "Check for non-standard alpha or color ordering"],
        commands=[
            "python3 -c \""
            "from PIL import Image; img=Image.open('image.png'); "
            "pal=img.getpalette(); "
            "[print(i,pal[i*3:i*3+3]) for i in range(256) if pal]\"",
            "zsteg image.png",
        ],
        transforms=["palette-extract"],
    ),
    # 29
    _Rule(
        title="ELF with constructor functions detected — hook with Frida, log side effects",
        category="rev",
        match_fn=_r29_elf_constructor,
        missing=["List all .init_array entries", "Check for self-modifying code in constructors"],
        commands=[
            "readelf -d binary | grep INIT",
            "frida-trace -f ./binary -i '*'",
            "frida -f ./binary --no-pause -e \""
            "Process.enumerateModules().forEach(m => {"
            "console.log(m.name, m.base)})\"",
        ],
        transforms=[],
    ),
    # 30
    _Rule(
        title="Binary contains CTF framework strings — extract all flag-pattern matches",
        category="forensics",
        match_fn=_r30_ctf_framework_strings,
        missing=["Rank candidates by surrounding context entropy", "Check for encoded/obfuscated flags"],
        commands=[
            "strings binary | grep -E '(flag|CTF|picoCTF|DUCTF|HTB)\\{[^}]+\\}'",
            "python3 -c \""
            "import re; data=open('binary','rb').read().decode('latin-1'); "
            "matches=re.findall(r'[A-Za-z0-9_]+\\{[^}]+\\}', data); "
            "[print(m) for m in matches]\"",
        ],
        transforms=["strings-filter", "regex-extract"],
    ),
    # 31
    _Rule(
        title="Inline Encoding pipeline declaration — apply declared transform chain",
        category="encoding",
        match_fn=_r31_inline_pipeline_declaration,
        missing=[
            "Parse 'Encoding:' header to extract transform sequence",
            "Apply each transform step in order (base85 → binary → reverse → atbash, etc.)",
        ],
        commands=[
            "python3 -c \""
            "import base64; payload=open('challenge.txt').read().split('payload:',1)[1].strip().split()[0]; "
            "print(base64.b85decode(payload))\"",
            "python3 -c \""
            "import base64, re; "
            "data=open('challenge.txt').read(); "
            "p=re.search(r'payload:\\s*([^\\n]+)', data); "
            "print(base64.b85decode(p.group(1).strip()) if p else 'not found')\"",
        ],
        transforms=["base85-decode", "binary-decode", "reverse", "atbash-decode"],
    ),
]


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

_AI_SYSTEM_PROMPT = (
    "You are an expert CTF solver. You will receive a JSON summary of findings from "
    "automated analysis of a CTF challenge file. Do NOT describe or re-explain what the "
    "JSON contains. Respond with a JSON object only, no prose, no markdown. "
    "The JSON object must have these keys:\n"
    '- "category": the most likely CTF challenge category\n'
    '- "confidence": your confidence as a float 0.0-1.0\n'
    '- "primary_target": the single most suspicious function, string, or artifact to investigate first\n'
    '- "vulnerability_class": the most likely vulnerability or technique required\n'
    '- "attack_steps": an ordered array of concrete steps, each with "step" (int), '
    '"action" (str), and "command" (str or null)\n'
    '- "flag_format_guess": your best guess at the flag format based on any patterns in the findings'
)


class HypothesisEngine:
    """
    Generates ordered attack hypotheses from session findings.

    Usage::

        engine = HypothesisEngine(ai_client=ai_client)
        hypotheses = engine.run(session)
        # generate() is an alias for backward compatibility
    """

    def __init__(self, ai_client=None) -> None:
        self._ai_client = ai_client
        self._fingerprinter = ChallengeFingerprinter()

    def run(self, session: Session) -> List[Hypothesis]:
        """Return an ordered list of Hypothesis objects (highest confidence first)."""
        findings = [f for f in session.findings if f.duplicate_of is None]

        hypotheses: List[Hypothesis] = []

        # Rule-based path (always runs, no API key required)
        hypotheses.extend(self._rule_based(findings))

        # AI-augmented path (runs additionally if API key configured)
        if self._ai_client and self._ai_client.available:
            ai_hyps = self._ai_augmented(findings, session)
            hypotheses.extend(ai_hyps)

        # Fingerprint path (always runs; appended as FINGERPRINT category)
        hypotheses.extend(self._fingerprint(findings))

        # Sort by confidence descending
        hypotheses.sort(key=lambda h: -h.confidence)

        # Deduplicate by title
        seen_titles: set = set()
        unique: List[Hypothesis] = []
        for h in hypotheses:
            if h.title not in seen_titles:
                seen_titles.add(h.title)
                unique.append(h)
        return unique

    def generate(self, session: Session) -> List[Hypothesis]:
        """Alias for run() — retained for backward compatibility."""
        return self.run(session)

    # ------------------------------------------------------------------

    def _rule_based(self, findings: List[Finding]) -> List[Hypothesis]:
        results: List[Hypothesis] = []
        for rule in _RULES:
            try:
                match = rule.match_fn(findings)
            except Exception:
                logger.debug("Rule %r raised an exception", rule.title, exc_info=True)
                continue
            if match is None:
                continue
            confidence, matching_findings = match
            results.append(Hypothesis(
                title=rule.title,
                confidence=confidence,
                category=rule.category,
                present_findings=[f.title for f in matching_findings],
                missing_findings=rule.missing,
                suggested_commands=rule.commands,
                suggested_transforms=rule.transforms,
                source="rules",
            ))
        return results

    # ------------------------------------------------------------------

    def _ai_augmented(
        self,
        findings: List[Finding],
        session: Session,
    ) -> List[Hypothesis]:
        """Call Claude with the CTF-solver system prompt; inject AI hypotheses."""
        top = sorted(
            [f for f in findings if f.confidence >= 0.4],
            key=lambda f: -f.confidence,
        )[:15]

        summary = [
            {
                "title": f.title,
                "severity": f.severity,
                "confidence": round(f.confidence, 2),
                "analyzer": f.analyzer,
                "detail_snippet": f.detail[:200],
                "flag_match": f.flag_match,
            }
            for f in top
        ]

        user_message = json.dumps(summary, indent=2)

        try:
            response = self._ai_client.complete_with_system(
                system_prompt=_AI_SYSTEM_PROMPT,
                user_message=user_message,
            )
        except Exception as exc:
            logger.warning("AI hypothesis call failed: %s", exc)
            return []

        # Strip markdown code fences that models sometimes emit despite instructions.
        # e.g. ```json\n{...}\n``` or ```\n{...}\n```
        clean = _strip_markdown_fences(response)

        # Strict JSON parse — discard silently if still invalid after stripping
        try:
            data = json.loads(clean)
        except (json.JSONDecodeError, TypeError):
            logger.warning(
                "AI response was not valid JSON — discarding. Response preview: %.200s",
                str(response),
            )
            return []

        category = str(data.get("category", "unknown")).lower()
        confidence = float(data.get("confidence", 0.5))
        primary_target = str(data.get("primary_target", ""))
        vuln_class = str(data.get("vulnerability_class", ""))
        flag_fmt = str(data.get("flag_format_guess", ""))

        # Build ordered command list from attack_steps
        commands: List[str] = []
        for step in data.get("attack_steps", []):
            if isinstance(step, dict):
                cmd = step.get("command")
                action = step.get("action", "")
                if cmd:
                    commands.append(f"# Step {step.get('step', '?')}: {action}\n{cmd}")
                elif action:
                    commands.append(f"# {action}")

        reasoning = (
            f"Primary target: {primary_target}\n"
            f"Vulnerability class: {vuln_class}\n"
            f"Flag format guess: {flag_fmt}"
        )

        results: List[Hypothesis] = [
            Hypothesis(
                title=f"AI Analysis: {vuln_class or category}",
                confidence=confidence,
                category=category,
                present_findings=[],
                missing_findings=[],
                suggested_commands=commands,
                suggested_transforms=[],
                source="ai",
                reasoning=reasoning,
            )
        ]
        return results

    # ------------------------------------------------------------------

    def _fingerprint(self, findings: List[Finding]) -> List[Hypothesis]:
        """Run the challenge fingerprinter and return top-3 matches as FINGERPRINT hypotheses."""
        matches = self._fingerprinter.match(findings, top_n=3)
        results: List[Hypothesis] = []
        for match in matches:
            archetype = match["archetype"]
            score = match["score"]
            pct = match["confidence_pct"]
            name = archetype.get("name", "Unknown")
            source = archetype.get("source", "")
            description = archetype.get("description", "")
            transforms = archetype.get("typical_transforms", [])
            category = archetype.get("category", "unknown")
            solve_hint = archetype.get("solve_rate_hint", "")

            reasoning_parts = [description]
            if source:
                reasoning_parts.append(f"Source: {source}")
            if solve_hint:
                reasoning_parts.append(f"Typical solve rate: {solve_hint}")
            reasoning_parts.append(f"Fingerprint confidence: {pct}%")

            results.append(Hypothesis(
                title=f"Fingerprint: {name}",
                confidence=score,
                category="fingerprint",
                present_findings=[],
                missing_findings=[],
                suggested_commands=[],
                suggested_transforms=transforms,
                source="fingerprint",
                reasoning="\n".join(reasoning_parts),
            ))
        return results
