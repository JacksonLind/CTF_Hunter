"""
Tool suggester: maps analysis findings to recommended external CTF tools.

After every analysis run, call suggest_tools(findings) to obtain a list of
tool suggestion dicts that can be displayed in the UI.
"""
from __future__ import annotations

import importlib
import shutil
from typing import Callable

from core.report import Finding

# ---------------------------------------------------------------------------
# Tool definitions
# ---------------------------------------------------------------------------

# Each entry: name, install_cmd, usage_template ({filename} is replaced at
# call time with the actual file path being analyzed), and an optional URL.
_TOOL_DEFS: dict[str, dict] = {
    "zsteg": {
        "name": "zsteg",
        "install": "gem install zsteg",
        "usage": "zsteg {filename}",
        "url": "https://github.com/zed-0xff/zsteg",
    },
    "stegsolve": {
        "name": "stegsolve",
        "install": "download from https://github.com/zardus/ctf-tools/tree/master/stegsolve",
        "usage": "java -jar stegsolve.jar",
        "url": "https://github.com/zardus/ctf-tools",
    },
    "stepic": {
        "name": "stepic",
        "install": "pip install stepic",
        "usage": (
            "python -c \"import stepic, PIL.Image; "
            "print(stepic.decode(PIL.Image.open('{filename}')))\""
        ),
        "url": "https://github.com/livitski/stepic",
    },
    "steghide": {
        "name": "steghide",
        "install": "apt install steghide",
        "usage": "steghide extract -sf {filename}",
        "url": "https://steghide.sourceforge.net/",
    },
    "outguess": {
        "name": "outguess",
        "install": "apt install outguess",
        "usage": "outguess -r {filename} out.txt",
        "url": "https://github.com/crorvick/outguess",
    },
    "stegdetect": {
        "name": "stegdetect",
        "install": "apt install stegdetect",
        "usage": "stegdetect {filename}",
        "url": "http://www.outguess.org/detection.php",
    },
    "upx": {
        "name": "upx",
        "install": "apt install upx",
        "usage": "upx -d {filename}",
        "url": "https://upx.github.io/",
    },
    "die": {
        "name": "die (Detect It Easy)",
        "install": "download from https://github.com/horsicq/Detect-It-Easy/releases",
        "usage": "diec {filename}",
        "url": "https://github.com/horsicq/Detect-It-Easy",
    },
    "x64dbg": {
        "name": "x64dbg",
        "install": "download from https://x64dbg.com/",
        "usage": "x64dbg  (load {filename} via File → Open)",
        "url": "https://x64dbg.com/",
    },
    "fcrackzip": {
        "name": "fcrackzip",
        "install": "apt install fcrackzip",
        "usage": "fcrackzip -u -D -p /usr/share/wordlists/rockyou.txt {filename}",
        "url": "http://oldhome.schmorp.de/marc/fcrackzip.html",
    },
    "john": {
        "name": "john (John the Ripper)",
        "install": "apt install john",
        "usage": "john --wordlist=/usr/share/wordlists/rockyou.txt {filename}",
        "url": "https://www.openwall.com/john/",
    },
    "pdf-parser": {
        "name": "pdf-parser",
        "install": "download from https://blog.didierstevens.com/programs/pdf-tools/",
        "usage": "pdf-parser.py {filename}",
        "url": "https://github.com/DidierStevens/DidierStevensSuite",
    },
    "peepdf": {
        "name": "peepdf",
        "install": "pip install peepdf",
        "usage": "peepdf {filename}",
        "url": "https://github.com/jesparza/peepdf",
    },
    "sonic-visualizer": {
        "name": "sonic-visualizer",
        "install": "apt install sonic-visualiser",
        "usage": "sonic-visualiser {filename}",
        "url": "https://www.sonicvisualiser.org/",
    },
    "audacity": {
        "name": "audacity",
        "install": "apt install audacity",
        "usage": "audacity {filename}",
        "url": "https://www.audacityteam.org/",
    },
    "deepsound": {
        "name": "deepsound",
        "install": "download from http://jpinsoft.net/DeepSound/",
        "usage": "DeepSound.exe  (load {filename})",
        "url": "http://jpinsoft.net/DeepSound/",
    },
    "wireshark": {
        "name": "wireshark",
        "install": "apt install wireshark",
        "usage": "wireshark {filename}",
        "url": "https://www.wireshark.org/",
    },
    "tshark": {
        "name": "tshark",
        "install": "apt install tshark",
        "usage": "tshark -r {filename}",
        "url": "https://www.wireshark.org/docs/man-pages/tshark.html",
    },
    "networkminer": {
        "name": "NetworkMiner",
        "install": "download from https://www.netresec.com/?page=NetworkMiner",
        "usage": "NetworkMiner.exe  (load {filename})",
        "url": "https://www.netresec.com/?page=NetworkMiner",
    },
    "quipqiup": {
        "name": "quipqiup",
        "install": "web tool — no install required",
        "usage": "https://quipqiup.com/  (paste cipher text from {filename})",
        "url": "https://quipqiup.com/",
    },
    "dcode": {
        "name": "dcode.fr",
        "install": "web tool — no install required",
        "usage": "https://www.dcode.fr/  (select cipher type, paste content from {filename})",
        "url": "https://www.dcode.fr/",
    },
    "hashcat": {
        "name": "hashcat",
        "install": "apt install hashcat",
        "usage": "hashcat -m 0 {filename} /usr/share/wordlists/rockyou.txt",
        "url": "https://hashcat.net/hashcat/",
    },
    "crackstation": {
        "name": "crackstation",
        "install": "web tool — no install required",
        "usage": "https://crackstation.net/  (paste hash from {filename})",
        "url": "https://crackstation.net/",
    },
    "netcat": {
        "name": "netcat",
        "install": "apt install netcat",
        "usage": "nc <host> <port>",
        "url": "https://nc110.sourceforge.io/",
    },
    "pwntools": {
        "name": "pwntools",
        "install": "pip install pwntools",
        "usage": (
            "python -c \"from pwn import *; "
            "r = remote('<host>', <port>); r.interactive()\""
        ),
        "url": "https://github.com/Gallopsled/pwntools",
    },
    "telnet": {
        "name": "telnet",
        "install": "apt install telnet",
        "usage": "telnet <host> <port>",
        "url": "https://en.wikipedia.org/wiki/Telnet",
    },
}

# ---------------------------------------------------------------------------
# Binary names used to check if a tool is installed via shutil.which()
# None means the tool is checked via importlib or is a web-only tool.
# ---------------------------------------------------------------------------

_BINARY_NAMES: dict[str, str | None] = {
    "zsteg":           "zsteg",
    "stegsolve":       None,            # GUI jar — no reliable PATH check
    "stepic":          None,            # pip package
    "steghide":        "steghide",
    "outguess":        "outguess",
    "stegdetect":      "stegdetect",
    "upx":             "upx",
    "die":             "diec",          # CLI frontend of Detect It Easy
    "x64dbg":          "x64dbg",
    "fcrackzip":       "fcrackzip",
    "john":            "john",
    "pdf-parser":      "pdf-parser.py",
    "peepdf":          None,            # pip package
    "sonic-visualizer": "sonic-visualiser",
    "audacity":        "audacity",
    "deepsound":       None,            # Windows GUI only
    "wireshark":       "wireshark",
    "tshark":          "tshark",
    "networkminer":    None,            # Windows GUI only
    "quipqiup":        None,            # web tool
    "dcode":           None,            # web tool
    "hashcat":         "hashcat",
    "crackstation":    None,            # web tool
    "netcat":          "nc",
    "pwntools":        None,            # pip package
    "telnet":          "telnet",
}

# pip/importlib package names for tools that cannot be found via which()
_PIP_MODULES: dict[str, str] = {
    "stepic":   "stepic",
    "peepdf":   "peepdf",
    "pwntools": "pwn",
}

# ---------------------------------------------------------------------------
# Signature mapping: (predicate, reason_template, [tool_keys])
# ---------------------------------------------------------------------------

_Predicate = Callable[[Finding], bool]

_SIGNATURES: list[tuple[_Predicate, str, list[str]]] = [
    # LSB anomaly (image or generic, not audio)
    (
        lambda f: (
            "lsb" in f.title.lower()
            and "AudioAnalyzer" not in f.analyzer
        ),
        "LSB steganography anomaly detected in image",
        ["zsteg", "stegsolve", "stepic"],
    ),
    # JPEG DCT anomaly
    (
        lambda f: "dct" in f.title.lower(),
        "JPEG DCT coefficient anomaly detected — JSteg / OutGuess indicator",
        ["steghide", "outguess", "stegdetect"],
    ),
    # High-entropy ELF / PE section
    (
        lambda f: (
            "entropy" in f.title.lower()
            and f.analyzer in ("BinaryAnalyzer", "GenericAnalyzer", "DisassemblyAnalyzer")
        ),
        "High-entropy ELF/PE section detected — possible packer or obfuscation",
        ["upx", "die", "x64dbg"],
    ),
    # ZIP encrypted entries
    (
        lambda f: (
            "encrypted zip" in f.title.lower()
            or (
                "encrypted" in f.title.lower()
                and f.analyzer == "ArchiveAnalyzer"
            )
        ),
        "Encrypted ZIP entries detected — password cracking may reveal contents",
        ["fcrackzip", "john"],
    ),
    # PDF streams
    (
        lambda f: (
            f.analyzer == "DocumentAnalyzer"
            and (
                "stream" in f.title.lower()
                or "pdf" in f.title.lower()
            )
        ),
        "PDF stream content detected — may contain embedded or obfuscated data",
        ["pdf-parser", "peepdf"],
    ),
    # Audio steganography
    (
        lambda f: (
            f.analyzer in ("AudioAnalyzer", "SteganalysisAnalyzer")
            and any(
                ext in (f.file or "").lower()
                for ext in (".wav", ".mp3", ".flac", ".ogg", ".aiff", ".aif")
            )
        ),
        "Audio steganography anomaly detected",
        ["sonic-visualizer", "audacity", "deepsound"],
    ),
    # PCAP / network capture
    (
        lambda f: f.analyzer == "PcapAnalyzer",
        "Network packet capture finding — inspect with packet analysis tools",
        ["wireshark", "tshark", "networkminer"],
    ),
    # Classical cipher
    (
        lambda f: any(
            kw in f.title.lower() or kw in f.detail.lower()
            for kw in (
                "caesar", "rot13", "rot-13", "vigenere", "vigenère",
                "substitution cipher", "classical cipher", "atbash",
                "rail fence", "playfair",
            )
        ),
        "Classical cipher pattern detected",
        ["quipqiup", "dcode"],
    ),
    # Hash identified
    (
        lambda f: (
            "hash" in f.title.lower()
            and f.analyzer in ("CryptoAnalyzer", "GenericAnalyzer")
        ),
        "Hash value identified — try cracking it with offline or online tools",
        ["hashcat", "john", "crackstation"],
    ),
    # Network service
    (
        lambda f: any(
            kw in f.title.lower()
            for kw in (
                "network service", "open port", "listening port",
                "tcp connection", "udp service",
            )
        ),
        "Network service detected — interact with it using connection tools",
        ["netcat", "pwntools", "telnet"],
    ),
]


# ---------------------------------------------------------------------------
# Installed-tool check (cached per-process)
# ---------------------------------------------------------------------------

_install_cache: dict[str, bool] = {}


def _check_installed(tool_key: str) -> bool:
    """Return True if the tool appears to be installed on the current system."""
    if tool_key in _install_cache:
        return _install_cache[tool_key]

    binary = _BINARY_NAMES.get(tool_key)
    if binary is not None:
        result = shutil.which(binary) is not None
    elif tool_key in _PIP_MODULES:
        try:
            importlib.import_module(_PIP_MODULES[tool_key])
            result = True
        except ImportError:
            result = False
    else:
        # web tool or GUI-only — never considered "installed"
        result = False

    _install_cache[tool_key] = result
    return result


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def suggest_tools(findings: list[Finding]) -> list[dict]:
    """
    Match *findings* against known CTF-tool signatures and return a
    deduplicated list of tool suggestion dicts.

    Each dict contains:
      tool_key      – internal key used in _TOOL_DEFS
      tool_name     – human-readable tool name
      install_cmd   – how to install the tool
      usage_example – pre-filled command using the actual filename
      url           – project / download URL
      reason        – why the tool was suggested
      finding_title – title of the triggering finding
      finding_id    – UUID of the triggering finding
      installed     – True if the tool is already available on this system
    """
    suggested: dict[str, dict] = {}  # tool_key → suggestion dict

    for finding in findings:
        if finding.duplicate_of:
            continue
        for predicate, reason, tool_keys in _SIGNATURES:
            try:
                if not predicate(finding):
                    continue
            except Exception:
                continue

            filename = finding.file or ""
            for tool_key in tool_keys:
                if tool_key in suggested:
                    continue  # already registered from a higher-priority finding
                tool_def = _TOOL_DEFS.get(tool_key)
                if tool_def is None:
                    continue
                usage = tool_def["usage"].replace("{filename}", filename)
                suggested[tool_key] = {
                    "tool_key": tool_key,
                    "tool_name": tool_def["name"],
                    "install_cmd": tool_def["install"],
                    "usage_example": usage,
                    "url": tool_def.get("url", ""),
                    "reason": reason,
                    "finding_title": finding.title,
                    "finding_id": finding.id,
                    "installed": _check_installed(tool_key),
                }

    return list(suggested.values())
