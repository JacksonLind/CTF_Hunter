"""
External tool availability probing and subprocess wrappers.
Provides graceful Python fallbacks for: exiftool, binwalk, strings, file, tshark.
"""
from __future__ import annotations

import re
import shutil
import subprocess
import struct
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Availability probe
# ---------------------------------------------------------------------------

_TOOLS: dict[str, Optional[str]] = {}


def probe_tools() -> dict[str, Optional[str]]:
    """Return dict mapping tool names to their paths (or None if missing)."""
    global _TOOLS
    for name in ("exiftool", "binwalk", "strings", "file", "tshark"):
        _TOOLS[name] = shutil.which(name)
    return _TOOLS


def is_available(name: str) -> bool:
    if not _TOOLS:
        probe_tools()
    return _TOOLS.get(name) is not None


# ---------------------------------------------------------------------------
# exiftool wrapper / Pillow fallback
# ---------------------------------------------------------------------------

def run_exiftool(path: str) -> dict[str, str]:
    """Extract metadata using exiftool; fall back to Pillow/mutagen."""
    if is_available("exiftool"):
        try:
            out = subprocess.check_output(
                ["exiftool", "-j", path],
                stderr=subprocess.DEVNULL,
                timeout=30,
            )
            import json
            data = json.loads(out.decode("utf-8", errors="replace"))
            return data[0] if isinstance(data, list) and data else {}
        except Exception:
            pass
    # Pillow fallback for images
    try:
        from PIL import Image
        from PIL.ExifTags import TAGS
        img = Image.open(path)
        exif_data = img.getexif()
        if exif_data:
            return {TAGS.get(k, str(k)): str(v) for k, v in exif_data.items()}
        info = img.info or {}
        return {str(k): str(v) for k, v in info.items()}
    except Exception:
        pass
    # mutagen fallback for audio
    try:
        import mutagen
        audio = mutagen.File(path)
        if audio:
            return {str(k): str(v) for k, v in audio.tags.items()} if audio.tags else {}
    except Exception:
        pass
    return {}


# ---------------------------------------------------------------------------
# binwalk wrapper / custom magic scanner fallback
# ---------------------------------------------------------------------------

_MAGIC_SIGS = [
    (b"\x89PNG\r\n\x1a\n", "PNG image"),
    (b"\xff\xd8\xff", "JPEG image"),
    (b"GIF87a", "GIF87 image"),
    (b"GIF89a", "GIF89 image"),
    (b"PK\x03\x04", "ZIP archive"),
    (b"\x1f\x8b", "gzip archive"),
    (b"BZh", "bzip2 archive"),
    (b"\xfd7zXZ\x00", "XZ archive"),
    (b"RIFF", "RIFF file"),
    (b"ID3", "MP3/ID3"),
    (b"\x7fELF", "ELF binary"),
    (b"MZ", "PE/DOS executable"),
    (b"%PDF", "PDF document"),
    (b"SQLite format 3", "SQLite database"),
    (b"OggS", "OGG container"),
]


def run_binwalk(path: str) -> list[dict]:
    """Find embedded files/signatures; fall back to pure Python scanner."""
    if is_available("binwalk"):
        try:
            out = subprocess.check_output(
                ["binwalk", path],
                stderr=subprocess.DEVNULL,
                timeout=60,
            )
            results = []
            for line in out.decode("utf-8", errors="replace").splitlines():
                parts = line.split(None, 2)
                if len(parts) == 3 and parts[0].isdigit():
                    try:
                        results.append({
                            "offset": int(parts[0]),
                            "hex_offset": parts[1],
                            "description": parts[2],
                        })
                    except ValueError:
                        pass
            return results
        except Exception:
            pass
    # Pure Python fallback
    results = []
    try:
        data = Path(path).read_bytes()
        for sig, desc in _MAGIC_SIGS:
            start = 0
            while True:
                idx = data.find(sig, start)
                if idx == -1:
                    break
                results.append({
                    "offset": idx,
                    "hex_offset": hex(idx),
                    "description": desc,
                })
                start = idx + 1
    except Exception:
        pass
    return results


# ---------------------------------------------------------------------------
# strings wrapper / pure Python fallback
# ---------------------------------------------------------------------------

def run_strings(path: str, min_len: int = 4) -> list[str]:
    """Extract printable strings; fall back to pure Python."""
    if is_available("strings"):
        try:
            out = subprocess.check_output(
                ["strings", "-n", str(min_len), path],
                stderr=subprocess.DEVNULL,
                timeout=30,
            )
            return out.decode("utf-8", errors="replace").splitlines()
        except Exception:
            pass
    # Pure Python fallback
    try:
        data = Path(path).read_bytes()
        return _extract_strings_python(data, min_len)
    except Exception:
        return []


def _extract_strings_python(data: bytes, min_len: int = 4) -> list[str]:
    results = []
    current = []
    for byte in data:
        if 0x20 <= byte <= 0x7E:
            current.append(chr(byte))
        else:
            if len(current) >= min_len:
                results.append("".join(current))
            current = []
    if len(current) >= min_len:
        results.append("".join(current))
    return results


# ---------------------------------------------------------------------------
# file (MIME) wrapper / python-magic fallback
# ---------------------------------------------------------------------------

def run_file(path: str) -> str:
    """Get file type description; fall back to python-magic then extension."""
    if is_available("file"):
        try:
            out = subprocess.check_output(
                ["file", "--mime-type", "-b", path],
                stderr=subprocess.DEVNULL,
                timeout=10,
            )
            return out.decode().strip()
        except Exception:
            pass
    try:
        import magic
        return magic.from_file(path, mime=True)
    except Exception:
        pass
    # Extension guess
    ext_map = {
        ".png": "image/png",
        ".jpg": "image/jpeg",
        ".jpeg": "image/jpeg",
        ".gif": "image/gif",
        ".bmp": "image/bmp",
        ".wav": "audio/wav",
        ".mp3": "audio/mpeg",
        ".zip": "application/zip",
        ".pdf": "application/pdf",
        ".elf": "application/x-elf",
        ".exe": "application/x-dosexec",
        ".txt": "text/plain",
        ".pcap": "application/vnd.tcpdump.pcap",
        ".pcapng": "application/vnd.tcpdump.pcap",
        ".sqlite": "application/x-sqlite3",
        ".db": "application/x-sqlite3",
    }
    suffix = Path(path).suffix.lower()
    return ext_map.get(suffix, "application/octet-stream")


# ---------------------------------------------------------------------------
# tshark wrapper (scapy used directly in pcap analyzer as primary)
# ---------------------------------------------------------------------------

def run_tshark(path: str, fields: list[str] | None = None) -> list[dict]:
    """Extract packet fields via tshark; returns list of field dicts."""
    if not is_available("tshark"):
        return []
    try:
        field_args: list[str] = []
        for f in (fields or ["frame.number", "ip.src", "ip.dst", "_ws.col.Protocol"]):
            field_args += ["-e", f]
        out = subprocess.check_output(
            ["tshark", "-r", path, "-T", "fields"] + field_args,
            stderr=subprocess.DEVNULL,
            timeout=60,
        )
        results = []
        keys = fields or ["frame.number", "ip.src", "ip.dst", "protocol"]
        for line in out.decode("utf-8", errors="replace").splitlines():
            parts = line.split("\t")
            if len(parts) == len(keys):
                results.append(dict(zip(keys, parts)))
        return results
    except Exception:
        return []
