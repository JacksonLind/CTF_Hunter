"""
Crypto analyzer: hash identification, hash cracking, known-plaintext XOR recovery.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import List, Optional

from core.report import Finding
from core.ai_client import AIClient
from core.external import run_strings
from .base import Analyzer

# ---------------------------------------------------------------------------
# Optional bcrypt support
# ---------------------------------------------------------------------------
try:
    import bcrypt as _bcrypt_lib
    _BCRYPT_AVAILABLE = True
except ImportError:
    _BCRYPT_AVAILABLE = False

# ---------------------------------------------------------------------------
# Hash patterns: (name, regex)
# ---------------------------------------------------------------------------
_HASH_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("MD5",    re.compile(r"\b[0-9a-fA-F]{32}\b")),
    ("SHA1",   re.compile(r"\b[0-9a-fA-F]{40}\b")),
    ("SHA256", re.compile(r"\b[0-9a-fA-F]{64}\b")),
    ("SHA512", re.compile(r"\b[0-9a-fA-F]{128}\b")),
    ("bcrypt", re.compile(r"\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}")),
    ("NTLM",   re.compile(r"\b[0-9a-fA-F]{32}\b")),   # same as MD5 length
    ("MySQL",  re.compile(r"\*[0-9A-F]{40}\b")),
    ("Cisco7", re.compile(r"\b(?:[0-9]{2}[0-9a-fA-F]{2})+\b")),
]

# Flag prefixes for known-plaintext XOR
_FLAG_PREFIXES = [b"CTF{", b"flag{", b"HTB{", b"picoCTF{", b"DUCTF{", b"FLAG{"]

# Built-in CTF-common password list
_CTF_PASSWORDS = [
    "ctf", "flag", "password", "secret", "admin", "root", "toor", "pass",
    "1234", "letmein", "infected", "malware", "challenge", "hackme", "solve",
    "12345", "qwerty", "abc123", "test", "guest", "user", "login", "key",
]

# Cisco Type 7 XOR lookup table — standard key sequence used in Cisco IOS
# password obfuscation (not encryption). Fully reversible.
_CISCO7_XLAT = (
    "dsfd;kfoA,.iyewrkldJKDHSUBsgvca69834ncxv9873254k;fg87"
)


# ---------------------------------------------------------------------------
# Hash computation helpers
# ---------------------------------------------------------------------------

def _md5(s: str) -> str:
    return hashlib.md5(s.encode("utf-8", errors="replace")).hexdigest()


def _sha1(s: str) -> str:
    return hashlib.sha1(s.encode("utf-8", errors="replace")).hexdigest()


def _sha256(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8", errors="replace")).hexdigest()


def _sha512(s: str) -> str:
    return hashlib.sha512(s.encode("utf-8", errors="replace")).hexdigest()


def _ntlm(s: str) -> str:
    """NTLM = MD4 of UTF-16LE."""
    raw = s.encode("utf-16-le")
    try:
        h = hashlib.new("md4", raw)
        return h.hexdigest()
    except ValueError:
        pass
    # Pure Python MD4 fallback (minimal implementation)
    return _md4_pure(raw)


def _mysql_hash(s: str) -> str:
    """MySQL password hash: *SHA1(SHA1(password)).upper()"""
    inner = hashlib.sha1(s.encode("utf-8", errors="replace")).digest()
    outer = hashlib.sha1(inner).hexdigest().upper()
    return f"*{outer}"


def _cisco7_decode(encoded: str) -> Optional[str]:
    """Decode Cisco Type 7 encoded password (reversible XOR)."""
    try:
        if len(encoded) < 4 or len(encoded) % 2 != 0:
            return None
        seed = int(encoded[:2])
        cipher_hex = encoded[2:]
        if len(cipher_hex) % 2 != 0:
            return None
        decoded_chars = []
        for i in range(0, len(cipher_hex), 2):
            byte_val = int(cipher_hex[i:i + 2], 16)
            key_byte = ord(_CISCO7_XLAT[(seed + i // 2) % len(_CISCO7_XLAT)])
            decoded_chars.append(chr(byte_val ^ key_byte))
        result = ''.join(decoded_chars)
        if all(0x20 <= ord(c) <= 0x7E for c in result):
            return result
    except Exception:
        pass
    return None


def _md4_pure(data: bytes) -> str:
    """Minimal pure-Python MD4 for NTLM when hashlib doesn't support md4."""
    import struct

    def _f(x, y, z): return (x & y) | (~x & z)
    def _g(x, y, z): return (x & y) | (x & z) | (y & z)
    def _h(x, y, z): return x ^ y ^ z
    def _rol(n, b): return ((n << b) | (n >> (32 - b))) & 0xFFFFFFFF

    msg = bytearray(data)
    msg_len_bits = len(data) * 8
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0)
    msg += struct.pack("<Q", msg_len_bits)

    A, B, C, D = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476

    for i in range(0, len(msg), 64):
        X = list(struct.unpack_from("<16I", msg, i))
        a, b, c, d = A, B, C, D
        for j in range(16):
            a = _rol((a + _f(b, c, d) + X[j]) & 0xFFFFFFFF, [3, 7, 11, 19][j % 4])
            a, b, c, d = d, a, b, c
        for idx, j in enumerate([0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15]):
            a = _rol((a + _g(b, c, d) + X[j] + 0x5A827999) & 0xFFFFFFFF, [3, 5, 9, 13][idx % 4])
            a, b, c, d = d, a, b, c
        for idx, j in enumerate([0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15]):
            a = _rol((a + _h(b, c, d) + X[j] + 0x6ED9EBA1) & 0xFFFFFFFF, [3, 9, 11, 15][idx % 4])
            a, b, c, d = d, a, b, c
        A = (A + a) & 0xFFFFFFFF
        B = (B + b) & 0xFFFFFFFF
        C = (C + c) & 0xFFFFFFFF
        D = (D + d) & 0xFFFFFFFF

    return struct.pack("<4I", A, B, C, D).hex()


# ---------------------------------------------------------------------------
# Wordlist loading
# ---------------------------------------------------------------------------

def _load_bundled_wordlist() -> list[str]:
    """Load the bundled rockyou_top1000.txt wordlist."""
    wl_path = Path(__file__).parent.parent / "wordlists" / "rockyou_top1000.txt"
    try:
        return wl_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except Exception:
        return []


def _load_custom_wordlist() -> list[str]:
    """Load user-configured custom wordlist from settings (config file)."""
    config_path = Path.home() / ".ctf_hunter" / "config.json"
    try:
        if config_path.exists():
            cfg = json.loads(config_path.read_text())
            wl_path = cfg.get("wordlist_path", "").strip()
            if wl_path:
                return Path(wl_path).read_text(encoding="utf-8", errors="replace").splitlines()
    except Exception:
        pass
    return []


# ---------------------------------------------------------------------------
# Analyzer
# ---------------------------------------------------------------------------

class CryptoAnalyzer(Analyzer):
    def analyze(
        self,
        path: str,
        flag_pattern: re.Pattern,
        depth: str,
        ai_client: Optional[AIClient],
        **_kw,
    ) -> List[Finding]:
        findings: List[Finding] = []

        # Extract strings for hash identification and as cracking candidates
        strings = run_strings(path, min_len=16)

        # Hash identification + cracking
        findings.extend(self._identify_and_crack_hashes(path, flag_pattern, strings))

        # Known-plaintext XOR recovery
        if depth == "deep":
            findings.extend(self._xor_known_plaintext(path, flag_pattern))

        return findings

    # ------------------------------------------------------------------

    def _identify_and_crack_hashes(
        self,
        path: str,
        flag_pattern: re.Pattern,
        strings: list[str],
    ) -> List[Finding]:
        findings: List[Finding] = []
        seen: set[str] = set()

        # Strings extracted from this file — also used as cracking candidates
        file_strings = run_strings(path, min_len=4)
        file_candidates = [(s.strip(), "extracted-string") for s in file_strings if s.strip()]

        # Build crack candidate list (wordlist + CTF passwords + file strings)
        bundled = [(w.strip(), "wordlist") for w in _load_bundled_wordlist() if w.strip()]
        custom = [(w.strip(), "custom-wordlist") for w in _load_custom_wordlist() if w.strip()]
        builtin = [(p, "built-in") for p in _CTF_PASSWORDS]
        # Add filename without extension as a candidate
        stem = Path(path).stem
        all_candidates = bundled + custom + builtin + [(stem, "filename")] + file_candidates

        for s in strings:
            for hash_name, pattern in _HASH_PATTERNS:
                for match in pattern.finditer(s):
                    val = match.group()
                    key = f"{hash_name}:{val}"
                    if key in seen:
                        continue
                    seen.add(key)

                    # Cisco Type 7: fully reversible — decode directly
                    if hash_name == "Cisco7":
                        decoded = _cisco7_decode(val)
                        if decoded:
                            findings.append(self._finding(
                                path,
                                "Cisco Type 7 password decoded",
                                f"Encoded: {val}\nDecoded: {decoded}",
                                severity="HIGH",
                                confidence=0.95,
                            ))
                        continue

                    findings.append(self._finding(
                        path,
                        f"Potential {hash_name} hash found",
                        val,
                        severity="MEDIUM",
                        confidence=0.65,
                    ))

                    # Attempt to crack
                    crack_result = self._crack_hash(val, hash_name, all_candidates)
                    if crack_result:
                        plaintext, source = crack_result
                        findings.append(self._finding(
                            path,
                            f"{hash_name} hash cracked",
                            f"Hash: {val}\nPlaintext: {plaintext}\nSource: {source}",
                            severity="HIGH",
                            confidence=0.99,
                        ))

        return findings

    def _crack_hash(
        self,
        hash_val: str,
        hash_name: str,
        candidates: list[tuple[str, str]],
    ) -> Optional[tuple[str, str]]:
        """Try to crack a hash. Returns (plaintext, source) or None."""
        hash_lower = hash_val.lower()

        # bcrypt: use bcrypt library's checkpw
        if hash_name == "bcrypt":
            if _BCRYPT_AVAILABLE:
                for candidate, source in candidates:
                    try:
                        if _bcrypt_lib.checkpw(
                            candidate.encode("utf-8"),
                            hash_val.encode("utf-8"),
                        ):
                            return candidate, source
                    except Exception:
                        continue
            return None

        for candidate, source in candidates:
            if not candidate:
                continue
            # Determine which hash functions to check
            if hash_name == "MD5" and _md5(candidate) == hash_lower:
                return candidate, source
            if hash_name == "SHA1" and _sha1(candidate) == hash_lower:
                return candidate, source
            if hash_name == "SHA256" and _sha256(candidate) == hash_lower:
                return candidate, source
            if hash_name == "SHA512" and _sha512(candidate) == hash_lower:
                return candidate, source
            if hash_name == "NTLM" and _ntlm(candidate) == hash_lower:
                return candidate, source
            if hash_name == "MySQL" and _mysql_hash(candidate) == hash_val.upper():
                return candidate, source
            # MD5 and NTLM share the same length pattern — try both
            if hash_name == "NTLM" and _md5(candidate) == hash_lower:
                return candidate, source

        return None

    def _xor_known_plaintext(self, path: str, flag_pattern: re.Pattern) -> List[Finding]:
        findings: List[Finding] = []
        try:
            data = Path(path).read_bytes()
        except Exception:
            return []

        for prefix in _FLAG_PREFIXES:
            if len(prefix) > len(data):
                continue
            # XOR first N bytes of data with prefix to get candidate key
            candidate_key = bytes(data[i] ^ prefix[i] for i in range(len(prefix)))
            # Try the full decryption with this key (cycled)
            decrypted = bytes(data[i] ^ candidate_key[i % len(candidate_key)] for i in range(len(data)))
            try:
                text = decrypted.decode("utf-8", errors="replace")
            except Exception:
                continue
            if self._check_flag(text, flag_pattern):
                findings.append(self._finding(
                    path,
                    f"Known-plaintext XOR recovery with prefix {prefix!r}",
                    f"Key={candidate_key.hex()}: {text[:300]}",
                    severity="HIGH",
                    flag_match=True,
                    confidence=0.90,
                ))
            elif sum(1 for c in text[:200] if c.isprintable()) / max(len(text[:200]), 1) > 0.85:
                findings.append(self._finding(
                    path,
                    f"Possible XOR decryption with key derived from prefix {prefix!r}",
                    f"Key={candidate_key.hex()}: {text[:200]}",
                    severity="MEDIUM",
                    confidence=0.55,
                ))

        return findings
