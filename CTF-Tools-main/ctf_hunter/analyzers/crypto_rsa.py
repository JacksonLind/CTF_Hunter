"""
RSA Crypto Analyzer for CTF Hunter.

Detects and attempts the following attacks:
  - Small public exponent attacks (e=3, Håstad broadcast)
  - Common modulus attack (multiple public keys share N)
  - Wiener's attack (small private exponent via continued fractions)
  - LSB oracle simulation hint (flag if ciphertext + public key present)
  - Factor database lookup via factordb.com API (timeout 5s)

Outputs recovered plaintext as a finding if any attack succeeds; otherwise
outputs a structured diagnosis (key size, e value, factor status) as INFO findings.

Integrates into the dispatcher for files containing PEM blocks, DER headers, or
RSA-shaped integer pairs extracted by the generic analyzer.
"""
from __future__ import annotations

import logging
import math
import re
import struct
from typing import List, Optional, Tuple

from core.report import Finding
from core.ai_client import AIClient
from .base import Analyzer

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Optional imports — graceful degradation
# ---------------------------------------------------------------------------
try:
    from Crypto.PublicKey import RSA as _PyCryptoRSA
    _PYCRYPTO_AVAILABLE = True
except ImportError:
    _PYCRYPTO_AVAILABLE = False
    logger.warning("pycryptodome not installed; RSA key parsing will use fallback parser.")

try:
    import urllib.request as _urllib_request
    import json as _json_mod
    _HTTP_AVAILABLE = True
except ImportError:
    _HTTP_AVAILABLE = False

# ---------------------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------------------
_PEM_RE = re.compile(
    rb"-----BEGIN ([A-Z ]+)-----\s*([\s\S]+?)\s*-----END [A-Z ]+-----"
)
_LARGE_INT_RE = re.compile(r"(?:0x[0-9a-fA-F]{32,})|(?:[0-9]{40,})")

# Factordb API endpoint
_FACTORDB_URL = "http://factordb.com/api?query={}"
_FACTORDB_TIMEOUT = 5


# ---------------------------------------------------------------------------
# ASN.1 / DER minimal parser for RSA public/private key extraction
# ---------------------------------------------------------------------------

def _parse_asn1_length(data: bytes, pos: int) -> Tuple[int, int]:
    """Parse ASN.1 DER length field; returns (length, new_pos)."""
    if pos >= len(data):
        raise ValueError("Truncated ASN.1 data")
    b = data[pos]
    pos += 1
    if b < 0x80:
        return b, pos
    n_bytes = b & 0x7F
    if pos + n_bytes > len(data):
        raise ValueError("Truncated ASN.1 length")
    length = int.from_bytes(data[pos:pos + n_bytes], "big")
    return length, pos + n_bytes


def _parse_asn1_integer(data: bytes, pos: int) -> Tuple[int, int]:
    """Parse an ASN.1 INTEGER; returns (value, new_pos)."""
    if data[pos] != 0x02:
        raise ValueError(f"Expected INTEGER tag 0x02, got 0x{data[pos]:02x}")
    pos += 1
    length, pos = _parse_asn1_length(data, pos)
    raw = data[pos:pos + length]
    value = int.from_bytes(raw, "big")
    return value, pos + length


def _extract_rsa_from_der(der: bytes) -> Optional[dict]:
    """
    Attempt to extract RSA parameters (n, e, d, p, q) from raw DER bytes.
    Returns a dict with whatever was found, or None on failure.
    """
    try:
        pos = 0
        if der[pos] != 0x30:
            return None
        pos += 1
        _, pos = _parse_asn1_length(der, pos)

        params = {}
        names = ["version", "n", "e", "d", "p", "q", "dp", "dq", "qp"]
        idx = 0
        while pos < len(der) and idx < len(names):
            if der[pos] == 0x02:
                val, pos = _parse_asn1_integer(der, pos)
                params[names[idx]] = val
                idx += 1
            else:
                break
        if "n" in params and "e" in params:
            return params
    except Exception:
        pass
    return None


def _extract_rsa_from_pem(pem_data: bytes) -> List[dict]:
    """Extract all RSA keys from PEM blocks in data."""
    import base64
    keys = []
    for m in _PEM_RE.finditer(pem_data):
        label = m.group(1).decode("ascii", errors="replace")
        b64 = re.sub(rb"\s+", b"", m.group(2))
        try:
            der = base64.b64decode(b64)
        except Exception:
            continue

        if _PYCRYPTO_AVAILABLE:
            try:
                key = _PyCryptoRSA.import_key(m.group(0))
                params = {"n": key.n, "e": key.e}
                if key.has_private():
                    params["d"] = key.d
                    if hasattr(key, "p"):
                        params["p"] = key.p
                    if hasattr(key, "q"):
                        params["q"] = key.q
                keys.append(params)
                continue
            except Exception:
                pass

        # Fallback: try our minimal DER parser
        result = _extract_rsa_from_der(der)
        if result:
            result["label"] = label
            keys.append(result)

    return keys


# ---------------------------------------------------------------------------
# Continued fractions (Wiener's attack)
# ---------------------------------------------------------------------------

def _continued_fraction(n: int, d: int) -> List[int]:
    """Return the continued fraction expansion of n/d."""
    cf = []
    while d:
        q, r = divmod(n, d)
        cf.append(q)
        n, d = d, r
    return cf


def _convergents(cf: List[int]) -> List[Tuple[int, int]]:
    """Return the convergents of a continued fraction."""
    convs = []
    p_prev, p_curr = 1, cf[0]
    q_prev, q_curr = 0, 1
    convs.append((p_curr, q_curr))
    for i in range(1, len(cf)):
        p_prev, p_curr = p_curr, cf[i] * p_curr + p_prev
        q_prev, q_curr = q_curr, cf[i] * q_curr + q_prev
        convs.append((p_curr, q_curr))
    return convs


def _isqrt(n: int) -> int:
    if n < 0:
        raise ValueError("Square root not defined for negative numbers")
    if n == 0:
        return 0
    x = n
    y = (x + 1) // 2
    while y < x:
        x = y
        y = (x + n // x) // 2
    return x


def _wiener_attack(n: int, e: int) -> Optional[int]:
    """
    Wiener's attack on RSA.  Returns private exponent d if the attack succeeds,
    otherwise None.
    """
    cf = _continued_fraction(e, n)
    for k, d in _convergents(cf):
        if k == 0:
            continue
        phi_candidate, rem = divmod(e * d - 1, k)
        if rem != 0:
            continue
        # Check if phi_candidate gives integer p, q
        # n = p*q, p+q = n - phi + 1, p*q = n
        b = n - phi_candidate + 1
        discriminant = b * b - 4 * n
        if discriminant < 0:
            continue
        sqrt_disc = _isqrt(discriminant)
        if sqrt_disc * sqrt_disc == discriminant:
            return d
    return None


# ---------------------------------------------------------------------------
# Cube root (for small e=3 attacks without ciphertext broadcast)
# ---------------------------------------------------------------------------

def _integer_cube_root(n: int) -> Optional[int]:
    """
    Return integer cube root of n if it's a perfect cube, else None.
    Uses Newton's method for exact integer arithmetic (handles large integers).
    """
    if n <= 0:
        return None
    # Newton's method for integer cube root
    x = n
    y = (2 * x + n // (x * x)) // 3
    while y < x:
        x = y
        y = (2 * x + n // (x * x)) // 3
    # Check neighbours due to rounding
    for candidate in [x - 1, x, x + 1]:
        if candidate > 0 and candidate ** 3 == n:
            return candidate
    return None


def _hastad_broadcast(ciphertexts: List[int], moduli: List[int]) -> Optional[int]:
    """
    Håstad's broadcast attack for e=3.
    Given 3 ciphertexts and 3 different moduli all with e=3,
    use CRT to find m^3 mod (N1*N2*N3), then take cube root.
    Returns plaintext integer or None.
    """
    if len(ciphertexts) < 3 or len(moduli) < 3:
        return None
    # Only use first 3
    c = ciphertexts[:3]
    n = moduli[:3]

    # CRT
    N = n[0] * n[1] * n[2]
    try:
        result = 0
        for i in range(3):
            Ni = N // n[i]
            # Modular inverse of Ni mod n[i]
            inv = pow(Ni, -1, n[i])
            result = (result + c[i] * Ni * inv) % N
    except Exception:
        return None

    return _integer_cube_root(result)


# ---------------------------------------------------------------------------
# Common modulus attack
# ---------------------------------------------------------------------------

def _extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
    """Extended Euclidean algorithm; returns (gcd, x, y) such that a*x + b*y = gcd."""
    if a == 0:
        return b, 0, 1
    g, x, y = _extended_gcd(b % a, a)
    return g, y - (b // a) * x, x


def _common_modulus_attack(
    n: int, e1: int, e2: int, c1: int, c2: int
) -> Optional[int]:
    """
    Common modulus attack: same message encrypted with same N but different e.
    Returns plaintext integer or None.
    """
    g, u, v = _extended_gcd(e1, e2)
    if g != 1:
        return None
    try:
        # m = c1^u * c2^v mod n  (handle negative exponents via modular inverse)
        if u < 0:
            c1_inv = pow(c1, -1, n)
            part1 = pow(c1_inv, -u, n)
        else:
            part1 = pow(c1, u, n)
        if v < 0:
            c2_inv = pow(c2, -1, n)
            part2 = pow(c2_inv, -v, n)
        else:
            part2 = pow(c2, v, n)
        return (part1 * part2) % n
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Factordb lookup
# ---------------------------------------------------------------------------

def _factordb_lookup(n: int) -> Optional[List[int]]:
    """
    Query factordb.com for the factorization of n.
    Returns a list of prime factors if fully factored, else None.
    """
    if not _HTTP_AVAILABLE:
        return None
    try:
        url = _FACTORDB_URL.format(n)
        req = _urllib_request.Request(
            url,
            headers={"User-Agent": "CTFHunter/1.0"},
        )
        with _urllib_request.urlopen(req, timeout=_FACTORDB_TIMEOUT) as resp:
            data = _json_mod.loads(resp.read().decode("utf-8", errors="replace"))
        status = data.get("status", "")
        if status in ("FF", "P", "Prp"):
            factors_raw = data.get("factors", [])
            factors = []
            for item in factors_raw:
                val = int(item[0])
                exp = item[1] if len(item) > 1 else 1
                factors.extend([val] * exp)
            return factors if factors else None
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# Plaintext to bytes helper
# ---------------------------------------------------------------------------

def _int_to_bytes(n: int) -> bytes:
    if n == 0:
        return b"\x00"
    length = (n.bit_length() + 7) // 8
    return n.to_bytes(length, "big")


def _try_decode_plaintext(n: int) -> str:
    """Try to decode an integer as a UTF-8 string."""
    try:
        raw = _int_to_bytes(n)
        return raw.decode("utf-8", errors="replace")
    except Exception:
        return hex(n)


# ---------------------------------------------------------------------------
# Analyzer
# ---------------------------------------------------------------------------

class CryptoRSAAnalyzer(Analyzer):
    """
    RSA attack suite: small-e attacks, Wiener, common modulus,
    LSB oracle hint, and factordb lookup.
    """

    def analyze(
        self,
        path: str,
        flag_pattern: re.Pattern,
        depth: str,
        ai_client: Optional[AIClient],
        **_kw,
    ) -> List[Finding]:
        findings: List[Finding] = []

        try:
            raw = open(path, "rb").read()
        except Exception:
            return []

        # Extract all RSA keys from PEM blocks
        pem_keys = _extract_rsa_from_pem(raw)

        # Extract large integers from the file (for textual challenge files)
        text_ints = self._extract_large_ints(raw)

        if not pem_keys and not text_ints:
            return []

        # Diagnose each PEM key
        for key in pem_keys:
            findings.extend(self._diagnose_key(path, key, flag_pattern, depth, raw))

        # Multi-key attacks
        if len(pem_keys) >= 2:
            findings.extend(
                self._multi_key_attacks(path, pem_keys, flag_pattern, raw)
            )

        # Text-extracted large integer analysis
        if text_ints and not pem_keys:
            findings.extend(
                self._analyze_text_ints(path, text_ints, flag_pattern, depth)
            )

        return findings

    # ------------------------------------------------------------------
    # Per-key diagnosis
    # ------------------------------------------------------------------

    def _diagnose_key(
        self,
        path: str,
        key: dict,
        flag_pattern: re.Pattern,
        depth: str,
        raw: bytes,
    ) -> List[Finding]:
        findings: List[Finding] = []
        n = key.get("n", 0)
        e = key.get("e", 65537)
        d = key.get("d")
        label = key.get("label", "RSA key")

        if not n:
            return []

        key_bits = n.bit_length()

        # Basic diagnosis finding
        diag = (
            f"Label: {label}\n"
            f"Key size: {key_bits} bits\n"
            f"Public exponent e: {e}\n"
            f"Has private key: {'yes' if d else 'no'}"
        )
        findings.append(self._finding(
            path,
            f"RSA key detected ({key_bits}-bit, e={e})",
            diag,
            severity="MEDIUM",
            confidence=0.75,
        ))

        # Small e attacks
        if e == 3:
            findings.extend(self._small_e_attack(path, n, e, raw, flag_pattern))

        # Wiener's attack (effective when e is large and d is small)
        if key_bits >= 512:
            d_wiener = _wiener_attack(n, e)
            if d_wiener is not None:
                findings.append(self._finding(
                    path,
                    "Wiener's attack: small private exponent recovered",
                    f"Recovered d = {d_wiener}\n(key is vulnerable to Wiener's attack)",
                    severity="HIGH",
                    confidence=0.90,
                ))

        # Factordb lookup
        if depth == "deep" or key_bits <= 512:
            factors = _factordb_lookup(n)
            if factors and len(factors) >= 2:
                p, q = factors[0], factors[1]
                phi = (p - 1) * (q - 1)
                try:
                    d_from_factors = pow(e, -1, phi)
                    findings.append(self._finding(
                        path,
                        "RSA factored via factordb.com",
                        f"p = {p}\nq = {q}\nRecovered d = {d_from_factors}",
                        severity="HIGH",
                        confidence=0.95,
                    ))
                    # Try to decrypt any ciphertext found in the file
                    ct = self._extract_ciphertext(raw, n)
                    if ct is not None:
                        m = pow(ct, d_from_factors, n)
                        plaintext = _try_decode_plaintext(m)
                        fm = self._check_flag(plaintext, flag_pattern)
                        findings.append(self._finding(
                            path,
                            "RSA plaintext recovered (factordb factors)",
                            f"Plaintext: {plaintext[:500]}",
                            severity="HIGH" if fm else "MEDIUM",
                            flag_match=fm,
                            confidence=0.92 if fm else 0.75,
                        ))
                except Exception:
                    pass
            else:
                findings.append(self._finding(
                    path,
                    "RSA modulus: not found in factordb",
                    f"N ({key_bits}-bit) was not factored by factordb.com",
                    severity="INFO",
                    confidence=0.5,
                ))

        # LSB oracle hint
        if n % 2 == 0 and e > 0:
            ct = self._extract_ciphertext(raw, n)
            if ct is not None:
                findings.append(self._finding(
                    path,
                    "LSB oracle vulnerability hint",
                    (
                        "Even modulus detected with ciphertext present.\n"
                        "LSB oracle attack may be applicable if a decryption oracle is available."
                    ),
                    severity="MEDIUM",
                    confidence=0.65,
                ))

        return findings

    # ------------------------------------------------------------------
    # Small-e / Cube root attack
    # ------------------------------------------------------------------

    def _small_e_attack(
        self,
        path: str,
        n: int,
        e: int,
        raw: bytes,
        flag_pattern: re.Pattern,
    ) -> List[Finding]:
        findings: List[Finding] = []
        ct = self._extract_ciphertext(raw, n)
        if ct is None:
            findings.append(self._finding(
                path,
                "RSA small exponent (e=3) — no ciphertext found",
                "File has e=3 key but no ciphertext was found for cube root attack.",
                severity="INFO",
                confidence=0.5,
            ))
            return findings

        # Try direct cube root (works when m^3 < n, i.e., no modular reduction)
        root = _integer_cube_root(ct)
        if root is not None:
            plaintext = _try_decode_plaintext(root)
            fm = self._check_flag(plaintext, flag_pattern)
            findings.append(self._finding(
                path,
                "RSA cube root attack succeeded (e=3, small message)",
                f"Plaintext: {plaintext[:500]}",
                severity="HIGH" if fm else "MEDIUM",
                flag_match=fm,
                confidence=0.88 if fm else 0.70,
            ))

        return findings

    # ------------------------------------------------------------------
    # Multi-key attacks
    # ------------------------------------------------------------------

    def _multi_key_attacks(
        self,
        path: str,
        keys: List[dict],
        flag_pattern: re.Pattern,
        raw: bytes,
    ) -> List[Finding]:
        findings: List[Finding] = []

        # Common modulus attack (same N, different e, different ciphertext)
        # NOTE: This attack requires two *distinct* ciphertexts of the same
        # plaintext encrypted under different exponents with the same modulus.
        # When only one ciphertext is available in the file we report the
        # vulnerability as an INFO/MEDIUM diagnostic instead of attempting
        # the attack (which would be ineffective with c1 == c2).
        seen_n: dict[int, List[dict]] = {}
        for k in keys:
            n = k.get("n", 0)
            if n:
                seen_n.setdefault(n, []).append(k)

        for n, key_group in seen_n.items():
            if len(key_group) >= 2:
                k1, k2 = key_group[0], key_group[1]
                e1, e2 = k1.get("e", 0), k2.get("e", 0)
                if e1 and e2 and e1 != e2:
                    c1 = k1.get("ciphertext") or self._extract_ciphertext(raw, n)
                    c2 = k2.get("ciphertext")
                    if c1 and c2 and c1 != c2:
                        # Distinct ciphertexts available — attempt the attack
                        m = _common_modulus_attack(n, e1, e2, c1, c2)
                        if m is not None:
                            plaintext = _try_decode_plaintext(m)
                            fm = self._check_flag(plaintext, flag_pattern)
                            findings.append(self._finding(
                                path,
                                "Common modulus attack succeeded",
                                f"e1={e1}, e2={e2}\nPlaintext: {plaintext[:500]}",
                                severity="HIGH" if fm else "MEDIUM",
                                flag_match=fm,
                                confidence=0.85 if fm else 0.65,
                            ))
                    else:
                        # Only one ciphertext — report as vulnerability finding
                        findings.append(self._finding(
                            path,
                            "Common modulus vulnerability detected",
                            (
                                f"Multiple keys share N ({n.bit_length()}-bit) "
                                f"with e1={e1}, e2={e2}. "
                                "Provide two distinct ciphertexts to attempt decryption."
                            ),
                            severity="MEDIUM",
                            confidence=0.70,
                        ))

        # Håstad broadcast attack (3+ keys with e=3)
        e3_keys = [k for k in keys if k.get("e") == 3 and k.get("n")]
        if len(e3_keys) >= 3:
            moduli = [k["n"] for k in e3_keys[:3]]
            ciphertexts = [self._extract_ciphertext(raw, k["n"]) for k in e3_keys[:3]]
            if all(c is not None for c in ciphertexts):
                m = _hastad_broadcast(ciphertexts, moduli)
                if m is not None:
                    plaintext = _try_decode_plaintext(m)
                    fm = self._check_flag(plaintext, flag_pattern)
                    findings.append(self._finding(
                        path,
                        "Håstad broadcast attack succeeded (e=3, 3 ciphertexts)",
                        f"Plaintext: {plaintext[:500]}",
                        severity="HIGH" if fm else "MEDIUM",
                        flag_match=fm,
                        confidence=0.90 if fm else 0.72,
                    ))

        return findings

    # ------------------------------------------------------------------
    # Text integer analysis
    # ------------------------------------------------------------------

    def _analyze_text_ints(
        self,
        path: str,
        ints: List[int],
        flag_pattern: re.Pattern,
        depth: str,
    ) -> List[Finding]:
        findings: List[Finding] = []
        large = [v for v in ints if v.bit_length() >= 128]
        if not large:
            return []

        # Heuristically treat the largest integer as a possible modulus
        n = max(large)
        findings.append(self._finding(
            path,
            f"Large integer found — possible RSA modulus ({n.bit_length()} bits)",
            f"Value (hex): {hex(n)[:80]}…",
            severity="INFO",
            confidence=0.45,
        ))

        if depth == "deep":
            factors = _factordb_lookup(n)
            if factors and len(factors) >= 2:
                findings.append(self._finding(
                    path,
                    "Large integer factored via factordb.com",
                    f"Factors: {', '.join(str(f) for f in factors)}",
                    severity="HIGH",
                    confidence=0.80,
                ))

        return findings

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_large_ints(raw: bytes) -> List[int]:
        """Extract large integers (hex or decimal) from file content."""
        text = raw.decode("utf-8", errors="replace")
        results = []
        for m in _LARGE_INT_RE.finditer(text):
            s = m.group()
            try:
                results.append(int(s, 16) if s.startswith("0x") else int(s))
            except ValueError:
                pass
        return results

    @staticmethod
    def _extract_ciphertext(raw: bytes, n: int) -> Optional[int]:
        """
        Heuristically extract a ciphertext integer from file content.
        Looks for large integers of roughly the same size as n.
        """
        text = raw.decode("utf-8", errors="replace")
        n_bits = n.bit_length()
        for m in _LARGE_INT_RE.finditer(text):
            s = m.group()
            try:
                val = int(s, 16) if s.startswith("0x") else int(s)
            except ValueError:
                continue
            # Must be in range [2, n-1] and roughly same bit length (within 20%)
            if 2 <= val < n and abs(val.bit_length() - n_bits) <= n_bits // 5:
                return val
        return None
