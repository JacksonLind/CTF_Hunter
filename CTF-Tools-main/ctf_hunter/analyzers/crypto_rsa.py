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
            with open(path, "rb") as _fh:
                raw = _fh.read()
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
                    c2 = k2.get("ciphertext") or self._extract_ciphertext(raw, n)
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


# ---------------------------------------------------------------------------
# ECC: helper arithmetic + Smart attack + Pohlig-Hellman
# ---------------------------------------------------------------------------

# Regex to extract labelled ECC parameters from challenge text files.
# Handles both decimal and 0x-prefixed hex.  Point coords may be bare
# integers or (x, y) tuples.
_ECC_PARAM_RE = re.compile(
    r"(?:^|[\n\r\s])(?P<name>p|a|b|n|order|gx|gy|qx|qy)"
    r"\s*[=:]\s*(?P<val>0x[0-9a-fA-F]+|[0-9]{4,})",
    re.MULTILINE | re.IGNORECASE,
)
_ECC_TUPLE_RE = re.compile(
    r"(?:^|[\n\r\s])(?P<name>G|Q|generator|public[_\s]?key)"
    r"\s*[=:]\s*\(\s*(?P<x>0x[0-9a-fA-F]+|[0-9]{4,})\s*,\s*"
    r"(?P<y>0x[0-9a-fA-F]+|[0-9]{4,})\s*\)",
    re.MULTILINE | re.IGNORECASE,
)


def _parse_int(s: str) -> int:
    s = s.strip()
    return int(s, 16) if s.startswith("0x") or s.startswith("0X") else int(s)


def _ec_add(P, Q, a: int, p: int):
    """Affine point addition on y^2 = x^3 + ax + b (mod p).  None = infinity."""
    if P is None:
        return Q
    if Q is None:
        return P
    x1, y1 = P
    x2, y2 = Q
    if x1 % p == x2 % p:
        if (y1 + y2) % p == 0:
            return None  # P + (-P) = infinity
        # Point doubling
        inv = pow(int(2 * y1) % p, -1, p)
        lam = (3 * x1 * x1 + a) * inv % p
    else:
        inv = pow(int(x2 - x1) % p, -1, p)
        lam = (y2 - y1) * inv % p
    x3 = (lam * lam - x1 - x2) % p
    y3 = (lam * (x1 - x3) - y1) % p
    return (x3, y3)


def _ec_mul(k: int, P, a: int, p: int):
    """Scalar multiplication k*P on an elliptic curve over Fp."""
    if P is None:
        return None
    if k < 0:
        P = (P[0], (-P[1]) % p)
        k = -k
    result = None
    addend = P
    while k:
        if k & 1:
            result = _ec_add(result, addend, a, p)
        addend = _ec_add(addend, addend, a, p)
        k >>= 1
    return result


def _trial_factor(n: int, limit: int = 100_000) -> Optional[List[Tuple[int, int]]]:
    """Trial-divide n up to *limit*.  Returns [(prime, exponent)] list if fully
    factored within the limit, else None."""
    factors: List[Tuple[int, int]] = []
    d = 2
    while d * d <= n and d <= limit:
        if n % d == 0:
            exp = 0
            while n % d == 0:
                exp += 1
                n //= d
            factors.append((d, exp))
        d += 1 if d == 2 else 2
    if n > 1:
        if n > limit:
            return None  # not fully factored within limit
        factors.append((n, 1))
    return factors if factors else [(n, 1)]


def _bsgs_ec(G, Q, q: int, e: int, a: int, p: int) -> Optional[int]:
    """Baby-step giant-step DLP in the order-q^e subgroup of E(Fp).
    Solves Q = k*G for k in [0, q^e)."""
    if G is None:
        return 0 if Q is None else None
    if Q is None:
        return 0
    mod = q ** e
    m = int(math.isqrt(mod)) + 1
    # Baby steps: store {j*G: j} for j in 0..m-1
    baby: dict = {}
    step = None
    for j in range(m):
        key = step
        baby[key] = j
        step = _ec_add(step, G, a, p)
    # Giant steps: Q - i*(m*G)
    mG = _ec_mul(m, G, a, p)
    neg_mG = (mG[0], (-mG[1]) % p) if mG else None
    giant = Q
    for i in range(m):
        if giant in baby:
            k = (i * m + baby[giant]) % mod
            return k
        giant = _ec_add(giant, neg_mG, a, p)
    return None


def _crt(residues: List[int], moduli: List[int]) -> int:
    """Chinese Remainder Theorem: given r[i] ≡ x (mod m[i]), return x."""
    M = 1
    for mi in moduli:
        M *= mi
    x = 0
    for ri, mi in zip(residues, moduli):
        Mi = M // mi
        x += ri * Mi * pow(Mi, -1, mi)
    return x % M


def _smart_attack(p: int, a: int, Gx: int, Gy: int, Qx: int, Qy: int) -> Optional[int]:
    """Smart's attack for anomalous elliptic curves (#E(Fp) == p).

    Computes the DLP via the formal group logarithm using p-adic arithmetic.
    Points in E^1(Qp) (formal group) have x with v_p = -2 and y with v_p = -3,
    so the formal group parameter t = -x/y has v_p = 1 and

        log_G = t([p]*G_lift) / p  ≡  -(x_unit) / (y_unit)  mod p

    where x_unit = (x * p²) mod p  and  y_unit = (y * p³) mod p.

    Returns k such that Q = k*G (with k in [0, p-1]), or None on failure.
    """
    # ------------------------------------------------------------------
    # Minimal p-adic arithmetic with precision PREC digits.
    # A value is stored as (v, c) where value = p^v * c  (c not div by p).
    # ------------------------------------------------------------------
    PREC = max(8, p.bit_length() // 8 + 4)  # digits of p-adic precision
    PK = p ** PREC

    def _strip(n: int) -> tuple:
        """Return (v, c) with n = p^v * c,  c not divisible by p."""
        if n == 0:
            return PREC, 0
        v = 0
        while n % p == 0:
            n //= p
            v += 1
        return v, n % PK

    class _Pad:
        """Minimal p-adic number: value = p^v * c."""
        __slots__ = ("v", "c")

        def __init__(self, n: int = 0, d: int = 1) -> None:
            if n == 0:
                self.v, self.c = PREC, 0
                return
            vn, ns = _strip(abs(n))
            vd, ds = _strip(abs(d))
            self.v = vn - vd
            sign = -1 if (n < 0) != (d < 0) else 1
            try:
                self.c = sign * ns * pow(int(ds), -1, PK) % PK
            except Exception:
                self.v, self.c = PREC, 0

        @staticmethod
        def _new(v: int, c: int) -> "_Pad":
            r = _Pad.__new__(_Pad)
            r.v, r.c = v, c % PK
            return r

        def __add__(self, o: "_Pad") -> "_Pad":
            if self.v >= PREC:
                return o
            if o.v >= PREC:
                return self
            if self.v <= o.v:
                c = (self.c + o.c * p ** (o.v - self.v)) % PK
                r = _Pad._new(self.v, c)
            else:
                c = (self.c * p ** (self.v - o.v) + o.c) % PK
                r = _Pad._new(o.v, c)
            if r.c == 0:
                r.v = PREC
                return r
            while r.c % p == 0:
                r.c //= p
                r.v += 1
            return r

        def __neg__(self) -> "_Pad":
            return _Pad._new(self.v, (-self.c) % PK)

        def __sub__(self, o: "_Pad") -> "_Pad":
            return self + (-o)

        def __mul__(self, o: "_Pad") -> "_Pad":
            if self.v >= PREC or o.v >= PREC:
                return _Pad()
            r = _Pad._new(self.v + o.v, self.c * o.c % PK)
            if r.c == 0:
                r.v = PREC
                return r
            while r.c % p == 0:
                r.c //= p
                r.v += 1
            return r

        def __truediv__(self, o: "_Pad") -> "_Pad":
            if o.v >= PREC:
                raise ZeroDivisionError("p-adic zero")
            inv_c = pow(int(o.c % PK), -1, PK)
            return _Pad._new(self.v - o.v, self.c * inv_c % PK)

        def unit_mod_p(self) -> int:
            """Return c mod p (the leading p-adic digit, ignoring valuation)."""
            return int(self.c % p)

    def _pad(n: int) -> _Pad:
        return _Pad(n)

    # ------------------------------------------------------------------
    # Hensel-lift y from E(Fp) to E(Z/p²Z)
    # ------------------------------------------------------------------
    b = (Gy * Gy - pow(Gx, 3) - a * Gx) % p
    p2 = p * p

    def _hensel_y(x: int, y0: int, b_lift: int = b) -> Optional[int]:
        """Hensel-lift y0 from E(Fp) to E'(Z/p²Z) where E' uses b_lift."""
        rhs = (pow(x, 3, p2) + a * x + b_lift) % p2
        f_val = (y0 * y0 - rhs) % p2
        if f_val % p != 0:
            return None
        inv_2y = pow(2 * y0 % p, -1, p)
        t = (f_val // p) * inv_2y % p
        return (y0 - t * p) % p2

    # ------------------------------------------------------------------
    # Elliptic curve addition over Q_p using p-adic arithmetic
    # ------------------------------------------------------------------
    def _ec_add_pad(P, Q):
        if P is None:
            return Q
        if Q is None:
            return P
        x1, y1 = P
        x2, y2 = Q
        dx = x2 - x1
        if dx.v >= PREC:                    # x1 == x2
            dy_sum = y1 + y2
            if dy_sum.v >= PREC:
                return None                 # inverses → infinity
            lam = (_pad(3) * x1 * x1 + _pad(a)) / (_pad(2) * y1)
        else:
            lam = (y2 - y1) / dx
        x3 = lam * lam - x1 - x2
        y3 = lam * (x1 - x3) - y1
        return (x3, y3)

    def _ec_mul_pad(k: int, Px: int, Py: int):
        result = None
        addend = (_pad(Px), _pad(Py))
        while k:
            if k & 1:
                result = _ec_add_pad(result, addend)
            addend = _ec_add_pad(addend, addend)
            k >>= 1
        return result

    # ------------------------------------------------------------------
    # Formal group logarithm
    # For P = [p]*G_lift ∈ E^1(Qp):
    #   v_p(x(P)) = -2,  v_p(y(P)) = -3
    #   t(P) = -x/y  →  v_p(t) = 1
    #   log(P) = t(P)/p  ≡  -(x.c mod p) * inv(y.c mod p)  mod p
    # ------------------------------------------------------------------
    def _formal_log(pt) -> Optional[int]:
        """Return the p-adic formal group log of a point in E^1 as an integer mod p."""
        if pt is None:
            return None
        xP, yP = pt
        if xP.v != -2 or yP.v != -3:
            return None  # not in the expected E^1 stratum
        x_unit = xP.unit_mod_p()
        y_unit = yP.unit_mod_p()
        if y_unit == 0:
            return None
        try:
            return (-x_unit * pow(y_unit, -1, p)) % p
        except Exception:
            return None

    # Try successive curve lifts b' = b + t*p until the formal group log
    # of [p]*G_lift lands in E^1 \ E^2 (i.e. log_G ≢ 0 mod p).
    # This handles the rare case where the standard lift gives [p]*G_lift ∈ E^2.
    for t_lift in range(p):
        try:
            b_lift = (b + t_lift * p) % p2
            Gy_lift = _hensel_y(Gx, Gy, b_lift)
            Qy_lift = _hensel_y(Qx, Qy, b_lift)
            if Gy_lift is None or Qy_lift is None:
                continue

            pG = _ec_mul_pad(p, Gx, Gy_lift)
            pQ = _ec_mul_pad(p, Qx, Qy_lift)

            log_G = _formal_log(pG)
            if log_G is None or log_G == 0:
                continue          # try next lift

            log_Q = _formal_log(pQ)
            if log_Q is None:
                continue

            return log_Q * pow(int(log_G), -1, p) % p
        except Exception:
            continue

    return None


def _pohlig_hellman_ec(
    p: int, a: int, G, n: int, Q, factor_limit: int = 100_000
) -> Optional[int]:
    """Pohlig-Hellman DLP on E(Fp): solve Q = k*G given smooth group order n.

    Returns k or None if the order is not sufficiently smooth.
    """
    factors = _trial_factor(n, factor_limit)
    if not factors:
        return None

    residues: List[int] = []
    moduli: List[int] = []

    for q, e in factors:
        mod = q ** e
        cofactor = n // mod
        Gq = _ec_mul(cofactor, G, a, p)
        Qq = _ec_mul(cofactor, Q, a, p)
        if Gq is None:
            if Qq is None:
                residues.append(0)
                moduli.append(mod)
                continue
            return None
        k_q = _bsgs_ec(Gq, Qq, q, e, a, p)
        if k_q is None:
            return None
        residues.append(k_q)
        moduli.append(mod)

    try:
        k = _crt(residues, moduli) % n
    except Exception:
        return None
    return k


def _extract_ecc_params(text: str) -> dict:
    """Parse ECC parameters from a challenge text file.

    Returns a dict with any of: p, a, b, n, Gx, Gy, Qx, Qy.
    """
    params: dict = {}
    for m in _ECC_PARAM_RE.finditer(text):
        name = m.group("name").lower()
        val  = _parse_int(m.group("val"))
        # Normalise aliases
        if name == "order":
            name = "n"
        params[name] = val

    for m in _ECC_TUPLE_RE.finditer(text):
        name = m.group("name").lower().replace(" ", "").replace("_", "")
        x = _parse_int(m.group("x"))
        y = _parse_int(m.group("y"))
        if "g" in name or "gen" in name:
            params["gx"] = x
            params["gy"] = y
        elif "q" in name or "pub" in name:
            params["qx"] = x
            params["qy"] = y

    return params


class CryptoECCAnalyzer(Analyzer):
    """ECC attack suite: anomalous curve (Smart attack) + Pohlig-Hellman."""

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
            with open(path, "rb") as _fh:
                raw = _fh.read()
        except Exception:
            return []

        text = raw.decode("utf-8", errors="replace")
        params = _extract_ecc_params(text)

        p  = params.get("p")
        a  = params.get("a")
        b  = params.get("b")
        n  = params.get("n")
        Gx = params.get("gx")
        Gy = params.get("gy")
        Qx = params.get("qx")
        Qy = params.get("qy")

        if not p or not a:
            return []

        # Need at minimum p, a, and n to do anything useful
        if not n:
            return []

        findings.append(self._finding(
            path,
            f"ECC parameters detected (p={p.bit_length()}-bit)",
            f"p  = {hex(p)}\na  = {a}\nb  = {b}\nn  = {n}\n"
            f"Anomalous: {'YES (#E = p)' if n == p else 'no'}",
            severity="MEDIUM",
            confidence=0.70,
        ))

        # ------------------------------------------------------------------
        # Anomalous curve: Smart attack
        # ------------------------------------------------------------------
        if n == p:
            findings.append(self._finding(
                path,
                "Anomalous ECC curve detected (#E = p) — Smart attack applicable",
                "The curve order equals the characteristic p.  "
                "The discrete log problem reduces to a p-adic computation (O(log p)).",
                severity="HIGH",
                confidence=0.90,
            ))

            if Gx is not None and Gy is not None and Qx is not None and Qy is not None:
                try:
                    k = _smart_attack(p, a, Gx, Gy, Qx, Qy)
                except Exception:
                    k = None

                if k is not None:
                    # Attempt to interpret k as a flag
                    plaintext = _try_decode_plaintext(k)
                    fm = self._check_flag(plaintext, flag_pattern)
                    findings.append(self._finding(
                        path,
                        "Smart attack: discrete log recovered",
                        f"k = {k}\nDecoded: {plaintext[:300]}",
                        severity="HIGH" if fm else "MEDIUM",
                        flag_match=fm,
                        confidence=0.95 if fm else 0.82,
                    ))
                else:
                    findings.append(self._finding(
                        path,
                        "Smart attack: failed (verify G, Q coordinates and curve params)",
                        "Could not compute discrete log — check that G and Q "
                        "are correct points on the curve and #E = p.",
                        severity="MEDIUM",
                        confidence=0.55,
                    ))

        # ------------------------------------------------------------------
        # Smooth-order curve: Pohlig-Hellman
        # ------------------------------------------------------------------
        elif _trial_factor(n, 100_000) is not None:
            factors = _trial_factor(n, 100_000)
            factor_str = " × ".join(
                f"{q}^{e}" if e > 1 else str(q) for q, e in factors
            )
            findings.append(self._finding(
                path,
                f"ECC group order is smooth — Pohlig-Hellman applicable",
                f"n = {n}\nFactors: {factor_str}",
                severity="HIGH",
                confidence=0.85,
            ))

            if (Gx is not None and Gy is not None
                    and Qx is not None and Qy is not None):
                G = (Gx, Gy)
                Q = (Qx, Qy)
                try:
                    k = _pohlig_hellman_ec(p, a, G, n, Q)
                except Exception:
                    k = None

                if k is not None:
                    plaintext = _try_decode_plaintext(k)
                    fm = self._check_flag(plaintext, flag_pattern)
                    findings.append(self._finding(
                        path,
                        "Pohlig-Hellman: discrete log recovered",
                        f"k = {k}\nDecoded: {plaintext[:300]}",
                        severity="HIGH" if fm else "MEDIUM",
                        flag_match=fm,
                        confidence=0.92 if fm else 0.78,
                    ))

        return findings
