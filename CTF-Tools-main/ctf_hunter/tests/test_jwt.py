"""
Tests for analyzers/jwt.py — JWT detection, decoding, and attack checks.

Coverage:
  A. Helpers
      1.  _b64url_decode handles no-padding, 1-, 2-, 3-char padding
      2.  _b64url_decode handles URL-safe chars (- and _)
      3.  _b64url_encode produces URL-safe, no-padding output
      4.  Round-trip: encode → decode is identity

  B. Token analysis — claims / flag detection
      5.  Flag in JWT payload claims → HIGH + flag_match
      6.  Flag in JWT header → HIGH + flag_match
      7.  Normal JWT (no flag) → MEDIUM, no flag_match
      8.  Malformed JWT (2 parts only) → no findings, no crash

  C. Timestamp anomalies
      9.  Expired exp → MEDIUM finding mentioning "expired"
     10.  Future iat → MEDIUM finding
     11.  Future nbf → INFO finding
     12.  No exp/iat/nbf → no timestamp findings

  D. alg:none bypass
     13.  HS256 token → alg:none finding emitted with forged token string
     14.  Forged token has empty signature (ends with ".")
     15.  Token already using alg=none → no alg:none bypass finding emitted

  E. HMAC brute-force
     16.  HS256 token signed with "secret" → secret cracked
     17.  HS256 token signed with empty string → secret cracked (empty key in CTF_SECRETS)
     18.  HS512 token with known password → cracked
     19.  RS256 token → brute-force not attempted
     20.  HS256 with unknown strong secret → no crack finding

  F. File scanning
     21.  JWT in plain text file → found by analyze()
     22.  JWT embedded mid-line in larger text → found
     23.  Multiple JWTs in one file → each analyzed (separate findings)
     24.  Non-JWT file → zero JWT findings
     25.  Empty file → no crash

  G. Edge cases
     26.  Payload with non-ASCII Unicode in claims → no crash, still decoded
     27.  Very long file (> 1 MB cap) → only first 1 MB scanned (no crash)
     28.  alg:none forged token is a valid 3-part dot-separated string

Run from ctf_hunter/ directory:
    python -m unittest tests.test_jwt -v
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import sys
import tempfile
import time
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from analyzers.jwt import (
    JWTAnalyzer,
    _b64url_decode,
    _b64url_encode,
    _forge_alg_none,
)

FLAG_RE = re.compile(r"flag\{[^}]+\}", re.IGNORECASE)
_ANA = JWTAnalyzer()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _b64url_enc(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _make_jwt(
    header: dict,
    payload: dict,
    secret: str = "",
    alg: str = "HS256",
) -> str:
    """Build a signed (HS256/HS384/HS512) or unsigned (alg=none) JWT."""
    h = _b64url_enc(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url_enc(json.dumps(payload, separators=(",", ":")).encode())
    message = f"{h}.{p}".encode()

    if header.get("alg", "").lower() == "none":
        return f"{h}.{p}."

    hash_fn = {"HS256": hashlib.sha256, "HS384": hashlib.sha384,
               "HS512": hashlib.sha512}.get(alg, hashlib.sha256)
    sig = _b64url_enc(hmac.new(secret.encode(), message, hash_fn).digest())
    return f"{h}.{p}.{sig}"


def _tmp(content: bytes, suffix: str = ".txt") -> str:
    fd, path = tempfile.mkstemp(suffix=suffix)
    with os.fdopen(fd, "wb") as f:
        f.write(content)
    return path


def _run(content: bytes, depth: str = "deep") -> list:
    path = _tmp(content)
    try:
        return _ANA.analyze(path, FLAG_RE, depth, None)
    finally:
        os.unlink(path)


def _std_header(alg: str = "HS256") -> dict:
    return {"alg": alg, "typ": "JWT"}


def _std_payload(extra: dict | None = None) -> dict:
    p = {"sub": "1234567890", "name": "Test User", "iat": int(time.time())}
    if extra:
        p.update(extra)
    return p


# ===========================================================================
# A — Helpers
# ===========================================================================

class TestHelpers(unittest.TestCase):

    def test_a1_b64url_decode_padding_variants(self):
        for n in range(1, 20):
            original = b"x" * n
            encoded = base64.urlsafe_b64encode(original).rstrip(b"=").decode()
            self.assertEqual(_b64url_decode(encoded), original,
                             f"Failed for n={n}: {encoded!r}")

    def test_a2_b64url_decode_url_safe_chars(self):
        # Ensure bytes that encode to '+' / '/' in standard base64
        # are decoded correctly when given as '-' / '_'
        raw = b"\xfb\xff\xfe"
        encoded = base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
        self.assertIn("-" or "_", encoded)
        self.assertEqual(_b64url_decode(encoded), raw)

    def test_a3_b64url_encode_no_padding_url_safe(self):
        result = _b64url_encode(b"\xfb\xff\xfe")
        self.assertNotIn("=", result)
        self.assertNotIn("+", result)
        self.assertNotIn("/", result)

    def test_a4_round_trip_identity(self):
        for data in (b"hello", b"", b"\x00\xff", b"flag{test}"):
            self.assertEqual(_b64url_decode(_b64url_encode(data)), data)


# ===========================================================================
# B — Token analysis
# ===========================================================================

class TestTokenAnalysis(unittest.TestCase):

    def test_b5_flag_in_payload_high_flag_match(self):
        token = _make_jwt(_std_header(), {"sub": "user", "note": "flag{jwt_payload_flag}"})
        findings = _run(token.encode())
        self.assertTrue(any(f.flag_match for f in findings),
                        f"titles={[f.title for f in findings]}")
        high = [f for f in findings if f.flag_match]
        self.assertTrue(all(f.severity == "HIGH" for f in high))

    def test_b6_flag_in_header_field(self):
        hdr = {"alg": "HS256", "typ": "JWT", "kid": "flag{kid_flag}"}
        token = _make_jwt(hdr, _std_payload())
        findings = _run(token.encode())
        self.assertTrue(any(f.flag_match for f in findings),
                        f"Expected flag match in header kid; titles={[f.title for f in findings]}")

    def test_b7_normal_jwt_medium_no_flag(self):
        token = _make_jwt(_std_header(), _std_payload())
        findings = _run(token.encode())
        jwt_findings = [f for f in findings if "JWT detected" in f.title]
        self.assertTrue(len(jwt_findings) >= 1)
        self.assertFalse(any(f.flag_match for f in jwt_findings))
        self.assertTrue(all(f.severity == "MEDIUM" for f in jwt_findings))

    def test_b8_malformed_jwt_no_crash(self):
        # Only 2 dot-separated segments — not a valid JWT
        bad = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0"
        try:
            findings = _run(bad.encode())
            # Must not raise; may return empty or findings from other analyzers
            self.assertIsInstance(findings, list)
        except Exception as exc:
            self.fail(f"Malformed JWT raised: {exc}")


# ===========================================================================
# C — Timestamp anomalies
# ===========================================================================

class TestTimestamps(unittest.TestCase):

    def test_c9_expired_exp(self):
        past = int(time.time()) - 3600  # 1 hour ago
        token = _make_jwt(_std_header(), _std_payload({"exp": past}))
        findings = _run(token.encode())
        expired = [f for f in findings if "expired" in f.title.lower()]
        self.assertTrue(len(expired) >= 1,
                        f"Expected expired finding; got {[f.title for f in findings]}")
        self.assertTrue(all(f.severity == "MEDIUM" for f in expired))

    def test_c10_future_iat(self):
        future_iat = int(time.time()) + 7200  # 2 hours ahead
        token = _make_jwt(_std_header(), {"sub": "user", "iat": future_iat})
        findings = _run(token.encode())
        future_f = [f for f in findings if "iat" in f.title.lower() and "future" in f.title.lower()]
        self.assertTrue(len(future_f) >= 1,
                        f"Expected future-iat finding; got {[f.title for f in findings]}")

    def test_c11_future_nbf(self):
        future_nbf = int(time.time()) + 3600
        token = _make_jwt(_std_header(), {"sub": "user", "iat": int(time.time()), "nbf": future_nbf})
        findings = _run(token.encode())
        nbf_f = [f for f in findings if "nbf" in f.title.lower()]
        self.assertTrue(len(nbf_f) >= 1,
                        f"Expected nbf finding; got {[f.title for f in findings]}")
        self.assertTrue(all(f.severity == "INFO" for f in nbf_f))

    def test_c12_no_timestamps_no_ts_findings(self):
        token = _make_jwt(_std_header(), {"sub": "user", "role": "admin"})
        findings = _run(token.encode())
        ts_findings = [f for f in findings if any(
            kw in f.title.lower() for kw in ("expired", "iat", "nbf", "future")
        )]
        self.assertEqual(ts_findings, [],
                         f"Unexpected timestamp findings: {[f.title for f in ts_findings]}")


# ===========================================================================
# D — alg:none bypass
# ===========================================================================

class TestAlgNoneBypass(unittest.TestCase):

    def test_d13_hs256_token_emits_alg_none_finding(self):
        token = _make_jwt(_std_header("HS256"), _std_payload(), secret="secret")
        findings = _run(token.encode())
        none_f = [f for f in findings if "alg:none" in f.title.lower() or "none bypass" in f.title.lower()]
        self.assertTrue(len(none_f) >= 1,
                        f"Expected alg:none finding; got {[f.title for f in findings]}")

    def test_d14_forged_token_has_empty_signature(self):
        token = _make_jwt(_std_header("HS256"), _std_payload(), secret="secret")
        findings = _run(token.encode())
        none_f = [f for f in findings if "none" in f.title.lower()]
        self.assertTrue(len(none_f) >= 1)
        # The forged token in the detail must end with "."
        detail = none_f[0].detail
        lines = [l.strip() for l in detail.splitlines() if l.strip().startswith("eyJ")]
        self.assertTrue(len(lines) >= 1, f"No forged token line in detail: {detail!r}")
        forged = lines[0]
        self.assertTrue(forged.endswith("."),
                        f"Forged token must end with '.'; got: {forged!r}")

    def test_d15_alg_none_token_no_bypass_finding(self):
        """A token already using alg=none must NOT emit another alg:none finding."""
        token = _make_jwt({"alg": "none", "typ": "JWT"}, _std_payload())
        findings = _run(token.encode())
        none_f = [f for f in findings if "none bypass" in f.title.lower()]
        self.assertEqual(none_f, [],
                         f"Should not emit bypass finding for alg=none token: {[f.title for f in none_f]}")


# ===========================================================================
# E — HMAC brute-force
# ===========================================================================

class TestHMACBrute(unittest.TestCase):

    def test_e16_hs256_secret_cracked(self):
        token = _make_jwt(_std_header("HS256"), _std_payload(), secret="secret")
        findings = _run(token.encode())
        crack_f = [f for f in findings if "cracked" in f.title.lower() or "secret" in f.title.lower()]
        self.assertTrue(len(crack_f) >= 1,
                        f"Expected cracked finding; got {[f.title for f in findings]}")
        self.assertTrue(any("secret" in f.title for f in crack_f))

    def test_e17_hs256_empty_string_secret(self):
        token = _make_jwt(_std_header("HS256"), _std_payload(), secret="")
        findings = _run(token.encode())
        crack_f = [f for f in findings if "cracked" in f.title.lower()]
        self.assertTrue(len(crack_f) >= 1,
                        f"Empty-string secret not cracked; got {[f.title for f in findings]}")

    def test_e18_hs512_known_secret(self):
        token = _make_jwt({"alg": "HS512", "typ": "JWT"}, _std_payload(),
                          secret="password", alg="HS512")
        findings = _run(token.encode())
        crack_f = [f for f in findings if "cracked" in f.title.lower()]
        self.assertTrue(len(crack_f) >= 1,
                        f"HS512 secret 'password' not cracked; got {[f.title for f in findings]}")

    def test_e19_rs256_no_brute_attempt(self):
        """RS256 tokens should not produce an HMAC crack finding."""
        # Build a fake RS256 token (signature won't be valid, but we only test
        # that the brute-force path is not triggered)
        hdr = _b64url_enc(json.dumps({"alg": "RS256", "typ": "JWT"}, separators=(",", ":")).encode())
        pay = _b64url_enc(json.dumps(_std_payload(), separators=(",", ":")).encode())
        fake_sig = _b64url_enc(b"\x00" * 64)
        token = f"{hdr}.{pay}.{fake_sig}"
        findings = _run(token.encode())
        crack_f = [f for f in findings if "cracked" in f.title.lower()]
        self.assertEqual(crack_f, [],
                         f"RS256 should not produce HMAC crack finding; got {[f.title for f in crack_f]}")

    def test_e20_unknown_strong_secret_not_cracked(self):
        token = _make_jwt(_std_header("HS256"), _std_payload(),
                          secret="XTRM_RANDOM_CTF_SECRET_NOTINWORDLIST_XYZ987")
        findings = _run(token.encode())
        crack_f = [f for f in findings if "cracked" in f.title.lower()]
        self.assertEqual(crack_f, [],
                         f"Strong secret should not be cracked; got {[f.title for f in crack_f]}")


# ===========================================================================
# F — File scanning
# ===========================================================================

class TestFileScanning(unittest.TestCase):

    def test_f21_jwt_in_text_file_found(self):
        token = _make_jwt(_std_header(), _std_payload(), secret="secret")
        content = f"Authorization: Bearer {token}\n".encode()
        findings = _run(content)
        jwt_f = [f for f in findings if "JWT" in f.title]
        self.assertTrue(len(jwt_f) >= 1,
                        f"JWT not found in text file; got {[f.title for f in findings]}")

    def test_f22_jwt_embedded_mid_line(self):
        token = _make_jwt(_std_header(), _std_payload(), secret="test")
        content = f'response_body = {{"token": "{token}", "status": "ok"}}'.encode()
        findings = _run(content)
        jwt_f = [f for f in findings if "JWT" in f.title]
        self.assertTrue(len(jwt_f) >= 1)

    def test_f23_multiple_jwts_each_analyzed(self):
        t1 = _make_jwt(_std_header(), {"sub": "alice"}, secret="secret")
        t2 = _make_jwt(_std_header(), {"sub": "bob"}, secret="password")
        content = f"{t1}\n{t2}\n".encode()
        findings = _run(content)
        jwt_f = [f for f in findings if "JWT detected" in f.title]
        self.assertEqual(len(jwt_f), 2,
                         f"Expected 2 JWT-detected findings; got {[f.title for f in jwt_f]}")

    def test_f24_non_jwt_file_no_jwt_findings(self):
        content = b"This is a completely normal text file with no JWTs.\nHello world.\n"
        findings = _run(content)
        jwt_f = [f for f in findings if "JWT" in f.title]
        self.assertEqual(jwt_f, [],
                         f"Unexpected JWT findings: {[f.title for f in jwt_f]}")

    def test_f25_empty_file_no_crash(self):
        try:
            _run(b"")
        except Exception as exc:
            self.fail(f"Empty file raised: {exc}")


# ===========================================================================
# G — Edge cases
# ===========================================================================

class TestEdgeCases(unittest.TestCase):

    def test_g26_unicode_payload_no_crash(self):
        payload = {"sub": "user", "note": "こんにちは世界", "emoji": "🚩"}
        token = _make_jwt(_std_header(), payload, secret="secret")
        try:
            findings = _run(token.encode("utf-8"))
            self.assertIsInstance(findings, list)
        except Exception as exc:
            self.fail(f"Unicode payload raised: {exc}")

    def test_g27_oversized_file_no_crash(self):
        token = _make_jwt(_std_header(), _std_payload(), secret="secret")
        # 2 MB of filler + token
        content = (b"A" * 2_000_000) + token.encode()
        path = _tmp(content)
        try:
            findings = _ANA.analyze(path, FLAG_RE, "deep", None)
            self.assertIsInstance(findings, list)
            # The token is past the 1 MB cap, so it may or may not be found —
            # either outcome is acceptable; we only require no crash.
        except Exception as exc:
            self.fail(f"Oversized file raised: {exc}")
        finally:
            os.unlink(path)

    def test_g28_forged_none_token_is_valid_three_part(self):
        hdr = {"alg": "HS256", "typ": "JWT"}
        payload_b64 = _b64url_enc(json.dumps({"sub": "user"}, separators=(",", ":")).encode())
        forged = _forge_alg_none(hdr, payload_b64)
        self.assertIsNotNone(forged)
        parts = forged.split(".")
        self.assertEqual(len(parts), 3, f"Forged token must have 3 parts: {forged!r}")
        self.assertEqual(parts[2], "", f"Signature must be empty: {forged!r}")
        # Header must decode to alg=none
        hdr_decoded = json.loads(_b64url_decode(parts[0]))
        self.assertEqual(hdr_decoded["alg"], "none")


if __name__ == "__main__":
    unittest.main(verbosity=2)
