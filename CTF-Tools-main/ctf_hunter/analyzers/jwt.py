"""
JWT Analyzer: detect, decode, and attack JSON Web Tokens embedded in any file.

Checks performed on every token found:
  1. Decode and display all claims (header + payload).
  2. Timestamp anomalies: expired exp, future iat, not-yet-valid nbf.
  3. alg:none bypass  — forge a token with alg=none and empty signature.
  4. Weak HMAC secret — brute-force HS256/HS384/HS512 against rockyou top-1000
     plus common CTF secrets (no pyjwt dependency, pure stdlib hmac).
  5. RS256→HS256 key-confusion — if a public key is registered in KeyRegistry,
     re-sign the payload with that key as the HMAC secret (deep mode only).

Always-run: scans every file for the eyJ… JWT header pattern.
"""
from __future__ import annotations

import base64
import hashlib
import hmac as _hmac
import json
import re
import time
from pathlib import Path
from typing import List, Optional

from core.report import Finding
from core.ai_client import AIClient
from .base import Analyzer

_JWT_RE = re.compile(
    r"eyJ[A-Za-z0-9_\-]+"         # header (always starts with eyJ = {"...)
    r"\.[A-Za-z0-9_\-]+"          # payload
    r"\.[A-Za-z0-9_\-]*"          # signature (may be empty for alg:none)
)

_WORDLIST_PATH = Path(__file__).parent.parent / "wordlists" / "rockyou_top1000.txt"

# Common CTF / default JWT secrets tried before the wordlist
def _forge_alg_none(header: dict, payload_b64: str) -> Optional[str]:
    """Return a forged token with alg=none and empty signature, or None on error."""
    try:
        new_hdr = {**header, "alg": "none"}
        new_hdr_b64 = _b64url_encode(
            json.dumps(new_hdr, separators=(",", ":")).encode()
        )
        return f"{new_hdr_b64}.{payload_b64}."
    except Exception:
        return None


_CTF_SECRETS: list[str] = [
    "secret", "password", "jwt_secret", "mysecret", "", "key", "admin",
    "flag", "ctf", "challenge", "token", "supersecret", "1234", "test",
    "changeme", "letmein", "qwerty", "abc123", "p@ssw0rd", "signingkey",
]


# ---------------------------------------------------------------------------
# Base64url helpers (stdlib only)
# ---------------------------------------------------------------------------

def _b64url_decode(s: str) -> bytes:
    s = s.replace("-", "+").replace("_", "/")
    pad = (4 - len(s) % 4) % 4
    return base64.b64decode(s + "=" * pad)


def _b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _load_wordlist() -> list[str]:
    try:
        return _WORDLIST_PATH.read_text(encoding="utf-8", errors="replace").splitlines()
    except Exception:
        return []


# ---------------------------------------------------------------------------
# Analyzer
# ---------------------------------------------------------------------------

class JWTAnalyzer(Analyzer):
    """Always-run analyzer that scans any file for JWT strings."""

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
            data = Path(path).read_bytes()
        except Exception:
            return []

        try:
            text = data[:1_000_000].decode("utf-8", errors="replace")
        except Exception:
            return []

        # Deduplicate tokens while preserving order
        seen: set[str] = set()
        tokens: list[str] = []
        for tok in _JWT_RE.findall(text):
            if tok not in seen:
                seen.add(tok)
                tokens.append(tok)

        for token in tokens[:10]:
            findings.extend(
                self._analyze_token(path, token, flag_pattern, depth)
            )

        return findings

    # ------------------------------------------------------------------

    def _analyze_token(
        self,
        path: str,
        token: str,
        flag_pattern: re.Pattern,
        depth: str,
    ) -> List[Finding]:
        findings: List[Finding] = []
        parts = token.split(".")
        if len(parts) != 3:
            return []

        header_b64, payload_b64, sig_b64 = parts

        try:
            header: dict = json.loads(_b64url_decode(header_b64))
        except Exception:
            return []

        try:
            payload: dict = json.loads(_b64url_decode(payload_b64))
        except Exception:
            return []

        alg: str = str(header.get("alg", "unknown"))

        # 1. Emit all claims
        claims_txt = json.dumps(payload, indent=2)
        header_txt = json.dumps(header)
        combined = claims_txt + " " + header_txt
        fm = self._check_flag(combined, flag_pattern)
        findings.append(self._finding(
            path,
            f"JWT detected (alg={alg})",
            f"Header: {header_txt}\nPayload:\n{claims_txt}",
            severity="HIGH" if fm else "MEDIUM",
            flag_match=fm,
            confidence=0.90 if fm else 0.70,
        ))

        # 2. Timestamp anomalies
        findings.extend(self._check_timestamps(path, payload))

        # 3. alg:none bypass
        none_token = _forge_alg_none(header, payload_b64)
        if none_token and alg.lower() != "none":
            findings.append(self._finding(
                path,
                f"JWT alg:none bypass (original alg={alg})",
                f"Change alg to 'none' and drop the signature.\n"
                f"Forged token:\n{none_token}",
                severity="HIGH",
                confidence=0.80,
            ))

        # 4. HMAC brute-force
        if alg.startswith("HS"):
            findings.extend(
                self._brute_hmac(path, header_b64, payload_b64, sig_b64, alg)
            )

        # 5. RS256→HS256 key-confusion (deep only)
        if depth == "deep" and alg == "RS256":
            findings.extend(
                self._rs256_hs256(path, header, header_b64, payload_b64)
            )

        return findings

    # ------------------------------------------------------------------

    def _check_timestamps(self, path: str, payload: dict) -> List[Finding]:
        findings: List[Finding] = []
        now = int(time.time())

        for claim, label, check in (
            ("exp", "expired",          lambda v: v < now),
            ("iat", "iat in the future", lambda v: v > now + 60),
            ("nbf", "nbf not yet valid", lambda v: v > now),
        ):
            raw = payload.get(claim)
            if raw is None:
                continue
            try:
                val = int(raw)
            except (TypeError, ValueError):
                continue

            if not check(val):
                continue

            if claim == "exp":
                import datetime
                ts = datetime.datetime.fromtimestamp(val, tz=datetime.timezone.utc).isoformat()
                detail = (
                    f"exp={val} ({ts} UTC, "
                    f"expired {now - val}s ago)\n"
                    "Expired tokens may be accepted by misconfigured servers."
                )
                sev, conf = "MEDIUM", 0.75
            elif claim == "iat":
                detail = f"iat={val}, now={now}, delta=+{val - now}s (clock skew / anomaly)"
                sev, conf = "MEDIUM", 0.65
            else:  # nbf
                detail = f"nbf={val}, now={now}, valid in {val - now}s"
                sev, conf = "INFO", 0.60

            findings.append(self._finding(
                path,
                f"JWT {label} ({claim}={val})",
                detail,
                severity=sev,
                confidence=conf,
            ))

        return findings

    # ------------------------------------------------------------------

    def _brute_hmac(
        self,
        path: str,
        header_b64: str,
        payload_b64: str,
        sig_b64: str,
        alg: str,
    ) -> List[Finding]:
        """Brute-force HS256/HS384/HS512 secret against wordlist + CTF extras."""
        try:
            expected = _b64url_decode(sig_b64)
        except Exception:
            return []

        hash_fn = {
            "HS256": hashlib.sha256,
            "HS384": hashlib.sha384,
            "HS512": hashlib.sha512,
        }.get(alg)
        if hash_fn is None:
            return []

        message = f"{header_b64}.{payload_b64}".encode()
        wordlist = _load_wordlist()
        candidates = _CTF_SECRETS + wordlist

        for pwd in candidates:
            try:
                sig = _hmac.new(pwd.encode("utf-8", errors="replace"), message, hash_fn).digest()
                if _hmac.compare_digest(sig, expected):
                    return [self._finding(
                        path,
                        f"JWT {alg} secret cracked: {pwd!r}",
                        f"Algorithm : {alg}\n"
                        f"Secret    : {pwd!r}\n"
                        f"You can now forge arbitrary tokens signed with this secret.",
                        severity="HIGH",
                        confidence=0.99,
                    )]
            except Exception:
                continue

        return []

    # ------------------------------------------------------------------

    def _rs256_hs256(
        self,
        path: str,
        header: dict,
        header_b64: str,
        payload_b64: str,
    ) -> List[Finding]:
        """RS256→HS256 key-confusion: sign with the public key as HMAC secret."""
        try:
            from core.key_registry import KeyRegistry
            raw = KeyRegistry.get("public_key")
            pubkeys: list = raw if isinstance(raw, list) else ([raw] if raw else [])
        except Exception:
            return []

        if not pubkeys:
            return []

        hs256_hdr = _b64url_encode(
            json.dumps({**header, "alg": "HS256"}, separators=(",", ":")).encode()
        )
        message = f"{hs256_hdr}.{payload_b64}".encode()
        findings: List[Finding] = []

        for pubkey in pubkeys:
            try:
                key_bytes = pubkey.encode() if isinstance(pubkey, str) else pubkey
                sig = _hmac.new(key_bytes, message, hashlib.sha256).digest()
                forged = f"{hs256_hdr}.{payload_b64}.{_b64url_encode(sig)}"
                findings.append(self._finding(
                    path,
                    "JWT RS256→HS256 key-confusion attack",
                    "Public key used as HMAC-SHA256 secret.\n"
                    f"Forged HS256 token:\n{forged}",
                    severity="HIGH",
                    confidence=0.85,
                ))
            except Exception:
                continue

        return findings
