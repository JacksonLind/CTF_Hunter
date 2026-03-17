"""
Key Extractor for CTF Hunter.

Scans all findings in a session and extracts cryptographic key candidates
from patterns in finding titles and detail text.  The extracted candidates
are intended to be registered in :class:`~ctf_hunter.core.key_registry.KeyRegistry`
so that they can be tried against ciphertexts discovered in *other* findings
(cross-finding key correlation).

Recognised patterns
-------------------
Vigenère / Beaufort (from ClassicalCipherAnalyzer):
  * Title contains ``key='KEY'``
    e.g. "Possible Vigenère cipher (key_len=5, key='HELLO')"
  * Detail contains ``Key: KEY`` or ``| Key: KEY``
    e.g. "IC=0.048 | Key: hello\\nPlaintext: ..."

XOR (from EncodingAnalyzer and ContentRedispatcher):
  * Title: "XOR key 0xXX produces printable data"
  * Title: "XOR with key b'...' produces printable data"
  * Detail: "Key=0xXX: ..."
  * Encoding chain in detail: "xor_0xXX" or "xor_key_HEXSTR"

Vigenère from ContentRedispatcher encoding chains:
  * Detail contains "Encoding chain: ... → vigenere_key_KEYSTR → ..."

ZIP passwords (from ArchiveAnalyzer):
  * Title: "ZIP password cracked: 'PASSWORD'"

AES / generic:
  * Title contains "AES key:" followed by the key value
  * Title contains "Key candidate:" followed by the value
"""
from __future__ import annotations

import re
from typing import List, TYPE_CHECKING

from .key_registry import KeyCandidate, KeyRegistry

if TYPE_CHECKING:
    from .report import Session

# ---------------------------------------------------------------------------
# Compiled regular expressions
# ---------------------------------------------------------------------------

# key='VALUE' in titles (Vigenère / Beaufort from classical_cipher.py)
_RE_KEY_IN_TITLE = re.compile(r"\bkey='([A-Za-z0-9_\-]+)'", re.IGNORECASE)

# "Key: VALUE" or "| Key: VALUE" in finding details (classical_cipher.py)
_RE_KEY_IN_DETAIL = re.compile(
    r"(?:^\|?\s*Key:\s*|[|\n]\s*Key:\s*)([A-Za-z0-9_\-]+)",
    re.IGNORECASE | re.MULTILINE,
)

# "XOR key 0xXX" in finding titles (encoding.py)
_RE_XOR_TITLE_HEX = re.compile(
    r"\bXOR\s+key\s+(0x[0-9a-fA-F]+)\b", re.IGNORECASE
)

# "XOR with key b'VALUE'" in finding titles (encoding.py)
_RE_XOR_TITLE_BYTES = re.compile(
    r"\bXOR\s+with\s+key\s+b'([^']+)'", re.IGNORECASE
)

# "Key=0xXX:" in finding details (encoding.py)
_RE_XOR_DETAIL_HEX = re.compile(r"\bKey=(0x[0-9a-fA-F]+):", re.IGNORECASE)

# "Key=b'VALUE':" in finding details (encoding.py)
_RE_XOR_DETAIL_BYTES = re.compile(r"\bKey=b'([^']+)':", re.IGNORECASE)

# Encoding chain "vigenere_key_KEYSTR" in details (content_redispatcher.py)
_RE_CHAIN_VIGENERE = re.compile(r"vigenere_key_([A-Z]+)", re.IGNORECASE)

# Encoding chain "xor_0xXX" in details (content_redispatcher.py)
_RE_CHAIN_XOR_SINGLE = re.compile(r"\bxor_0x([0-9a-fA-F]+)\b", re.IGNORECASE)

# Encoding chain "xor_key_HEXSTR" in details (content_redispatcher.py)
_RE_CHAIN_XOR_MULTI = re.compile(r"\bxor_key_([0-9a-fA-F]+)\b", re.IGNORECASE)

# "ZIP password cracked: 'PASSWORD'" in titles (archive.py)
_RE_ZIP_PASSWORD = re.compile(
    r"\bZIP\s+password\s+cracked:\s+'([^']+)'", re.IGNORECASE
)

# "AES key: VALUE" in titles or details
_RE_AES_KEY = re.compile(r"\bAES\s+key[:\s]+([A-Za-z0-9+/=_\-]{8,})", re.IGNORECASE)

# "Key candidate: VALUE" generic pattern
_RE_KEY_CANDIDATE = re.compile(
    r"\bkey\s+candidate[:\s]+([A-Za-z0-9+/=_\-]{3,})", re.IGNORECASE
)


# ---------------------------------------------------------------------------
# KeyExtractor
# ---------------------------------------------------------------------------


class KeyExtractor:
    """Scans every finding in a session and returns extracted key candidates.

    Usage::

        extractor = KeyExtractor()
        candidates = extractor.extract(session)
        for candidate in candidates:
            session.key_registry.register(candidate)
    """

    def extract(self, session: "Session") -> List[KeyCandidate]:
        """Scan all findings in *session* and return discovered key candidates.

        Args:
            session: The active analysis session whose ``findings`` list will
                be scanned.

        Returns:
            A list of :class:`KeyCandidate` objects.  The list may be empty if
            no key-bearing findings are present.
        """
        candidates: List[KeyCandidate] = []
        for finding in session.findings:
            candidates.extend(self._extract_from_finding(finding))
        return candidates

    # ------------------------------------------------------------------
    # Per-finding extraction helpers
    # ------------------------------------------------------------------

    def _extract_from_finding(self, finding) -> List[KeyCandidate]:
        results: List[KeyCandidate] = []
        title = finding.title or ""
        detail = finding.detail or ""
        fid = finding.id
        # Cap confidence at 0.99 (matching the convention in confidence.py)
        # to leave room for manually-confirmed findings to score 1.0.
        conf = min(0.99, max(0.0, float(finding.confidence)))
        # Combined text used for cipher-type context detection
        combined = title + "\n" + detail

        results.extend(self._extract_vigenere_title(title, fid, conf))
        results.extend(self._extract_vigenere_detail(combined, detail, fid, conf))
        results.extend(self._extract_xor_title(title, fid, conf))
        results.extend(self._extract_xor_detail(detail, fid, conf))
        results.extend(self._extract_chain_vigenere(detail, fid, conf))
        results.extend(self._extract_chain_xor(detail, fid, conf))
        results.extend(self._extract_zip_password(title, fid, conf))
        results.extend(self._extract_aes(title, detail, fid, conf))
        results.extend(self._extract_generic_candidate(title, detail, fid, conf))

        return results

    # ------------------------------------------------------------------

    def _extract_vigenere_title(
        self, title: str, fid: str, conf: float
    ) -> List[KeyCandidate]:
        """Extract key='VALUE' patterns from titles (classical_cipher.py)."""
        results = []
        title_lower = title.lower()
        # Classify as vigenere if title mentions vigenere/beaufort/cipher,
        # but fall back to generic for unrecognised sources.
        for match in _RE_KEY_IN_TITLE.finditer(title):
            key_val = match.group(1)
            if not key_val:
                continue
            if "vigenere" in title_lower or "vigenère" in title_lower:
                key_type = "vigenere"
                context = f"Vigenère key extracted from finding title: {title[:120]}"
            elif "beaufort" in title_lower:
                key_type = "vigenere"
                context = f"Beaufort key extracted from finding title: {title[:120]}"
            else:
                key_type = "generic"
                context = f"Key extracted from finding title: {title[:120]}"
            results.append(KeyCandidate(
                value=key_val,
                source_finding_id=fid,
                key_type=key_type,
                confidence=conf,
                context=context,
            ))
        return results

    def _extract_vigenere_detail(
        self, combined: str, detail: str, fid: str, conf: float
    ) -> List[KeyCandidate]:
        """Extract 'Key: VALUE' lines from finding details (classical_cipher.py).

        Args:
            combined: Title + newline + detail, used for cipher-type detection.
            detail:   Raw detail text that is searched for the Key: pattern.
        """
        results = []
        combined_lower = combined.lower()
        for match in _RE_KEY_IN_DETAIL.finditer(detail):
            key_val = match.group(1).strip()
            if not key_val:
                continue
            # Determine type from combined title+detail context
            if (
                "vigenere" in combined_lower
                or "vigenère" in combined_lower
                or "beaufort" in combined_lower
            ):
                key_type = "vigenere"
            else:
                key_type = "generic"
            context = (
                f"Key extracted from finding detail 'Key:' line; "
                f"detail snippet: {detail[:120]}"
            )
            results.append(KeyCandidate(
                value=key_val,
                source_finding_id=fid,
                key_type=key_type,
                confidence=conf,
                context=context,
            ))
        return results

    def _extract_xor_title(
        self, title: str, fid: str, conf: float
    ) -> List[KeyCandidate]:
        """Extract XOR keys from finding titles (encoding.py)."""
        results = []
        for match in _RE_XOR_TITLE_HEX.finditer(title):
            key_val = match.group(1)
            results.append(KeyCandidate(
                value=key_val,
                source_finding_id=fid,
                key_type="xor",
                confidence=conf,
                context=f"Single-byte XOR key from finding title: {title[:120]}",
            ))
        for match in _RE_XOR_TITLE_BYTES.finditer(title):
            key_val = match.group(1)
            results.append(KeyCandidate(
                value=key_val,
                source_finding_id=fid,
                key_type="xor",
                confidence=conf,
                context=f"Multi-byte XOR key from finding title: {title[:120]}",
            ))
        return results

    def _extract_xor_detail(
        self, detail: str, fid: str, conf: float
    ) -> List[KeyCandidate]:
        """Extract XOR keys from finding details (encoding.py)."""
        results = []
        for match in _RE_XOR_DETAIL_HEX.finditer(detail):
            key_val = match.group(1)
            results.append(KeyCandidate(
                value=key_val,
                source_finding_id=fid,
                key_type="xor",
                confidence=conf,
                context=f"Single-byte XOR key from finding detail; snippet: {detail[:120]}",
            ))
        for match in _RE_XOR_DETAIL_BYTES.finditer(detail):
            key_val = match.group(1)
            results.append(KeyCandidate(
                value=key_val,
                source_finding_id=fid,
                key_type="xor",
                confidence=conf,
                context=f"Multi-byte XOR key from finding detail; snippet: {detail[:120]}",
            ))
        return results

    def _extract_chain_vigenere(
        self, detail: str, fid: str, conf: float
    ) -> List[KeyCandidate]:
        """Extract Vigenère keys embedded in encoding chain labels (content_redispatcher.py)."""
        results = []
        for match in _RE_CHAIN_VIGENERE.finditer(detail):
            key_val = match.group(1).upper()
            if not key_val:
                continue
            results.append(KeyCandidate(
                value=key_val,
                source_finding_id=fid,
                key_type="vigenere",
                confidence=conf,
                context=(
                    f"Vigenère key recovered from content-redispatcher encoding chain; "
                    f"detail snippet: {detail[:120]}"
                ),
            ))
        return results

    def _extract_chain_xor(
        self, detail: str, fid: str, conf: float
    ) -> List[KeyCandidate]:
        """Extract XOR keys embedded in encoding chain labels (content_redispatcher.py)."""
        results = []
        for match in _RE_CHAIN_XOR_SINGLE.finditer(detail):
            key_val = f"0x{match.group(1)}"
            results.append(KeyCandidate(
                value=key_val,
                source_finding_id=fid,
                key_type="xor",
                confidence=conf,
                context=(
                    f"Single-byte XOR key recovered from content-redispatcher "
                    f"encoding chain; detail snippet: {detail[:120]}"
                ),
            ))
        for match in _RE_CHAIN_XOR_MULTI.finditer(detail):
            key_val = match.group(1)
            results.append(KeyCandidate(
                value=key_val,
                source_finding_id=fid,
                key_type="xor",
                confidence=conf,
                context=(
                    f"Multi-byte XOR key recovered from content-redispatcher "
                    f"encoding chain; detail snippet: {detail[:120]}"
                ),
            ))
        return results

    def _extract_zip_password(
        self, title: str, fid: str, conf: float
    ) -> List[KeyCandidate]:
        """Extract cracked ZIP passwords from finding titles (archive.py)."""
        results = []
        for match in _RE_ZIP_PASSWORD.finditer(title):
            pwd = match.group(1)
            if not pwd:
                continue
            results.append(KeyCandidate(
                value=pwd,
                source_finding_id=fid,
                key_type="zip_password",
                confidence=conf,
                context=f"ZIP password cracked; finding title: {title[:120]}",
            ))
        return results

    def _extract_aes(
        self, title: str, detail: str, fid: str, conf: float
    ) -> List[KeyCandidate]:
        """Extract AES key values mentioned in titles or details."""
        results = []
        for text in (title, detail):
            for match in _RE_AES_KEY.finditer(text):
                key_val = match.group(1).strip()
                if not key_val:
                    continue
                results.append(KeyCandidate(
                    value=key_val,
                    source_finding_id=fid,
                    key_type="aes",
                    confidence=conf,
                    context=f"AES key extracted; source text snippet: {text[:120]}",
                ))
        return results

    def _extract_generic_candidate(
        self, title: str, detail: str, fid: str, conf: float
    ) -> List[KeyCandidate]:
        """Extract generic 'key candidate: VALUE' patterns."""
        results = []
        for text in (title, detail):
            for match in _RE_KEY_CANDIDATE.finditer(text):
                key_val = match.group(1).strip()
                if not key_val:
                    continue
                results.append(KeyCandidate(
                    value=key_val,
                    source_finding_id=fid,
                    key_type="generic",
                    confidence=conf,
                    context=f"Generic key candidate; source text snippet: {text[:120]}",
                ))
        return results
