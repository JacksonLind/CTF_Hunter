"""
Archive analyzer: ZIP comment, encrypted entries, path traversal, wordlist cracking.
"""
from __future__ import annotations

import io
import re
import zipfile
from pathlib import Path
from typing import List, Optional

from core.report import Finding
from core.ai_client import AIClient
from .base import Analyzer

_WORDLIST_PATH = Path(__file__).parent.parent / "wordlists" / "rockyou_top1000.txt"


class ArchiveAnalyzer(Analyzer):
    def analyze(
        self,
        path: str,
        flag_pattern: re.Pattern,
        depth: str,
        ai_client: Optional[AIClient],
        session=None,
        dispatcher_module=None,
    ) -> List[Finding]:
        findings: List[Finding] = []

        if not self._is_zip(path):
            findings.extend(self._check_generic_archive(path, flag_pattern))
            self._run_redispatch_hook(findings, session, dispatcher_module)
            return findings

        try:
            with zipfile.ZipFile(path, "r") as zf:
                # ZIP comment
                findings.extend(self._check_comment(path, zf, flag_pattern))
                # Encrypted entries
                findings.extend(self._check_encrypted(path, zf, flag_pattern, depth))
                # Path traversal
                findings.extend(self._check_path_traversal(path, zf))
                # Nested archives
                if depth == "deep":
                    findings.extend(self._check_nested(
                        path, zf, flag_pattern, ai_client,
                        depth=depth, session=session, dispatcher_module=dispatcher_module,
                    ))
        except (zipfile.BadZipFile, Exception) as exc:
            findings.append(self._finding(
                path,
                "Archive read error",
                str(exc),
                severity="INFO",
                confidence=0.2,
            ))
        self._run_redispatch_hook(findings, session, dispatcher_module)
        return findings

    # ------------------------------------------------------------------

    def _is_zip(self, path: str) -> bool:
        try:
            with open(path, "rb") as fh:
                magic = fh.read(4)
            return magic in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")
        except Exception:
            return False

    def _check_comment(
        self, path: str, zf: zipfile.ZipFile, flag_pattern: re.Pattern
    ) -> List[Finding]:
        comment = zf.comment
        if not comment:
            return []
        text = comment.decode("utf-8", errors="replace")
        fm = self._check_flag(text, flag_pattern)
        return [self._finding(
            path,
            f"ZIP end-of-central-directory comment ({len(comment)} bytes)",
            text[:500],
            severity="HIGH" if fm else "MEDIUM",
            flag_match=fm,
            confidence=0.85 if fm else 0.60,
        )]

    def _check_encrypted(
        self,
        path: str,
        zf: zipfile.ZipFile,
        flag_pattern: re.Pattern,
        depth: str,
    ) -> List[Finding]:
        findings: List[Finding] = []
        encrypted = [info for info in zf.infolist() if info.flag_bits & 0x1]
        if not encrypted:
            return []
        names = [e.filename for e in encrypted]
        findings.append(self._finding(
            path,
            f"Encrypted ZIP entries: {len(encrypted)} file(s)",
            "Encrypted: " + ", ".join(names[:10]),
            severity="HIGH",
            confidence=0.80,
        ))
        if depth == "deep":
            findings.extend(self._crack_passwords(path, zf, encrypted, flag_pattern))
        return findings

    def _crack_passwords(
        self,
        path: str,
        zf: zipfile.ZipFile,
        encrypted: list,
        flag_pattern: re.Pattern,
    ) -> List[Finding]:
        words = self._load_wordlist()
        target = encrypted[0]
        for password in words:
            try:
                data = zf.read(target.filename, pwd=password.encode())
                text = data.decode("utf-8", errors="replace")
                fm = self._check_flag(text, flag_pattern)

                detail = f"Decrypted '{target.filename}' content: {text[:200]}"

                # When the flag is not immediately visible in the decrypted content
                # (e.g. it may be XOR-encoded), embed the raw bytes so that the
                # ContentRedispatcher can apply XOR brute-force and other
                # transformations via the raw_hex= extraction pipeline.
                if not fm:
                    detail += f"\nraw_hex={data.hex()}"

                # Extract all remaining encrypted entries with the found password.
                # Failures are silently skipped – a single bad entry should not
                # prevent reporting the successfully cracked password.
                for entry in encrypted[1:]:
                    try:
                        entry_data = zf.read(entry.filename, pwd=password.encode())
                        entry_text = entry_data.decode("utf-8", errors="replace")
                        entry_fm = self._check_flag(entry_text, flag_pattern)
                        if entry_fm:
                            fm = True
                            detail += f"\nExtracted '{entry.filename}': {entry_text[:200]}"
                        else:
                            detail += f"\nraw_hex={entry_data.hex()}"
                    except Exception:
                        pass

                return [self._finding(
                    path,
                    f"ZIP password cracked: '{password}'",
                    detail,
                    severity="HIGH",
                    flag_match=fm,
                    confidence=0.95,
                )]
            except (RuntimeError, zipfile.BadZipFile, Exception):
                continue
        return []

    def _load_wordlist(self) -> list[str]:
        words: list[str] = []
        if _WORDLIST_PATH.exists():
            try:
                words = [
                    w for w in _WORDLIST_PATH.read_text(errors="replace").splitlines()
                    if w.strip()
                ]
            except Exception:
                pass
        return words or ["password", "123456", "admin", "secret", "flag"]

    def _check_path_traversal(self, path: str, zf: zipfile.ZipFile) -> List[Finding]:
        findings: List[Finding] = []
        for info in zf.infolist():
            if ".." in info.filename or info.filename.startswith("/"):
                findings.append(self._finding(
                    path,
                    f"Path traversal in ZIP entry: {info.filename}",
                    "ZIP entry attempts directory traversal.",
                    severity="HIGH",
                    confidence=0.90,
                ))
        return findings

    def _check_nested(
        self,
        path: str,
        zf: zipfile.ZipFile,
        flag_pattern: re.Pattern,
        ai_client: Optional[AIClient],
        depth: str = "deep",
        session=None,
        dispatcher_module=None,
    ) -> List[Finding]:
        import tempfile
        findings: List[Finding] = []
        for info in zf.infolist():
            if info.filename.lower().endswith((".zip", ".gz", ".tar")):
                try:
                    data = zf.read(info.filename)
                    # Use a secure temp file (cross-platform, no path traversal)
                    with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp_fh:
                        tmp_fh.write(data)
                        tmp_path = tmp_fh.name
                    nested_analyzer = ArchiveAnalyzer()
                    nested = nested_analyzer.analyze(
                        tmp_path, flag_pattern, depth, ai_client,
                        session=session, dispatcher_module=dispatcher_module,
                    )
                    for f in nested:
                        f.title = f"[nested:{info.filename}] " + f.title
                    findings.extend(nested)
                    Path(tmp_path).unlink(missing_ok=True)
                except Exception:
                    pass
        return findings

    def _check_generic_archive(self, path: str, flag_pattern: re.Pattern) -> List[Finding]:
        """Try to list gzip/bzip2/xz contents for comment-like metadata."""
        findings: List[Finding] = []
        try:
            data = Path(path).read_bytes()
            # Look for comment-like strings after magic bytes
            text = data[:256].decode("latin-1", errors="replace")
            if self._check_flag(text, flag_pattern):
                findings.append(self._finding(
                    path,
                    "Flag pattern in archive header area",
                    text[:256],
                    severity="HIGH",
                    flag_match=True,
                    confidence=0.85,
                ))
        except Exception:
            pass
        return findings
