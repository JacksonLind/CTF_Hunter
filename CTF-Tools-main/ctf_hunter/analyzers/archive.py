"""
Archive analyzer: ZIP comment, encrypted entries, path traversal, wordlist cracking.
"""
from __future__ import annotations

import io
import re
import threading
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import List, Optional, Union

from core.report import Finding
from core.ai_client import AIClient
from .base import Analyzer

_WORDLIST_PATH = Path(__file__).parent.parent / "wordlists" / "rockyou_top1000.txt"
# Maximum recursion depth for nested archive extraction. Prevents infinite
# recursion when a ZIP contains another ZIP (or a self-referential archive).
_MAX_NEST_DEPTH = 5
# Skip nested archives larger than this to prevent memory exhaustion.
_MAX_NESTED_BYTES = 50 * 1024 * 1024  # 50 MB

# Module-level wordlist cache – loaded once, reused across all calls and
# nested analyzer instances so we never re-read the file from disk.
_WORDLIST_CACHE: Optional[List[str]] = None
_WORDLIST_LOCK = threading.Lock()


class ArchiveAnalyzer(Analyzer):
    def analyze(
        self,
        path: str,
        flag_pattern: re.Pattern,
        depth: str,
        ai_client: Optional[AIClient],
        session=None,
        dispatcher_module=None,
        _nest_depth: int = 0,
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
                # Encrypted entries – pass path so parallel workers can open
                # their own ZipFile handles without sharing the current one.
                findings.extend(self._check_encrypted(path, zf, flag_pattern, depth, zip_source=path))
                # Path traversal
                findings.extend(self._check_path_traversal(path, zf))
                # Nested archives
                if depth == "deep" and _nest_depth < _MAX_NEST_DEPTH:
                    findings.extend(self._check_nested(
                        path, zf, flag_pattern, ai_client,
                        depth=depth, session=session, dispatcher_module=dispatcher_module,
                        _nest_depth=_nest_depth,
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
        zip_source: Union[str, bytes, None] = None,
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
            # Use zip_source so each parallel worker can open its own ZipFile.
            src: Union[str, bytes] = zip_source if zip_source is not None else path
            findings.extend(self._crack_passwords(path, src, encrypted, flag_pattern))
        return findings

    def _crack_passwords(
        self,
        path: str,
        zip_source: Union[str, bytes],
        encrypted: list,
        flag_pattern: re.Pattern,
    ) -> List[Finding]:
        words = self._load_wordlist()
        target = encrypted[0]
        stop = threading.Event()

        def _open_zip() -> zipfile.ZipFile:
            """Open a fresh ZipFile handle so each thread is independent."""
            if isinstance(zip_source, bytes):
                return zipfile.ZipFile(io.BytesIO(zip_source), "r")
            return zipfile.ZipFile(zip_source, "r")

        def try_password(password: str) -> Optional[tuple]:
            if stop.is_set():
                return None
            try:
                with _open_zip() as zf:
                    data = zf.read(target.filename, pwd=password.encode())
                return (password, data)
            except Exception:
                return None

        if not words:
            return []

        cracked: Optional[tuple] = None
        with ThreadPoolExecutor(max_workers=min(8, len(words))) as executor:
            futures = [executor.submit(try_password, pw) for pw in words]
            for future in as_completed(futures):
                result = future.result()
                if result is not None:
                    stop.set()
                    cracked = result
                    break

        if cracked is None:
            return []

        password, first_data = cracked
        text = first_data.decode("utf-8", errors="replace")
        fm = self._check_flag(text, flag_pattern)

        detail = f"Decrypted '{target.filename}' content: {text[:200]}"

        # When the flag is not immediately visible in the decrypted content
        # (e.g. it may be XOR-encoded), embed the raw bytes so that the
        # ContentRedispatcher can apply XOR brute-force and other
        # transformations via the raw_hex= extraction pipeline.
        if not fm:
            detail += f"\nraw_hex={first_data.hex()}"

        # Extract all remaining encrypted entries with the found password using
        # a single ZipFile handle to avoid repeated open/close overhead.
        if encrypted[1:]:
            try:
                with _open_zip() as zf:
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

    def _load_wordlist(self) -> List[str]:
        global _WORDLIST_CACHE
        if _WORDLIST_CACHE is not None:
            return _WORDLIST_CACHE
        with _WORDLIST_LOCK:
            # Double-checked locking: re-test inside the lock so only the
            # first thread actually reads from disk.
            if _WORDLIST_CACHE is not None:
                return _WORDLIST_CACHE
            words: List[str] = []
            if _WORDLIST_PATH.exists():
                try:
                    words = [
                        w for w in _WORDLIST_PATH.read_text(errors="replace").splitlines()
                        if w.strip()
                    ]
                except Exception:
                    pass
            _WORDLIST_CACHE = words or ["password", "123456", "admin", "secret", "flag"]
        return _WORDLIST_CACHE

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
        _nest_depth: int = 0,
    ) -> List[Finding]:
        findings: List[Finding] = []
        for info in zf.infolist():
            lname = info.filename.lower()
            if not lname.endswith((".zip", ".gz", ".tar")):
                continue
            # Guard against memory exhaustion from unexpectedly large entries.
            if info.file_size > _MAX_NESTED_BYTES:
                continue
            try:
                data = zf.read(info.filename)
                if (
                    lname.endswith(".zip")
                    and len(data) >= 4
                    and data[:4] in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")
                ):
                    # Analyse the nested ZIP entirely in memory – no temp file needed.
                    nested = self._analyze_zip_bytes(
                        data, path, flag_pattern, ai_client,
                        depth=depth, session=session, dispatcher_module=dispatcher_module,
                        _nest_depth=_nest_depth + 1,
                    )
                else:
                    # For non-ZIP archives check only the header area in memory.
                    nested = self._check_generic_archive_bytes(data, path, flag_pattern)
            except Exception:
                # Silently skip individual nested entries that cannot be
                # extracted or analyzed (e.g. encrypted, corrupted, or
                # unsupported format) so one bad entry doesn't abort the
                # rest of the archive.
                continue
            for f in nested:
                f.title = f"[nested:{info.filename}] " + f.title
            findings.extend(nested)
        return findings

    def _analyze_zip_bytes(
        self,
        data: bytes,
        path: str,
        flag_pattern: re.Pattern,
        ai_client: Optional[AIClient],
        depth: str = "deep",
        session=None,
        dispatcher_module=None,
        _nest_depth: int = 0,
    ) -> List[Finding]:
        """Analyse a ZIP archive from in-memory *data* without any disk I/O."""
        findings: List[Finding] = []
        try:
            with zipfile.ZipFile(io.BytesIO(data), "r") as zf:
                findings.extend(self._check_comment(path, zf, flag_pattern))
                # Pass the raw bytes as zip_source so parallel workers each
                # wrap them in their own BytesIO – ZipFile is not thread-safe.
                findings.extend(self._check_encrypted(path, zf, flag_pattern, depth, zip_source=data))
                findings.extend(self._check_path_traversal(path, zf))
                if depth == "deep" and _nest_depth < _MAX_NEST_DEPTH:
                    findings.extend(self._check_nested(
                        path, zf, flag_pattern, ai_client,
                        depth=depth, session=session, dispatcher_module=dispatcher_module,
                        _nest_depth=_nest_depth,
                    ))
        except (zipfile.BadZipFile, Exception) as exc:
            findings.append(self._finding(
                path,
                "Archive read error",
                str(exc),
                severity="INFO",
                confidence=0.2,
            ))
        return findings

    def _check_generic_archive(self, path: str, flag_pattern: re.Pattern) -> List[Finding]:
        """Try to list gzip/bzip2/xz contents for comment-like metadata."""
        try:
            data = Path(path).read_bytes()
        except Exception:
            return []
        return self._check_generic_archive_bytes(data, path, flag_pattern)

    def _check_generic_archive_bytes(
        self, data: bytes, path: str, flag_pattern: re.Pattern
    ) -> List[Finding]:
        """Inspect the header area of a non-ZIP archive already in memory."""
        findings: List[Finding] = []
        try:
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
