"""
Filesystem analyzer: disk image walking, deleted file recovery, hidden partition detection.
Uses pytsk3 (The Sleuth Kit) when available, falls back to pyfilesystem2/zipfile scan.
"""
from __future__ import annotations

import re
import os
import tempfile
from pathlib import Path
from typing import List, Optional

from core.report import Finding
from core.ai_client import AIClient
from .base import Analyzer


class FilesystemAnalyzer(Analyzer):
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
        try:
            import pytsk3
            findings.extend(self._analyze_with_tsk(path, flag_pattern, depth, ai_client))
        except ImportError:
            findings.extend(self._analyze_fallback(path, flag_pattern, depth))
        except Exception as exc:
            findings.append(self._finding(
                path, "Filesystem analysis error", str(exc),
                severity="INFO", confidence=0.2,
            ))
        self._run_redispatch_hook(findings, session, dispatcher_module)
        return findings

    # ------------------------------------------------------------------

    def _analyze_with_tsk(
        self,
        path: str,
        flag_pattern: re.Pattern,
        depth: str,
        ai_client: Optional[AIClient],
    ) -> List[Finding]:
        import pytsk3
        findings: List[Finding] = []
        try:
            img = pytsk3.Img_Info(path)
        except Exception as exc:
            return [self._finding(path, f"TSK image open error: {exc}", "", confidence=0.2)]

        try:
            fs = pytsk3.FS_Info(img)
        except Exception as exc:
            return [self._finding(path, f"TSK filesystem open error: {exc}", "", confidence=0.2)]

        findings.append(self._finding(
            path,
            f"Disk image opened successfully via TSK",
            f"Block size: {fs.info.block_size}, Block count: {fs.info.block_count}",
            severity="INFO",
            confidence=0.6,
        ))

        # Walk directory recursively
        try:
            dir_obj = fs.open_dir(path="/")
            findings.extend(self._walk_dir(path, dir_obj, fs, flag_pattern, depth, []))
        except Exception as exc:
            findings.append(self._finding(
                path, f"TSK directory walk error: {exc}", "", confidence=0.2,
            ))
        return findings

    def _walk_dir(
        self,
        img_path: str,
        directory,
        fs,
        flag_pattern: re.Pattern,
        depth: str,
        path_stack: list,
        max_files: int = 500,
    ) -> List[Finding]:
        import pytsk3
        findings: List[Finding] = []
        count = 0
        for entry in directory:
            if count >= max_files:
                break
            try:
                name = entry.info.name.name.decode("utf-8", errors="replace")
                if name in (".", ".."):
                    continue
                full_path = "/".join(path_stack + [name])
                meta = entry.info.meta
                if meta is None:
                    # Deleted file (no metadata)
                    findings.append(self._finding(
                        img_path,
                        f"Deleted file detected: {full_path}",
                        "Inode metadata is None — file may be deleted.",
                        severity="MEDIUM",
                        confidence=0.65,
                    ))
                    continue

                file_type = meta.type
                # TSK_FS_META_TYPE_REG = 1
                if file_type == pytsk3.TSK_FS_META_TYPE_REG:
                    size = meta.size
                    if self._check_flag(full_path, flag_pattern):
                        findings.append(self._finding(
                            img_path,
                            f"Flag pattern in filename: {full_path}",
                            f"File: {full_path}, size={size}",
                            severity="HIGH",
                            flag_match=True,
                            confidence=0.90,
                        ))
                    else:
                        findings.append(self._finding(
                            img_path,
                            f"File found: {full_path} ({size} bytes)",
                            "",
                            severity="INFO",
                            confidence=0.4,
                        ))
                    # Read contents if deep mode and small enough
                    if depth == "deep" and size > 0 and size < 1024 * 1024:
                        try:
                            f = entry.as_file()
                            content = f.read_random(0, size)
                            text = content.decode("utf-8", errors="replace")
                            if self._check_flag(text, flag_pattern):
                                findings.append(self._finding(
                                    img_path,
                                    f"Flag pattern in file contents: {full_path}",
                                    text[:300],
                                    severity="HIGH",
                                    flag_match=True,
                                    confidence=0.95,
                                ))
                        except Exception:
                            pass
                elif file_type == pytsk3.TSK_FS_META_TYPE_DIR:
                    sub_dir = entry.as_directory()
                    findings.extend(self._walk_dir(
                        img_path, sub_dir, fs, flag_pattern, depth,
                        path_stack + [name], max_files - count,
                    ))
                count += 1
            except Exception:
                count += 1
                continue
        return findings

    def _analyze_fallback(
        self,
        path: str,
        flag_pattern: re.Pattern,
        depth: str,
    ) -> List[Finding]:
        """Fallback: scan ISO via zipfile or look for raw file signatures."""
        findings: List[Finding] = []

        # Try ISO/ZIP-style directory listing
        try:
            import zipfile
            if zipfile.is_zipfile(path):
                with zipfile.ZipFile(path, "r") as zf:
                    for info in zf.infolist():
                        fname = info.filename
                        if self._check_flag(fname, flag_pattern):
                            findings.append(self._finding(
                                path,
                                f"Flag pattern in filesystem path: {fname}",
                                "",
                                severity="HIGH",
                                flag_match=True,
                                confidence=0.90,
                            ))
                        else:
                            findings.append(self._finding(
                                path,
                                f"Filesystem entry: {fname}",
                                "",
                                severity="INFO",
                                confidence=0.4,
                            ))
                        if depth == "deep":
                            try:
                                content = zf.read(info.filename).decode("utf-8", errors="replace")
                                if self._check_flag(content, flag_pattern):
                                    findings.append(self._finding(
                                        path,
                                        f"Flag pattern in filesystem file: {fname}",
                                        content[:300],
                                        severity="HIGH",
                                        flag_match=True,
                                        confidence=0.95,
                                    ))
                            except Exception:
                                pass
                return findings
        except Exception:
            pass

        # Raw scan for magic bytes
        try:
            data = Path(path).read_bytes()
            _FILE_SIGS = {
                b"\x89PNG\r\n\x1a\n": "PNG",
                b"\xff\xd8\xff": "JPEG",
                b"PK\x03\x04": "ZIP",
                b"\x7fELF": "ELF",
                b"%PDF": "PDF",
            }
            for sig, name in _FILE_SIGS.items():
                count = data.count(sig)
                if count > 0:
                    idx = data.index(sig)
                    findings.append(self._finding(
                        path,
                        f"Found {count} embedded {name} signature(s) in disk image",
                        f"First occurrence at offset 0x{idx:x}",
                        severity="MEDIUM",
                        offset=idx,
                        confidence=0.65,
                    ))
        except Exception:
            pass

        return findings
