"""
Filesystem analyzer: disk image walking, deleted file recovery, hidden partition detection.
Uses pytsk3 (The Sleuth Kit) when available, falls back to pyfilesystem2/zipfile scan.
"""
from __future__ import annotations

import re
import os
import struct
import tempfile
import time as _time_mod
from pathlib import Path
from typing import List, Optional, Tuple

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

        # Inode timestamp steganography check
        try:
            findings.extend(self._check_inode_timestamps_tsk(path, fs, flag_pattern))
        except Exception:
            pass

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

        # Raw scan for magic bytes + ext4 inode timestamp steg check
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
            # Raw ext4 inode timestamp steg
            findings.extend(self._check_inode_timestamps_raw(path, data, flag_pattern))
        except Exception:
            pass

        return findings

    # ------------------------------------------------------------------
    # Inode timestamp steganography
    # ------------------------------------------------------------------

    def _check_inode_timestamps_tsk(
        self,
        img_path: str,
        fs,
        flag_pattern: re.Pattern,
    ) -> List[Finding]:
        """Detect ASCII encoding in inode atime/mtime/ctime/crtime via pytsk3."""
        import pytsk3  # noqa: F401 — already imported by caller
        records: List[Tuple[str, int, int, int, int]] = []
        try:
            self._collect_ts_records(fs.open_dir(path="/"), records, [])
        except Exception:
            return []
        if len(records) < 4:
            return []
        return self._decode_timestamp_channel(img_path, records, flag_pattern, "pytsk3")

    def _collect_ts_records(
        self,
        directory,
        records: List[Tuple[str, int, int, int, int]],
        path_stack: List[str],
        max_files: int = 500,
    ) -> None:
        """Recursively collect (full_path, atime, mtime, ctime, crtime) for regular files."""
        import pytsk3
        for entry in directory:
            if len(records) >= max_files:
                break
            try:
                name = entry.info.name.name.decode("utf-8", errors="replace")
                if name in (".", ".."):
                    continue
                meta = entry.info.meta
                if meta is None:
                    continue
                full_name = "/".join(path_stack + [name]) if path_stack else name
                if meta.type == pytsk3.TSK_FS_META_TYPE_REG:
                    records.append((
                        full_name,
                        int(getattr(meta, "atime",  0) or 0),
                        int(getattr(meta, "mtime",  0) or 0),
                        int(getattr(meta, "ctime",  0) or 0),
                        int(getattr(meta, "crtime", 0) or 0),
                    ))
                elif meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                    try:
                        sub_dir = entry.as_directory()
                        self._collect_ts_records(
                            sub_dir, records, path_stack + [name], max_files
                        )
                    except Exception:
                        pass
            except Exception:
                continue

    def _check_inode_timestamps_raw(
        self,
        img_path: str,
        data: bytes,
        flag_pattern: re.Pattern,
    ) -> List[Finding]:
        """Detect inode timestamp steg by parsing raw ext4 without pytsk3."""
        try:
            records = self._parse_ext4_inodes(data)
        except Exception:
            return []
        if len(records) < 4:
            return []
        return self._decode_timestamp_channel(img_path, records, flag_pattern, "raw-ext4")

    @staticmethod
    def _parse_ext4_inodes(
        data: bytes,
    ) -> List[Tuple[str, int, int, int, int]]:
        """Parse ext4 superblock + inode tables; return (name, atime, mtime, ctime, crtime).

        No directory parsing: name is a placeholder inode_{N}.
        Records are ordered by inode number (proxy for creation order).
        """
        SB_OFF = 1024
        if len(data) < SB_OFF + 100:
            return []

        magic = struct.unpack_from("<H", data, SB_OFF + 0x38)[0]
        if magic != 0xEF53:
            return []

        inodes_count     = struct.unpack_from("<I", data, SB_OFF + 0x00)[0]
        log_block_size   = struct.unpack_from("<I", data, SB_OFF + 0x18)[0]
        blocks_per_group = struct.unpack_from("<I", data, SB_OFF + 0x20)[0]  # noqa: F841
        inodes_per_group = struct.unpack_from("<I", data, SB_OFF + 0x28)[0]
        first_data_block = struct.unpack_from("<I", data, SB_OFF + 0x14)[0]
        inode_size       = struct.unpack_from("<H", data, SB_OFF + 0x58)[0]
        feature_incompat = struct.unpack_from("<I", data, SB_OFF + 0x60)[0]

        block_size = 1024 << min(int(log_block_size), 6)  # cap at 64 KB

        if inode_size < 128 or inode_size > 4096 or inodes_per_group == 0:
            return []

        INCOMPAT_64BIT = 0x80
        desc_size = 64 if (feature_incompat & INCOMPAT_64BIT) else 32

        gdt_off = (first_data_block + 1) * block_size
        num_groups = (inodes_count + inodes_per_group - 1) // inodes_per_group

        records: List[Tuple[str, int, int, int, int]] = []

        for grp in range(num_groups):
            gd_off = gdt_off + grp * desc_size
            if gd_off + desc_size > len(data):
                break

            it_lo = struct.unpack_from("<I", data, gd_off + 0x08)[0]
            if desc_size >= 64:
                it_hi = struct.unpack_from("<I", data, gd_off + 0x28)[0]
                it_block = (int(it_hi) << 32) | it_lo
            else:
                it_block = int(it_lo)

            it_off = it_block * block_size

            for idx in range(inodes_per_group):
                global_ino = grp * inodes_per_group + idx + 1
                if global_ino > inodes_count:
                    break
                if global_ino <= 10:          # skip reserved inodes 1–10
                    continue

                ino_off = it_off + idx * inode_size
                if ino_off + 128 > len(data):
                    break

                i_mode = struct.unpack_from("<H", data, ino_off)[0]
                # Regular file: top nibble of mode == 8
                if (i_mode & 0xF000) != 0x8000 or i_mode == 0:
                    continue

                atime = struct.unpack_from("<I", data, ino_off + 0x08)[0]
                ctime = struct.unpack_from("<I", data, ino_off + 0x0C)[0]
                mtime = struct.unpack_from("<I", data, ino_off + 0x10)[0]
                crtime = 0
                if inode_size >= 0x94 + 4 and ino_off + 0x94 + 4 <= len(data):
                    crtime = struct.unpack_from("<I", data, ino_off + 0x90)[0]

                if atime == 0 and mtime == 0 and ctime == 0:
                    continue  # unallocated / empty inode

                records.append((f"inode_{global_ino}", atime, mtime, ctime, crtime))

        return records

    def _decode_timestamp_channel(
        self,
        img_path: str,
        records: List[Tuple[str, int, int, int, int]],
        flag_pattern: re.Pattern,
        source: str,
    ) -> List[Finding]:
        """Try sort orders × timestamp fields × formulas; emit findings for printable hits."""

        def _natural_key(rec: Tuple) -> List:
            parts = re.split(r"(\d+)", rec[0].lower())
            return [int(p) if p.isdigit() else p for p in parts]

        ts_fields = [
            ("atime",  1),
            ("mtime",  2),
            ("ctime",  3),
            ("crtime", 4),
        ]
        sort_orders = [
            ("name",  sorted(records, key=_natural_key)),
            ("order", list(records)),
        ]
        formulas = [
            ("mm\u00d760+ss", self._ts_mmss),
            ("ss",            self._ts_ss),
        ]

        seen: set = set()
        findings: List[Finding] = []

        for sort_label, sorted_recs in sort_orders:
            for field_name, field_idx in ts_fields:
                ts_vals = [r[field_idx] for r in sorted_recs]
                for formula_name, decode_fn in formulas:
                    try:
                        decoded = decode_fn(ts_vals)
                    except Exception:
                        continue
                    if not decoded or len(decoded) < 4:
                        continue
                    printable = sum(1 for c in decoded if 0x20 <= ord(c) <= 0x7E)
                    if printable < len(decoded) * 0.80:
                        continue
                    key = decoded[:120]
                    if key in seen:
                        continue
                    seen.add(key)
                    fm = self._check_flag(decoded, flag_pattern)
                    findings.append(self._finding(
                        img_path,
                        f"Inode timestamp steg \u2014 {field_name}/{formula_name}",
                        (
                            f"Source: {source} | Files: {len(sorted_recs)} | "
                            f"Sort: {sort_label} | Field: {field_name} | "
                            f"Formula: {formula_name}\n"
                            f"Decoded ({len(decoded)} chars): {decoded[:300]}"
                        ),
                        severity="HIGH" if fm else "MEDIUM",
                        flag_match=fm,
                        confidence=0.93 if fm else 0.72,
                    ))

        return findings

    @staticmethod
    def _ts_mmss(timestamps: List[int]) -> str:
        """Decode epoch timestamps as chr(mm*60 + ss) per timestamp."""
        result = []
        for t in timestamps:
            if not t:
                result.append("\x00")
                continue
            dt = _time_mod.gmtime(int(t))
            val = dt.tm_min * 60 + dt.tm_sec
            result.append(chr(val) if 0x20 <= val <= 0x7E else "\x00")
        return "".join(result)

    @staticmethod
    def _ts_ss(timestamps: List[int]) -> str:
        """Decode epoch timestamps as chr(seconds) per timestamp."""
        result = []
        for t in timestamps:
            if not t:
                result.append("\x00")
                continue
            dt = _time_mod.gmtime(int(t))
            val = dt.tm_sec
            result.append(chr(val) if 0x20 <= val <= 0x7E else "\x00")
        return "".join(result)
