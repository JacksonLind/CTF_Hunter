"""
Forensics Timeline Reconstruction analyzer.

Extracts all available timestamps from every possible source and
reconstructs a unified chronological timeline per file.
"""
from __future__ import annotations

import re
import os
import struct
import datetime
import zipfile
from pathlib import Path
from typing import List, Optional

from core.report import Finding
from core.ai_client import AIClient
from .base import Analyzer

_UTC = datetime.timezone.utc
_EPOCH = datetime.datetime(1970, 1, 1, tzinfo=_UTC)

# Maximum reasonable POSIX timestamp (~year 2033); values above this are suspicious
_MAX_UNIX_TIMESTAMP = 2_000_000_000


def _safe_dt(ts: float) -> Optional[datetime.datetime]:
    """Convert a POSIX timestamp to UTC datetime, returning None on error."""
    try:
        return datetime.datetime.fromtimestamp(ts, tz=_UTC)
    except (OSError, OverflowError, ValueError):
        return None


def _ts_hex_decode(ts: float) -> Optional[str]:
    """Try to decode a timestamp's hex representation as ASCII."""
    try:
        raw = struct.pack(">Q", int(ts))
        decoded = raw.lstrip(b'\x00').decode("ascii")
        if len(decoded) >= 4 and all(0x20 <= ord(c) < 0x7F for c in decoded):
            return decoded
    except Exception:
        pass
    return None


class ForensicsTimelineAnalyzer(Analyzer):
    """Extract and reconstruct a chronological timeline for each analyzed file."""

    def analyze(
        self,
        path: str,
        flag_pattern: re.Pattern,
        depth: str,
        ai_client: Optional[AIClient],
        **_kw,
    ) -> List[Finding]:
        findings: List[Finding] = []
        timeline: list[dict] = []

        now = datetime.datetime.now(_UTC)

        # 1. Filesystem metadata
        self._extract_fs_timestamps(path, timeline)

        # 2. Source-specific extraction
        data = b""
        try:
            data = Path(path).read_bytes()
        except Exception:
            pass

        ext = Path(path).suffix.lower()

        if ext in (".png", ".jpg", ".jpeg", ".tif", ".tiff", ".heic"):
            self._extract_exif(path, timeline)
        elif ext == ".pdf":
            self._extract_pdf_timestamps(data, timeline)
        elif ext in (".docx", ".xlsx", ".pptx"):
            self._extract_docx_timestamps(path, timeline)
        elif ext == ".zip":
            self._extract_zip_timestamps(path, timeline)
        elif ext in (".mp3", ".flac", ".ogg"):
            self._extract_id3_timestamps(path, timeline)
        elif ext in (".pcap", ".pcapng", ".cap"):
            self._extract_pcap_timestamps(data, timeline)
        elif ext in (".db", ".sqlite", ".sqlite3"):
            self._extract_sqlite_timestamps(path, timeline)

        if data[:4] == b"\x7fELF":
            self._extract_elf_timestamp(data, timeline)
        elif data[:2] == b"MZ":
            self._extract_pe_timestamp(data, timeline)
        elif data[:2] in (b"PK",) and ext != ".zip":
            # Could be a DOCX/XLSX/PPTX without the proper extension
            try:
                self._extract_zip_timestamps(path, timeline)
            except Exception:
                pass

        if not timeline:
            return []

        # Sort by datetime
        timeline.sort(key=lambda x: x["dt"])

        # Anomaly detection + flag checking
        findings.extend(self._flag_anomalies(path, timeline, now, flag_pattern))

        # Deep mode: send to AI
        if depth == "deep" and ai_client:
            try:
                rows = self._format_table(timeline)
                prompt = (
                    "The following is a timestamp timeline extracted from a CTF file. "
                    "Identify any anomalies, hidden data, or suspicious patterns:\n\n"
                    + rows
                )
                ai_response = ai_client.ask(prompt)
                if ai_response:
                    findings.append(self._finding(
                        path,
                        "AI timeline anomaly interpretation",
                        ai_response[:800],
                        severity="INFO",
                        confidence=0.6,
                    ))
            except Exception:
                pass

        # Emit full timeline as an INFO finding
        table = self._format_table(timeline)
        findings.append(self._finding(
            path,
            f"Timeline: {len(timeline)} timestamp(s) extracted",
            table,
            severity="INFO",
            confidence=0.9,
        ))

        return findings

    # ------------------------------------------------------------------
    # Timestamp extractors
    # ------------------------------------------------------------------

    def _extract_fs_timestamps(self, path: str, timeline: list[dict]) -> None:
        try:
            st = os.stat(path)
            for name, ts in [
                ("fs:mtime", st.st_mtime),
                ("fs:atime", st.st_atime),
                ("fs:ctime", st.st_ctime),
            ]:
                dt = _safe_dt(ts)
                if dt:
                    timeline.append({"source": "filesystem", "field": name,
                                     "raw": ts, "dt": dt, "anomaly": ""})
        except Exception:
            pass

    def _extract_exif(self, path: str, timeline: list[dict]) -> None:
        try:
            from PIL import Image
            from PIL.ExifTags import TAGS
            img = Image.open(path)
            exif = img.getexif()
            if not exif:
                return
            tag_names = {v: k for k, v in TAGS.items()}
            for field in ("DateTimeOriginal", "DateTimeDigitized", "DateTime"):
                tag_id = tag_names.get(field)
                if tag_id and tag_id in exif:
                    raw_val = str(exif[tag_id])
                    try:
                        dt = datetime.datetime.strptime(raw_val, "%Y:%m:%d %H:%M:%S")
                        dt = dt.replace(tzinfo=_UTC)
                        timeline.append({
                            "source": "EXIF", "field": field,
                            "raw": raw_val, "dt": dt, "anomaly": "",
                        })
                    except ValueError:
                        pass
        except Exception:
            pass

    def _extract_pdf_timestamps(self, data: bytes, timeline: list[dict]) -> None:
        pattern = re.compile(rb"/(?:CreationDate|ModDate)\s*\(D:(\d{14})")
        for m in pattern.finditer(data):
            field_match = re.search(rb"/(CreationDate|ModDate)", data[:m.start() + 20])
            field = "CreationDate" if field_match and b"Creation" in field_match.group() else "ModDate"
            raw_val = m.group(1).decode("ascii", errors="replace")
            try:
                dt = datetime.datetime.strptime(raw_val[:14], "%Y%m%d%H%M%S")
                dt = dt.replace(tzinfo=_UTC)
                timeline.append({
                    "source": "PDF", "field": field,
                    "raw": raw_val, "dt": dt, "anomaly": "",
                })
            except ValueError:
                pass

    def _extract_docx_timestamps(self, path: str, timeline: list[dict]) -> None:
        try:
            import zipfile as zf
            import xml.etree.ElementTree as ET
            with zf.ZipFile(path, "r") as z:
                if "docProps/core.xml" not in z.namelist():
                    return
                xml_data = z.read("docProps/core.xml")
                root = ET.fromstring(xml_data)
                ns = {
                    "cp": "http://schemas.openxmlformats.org/package/2006/metadata/core-properties",
                    "dcterms": "http://purl.org/dc/terms/",
                }
                for field, xpath in [
                    ("created", ".//dcterms:created"),
                    ("modified", ".//dcterms:modified"),
                ]:
                    el = root.find(xpath, ns)
                    if el is not None and el.text:
                        raw_val = el.text.strip()
                        try:
                            dt = datetime.datetime.fromisoformat(
                                raw_val.replace("Z", "+00:00")
                            )
                            if dt.tzinfo is None:
                                dt = dt.replace(tzinfo=_UTC)
                            timeline.append({
                                "source": "DOCX", "field": field,
                                "raw": raw_val, "dt": dt, "anomaly": "",
                            })
                        except ValueError:
                            pass
        except Exception:
            pass

    def _extract_zip_timestamps(self, path: str, timeline: list[dict]) -> None:
        try:
            with zipfile.ZipFile(path, "r") as z:
                for info in z.infolist():
                    if info.date_time and info.date_time[0] > 1970:
                        try:
                            dt = datetime.datetime(*info.date_time, tzinfo=_UTC)
                            timeline.append({
                                "source": "ZIP",
                                "field": f"entry:{info.filename}",
                                "raw": str(info.date_time),
                                "dt": dt,
                                "anomaly": "",
                            })
                        except (ValueError, TypeError):
                            pass
        except Exception:
            pass

    def _extract_id3_timestamps(self, path: str, timeline: list[dict]) -> None:
        try:
            import mutagen
            audio = mutagen.File(path)
            if not audio or not audio.tags:
                return
            for frame_id in ("TDRC", "TYER", "TDRL"):
                tag = audio.tags.get(frame_id)
                if tag:
                    raw_val = str(tag)
                    year_match = re.search(r"(\d{4})", raw_val)
                    if year_match:
                        year = int(year_match.group(1))
                        try:
                            dt = datetime.datetime(year, 1, 1, tzinfo=_UTC)
                            timeline.append({
                                "source": "ID3", "field": frame_id,
                                "raw": raw_val, "dt": dt, "anomaly": "",
                            })
                        except ValueError:
                            pass
        except Exception:
            pass

    def _extract_pcap_timestamps(self, data: bytes, timeline: list[dict]) -> None:
        if len(data) < 24:
            return
        # PCAP global header: magic, version major/minor, timezone offset, sig figs,
        # snaplen, datalink
        magic = data[:4]
        if magic not in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4"):
            return
        bo = "<" if magic == b"\xd4\xc3\xb2\xa1" else ">"
        # First packet header starts at offset 24
        first_ts: Optional[float] = None
        last_ts: Optional[float] = None
        offset = 24
        while offset + 16 <= len(data):
            try:
                ts_sec, ts_usec, incl_len, orig_len = struct.unpack_from(
                    f"{bo}IIII", data, offset
                )
                ts = ts_sec + ts_usec / 1_000_000
                dt = _safe_dt(ts)
                if dt and 1970 < dt.year < 2100:
                    if first_ts is None:
                        first_ts = ts
                        timeline.append({
                            "source": "PCAP", "field": "first_packet",
                            "raw": ts, "dt": dt, "anomaly": "",
                        })
                    last_ts = ts
                offset += 16 + incl_len
            except struct.error:
                break
        if last_ts and last_ts != first_ts:
            dt = _safe_dt(last_ts)
            if dt:
                timeline.append({
                    "source": "PCAP", "field": "last_packet",
                    "raw": last_ts, "dt": dt, "anomaly": "",
                })

    def _extract_sqlite_timestamps(self, path: str, timeline: list[dict]) -> None:
        try:
            import sqlite3
            conn = sqlite3.connect(path)
            cur = conn.cursor()
            # sqlite_master timestamps
            cur.execute("SELECT name, type FROM sqlite_master WHERE type='table'")
            tables = cur.fetchall()
            for table_name, _ in tables:
                try:
                    # Look for common timestamp column names
                    cur.execute(f'PRAGMA table_info("{table_name}")')
                    cols = [row[1] for row in cur.fetchall()]
                    ts_cols = [c for c in cols if any(
                        kw in c.lower() for kw in ("time", "date", "created", "modified")
                    )]
                    for col in ts_cols[:2]:
                        cur.execute(
                            f'SELECT "{col}" FROM "{table_name}" '
                            f'WHERE "{col}" IS NOT NULL LIMIT 3'
                        )
                        for row in cur.fetchall():
                            val = row[0]
                            if isinstance(val, (int, float)) and 0 < val < _MAX_UNIX_TIMESTAMP:
                                dt = _safe_dt(float(val))
                                if dt:
                                    timeline.append({
                                        "source": "SQLite",
                                        "field": f"{table_name}.{col}",
                                        "raw": val, "dt": dt, "anomaly": "",
                                    })
                            elif isinstance(val, str):
                                for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
                                    try:
                                        dt = datetime.datetime.strptime(val[:19], fmt)
                                        dt = dt.replace(tzinfo=_UTC)
                                        timeline.append({
                                            "source": "SQLite",
                                            "field": f"{table_name}.{col}",
                                            "raw": val, "dt": dt, "anomaly": "",
                                        })
                                        break
                                    except ValueError:
                                        pass
                except Exception:
                    pass
            conn.close()
        except Exception:
            pass

    def _extract_pe_timestamp(self, data: bytes, timeline: list[dict]) -> None:
        try:
            # PE: find PE signature (MZ -> PE offset at 0x3C)
            if len(data) < 0x40:
                return
            pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
            if pe_offset + 8 > len(data):
                return
            if data[pe_offset:pe_offset + 4] != b"PE\x00\x00":
                return
            ts = struct.unpack_from("<I", data, pe_offset + 8)[0]
            dt = _safe_dt(float(ts))
            if dt and 1970 < dt.year < 2100:
                timeline.append({
                    "source": "PE", "field": "TimeDateStamp",
                    "raw": ts, "dt": dt, "anomaly": "",
                })
        except Exception:
            pass

    def _extract_elf_timestamp(self, data: bytes, timeline: list[dict]) -> None:
        # ELF has no standard compile timestamp in the header itself.
        # Look for .note.gnu.build-id (not a timestamp but sometimes contains one).
        # ELF section headers: check for any embedded Unix timestamp patterns.
        try:
            # Search for note section with build-id
            build_id_marker = b"\x04\x00\x00\x00\x14\x00\x00\x00\x03\x00\x00\x00GNU\x00"
            idx = data.find(build_id_marker)
            if idx != -1:
                # Build-ID follows the marker header
                build_id = data[idx + len(build_id_marker):idx + len(build_id_marker) + 20]
                timeline.append({
                    "source": "ELF", "field": ".note.gnu.build-id",
                    "raw": build_id.hex(),
                    "dt": datetime.datetime(1970, 1, 1, tzinfo=_UTC),
                    "anomaly": "",
                })
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Anomaly detection
    # ------------------------------------------------------------------

    def _flag_anomalies(
        self,
        path: str,
        timeline: list[dict],
        now: datetime.datetime,
        flag_pattern: re.Pattern,
    ) -> List[Finding]:
        findings: List[Finding] = []

        dt_values: list[datetime.datetime] = []

        for entry in timeline:
            dt = entry["dt"]
            raw = entry["raw"]
            anomalies = []

            # Unix epoch or year 1970
            if dt.year == 1970 or (isinstance(raw, (int, float)) and raw == 0):
                anomalies.append("Unix epoch (suspicious)")

            # Future timestamp
            if dt > now:
                anomalies.append("FUTURE timestamp")
                findings.append(self._finding(
                    path,
                    f"Future timestamp in {entry['field']}",
                    f"Source: {entry['source']} | Field: {entry['field']} | "
                    f"Value: {entry['raw']} | DateTime: {dt.isoformat()}",
                    severity="HIGH",
                    confidence=0.90,
                ))

            # Timestamp encodes printable ASCII
            if isinstance(raw, (int, float)):
                decoded = _ts_hex_decode(float(raw))
                if decoded:
                    anomalies.append(f"Hex encodes: {decoded!r}")
                    sev = "HIGH" if self._check_flag(decoded, flag_pattern) else "MEDIUM"
                    findings.append(self._finding(
                        path,
                        f"Timestamp value encodes printable text",
                        f"Source: {entry['source']} | Field: {entry['field']} | "
                        f"Timestamp: {int(raw)} → {decoded!r}",
                        severity=sev,
                        flag_match=(sev == "HIGH"),
                        confidence=0.75,
                    ))

            entry["anomaly"] = "; ".join(anomalies)
            dt_values.append(dt)

        # Identical timestamps across multiple fields
        if len(dt_values) > 1:
            count = {}
            for entry in timeline:
                key = entry["dt"].isoformat()
                count[key] = count.get(key, 0) + 1
            for ts_val, cnt in count.items():
                if cnt >= 3:
                    fields = [e["field"] for e in timeline if e["dt"].isoformat() == ts_val]
                    findings.append(self._finding(
                        path,
                        "Identical timestamps across multiple fields (possible tampering)",
                        f"Timestamp: {ts_val} | Fields: {', '.join(fields)}",
                        severity="MEDIUM",
                        confidence=0.60,
                    ))

        return findings

    def _format_table(self, timeline: list[dict]) -> str:
        header = f"{'Source':<20} | {'Field':<35} | {'Raw Value':<22} | {'DateTime (UTC)':<26} | Anomaly"
        sep = "-" * len(header)
        rows = [header, sep]
        for entry in timeline:
            raw_str = str(entry["raw"])[:22]
            dt_str = entry["dt"].isoformat()
            rows.append(
                f"{entry['source']:<20} | {entry['field']:<35} | "
                f"{raw_str:<22} | {dt_str:<26} | {entry['anomaly']}"
            )
        return "\n".join(rows)
