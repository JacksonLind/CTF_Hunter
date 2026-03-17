"""
Document analyzer: PDF JS/embedded streams, DOCX macros, OLE objects.
"""
from __future__ import annotations

import re
import zipfile
from pathlib import Path
from typing import List, Optional

from core.report import Finding
from core.ai_client import AIClient
from .base import Analyzer


class DocumentAnalyzer(Analyzer):
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
            data = Path(path).read_bytes()
        except Exception as exc:
            return [self._finding(path, "Read error", str(exc), confidence=0.1)]

        if data.startswith(b"%PDF"):
            findings.extend(self._analyze_pdf(path, data, flag_pattern))
        elif data[:4] == b"PK\x03\x04":
            # DOCX/XLSX/PPTX = ZIP
            findings.extend(self._analyze_docx(path, flag_pattern))
        elif data[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
            # OLE binary (DOC, XLS, PPT)
            findings.extend(self._analyze_ole(path, flag_pattern))

        self._run_redispatch_hook(findings, session, dispatcher_module)
        return findings

    # ------------------------------------------------------------------

    def _analyze_pdf(self, path: str, data: bytes, flag_pattern: re.Pattern) -> List[Finding]:
        findings: List[Finding] = []
        text = data.decode("latin-1", errors="replace")

        suspicious_keys = ["/JavaScript", "/JS", "/EmbeddedFile", "/AA", "/OpenAction",
                           "/Launch", "/URI", "/SubmitForm", "/RichMedia"]
        for key in suspicious_keys:
            idx = text.find(key)
            if idx != -1:
                snippet = text[max(0, idx - 20):idx + 80]
                fm = self._check_flag(snippet, flag_pattern)
                findings.append(self._finding(
                    path,
                    f"PDF contains '{key}'",
                    f"Suspicious PDF key at offset ~{idx}: ...{snippet[:100]}...",
                    severity="HIGH",
                    offset=idx,
                    flag_match=fm,
                    confidence=0.80,
                ))

        # Search all stream data
        for m in re.finditer(rb"stream\r?\n(.*?)endstream", data, re.DOTALL):
            stream_data = m.group(1)
            # Try raw string search
            decoded = stream_data.decode("latin-1", errors="replace")
            if self._check_flag(decoded, flag_pattern):
                findings.append(self._finding(
                    path,
                    "Flag pattern in PDF stream",
                    decoded[:200],
                    severity="HIGH",
                    offset=m.start(),
                    flag_match=True,
                    confidence=0.95,
                ))

        # Try PyMuPDF for richer analysis
        try:
            import fitz
            doc = fitz.open(path)
            for page_num, page in enumerate(doc):
                page_text = page.get_text()
                if self._check_flag(page_text, flag_pattern):
                    findings.append(self._finding(
                        path,
                        f"Flag pattern in PDF page {page_num + 1} text",
                        page_text[:300],
                        severity="HIGH",
                        flag_match=True,
                        confidence=0.95,
                    ))
            doc.close()
        except Exception:
            pass

        return findings

    def _analyze_docx(self, path: str, flag_pattern: re.Pattern) -> List[Finding]:
        findings: List[Finding] = []
        try:
            with zipfile.ZipFile(path, "r") as zf:
                names = zf.namelist()
                # Check for VBA macros
                if "word/vbaProject.bin" in names or any(n.endswith(".bin") for n in names):
                    findings.append(self._finding(
                        path,
                        "DOCX contains VBA macro binary (vbaProject.bin)",
                        "Office macro detected — may contain malicious or CTF logic.",
                        severity="HIGH",
                        confidence=0.85,
                    ))
                # Check for embedded OLE objects
                ole_entries = [n for n in names if "embeddings" in n.lower() or n.endswith(".bin")]
                for entry in ole_entries:
                    findings.append(self._finding(
                        path,
                        f"DOCX embedded object: {entry}",
                        "Embedded file may contain hidden data.",
                        severity="MEDIUM",
                        confidence=0.60,
                    ))
                # Search all XML for flag patterns
                for name in names:
                    if name.endswith(".xml") or name.endswith(".rels"):
                        try:
                            content = zf.read(name).decode("utf-8", errors="replace")
                            if self._check_flag(content, flag_pattern):
                                findings.append(self._finding(
                                    path,
                                    f"Flag pattern in DOCX component: {name}",
                                    content[:300],
                                    severity="HIGH",
                                    flag_match=True,
                                    confidence=0.95,
                                ))
                        except Exception:
                            pass
        except Exception as exc:
            findings.append(self._finding(path, "DOCX read error", str(exc), confidence=0.1))
        return findings

    def _analyze_ole(self, path: str, flag_pattern: re.Pattern) -> List[Finding]:
        findings: List[Finding] = []
        try:
            import olefile
            if not olefile.isOleFile(path):
                return []
            ole = olefile.OleFileIO(path)
            for stream in ole.listdir():
                stream_path = "/".join(stream)
                if "VBA" in stream_path.upper() or "MACRO" in stream_path.upper():
                    findings.append(self._finding(
                        path,
                        f"OLE macro stream: {stream_path}",
                        "OLE VBA/macro stream detected.",
                        severity="HIGH",
                        confidence=0.85,
                    ))
                try:
                    data = ole.openstream(stream).read()
                    text = data.decode("latin-1", errors="replace")
                    if self._check_flag(text, flag_pattern):
                        findings.append(self._finding(
                            path,
                            f"Flag pattern in OLE stream '{stream_path}'",
                            text[:300],
                            severity="HIGH",
                            flag_match=True,
                            confidence=0.95,
                        ))
                except Exception:
                    pass
            ole.close()
        except ImportError:
            findings.append(self._finding(
                path,
                "OLE analysis skipped (olefile not installed)",
                "",
                severity="INFO",
                confidence=0.1,
            ))
        except Exception as exc:
            findings.append(self._finding(path, "OLE read error", str(exc), confidence=0.1))
        return findings
