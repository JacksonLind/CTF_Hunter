# """
# Magic-byte dispatcher: identifies file types and routes to all applicable analyzers.
# """
# from __future__ import annotations

# import logging
# import re
# from pathlib import Path
# from typing import List, Optional

# from .report import Finding, Session
# from .deduplicator import deduplicate
# from .external import run_file
# from .ai_client import AIClient
# from .confidence import ConfidenceScorer

# # Analyzer imports
# from analyzers.base import Analyzer
# from analyzers.generic import GenericAnalyzer
# from analyzers.image import ImageAnalyzer
# from analyzers.audio import AudioAnalyzer
# from analyzers.archive import ArchiveAnalyzer
# from analyzers.document import DocumentAnalyzer
# from analyzers.binary import BinaryAnalyzer
# from analyzers.steganalysis import SteganalysisAnalyzer
# from analyzers.encoding import EncodingAnalyzer
# from analyzers.crypto import CryptoAnalyzer
# from analyzers.pcap import PcapAnalyzer
# from analyzers.filesystem import FilesystemAnalyzer
# from analyzers.database import DatabaseAnalyzer
# from analyzers.disassembly import DisassemblyAnalyzer
# from analyzers.classical_cipher import ClassicalCipherAnalyzer
# from analyzers.forensics_timeline import ForensicsTimelineAnalyzer
# from analyzers.image_format import ImageFormatAnalyzer
# from analyzers.crypto_rsa import CryptoRSAAnalyzer

# # ---------------------------------------------------------------------------
# # Magic byte signatures mapped to analyzer keys
# # ---------------------------------------------------------------------------

# _MAGIC_MAP: list[tuple[bytes, list[str]]] = [
#     (b"\x89PNG\r\n\x1a\n",    ["image", "steganalysis", "image_format"]),
#     (b"\xff\xd8\xff",          ["image", "steganalysis", "image_format"]),
#     (b"GIF87a",                ["image", "steganalysis", "image_format"]),
#     (b"GIF89a",                ["image", "steganalysis", "image_format"]),
#     (b"BM",                    ["image", "steganalysis", "image_format"]),
#     (b"RIFF",                  ["audio"]),
#     (b"ID3",                   ["audio"]),
#     (b"\xff\xfb",              ["audio"]),
#     (b"fLaC",                  ["audio"]),
#     (b"OggS",                  ["audio"]),
#     (b"PK\x03\x04",           ["archive"]),
#     (b"PK\x05\x06",           ["archive"]),
#     (b"\x1f\x8b",             ["archive"]),
#     (b"BZh",                   ["archive"]),
#     (b"\xfd7zXZ\x00",         ["archive"]),
#     (b"Rar!\x1a\x07",         ["archive"]),
#     (b"%PDF",                  ["document"]),
#     (b"\xd0\xcf\x11\xe0",     ["document"]),   # OLE (DOC, XLS, PPT)
#     (b"\x7fELF",              ["binary", "disassembly"]),
#     (b"MZ",                    ["binary", "disassembly"]),
#     (b"\xca\xfe\xba\xbe",     ["binary", "disassembly"]),  # Mach-O
#     (b"SQLite format 3\x00",   ["database"]),
# ]

# _MIME_MAP: dict[str, list[str]] = {
#     "image/png":              ["image", "steganalysis", "image_format"],
#     "image/jpeg":             ["image", "steganalysis", "image_format"],
#     "image/gif":              ["image", "steganalysis", "image_format"],
#     "image/bmp":              ["image", "steganalysis", "image_format"],
#     "image/tiff":             ["image", "steganalysis"],
#     "audio/wav":              ["audio"],
#     "audio/x-wav":            ["audio"],
#     "audio/mpeg":             ["audio"],
#     "audio/flac":             ["audio"],
#     "audio/ogg":              ["audio"],
#     "application/zip":        ["archive"],
#     "application/x-rar":      ["archive"],
#     "application/gzip":       ["archive"],
#     "application/x-bzip2":    ["archive"],
#     "application/x-xz":       ["archive"],
#     "application/pdf":        ["document"],
#     "application/msword":     ["document"],
#     "application/vnd.openxmlformats-officedocument.wordprocessingml.document": ["document"],
#     "application/x-elf":      ["binary", "disassembly"],
#     "application/x-dosexec":  ["binary", "disassembly"],
#     "application/vnd.tcpdump.pcap": ["pcap"],
#     "application/x-pcapng":   ["pcap"],
#     "application/x-sqlite3":  ["database"],
#     "application/octet-stream": [],
# }

# _DISK_EXTS = {".dd", ".img", ".iso", ".raw", ".dmg"}

# _ANALYZER_REGISTRY: dict[str, type[Analyzer]] = {
#     "image":           ImageAnalyzer,
#     "audio":           AudioAnalyzer,
#     "archive":         ArchiveAnalyzer,
#     "document":        DocumentAnalyzer,
#     "binary":          BinaryAnalyzer,
#     "steganalysis":    SteganalysisAnalyzer,
#     "encoding":        EncodingAnalyzer,
#     "crypto":          CryptoAnalyzer,
#     "pcap":            PcapAnalyzer,
#     "filesystem":      FilesystemAnalyzer,
#     "database":        DatabaseAnalyzer,
#     "disassembly":     DisassemblyAnalyzer,
#     "classical_cipher": ClassicalCipherAnalyzer,
#     "forensics_timeline": ForensicsTimelineAnalyzer,
#     "image_format":    ImageFormatAnalyzer,
#     "crypto_rsa":      CryptoRSAAnalyzer,
# }

# # PEM/DER/RSA detection patterns
# _PEM_RE = re.compile(rb"-----BEGIN [A-Z ]+-----")
# _DER_HEADER = b"\x30\x82"  # ASN.1 SEQUENCE tag with 2-byte length
# _RSA_PAIR_RE = re.compile(
#     rb"(?:(?:0x[0-9a-fA-F]{64,})|(?:[0-9]{100,}))"
# )

# _CONFIDENCE_SCORER = ConfidenceScorer()
# _log = logging.getLogger(__name__)


# def dispatch(
#     path: str,
#     flag_pattern: re.Pattern,
#     depth: str = "fast",
#     ai_client: Optional[AIClient] = None,
# ) -> List[Finding]:
#     """
#     Identify file type, select all applicable analyzers, run them, and return
#     deduplicated findings.  GenericAnalyzer always runs.

#     Modes:
#       fast  – Quick targeted checks.
#       deep  – Exhaustive checks.
#       auto  – Run all analyzers in fast mode first, then run all analyzers
#               again in deep mode.
#     """
#     if depth == "auto":
#         return _dispatch_auto(path, flag_pattern, ai_client)

#     findings = _run_dispatch(path, flag_pattern, depth, ai_client)
#     extra = _run_redispatch_fallback(findings, flag_pattern, depth)
#     if extra:
#         findings = deduplicate(findings + extra)
#     _score_findings(findings, flag_pattern, depth)
#     return findings


# def _dispatch_auto(
#     path: str,
#     flag_pattern: re.Pattern,
#     ai_client: Optional[AIClient],
# ) -> List[Finding]:
#     """AUTO mode: fast first, then deep with all analyzers."""
#     # Phase 1: fast
#     fast_findings = _run_dispatch(path, flag_pattern, "fast", ai_client)
#     _score_findings(fast_findings, flag_pattern, "fast")

#     # Phase 2: deep, all analyzers (every analyzer must explore every path)
#     deep_findings = _run_dispatch(
#         path, flag_pattern, "deep", ai_client,
#     )
#     _score_findings(deep_findings, flag_pattern, "deep")

#     # Merge: start with fast findings, add all deep findings
#     merged = list(fast_findings) + list(deep_findings)

#     deduped = deduplicate(merged)
#     extra = _run_redispatch_fallback(deduped, flag_pattern, "deep")
#     if extra:
#         deduped = deduplicate(list(deduped) + extra)
#     _score_findings(deduped, flag_pattern, "deep")
#     return deduped


# def _run_dispatch(
#     path: str,
#     flag_pattern: re.Pattern,
#     depth: str,
#     ai_client: Optional[AIClient],
#     restrict_analyzers: Optional[set] = None,
# ) -> List[Finding]:
#     """Run all applicable analyzers at the given depth, optionally restricted."""
#     data = _read_header(path)
#     keys = _identify_analyzers(path, data)

#     all_findings: List[Finding] = []

#     # Always run generic
#     generic = GenericAnalyzer()
#     all_findings.extend(generic.analyze(path, flag_pattern, depth, ai_client))

#     # Always-run analyzers
#     always_run = ("encoding", "crypto", "classical_cipher", "forensics_timeline")
#     for key in always_run:
#         if restrict_analyzers is not None and key not in restrict_analyzers:
#             continue
#         analyzer = _ANALYZER_REGISTRY[key]()
#         all_findings.extend(analyzer.analyze(path, flag_pattern, depth, ai_client))

#     # Type-specific analyzers
#     for key in keys:
#         if key in always_run:
#             continue
#         if restrict_analyzers is not None and key not in restrict_analyzers:
#             continue
#         cls = _ANALYZER_REGISTRY.get(key)
#         if cls:
#             try:
#                 analyzer = cls()
#                 all_findings.extend(analyzer.analyze(path, flag_pattern, depth, ai_client))
#             except Exception as exc:
#                 all_findings.append(Finding(
#                     file=path,
#                     analyzer=key,
#                     title=f"Analyzer error in {key}",
#                     severity="INFO",
#                     detail=str(exc),
#                     confidence=0.1,
#                 ))

#     return deduplicate(all_findings)


# def _score_findings(
#     findings: List[Finding],
#     flag_pattern: re.Pattern,
#     depth: str,
# ) -> None:
#     """Apply confidence scoring in-place using a temporary Session wrapper."""
#     from .report import Session
#     tmp_session = Session(findings=findings)
#     try:
#         tmp_session.flag_pattern = flag_pattern.pattern
#     except Exception:
#         pass
#     _CONFIDENCE_SCORER.score_session(tmp_session)


# def _read_header(path: str) -> bytes:
#     try:
#         with open(path, "rb") as fh:
#             return fh.read(512)
#     except Exception:
#         return b""


# def _run_redispatch_fallback(
#     findings: List[Finding],
#     flag_pattern: re.Pattern,
#     depth: str,
# ) -> List[Finding]:
#     """Run ContentRedispatcher on every root finding to catch missed extracted content.

#     A *root* finding is one whose ``source_finding_id`` is ``None`` — pipeline-
#     generated findings already have a source and must not be re-processed.

#     Logs statistics at INFO level: total content objects found, processed,
#     skipped (dedup), and timed out.

#     Returns:
#         List of additional findings produced by the ContentRedispatcher.
#     """
#     import sys
#     from .content_redispatcher import ContentRedispatcher
#     from .extracted_content import extract_from_finding

#     dispatcher_module = sys.modules[__name__]
#     rd = ContentRedispatcher()

#     # Temporary session: only used for seen-hash dedup and depth tracking
#     tmp_session = Session(findings=[])
#     tmp_session._seen_content_hashes = set()
#     try:
#         tmp_session.flag_pattern = flag_pattern.pattern
#     except Exception:
#         pass
#     tmp_session.depth = depth

#     total_found = 0
#     total_processed = 0
#     total_skipped = 0
#     total_timed_out = 0
#     extra: List[Finding] = []

#     for finding in findings:
#         if getattr(finding, "source_finding_id", None) is not None:
#             continue  # pipeline-generated — already processed, skip

#         contents = extract_from_finding(finding)
#         total_found += len(contents)

#         for content in contents:
#             if content.content_hash in tmp_session._seen_content_hashes:
#                 total_skipped += 1
#                 continue

#             child_findings = rd.process(content, tmp_session, dispatcher_module)
#             total_processed += 1

#             for f in child_findings:
#                 if "Recursion timeout" in getattr(f, "title", ""):
#                     total_timed_out += 1

#             extra.extend(child_findings)

#     _log.info(
#         "ContentRedispatcher fallback: found=%d processed=%d skipped=%d timed_out=%d",
#         total_found, total_processed, total_skipped, total_timed_out,
#     )

#     return extra


# def analyze_file(
#     path: str,
#     session: "Session",
#     analyzers: Optional[List[str]] = None,
#     virtual_name: str = "",
#     ai_client: Optional[AIClient] = None,
# ) -> List[Finding]:
#     """Run a specific subset of analyzers on *path* and return deduplicated findings.

#     This entry-point is used by :class:`~ctf_hunter.core.content_redispatcher.ContentRedispatcher`
#     to re-dispatch extracted content blobs through the existing analyzer suite as
#     if they were freshly-dropped files.

#     Args:
#         path: Filesystem path to the (possibly temporary) file to analyze.
#         session: Active analysis session; provides ``flag_pattern`` and ``depth``.
#         analyzers: Analyzer registry keys to run.  Pass ``None`` or ``[]`` to run
#             nothing (returns an empty list).
#         virtual_name: Human-readable name shown in findings instead of *path*.
#         ai_client: Optional AI client forwarded to each analyzer.

#     Returns:
#         Deduplicated list of :class:`~ctf_hunter.core.report.Finding` objects.
#     """
#     if not analyzers:
#         return []

#     try:
#         flag_pattern: re.Pattern = re.compile(
#             getattr(session, "flag_pattern", r"CTF\{[^}]+\}")
#         )
#     except re.error:
#         flag_pattern = re.compile(r"CTF\{[^}]+\}")

#     depth: str = getattr(session, "depth", "fast") or "fast"  # guard against empty string

#     all_findings: List[Finding] = []
#     import sys as _sys
#     _dispatcher_module = _sys.modules[__name__]
#     for key in analyzers:
#         cls = _ANALYZER_REGISTRY.get(key)
#         if cls is None:
#             continue
#         try:
#             a = cls()
#             new_findings = a.analyze(
#                 path, flag_pattern, depth, ai_client,
#                 session=session, dispatcher_module=_dispatcher_module,
#             )
#             if virtual_name:
#                 for f in new_findings:
#                     f.file = virtual_name
#             all_findings.extend(new_findings)
#         except Exception as exc:
#             all_findings.append(Finding(
#                 file=virtual_name or path,
#                 analyzer=key,
#                 title=f"Analyzer error in {key}",
#                 severity="INFO",
#                 detail=str(exc),
#                 confidence=0.1,
#             ))

#     return deduplicate(all_findings)


# def _identify_analyzers(path: str, data: bytes) -> list[str]:
#     keys: list[str] = []

#     # Check disk image extension
#     if Path(path).suffix.lower() in _DISK_EXTS:
#         keys.append("filesystem")

#     # Magic bytes
#     for sig, analyzer_keys in _MAGIC_MAP:
#         if data.startswith(sig) or data.find(sig) != -1:
#             for k in analyzer_keys:
#                 if k not in keys:
#                     keys.append(k)
#             break

#     # MIME type via 'file' or python-magic
#     mime = run_file(path)
#     for mime_key, analyzer_keys in _MIME_MAP.items():
#         if mime.startswith(mime_key):
#             for k in analyzer_keys:
#                 if k not in keys:
#                     keys.append(k)

#     # PCAP extension fallback
#     if Path(path).suffix.lower() in (".pcap", ".pcapng", ".cap") and "pcap" not in keys:
#         keys.append("pcap")

#     # PEM / DER / RSA detection
#     full_data = data  # header is 512 bytes; enough for PEM begin marker
#     if _PEM_RE.search(full_data) or full_data[:2] == _DER_HEADER or _RSA_PAIR_RE.search(full_data):
#         if "crypto_rsa" not in keys:
#             keys.append("crypto_rsa")
#     # Also check file extension for .pem / .der / .key / .crt / .csr
#     if Path(path).suffix.lower() in (".pem", ".der", ".key", ".crt", ".csr", ".pub"):
#         if "crypto_rsa" not in keys:
#             keys.append("crypto_rsa")

#     return keys
