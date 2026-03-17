"""
PCAP analyzer: protocol summary, TCP stream reassembly, HTTP bodies,
credential sniffing, file carving, flag pattern search, and DNS covert
channel detection.
Uses scapy with tshark fallback.
"""
from __future__ import annotations

import re
import base64
import binascii
import string
from collections import defaultdict, Counter
from pathlib import Path
from typing import List, Optional

from core.report import Finding
from core.ai_client import AIClient
from core.external import run_tshark
from .base import Analyzer


class PcapAnalyzer(Analyzer):
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
            from scapy.all import rdpcap, TCP, UDP, IP, Raw, Ether
            packets = rdpcap(path)
        except Exception as exc:
            # Fallback to tshark summary only
            tshark_data = run_tshark(path)
            if tshark_data:
                findings.append(self._finding(
                    path,
                    f"PCAP parsed via tshark: {len(tshark_data)} packets",
                    str(tshark_data[:5]),
                    severity="INFO",
                    confidence=0.4,
                ))
            else:
                findings.append(self._finding(
                    path,
                    f"PCAP parse error (scapy): {exc}",
                    "",
                    severity="INFO",
                    confidence=0.2,
                ))
            self._run_redispatch_hook(findings, session, dispatcher_module)
            return findings

        # Protocol summary
        findings.extend(self._protocol_summary(path, packets))

        # TCP stream reassembly
        if depth == "deep":
            streams = self._reassemble_tcp(packets)
        else:
            streams = self._reassemble_tcp_fast(packets)

        # HTTP extraction
        findings.extend(self._extract_http(path, streams, flag_pattern))

        # Credential sniffing
        findings.extend(self._sniff_credentials(path, streams, flag_pattern))

        # Flag pattern in all payloads
        findings.extend(self._search_payloads(path, packets, flag_pattern))

        if depth == "deep":
            # File carving
            findings.extend(self._carve_files(path, streams, flag_pattern))

        # DNS covert channel detection (always run)
        findings.extend(self._detect_dns_covert_channel(path, packets, flag_pattern))

        self._run_redispatch_hook(findings, session, dispatcher_module)
        return findings

    # ------------------------------------------------------------------

    def _protocol_summary(self, path: str, packets) -> List[Finding]:
        try:
            from scapy.all import IP, TCP, UDP, ICMP
        except Exception:
            return []
        proto_counts: Counter = Counter()
        for pkt in packets:
            if pkt.haslayer("TCP"):
                proto_counts["TCP"] += 1
            elif pkt.haslayer("UDP"):
                proto_counts["UDP"] += 1
            elif pkt.haslayer("ICMP"):
                proto_counts["ICMP"] += 1
            else:
                proto_counts["Other"] += 1
        summary = ", ".join(f"{k}:{v}" for k, v in proto_counts.most_common())
        return [self._finding(
            path,
            f"PCAP protocol summary: {len(packets)} packets",
            summary,
            severity="INFO",
            confidence=0.5,
        )]

    def _reassemble_tcp(self, packets) -> dict[tuple, bytes]:
        """Full TCP stream reassembly keyed by (src_ip, src_port, dst_ip, dst_port)."""
        streams: dict[tuple, bytes] = defaultdict(bytes)
        try:
            from scapy.all import TCP, IP, Raw
            for pkt in packets:
                if pkt.haslayer(TCP) and pkt.haslayer(Raw) and pkt.haslayer(IP):
                    key = (pkt[IP].src, pkt[TCP].sport, pkt[IP].dst, pkt[TCP].dport)
                    streams[key] += bytes(pkt[Raw].load)
        except Exception:
            pass
        return dict(streams)

    def _reassemble_tcp_fast(self, packets) -> dict[tuple, bytes]:
        """Fast mode: only first 100 packets per stream, limited to 4096 bytes."""
        streams: dict[tuple, bytes] = defaultdict(bytes)
        stream_counts: Counter = Counter()
        try:
            from scapy.all import TCP, IP, Raw
            for pkt in packets:
                if pkt.haslayer(TCP) and pkt.haslayer(Raw) and pkt.haslayer(IP):
                    key = (pkt[IP].src, pkt[TCP].sport, pkt[IP].dst, pkt[TCP].dport)
                    if stream_counts[key] < 100 and len(streams[key]) < 4096:
                        streams[key] += bytes(pkt[Raw].load)
                        stream_counts[key] += 1
        except Exception:
            pass
        return dict(streams)

    def _extract_http(
        self, path: str, streams: dict, flag_pattern: re.Pattern
    ) -> List[Finding]:
        findings: List[Finding] = []
        for key, data in streams.items():
            text = data.decode("latin-1", errors="replace")
            # Find HTTP requests
            for m in re.finditer(r"(GET|POST|PUT|DELETE|HEAD) (.+?) HTTP/[\d.]+", text):
                method, uri = m.group(1), m.group(2)
                findings.append(self._finding(
                    path,
                    f"HTTP {method} request: {uri[:100]}",
                    f"Stream {key[0]}:{key[1]} → {key[2]}:{key[3]}",
                    severity="INFO",
                    confidence=0.5,
                ))
            # Flag in HTTP body
            if self._check_flag(text, flag_pattern):
                findings.append(self._finding(
                    path,
                    f"Flag pattern in HTTP stream {key[0]}→{key[2]}",
                    text[:500],
                    severity="HIGH",
                    flag_match=True,
                    confidence=0.95,
                ))
        return findings

    def _sniff_credentials(
        self, path: str, streams: dict, flag_pattern: re.Pattern
    ) -> List[Finding]:
        findings: List[Finding] = []
        for key, data in streams.items():
            text = data.decode("latin-1", errors="replace")
            # Basic Auth
            for m in re.finditer(r"Authorization: Basic ([A-Za-z0-9+/=]+)", text):
                try:
                    creds = base64.b64decode(m.group(1)).decode("utf-8", errors="replace")
                    findings.append(self._finding(
                        path,
                        f"HTTP Basic Auth credentials in stream",
                        f"Credentials: {creds}",
                        severity="HIGH",
                        flag_match=self._check_flag(creds, flag_pattern),
                        confidence=0.90,
                    ))
                except Exception:
                    pass
            # FTP
            for m in re.finditer(r"(?:USER|PASS) ([^\r\n]+)", text, re.IGNORECASE):
                findings.append(self._finding(
                    path,
                    f"FTP credential in stream: {m.group(0)[:80]}",
                    str(key),
                    severity="HIGH",
                    confidence=0.85,
                ))
            # HTTP form POST
            for m in re.finditer(r"(?:password|passwd|pwd)=([^&\r\n]+)", text, re.IGNORECASE):
                findings.append(self._finding(
                    path,
                    f"HTTP form password in stream: {m.group(0)[:80]}",
                    str(key),
                    severity="HIGH",
                    confidence=0.85,
                ))
        return findings

    def _search_payloads(
        self, path: str, packets, flag_pattern: re.Pattern
    ) -> List[Finding]:
        findings: List[Finding] = []
        try:
            from scapy.all import Raw
            for i, pkt in enumerate(packets):
                if pkt.haslayer(Raw):
                    payload = bytes(pkt[Raw].load)
                    text = payload.decode("latin-1", errors="replace")
                    if self._check_flag(text, flag_pattern):
                        findings.append(self._finding(
                            path,
                            f"Flag pattern in packet #{i} payload",
                            text[:300],
                            severity="HIGH",
                            flag_match=True,
                            confidence=0.95,
                        ))
        except Exception:
            pass
        return findings

    def _carve_files(
        self, path: str, streams: dict, flag_pattern: re.Pattern
    ) -> List[Finding]:
        findings: List[Finding] = []
        _FILE_SIGS = {
            b"\x89PNG\r\n\x1a\n": "PNG",
            b"\xff\xd8\xff": "JPEG",
            b"PK\x03\x04": "ZIP",
            b"\x1f\x8b": "gzip",
            b"%PDF": "PDF",
        }
        for key, data in streams.items():
            for sig, file_type in _FILE_SIGS.items():
                if sig in data:
                    idx = data.index(sig)
                    findings.append(self._finding(
                        path,
                        f"Carved {file_type} file from TCP stream {key[0]}→{key[2]}",
                        f"Signature at byte offset {idx} in stream",
                        severity="HIGH",
                        confidence=0.80,
                    ))
        return findings

    # ------------------------------------------------------------------
    # DNS covert channel detection
    # ------------------------------------------------------------------

    def _detect_dns_covert_channel(
        self, path: str, packets, flag_pattern: re.Pattern
    ) -> List[Finding]:
        """Detect DNS covert channels by analysing DNS query subdomain labels.

        For every UDP/53 packet the queried domain name is extracted from the
        DNS wire format.  Queries are grouped by *base domain* (everything
        after the first subdomain label).  For each base domain the leftmost
        subdomain label from each query is collected in packet-arrival order,
        concatenated, and decoded as Base64 / Base32 / hex / raw ASCII.

        * HIGH   – when any decode produces printable ASCII or matches the
                   configured flag pattern.
        * MEDIUM – for any base domain that received ≥ 3 queries, even if
                   decoding fails (suspected covert channel).
        """
        findings: List[Finding] = []
        try:
            from scapy.all import UDP, IP  # noqa: F401 – availability check
        except Exception:
            return []

        # base_domain -> [(packet_index, leftmost_subdomain_label), ...]
        queries: dict[str, list[tuple[int, str]]] = defaultdict(list)

        for i, pkt in enumerate(packets):
            if not pkt.haslayer("UDP"):
                continue
            try:
                from scapy.all import UDP as _UDP
                if pkt[_UDP].dport != 53 and pkt[_UDP].sport != 53:
                    continue
            except Exception:
                continue

            domain = self._extract_dns_qname(pkt)
            if not domain:
                continue

            labels = domain.rstrip(".").split(".")
            if len(labels) < 2:
                continue

            # The leftmost label is the potential encoded chunk; the rest is
            # the base domain used as the covert channel carrier.
            leftmost = labels[0]
            base_domain = ".".join(labels[1:])
            queries[base_domain].append((i, leftmost))

        for base_domain, query_list in queries.items():
            subdomains = [s for _, s in query_list]
            concatenated = "".join(subdomains)

            # Try decodes in priority order
            decoded: Optional[str] = None
            decode_method: str = ""

            for method, fn in (
                ("Base64", self._try_b64decode),
                ("Base32", self._try_b32decode),
                ("Hex",    self._try_hexdecode),
            ):
                result = fn(concatenated)
                if result is not None and self._is_printable_ascii(result):
                    decoded = result
                    decode_method = method
                    break

            # Fallback: raw concatenation as ASCII
            if decoded is None and self._is_printable_ascii(concatenated):
                decoded = concatenated
                decode_method = "Raw ASCII"

            # HIGH finding when we successfully decoded something meaningful
            if decoded is not None and (
                self._is_printable_ascii(decoded)
                or self._check_flag(decoded, flag_pattern)
            ):
                flag_found = self._check_flag(decoded, flag_pattern)
                detail = (
                    f"Base domain: {base_domain}\n"
                    f"Subdomains ({len(subdomains)}): "
                    f"{', '.join(subdomains[:30])}\n"
                    f"Decode method: {decode_method}\n"
                    f"Reconstructed: {decoded[:500]}"
                )
                findings.append(self._finding(
                    path,
                    f"DNS covert channel decoded ({decode_method}): "
                    f"{decoded[:80]}",
                    detail,
                    severity="HIGH",
                    flag_match=flag_found,
                    confidence=0.90,
                ))

            # MEDIUM finding for ≥ 3 queries only when decoding failed
            # (the problem spec says "even if decoding fails", implying MEDIUM
            # is the fallback for undecodable but suspicious traffic)
            if len(query_list) >= 3 and decoded is None:
                detail = (
                    f"Base domain: {base_domain}\n"
                    f"Query count: {len(query_list)}\n"
                    f"Subdomains: {', '.join(subdomains[:30])}\n"
                    f"Concatenated labels: {concatenated[:200]}"
                )
                findings.append(self._finding(
                    path,
                    f"Suspected DNS covert channel on {base_domain} "
                    f"({len(query_list)} queries)",
                    detail,
                    severity="MEDIUM",
                    confidence=0.70,
                ))

        return findings

    # ------------------------------------------------------------------
    # DNS wire-format helpers
    # ------------------------------------------------------------------

    def _extract_dns_qname(self, pkt) -> Optional[str]:
        """Extract the first QNAME from a DNS packet using scapy or raw parsing."""
        # Prefer scapy's DNS layer
        try:
            from scapy.all import DNSQR
            if pkt.haslayer(DNSQR):
                qname = pkt[DNSQR].qname
                if isinstance(qname, bytes):
                    return qname.decode("latin-1", errors="replace")
                return str(qname)
        except Exception:
            pass

        # Fallback: manual DNS wire-format parse
        try:
            from scapy.all import UDP, Raw
            if pkt.haslayer(Raw):
                raw = bytes(pkt[Raw].load)
            else:
                raw = bytes(pkt[UDP].payload)
            return self._parse_dns_qname_raw(raw)
        except Exception:
            return None

    def _parse_dns_qname_raw(self, data: bytes) -> Optional[str]:
        """Parse the QNAME from raw DNS payload (after 12-byte header)."""
        if len(data) < 13:
            return None
        offset = 12  # skip DNS fixed header
        labels: list[str] = []
        while offset < len(data):
            length = data[offset]
            if length == 0:
                break
            # Compression pointer — not expected in queries, but stop gracefully
            if (length & 0xC0) == 0xC0:
                break
            offset += 1
            end = offset + length
            if end > len(data):
                break
            labels.append(data[offset:end].decode("latin-1", errors="replace"))
            offset = end
        return ".".join(labels) if labels else None

    # ------------------------------------------------------------------
    # Decode helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _try_b64decode(s: str) -> Optional[str]:
        """Return the Base64-decoded string, or None on failure."""
        try:
            # Add padding if needed
            padded = s + "=" * (-len(s) % 4)
            raw = base64.b64decode(padded, validate=False)
            return raw.decode("utf-8", errors="strict")
        except Exception:
            return None

    @staticmethod
    def _try_b32decode(s: str) -> Optional[str]:
        """Return the Base32-decoded string, or None on failure."""
        try:
            padded = s.upper() + "=" * (-len(s) % 8)
            raw = base64.b32decode(padded)
            return raw.decode("utf-8", errors="strict")
        except Exception:
            return None

    @staticmethod
    def _try_hexdecode(s: str) -> Optional[str]:
        """Return the hex-decoded string, or None on failure."""
        try:
            raw = binascii.unhexlify(s)
            return raw.decode("utf-8", errors="strict")
        except Exception:
            return None

    @staticmethod
    def _is_printable_ascii(s: str) -> bool:
        """Return True when at least 80 % of characters are printable ASCII."""
        if not s:
            return False
        printable = set(string.printable)
        count = sum(1 for c in s if c in printable)
        return count / len(s) >= 0.80
