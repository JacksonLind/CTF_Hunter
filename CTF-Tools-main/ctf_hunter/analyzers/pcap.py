"""
PCAP analyzer: protocol summary, TCP stream reassembly, HTTP bodies,
credential sniffing, file carving, flag pattern search, and DNS covert
channel detection.
Uses scapy with tshark fallback.
"""
from __future__ import annotations

import bisect
import mmap
import re
import struct
import base64
import binascii
import string
from collections import defaultdict, Counter
from pathlib import Path
from typing import Dict, List, Optional, Tuple

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

        # pcapng merge metadata + covert timing channel (always run, raw binary)
        findings.extend(self._parse_pcapng_metadata(path, flag_pattern))
        findings.extend(self._timing_channel_analysis(path, flag_pattern))

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
    # pcapng metadata parser — merge comments + interface packet counts
    # ------------------------------------------------------------------

    def _parse_pcapng_metadata(self, path: str, flag_pattern: re.Pattern) -> List[Finding]:
        """Parse raw pcapng binary for Section Header Block capture comments
        and per-interface packet counts.

        Reads only block headers and option fields — never loads packet
        payloads — so it is safe on files up to several GB.  Uses mmap for
        zero-copy access.
        """
        findings: List[Finding] = []
        try:
            file_size = Path(path).stat().st_size
            if file_size < 28:
                return findings
            with open(path, "rb") as fh:
                mm = mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ)
                try:
                    findings.extend(self._pcapng_scan(path, mm, file_size, flag_pattern))
                finally:
                    mm.close()
        except Exception:
            pass
        return findings

    def _pcapng_scan(
        self,
        path: str,
        mm: mmap.mmap,
        file_size: int,
        flag_pattern: re.Pattern,
    ) -> List[Finding]:
        findings: List[Finding] = []

        # Block type constants
        SHB  = 0x0A0D0D0A  # Section Header Block
        IDB  = 0x00000001  # Interface Description Block
        EPB  = 0x00000006  # Enhanced Packet Block
        OPT_COMMENT = 0x0003
        OPT_ENDOFOPT = 0x0000

        # Check byte order from SHB byte-order magic
        if file_size < 12:
            return findings
        shb_bom = struct.unpack_from("<I", mm, 8)[0]
        endian = "<" if shb_bom == 0x1A2B3C4D else ">"

        iface_count   = 0
        iface_packets: Dict[int, int] = {}
        capture_comments: List[str] = []
        pos = 0

        while pos + 8 <= file_size:
            bt = struct.unpack_from(f"{endian}I", mm, pos)[0]
            bl = struct.unpack_from(f"{endian}I", mm, pos + 4)[0]
            if bl < 12 or pos + bl > file_size:
                break

            if bt == SHB:
                # Scan options inside SHB for capture comment (code 0x0003)
                opt_pos = pos + 28  # skip type(4) + len(4) + bom(4) + maj(2) + min(2) + sec_len(8)
                opt_end = pos + bl - 4  # exclude trailing block-total-length
                while opt_pos + 4 <= opt_end:
                    opt_code = struct.unpack_from(f"{endian}H", mm, opt_pos)[0]
                    opt_len  = struct.unpack_from(f"{endian}H", mm, opt_pos + 2)[0]
                    if opt_code == OPT_ENDOFOPT:
                        break
                    if opt_code == OPT_COMMENT and opt_len > 0:
                        raw_opt = opt_pos + 4
                        if raw_opt + opt_len <= opt_end:
                            comment = mm[raw_opt: raw_opt + opt_len].decode("utf-8", errors="replace")
                            capture_comments.append(comment)
                    # Options are padded to 4-byte boundary
                    opt_pos += 4 + opt_len + (4 - opt_len % 4) % 4

            elif bt == IDB:
                iface_packets[iface_count] = 0
                iface_count += 1

            elif bt == EPB:
                if bl >= 12:
                    iface_id = struct.unpack_from(f"{endian}I", mm, pos + 8)[0]
                    iface_packets[iface_id] = iface_packets.get(iface_id, 0) + 1

            pos += bl

        # Emit capture comment findings
        for comment in capture_comments:
            lines = comment.strip().splitlines()
            merged_files = [l.strip() for l in lines if re.match(r"File\d+\s*:", l, re.IGNORECASE)]
            covert_hints = [
                f for f in merged_files
                if re.search(r"covert|timing|hidden|steg|secret", f, re.IGNORECASE)
            ]
            detail = f"Capture comment:\n{comment[:800]}"
            if merged_files:
                detail += f"\n\nMerged source files detected:\n" + "\n".join(merged_files)
            findings.append(self._finding(
                path,
                f"pcapng capture comment ({len(merged_files)} merged file(s) detected)",
                detail,
                severity="HIGH" if merged_files else "INFO",
                confidence=0.85 if merged_files else 0.50,
            ))
            if covert_hints:
                findings.append(self._finding(
                    path,
                    "Covert channel filename in pcapng merge comment",
                    "Suspicious filename(s): " + "; ".join(covert_hints),
                    severity="HIGH",
                    confidence=0.92,
                ))

        # Emit per-interface packet count findings
        if iface_packets:
            total = sum(iface_packets.values())
            summary = ", ".join(
                f"iface#{i}={c}" for i, c in sorted(iface_packets.items())
            )
            findings.append(self._finding(
                path,
                f"pcapng interface packet counts ({iface_count} interface(s), {total} total)",
                summary,
                severity="INFO",
                confidence=0.70,
            ))
            # Flag low-volume interfaces as covert candidates
            if total > 0:
                for iface_id, count in iface_packets.items():
                    ratio = count / total
                    if 50 <= count <= 5000 and ratio < 0.01:
                        findings.append(self._finding(
                            path,
                            f"Low-volume interface #{iface_id} — likely covert candidate",
                            f"{count} packets ({ratio*100:.4f}% of total {total})",
                            severity="HIGH",
                            confidence=0.88,
                        ))

        return findings

    # ------------------------------------------------------------------
    # Covert timing channel detector
    # ------------------------------------------------------------------

    def _timing_channel_analysis(self, path: str, flag_pattern: re.Pattern) -> List[Finding]:
        """Extract per-interface packet timestamps from pcapng and detect
        quantised inter-arrival timing channels.

        Supports:
        - 2-value binary encoding (long=1, short=0)
        - 4-value base-4 encoding (2 bits per symbol)
        - MSB-first and LSB-first bit ordering
        - Single leading framing-bit alignment fix
        Uses mmap + struct for performance on large captures.
        """
        findings: List[Finding] = []
        try:
            file_size = Path(path).stat().st_size
            if file_size < 28:
                return findings
            with open(path, "rb") as fh:
                mm = mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ)
                try:
                    findings.extend(self._timing_scan(path, mm, file_size, flag_pattern))
                finally:
                    mm.close()
        except Exception:
            pass
        return findings

    def _timing_scan(
        self,
        path: str,
        mm: mmap.mmap,
        file_size: int,
        flag_pattern: re.Pattern,
    ) -> List[Finding]:
        findings: List[Finding] = []

        EPB    = 0x00000006
        IDB    = 0x00000001
        shb_bom = struct.unpack_from("<I", mm, 8)[0]
        endian  = "<" if shb_bom == 0x1A2B3C4D else ">"

        # ts_resol per interface (default 1e-6 = microseconds)
        iface_tsresol: Dict[int, float] = {}
        iface_times:   Dict[int, List[float]] = defaultdict(list)
        iface_count = 0
        pos = 0

        while pos + 8 <= file_size:
            bt = struct.unpack_from(f"{endian}I", mm, pos)[0]
            bl = struct.unpack_from(f"{endian}I", mm, pos + 4)[0]
            if bl < 12 or pos + bl > file_size:
                break

            if bt == IDB:
                # Default tsresol is microseconds (10^-6)
                iface_tsresol[iface_count] = 1e-6
                iface_count += 1

            elif bt == EPB and bl >= 20:
                iface_id = struct.unpack_from(f"{endian}I", mm, pos + 8)[0]
                ts_high  = struct.unpack_from(f"{endian}I", mm, pos + 12)[0]
                ts_low   = struct.unpack_from(f"{endian}I", mm, pos + 16)[0]
                ts_raw   = (ts_high << 32) | ts_low
                resol    = iface_tsresol.get(iface_id, 1e-6)
                iface_times[iface_id].append(ts_raw * resol)

            pos += bl

        for iface_id, times in iface_times.items():
            n = len(times)
            if not (50 <= n <= 5000):
                continue

            times_sorted = sorted(times)
            deltas = [
                round(times_sorted[i] - times_sorted[i - 1], 6)
                for i in range(1, len(times_sorted))
                if times_sorted[i] - times_sorted[i - 1] > 1e-9
            ]
            if len(deltas) < 8:
                continue

            distinct = sorted(set(deltas))

            if len(distinct) == 2:
                findings.extend(
                    self._decode_binary_timing(
                        path, iface_id, deltas, distinct, flag_pattern
                    )
                )
            elif len(distinct) in (3, 4):
                findings.extend(
                    self._decode_basen_timing(
                        path, iface_id, deltas, distinct, flag_pattern
                    )
                )

        return findings

    def _decode_binary_timing(
        self,
        path: str,
        iface_id: int,
        deltas: List[float],
        distinct: List[float],
        flag_pattern: re.Pattern,
    ) -> List[Finding]:
        """Decode a 2-value timing channel: larger delta = 1, smaller = 0."""
        findings: List[Finding] = []
        short_val, long_val = distinct[0], distinct[1]
        bits = [1 if d == long_val else 0 for d in deltas]

        candidates: List[Tuple[str, List[int]]] = [
            ("raw",         bits),
            ("framing+0",   [0] + bits),
            ("framing+1",   [1] + bits),
        ]

        for label, bit_seq in candidates:
            # Pad to byte boundary
            remainder = len(bit_seq) % 8
            padded = bit_seq + [0] * ((8 - remainder) % 8) if remainder else bit_seq
            for order, rev in (("MSB", False), ("LSB", True)):
                decoded = self._bits_to_ascii(padded, lsb_first=rev)
                if decoded and self._is_printable_ascii(decoded):
                    fm = self._check_flag(decoded, flag_pattern)
                    findings.append(self._finding(
                        path,
                        f"Covert timing channel decoded — iface#{iface_id} "
                        f"({label}, {order}-first)",
                        f"Short={short_val}s=0  Long={long_val}s=1\n"
                        f"{len(deltas)} deltas → {len(padded)//8} bytes\n"
                        f"Decoded: {decoded[:300]}",
                        severity="HIGH" if fm else "MEDIUM",
                        flag_match=fm,
                        confidence=0.97 if fm else 0.80,
                    ))
        return findings

    def _decode_basen_timing(
        self,
        path: str,
        iface_id: int,
        deltas: List[float],
        distinct: List[float],
        flag_pattern: re.Pattern,
    ) -> List[Finding]:
        """Decode a 3–4 value timing channel as base-N symbols."""
        findings: List[Finding] = []
        if len(distinct) == 4:
            # 2 bits per symbol
            sym_map = {v: i for i, v in enumerate(distinct)}
            bits: List[int] = []
            for d in deltas:
                sym = sym_map.get(d, 0)
                bits += [(sym >> 1) & 1, sym & 1]
            padded = bits + [0] * ((8 - len(bits) % 8) % 8)
            for order, rev in (("MSB", False), ("LSB", True)):
                decoded = self._bits_to_ascii(padded, lsb_first=rev)
                if decoded and self._is_printable_ascii(decoded):
                    fm = self._check_flag(decoded, flag_pattern)
                    findings.append(self._finding(
                        path,
                        f"Covert timing channel (base-4) decoded — iface#{iface_id} ({order}-first)",
                        f"Symbol map: {sym_map}\nDecoded: {decoded[:300]}",
                        severity="HIGH" if fm else "MEDIUM",
                        flag_match=fm,
                        confidence=0.95 if fm else 0.75,
                    ))
        return findings

    @staticmethod
    def _bits_to_ascii(bits: List[int], lsb_first: bool = False) -> Optional[str]:
        """Convert a flat list of bits to an ASCII string, 8 bits per char."""
        result = []
        for i in range(0, len(bits) - 7, 8):
            byte_bits = bits[i: i + 8]
            if lsb_first:
                byte_bits = byte_bits[::-1]
            val = int("".join(str(b) for b in byte_bits), 2)
            if 0x20 <= val < 0x7F or val in (0x09, 0x0A, 0x0D):
                result.append(chr(val))
            else:
                result.append("\x00")
        text = "".join(result)
        return text if text.strip("\x00") else None

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