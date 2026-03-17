"""
Disassembly analyzer: r2pipe (radare2) primary engine with Capstone linear fallback.

Supports ELF, PE, and .so files.  Extracts imports, exports, relocations, GOT
entries, a consolidated Symbol Map, per-function CFGs, decompilation output,
crypto-constant fingerprints, xref-mapped strings, and .so-specific constructor
/ DWARF / LD_PRELOAD analysis.  Falls back to the original Capstone linear
disassembler when r2pipe / radare2 are not installed.
"""
from __future__ import annotations

import re
import struct
from pathlib import Path
from typing import List, Optional

from core.report import Finding
from core.ai_client import AIClient
from .base import Analyzer

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Imports that are commonly abused in CTF pwn/exploit challenges
_DANGEROUS_IMPORTS: set[str] = {
    "system", "execve", "gets", "strcpy", "printf",
    "read", "mmap", "mprotect",
}

# Exports that indicate an LD_PRELOAD hooking library (intercepts libc calls)
_LD_PRELOAD_HOOKS: set[str] = {
    "malloc", "free", "calloc", "realloc",
    "open", "close", "read", "write",
    "connect", "send", "recv",
    "fopen", "fclose", "fread", "fwrite",
}

# Minimum separation (bytes) between two hits of the same crypto pattern before
# a second finding is emitted.  256 bytes is chosen because a crypto table
# (e.g. AES S-box = 256 bytes) repeated back-to-back or padded to an
# alignment boundary will appear within this window and should be counted as a
# single instance rather than generating two separate findings.
_CRYPTO_DEDUP_WINDOW = 256

# Known crypto byte-pattern signatures searched in binary data.
# Each entry: (display_name, byte_sequence, severity)
_CRYPTO_SIGNATURES: list[tuple[str, bytes, str]] = [
    # AES S-box first 16 bytes (little-endian row 0)
    ("AES S-box", bytes([
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
        0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    ]), "HIGH"),
    # AES inverse S-box first 8 bytes
    ("AES inverse S-box", bytes([
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38,
    ]), "HIGH"),
    # SHA-256 first round constant (0x428a2f98) little-endian
    ("SHA-256 round constants", bytes([0x98, 0x2f, 0x8a, 0x42]), "MEDIUM"),
    # SHA-512 first round constant (0x428a2f98d728ae22) little-endian
    ("SHA-512 round constants", bytes([
        0x22, 0xae, 0x28, 0xd7, 0x98, 0x2f, 0x8a, 0x42,
    ]), "MEDIUM"),
    # SHA-1 initial hash value H0 (0x67452301) little-endian
    ("SHA-1/MD5 initial hash", bytes([0x01, 0x23, 0x45, 0x67]), "MEDIUM"),
    # CRC32 table first two entries (little-endian)
    ("CRC32 lookup table", bytes([
        0x00, 0x00, 0x00, 0x00, 0x96, 0x30, 0x07, 0x77,
    ]), "MEDIUM"),
    # DES initial permutation table (first 8 bytes)
    ("DES permutation table", bytes([
        0x3a, 0x32, 0x2a, 0x22, 0x1a, 0x12, 0x0a, 0x02,
    ]), "MEDIUM"),
    # RC4 identity permutation seed — the sequential 0x00…0x13 byte sequence
    # in .rodata indicates the S-box or identity table used to initialize RC4
    ("RC4 identity table", bytes([
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13,
    ]), "MEDIUM"),
]


# ---------------------------------------------------------------------------
# Helpers shared by both engines
# ---------------------------------------------------------------------------

def _is_supported_binary(data: bytes) -> bool:
    """Return True if *data* looks like an ELF, PE, or shared-object binary."""
    return data[:4] == b"\x7fELF" or data[:2] == b"MZ"


def _get_capstone_arch(data: bytes):
    """Determine capstone arch/mode from ELF/PE header."""
    try:
        import capstone as cs
        if data[:4] == b"\x7fELF":
            ei_class = data[4]  # 1=32, 2=64
            e_machine = struct.unpack_from("<H", data, 18)[0]
            if e_machine == 0x28:   # ARM
                return cs.CS_ARCH_ARM, cs.CS_MODE_ARM
            if e_machine == 0xb7:   # AArch64
                return cs.CS_ARCH_ARM64, cs.CS_MODE_ARM
            if ei_class == 2:
                return cs.CS_ARCH_X86, cs.CS_MODE_64
            return cs.CS_ARCH_X86, cs.CS_MODE_32
        elif data[:2] == b"MZ":
            # Check PE optional header machine field for 32/64
            try:
                pe_off = struct.unpack_from("<I", data, 0x3C)[0]
                machine = struct.unpack_from("<H", data, pe_off + 4)[0]
                if machine == 0x8664:
                    return cs.CS_ARCH_X86, cs.CS_MODE_64
                return cs.CS_ARCH_X86, cs.CS_MODE_32
            except Exception:
                return cs.CS_ARCH_X86, cs.CS_MODE_32
    except ImportError:
        pass
    return None, None


def _find_code_section(data: bytes) -> tuple[int, bytes]:
    """Return (offset, code_bytes) for the first executable section."""
    if data[:4] == b"\x7fELF":
        # ELF: find first SHT_PROGBITS section with EXECINSTR flag
        try:
            ei_class = data[4]
            if ei_class == 2:  # 64-bit
                e_shoff = struct.unpack_from("<Q", data, 40)[0]
                e_shentsize = struct.unpack_from("<H", data, 58)[0]
                e_shnum = struct.unpack_from("<H", data, 60)[0]
                for i in range(min(e_shnum, 40)):
                    sh_off = e_shoff + i * e_shentsize
                    sh_type = struct.unpack_from("<I", data, sh_off + 4)[0]
                    sh_flags = struct.unpack_from("<Q", data, sh_off + 8)[0]
                    sh_offset = struct.unpack_from("<Q", data, sh_off + 24)[0]
                    sh_size = struct.unpack_from("<Q", data, sh_off + 32)[0]
                    SHF_EXECINSTR = 0x4
                    if sh_type == 1 and sh_flags & SHF_EXECINSTR:
                        return sh_offset, data[sh_offset:sh_offset + sh_size]
        except Exception:
            pass
        return 0, data[:4096]
    elif data[:2] == b"MZ":
        try:
            pe_off = struct.unpack_from("<I", data, 0x3C)[0]
            if data[pe_off:pe_off + 4] != b"PE\x00\x00":
                return 0, data[:4096]
            num_sections = struct.unpack_from("<H", data, pe_off + 6)[0]
            opt_size = struct.unpack_from("<H", data, pe_off + 20)[0]
            sec_tab = pe_off + 24 + opt_size
            for i in range(num_sections):
                sec_off = sec_tab + i * 40
                characteristics = struct.unpack_from("<I", data, sec_off + 36)[0]
                IMAGE_SCN_CNT_CODE = 0x20
                IMAGE_SCN_MEM_EXECUTE = 0x20000000
                if characteristics & (IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE):
                    raw_offset = struct.unpack_from("<I", data, sec_off + 20)[0]
                    raw_size = struct.unpack_from("<I", data, sec_off + 16)[0]
                    return raw_offset, data[raw_offset:raw_offset + raw_size]
        except Exception:
            pass
        return 0, data[:4096]
    return 0, data[:4096]


# ---------------------------------------------------------------------------
# Capstone fallback (original linear disassembly path)
# ---------------------------------------------------------------------------

def _capstone_fallback(
    analyzer: "DisassemblyAnalyzer",
    path: str,
    data: bytes,
    depth: str,
    ai_client: Optional[AIClient],
    findings: List[Finding],
) -> List[Finding]:
    """Run the original Capstone linear disassembly as a fallback engine."""
    import capstone

    arch, mode = _get_capstone_arch(data)
    if arch is None:
        findings.append(analyzer._finding(
            path,
            "Disassembly skipped: unrecognized binary format",
            "",
            severity="INFO",
            confidence=0.1,
        ))
        return findings

    code_offset, code_bytes = _find_code_section(data)
    if not code_bytes:
        findings.append(analyzer._finding(
            path,
            "No executable section found",
            "",
            severity="INFO",
            confidence=0.3,
        ))
        return findings

    try:
        md = capstone.Cs(arch, mode)
        md.detail = False
        if depth == "fast":
            insns = list(md.disasm(code_bytes, code_offset))[:100]
        else:
            insns = list(md.disasm(code_bytes, code_offset))
    except Exception as exc:
        findings.append(analyzer._finding(
            path, f"Disassembly error: {exc}", "", confidence=0.2,
        ))
        return findings

    if not insns:
        findings.append(analyzer._finding(
            path,
            "No instructions disassembled",
            "",
            severity="INFO",
            confidence=0.2,
        ))
        return findings

    lines = [
        f"0x{ins.address:08x}:  {ins.mnemonic:<10} {ins.op_str}"
        for ins in insns
    ]
    asm_text = "\n".join(lines)
    detail = f"Disassembled {len(insns)} instructions from offset 0x{code_offset:x}"

    findings.append(analyzer._finding(
        path,
        f"Disassembly ({len(insns)} instructions, "
        f"arch={'x64' if mode == capstone.CS_MODE_64 else 'x86/ARM'})",
        detail + "\n\n" + asm_text[:3000],
        severity="INFO",
        offset=code_offset,
        confidence=0.6,
    ))

    if depth == "deep" and ai_client and ai_client.available:
        summary = ai_client.explain_disassembly(asm_text)
        if summary:
            findings.append(analyzer._finding(
                path,
                "AI disassembly summary",
                summary,
                severity="MEDIUM",
                offset=code_offset,
                confidence=0.65,
            ))

    return findings


# ---------------------------------------------------------------------------
# r2pipe primary engine – helper steps 4-7
# ---------------------------------------------------------------------------

def _step4_decompile(
    r2,
    analyzer: "DisassemblyAnalyzer",
    path: str,
    funcs: list,
    depth: str,
    findings: List[Finding],
) -> list[dict]:
    """Step 4 – Decompile each function with r2ghidra (pdgj); fall back to pdf.

    r2ghidra provides C-like pseudocode via the ``pdgj`` command.  Two
    distinct failure modes are handled before falling back to ``pdf``:

    * **Missing ``code`` key** – r2ghidra returned an error object such as
      ``{"error": "cannot decompile indirect jump"}`` with no ``code`` field.
    * **Empty ``code`` value** – r2ghidra returned ``{"code": ""}`` or
      ``{"code": null}`` for functions it cannot represent (e.g. hand-written
      asm, heavily obfuscated code).

    Both cases are caught by normalising the ``cmdj`` result to a dict and
    using ``decomp_dict.get("code") or ""`` so that ``None``, a missing key,
    and an empty string all produce the same falsy value.

    Returns a list of ``{"name", "address", "pseudocode"}`` dicts suitable
    for the Step 8 structured AI payload.
    """
    func_limit = 5 if depth == "fast" else 20
    decompiled: list[dict] = []

    for func in funcs[:func_limit]:
        fname: str = func.get("name", "?")
        faddr: int = func.get("offset", 0) or 0

        # Try r2ghidra JSON decompilation first.  cmdj may return None, a
        # list, or a dict whose "error" key indicates failure — all must
        # fall through to the pdf fallback.
        code = ""
        engine = "r2ghidra"
        try:
            result = r2.cmdj(f"pdgj @ 0x{faddr:x}")
            # Accept only dict results; a list or None means failure.
            decomp_dict = result if isinstance(result, dict) else {}
            # Missing "code" key AND empty/null "code" value both fall through.
            code = (decomp_dict.get("code") or "").strip()
        except Exception:
            code = ""

        if not code:
            # Fallback: plain pdf text output
            try:
                code = (r2.cmd(f"pdf @ 0x{faddr:x}") or "").strip()
                engine = "pdf"
            except Exception:
                code = ""

        if code:
            findings.append(analyzer._finding(
                path,
                f"Decompilation [{engine}]: {fname}",
                code[:3000],
                severity="INFO",
                offset=faddr,
                confidence=0.7,
            ))
            decompiled.append({
                "name": fname,
                "address": faddr,
                "pseudocode": code[:1500],
            })

    return decompiled


def _step5_crypto_constants(
    analyzer: "DisassemblyAnalyzer",
    path: str,
    data: bytes,
    findings: List[Finding],
) -> list[str]:
    """Step 5 – Detect known cryptographic constants via byte-pattern search.

    Searches the raw binary for characteristic byte sequences from common
    cryptographic primitives (AES, SHA-256/512, SHA-1/MD5, CRC32, DES, RC4).

    All non-overlapping occurrences of each pattern are found.  Hits within
    256 bytes of the previous accepted hit for the same pattern are suppressed
    as near-duplicates — this prevents a single OpenSSL-linked binary from
    generating dozens of AES findings that bury legitimate signal.  The
    suppression count is noted in the finding detail.

    Returns a list of detected crypto-primitive labels for the Step 8 AI
    payload.
    """
    detected_labels: list[str] = []

    for label, pattern, severity in _CRYPTO_SIGNATURES:
        # Collect all non-overlapping occurrence offsets.
        all_offsets: list[int] = []
        start = 0
        while True:
            pos = data.find(pattern, start)
            if pos == -1:
                break
            all_offsets.append(pos)
            start = pos + len(pattern)

        if not all_offsets:
            continue

        # Deduplicate: keep only hits that are more than 256 bytes apart from
        # the last accepted hit (sliding window deduplication).
        accepted: list[int] = [all_offsets[0]]
        for off in all_offsets[1:]:
            if off - accepted[-1] > _CRYPTO_DEDUP_WINDOW:
                accepted.append(off)

        suppressed = len(all_offsets) - len(accepted)
        suffix = (
            f" ({suppressed} near-duplicate occurrence(s) suppressed)"
            if suppressed else ""
        )
        for offset in accepted:
            findings.append(analyzer._finding(
                path,
                f"Crypto constant detected: {label}",
                f"Pattern found at file offset 0x{offset:08x} — "
                f"binary likely implements or uses {label}{suffix}",
                severity=severity,
                offset=offset,
                confidence=0.8,
            ))
        detected_labels.append(label)

    return detected_labels


def _step6_xref_strings(
    r2,
    analyzer: "DisassemblyAnalyzer",
    path: str,
    depth: str,
    findings: List[Finding],
) -> list[str]:
    """Step 6 – Extract strings and map each to the functions that reference it.

    Retrieves all binary strings via ``izj``, then for each string queries
    ``axtj @ <vaddr>`` (analyze cross-references **to** the address) to find
    which code locations reference the string.  ``axtj`` is the correct
    command here — it returns callers of the address — whereas ``axfj``
    (analyze cross-references **from** the address) would follow references
    outward from the string itself, which is not useful for string-to-caller
    mapping.

    Returns the list of formatted cross-reference rows for the Step 8 AI
    payload.
    """
    strings_raw: list = r2.cmdj("izj") or []
    # Limit in fast mode to keep analysis snappy
    str_limit = 30 if depth == "fast" else 150

    xref_rows: list[str] = []
    for sobj in strings_raw[:str_limit]:
        vaddr: int = sobj.get("vaddr", 0) or 0
        string_val: str = sobj.get("string", "")
        if not string_val or not vaddr:
            continue

        try:
            # axtj: cross-references TO this address (i.e. code → string)
            xrefs = r2.cmdj(f"axtj @ 0x{vaddr:x}") or []
        except Exception:
            xrefs = []

        callers = [
            f"0x{x.get('from', 0):08x}" for x in xrefs
            if x.get("from")
        ]
        caller_str = ", ".join(callers[:5]) if callers else "(no xrefs)"
        xref_rows.append(f"  {caller_str}  →  \"{string_val[:80]}\"")

    if xref_rows:
        findings.append(analyzer._finding(
            path,
            f"Xref-mapped strings ({len(xref_rows)} shown)",
            "\n".join(xref_rows),
            severity="INFO",
            confidence=0.65,
        ))

    return xref_rows


def _step7_so_specifics(
    r2,
    analyzer: "DisassemblyAnalyzer",
    path: str,
    data: bytes,
    findings: List[Finding],
) -> None:
    """Step 7 – .so-specific analysis: constructors, DWARF, LD_PRELOAD detection.

    Constructor functions (.init_array / .ctors):
        Functions registered in ``.init_array`` or ``.ctors`` ELF sections run
        *before* ``main`` and are a favourite CTF hiding place.  We locate
        these sections via ``iSj``, read the function-pointer array from the
        binary, resolve each pointer to a symbol name via ``fd @ <addr>``, and
        emit HIGH-severity findings for each constructor.

    DWARF debug information:
        If the .so retains DWARF sections (``.debug_*``) the binary was built
        without stripping.  We surface source file names extracted via
        ``idpj`` (r2 DWARF parser) as INFO findings.

    LD_PRELOAD indicator:
        A shared library that exports the same symbol names as libc (``open``,
        ``read``, ``write``, ``malloc``, …) is almost certainly designed to be
        injected via ``LD_PRELOAD`` to intercept calls.  We flag any overlap
        with the well-known hook set.
    """
    # ------------------------------------------------------------------ #
    # 7a – Constructor detection (.init_array / .ctors)                    #
    # ------------------------------------------------------------------ #
    sections_raw: list = r2.cmdj("iSj") or []

    # Section types that hold constructor function pointers
    ctor_section_names = {".init_array", ".ctors", "__mod_init_func"}
    ctor_sections = [
        s for s in sections_raw
        if s.get("name", "") in ctor_section_names
    ]

    for sec in ctor_sections:
        sec_name: str = sec.get("name", "")
        sec_vaddr: int = sec.get("vaddr", 0) or 0
        sec_paddr: int = sec.get("paddr", 0) or 0
        sec_size: int = sec.get("size", 0) or 0

        # Read pointer-sized entries from the raw binary.
        # Guard against truncated / non-ELF data before accessing the ELF
        # class byte at index 4 (1=32-bit, 2=64-bit).
        ptr_size = 8 if (len(data) > 4 and data[:4] == b"\x7fELF" and data[4] == 2) else 4
        fmt = "<Q" if ptr_size == 8 else "<I"
        n_ptrs = sec_size // ptr_size

        ctor_details: list[str] = []
        for i in range(min(n_ptrs, 32)):
            offset = sec_paddr + i * ptr_size
            if offset + ptr_size > len(data):
                break
            try:
                fn_ptr = struct.unpack_from(fmt, data, offset)[0]
            except struct.error:
                break
            if fn_ptr == 0:
                continue
            # Resolve symbol name from r2
            try:
                sym_name = (r2.cmd(f"fd @ 0x{fn_ptr:x}") or "").strip()
            except Exception:
                sym_name = ""
            sym_name = sym_name or f"sub_0x{fn_ptr:x}"
            ctor_details.append(f"  0x{fn_ptr:08x}  {sym_name}")

        if ctor_details:
            findings.append(analyzer._finding(
                path,
                f"Constructor functions in {sec_name} "
                f"({len(ctor_details)} entries)",
                "\n".join(ctor_details),
                severity="HIGH",
                offset=sec_vaddr,
                confidence=0.85,
            ))

    # ------------------------------------------------------------------ #
    # 7b – DWARF debug information                                         #
    # ------------------------------------------------------------------ #
    debug_sections = [
        s.get("name", "") for s in sections_raw
        if s.get("name", "").startswith(".debug_")
    ]

    if debug_sections:
        # Try to extract DWARF compilation-unit info via r2's idpj
        dwarf_detail_lines: list[str] = [
            f"Debug sections present: {', '.join(debug_sections[:10])}"
        ]
        try:
            dwarf_raw = r2.cmdj("idpj") or []
            for cu in dwarf_raw[:20]:
                comp_dir = cu.get("comp_dir", "")
                producer = cu.get("producer", "")
                lang = cu.get("language", "")
                src = cu.get("name", "")
                if src or comp_dir:
                    dwarf_detail_lines.append(
                        f"  CU: {src}  dir={comp_dir}  lang={lang}  "
                        f"compiler={producer}"
                    )
        except Exception:
            pass

        findings.append(analyzer._finding(
            path,
            "DWARF debug info present (binary not stripped)",
            "\n".join(dwarf_detail_lines),
            severity="INFO",
            confidence=0.75,
        ))

    # ------------------------------------------------------------------ #
    # 7c – LD_PRELOAD hook indicator                                       #
    # ------------------------------------------------------------------ #
    try:
        exports_raw: list = r2.cmdj("iEj") or []
    except Exception:
        exports_raw = []

    export_names: set[str] = set()
    for exp in exports_raw:
        raw_name: str = exp.get("name", "")
        # Strip leading underscores to normalize (e.g. _open -> open)
        export_names.add(raw_name.lstrip("_"))

    hooked = sorted(export_names & _LD_PRELOAD_HOOKS)
    if hooked:
        findings.append(analyzer._finding(
            path,
            f"LD_PRELOAD hook library detected ({len(hooked)} libc symbol(s) overridden)",
            "Exported symbols that shadow libc: " + ", ".join(hooked) + "\n"
            "This .so is likely injected via LD_PRELOAD to intercept system calls.",
            severity="HIGH",
            confidence=0.9,
        ))


# ---------------------------------------------------------------------------
# r2pipe primary engine
# ---------------------------------------------------------------------------

def _r2_analyze(
    analyzer: "DisassemblyAnalyzer",
    path: str,
    data: bytes,
    depth: str,
    ai_client: Optional[AIClient],
) -> List[Finding]:
    """Full r2pipe-based analysis: symbols, relocations, GOT, CFG, disassembly.

    Opens the binary with ``r2pipe.open(path, flags=["-2", "-A"])`` so that
    radare2 suppresses stderr (-2) and runs a full auto-analysis on open (-A,
    equivalent to ``aaa``).  The session is always closed in a ``finally``
    block to prevent zombie r2 processes.
    """
    import r2pipe  # noqa: F401 - ImportError propagates to caller for fallback

    findings: List[Finding] = []
    r2 = None
    try:
        # -2: suppress stderr   -A: run aaa (full analysis) on open
        r2 = r2pipe.open(path, flags=["-2", "-A"])

        # Detect whether this is a shared library by file name
        p = Path(path)
        is_so = p.suffix == ".so" or ".so." in p.name

        # ------------------------------------------------------------------ #
        # Step 2a – Imports (iij)                                              #
        # ------------------------------------------------------------------ #
        imports_raw: list = r2.cmdj("iij") or []
        dangerous_found: list[tuple[int, str]] = []
        import_rows: list[str] = []

        for imp in imports_raw:
            name: str = imp.get("name", "")
            plt: int = imp.get("plt", imp.get("vaddr", 0)) or 0
            # Strip leading underscores and '@plt' suffix for matching
            base_name = name.split("@")[0].lstrip("_")
            import_rows.append(f"  0x{plt:08x}  {name}")
            if base_name in _DANGEROUS_IMPORTS:
                dangerous_found.append((plt, name))

        if import_rows:
            findings.append(analyzer._finding(
                path,
                f"Imports ({len(import_rows)} found)",
                "\n".join(import_rows),
                severity="INFO",
                confidence=0.7,
            ))

        for plt_addr, imp_name in dangerous_found:
            findings.append(analyzer._finding(
                path,
                f"Dangerous import: {imp_name}",
                f"PLT address 0x{plt_addr:08x} — commonly exploited in CTF challenges",
                severity="HIGH",
                offset=plt_addr,
                confidence=0.85,
            ))

        # ------------------------------------------------------------------ #
        # Step 2b – Exports (iEj)                                              #
        # ------------------------------------------------------------------ #
        # r2 command: iEj = exports as JSON.  For .so files this is the
        # primary entry-point list (all publicly visible symbols).
        exports_raw: list = r2.cmdj("iEj") or []

        for exp in exports_raw:
            name: str = exp.get("name", "")
            vaddr: int = exp.get("vaddr", 0) or 0
            real_name: str = exp.get("realname", name)
            findings.append(analyzer._finding(
                path,
                f"Export: {name}",
                f"Address 0x{vaddr:08x}  (demangled: {real_name})",
                severity="MEDIUM" if is_so else "INFO",
                offset=vaddr,
                confidence=0.75,
            ))

        # ------------------------------------------------------------------ #
        # Step 2c – Relocations (irj)                                          #
        # ------------------------------------------------------------------ #
        relocs_raw: list = r2.cmdj("irj") or []

        unresolved = [r for r in relocs_raw if not r.get("name")]
        if unresolved:
            reloc_lines = [
                f"  0x{r.get('vaddr', 0):08x}  type={r.get('type', '?')}"
                for r in unresolved[:50]
            ]
            findings.append(analyzer._finding(
                path,
                f"Unresolved relocations ({len(unresolved)})",
                "\n".join(reloc_lines),
                severity="INFO",
                confidence=0.6,
            ))

        # ------------------------------------------------------------------ #
        # Step 2d – GOT entries                                                #
        # Extract GOT entries from relocation table: any relocation whose     #
        # type contains "GOT" is a GOT slot.                                  #
        # ------------------------------------------------------------------ #
        got_entries = [
            r for r in relocs_raw
            if "GOT" in r.get("type", "").upper()
        ]
        if got_entries:
            got_lines = [
                f"  0x{r.get('vaddr', 0):08x}  {r.get('name', '<unnamed>')}"
                for r in got_entries[:50]
            ]
            findings.append(analyzer._finding(
                path,
                f"GOT entries ({len(got_entries)})",
                "\n".join(got_lines),
                severity="INFO",
                confidence=0.65,
            ))

        # ------------------------------------------------------------------ #
        # Step 2e – Consolidated Symbol Map (INFO, for AI consumption)         #
        # ------------------------------------------------------------------ #
        sym_lines: list[str] = ["=== IMPORTS ==="]
        sym_lines += import_rows or ["  (none)"]
        sym_lines.append("=== EXPORTS ===")
        sym_lines += [
            f"  0x{e.get('vaddr', 0):08x}  {e.get('name', '')}"
            for e in exports_raw
        ] or ["  (none)"]
        sym_lines.append("=== RELOCATIONS ===")
        sym_lines += [
            f"  0x{r.get('vaddr', 0):08x}  "
            f"{r.get('name', '<unnamed>')}  type={r.get('type', '?')}"
            for r in relocs_raw[:50]
        ] or ["  (none)"]

        findings.append(analyzer._finding(
            path,
            "Symbol Map",
            "\n".join(sym_lines),
            severity="INFO",
            confidence=0.7,
        ))

        # ------------------------------------------------------------------ #
        # Step 3 – Function list (aflj) + per-function CFG (agfj)              #
        # ------------------------------------------------------------------ #
        funcs: list = r2.cmdj("aflj") or []

        if funcs:
            func_limit = 20 if depth == "fast" else len(funcs)
            cfg_lines: list[str] = []

            for func in funcs[:func_limit]:
                fname: str = func.get("name", "?")
                faddr: int = func.get("offset", 0) or 0
                cfg_raw = r2.cmdj(f"agfj @ 0x{faddr:x}") or []
                n_blocks = (
                    len(cfg_raw[0].get("blocks", []))
                    if cfg_raw and len(cfg_raw) > 0 else 0
                )
                cfg_lines.append(
                    f"  0x{faddr:08x}  {fname}  basic_blocks={n_blocks}"
                )

            findings.append(analyzer._finding(
                path,
                f"Function list ({len(funcs)} functions, "
                f"showing {min(func_limit, len(funcs))})",
                "\n".join(cfg_lines),
                severity="INFO",
                confidence=0.7,
            ))

        # ------------------------------------------------------------------ #
        # Step 4 – Decompilation (r2ghidra / pdf fallback)                  #
        # ------------------------------------------------------------------ #
        decompiled_funcs: list[dict] = []
        if funcs:
            decompiled_funcs = _step4_decompile(r2, analyzer, path, funcs, depth, findings)

        # ------------------------------------------------------------------ #
        # Step 5 – Crypto constant detection                                   #
        # ------------------------------------------------------------------ #
        detected_crypto = _step5_crypto_constants(analyzer, path, data, findings)

        # ------------------------------------------------------------------ #
        # Step 6 – Xref-mapped strings                                         #
        # ------------------------------------------------------------------ #
        xref_rows = _step6_xref_strings(r2, analyzer, path, depth, findings)

        # ------------------------------------------------------------------ #
        # Step 7 – .so-specific: constructor / DWARF / LD_PRELOAD             #
        # ------------------------------------------------------------------ #
        if is_so:
            _step7_so_specifics(r2, analyzer, path, data, findings)

        # ------------------------------------------------------------------ #
        # Entry-point disassembly for AI context                               #
        # ------------------------------------------------------------------ #
        entries_raw: list = r2.cmdj("iej") or []
        entry_addr: Optional[int] = None
        for entry in entries_raw:
            if entry.get("type") == "program" or not entry_addr:
                entry_addr = entry.get("vaddr")
                break

        if entry_addr is None and funcs:
            entry_addr = funcs[0].get("offset")

        asm_text = ""
        if entry_addr is not None:
            n_insns = 50 if depth == "fast" else 200
            disasm = r2.cmd(f"pd {n_insns} @ 0x{entry_addr:x}") or ""
            asm_text = disasm.strip()
            if asm_text:
                findings.append(analyzer._finding(
                    path,
                    f"Disassembly at entry 0x{entry_addr:08x}",
                    asm_text[:3000],
                    severity="INFO",
                    offset=entry_addr,
                    confidence=0.7,
                ))

        if depth == "deep" and ai_client and ai_client.available and asm_text:
            summary = ai_client.explain_disassembly(asm_text)
            if summary:
                findings.append(analyzer._finding(
                    path,
                    "AI disassembly summary",
                    summary,
                    severity="MEDIUM",
                    offset=entry_addr if entry_addr is not None else -1,
                    confidence=0.65,
                ))

        # ------------------------------------------------------------------ #
        # Step 8 – Structured AI binary analysis payload                       #
        # Sends a rich structured context to Claude — high-complexity          #
        # function pseudocode, flagged imports, detected crypto primitives,    #
        # and xref-mapped strings — to produce an actionable CTF attack plan.  #
        #                                                                      #
        # The depth guard is enforced HERE inside _r2_analyze() rather than   #
        # at the call site so that fast vs deep divergence over time cannot    #
        # silently disable this step.                                          #
        # ------------------------------------------------------------------ #
        if depth == "deep" and ai_client and ai_client.available:
            analysis = ai_client.analyze_binary(
                file_path=path,
                high_complexity_functions=decompiled_funcs,
                flagged_imports=[name for _, name in dangerous_found],
                crypto_constants=detected_crypto,
                xref_strings=xref_rows,
            )
            if analysis:
                findings.append(analyzer._finding(
                    path,
                    "AI binary analysis (structured)",
                    analysis,
                    severity="HIGH",
                    offset=entry_addr if entry_addr is not None else -1,
                    confidence=0.75,
                ))

    finally:
        # Always close the r2 session to prevent zombie r2 processes
        if r2 is not None:
            try:
                r2.quit()
            except Exception:
                pass

    return findings


# ---------------------------------------------------------------------------
# Analyzer class
# ---------------------------------------------------------------------------

class DisassemblyAnalyzer(Analyzer):
    def analyze(
        self,
        path: str,
        flag_pattern: re.Pattern,
        depth: str,
        ai_client: Optional[AIClient],
        **_kw,
    ) -> List[Finding]:
        findings: List[Finding] = []

        try:
            data = Path(path).read_bytes()
        except Exception as exc:
            return [self._finding(path, f"Read error: {exc}", "", confidence=0.1)]

        if not _is_supported_binary(data):
            return [self._finding(
                path,
                "Disassembly skipped: unrecognized binary format",
                "",
                severity="INFO",
                confidence=0.1,
            )]

        # ------------------------------------------------------------------ #
        # Primary engine: r2pipe                                               #
        # ------------------------------------------------------------------ #
        try:
            import r2pipe  # noqa: F401
            return _r2_analyze(self, path, data, depth, ai_client)
        except ImportError:
            findings.append(self._finding(
                path,
                "r2pipe not found — using linear disassembly fallback; "
                "install radare2 for full analysis",
                "",
                severity="INFO",
                confidence=0.3,
            ))

        # ------------------------------------------------------------------ #
        # Fallback engine: Capstone linear disassembly                         #
        # ------------------------------------------------------------------ #
        try:
            import capstone  # noqa: F401
        except ImportError:
            return findings + [self._finding(
                path,
                "Disassembly skipped: capstone not installed",
                "",
                severity="INFO",
                confidence=0.1,
            )]

        return _capstone_fallback(self, path, data, depth, ai_client, findings)
