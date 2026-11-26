from __future__ import annotations

import struct
from typing import Any, Sequence


def _align_up(val: int, align: int) -> int:
    return (val + align - 1) & ~(align - 1)


def build_minimal_pe64(
    text_bytes: bytes,
    rdata_bytes: bytes = b"",
    *,
    image_base: int = 0x140000000,
    text_rva: int = 0x1000,
    rdata_rva: int = 0x2000,
    pdata_entries: Sequence[tuple[int, int, int]] = (),
    pdata_rva: int = 0x4000,
    entry_rva: int | None = None,
) -> bytes:
    file_align = 0x200
    sec_align = 0x1000
    headers_size = 0x400

    pdata_bytes = b"".join(struct.pack("<III", b, e, u) for b, e, u in pdata_entries)
    if rdata_bytes and pdata_bytes and pdata_rva < rdata_rva + len(rdata_bytes):
        pdata_rva = _align_up(rdata_rva + len(rdata_bytes), sec_align)

    sections_spec: list[tuple[bytes, int, bytes, int]] = [
        (b".text\x00\x00\x00", text_rva, text_bytes, 0x60000020)
    ]
    if rdata_bytes:
        sections_spec.append((b".rdata\x00\x00", rdata_rva, rdata_bytes, 0x40000040))
    if pdata_bytes:
        sections_spec.append((b".pdata\x00\x00", pdata_rva, pdata_bytes, 0x40000040))

    num_sections = len(sections_spec)
    e_lfanew = 0x80
    size_opt_hdr = 240  # 112 + 16 * 8

    dos_hdr = bytearray(e_lfanew)
    dos_hdr[0:2] = b"MZ"
    struct.pack_into("<I", dos_hdr, 0x3C, e_lfanew)

    pe_sig = b"PE\x00\x00"
    coff_hdr = struct.pack(
        "<HHIIIHH",
        0x8664,
        num_sections,
        0,
        0,
        0,
        size_opt_hdr,
        0x2022,
    )

    last_rva = max(vrva + max(len(raw), 1) for _, vrva, raw, _ in sections_spec)
    size_of_image = _align_up(last_rva, sec_align)

    opt_hdr = bytearray(size_opt_hdr)
    struct.pack_into("<H", opt_hdr, 0, 0x020B)  # PE32+
    struct.pack_into("<I", opt_hdr, 4, _align_up(len(text_bytes), file_align))
    struct.pack_into("<I", opt_hdr, 16, entry_rva if entry_rva is not None else text_rva)
    struct.pack_into("<I", opt_hdr, 20, text_rva)
    struct.pack_into("<Q", opt_hdr, 24, image_base)
    struct.pack_into("<II", opt_hdr, 32, sec_align, file_align)
    struct.pack_into("<HH", opt_hdr, 40, 6, 0)
    struct.pack_into("<HH", opt_hdr, 48, 6, 0)
    struct.pack_into("<II", opt_hdr, 56, size_of_image, headers_size)
    struct.pack_into("<H", opt_hdr, 68, 3)  # Windows CUI
    struct.pack_into("<QQQQ", opt_hdr, 72, 0x100000, 0x1000, 0x100000, 0x1000)
    struct.pack_into("<I", opt_hdr, 108, 16)
    if pdata_bytes:
        struct.pack_into("<II", opt_hdr, 112 + 24, pdata_rva, len(pdata_bytes))

    sec_hdrs = bytearray()
    sec_blobs = bytearray()
    cur_raw_ptr = headers_size

    for name8, vrva, raw, chars in sections_spec:
        rsize = _align_up(max(len(raw), 1), file_align)
        padded = raw + b"\x00" * (rsize - len(raw))
        sec_hdrs.extend(
            struct.pack(
                "<8sIIIIIIHHI",
                name8,
                len(raw),
                vrva,
                rsize,
                cur_raw_ptr,
                0,
                0,
                0,
                0,
                chars,
            )
        )
        sec_blobs.extend(padded)
        cur_raw_ptr += rsize

    header_block = bytes(dos_hdr) + pe_sig + coff_hdr + bytes(opt_hdr) + bytes(sec_hdrs)
    if len(header_block) > headers_size:
        raise ValueError("PE headers overflow headers_size")
    header_pad = b"\x00" * (headers_size - len(header_block))
    return header_block + header_pad + bytes(sec_blobs)


def build_minimal_elf64(
    text_bytes: bytes,
    rodata_bytes: bytes = b"",
    *,
    image_base: int = 0x400000,
    text_rva: int = 0x1000,
    rodata_rva: int = 0x2000,
    func_symbols: Sequence[tuple[str, int, int]] = (),
    entry_rva: int | None = None,
) -> bytes:
    if rodata_bytes and rodata_rva < text_rva + len(text_bytes):
        rodata_rva = _align_up(text_rva + len(text_bytes), 0x1000)

    ehdr_size = 64
    phdr_size = 56
    phoff = ehdr_size

    # Build string tables and symbol table
    strtab = bytearray(b"\x00")
    symtab = bytearray(b"\x00" * 24)
    for sym_name, start_rva, sym_size in func_symbols:
        name_off = len(strtab)
        strtab.extend(sym_name.encode("ascii") + b"\x00")
        symtab.extend(
            struct.pack(
                "<IBBHQQ",
                name_off,
                0x12,  # STB_GLOBAL | STT_FUNC
                0,
                1,  # .text section index
                image_base + start_rva,
                sym_size,
            )
        )

    sh_names = ["", ".text"]
    if rodata_bytes:
        sh_names.append(".rodata")
    sh_names.extend([".strtab", ".symtab", ".shstrtab"])

    shstrtab = bytearray()
    sh_name_offs: dict[str, int] = {}
    for nm in sh_names:
        sh_name_offs[nm] = len(shstrtab)
        shstrtab.extend(nm.encode("ascii") + b"\x00")

    text_off = text_rva
    rodata_off = rodata_rva if rodata_bytes else text_off + len(text_bytes)
    cur_off = (rodata_off + len(rodata_bytes)) if rodata_bytes else (text_off + len(text_bytes))

    strtab_off = cur_off
    cur_off += len(strtab)
    cur_off = _align_up(cur_off, 8)
    symtab_off = cur_off
    cur_off += len(symtab)
    shstrtab_off = cur_off
    cur_off += len(shstrtab)
    cur_off = _align_up(cur_off, 8)
    shoff = cur_off

    shdrs: list[bytes] = []
    # 0: SHT_NULL
    shdrs.append(struct.pack("<IIQQQQIIQQ", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0))
    # 1: .text
    shdrs.append(
        struct.pack(
            "<IIQQQQIIQQ",
            sh_name_offs[".text"],
            1,  # SHT_PROGBITS
            0x6,  # SHF_ALLOC | SHF_EXECINSTR
            image_base + text_rva,
            text_off,
            len(text_bytes),
            0,
            0,
            16,
            0,
        )
    )
    if rodata_bytes:
        shdrs.append(
            struct.pack(
                "<IIQQQQIIQQ",
                sh_name_offs[".rodata"],
                1,
                0x2,  # SHF_ALLOC
                image_base + rodata_rva,
                rodata_off,
                len(rodata_bytes),
                0,
                0,
                8,
                0,
            )
        )
    strtab_idx = len(shdrs)
    shdrs.append(
        struct.pack(
            "<IIQQQQIIQQ",
            sh_name_offs[".strtab"],
            3,  # SHT_STRTAB
            0,
            0,
            strtab_off,
            len(strtab),
            0,
            0,
            1,
            0,
        )
    )
    shdrs.append(
        struct.pack(
            "<IIQQQQIIQQ",
            sh_name_offs[".symtab"],
            2,  # SHT_SYMTAB
            0,
            0,
            symtab_off,
            len(symtab),
            strtab_idx,
            1,
            8,
            24,
        )
    )
    shstrtab_idx = len(shdrs)
    shdrs.append(
        struct.pack(
            "<IIQQQQIIQQ",
            sh_name_offs[".shstrtab"],
            3,
            0,
            0,
            shstrtab_off,
            len(shstrtab),
            0,
            0,
            1,
            0,
        )
    )

    total_load_sz = (
        (rodata_off + len(rodata_bytes)) if rodata_bytes else (text_off + len(text_bytes))
    )
    total_file_sz = shoff + len(shdrs) * 64
    out = bytearray(total_file_sz)

    # e_ident
    out[0:16] = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8
    e_entry = image_base + (entry_rva if entry_rva is not None else text_rva)
    struct.pack_into(
        "<HHIQQQIHHHHHH",
        out,
        16,
        2,  # ET_EXEC
        62,  # EM_X86_64
        1,
        e_entry,
        phoff,
        shoff,
        0,
        ehdr_size,
        phdr_size,
        1,
        64,
        len(shdrs),
        shstrtab_idx,
    )

    # Single PT_LOAD segment
    struct.pack_into(
        "<IIQQQQQQ",
        out,
        phoff,
        1,  # PT_LOAD
        5,  # PF_R | PF_X
        0,
        image_base,
        image_base,
        total_load_sz,
        total_load_sz,
        0x1000,
    )

    out[text_off : text_off + len(text_bytes)] = text_bytes
    if rodata_bytes:
        out[rodata_off : rodata_off + len(rodata_bytes)] = rodata_bytes
    out[strtab_off : strtab_off + len(strtab)] = strtab
    out[symtab_off : symtab_off + len(symtab)] = symtab
    out[shstrtab_off : shstrtab_off + len(shstrtab)] = shstrtab
    for i, sh in enumerate(shdrs):
        off = shoff + i * 64
        out[off : off + 64] = sh

    return bytes(out)


def _rel32(insn_rva: int, insn_len: int, target_rva: int) -> bytes:
    return struct.pack("<i", target_rva - (insn_rva + insn_len))


def _build_demo_sections(
    *,
    text_rva: int,
    rdata_rva: int,
    is_v2: bool,
) -> tuple[bytes, bytes, list[tuple[int, int, int]], dict[str, int], dict[str, int]]:
    # Build .rdata
    rdata = bytearray()
    if is_v2:
        # +32 bytes internal offset shift in v2
        rdata.extend(b"PATCH_HEADER_PADDING_V2_32BYTES!")
    str_actual_off = len(rdata)
    rdata.extend(b"ACTUAL_PLAYER@db\x00")
    str_table_off = len(rdata)
    rdata.extend(b"FM26_PLAYER_TABLE\x00")
    while len(rdata) % 8 != 0:
        rdata.append(0)
    g_ptr_off = len(rdata)
    rdata.extend(struct.pack("<Q", 0x140002000 + g_ptr_off))

    rdata_rvas = {
        "actual_player_str": rdata_rva + str_actual_off,
        "fm26_table_str": rdata_rva + str_table_off,
        "g_PlayerDbPtr": rdata_rva + g_ptr_off,
    }

    # Build .text in two passes so forward/backward rel32 targets are exact
    stack_imm = 0x30 if is_v2 else 0x20
    prologue_body = bytes.fromhex("48 89 5C 24 08 48 89 74 24 10 57 48 83 EC") + bytes([stack_imm])

    # Pre-calculate function offsets
    text = bytearray()
    if is_v2:
        # 48-byte (0x30) new function inserted at start of .text
        patch_fn = bytearray(bytes.fromhex("48 83 EC 28 33 C0 48 83 C4 28 C3"))
        patch_fn.extend(b"\xcc" * (48 - len(patch_fn)))
        assert len(patch_fn) == 0x30
        text.extend(patch_fn)

    # Function 1: decoy_func (shares exact 15-byte prologue in v1; in v2 prologue has 0x20 vs 0x30)
    decoy_start = text_rva + len(text)
    decoy_prologue = bytes.fromhex("48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 20")
    decoy_body = decoy_prologue + bytes.fromhex("33 C0 83 C0 07 48 83 C4 20 5F C3 CC CC CC CC")
    text.extend(decoy_body)
    decoy_end = text_rva + len(text) - 4

    # Function 2: resolve_player_db (Target #1)
    f1_start = text_rva + len(text)
    f1_mov_rip_rva = text_rva + len(text) + len(prologue_body)
    f1_call_rva = f1_mov_rip_rva + 7 + 6 + 2 + 4
    f1_lea_rip_rva = f1_call_rva + 5
    f1_epilogue = (
        bytes.fromhex("48 83 C4") + bytes([stack_imm]) + bytes.fromhex("5F C3 CC CC CC CC")
    )
    f1_len_no_pad = len(prologue_body) + 7 + 6 + 2 + 4 + 5 + 7 + (len(f1_epilogue) - 4)
    f1_end = f1_start + f1_len_no_pad

    # Function 3: calc_ca_pa_rating (Target #2)
    f2_start = f1_start + f1_len_no_pad + 4
    # 48 83 EC 28 (4) + 8B 44 24 28 (4) + 0F AF C1 (3) + 48 8D 15 <disp32> (7) + 85 C0 (2) + 0F 84 05 00 00 00 (6) + E8 <rel32> (5) + 48 83 C4 28 (4) + C3 (1) + CC CC (2)
    f2_lea_rva = f2_start + 4 + 4 + 3
    f2_call_rva = f2_lea_rva + 7 + 2 + 6
    f2_len_no_pad = 4 + 4 + 3 + 7 + 2 + 6 + 5 + 4 + 1
    f2_end = f2_start + f2_len_no_pad

    # Function 4: helper_fn
    helper_start = f2_start + f2_len_no_pad + 2
    helper_bytes = bytes.fromhex("8D 41 01 C3 CC CC CC CC")
    helper_end = helper_start + 4

    # Assemble Target #1
    text.extend(prologue_body)
    text.extend(b"\x48\x8b\x05" + _rel32(f1_mov_rip_rva, 7, rdata_rvas["g_PlayerDbPtr"]))
    text.extend(bytes.fromhex("F7 C1 80 00 00 00"))  # test ecx, 0x80
    text.extend(bytes.fromhex("F7 D1"))  # not ecx
    text.extend(bytes.fromhex("C5 F9 74 C1"))  # vpcmpeqb xmm0, xmm0, xmm1
    text.extend(b"\xe8" + _rel32(f1_call_rva, 5, helper_start))
    text.extend(b"\x48\x8d\x0d" + _rel32(f1_lea_rip_rva, 7, rdata_rvas["actual_player_str"]))
    text.extend(f1_epilogue)

    # Assemble Target #2
    text.extend(bytes.fromhex("48 83 EC 28"))
    text.extend(bytes.fromhex("8B 44 24 28"))
    text.extend(bytes.fromhex("0F AF C1"))
    text.extend(b"\x48\x8d\x15" + _rel32(f2_lea_rva, 7, rdata_rvas["fm26_table_str"]))
    text.extend(bytes.fromhex("85 C0"))
    text.extend(bytes.fromhex("0F 84 05 00 00 00"))
    text.extend(b"\xe8" + _rel32(f2_call_rva, 5, helper_start))
    text.extend(bytes.fromhex("48 83 C4 28 C3 CC CC"))

    # Assemble Function 4: helper_fn
    text.extend(helper_bytes)

    pdata_entries: list[tuple[int, int, int]] = []
    if is_v2:
        pdata_entries.append((text_rva, text_rva + 11, 0))
    pdata_entries.extend(
        [
            (decoy_start, decoy_end, 0),
            (f1_start, f1_end, 0),
            (f2_start, f2_end, 0),
            (helper_start, helper_end, 0),
        ]
    )

    targets = {
        "decoy_func": decoy_start,
        "resolve_player_db": f1_start,
        "calc_ca_pa_rating": f2_start,
        "helper_fn": helper_start,
    }
    return bytes(text), bytes(rdata), pdata_entries, targets, rdata_rvas


def make_demo_binary_pair() -> dict[str, Any]:
    text_v1, rdata_v1, pdata_v1, targets_v1, rdata_rvas_v1 = _build_demo_sections(
        text_rva=0x1000, rdata_rva=0x2000, is_v2=False
    )
    text_v2, rdata_v2, pdata_v2, targets_v2, rdata_rvas_v2 = _build_demo_sections(
        text_rva=0x1000, rdata_rva=0x3000, is_v2=True
    )

    pe_v1 = build_minimal_pe64(
        text_v1,
        rdata_v1,
        text_rva=0x1000,
        rdata_rva=0x2000,
        pdata_entries=pdata_v1,
        pdata_rva=0x4000,
        entry_rva=targets_v1["resolve_player_db"],
    )
    pe_v2 = build_minimal_pe64(
        text_v2,
        rdata_v2,
        text_rva=0x1000,
        rdata_rva=0x3000,
        pdata_entries=pdata_v2,
        pdata_rva=0x4000,
        entry_rva=targets_v2["resolve_player_db"],
    )

    elf_syms = [
        ("decoy_func", targets_v1["decoy_func"], 26),
        ("resolve_player_db", targets_v1["resolve_player_db"], 52),
        ("calc_ca_pa_rating", targets_v1["calc_ca_pa_rating"], 36),
        ("helper_fn", targets_v1["helper_fn"], 4),
    ]
    elf_v1 = build_minimal_elf64(
        text_v1,
        rdata_v1,
        text_rva=0x1000,
        rodata_rva=0x2000,
        func_symbols=elf_syms,
        entry_rva=targets_v1["resolve_player_db"],
    )

    return {
        "pe_v1": pe_v1,
        "pe_v2": pe_v2,
        "elf_v1": elf_v1,
        "targets_v1": targets_v1,
        "targets_v2": targets_v2,
        "rdata_v1": rdata_rvas_v1,
        "rdata_v2": rdata_rvas_v2,
    }
