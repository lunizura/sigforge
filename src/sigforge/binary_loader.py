from __future__ import annotations

import struct

from sigforge.errors import BinaryFormatError
from sigforge.models import BinaryImage, FuncBounds, SectionInfo

_MAX_VIRTUAL_PAD = 16 * 1024 * 1024


def parse_binary(data: bytes) -> BinaryImage:
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise BinaryFormatError("Binary input must be bytes-like")
    raw = bytes(data)
    if len(raw) >= 64 and raw[:2] == b"MZ":
        return _parse_pe64(raw)
    if len(raw) >= 64 and raw[:4] == b"\x7fELF":
        return _parse_elf64(raw)
    raise BinaryFormatError("Input is neither a valid PE32+ nor ELF64 x86-64 image")


def _read_rva_from_sections(sections: list[SectionInfo], rva: int, size: int) -> bytes:
    if rva <= 0 or size <= 0:
        return b""
    for sec in sections:
        if sec.rva <= rva < sec.rva + len(sec.data):
            off = rva - sec.rva
            avail = min(size, len(sec.data) - off)
            return sec.data[off : off + avail]
    return b""


def _parse_pe64(data: bytes) -> BinaryImage:
    if len(data) < 64:
        raise BinaryFormatError("Truncated DOS header")
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if e_lfanew > len(data) - 24 or data[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
        raise BinaryFormatError("Invalid PE signature or e_lfanew out of bounds")

    coff = e_lfanew + 4
    machine, num_sections, _, _, _, size_opt_hdr, _ = struct.unpack_from("<HHIIIHH", data, coff)
    if machine != 0x8664:
        raise BinaryFormatError(f"Unsupported PE machine 0x{machine:04X}; expected AMD64 (0x8664)")
    if size_opt_hdr < 112:
        raise BinaryFormatError(f"PE optional header too small: {size_opt_hdr}")

    opt = coff + 20
    sec_table_off = opt + size_opt_hdr
    if sec_table_off + num_sections * 40 > len(data):
        raise BinaryFormatError("PE section headers extend past end of file")

    magic = struct.unpack_from("<H", data, opt)[0]
    if magic != 0x020B:
        raise BinaryFormatError(
            f"Unsupported PE optional magic 0x{magic:04X}; expected PE32+ (0x020B)"
        )

    entry_rva = struct.unpack_from("<I", data, opt + 16)[0]
    image_base = struct.unpack_from("<Q", data, opt + 24)[0]

    num_dd = min(
        16,
        struct.unpack_from("<I", data, opt + 108)[0],
        (size_opt_hdr - 112) // 8,
    )
    pdata_rva = 0
    pdata_size = 0
    if num_dd > 3:
        pdata_rva, pdata_size = struct.unpack_from("<II", data, opt + 112 + 24)

    sections: list[SectionInfo] = []
    for i in range(num_sections):
        off = sec_table_off + i * 40
        sec_name = data[off : off + 8].split(b"\x00", 1)[0].decode("ascii", errors="replace")
        vsize, vrva, rsize, rptr, _, _, _, _, chars = struct.unpack_from(
            "<IIIIIIHHI", data, off + 8
        )
        logical_len = vsize if vsize > 0 else rsize
        avail = min(rsize, logical_len)
        if avail > 0:
            if rptr + avail > len(data):
                raise BinaryFormatError(
                    f"PE section '{sec_name}' raw data (0x{rptr:X}+0x{avail:X}) exceeds file length"
                )
            sec_bytes = data[rptr : rptr + avail]
        else:
            sec_bytes = b""
        if logical_len > avail and (logical_len - avail) <= _MAX_VIRTUAL_PAD:
            sec_bytes += b"\x00" * (logical_len - avail)

        is_exec = bool(chars & 0x20000020)
        is_ro = bool(chars & 0x40000000) and not is_exec and not bool(chars & 0x80000000)
        sections.append(
            SectionInfo(
                name=sec_name,
                rva=vrva,
                size=logical_len,
                raw_offset=rptr,
                data=sec_bytes,
                is_exec=is_exec,
                is_readonly_data=is_ro,
            )
        )

    exec_secs = [s for s in sections if s.is_exec and len(s.data) > 0]
    if not exec_secs:
        raise BinaryFormatError("PE32+ image contains no non-empty executable sections")

    func_bounds: list[FuncBounds] = []
    if pdata_rva > 0 and pdata_size >= 12:
        pdata_bytes = _read_rva_from_sections(sections, pdata_rva, pdata_size)
        count = len(pdata_bytes) // 12
        for idx in range(count):
            begin_rva, end_rva, _ = struct.unpack_from("<III", pdata_bytes, idx * 12)
            if begin_rva == 0 or end_rva <= begin_rva:
                continue
            for es in exec_secs:
                if es.rva <= begin_rva < es.rva + len(es.data):
                    clamped_end = min(end_rva, es.rva + len(es.data))
                    if clamped_end > begin_rva:
                        func_bounds.append(FuncBounds(start_rva=begin_rva, end_rva=clamped_end))
                    break
        func_bounds.sort(key=lambda fb: fb.start_rva)

    return BinaryImage(
        format="pe64",
        image_base=image_base,
        entry_rva=entry_rva,
        sections=sections,
        func_bounds=func_bounds,
    )


def _parse_elf64(data: bytes) -> BinaryImage:
    if len(data) < 64:
        raise BinaryFormatError("Truncated ELF64 header")
    if data[4] != 2:
        raise BinaryFormatError(f"Unsupported ELF class {data[4]}; expected ELFCLASS64 (2)")
    if data[5] != 1:
        raise BinaryFormatError(f"Unsupported ELF endianness {data[5]}; expected little-endian (1)")

    (
        _e_type,
        e_machine,
        _e_version,
        e_entry,
        e_phoff,
        e_shoff,
        _e_flags,
        _e_ehsize,
        e_phentsize,
        e_phnum,
        e_shentsize,
        e_shnum,
        e_shstrndx,
    ) = struct.unpack_from("<HHIQQQIHHHHHH", data, 16)

    if e_machine != 62:
        raise BinaryFormatError(f"Unsupported ELF machine {e_machine}; expected EM_X86_64 (62)")

    load_vaddrs: list[int] = []
    if e_phoff > 0 and e_phnum > 0:
        if e_phentsize < 56 or e_phoff + e_phnum * e_phentsize > len(data):
            raise BinaryFormatError("ELF64 program headers out of bounds")
        for i in range(e_phnum):
            off = e_phoff + i * e_phentsize
            p_type, _p_flags, _p_offset, p_vaddr, _p_paddr, p_filesz, _p_memsz, _p_align = (
                struct.unpack_from("<IIQQQQQQ", data, off)
            )
            if p_type == 1 and p_filesz > 0:
                load_vaddrs.append(p_vaddr)

    image_base = min(load_vaddrs) if load_vaddrs else 0
    entry_rva = e_entry - image_base if e_entry >= image_base else e_entry

    if e_shoff == 0 or e_shnum == 0 or e_shentsize < 64:
        raise BinaryFormatError("ELF64 image has no section headers")
    if e_shoff + e_shnum * e_shentsize > len(data):
        raise BinaryFormatError("ELF64 section headers extend past end of file")

    raw_shdrs: list[tuple[int, int, int, int, int, int, int, int, int, int]] = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        raw_shdrs.append(struct.unpack_from("<IIQQQQIIQQ", data, off))

    shstr_bytes = b""
    if 0 <= e_shstrndx < e_shnum:
        shstr = raw_shdrs[e_shstrndx]
        if shstr[4] + shstr[5] <= len(data):
            shstr_bytes = data[shstr[4] : shstr[4] + shstr[5]]

    def _read_cstr(table: bytes, idx: int) -> str:
        if not table or idx < 0 or idx >= len(table):
            return ""
        end = table.find(b"\x00", idx)
        if end == -1:
            end = len(table)
        return table[idx:end].decode("ascii", errors="replace")

    sections: list[SectionInfo] = []
    sym_sections: list[tuple[int, int, int, int]] = []  # (sh_offset, sh_size, sh_entsize, sh_link)

    for (
        sh_name_idx,
        sh_type,
        sh_flags,
        sh_addr,
        sh_offset,
        sh_size,
        sh_link,
        _sh_info,
        _align,
        sh_entsize,
    ) in raw_shdrs:
        sec_name = _read_cstr(shstr_bytes, sh_name_idx)
        if (sh_flags & 0x2) and sh_type != 8 and sh_size > 0:
            if sh_offset + sh_size > len(data):
                raise BinaryFormatError(f"ELF64 section '{sec_name}' extends past end of file")
            rva = sh_addr - image_base if sh_addr >= image_base else sh_addr
            is_exec = bool(sh_flags & 0x4)
            is_ro = not is_exec and not bool(sh_flags & 0x1)
            sections.append(
                SectionInfo(
                    name=sec_name,
                    rva=rva,
                    size=sh_size,
                    raw_offset=sh_offset,
                    data=data[sh_offset : sh_offset + sh_size],
                    is_exec=is_exec,
                    is_readonly_data=is_ro,
                )
            )
        if sh_type in (2, 11) and sh_size > 0:
            sym_sections.append((sh_offset, sh_size, sh_entsize, sh_link))

    exec_secs = [s for s in sections if s.is_exec and len(s.data) > 0]
    if not exec_secs:
        raise BinaryFormatError("ELF64 image contains no non-empty executable sections")

    func_bounds: list[FuncBounds] = []
    for sh_offset, sh_size, sh_entsize, sh_link in sym_sections:
        if sh_entsize < 24 or sh_offset + sh_size > len(data):
            continue
        strtab = b""
        if 0 <= sh_link < e_shnum:
            str_hdr = raw_shdrs[sh_link]
            if str_hdr[4] + str_hdr[5] <= len(data):
                strtab = data[str_hdr[4] : str_hdr[4] + str_hdr[5]]
        count = sh_size // sh_entsize
        for idx in range(count):
            sym_off = sh_offset + idx * sh_entsize
            st_name, st_info, _st_other, _st_shndx, st_value, st_size = struct.unpack_from(
                "<IBBHQQ", data, sym_off
            )
            if (st_info & 0xF) == 2 and st_value > 0 and st_size > 0:
                start_rva = st_value - image_base if st_value >= image_base else st_value
                for es in exec_secs:
                    if es.rva <= start_rva < es.rva + len(es.data):
                        end_rva = min(start_rva + st_size, es.rva + len(es.data))
                        if end_rva > start_rva:
                            sym_name = _read_cstr(strtab, st_name) or None
                            func_bounds.append(
                                FuncBounds(start_rva=start_rva, end_rva=end_rva, name=sym_name)
                            )
                        break

    func_bounds.sort(key=lambda fb: fb.start_rva)

    return BinaryImage(
        format="elf64",
        image_base=image_base,
        entry_rva=entry_rva,
        sections=sections,
        func_bounds=func_bounds,
    )
