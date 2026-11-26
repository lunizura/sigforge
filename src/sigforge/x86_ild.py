from __future__ import annotations

import struct

from sigforge.errors import RvaOutOfBoundsError
from sigforge.models import BinaryImage, ByteRole, DecodedInsn

_LEGACY_PREFIXES: frozenset[int] = frozenset(
    {0x26, 0x2E, 0x36, 0x3E, 0x64, 0x65, 0x66, 0x67, 0xF0, 0xF2, 0xF3}
)

_INVALID_PRIMARY_64: frozenset[int] = frozenset(
    {
        0x06,
        0x07,
        0x0E,
        0x16,
        0x17,
        0x1E,
        0x1F,
        0x27,
        0x2F,
        0x37,
        0x3F,
        0x60,
        0x61,
        0x62,
        0x82,
        0x9A,
        0xC4,
        0xC5,
        0xCE,
        0xD4,
        0xD5,
        0xD6,
        0xEA,
    }
)

_MAP1_NO_MODRM: frozenset[int] = frozenset(
    {
        0x05,
        0x06,
        0x07,
        0x08,
        0x09,
        0x0B,
        0x30,
        0x31,
        0x32,
        0x33,
        0x34,
        0x35,
        0x77,
        0xA0,
        0xA1,
        0xA2,
        0xA8,
        0xA9,
    }
    | set(range(0xC8, 0xD0))
)

_MAP1_IMM8: frozenset[int] = frozenset(
    {0x70, 0x71, 0x72, 0x73, 0xA4, 0xAC, 0xBA, 0xC2, 0xC4, 0xC5, 0xC6}
)


def _invalid_insn(buf: bytes | memoryview, offset: int, rva: int) -> DecodedInsn:
    if 0 <= offset < len(buf):
        raw = bytes(buf[offset : offset + 1])
        roles: tuple[ByteRole, ...] = (ByteRole.OPCODE,)
    else:
        raw = b""
        roles = ()
    return DecodedInsn(
        rva=rva,
        raw=raw,
        roles=roles,
        mnemonic_class="invalid",
        is_valid=False,
    )


def decode_insn(buf: bytes | memoryview, offset: int, rva: int) -> DecodedInsn:
    n = len(buf)
    if offset < 0 or offset >= n:
        return _invalid_insn(buf, offset, rva)

    pos = offset
    roles: list[ByteRole] = []
    has_66 = False
    has_67 = False

    # 1. Legacy prefixes
    while pos < n and (pos - offset) < 14 and buf[pos] in _LEGACY_PREFIXES:
        b = buf[pos]
        roles.append(ByteRole.PREFIX)
        if b == 0x66:
            has_66 = True
        elif b == 0x67:
            has_67 = True
        pos += 1

    if pos >= n:
        return _invalid_insn(buf, offset, rva)

    # 2. REX or VEX
    rex_w = False
    rex_b = False
    vex_map = 0

    b_cur = buf[pos]
    if 0x40 <= b_cur <= 0x4F:
        rex_w = bool(b_cur & 0x08)
        rex_b = bool(b_cur & 0x01)
        roles.append(ByteRole.PREFIX if (b_cur & 0x07) == 0 else ByteRole.REX_EXT)
        pos += 1
    elif pos == offset and pos + 2 < n and b_cur == 0xC5:
        v1 = buf[pos + 1]
        vex_map = 1
        has_66 = (v1 & 0x03) == 1
        roles.extend((ByteRole.OPCODE, ByteRole.REX_EXT))
        pos += 2
    elif pos == offset and pos + 3 < n and b_cur == 0xC4:
        v1 = buf[pos + 1]
        v2 = buf[pos + 2]
        m = v1 & 0x1F
        if m not in (1, 2, 3):
            return _invalid_insn(buf, offset, rva)
        vex_map = m
        rex_w = bool(v2 & 0x80)
        rex_b = not bool(v1 & 0x20)
        has_66 = (v2 & 0x03) == 1
        roles.extend((ByteRole.OPCODE, ByteRole.REX_EXT, ByteRole.REX_EXT))
        pos += 3

    if pos >= n:
        return _invalid_insn(buf, offset, rva)

    # 3. Opcode maps
    imm_z = 2 if (has_66 and not rex_w) else 4
    has_modrm = False
    imm_len = 0
    rel_len = 0
    moffs_len = 0
    is_ret = False
    is_uncond_jmp = False
    is_padding = False
    is_grp3 = False
    grp3_op = 0
    is_ff = False
    mnem = "op"

    if vex_map in (1, 2, 3) or buf[pos] == 0x0F:
        if vex_map in (1, 2, 3):
            map_id = vex_map
        else:
            roles.append(ByteRole.OPCODE)
            pos += 1
            if pos >= n:
                return _invalid_insn(buf, offset, rva)
            if buf[pos] == 0x38:
                map_id = 2
                roles.append(ByteRole.OPCODE)
                pos += 1
            elif buf[pos] == 0x3A:
                map_id = 3
                roles.append(ByteRole.OPCODE)
                pos += 1
            else:
                map_id = 1

        if pos >= n:
            return _invalid_insn(buf, offset, rva)
        op = buf[pos]
        roles.append(ByteRole.OPCODE)
        pos += 1

        if map_id == 2:
            has_modrm = True
            imm_len = 0
            mnem = "simd_ext"
        elif map_id == 3:
            has_modrm = True
            imm_len = 1
            mnem = "simd_imm"
        else:
            if 0x80 <= op <= 0x8F and vex_map == 0:
                has_modrm = False
                rel_len = 4
                mnem = "jcc"
            elif op in _MAP1_NO_MODRM:
                has_modrm = False
                imm_len = 0
                mnem = "sys_or_bswap"
            elif op in _MAP1_IMM8:
                has_modrm = True
                imm_len = 1
                mnem = "ext_imm8"
            else:
                has_modrm = True
                imm_len = 0
                mnem = "nop" if op == 0x1F else "ext_op"
    else:
        op = buf[pos]
        roles.append(ByteRole.OPCODE)
        pos += 1

        if op in _INVALID_PRIMARY_64:
            return _invalid_insn(buf, offset, rva)

        if (op & 0xC0) == 0 and (op & 7) <= 5:
            low = op & 7
            if low <= 3:
                has_modrm = True
            elif low == 4:
                imm_len = 1
            else:
                imm_len = imm_z
            mnem = "alu"
        elif 0x50 <= op <= 0x5F:
            mnem = "push_pop"
        elif op == 0x63:
            has_modrm = True
            mnem = "mov"
        elif op == 0x68:
            imm_len = imm_z
            mnem = "push"
        elif op == 0x69:
            has_modrm = True
            imm_len = imm_z
            mnem = "imul"
        elif op == 0x6A:
            imm_len = 1
            mnem = "push"
        elif op == 0x6B:
            has_modrm = True
            imm_len = 1
            mnem = "imul"
        elif 0x6C <= op <= 0x6F:
            mnem = "io_str"
        elif 0x70 <= op <= 0x7F:
            rel_len = 1
            mnem = "jcc"
        elif op in (0x80, 0x83):
            has_modrm = True
            imm_len = 1
            mnem = "alu"
        elif op == 0x81:
            has_modrm = True
            imm_len = imm_z
            mnem = "alu"
        elif 0x84 <= op <= 0x8F:
            has_modrm = True
            mnem = "lea" if op == 0x8D else ("test" if op <= 0x85 else "mov")
        elif 0x90 <= op <= 0x9F:
            mnem = "nop" if (op == 0x90 and not rex_b) else "misc"
        elif 0xA0 <= op <= 0xA3:
            moffs_len = 4 if has_67 else 8
            mnem = "mov_moffs"
        elif op in (0xA4, 0xA5, 0xA6, 0xA7) or 0xAA <= op <= 0xAF:
            mnem = "str"
        elif op == 0xA8:
            imm_len = 1
            mnem = "test"
        elif op == 0xA9:
            imm_len = imm_z
            mnem = "test"
        elif 0xB0 <= op <= 0xB7:
            imm_len = 1
            mnem = "mov"
        elif 0xB8 <= op <= 0xBF:
            imm_len = 8 if rex_w else (2 if has_66 else 4)
            mnem = "mov"
        elif op in (0xC0, 0xC1):
            has_modrm = True
            imm_len = 1
            mnem = "shift"
        elif op in (0xC2, 0xCA):
            imm_len = 2
            is_ret = True
            mnem = "ret"
        elif op in (0xC3, 0xCB):
            is_ret = True
            mnem = "ret"
        elif op == 0xC6:
            has_modrm = True
            imm_len = 1
            mnem = "mov"
        elif op == 0xC7:
            has_modrm = True
            imm_len = imm_z
            mnem = "mov"
        elif op == 0xC8:
            imm_len = 3
            mnem = "enter"
        elif op in (0xC9, 0xCF):
            mnem = "leave_iret"
        elif op == 0xCC:
            is_padding = True
            mnem = "int3"
        elif op == 0xCD:
            imm_len = 1
            mnem = "int"
        elif 0xD0 <= op <= 0xD3 or 0xD8 <= op <= 0xDF:
            has_modrm = True
            mnem = "shift_fp"
        elif op == 0xD7:
            mnem = "xlat"
        elif 0xE0 <= op <= 0xE3:
            rel_len = 1
            mnem = "loop_jrcxz"
        elif 0xE4 <= op <= 0xE7:
            imm_len = 1
            mnem = "io"
        elif op == 0xE8:
            rel_len = 4
            mnem = "call"
        elif op == 0xE9:
            rel_len = 4
            is_uncond_jmp = True
            mnem = "jmp"
        elif op == 0xEB:
            rel_len = 1
            is_uncond_jmp = True
            mnem = "jmp"
        elif op in (0xEC, 0xED, 0xEE, 0xEF, 0xF1, 0xF4, 0xF5) or 0xF8 <= op <= 0xFD:
            mnem = "misc"
        elif op in (0xF6, 0xF7):
            has_modrm = True
            is_grp3 = True
            grp3_op = op
            mnem = "grp3"
        elif op in (0xFE, 0xFF):
            has_modrm = True
            is_ff = op == 0xFF
            mnem = "grp4_5"
        else:
            return _invalid_insn(buf, offset, rva)

    # 4. ModR/M + SIB + Displacements
    rip_disp_offset: int | None = None
    rip_disp_val: int | None = None
    rel_disp_offset: int | None = None
    rel_disp_val: int | None = None

    if has_modrm:
        if pos >= n:
            return _invalid_insn(buf, offset, rva)
        modrm = buf[pos]
        roles.append(ByteRole.MODRM_SIB)
        pos += 1
        mod = (modrm >> 6) & 3
        reg_bits = (modrm >> 3) & 7
        rm = modrm & 7

        if is_grp3:
            if reg_bits in (0, 1):
                imm_len = 1 if grp3_op == 0xF6 else imm_z
                mnem = "test"
            else:
                imm_len = 0
                mnem = "grp3_unary"

        if is_ff:
            if reg_bits == 4:
                is_uncond_jmp = True
                mnem = "jmp_ind"
            elif reg_bits == 2:
                mnem = "call_ind"

        if mod != 3:
            base_reg = rm | (8 if rex_b else 0)
            sib = 0
            if rm == 4:
                if pos >= n:
                    return _invalid_insn(buf, offset, rva)
                sib = buf[pos]
                roles.append(ByteRole.MODRM_SIB)
                pos += 1
                base_reg = (sib & 7) | (8 if rex_b else 0)

            if mod == 0:
                if rm == 5:
                    if pos + 4 > n:
                        return _invalid_insn(buf, offset, rva)
                    rip_disp_offset = pos - offset
                    rip_disp_val = struct.unpack_from("<i", buf, pos)[0]
                    roles.extend((ByteRole.RIP_DISP32,) * 4)
                    pos += 4
                elif rm == 4 and (sib & 7) == 5:
                    if pos + 4 > n:
                        return _invalid_insn(buf, offset, rva)
                    roles.extend((ByteRole.DISP32,) * 4)
                    pos += 4
            elif mod == 1:
                if pos >= n:
                    return _invalid_insn(buf, offset, rva)
                roles.append(ByteRole.STACK_DISP8 if base_reg in (4, 5) else ByteRole.STRUCT_DISP8)
                pos += 1
            elif mod == 2:
                if pos + 4 > n:
                    return _invalid_insn(buf, offset, rva)
                roles.extend((ByteRole.DISP32,) * 4)
                pos += 4

    if moffs_len > 0:
        if pos + moffs_len > n:
            return _invalid_insn(buf, offset, rva)
        roles.extend((ByteRole.DISP32,) * moffs_len)
        pos += moffs_len

    if rel_len > 0:
        if pos + rel_len > n:
            return _invalid_insn(buf, offset, rva)
        rel_disp_offset = pos - offset
        if rel_len == 1:
            rel_disp_val = struct.unpack_from("<b", buf, pos)[0]
        else:
            rel_disp_val = struct.unpack_from("<i", buf, pos)[0]
        roles.extend((ByteRole.REL,) * rel_len)
        pos += rel_len

    if imm_len > 0:
        if pos + imm_len > n:
            return _invalid_insn(buf, offset, rva)
        roles.extend((ByteRole.IMM,) * imm_len)
        pos += imm_len

    insn_len = pos - offset
    if insn_len <= 0 or insn_len > 15:
        return _invalid_insn(buf, offset, rva)

    rip_target_rva = (
        (rva + insn_len + rip_disp_val) & 0xFFFFFFFFFFFFFFFF if rip_disp_val is not None else None
    )
    rel_target_rva = (
        (rva + insn_len + rel_disp_val) & 0xFFFFFFFFFFFFFFFF if rel_disp_val is not None else None
    )

    return DecodedInsn(
        rva=rva,
        raw=bytes(buf[offset:pos]),
        roles=tuple(roles),
        mnemonic_class=mnem,
        is_valid=True,
        is_ret=is_ret,
        is_uncond_jmp=is_uncond_jmp,
        is_padding=is_padding,
        rip_disp_offset=rip_disp_offset,
        rip_target_rva=rip_target_rva,
        rel_disp_offset=rel_disp_offset,
        rel_target_rva=rel_target_rva,
    )


def decode_window(
    image: BinaryImage, start_rva: int, *, max_bytes: int = 64, max_insns: int = 24
) -> list[DecodedInsn]:
    sec = image.section_at_rva(start_rva)
    if sec is None or not sec.is_exec:
        raise RvaOutOfBoundsError(f"RVA 0x{start_rva:X} does not map into an executable section")

    limit_rva = min(sec.rva + len(sec.data), start_rva + max_bytes)
    fb = image.func_containing(start_rva)
    if fb is not None:
        limit_rva = min(limit_rva, fb.end_rva)

    end_off = limit_rva - sec.rva
    view = memoryview(sec.data)[:end_off]

    insns: list[DecodedInsn] = []
    cur_rva = start_rva
    max_forward_target = -1

    while cur_rva < limit_rva and len(insns) < max_insns:
        off = cur_rva - sec.rva
        insn = decode_insn(view, off, cur_rva)
        if not insn.is_valid or insn.is_padding:
            break
        insns.append(insn)

        if (
            insn.rel_target_rva is not None
            and insn.mnemonic_class != "call"
            and cur_rva < insn.rel_target_rva < limit_rva
        ):
            if insn.rel_target_rva > max_forward_target:
                max_forward_target = insn.rel_target_rva

        cur_rva += insn.length
        if (insn.is_ret or insn.is_uncond_jmp) and cur_rva > max_forward_target:
            if cur_rva >= limit_rva or sec.data[cur_rva - sec.rva] in (0xCC, 0x90):
                break

    return insns
