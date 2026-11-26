from __future__ import annotations

import struct

import pytest

from sigforge.binary_loader import parse_binary
from sigforge.errors import BinaryFormatError, RvaOutOfBoundsError, SpecValidationError
from sigforge.models import ByteRole, RipCapture, SigEntry, SigSpec
from sigforge.synthetic_bins import build_minimal_elf64, build_minimal_pe64, make_demo_binary_pair
from sigforge.x86_ild import decode_insn, decode_window


def test_pe64_and_elf64_parsing_and_bounds() -> None:
    pair = make_demo_binary_pair()
    img_v1 = parse_binary(pair["pe_v1"])
    img_v2 = parse_binary(pair["pe_v2"])
    elf_v1 = parse_binary(pair["elf_v1"])

    assert img_v1.format == "pe64"
    assert img_v1.image_base == 0x140000000
    assert len(img_v1.exec_sections()) == 1
    assert len(img_v1.readonly_sections()) >= 1
    assert len(img_v1.func_bounds) == 4

    t1 = pair["targets_v1"]["resolve_player_db"]
    t2 = pair["targets_v2"]["resolve_player_db"]
    assert t2 - t1 == 0x30
    assert img_v1.normalize_rva(t1) == t1
    assert img_v1.normalize_rva(0x140000000 + t1) == t1
    assert img_v1.func_containing(t1) is not None
    assert img_v2.func_containing(t2) is not None

    with pytest.raises(RvaOutOfBoundsError):
        img_v1.normalize_rva(0x2000)  # .rdata is not executable
    with pytest.raises(RvaOutOfBoundsError):
        img_v1.normalize_rva(-1)

    assert elf_v1.format == "elf64"
    assert elf_v1.image_base == 0x400000
    assert elf_v1.normalize_rva(0x400000 + t1) == t1
    assert any(fb.name == "resolve_player_db" for fb in elf_v1.func_bounds)


def test_pe64_image_base_offset_opt_plus_24() -> None:
    # Verify ImageBase is read at opt+24 (8 bytes), not opt+28
    custom_base = 0x7FF712340000
    pe = build_minimal_pe64(b"\x90\xc3", image_base=custom_base)
    img = parse_binary(pe)
    assert img.image_base == custom_base


def test_binary_loader_rejects_invalid_inputs() -> None:
    with pytest.raises(BinaryFormatError):
        parse_binary(b"NOT_A_BINARY" * 10)

    # PE32 (0x010B) instead of PE32+ (0x020B)
    pe = bytearray(build_minimal_pe64(b"\x90\xc3"))
    e_lfanew = struct.unpack_from("<I", pe, 0x3C)[0]
    struct.pack_into("<H", pe, e_lfanew + 24, 0x010B)
    with pytest.raises(BinaryFormatError):
        parse_binary(bytes(pe))

    # ELF32 instead of ELF64
    elf = bytearray(build_minimal_elf64(b"\x90\xc3"))
    elf[4] = 1
    with pytest.raises(BinaryFormatError):
        parse_binary(bytes(elf))


def test_pe64_padding_and_elf64_et_dyn_dynsym() -> None:
    # PE32+ with vsize > rsize (virtual zero-pad) and rsize > vsize (truncate file-align padding)
    pe = build_minimal_pe64(b"\x48\x83\xec\x20\xc3")
    img = parse_binary(pe)
    text_sec = img.exec_sections()[0]
    assert len(text_sec.data) == 5  # logical_len = vsize = 5, not 0x200

    # ELF64 ET_DYN with image_base=0 and SHT_DYNSYM (type 11)
    elf = bytearray(
        build_minimal_elf64(
            b"\x48\x83\xec\x20\xc3\xcc",
            image_base=0,
            text_rva=0x1000,
            func_symbols=[("dyn_fn", 0x1000, 5)],
        )
    )
    struct.pack_into("<H", elf, 16, 3)  # ET_DYN
    # Change .symtab sh_type (2) to SHT_DYNSYM (11)
    e_shoff = struct.unpack_from("<Q", elf, 40)[0]
    e_shnum = struct.unpack_from("<H", elf, 60)[0]
    for i in range(e_shnum):
        off = e_shoff + i * 64
        if struct.unpack_from("<I", elf, off + 4)[0] == 2:
            struct.pack_into("<I", elf, off + 4, 11)
    img_dyn = parse_binary(bytes(elf))
    assert img_dyn.image_base == 0
    assert len(img_dyn.func_bounds) == 1
    assert img_dyn.func_bounds[0].name == "dyn_fn"
    assert img_dyn.func_bounds[0].start_rva == 0x1000


def test_ild_edge_cases() -> None:
    # 1. 48 B8 imm64 (mov rax, imm64) -> 10 bytes
    ins = decode_insn(bytes.fromhex("48 B8 11 22 33 44 55 66 77 88"), 0, 0x1000)
    assert ins.is_valid and ins.length == 10
    assert ins.roles == (ByteRole.PREFIX, ByteRole.OPCODE) + (ByteRole.IMM,) * 8

    # 2. A1 moffs64 (1 + 8 = 9 bytes) and 67 A1 (1 + 1 + 4 = 6 bytes)
    ins_a1 = decode_insn(bytes.fromhex("A1 01 02 03 04 05 06 07 08"), 0, 0x1000)
    assert ins_a1.is_valid and ins_a1.length == 9
    assert ins_a1.roles == (ByteRole.OPCODE,) + (ByteRole.DISP32,) * 8

    ins_67a1 = decode_insn(bytes.fromhex("67 A1 01 02 03 04"), 0, 0x1000)
    assert ins_67a1.is_valid and ins_67a1.length == 6
    assert ins_67a1.roles == (ByteRole.PREFIX, ByteRole.OPCODE) + (ByteRole.DISP32,) * 4

    # 3. Grp3 trap: F7 /0 (test ecx, imm32 -> 6B) vs F7 /2 (not ecx -> 2B)
    ins_test = decode_insn(bytes.fromhex("F7 C1 80 00 00 00"), 0, 0x1000)
    assert ins_test.is_valid and ins_test.length == 6
    assert ins_test.roles == (ByteRole.OPCODE, ByteRole.MODRM_SIB) + (ByteRole.IMM,) * 4

    ins_not = decode_insn(bytes.fromhex("F7 D1 90 90 90 90"), 0, 0x1000)
    assert ins_not.is_valid and ins_not.length == 2
    assert ins_not.roles == (ByteRole.OPCODE, ByteRole.MODRM_SIB)

    # F6 /1 (test cl, imm8 -> 3B) vs F6 /3 (neg cl -> 2B)
    ins_f6_test = decode_insn(bytes.fromhex("F6 C9 0F"), 0, 0x1000)
    assert ins_f6_test.is_valid and ins_f6_test.length == 3
    ins_f6_neg = decode_insn(bytes.fromhex("F6 D9 90"), 0, 0x1000)
    assert ins_f6_neg.is_valid and ins_f6_neg.length == 2

    # 4. [rip + disp32]
    ins_rip = decode_insn(bytes.fromhex("48 8B 05 10 00 00 00"), 0, 0x1000)
    assert ins_rip.is_valid and ins_rip.length == 7
    assert ins_rip.rip_disp_offset == 3
    assert ins_rip.rip_target_rva == 0x1017
    assert ins_rip.roles[3:] == (ByteRole.RIP_DISP32,) * 4

    # 5. SIB mod=00 base=5 ([disp32 + rcx*4]) -> 48 8B 04 8D 10 20 30 40
    ins_sib = decode_insn(bytes.fromhex("48 8B 04 8D 10 20 30 40"), 0, 0x1000)
    assert ins_sib.is_valid and ins_sib.length == 8
    assert ins_sib.rip_disp_offset is None
    assert ins_sib.roles[4:] == (ByteRole.DISP32,) * 4

    # 6. [rsp + disp8] vs [rcx + disp8] vs [r12 + disp8]
    ins_rsp = decode_insn(bytes.fromhex("48 8B 44 24 10"), 0, 0x1000)
    assert ins_rsp.roles[-1] == ByteRole.STACK_DISP8
    ins_rcx = decode_insn(bytes.fromhex("48 8B 41 10"), 0, 0x1000)
    assert ins_rcx.roles[-1] == ByteRole.STRUCT_DISP8
    ins_r12 = decode_insn(bytes.fromhex("49 8B 44 24 10"), 0, 0x1000)
    assert ins_r12.roles[0] == ByteRole.REX_EXT
    assert ins_r12.roles[-1] == ByteRole.STRUCT_DISP8

    # 7. 2-byte VEX C5 F9 74 C1 & 3-byte VEX C4 E2 7D 58 C1 & C4 E3 7D 0E C1 05
    ins_vex2 = decode_insn(bytes.fromhex("C5 F9 74 C1"), 0, 0x1000)
    assert ins_vex2.is_valid and ins_vex2.length == 4
    ins_vex3_m2 = decode_insn(bytes.fromhex("C4 E2 7D 58 C1"), 0, 0x1000)
    assert ins_vex3_m2.is_valid and ins_vex3_m2.length == 5
    ins_vex3_m3 = decode_insn(bytes.fromhex("C4 E3 7D 0E C1 05"), 0, 0x1000)
    assert ins_vex3_m3.is_valid and ins_vex3_m3.length == 6
    assert ins_vex3_m3.roles[-1] == ByteRole.IMM

    # 8. 0F 84 rel32 and 0F 3A imm8
    ins_jcc = decode_insn(bytes.fromhex("0F 84 05 00 00 00"), 0, 0x1000)
    assert ins_jcc.is_valid and ins_jcc.length == 6
    assert ins_jcc.rel_disp_offset == 2 and ins_jcc.rel_target_rva == 0x100B
    ins_0f3a = decode_insn(bytes.fromhex("66 0F 3A 0E C1 03"), 0, 0x1000)
    assert ins_0f3a.is_valid and ins_0f3a.length == 6
    assert ins_0f3a.roles[-1] == ByteRole.IMM

    # 9. 0xCC padding stops decode_window
    pe = build_minimal_pe64(bytes.fromhex("90 C3 CC CC 90"))
    img = parse_binary(pe)
    win = decode_window(img, 0x1000)
    assert [i.length for i in win] == [1, 1]

    # 10. Forward E8 call in stripped binary does not bleed past RET + 0x90 NOP padding
    elf_call = build_minimal_elf64(bytes.fromhex("E8 03 00 00 00 C3 90 90 89 C8 C3 CC"))
    img_call = parse_binary(elf_call)
    win_call = decode_window(img_call, 0x1000)
    assert [(i.rva, i.mnemonic_class) for i in win_call] == [(0x1000, "call"), (0x1005, "ret")]


def test_sigspec_validation() -> None:
    good = SigSpec(
        name="demo_spec",
        binary_format="pe64",
        signatures=[
            SigEntry(
                name="sig_a",
                pattern="48 8B 05 ?? ?? ?? ??",
                rva_v1=0x1000,
                rip_capture=RipCapture(
                    insn_index=0, disp_offset=3, next_ip_offset=7, kind="rip_data"
                ),
            )
        ],
    )
    roundtrip = SigSpec.from_json(good.to_json())
    assert roundtrip.signatures[0].name == "sig_a"

    bad_wc_start = SigSpec(
        name="demo_spec",
        signatures=[SigEntry(name="sig_a", pattern="?? 8B 05", rva_v1=0x1000)],
    )
    with pytest.raises(SpecValidationError):
        bad_wc_start.to_json()

    bad_ident = SigSpec(
        name="123bad",
        signatures=[SigEntry(name="sig_a", pattern="48 8B", rva_v1=0x1000)],
    )
    with pytest.raises(SpecValidationError):
        bad_ident.to_json()
