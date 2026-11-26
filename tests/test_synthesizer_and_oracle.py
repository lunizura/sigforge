from __future__ import annotations

import pytest

from sigforge.binary_loader import parse_binary
from sigforge.differ import locate_target_in_v2
from sigforge.errors import SynthesisError
from sigforge.models import SigEntry
from sigforge.oracle import evaluate_signature
from sigforge.scanner_core import parse_pattern, resolve_rip_target_in_image, scan_buffer
from sigforge.synthetic_bins import build_minimal_elf64, build_minimal_pe64, make_demo_binary_pair
from sigforge.synthesizer import synthesize_entry, synthesize_spec


def test_overlap_scan_accuracy() -> None:
    buf = bytes.fromhex("48 90 48 90 48")
    toks = parse_pattern("48 ?? 48")
    assert scan_buffer(buf, toks) == [0, 2]
    assert scan_buffer(buf, toks, max_hits=1) == [0]

    # Multi-byte contiguous needle with overlapping hits and leading/trailing wildcards
    buf2 = bytes.fromhex("48 8B 90 48 8B 90 48 8B")
    assert scan_buffer(buf2, parse_pattern("48 8B ?? 48 8B")) == [0, 3]
    buf3 = bytes.fromhex("48 8B 05 48 8B 05 48 8B 05")
    assert scan_buffer(buf3, parse_pattern("48 8B ?? 48 8B")) == [0, 3]
    assert scan_buffer(bytearray(buf3), parse_pattern("?? 8B ?? 48")) == [0, 3]


def test_shared_prologue_disambiguation_and_auto_anchor_v2() -> None:
    pair = make_demo_binary_pair()
    v1 = parse_binary(pair["pe_v1"])
    v2 = parse_binary(pair["pe_v2"])

    rva1_p = pair["targets_v1"]["resolve_player_db"]
    rva2_p = pair["targets_v2"]["resolve_player_db"]
    assert rva2_p - rva1_p == 0x30

    # Auto-anchor v2 without passing rva_v2
    anchor = locate_target_in_v2(v1, rva1_p, v2)
    assert anchor.rva_v2 == rva2_p
    assert anchor.confidence >= 0.70

    entry, report = synthesize_entry("resolve_player_db", v1, rva1_p, v2=v2, rva_v2=None)
    assert entry.rva_v1 == rva1_p
    assert entry.rva_v2 == rva2_p
    # Must walk past the 15-byte shared prologue so decoy_func doesn't match
    assert entry.locked_count > 12
    assert len(entry.trace) >= 5
    assert entry.trace[3].cumulative_matches >= 2
    assert entry.trace[-1].cumulative_matches == 1

    # Verify RipCapture resolves g_PlayerDbPtr in both v1 and v2
    assert entry.rip_capture is not None
    t_v1 = resolve_rip_target_in_image(v1, rva1_p, entry.rip_capture)
    t_v2 = resolve_rip_target_in_image(v2, rva2_p, entry.rip_capture)
    assert t_v1 == pair["rdata_v1"]["g_PlayerDbPtr"]
    assert t_v2 == pair["rdata_v2"]["g_PlayerDbPtr"]

    assert report.passed
    assert report.survival_score >= 85.0
    assert report.naive_raw_score < 35.0


def test_synthesize_spec_both_targets_and_elf64() -> None:
    pair = make_demo_binary_pair()
    v1 = parse_binary(pair["pe_v1"])
    v2 = parse_binary(pair["pe_v2"])
    elf1 = parse_binary(pair["elf_v1"])

    spec, oracle = synthesize_spec(
        "fm26_demo",
        [
            ("resolve_player_db", pair["targets_v1"]["resolve_player_db"], None, "Player DB"),
            ("calc_ca_pa_rating", pair["targets_v1"]["calc_ca_pa_rating"], None, "CA/PA calc"),
        ],
        v1,
        v2=v2,
    )
    assert oracle.passed
    assert oracle.mean_survival_score >= 85.0
    for name, rep in oracle.reports.items():
        assert rep.survival_score >= 85.0, f"{name} score too low: {rep.survival_score}"
        assert rep.naive_raw_score < 35.0, (
            f"{name} naive score unexpectedly high: {rep.naive_raw_score}"
        )

    elf_entry, elf_rep = synthesize_entry(
        "resolve_player_db", elf1, pair["targets_v1"]["resolve_player_db"]
    )
    assert elf_rep.passed
    assert elf_entry.rip_capture is not None


def test_oracle_rejects_locked_rel32_and_rip_patterns() -> None:
    pair = make_demo_binary_pair()
    v1 = parse_binary(pair["pe_v1"])
    rva1 = pair["targets_v1"]["resolve_player_db"]

    # Read raw bytes starting at the shared prologue + mov rax, [rip+disp32] (22 bytes, locking RIP_DISP32!)
    raw_22 = v1.read_rva(rva1, 22)
    assert raw_22 is not None
    bad_entry = SigEntry(
        name="locked_rip",
        pattern=raw_22.hex(" ").upper(),
        rva_v1=rva1,
    )
    rep = evaluate_signature(bad_entry, v1)
    assert not rep.gate2_antifragile
    assert not rep.gate3_survival
    assert not rep.passed

    # Also test locking a rel32 call target in calc_ca_pa_rating
    rva2 = pair["targets_v1"]["calc_ca_pa_rating"]
    # Offset of E8 <rel32> in calc_ca_pa_rating: 4+4+3+7+2+6 = 26, 5 bytes long -> 31 bytes total
    raw_31 = v1.read_rva(rva2, 31)
    assert raw_31 is not None
    bad_rel_entry = SigEntry(
        name="locked_rel32",
        pattern=raw_31.hex(" ").upper(),
        rva_v1=rva2,
    )
    rep2 = evaluate_signature(bad_rel_entry, v1)
    assert not rep2.gate2_antifragile
    assert not rep2.gate3_survival
    assert not rep2.passed


def test_pass2_fallback_minimization_and_locked_count_floor() -> None:
    # Two functions identical in all opcodes/ModRM/stack/imm, differing ONLY in STRUCT_DISP8 (0x10 vs 0x20)
    body = bytes.fromhex("83 C0 05 48 89 C1 48 85 C9 74 02 33 C0 48 83 C4 20 5F C3")
    fn_decoy = bytes.fromhex("48 8B 41 10") + body + b"\xcc\xcc"
    fn_target = bytes.fromhex("48 8B 41 20") + body + b"\xcc\xcc"
    target_rva = 0x1000 + len(fn_decoy)
    pe = build_minimal_pe64(
        fn_decoy + fn_target,
        pdata_entries=[
            (0x1000, target_rva - 2, 0),
            (target_rva, target_rva + len(fn_target) - 2, 0),
        ],
    )
    img = parse_binary(pe)
    entry, rep = synthesize_entry("pass2_struct_disp8", img, target_rva)
    assert entry.pattern == "48 8B 41 20"
    assert len(entry.tokens()) == 4
    assert rep.passed
    assert rep.survival_score >= 90.0

    # Unique 1-insn prefix with < 4 locked bytes (0F AF C1 = 3 bytes) must extend to satisfy Gate 2
    pe_short = build_minimal_pe64(bytes.fromhex("0F AF C1 48 83 EC 20 8B 44 24 20 57 5F C3 CC CC"))
    img_short = parse_binary(pe_short)
    entry_s, rep_s = synthesize_entry("short_unique", img_short, 0x1000)
    assert entry_s.locked_count >= 4
    assert rep_s.gate2_antifragile
    assert rep_s.passed

    # Pass 2 IMM fallback disambiguation must pass Gate 3 (pure relocation 100%, score >= 75)
    imm_body = bytes.fromhex("48 89 C1 48 85 C9 74 02 33 C0 48 83 C4 20 5F C3")
    fn_imm_decoy = bytes.fromhex("B8 01 00 00 00") + imm_body + b"\xcc\xcc"
    fn_imm_target = bytes.fromhex("B8 02 00 00 00") + imm_body + b"\xcc\xcc"
    imm_rva = 0x1000 + len(fn_imm_decoy)
    pe_imm = build_minimal_pe64(
        fn_imm_decoy + fn_imm_target,
        pdata_entries=[
            (0x1000, imm_rva - 2, 0),
            (imm_rva, imm_rva + len(fn_imm_target) - 2, 0),
        ],
    )
    entry_imm, rep_imm = synthesize_entry("pass2_imm", parse_binary(pe_imm), imm_rva)
    assert entry_imm.pattern == "B8 02 ?? ?? ?? 48 89 C1"
    assert rep_imm.relocation_pass_rate == 1.0
    assert rep_imm.stack_pass_rate == 1.0
    assert rep_imm.hard_stress_pass_rate == 0.0
    assert rep_imm.survival_score >= 75.0
    assert rep_imm.passed


def test_differ_handles_rex_ext_change_without_func_bounds() -> None:
    v1_text = bytes.fromhex("49 8B 44 24 10 0F AF C1 F7 C1 80 00 00 00 C3 CC")
    v2_text = bytes.fromhex("90 90 90 90 48 8B 44 24 10 0F AF C1 F7 C1 80 00 00 00 C3 CC")
    e1 = parse_binary(build_minimal_elf64(v1_text))
    e2 = parse_binary(build_minimal_elf64(v2_text))
    match = locate_target_in_v2(e1, 0x1000, e2)
    assert match.rva_v2 == 0x1004
    assert match.confidence >= 0.70

    with pytest.raises(SynthesisError, match="Anchor byte at target RVA differs"):
        synthesize_entry("rex0_mismatch", e1, 0x1000, v2=e2)
