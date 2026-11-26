from __future__ import annotations

import random
import struct
from dataclasses import dataclass, field
from typing import Any

from sigforge.models import ROLE_VOLATILITY, BinaryImage, ByteRole, DecodedInsn, SigEntry, SigSpec
from sigforge.scanner_core import scan_buffer, scan_exec_sections
from sigforge.x86_ild import decode_insn


@dataclass
class SigOracleReport:
    name: str
    gate1_unique: bool
    gate2_antifragile: bool
    gate3_survival: bool
    matches_v1: list[int]
    matches_v2: list[int]
    relocation_pass_rate: float
    stack_pass_rate: float
    hard_stress_pass_rate: float
    survival_score: float
    naive_raw_score: float
    failures: list[str] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return self.gate1_unique and self.gate2_antifragile and self.gate3_survival

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "passed": self.passed,
            "gate1_unique": self.gate1_unique,
            "gate2_antifragile": self.gate2_antifragile,
            "gate3_survival": self.gate3_survival,
            "matches_v1": list(self.matches_v1),
            "matches_v2": list(self.matches_v2),
            "relocation_pass_rate": round(self.relocation_pass_rate, 4),
            "stack_pass_rate": round(self.stack_pass_rate, 4),
            "hard_stress_pass_rate": round(self.hard_stress_pass_rate, 4),
            "survival_score": round(self.survival_score, 2),
            "naive_raw_score": round(self.naive_raw_score, 2),
            "failures": list(self.failures),
        }


@dataclass
class SpecOracleResult:
    passed: bool
    gate1_uniqueness_passed: bool
    gate2_antifragile_passed: bool
    gate3_survival_passed: bool
    mean_survival_score: float
    reports: dict[str, SigOracleReport]
    failures: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "gate1_uniqueness_passed": self.gate1_uniqueness_passed,
            "gate2_antifragile_passed": self.gate2_antifragile_passed,
            "gate3_survival_passed": self.gate3_survival_passed,
            "mean_survival_score": round(self.mean_survival_score, 2),
            "reports": {k: v.to_dict() for k, v in self.reports.items()},
            "failures": list(self.failures),
        }


def _decode_covering_bytes(
    image: BinaryImage, start_rva: int, min_bytes: int
) -> tuple[list[DecodedInsn], list[ByteRole]]:
    sec = image.section_at_rva(start_rva)
    if sec is None or not sec.is_exec:
        return [], []
    base_off = start_rva - sec.rva
    insns: list[DecodedInsn] = []
    roles: list[ByteRole] = []
    pos = base_off
    view = memoryview(sec.data)
    while len(roles) < min_bytes and pos < len(sec.data):
        ins = decode_insn(view, pos, sec.rva + pos)
        if not ins.is_valid:
            break
        insns.append(ins)
        roles.extend(ins.roles)
        pos += ins.length
    return insns, roles


def _run_relocation_fuzzer(
    sec_data: bytes,
    target_off_in_sec: int,
    tokens: list[int | None],
    insns: list[DecodedInsn],
    roles: list[ByteRole],
    *,
    trials: int,
    seed: int,
) -> tuple[float, float, float, float]:
    if trials <= 0:
        return 1.0, 1.0, 1.0, 1.0

    rip_disp_offsets: list[int] = []
    rel_offsets: list[tuple[int, int]] = []
    stack_offsets: set[int] = set()
    hard_stress_offsets: set[int] = set()

    cur_off = 0
    for ins in insns:
        if ins.rip_disp_offset is not None:
            rip_disp_offsets.append(cur_off + ins.rip_disp_offset)
        if ins.rel_disp_offset is not None:
            rel_len = ins.length - ins.rel_disp_offset
            if rel_len in (1, 4):
                rel_offsets.append((cur_off + ins.rel_disp_offset, rel_len))
        if ins.length == 4 and ins.raw[:3] in (b"\x48\x83\xec", b"\x48\x83\xc4"):
            stack_offsets.add(cur_off + 3)
        for b_idx, role in enumerate(ins.roles):
            if role == ByteRole.STACK_DISP8:
                stack_offsets.add(cur_off + b_idx)
            elif role in (ByteRole.IMM, ByteRole.DISP32):
                hard_stress_offsets.add(cur_off + b_idx)
        cur_off += ins.length

    hard_stress_offsets -= stack_offsets

    anchor_b = tokens[0]
    stub_byte = 0xCC if anchor_b != 0xCC else 0x90
    rng = random.Random(seed)

    overall_pass = 0
    reloc_pass = 0
    stack_total = 0
    stack_pass = 0
    hard_total = 0
    hard_pass = 0

    stack_cutoff = int(trials * 0.60)
    hard_cutoff = int(trials * 0.85)

    for t_idx in range(trials):
        shift = rng.randint(16, 128)
        delta_rdata = rng.randint(0x1000, 0x40000)
        delta_call = rng.choice((-1, 1)) * rng.randint(0x100, 0x20000)
        delta_rel8 = rng.randint(1, 30)

        mut = bytearray(bytes([stub_byte]) * shift)
        mut.extend(sec_data)

        base = shift + target_off_in_sec
        for r_off in rip_disp_offsets:
            pos = base + r_off
            if pos + 4 <= len(mut):
                val = struct.unpack_from("<I", mut, pos)[0]
                struct.pack_into("<I", mut, pos, (val + delta_rdata) & 0xFFFFFFFF)

        for r_off, r_len in rel_offsets:
            pos = base + r_off
            if r_len == 4 and pos + 4 <= len(mut):
                val = struct.unpack_from("<I", mut, pos)[0]
                struct.pack_into("<I", mut, pos, (val + delta_call) & 0xFFFFFFFF)
            elif r_len == 1 and pos + 1 <= len(mut):
                mut[pos] = (mut[pos] + delta_rel8) & 0xFF

        reloc_ok = scan_buffer(mut, tokens, max_hits=4) == [base]
        if reloc_ok:
            reloc_pass += 1

        is_stack_trial = t_idx < stack_cutoff
        is_hard_trial = stack_cutoff <= t_idx < hard_cutoff

        if is_stack_trial:
            stack_total += 1
            s_delta = rng.choice((8, 16, 32))
            for s_off in stack_offsets:
                pos = base + s_off
                if pos < len(mut):
                    mut[pos] = (mut[pos] + s_delta) & 0xFF
            ok = scan_buffer(mut, tokens, max_hits=4) == [base]
            if ok:
                stack_pass += 1
                overall_pass += 1
        elif is_hard_trial:
            hard_total += 1
            for h_off in hard_stress_offsets:
                pos = base + h_off
                if pos < len(mut):
                    mut[pos] = (mut[pos] ^ rng.randint(1, 255)) & 0xFF
            ok = scan_buffer(mut, tokens, max_hits=4) == [base]
            if ok:
                hard_pass += 1
                overall_pass += 1
        else:
            if reloc_ok:
                overall_pass += 1

    overall_rate = overall_pass / trials
    reloc_rate = reloc_pass / trials
    stack_rate = (stack_pass / stack_total) if stack_total > 0 else 1.0
    hard_rate = (hard_pass / hard_total) if hard_total > 0 else 1.0
    return overall_rate, reloc_rate, stack_rate, hard_rate


def _compute_survival_score(
    tokens: list[int | None],
    roles: list[ByteRole],
    overall_pass_rate: float,
) -> float:
    pat_len = len(tokens)
    locked_indices = [i for i, t in enumerate(tokens) if t is not None]
    locked_count = len(locked_indices)
    if locked_count == 0 or len(roles) < pat_len:
        mean_vol = 1.0
    else:
        mean_vol = sum(ROLE_VOLATILITY[roles[i]] for i in locked_indices) / locked_count

    if locked_count >= 5 and pat_len <= 32:
        compact_pts = 10.0
    elif pat_len <= 48:
        compact_pts = 7.0
    else:
        compact_pts = 4.0

    raw = 70.0 * overall_pass_rate + 20.0 * (1.0 - mean_vol) + compact_pts
    return round(min(100.0, max(0.0, raw)), 2)


def evaluate_signature(
    entry: SigEntry,
    v1: BinaryImage,
    v2: BinaryImage | None = None,
    *,
    trials: int = 100,
    seed: int = 0x516F049E,
) -> SigOracleReport:
    tokens = entry.tokens()
    pat_len = len(tokens)
    failures: list[str] = []

    matches_v1 = scan_exec_sections(v1, tokens)
    matches_v2 = scan_exec_sections(v2, tokens) if v2 is not None else []

    # Gate 1: Exact Uniqueness
    gate1 = True
    if tokens[0] is None:
        gate1 = False
        failures.append("Gate 1: pattern starts with a wildcard")
    if tokens[-1] is None:
        gate1 = False
        failures.append("Gate 1: pattern ends with a wildcard")
    if matches_v1 != [entry.rva_v1]:
        gate1 = False
        failures.append(
            f"Gate 1: v1 matches {[hex(x) for x in matches_v1]} != [0x{entry.rva_v1:X}]"
        )
    if v2 is not None:
        if entry.rva_v2 is None or matches_v2 != [entry.rva_v2]:
            gate1 = False
            exp_v2 = f"0x{entry.rva_v2:X}" if entry.rva_v2 is not None else "None"
            failures.append(f"Gate 1: v2 matches {[hex(x) for x in matches_v2]} != [{exp_v2}]")

    # Gate 2: Anti-Fragility
    raw_len = max(pat_len, entry.byte_length)
    insns, roles = _decode_covering_bytes(v1, entry.rva_v1, raw_len)
    locked_indices = [i for i, t in enumerate(tokens) if t is not None]
    locked_count = len(locked_indices)

    gate2 = True
    if locked_count < 4:
        gate2 = False
        failures.append(f"Gate 2: locked_count={locked_count} < 4")
    if pat_len == 0 or (locked_count / pat_len) < 0.20:
        gate2 = False
        failures.append(f"Gate 2: locked density {locked_count}/{pat_len} < 0.20")
    if len(roles) < pat_len:
        gate2 = False
        failures.append(
            f"Gate 2: decoded only {len(roles)} bytes at 0x{entry.rva_v1:X}, need {pat_len}"
        )
    else:
        fragile = [i for i in locked_indices if roles[i] in (ByteRole.RIP_DISP32, ByteRole.REL)]
        if fragile:
            gate2 = False
            failures.append(f"Gate 2: locked volatile RIP/REL bytes at offsets {fragile}")

    # Gate 3: 100-Trial Deterministic Relocation Fuzzer
    sec = v1.section_at_rva(entry.rva_v1)
    if sec is None or not sec.is_exec or len(roles) < pat_len:
        reloc_rate = 0.0
        stack_rate = 0.0
        hard_rate = 0.0
        survival_score = 0.0
        naive_raw_score = 0.0
        gate3 = False
        failures.append("Gate 3: target RVA not decodable inside executable section")
    else:
        target_off = entry.rva_v1 - sec.rva
        overall_rate, reloc_rate, stack_rate, hard_rate = _run_relocation_fuzzer(
            sec.data,
            target_off,
            tokens,
            insns,
            roles,
            trials=trials,
            seed=seed,
        )
        survival_score = _compute_survival_score(tokens, roles, overall_rate)

        raw_slice = sec.data[target_off : target_off + raw_len]
        raw_tokens: list[int | None] = list(raw_slice)
        if len(raw_tokens) == raw_len:
            raw_overall, _, _, _ = _run_relocation_fuzzer(
                sec.data,
                target_off,
                raw_tokens,
                insns,
                roles,
                trials=trials,
                seed=seed,
            )
            naive_raw_score = _compute_survival_score(raw_tokens, roles, raw_overall)
        else:
            naive_raw_score = 0.0

        gate3 = reloc_rate == 1.0 and stack_rate == 1.0 and survival_score >= 75.0
        if reloc_rate < 1.0:
            failures.append(f"Gate 3: relocation_pass_rate={reloc_rate:.2%} < 100%")
        if stack_rate < 1.0:
            failures.append(f"Gate 3: stack_pass_rate={stack_rate:.2%} < 100%")
        if survival_score < 75.0:
            failures.append(f"Gate 3: survival_score={survival_score:.2f} < 75.0")

    return SigOracleReport(
        name=entry.name,
        gate1_unique=gate1,
        gate2_antifragile=gate2,
        gate3_survival=gate3,
        matches_v1=matches_v1,
        matches_v2=matches_v2,
        relocation_pass_rate=reloc_rate,
        stack_pass_rate=stack_rate,
        hard_stress_pass_rate=hard_rate,
        survival_score=survival_score,
        naive_raw_score=naive_raw_score,
        failures=failures,
    )


def verify_spec(
    spec: SigSpec, v1: BinaryImage, v2: BinaryImage | None = None, *, trials: int = 100
) -> SpecOracleResult:
    reports: dict[str, SigOracleReport] = {}
    all_failures: list[str] = []

    for entry in spec.signatures:
        rep = evaluate_signature(entry, v1, v2, trials=trials)
        reports[entry.name] = rep
        for f in rep.failures:
            all_failures.append(f"[{entry.name}] {f}")

    g1 = all(r.gate1_unique for r in reports.values())
    g2 = all(r.gate2_antifragile for r in reports.values())
    g3 = all(r.gate3_survival for r in reports.values())
    mean_score = (
        round(sum(r.survival_score for r in reports.values()) / len(reports), 2) if reports else 0.0
    )

    return SpecOracleResult(
        passed=(g1 and g2 and g3 and bool(reports)),
        gate1_uniqueness_passed=g1,
        gate2_antifragile_passed=g2,
        gate3_survival_passed=g3,
        mean_survival_score=mean_score,
        reports=reports,
        failures=all_failures,
    )
