from __future__ import annotations

from typing import Sequence

from sigforge.differ import align_instruction_windows, locate_target_in_v2
from sigforge.errors import DecodeError, SynthesisError
from sigforge.models import (
    DEFAULT_WILDCARD_ROLES,
    BinaryImage,
    ByteRole,
    DecodedInsn,
    InsnTrace,
    RipCapture,
    SigEntry,
    SigSpec,
    validate_spec,
)
from sigforge.oracle import SigOracleReport, SpecOracleResult, evaluate_signature, verify_spec
from sigforge.scanner_core import format_pattern, scan_exec_sections, trim_trailing_wildcards
from sigforge.x86_ild import decode_window


def _build_insn_mask(i1: DecodedInsn, i2: DecodedInsn | None) -> list[int | None]:
    mask: list[int | None] = []
    for b in range(i1.length):
        r1 = i1.roles[b]
        r2 = i2.roles[b] if i2 is not None else r1
        if (
            r1 in DEFAULT_WILDCARD_ROLES
            or r2 in DEFAULT_WILDCARD_ROLES
            or (i2 is not None and i1.raw[b] != i2.raw[b])
        ):
            mask.append(None)
        else:
            mask.append(i1.raw[b])
    return mask


def _find_rip_capture(
    aligned: list[tuple[DecodedInsn, DecodedInsn | None]], count: int
) -> RipCapture | None:
    byte_off = 0
    for idx in range(count):
        ins = aligned[idx][0]
        if ins.rip_disp_offset is not None:
            return RipCapture(
                insn_index=idx,
                disp_offset=byte_off + ins.rip_disp_offset,
                next_ip_offset=byte_off + ins.length,
                kind="rip_data",
            )
        if ins.rel_disp_offset is not None and (ins.length - ins.rel_disp_offset) == 4:
            return RipCapture(
                insn_index=idx,
                disp_offset=byte_off + ins.rel_disp_offset,
                next_ip_offset=byte_off + ins.length,
                kind="rel32_call_jmp",
            )
        byte_off += ins.length
    return None


def _has_rip_or_rel32(ins: DecodedInsn) -> bool:
    return ins.rip_disp_offset is not None or (
        ins.rel_disp_offset is not None and (ins.length - ins.rel_disp_offset) == 4
    )


def synthesize_entry(
    name: str,
    v1: BinaryImage,
    rva_v1: int,
    v2: BinaryImage | None = None,
    rva_v2: int | None = None,
    *,
    max_bytes: int = 64,
    capture_rip: bool = True,
    description: str = "",
) -> tuple[SigEntry, SigOracleReport]:
    norm_v1 = v1.normalize_rva(rva_v1)
    norm_v2: int | None = None
    if v2 is not None:
        if rva_v2 is None:
            norm_v2 = locate_target_in_v2(v1, norm_v1, v2).rva_v2
        else:
            norm_v2 = v2.normalize_rva(rva_v2)

    win1 = decode_window(v1, norm_v1, max_bytes=max_bytes, max_insns=32)
    if not win1:
        raise DecodeError(f"Failed to decode valid instructions at v1 RVA 0x{norm_v1:X}")

    if v2 is not None and norm_v2 is not None:
        win2 = decode_window(v2, norm_v2, max_bytes=max_bytes, max_insns=32)
        if not win2:
            raise DecodeError(f"Failed to decode valid instructions at v2 RVA 0x{norm_v2:X}")
        raw_aligned = align_instruction_windows(win1, win2)
        aligned: list[tuple[DecodedInsn, DecodedInsn | None]] = []
        for i1, i2 in raw_aligned:
            if i2 is None or i1.length != i2.length:
                break
            aligned.append((i1, i2))
        if not aligned:
            raise SynthesisError(
                f"No aligned instruction prefix between v1 0x{norm_v1:X} and v2 0x{norm_v2:X}"
            )
    else:
        aligned = [(ins, None) for ins in win1]

    insn_masks = [_build_insn_mask(i1, i2) for i1, i2 in aligned]
    if not insn_masks[0] or insn_masks[0][0] is None:
        if (
            v2 is not None
            and aligned[0][1] is not None
            and aligned[0][0].raw[0] != aligned[0][1].raw[0]
        ):
            raise SynthesisError(
                f"Anchor byte at target RVA differs between v1 (0x{aligned[0][0].raw[0]:02X}) "
                f"and v2 (0x{aligned[0][1].raw[0]:02X}); choose an interior instruction anchor"
            )
        insn_masks[0][0] = aligned[0][0].raw[0]

    traces: list[InsnTrace] = []
    chosen_k: int | None = None
    first_unique_k: int | None = None
    raw_accum: list[int | None] = []

    for k in range(1, len(aligned) + 1):
        i1 = aligned[k - 1][0]
        raw_accum.extend(insn_masks[k - 1])
        trimmed = trim_trailing_wildcards(raw_accum)
        hits1 = scan_exec_sections(v1, trimmed)
        hits2 = scan_exec_sections(v2, trimmed) if v2 is not None else []

        traces.append(
            InsnTrace(
                rva=i1.rva,
                raw_hex=i1.raw.hex(" ").upper(),
                pattern_tokens=["??" if t is None else f"{t:02X}" for t in insn_masks[k - 1]],
                roles=[r.value for r in i1.roles],
                mnemonic_class=i1.mnemonic_class,
                cumulative_matches=len(hits1),
                rip_target_rva=(
                    i1.rip_target_rva if i1.rip_target_rva is not None else i1.rel_target_rva
                ),
            )
        )

        if hits1 == [norm_v1] and (v2 is None or hits2 == [norm_v2]):
            if first_unique_k is None:
                first_unique_k = k
            locked_now = sum(1 for t in trimmed if t is not None)
            if locked_now >= 4 and (locked_now / len(trimmed)) >= 0.20:
                chosen_k = k
                break

    if chosen_k is None and first_unique_k is not None:
        chosen_k = first_unique_k
        traces = traces[:chosen_k]
        raw_accum = [t for m in insn_masks[:chosen_k] for t in m]

    if chosen_k is not None:
        if capture_rip and _find_rip_capture(aligned, chosen_k) is None:
            lookahead_end = min(len(aligned), chosen_k + 2)
            for ext_idx in range(chosen_k, lookahead_end):
                ext_ins = aligned[ext_idx][0]
                if _has_rip_or_rel32(ext_ins):
                    for k_ext in range(chosen_k + 1, ext_idx + 2):
                        i_ext = aligned[k_ext - 1][0]
                        raw_accum.extend(insn_masks[k_ext - 1])
                        trimmed_ext = trim_trailing_wildcards(raw_accum)
                        h1_ext = scan_exec_sections(v1, trimmed_ext)
                        traces.append(
                            InsnTrace(
                                rva=i_ext.rva,
                                raw_hex=i_ext.raw.hex(" ").upper(),
                                pattern_tokens=[
                                    "??" if t is None else f"{t:02X}" for t in insn_masks[k_ext - 1]
                                ],
                                roles=[r.value for r in i_ext.roles],
                                mnemonic_class=i_ext.mnemonic_class,
                                cumulative_matches=len(h1_ext),
                                rip_target_rva=(
                                    i_ext.rip_target_rva
                                    if i_ext.rip_target_rva is not None
                                    else i_ext.rel_target_rva
                                ),
                            )
                        )
                    chosen_k = ext_idx + 1
                    break
        final_tokens = trim_trailing_wildcards(raw_accum)
    else:
        # Pass 2 Fallback: progressively un-wildcard STRUCT_DISP8 then IMM bytes left-to-right
        work_masks = [list(m) for m in insn_masks]
        solved = False

        for target_role in (ByteRole.STRUCT_DISP8, ByteRole.IMM):
            if solved:
                break
            for idx, (i1, i2) in enumerate(aligned):
                if solved:
                    break
                for b in range(i1.length):
                    if work_masks[idx][b] is not None:
                        continue
                    if i1.roles[b] != target_role:
                        continue
                    if i2 is not None and i1.raw[b] != i2.raw[b]:
                        continue
                    work_masks[idx][b] = i1.raw[b]
                    cand_flat = [t for m in work_masks for t in m]
                    cand_trim = trim_trailing_wildcards(cand_flat)
                    h1 = scan_exec_sections(v1, cand_trim)
                    h2 = scan_exec_sections(v2, cand_trim) if v2 is not None else []
                    if h1 == [norm_v1] and (v2 is None or h2 == [norm_v2]):
                        solved = True
                        break

        if not solved:
            raise SynthesisError(
                f"Could not synthesize a unique signature for '{name}' at 0x{norm_v1:X} within {max_bytes} bytes"
            )

        # Minimize prefix k for Pass 2 (respecting Gate 2 locked_count >= 4 when possible)
        chosen_k = len(aligned)
        first_p2_unique: int | None = None
        p2_accum: list[int | None] = []
        for k in range(1, len(aligned) + 1):
            p2_accum.extend(work_masks[k - 1])
            p2_trim = trim_trailing_wildcards(p2_accum)
            h1 = scan_exec_sections(v1, p2_trim)
            h2 = scan_exec_sections(v2, p2_trim) if v2 is not None else []
            if h1 == [norm_v1] and (v2 is None or h2 == [norm_v2]):
                if first_p2_unique is None:
                    first_p2_unique = k
                locked_p2 = sum(1 for t in p2_trim if t is not None)
                if locked_p2 >= 4 and (locked_p2 / len(p2_trim)) >= 0.20:
                    chosen_k = k
                    break
        else:
            if first_p2_unique is not None:
                chosen_k = first_p2_unique

        if capture_rip and _find_rip_capture(aligned, chosen_k) is None:
            lookahead_end = min(len(aligned), chosen_k + 2)
            for ext_idx in range(chosen_k, lookahead_end):
                if _has_rip_or_rel32(aligned[ext_idx][0]):
                    chosen_k = ext_idx + 1
                    break

        # Rebuild traces with updated work_masks up to chosen_k
        traces = []
        accum: list[int | None] = []
        for idx in range(chosen_k):
            i1 = aligned[idx][0]
            accum.extend(work_masks[idx])
            tr = trim_trailing_wildcards(accum)
            h1 = scan_exec_sections(v1, tr)
            traces.append(
                InsnTrace(
                    rva=i1.rva,
                    raw_hex=i1.raw.hex(" ").upper(),
                    pattern_tokens=["??" if t is None else f"{t:02X}" for t in work_masks[idx]],
                    roles=[r.value for r in i1.roles],
                    mnemonic_class=i1.mnemonic_class,
                    cumulative_matches=len(h1),
                    rip_target_rva=(
                        i1.rip_target_rva if i1.rip_target_rva is not None else i1.rel_target_rva
                    ),
                )
            )
        final_tokens = trim_trailing_wildcards(accum)

    rip_cap = _find_rip_capture(aligned, chosen_k) if capture_rip else None
    byte_length = max(len(final_tokens), rip_cap.next_ip_offset if rip_cap else 0)
    locked_count = sum(1 for t in final_tokens if t is not None)

    entry = SigEntry(
        name=name,
        pattern=format_pattern(final_tokens),
        rva_v1=norm_v1,
        rva_v2=norm_v2,
        byte_length=byte_length,
        locked_count=locked_count,
        survival_score=0.0,
        rip_capture=rip_cap,
        trace=traces,
        description=description,
    )
    report = evaluate_signature(entry, v1, v2)
    entry.survival_score = report.survival_score
    return entry, report


def synthesize_spec(
    spec_name: str,
    targets: Sequence[tuple[str, int, int | None, str]],
    v1: BinaryImage,
    v2: BinaryImage | None = None,
    *,
    max_bytes: int = 64,
    capture_rip: bool = True,
    description: str = "",
) -> tuple[SigSpec, SpecOracleResult]:
    entries: list[SigEntry] = []
    for t_name, rva1, rva2, desc in targets:
        entry, _ = synthesize_entry(
            t_name,
            v1,
            rva1,
            v2=v2,
            rva_v2=rva2,
            max_bytes=max_bytes,
            capture_rip=capture_rip,
            description=desc,
        )
        entries.append(entry)

    spec = SigSpec(
        name=spec_name,
        binary_format=v1.format,
        description=description,
        signatures=entries,
    )
    validate_spec(spec)
    oracle = verify_spec(spec, v1, v2)
    return spec, oracle
