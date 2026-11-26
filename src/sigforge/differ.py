from __future__ import annotations

from dataclasses import dataclass
from difflib import SequenceMatcher

from sigforge.errors import AnchorNotFoundError
from sigforge.models import BinaryImage, ByteRole, DecodedInsn
from sigforge.scanner_core import scan_exec_sections, trim_trailing_wildcards
from sigforge.x86_ild import decode_window


@dataclass(frozen=True)
class AnchorMatch:
    rva_v2: int
    confidence: float
    opcode_similarity: float
    xref_hits: int
    callee_hits: int


def _insn_skeleton(insn: DecodedInsn) -> tuple[str, bytes]:
    kept = bytes(
        b for b, role in zip(insn.raw, insn.roles) if role in (ByteRole.OPCODE, ByteRole.PREFIX)
    )
    return (insn.mnemonic_class, kept)


def _extract_ro_xref_slices(image: BinaryImage, win: list[DecodedInsn]) -> list[bytes]:
    slices: list[bytes] = []
    for ins in win:
        if ins.rip_target_rva is None:
            continue
        sec = image.section_at_rva(ins.rip_target_rva)
        if sec is None or not sec.is_readonly_data:
            continue
        avail = min(16, (sec.rva + len(sec.data)) - ins.rip_target_rva)
        if avail >= 4:
            blob = image.read_rva(ins.rip_target_rva, avail)
            if blob and len(blob) >= 4:
                slices.append(blob)
    return slices


def _extract_callee_skeletons(
    image: BinaryImage, win: list[DecodedInsn]
) -> list[list[tuple[str, bytes]]]:
    callees: list[list[tuple[str, bytes]]] = []
    for ins in win:
        if ins.rel_target_rva is None or ins.mnemonic_class != "call":
            continue
        sec = image.section_at_rva(ins.rel_target_rva)
        if sec is None or not sec.is_exec:
            continue
        cwin = decode_window(image, ins.rel_target_rva, max_bytes=32, max_insns=4)
        if cwin:
            callees.append([_insn_skeleton(c) for c in cwin])
    return callees


def _first_insn_opcode_mask(insn: DecodedInsn) -> list[int | None]:
    mask: list[int | None] = [
        b if role in (ByteRole.OPCODE, ByteRole.PREFIX) else None
        for b, role in zip(insn.raw, insn.roles)
    ]
    if not mask or all(b is None for b in mask):
        mask = [insn.raw[0]]
    return trim_trailing_wildcards(mask)


def locate_target_in_v2(
    v1: BinaryImage, rva_v1: int, v2: BinaryImage, *, min_confidence: float = 0.70
) -> AnchorMatch:
    norm_v1 = v1.normalize_rva(rva_v1)
    win1 = decode_window(v1, norm_v1, max_bytes=96, max_insns=12)
    if not win1:
        raise AnchorNotFoundError(f"Could not decode anchor window at v1 RVA 0x{norm_v1:X}")

    skel1 = [_insn_skeleton(ins) for ins in win1]
    ro_slices1 = _extract_ro_xref_slices(v1, win1)
    callees1 = _extract_callee_skeletons(v1, win1)

    mask0 = _first_insn_opcode_mask(win1[0])
    cand_set: set[int] = set(scan_exec_sections(v2, mask0))
    for fb in v2.func_bounds:
        cand_set.add(fb.start_rva)

    if not cand_set:
        raise AnchorNotFoundError("No candidate locations found in v2 executable sections")

    best: AnchorMatch | None = None
    for cand_rva in sorted(cand_set):
        win2 = decode_window(v2, cand_rva, max_bytes=96, max_insns=12)
        if not win2:
            continue
        skel2 = [_insn_skeleton(ins) for ins in win2]
        opcode_sim = SequenceMatcher(None, skel1, skel2, autojunk=False).ratio()

        ro_slices2 = _extract_ro_xref_slices(v2, win2)
        xref_hits = 0
        if ro_slices1 and ro_slices2:
            for s1 in ro_slices1:
                if any(
                    s1[: min(len(s1), len(s2))] == s2[: min(len(s1), len(s2))] for s2 in ro_slices2
                ):
                    xref_hits += 1
        xref_score = (xref_hits / len(ro_slices1)) if ro_slices1 else 0.0

        callees2 = _extract_callee_skeletons(v2, win2)
        callee_hits = 0
        if callees1 and callees2:
            for c1 in callees1:
                if any(
                    SequenceMatcher(None, c1, c2, autojunk=False).ratio() >= 0.75 for c2 in callees2
                ):
                    callee_hits += 1
        callee_score = (callee_hits / len(callees1)) if callees1 else 0.0

        if ro_slices1:
            conf = 0.50 * opcode_sim + 0.35 * xref_score + 0.15 * callee_score
        elif callees1:
            conf = 0.75 * opcode_sim + 0.25 * callee_score
        else:
            conf = opcode_sim

        match = AnchorMatch(
            rva_v2=cand_rva,
            confidence=round(conf, 4),
            opcode_similarity=round(opcode_sim, 4),
            xref_hits=xref_hits,
            callee_hits=callee_hits,
        )
        if best is None or match.confidence > best.confidence:
            best = match

    if best is None or best.confidence < min_confidence:
        best_conf = best.confidence if best is not None else 0.0
        raise AnchorNotFoundError(
            f"Unable to locate v1 RVA 0x{norm_v1:X} in v2 (best confidence={best_conf:.3f} < {min_confidence:.3f})"
        )
    return best


def align_instruction_windows(
    win1: list[DecodedInsn], win2: list[DecodedInsn]
) -> list[tuple[DecodedInsn, DecodedInsn | None]]:
    keys1 = [_insn_skeleton(ins) for ins in win1]
    keys2 = [_insn_skeleton(ins) for ins in win2]
    sm = SequenceMatcher(None, keys1, keys2, autojunk=False)
    aligned: list[tuple[DecodedInsn, DecodedInsn | None]] = []

    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == "equal":
            for off in range(i2 - i1):
                aligned.append((win1[i1 + off], win2[j1 + off]))
        elif tag == "replace":
            if (i2 - i1) == (j2 - j1):
                for off in range(i2 - i1):
                    aligned.append((win1[i1 + off], win2[j1 + off]))
            else:
                for i in range(i1, i2):
                    aligned.append((win1[i], None))
        elif tag == "delete":
            for i in range(i1, i2):
                aligned.append((win1[i], None))
        # "insert": extra v2 instructions skipped
    return aligned
