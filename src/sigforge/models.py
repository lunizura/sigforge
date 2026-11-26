from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Literal

from sigforge.errors import RvaOutOfBoundsError, SpecValidationError

_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_HEX_BYTE_RE = re.compile(r"^[0-9A-Fa-f]{2}$")


class ByteRole(str, Enum):
    PREFIX = "prefix"  # Legacy prefixes (66/67/F0/F2/F3) and REX.W (0x48)
    REX_EXT = "rex_ext"  # REX with R/X/B extension bits (register allocation sensitive)
    OPCODE = "opcode"  # 1/2/3-byte primary opcode or VEX escape
    MODRM_SIB = "modrm_sib"  # ModR/M and SIB addressing bytes
    STRUCT_DISP8 = "struct_disp8"  # Non-stack [reg + disp8] struct field offset
    STACK_DISP8 = "stack_disp8"  # [rsp/rbp + disp8] stack frame offset
    DISP32 = "disp32"  # 32-bit displacement or moffs64
    RIP_DISP32 = "rip_disp32"  # [rip + disp32] global / .rdata displacement
    REL = "rel"  # rel8 / rel32 branch or call displacement
    IMM = "imm"  # imm8 / imm16 / imm32 / imm64 immediate


ROLE_VOLATILITY: dict[ByteRole, float] = {
    ByteRole.OPCODE: 0.00,
    ByteRole.PREFIX: 0.05,
    ByteRole.MODRM_SIB: 0.15,
    ByteRole.REX_EXT: 0.25,
    ByteRole.STRUCT_DISP8: 0.45,
    ByteRole.IMM: 0.70,
    ByteRole.STACK_DISP8: 0.80,
    ByteRole.DISP32: 0.88,
    ByteRole.RIP_DISP32: 0.95,
    ByteRole.REL: 0.98,
}

DEFAULT_WILDCARD_ROLES: frozenset[ByteRole] = frozenset(
    {
        ByteRole.STRUCT_DISP8,
        ByteRole.STACK_DISP8,
        ByteRole.DISP32,
        ByteRole.RIP_DISP32,
        ByteRole.REL,
        ByteRole.IMM,
    }
)


@dataclass(frozen=True)
class SectionInfo:
    name: str
    rva: int
    size: int
    raw_offset: int
    data: bytes
    is_exec: bool
    is_readonly_data: bool

    def contains_rva(self, rva: int) -> bool:
        return self.rva <= rva < self.rva + len(self.data)


@dataclass(frozen=True)
class FuncBounds:
    start_rva: int
    end_rva: int
    name: str | None = None


@dataclass
class BinaryImage:
    format: Literal["pe64", "elf64"]
    image_base: int
    entry_rva: int
    sections: list[SectionInfo]
    func_bounds: list[FuncBounds] = field(default_factory=list)

    def exec_sections(self) -> list[SectionInfo]:
        return [s for s in self.sections if s.is_exec and len(s.data) > 0]

    def readonly_sections(self) -> list[SectionInfo]:
        return [s for s in self.sections if s.is_readonly_data and len(s.data) > 0]

    def section_at_rva(self, rva: int) -> SectionInfo | None:
        for sec in self.sections:
            if sec.contains_rva(rva):
                return sec
        return None

    def normalize_rva(self, addr: int) -> int:
        if addr < 0:
            raise RvaOutOfBoundsError(f"Negative address: {addr}")
        sec = self.section_at_rva(addr)
        if sec is not None and sec.is_exec:
            return addr
        if self.image_base > 0 and addr >= self.image_base:
            cand = addr - self.image_base
            sec2 = self.section_at_rva(cand)
            if sec2 is not None and sec2.is_exec:
                return cand
        raise RvaOutOfBoundsError(
            f"Address 0x{addr:X} does not map into any executable section (image_base=0x{self.image_base:X})"
        )

    def read_rva(self, rva: int, length: int) -> bytes | None:
        if length < 0:
            return None
        sec = self.section_at_rva(rva)
        if sec is None:
            return None
        off = rva - sec.rva
        if off + length > len(sec.data):
            return None
        return sec.data[off : off + length]

    def func_containing(self, rva: int) -> FuncBounds | None:
        for fb in self.func_bounds:
            if fb.start_rva <= rva < fb.end_rva:
                return fb
        return None


@dataclass(frozen=True)
class DecodedInsn:
    rva: int
    raw: bytes
    roles: tuple[ByteRole, ...]
    mnemonic_class: str
    is_valid: bool
    is_ret: bool = False
    is_uncond_jmp: bool = False
    is_padding: bool = False
    rip_disp_offset: int | None = None
    rip_target_rva: int | None = None
    rel_disp_offset: int | None = None
    rel_target_rva: int | None = None

    @property
    def length(self) -> int:
        return len(self.raw)


@dataclass
class RipCapture:
    insn_index: int
    disp_offset: int
    next_ip_offset: int
    kind: Literal["rip_data", "rel32_call_jmp"]

    def to_dict(self) -> dict[str, Any]:
        return {
            "insn_index": self.insn_index,
            "disp_offset": self.disp_offset,
            "next_ip_offset": self.next_ip_offset,
            "kind": self.kind,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> RipCapture:
        return cls(
            insn_index=int(d["insn_index"]),
            disp_offset=int(d["disp_offset"]),
            next_ip_offset=int(d["next_ip_offset"]),
            kind=d["kind"],
        )


@dataclass
class InsnTrace:
    rva: int
    raw_hex: str
    pattern_tokens: list[str]
    roles: list[str]
    mnemonic_class: str
    cumulative_matches: int
    rip_target_rva: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "rva": self.rva,
            "raw_hex": self.raw_hex,
            "pattern_tokens": list(self.pattern_tokens),
            "roles": list(self.roles),
            "mnemonic_class": self.mnemonic_class,
            "cumulative_matches": self.cumulative_matches,
            "rip_target_rva": self.rip_target_rva,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> InsnTrace:
        return cls(
            rva=int(d["rva"]),
            raw_hex=str(d["raw_hex"]),
            pattern_tokens=[str(x) for x in d["pattern_tokens"]],
            roles=[str(x) for x in d["roles"]],
            mnemonic_class=str(d["mnemonic_class"]),
            cumulative_matches=int(d["cumulative_matches"]),
            rip_target_rva=int(d["rip_target_rva"])
            if d.get("rip_target_rva") is not None
            else None,
        )


@dataclass
class SigEntry:
    name: str
    pattern: str
    rva_v1: int
    rva_v2: int | None = None
    byte_length: int = 0
    locked_count: int = 0
    survival_score: float = 0.0
    rip_capture: RipCapture | None = None
    trace: list[InsnTrace] = field(default_factory=list)
    description: str = ""

    def tokens(self) -> list[int | None]:
        parts = self.pattern.strip().split()
        if not parts:
            raise SpecValidationError(f"Empty pattern in signature '{self.name}'")
        out: list[int | None] = []
        for p in parts:
            if p in ("?", "??"):
                out.append(None)
            elif _HEX_BYTE_RE.match(p):
                out.append(int(p, 16))
            else:
                raise SpecValidationError(f"Invalid pattern token '{p}' in '{self.name}'")
        return out

    def to_dict(self) -> dict[str, Any]:
        toks = self.tokens()
        return {
            "name": self.name,
            "pattern": self.pattern,
            "rva_v1": self.rva_v1,
            "rva_v2": self.rva_v2,
            "byte_length": self.byte_length or len(toks),
            "locked_count": self.locked_count or sum(1 for t in toks if t is not None),
            "survival_score": round(self.survival_score, 2),
            "rip_capture": self.rip_capture.to_dict() if self.rip_capture else None,
            "trace": [t.to_dict() for t in self.trace],
            "description": self.description,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> SigEntry:
        rc = d.get("rip_capture")
        return cls(
            name=str(d["name"]),
            pattern=str(d["pattern"]),
            rva_v1=int(d["rva_v1"]),
            rva_v2=int(d["rva_v2"]) if d.get("rva_v2") is not None else None,
            byte_length=int(d.get("byte_length", 0)),
            locked_count=int(d.get("locked_count", 0)),
            survival_score=float(d.get("survival_score", 0.0)),
            rip_capture=RipCapture.from_dict(rc) if isinstance(rc, dict) else None,
            trace=[InsnTrace.from_dict(x) for x in d.get("trace", [])],
            description=str(d.get("description", "")),
        )


@dataclass
class SigSpec:
    name: str
    binary_format: Literal["pe64", "elf64"] = "pe64"
    description: str = ""
    signatures: list[SigEntry] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "binary_format": self.binary_format,
            "description": self.description,
            "signatures": [s.to_dict() for s in self.signatures],
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> SigSpec:
        if not isinstance(d, dict):
            raise SpecValidationError("Spec root must be a JSON object")
        spec = cls(
            name=str(d.get("name", "")),
            binary_format=d.get("binary_format", "pe64"),
            description=str(d.get("description", "")),
            signatures=[SigEntry.from_dict(x) for x in d.get("signatures", [])],
        )
        validate_spec(spec)
        return spec

    def to_json(self) -> str:
        validate_spec(self)
        return json.dumps(self.to_dict(), indent=2) + "\n"

    @classmethod
    def from_json(cls, text: str) -> SigSpec:
        try:
            raw = json.loads(text)
        except json.JSONDecodeError as exc:
            raise SpecValidationError(f"Invalid JSON in SigSpec: {exc}") from exc
        return cls.from_dict(raw)


def validate_spec(spec: SigSpec) -> None:
    if not _IDENT_RE.match(spec.name):
        raise SpecValidationError(f"Invalid spec identifier '{spec.name}'")
    if spec.binary_format not in ("pe64", "elf64"):
        raise SpecValidationError(f"Unsupported binary_format '{spec.binary_format}'")
    if not spec.signatures:
        raise SpecValidationError("SigSpec must contain at least one signature")
    seen: set[str] = set()
    for sig in spec.signatures:
        if not _IDENT_RE.match(sig.name):
            raise SpecValidationError(f"Invalid signature identifier '{sig.name}'")
        if sig.name in seen:
            raise SpecValidationError(f"Duplicate signature name '{sig.name}'")
        seen.add(sig.name)
        toks = sig.tokens()
        if toks[0] is None:
            raise SpecValidationError(
                f"Signature '{sig.name}' cannot start with a wildcard (anchor byte required)"
            )
        if sig.rip_capture is not None:
            rc = sig.rip_capture
            if rc.disp_offset < 0 or rc.disp_offset + 4 > max(len(toks), sig.byte_length):
                raise SpecValidationError(f"Invalid rip_capture disp_offset in '{sig.name}'")
            if rc.next_ip_offset < rc.disp_offset + 4:
                raise SpecValidationError(f"Invalid rip_capture next_ip_offset in '{sig.name}'")
            if rc.kind not in ("rip_data", "rel32_call_jmp"):
                raise SpecValidationError(f"Invalid rip_capture kind '{rc.kind}'")
