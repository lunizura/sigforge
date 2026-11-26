from __future__ import annotations

from sigforge.models import SigSpec, validate_spec
from sigforge.scanner_core import format_pattern


def generate_yara_rules(spec: SigSpec) -> str:
    validate_spec(spec)
    blocks: list[str] = []
    for entry in spec.signatures:
        yara_pat = format_pattern(entry.tokens(), wildcard="??")
        desc = entry.description.replace("\\", "\\\\").replace('"', '\\"')
        blocks.append(
            "\n".join(
                [
                    f"rule sigforge_{spec.name}_{entry.name} {{",
                    "    meta:",
                    f'        description = "{desc}"',
                    f'        rva_v1 = "0x{entry.rva_v1:X}"',
                    f'        survival_score = "{entry.survival_score:.2f}"',
                    "    strings:",
                    f"        $sig = {{ {yara_pat} }}",
                    "    condition:",
                    "        $sig",
                    "}",
                ]
            )
        )
    return "\n\n".join(blocks) + "\n"


def generate_ida_patterns(spec: SigSpec) -> str:
    validate_spec(spec)
    lines: list[str] = []
    for entry in spec.signatures:
        ida_pat = format_pattern(entry.tokens(), wildcard="?")
        lines.append(f"{entry.name}: {ida_pat}")
    return "\n".join(lines) + "\n"


def generate_x64dbg_patterns(spec: SigSpec) -> str:
    validate_spec(spec)
    lines: list[str] = []
    for entry in spec.signatures:
        x64_pat = format_pattern(entry.tokens(), wildcard="??")
        lines.append(f"{entry.name}: {x64_pat}")
    return "\n".join(lines) + "\n"
