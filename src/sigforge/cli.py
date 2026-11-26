from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

from sigforge import __version__
from sigforge.binary_loader import parse_binary
from sigforge.codegen_cpp import generate_cpp_header
from sigforge.codegen_py import generate_python_scanner
from sigforge.codegen_rules import (
    generate_ida_patterns,
    generate_x64dbg_patterns,
    generate_yara_rules,
)
from sigforge.errors import SigForgeError, SpecValidationError
from sigforge.models import SigSpec
from sigforge.oracle import verify_spec
from sigforge.report_html import generate_html_report
from sigforge.synthesizer import synthesize_spec
from sigforge.x86_ild import decode_window


def _parse_int(text: str) -> int:
    try:
        return int(text, 0)
    except ValueError as exc:
        raise SpecValidationError(f"Invalid integer/address '{text}'") from exc


def _parse_target_arg(raw: str) -> tuple[str, int, int | None, str]:
    parts = raw.split(":")
    if len(parts) not in (2, 3):
        raise SpecValidationError(
            f"Invalid --target '{raw}'; expected name:rva_v1 or name:rva_v1:rva_v2"
        )
    name = parts[0].strip()
    rva1 = _parse_int(parts[1].strip())
    rva2 = _parse_int(parts[2].strip()) if len(parts) == 3 and parts[2].strip() else None
    return (name, rva1, rva2, "")


def _read_binary(path_str: str) -> bytes:
    path = Path(path_str)
    if not path.is_file():
        raise SigForgeError(f"Binary file not found: {path}")
    return path.read_bytes()


def _read_spec(path_str: str) -> SigSpec:
    path = Path(path_str)
    if not path.is_file():
        raise SigForgeError(f"Spec file not found: {path}")
    return SigSpec.from_json(path.read_text(encoding="utf-8"))


def _cmd_probe(args: argparse.Namespace) -> int:
    img = parse_binary(_read_binary(args.binary))
    info: dict[str, object] = {
        "format": img.format,
        "image_base": f"0x{img.image_base:X}",
        "entry_rva": f"0x{img.entry_rva:X}",
        "sections": [
            {
                "name": s.name,
                "rva": f"0x{s.rva:X}",
                "size": len(s.data),
                "exec": s.is_exec,
                "readonly": s.is_readonly_data,
            }
            for s in img.sections
        ],
        "func_bounds": [
            {
                "start_rva": f"0x{fb.start_rva:X}",
                "end_rva": f"0x{fb.end_rva:X}",
                "name": fb.name,
            }
            for fb in img.func_bounds
        ],
    }

    if args.rva is not None:
        norm_rva = img.normalize_rva(_parse_int(args.rva))
        win = decode_window(img, norm_rva, max_bytes=128, max_insns=args.max_insns)
        info["decoded_at"] = f"0x{norm_rva:X}"
        info["instructions"] = [
            {
                "rva": f"0x{ins.rva:X}",
                "bytes": ins.raw.hex(" ").upper(),
                "mnemonic_class": ins.mnemonic_class,
                "roles": [r.value for r in ins.roles],
                "rip_target": f"0x{ins.rip_target_rva:X}"
                if ins.rip_target_rva is not None
                else None,
                "rel_target": f"0x{ins.rel_target_rva:X}"
                if ins.rel_target_rva is not None
                else None,
            }
            for ins in win
        ]

    if args.json:
        print(json.dumps(info, indent=2))
        return 0

    print(f"Format: {img.format} | ImageBase: 0x{img.image_base:X} | Entry: 0x{img.entry_rva:X}")
    print("Sections:")
    for s in img.sections:
        flags = "EXEC" if s.is_exec else ("RODATA" if s.is_readonly_data else "DATA")
        print(f"  {s.name:<10} RVA=0x{s.rva:08X}  Len=0x{len(s.data):X}  [{flags}]")
    if img.func_bounds:
        print(f"Functions ({len(img.func_bounds)}):")
        for fb in img.func_bounds[:20]:
            label = f" ({fb.name})" if fb.name else ""
            print(f"  0x{fb.start_rva:08X} .. 0x{fb.end_rva:08X}{label}")
    if "instructions" in info:
        print(f"\nDisassembly at {info['decoded_at']}:")
        for ins_row in info["instructions"]:  # type: ignore[attr-defined]
            roles_str = ",".join(ins_row["roles"])
            print(
                f"  {ins_row['rva']}  {ins_row['bytes']:<28}  "
                f"{ins_row['mnemonic_class']:<10}  [{roles_str}]"
            )
    return 0


def _cmd_synthesize(args: argparse.Namespace) -> int:
    v1 = parse_binary(_read_binary(args.binary))
    v2 = parse_binary(_read_binary(args.v2)) if args.v2 else None

    targets: list[tuple[str, int, int | None, str]] = []
    if args.target:
        for raw_t in args.target:
            targets.append(_parse_target_arg(raw_t))
    if args.rva:
        r1 = _parse_int(args.rva)
        r2 = _parse_int(args.rva2) if args.rva2 else None
        targets.append((args.name, r1, r2, ""))

    if not targets:
        raise SpecValidationError("Specify at least one --target name:rva[:rva2] or --rva 0x...")

    spec_name = args.spec_name or Path(args.binary).stem.replace("-", "_").replace(".", "_")
    if not spec_name or not (spec_name[0].isalpha() or spec_name[0] == "_"):
        spec_name = f"sig_{spec_name}"

    spec, oracle = synthesize_spec(
        spec_name,
        targets,
        v1,
        v2=v2,
        max_bytes=args.max_bytes,
        capture_rip=not args.no_rip_capture,
    )

    spec_json = spec.to_json()
    if args.output:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(spec_json, encoding="utf-8")
        print(
            f"Wrote {out_path} ({len(spec.signatures)} sigs, "
            f"mean_survival={oracle.mean_survival_score:.2f}/100, passed={oracle.passed})"
        )
    else:
        sys.stdout.write(spec_json)

    if args.report:
        rep_path = Path(args.report)
        rep_path.parent.mkdir(parents=True, exist_ok=True)
        rep_path.write_text(generate_html_report(spec, v1, v2, oracle), encoding="utf-8")

    if not oracle.passed:
        for fail in oracle.failures:
            print(f"ORACLE FAIL: {fail}", file=sys.stderr)
        return 1
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    spec = _read_spec(args.spec)
    v1 = parse_binary(_read_binary(args.binary))
    v2 = parse_binary(_read_binary(args.v2)) if args.v2 else None

    oracle = verify_spec(spec, v1, v2, trials=args.trials)

    if args.report:
        rep_path = Path(args.report)
        rep_path.parent.mkdir(parents=True, exist_ok=True)
        rep_path.write_text(generate_html_report(spec, v1, v2, oracle), encoding="utf-8")

    if args.json:
        print(json.dumps(oracle.to_dict(), indent=2))
    else:
        status = "PASS" if oracle.passed else "FAIL"
        print(f"Oracle Result: {status} | Mean Survival: {oracle.mean_survival_score:.2f}/100")
        for name, rep in oracle.reports.items():
            print(
                f"  {name}: G1={'OK' if rep.gate1_unique else 'FAIL'} "
                f"G2={'OK' if rep.gate2_antifragile else 'FAIL'} "
                f"G3={'OK' if rep.gate3_survival else 'FAIL'} "
                f"score={rep.survival_score:.2f} (naive={rep.naive_raw_score:.2f})"
            )
            for f in rep.failures:
                print(f"    - {f}", file=sys.stderr)

    return 0 if oracle.passed else 1


def _cmd_compile(args: argparse.Namespace) -> int:
    spec = _read_spec(args.spec)
    if args.lang == "cpp":
        out = generate_cpp_header(spec)
    elif args.lang == "python":
        out = generate_python_scanner(spec)
    elif args.lang == "yara":
        out = generate_yara_rules(spec)
    elif args.lang == "ida":
        out = generate_ida_patterns(spec)
    elif args.lang == "x64dbg":
        out = generate_x64dbg_patterns(spec)
    else:
        raise SpecValidationError(f"Unsupported language '{args.lang}'")

    if args.output:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(out, encoding="utf-8")
        print(f"Wrote {args.lang} output to {out_path}")
    else:
        sys.stdout.write(out)
    return 0


def _cmd_inspect(args: argparse.Namespace) -> int:
    spec = _read_spec(args.spec)
    v1 = parse_binary(_read_binary(args.binary))
    v2 = parse_binary(_read_binary(args.v2)) if args.v2 else None
    oracle = verify_spec(spec, v1, v2, trials=args.trials)
    html_text = generate_html_report(spec, v1, v2, oracle)
    if args.output:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(html_text, encoding="utf-8")
        print(f"Wrote HTML report to {out_path}")
    else:
        sys.stdout.write(html_text)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sigforge",
        description="Compiler-resilient x86-64 AOB signature synthesizer & C++20 scanner compiler",
    )
    parser.add_argument("--version", action="version", version=f"sigforge {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_probe = sub.add_parser(
        "probe", help="Inspect PE32+/ELF64 sections, functions, and instructions"
    )
    p_probe.add_argument("binary", help="Path to PE32+ or ELF64 binary")
    p_probe.add_argument("--rva", default=None, help="Target RVA or VA to decode")
    p_probe.add_argument("--max-insns", type=int, default=24)
    p_probe.add_argument("--json", action="store_true")
    p_probe.set_defaults(func=_cmd_probe)

    p_syn = sub.add_parser("synthesize", help="Synthesize compiler-resilient AOB signatures")
    p_syn.add_argument("binary", help="Path to baseline v1 binary")
    p_syn.add_argument("--target", action="append", help="Target spec name:rva_v1[:rva_v2]")
    p_syn.add_argument("--rva", default=None, help="Shorthand single target RVA/VA in v1")
    p_syn.add_argument("--rva2", default=None, help="Optional shorthand RVA/VA in v2")
    p_syn.add_argument("--name", default="sig_main", help="Signature name for --rva shorthand")
    p_syn.add_argument(
        "--v2", default=None, help="Optional patched v2 binary for differential anchoring"
    )
    p_syn.add_argument("--spec-name", default=None, help="Spec identifier name")
    p_syn.add_argument("-o", "--output", default=None, help="Output SigSpec JSON path")
    p_syn.add_argument("--report", default=None, help="Optional HTML report output path")
    p_syn.add_argument("--max-bytes", type=int, default=64)
    p_syn.add_argument("--no-rip-capture", action="store_true")
    p_syn.set_defaults(func=_cmd_synthesize)

    p_ver = sub.add_parser("verify", help="Run 3-Gate Oracle against a SigSpec JSON")
    p_ver.add_argument("spec", help="Path to SigSpec JSON")
    p_ver.add_argument("binary", help="Path to v1 binary")
    p_ver.add_argument("--v2", default=None, help="Optional v2 binary")
    p_ver.add_argument("--trials", type=int, default=100)
    p_ver.add_argument("--json", action="store_true")
    p_ver.add_argument("--report", default=None)
    p_ver.set_defaults(func=_cmd_verify)

    p_comp = sub.add_parser("compile", help="Compile SigSpec JSON to C++20/Python/YARA/IDA/x64dbg")
    p_comp.add_argument("spec", help="Path to SigSpec JSON")
    p_comp.add_argument(
        "--lang",
        required=True,
        choices=["cpp", "python", "yara", "ida", "x64dbg"],
    )
    p_comp.add_argument("-o", "--output", default=None)
    p_comp.set_defaults(func=_cmd_compile)

    p_ins = sub.add_parser("inspect", help="Generate dark-mode HTML5 volatility & match report")
    p_ins.add_argument("spec", help="Path to SigSpec JSON")
    p_ins.add_argument("binary", help="Path to v1 binary")
    p_ins.add_argument("--v2", default=None)
    p_ins.add_argument("--trials", type=int, default=100)
    p_ins.add_argument("-o", "--output", default=None)
    p_ins.set_defaults(func=_cmd_inspect)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except SigForgeError as exc:
        print(f"sigforge error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
