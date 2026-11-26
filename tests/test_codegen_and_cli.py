from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from sigforge.binary_loader import parse_binary
from sigforge.cli import main as cli_main
from sigforge.codegen_cpp import generate_cpp_header
from sigforge.codegen_py import generate_python_scanner
from sigforge.codegen_rules import (
    generate_ida_patterns,
    generate_x64dbg_patterns,
    generate_yara_rules,
)
from sigforge.models import SigEntry, SigSpec
from sigforge.report_html import generate_html_report
from sigforge.synthetic_bins import make_demo_binary_pair
from sigforge.synthesizer import synthesize_spec

_PROBE_CPP = r"""
#include <bit>
#include <cstdint>
#include <span>
#include <type_traits>

constexpr bool probe_fn(std::span<const std::uint8_t> s) noexcept {
    if (!std::is_constant_evaluated()) {
        return std::countr_zero(1u) == 0 && s.empty();
    }
    return s.empty();
}
static_assert(probe_fn(std::span<const std::uint8_t>{}));

int main() { return 0; }
"""


def _run_msvc_bat(
    vcvars: str, cl_args: str, work_dir: Path, bat_name: str
) -> subprocess.CompletedProcess[str]:
    bat_path = work_dir / bat_name
    bat_path.write_text(
        f'@echo off\r\ncall "{vcvars}" >nul 2>&1 || exit /b 1\r\ncl {cl_args}\r\n',
        encoding="utf-8",
    )
    return subprocess.run([str(bat_path)], cwd=str(work_dir), capture_output=True, text=True)


def _find_cpp20_compiler(tmp_path: Path) -> tuple[str, str | None]:
    probe_src = tmp_path / "probe_cpp20.cpp"
    probe_src.write_text(_PROBE_CPP, encoding="utf-8")

    for compiler in ("g++", "clang++"):
        exe = shutil.which(compiler)
        if not exe:
            continue
        out_bin = tmp_path / f"probe_{compiler}.exe"
        res = subprocess.run(
            [exe, "-std=c++20", "-Wall", "-Wextra", "-Werror", str(probe_src), "-o", str(out_bin)],
            capture_output=True,
            text=True,
        )
        if res.returncode == 0:
            return (compiler, exe)

    if os.name == "nt":
        vs_roots = [
            Path(r"C:\Program Files\Microsoft Visual Studio"),
            Path(r"C:\Program Files (x86)\Microsoft Visual Studio"),
        ]
        candidates: list[Path] = []
        for root in vs_roots:
            for year in ("2022", "2019"):
                for edition in ("Enterprise", "Professional", "Community", "BuildTools"):
                    vc = root / year / edition / "VC" / "Auxiliary" / "Build" / "vcvars64.bat"
                    if vc.is_file():
                        candidates.append(vc)
        for idx, vc in enumerate(candidates):
            out_bin = tmp_path / "probe_msvc.exe"
            res = _run_msvc_bat(
                str(vc),
                f'/nologo /std:c++latest /EHsc /W4 /WX "{probe_src}" /Fe:"{out_bin}"',
                tmp_path,
                f"probe_msvc_{idx}.bat",
            )
            if res.returncode == 0 and out_bin.is_file():
                return ("msvc", str(vc))

    pytest.skip("No C++20 compiler with <span> and <bit> found")


def _compile_and_run_cpp(
    kind: str,
    tool_path: str,
    src_path: Path,
    out_exe: Path,
    work_dir: Path,
    *,
    avx2: bool,
) -> None:
    if kind in ("g++", "clang++"):
        cmd = [tool_path, "-std=c++20", "-O2", "-Wall", "-Wextra", "-Werror"]
        if avx2:
            cmd.append("-mavx2")
        cmd.extend([str(src_path), "-o", str(out_exe)])
        res = subprocess.run(cmd, cwd=str(work_dir), capture_output=True, text=True)
        assert res.returncode == 0, f"{kind} compile failed:\n{res.stdout}\n{res.stderr}"
    else:
        arch = " /arch:AVX2" if avx2 else ""
        tag = "avx2" if avx2 else "sse2"
        res = _run_msvc_bat(
            tool_path,
            f'/nologo /std:c++latest /O2 /EHsc /W4 /WX{arch} "{src_path}" /Fe:"{out_exe}"',
            work_dir,
            f"compile_{tag}.bat",
        )
        assert res.returncode == 0, f"msvc compile failed:\n{res.stdout}\n{res.stderr}"

    run_res = subprocess.run([str(out_exe)], cwd=str(work_dir), capture_output=True, text=True)
    assert run_res.returncode == 0, (
        f"C++ test binary exited {run_res.returncode}:\n{run_res.stdout}\n{run_res.stderr}"
    )


def _c_array_literal(data: bytes) -> str:
    return ", ".join(f"0x{b:02X}u" for b in data)


def test_live_cpp20_sse2_avx2_and_constexpr(tmp_path: Path) -> None:
    kind, tool_path = _find_cpp20_compiler(tmp_path)
    assert tool_path is not None

    pair = make_demo_binary_pair()
    v1 = parse_binary(pair["pe_v1"])
    v2 = parse_binary(pair["pe_v2"])

    rva1_p = pair["targets_v1"]["resolve_player_db"]
    rva2_p = pair["targets_v2"]["resolve_player_db"]
    rva1_c = pair["targets_v1"]["calc_ca_pa_rating"]
    rva2_c = pair["targets_v2"]["calc_ca_pa_rating"]

    spec, oracle = synthesize_spec(
        "demo_cpp",
        [
            ("resolve_player_db", rva1_p, None, "Player DB"),
            ("calc_ca_pa_rating", rva1_c, None, "CA/PA"),
        ],
        v1,
        v2=v2,
    )
    assert oracle.passed

    # Also add an overlap test signature and negative-disp RIP capture to verify C++20 edge cases
    overlap_spec = SigSpec(
        name="demo_cpp",
        binary_format="pe64",
        signatures=spec.signatures
        + [
            SigEntry(name="overlap_pat", pattern="48 ?? 48", rva_v1=0x1000),
            SigEntry(
                name="neg_rip_pat",
                pattern="48 8B 05",
                rva_v1=0x1000,
                byte_length=7,
                rip_capture=spec.signatures[0].rip_capture.__class__(
                    insn_index=0, disp_offset=3, next_ip_offset=7, kind="rip_data"
                ),
            ),
        ],
    )

    hpp_path = tmp_path / "demo_sigs.hpp"
    hpp_path.write_text(generate_cpp_header(overlap_spec), encoding="utf-8")

    # Emit a second generated header to prove multi-header ODR safety in a single TU
    second_spec = SigSpec(
        name="aux_sigs",
        binary_format="pe64",
        signatures=[SigEntry(name="aux_ret", pattern="48 83 C4 28 C3", rva_v1=0x1000)],
    )
    (tmp_path / "aux_sigs.hpp").write_text(generate_cpp_header(second_spec), encoding="utf-8")

    sec1 = v1.exec_sections()[0]
    sec2 = v2.exec_sections()[0]
    expected_off1_p = rva1_p - sec1.rva
    expected_off2_p = rva2_p - sec2.rva
    expected_off1_c = rva1_c - sec1.rva
    expected_off2_c = rva2_c - sec2.rva

    raw_toks_p = [b if b is not None else 0xAA for b in spec.signatures[0].tokens()]
    last_idx_p = len(raw_toks_p) - 1
    req_p = max(len(raw_toks_p), spec.signatures[0].byte_length)
    pat_p_bytes = raw_toks_p + ([0xAA] * (req_p - len(raw_toks_p)))
    trunc_p_bytes = pat_p_bytes[: req_p - 1]
    exact_31 = ([0xCC] * (31 - req_p)) + pat_p_bytes if req_p <= 31 else pat_p_bytes[:31]
    exact_32 = ([0xCC] * (32 - req_p)) + pat_p_bytes if req_p <= 32 else pat_p_bytes
    exact_33 = ([0xCC] * (33 - req_p)) + pat_p_bytes if req_p <= 33 else pat_p_bytes
    # Exact AVX2 vector-loop boundaries (_sf_vec_span = max(req_p, last_idx_p + 32))
    avx_vec_span = max(req_p, last_idx_p + 32)
    avx_m1_pad = avx_vec_span - 1 - req_p
    avx_ex_pad = avx_vec_span - req_p
    avx_p1_pad = avx_vec_span + 1 - req_p
    avx_m1 = ([0xCC] * avx_m1_pad) + pat_p_bytes
    avx_ex = ([0xCC] * avx_ex_pad) + pat_p_bytes
    avx_p1 = ([0xCC] * avx_p1_pad) + pat_p_bytes

    test_cpp = f"""
#include "demo_sigs.hpp"
#include "aux_sigs.hpp"
#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

inline constexpr std::array<std::uint8_t, {len(pat_p_bytes)}> kConstTarget{{
    {_c_array_literal(bytes(pat_p_bytes))}
}};
static_assert(sigforge_gen::find_resolve_player_db(kConstTarget) == std::optional<std::size_t>{{0u}});

inline constexpr std::array<std::uint8_t, {len(trunc_p_bytes)}> kConstTruncTarget{{
    {_c_array_literal(bytes(trunc_p_bytes))}
}};
static_assert(!sigforge_gen::find_resolve_player_db(kConstTruncTarget).has_value());

inline constexpr std::array<std::uint8_t, 5> kConstOverlap{{0x48u, 0x90u, 0x48u, 0x90u, 0x48u}};
static_assert(sigforge_gen::find_overlap_pat(kConstOverlap) == std::optional<std::size_t>{{0u}});

int main() {{
    static const std::array<std::uint8_t, {len(sec1.data)}> text_v1{{
        {_c_array_literal(sec1.data)}
    }};
    static const std::array<std::uint8_t, {len(sec2.data)}> text_v2{{
        {_c_array_literal(sec2.data)}
    }};

    // 1. Exact v1 and v2 matches (uint8_t span) + second header symbol
    auto h1p = sigforge_gen::find_resolve_player_db(text_v1);
    auto h2p = sigforge_gen::find_resolve_player_db(text_v2);
    assert(h1p.has_value() && *h1p == {expected_off1_p}u);
    assert(h2p.has_value() && *h2p == {expected_off2_p}u);
    assert(sigforge_gen::find_aux_ret(text_v1).has_value());

    auto h1c = sigforge_gen::find_calc_ca_pa_rating(text_v1);
    auto h2c = sigforge_gen::find_calc_ca_pa_rating(text_v2);
    assert(h1c.has_value() && *h1c == {expected_off1_c}u);
    assert(h2c.has_value() && *h2c == {expected_off2_c}u);

    // 2. std::byte span overload
    auto byte_span_v1 = std::as_bytes(std::span<const std::uint8_t>{{text_v1}});
    assert(sigforge_gen::find_resolve_player_db(byte_span_v1) == std::optional<std::size_t>{{{expected_off1_p}u}});

    // 3. RIP target resolution in both v1 and v2
    auto rip1 = sigforge_gen::resolve_resolve_player_db_rip_target(text_v1, 0x{sec1.rva:X}ULL);
    auto rip2 = sigforge_gen::resolve_resolve_player_db_rip_target(text_v2, 0x{sec2.rva:X}ULL);
    assert(rip1.has_value() && *rip1 == 0x{pair["rdata_v1"]["g_PlayerDbPtr"]:X}ULL);
    assert(rip2.has_value() && *rip2 == 0x{pair["rdata_v2"]["g_PlayerDbPtr"]:X}ULL);

    auto rip1c = sigforge_gen::resolve_calc_ca_pa_rating_rip_target(text_v1, 0x{sec1.rva:X}ULL);
    auto rip2c = sigforge_gen::resolve_calc_ca_pa_rating_rip_target(text_v2, 0x{sec2.rva:X}ULL);
    assert(rip1c.has_value() && *rip1c == 0x{pair["rdata_v1"]["fm26_table_str"]:X}ULL);
    assert(rip2c.has_value() && *rip2c == 0x{pair["rdata_v2"]["fm26_table_str"]:X}ULL);

    // 4. Overlap hits via find_all
    const std::array<std::uint8_t, 5> ov_buf{{0x48u, 0x90u, 0x48u, 0x90u, 0x48u}};
    auto ov_hits = sigforge_gen::find_all_overlap_pat(ov_buf);
    assert(ov_hits.size() == 2u && ov_hits[0] == 0u && ov_hits[1] == 2u);

    // 5. Boundary buffer lengths: 0, 1, req_p - 1 (with concrete prefix!), 31, 32, 33
    std::span<const std::uint8_t> empty_span{{}};
    assert(!sigforge_gen::find_resolve_player_db(empty_span).has_value());
    const std::array<std::uint8_t, 1> one_b{{0x48u}};
    assert(!sigforge_gen::find_resolve_player_db(one_b).has_value());
    assert(!sigforge_gen::find_resolve_player_db(kConstTruncTarget).has_value());

    const std::array<std::uint8_t, {len(exact_31)}> b31{{{_c_array_literal(bytes(exact_31))}}};
    const std::array<std::uint8_t, {len(exact_32)}> b32{{{_c_array_literal(bytes(exact_32))}}};
    const std::array<std::uint8_t, {len(exact_33)}> b33{{{_c_array_literal(bytes(exact_33))}}};
    assert(sigforge_gen::find_resolve_player_db(b31) == std::optional<std::size_t>{{{len(exact_31) - req_p}u}});
    assert(sigforge_gen::find_resolve_player_db(b32) == std::optional<std::size_t>{{{len(exact_32) - req_p}u}});
    assert(sigforge_gen::find_resolve_player_db(b33) == std::optional<std::size_t>{{{len(exact_33) - req_p}u}});

    // 6. Exact AVX2 _sf_vec_span boundaries (_sf_vec_span - 1, _sf_vec_span, _sf_vec_span + 1)
    const std::array<std::uint8_t, {len(avx_m1)}> b_avx_m1{{{_c_array_literal(bytes(avx_m1))}}};
    const std::array<std::uint8_t, {len(avx_ex)}> b_avx_ex{{{_c_array_literal(bytes(avx_ex))}}};
    const std::array<std::uint8_t, {len(avx_p1)}> b_avx_p1{{{_c_array_literal(bytes(avx_p1))}}};
    assert(sigforge_gen::find_resolve_player_db(b_avx_m1) == std::optional<std::size_t>{{{avx_m1_pad}u}});
    assert(sigforge_gen::find_resolve_player_db(b_avx_ex) == std::optional<std::size_t>{{{avx_ex_pad}u}});
    assert(sigforge_gen::find_resolve_player_db(b_avx_p1) == std::optional<std::size_t>{{{avx_p1_pad}u}});

    // 7. Negative int32 RIP displacement resolution
    const std::array<std::uint8_t, 7> neg_buf{{0x48u, 0x8Bu, 0x05u, 0xF9u, 0xFFu, 0xFFu, 0xFFu}}; // disp = -7 -> target = base + 0 + 7 - 7 = base
    assert(sigforge_gen::resolve_neg_rip_pat_rip_target(neg_buf, 0x1000ULL) == std::optional<std::uint64_t>{{0x1000ULL}});

    return 0;
}}
"""
    cpp_src = tmp_path / "test_runner.cpp"
    cpp_src.write_text(test_cpp, encoding="utf-8")

    # Compile & run default (SSE2/scalar) and AVX2
    _compile_and_run_cpp(kind, tool_path, cpp_src, tmp_path / "test_sse2.exe", tmp_path, avx2=False)
    _compile_and_run_cpp(kind, tool_path, cpp_src, tmp_path / "test_avx2.exe", tmp_path, avx2=True)


def test_python_yara_ida_x64dbg_and_html_xss() -> None:
    pair = make_demo_binary_pair()
    v1 = parse_binary(pair["pe_v1"])
    v2 = parse_binary(pair["pe_v2"])

    rva1_p = pair["targets_v1"]["resolve_player_db"]
    rva2_p = pair["targets_v2"]["resolve_player_db"]

    spec, oracle = synthesize_spec(
        "xss_spec",
        [("resolve_player_db", rva1_p, None, '<script>alert("xss")</script>')],
        v1,
        v2=v2,
        description="<b>Unsafe</b> & <script>alert(1)</script>",
    )
    assert oracle.passed

    # Generated Python scanner execution
    py_code = generate_python_scanner(spec)
    ns: dict[str, object] = {}
    exec(py_code, ns)  # noqa: S102
    sec1 = v1.exec_sections()[0]
    sec2 = v2.exec_sections()[0]
    scan_first = ns["scan_first_resolve_player_db"]
    resolve_rip = ns["resolve_resolve_player_db_rip_target"]
    assert callable(scan_first) and callable(resolve_rip)
    assert scan_first(sec1.data) == rva1_p - sec1.rva
    assert scan_first(sec2.data) == rva2_p - sec2.rva
    assert resolve_rip(sec1.data, sec1.rva) == pair["rdata_v1"]["g_PlayerDbPtr"]
    assert resolve_rip(sec2.data, sec2.rva) == pair["rdata_v2"]["g_PlayerDbPtr"]
    # Truncated tail (18 concrete tokens present, missing 4-byte RIP disp32) must not match
    trunc_tail = sec1.data[rva1_p - sec1.rva : rva1_p - sec1.rva + 21]
    assert scan_first(trunc_tail) is None

    # YARA / IDA / x64dbg
    yara = generate_yara_rules(spec)
    assert "rule sigforge_xss_spec_resolve_player_db" in yara
    assert "$sig = {" in yara
    ida = generate_ida_patterns(spec)
    assert "resolve_player_db: " in ida
    assert " ? " in ida and " ?? " not in ida
    x64 = generate_x64dbg_patterns(spec)
    assert " ?? " in x64

    # HTML XSS escaping
    html_out = generate_html_report(spec, v1, v2=v2, oracle=oracle)
    assert "<script>alert" not in html_out
    assert "&lt;script&gt;alert" in html_out
    assert "#0f172a" in html_out
    assert "<svg" in html_out


def test_cli_end_to_end_all_subcommands(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    pair = make_demo_binary_pair()
    v1_path = tmp_path / "v1.dll"
    v2_path = tmp_path / "v2.dll"
    v1_path.write_bytes(pair["pe_v1"])
    v2_path.write_bytes(pair["pe_v2"])

    rva_p = pair["targets_v1"]["resolve_player_db"]
    rva_c = pair["targets_v1"]["calc_ca_pa_rating"]

    # 1. probe
    assert cli_main(["probe", str(v1_path), "--rva", hex(rva_p), "--json"]) == 0
    probe_out = capsys.readouterr().out
    assert '"format": "pe64"' in probe_out

    # 2. synthesize
    spec_path = tmp_path / "sigs.json"
    rep_path = tmp_path / "syn_report.html"
    assert (
        cli_main(
            [
                "synthesize",
                str(v1_path),
                "--v2",
                str(v2_path),
                "--target",
                f"resolve_player_db:{hex(rva_p)}",
                "--target",
                f"calc_ca_pa_rating:{hex(rva_c)}",
                "-o",
                str(spec_path),
                "--report",
                str(rep_path),
            ]
        )
        == 0
    )
    capsys.readouterr()
    assert spec_path.is_file()
    assert rep_path.is_file()

    # 3. verify
    assert cli_main(["verify", str(spec_path), str(v1_path), "--v2", str(v2_path), "--json"]) == 0
    ver_out = capsys.readouterr().out
    assert '"passed": true' in ver_out

    # 4. compile (all 5 langs)
    hpp_out = tmp_path / "out.hpp"
    py_out = tmp_path / "out.py"
    yara_out = tmp_path / "out.yar"
    assert cli_main(["compile", str(spec_path), "--lang", "cpp", "-o", str(hpp_out)]) == 0
    assert cli_main(["compile", str(spec_path), "--lang", "python", "-o", str(py_out)]) == 0
    assert cli_main(["compile", str(spec_path), "--lang", "yara", "-o", str(yara_out)]) == 0
    assert cli_main(["compile", str(spec_path), "--lang", "ida"]) == 0
    assert cli_main(["compile", str(spec_path), "--lang", "x64dbg"]) == 0
    capsys.readouterr()
    assert hpp_out.is_file() and py_out.is_file() and yara_out.is_file()

    # 5. inspect
    insp_path = tmp_path / "inspect.html"
    assert (
        cli_main(
            ["inspect", str(spec_path), str(v1_path), "--v2", str(v2_path), "-o", str(insp_path)]
        )
        == 0
    )
    assert insp_path.is_file()

    # 6. Error handling returns exit code 1 cleanly
    assert cli_main(["probe", str(tmp_path / "missing.dll")]) == 1
    err_out = capsys.readouterr().err
    assert "sigforge error" in err_out
