# sigforge

[![CI](https://github.com/lunizura/sigforge/actions/workflows/ci.yml/badge.svg)](https://github.com/lunizura/sigforge/actions/workflows/ci.yml)
![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-3776ab)
![License: MIT](https://img.shields.io/badge/license-MIT-10b981)
![Codegen](https://img.shields.io/badge/codegen-C%2B%2B20%20AVX2%20%7C%20Python%20%7C%20YARA%20%7C%20IDA-38bdf8)
![Zero Runtime Deps](https://img.shields.io/badge/runtime-100%25%20stdlib-a78bfa)

**Pure-stdlib x86-64 AOB signature synthesizer, multi-build differential anchor engine, 3-Gate Patch-Survival Oracle, and C++20 SIMD / `std::span` scanner compiler.**

Zero third-party runtime dependencies (`dependencies = []`, Python `>=3.10`).

---

## Architecture

```text
PE32+ (.exe/.dll) / ELF64
        │
        ▼
  binary_loader.py ──► BinaryImage (.text / .rdata / .pdata / .symtab)
        │
        ▼
   x86_ild.py ───────► DecodedInsn[] + ByteRole Volatility Map
        │                 (PREFIX, OPCODE, MODRM_SIB, REX_EXT,
        │                  STRUCT_DISP8, STACK_DISP8, DISP32,
        │                  RIP_DISP32, REL, IMM)
        ├───► differ.py (v1 -> v2 auto-anchoring & SequenceMatcher alignment)
        │
        ▼
  synthesizer.py ────► Shortest-Unique Masked SigSpec + RipCapture
        │
        ▼
    oracle.py ───────► 3-Gate Oracle & 100-Trial Relocation Fuzzer (0..100)
        │
        ├──► codegen_cpp.py   ──► #pragma once C++20 AVX2/SSE2/constexpr std::span
        ├──► codegen_py.py    ──► Standalone Python 3.10+ scanner + RIP resolver
        ├──► codegen_rules.py ──► YARA / IDA (?) / x64dbg (??) exporters
        └──► report_html.py   ──► Dark-mode HTML5 Volatility & .text Match Map
```

---

## 3-Gate Patch-Survival Oracle

Every synthesized or imported `SigSpec` is validated by `verify_spec()` across three deterministic gates:

1. **Gate 1 — Exact Uniqueness:** Pattern must start and end with locked bytes and match strictly `[rva_v1]` in `v1` (and `[rva_v2]` in `v2` if supplied), using an overlap-exact scanner (`pos = hit + 1`).
2. **Gate 2 — Anti-Fragility:** Requires `locked_count >= 4`, locked density `>= 20%`, and **zero** locked bytes at `ByteRole.RIP_DISP32` or `ByteRole.REL` displacements.
3. **Gate 3 — 100-Trial Deterministic Relocation Fuzzer (`seed = 0x516F049E`):**
   - **100% of trials:** Prepends `16..128` bytes of non-matching stub code (ASLR/shift), perturbs all `[rip + disp32]` offsets, and perturbs all `rel8`/`rel32` call/branch displacements.
   - **60% of trials:** Grows stack frames (`+8/+16/+32` on `STACK_DISP8` and `sub/add rsp, imm8`).
   - **25% of trials:** Perturbs non-stack `IMM` and `DISP32` bytes.
   - Computes `survival_score` (`0..100`) alongside `naive_raw_score` on unmasked raw bytes. Gate 3 passes iff `relocation_pass_rate == 1.0`, `stack_pass_rate == 1.0`, and `survival_score >= 75.0`.

---

## Quickstart

Install in editable mode with dev tools:

```bash
python -m pip install -e ".[dev]"
python examples/generate_demo_binaries.py
```

### 1. Probe binary sections, `.pdata` bounds, and decoded instructions

```bash
sigforge probe examples/samples/game_v1.dll --rva 0x101E
sigforge probe examples/samples/engine_v1.elf --rva 0x1056
```

### 2. Synthesize resilient signatures across `v1` -> `v2`

```bash
sigforge synthesize examples/samples/game_v1.dll \
  --v2 examples/samples/game_v2.dll \
  --target resolve_player_db:0x101E \
  --target calc_ca_pa_rating:0x1056 \
  -o demo_sigs.json \
  --report demo_report.html
```

### 3. Verify a `SigSpec` through the 3-Gate Oracle

```bash
sigforge verify demo_sigs.json examples/samples/game_v1.dll --v2 examples/samples/game_v2.dll
```

### 4. Compile to C++20, Python, YARA, IDA, or x64dbg

```bash
sigforge compile demo_sigs.json --lang cpp -o demo_sigs.hpp
sigforge compile demo_sigs.json --lang python -o demo_sigs.py
sigforge compile demo_sigs.json --lang yara -o demo_sigs.yar
sigforge compile demo_sigs.json --lang ida
sigforge compile demo_sigs.json --lang x64dbg
```

### 5. Generate standalone HTML5 Byte-Volatility Inspector

```bash
sigforge inspect demo_sigs.json examples/samples/game_v1.dll --v2 examples/samples/game_v2.dll -o report.html
```

---

## C++20 Generated Scanner Usage

The emitted `#pragma once` header (`namespace sigforge_gen`) supports compile-time `constexpr` verification (`static_assert`), runtime AVX2 (`__AVX2__`) / SSE2 (`__SSE2__` / `_M_X64`) acceleration with page-boundary-safe vector bounds, and UB-free RIP target resolution:

```cpp
#include "demo_sigs.hpp"

void scan_module(std::span<const std::uint8_t> text_section, std::uint64_t text_rva) {
    if (auto offset = sigforge_gen::find_resolve_player_db(text_section)) {
        auto global_rva = sigforge_gen::resolve_resolve_player_db_rip_target(
            text_section, text_rva);
        // ...
    }
}
```
