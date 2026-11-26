from __future__ import annotations

import html

from sigforge.codegen_cpp import generate_cpp_header
from sigforge.models import BinaryImage, SigEntry, SigSpec, validate_spec
from sigforge.oracle import SigOracleReport, SpecOracleResult, verify_spec
from sigforge.scanner_core import format_pattern


def _role_color(role: str) -> str:
    if role in ("opcode", "prefix"):
        return "#34d399"
    if role in ("modrm_sib", "rex_ext"):
        return "#38bdf8"
    if role in ("rip_disp32", "rel"):
        return "#fb7185"
    return "#fbbf24"


def _badge(label: str, ok: bool) -> str:
    cls = "badge-pass" if ok else "badge-fail"
    state = "PASS" if ok else "FAIL"
    return f'<span class="badge {cls}">{html.escape(label)}: {state}</span>'


def _render_funnel_svg(entry: SigEntry) -> str:
    if not entry.trace:
        return '<svg width="520" height="80" xmlns="http://www.w3.org/2000/svg"></svg>'

    width = 560
    bar_h = 22
    gap = 6
    pad_top = 10
    height = pad_top * 2 + len(entry.trace) * (bar_h + gap)
    max_hits = max(max(t.cumulative_matches for t in entry.trace), 1)

    bars: list[str] = []
    for idx, tr in enumerate(entry.trace):
        y = pad_top + idx * (bar_h + gap)
        ratio = tr.cumulative_matches / max_hits
        bw = max(8, int(ratio * 280))
        color = "#34d399" if tr.cumulative_matches == 1 else "#38bdf8"
        lbl = html.escape(
            f"#{idx} {tr.mnemonic_class} ({tr.cumulative_matches} hit{'s' if tr.cumulative_matches != 1 else ''})"
        )
        bars.append(
            f'<text x="8" y="{y + 15}" fill="#cbd5e1" font-size="11" font-family="monospace">{lbl}</text>'
            f'<rect x="250" y="{y + 2}" width="{bw}" height="{bar_h - 4}" rx="4" fill="{color}" />'
        )
    return (
        f'<svg viewBox="0 0 {width} {height}" width="100%" height="{height}" '
        f'xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Match Elimination Funnel">'
        f'<rect width="{width}" height="{height}" rx="8" fill="#020617" />'
        + "".join(bars)
        + "</svg>"
    )


def _render_rva_pin_svg(entry: SigEntry, v1: BinaryImage, v2: BinaryImage | None) -> str:
    width = 560
    height = 74
    secs1 = v1.exec_sections()
    sec1 = v1.section_at_rva(entry.rva_v1) or (secs1[0] if secs1 else None)
    p1 = 40
    if sec1 and len(sec1.data) > 0:
        rel1 = max(0.0, min(1.0, (entry.rva_v1 - sec1.rva) / len(sec1.data)))
        p1 = 20 + int(rel1 * 520)

    pin2_svg = ""
    if v2 is not None and entry.rva_v2 is not None:
        secs2 = v2.exec_sections()
        sec2 = v2.section_at_rva(entry.rva_v2) or (secs2[0] if secs2 else None)
        p2 = p1
        if sec2 and len(sec2.data) > 0:
            rel2 = max(0.0, min(1.0, (entry.rva_v2 - sec2.rva) / len(sec2.data)))
            p2 = 20 + int(rel2 * 520)
        pin2_svg = (
            f'<line x1="{p2}" y1="36" x2="{p2}" y2="62" stroke="#fbbf24" stroke-width="3" />'
            f'<circle cx="{p2}" cy="58" r="5" fill="#fbbf24" />'
            f'<text x="{min(p2 + 8, 440)}" y="62" fill="#fbbf24" font-size="11" font-family="monospace">'
            f"v2 0x{entry.rva_v2:X}</text>"
        )

    return (
        f'<svg viewBox="0 0 {width} {height}" width="100%" height="{height}" '
        f'xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Executable Section Pin Map">'
        f'<rect width="{width}" height="{height}" rx="8" fill="#020617" />'
        f'<rect x="20" y="28" width="520" height="12" rx="4" fill="#1e293b" />'
        f'<line x1="{p1}" y1="10" x2="{p1}" y2="38" stroke="#34d399" stroke-width="3" />'
        f'<circle cx="{p1}" cy="14" r="5" fill="#34d399" />'
        f'<text x="{min(p1 + 8, 440)}" y="18" fill="#34d399" font-size="11" font-family="monospace">'
        f"v1 0x{entry.rva_v1:X}</text>"
        f"{pin2_svg}"
        "</svg>"
    )


def _render_heatmap(entry: SigEntry) -> str:
    if not entry.trace:
        toks = entry.tokens()
        cells = [
            f'<span class="byte-chip" style="border-color:#38bdf8;color:#e2e8f0">'
            f"{'??' if t is None else f'{t:02X}'}</span>"
            for t in toks
        ]
        return f'<div class="heatmap">{"".join(cells)}</div>'

    rows: list[str] = []
    for idx, tr in enumerate(entry.trace):
        raw_bytes = tr.raw_hex.split()
        chips: list[str] = []
        for b_idx, tok in enumerate(tr.pattern_tokens):
            role = tr.roles[b_idx] if b_idx < len(tr.roles) else "opcode"
            raw_b = raw_bytes[b_idx] if b_idx < len(raw_bytes) else tok
            color = _role_color(role)
            is_wc = tok == "??"
            bg = "rgba(15,23,42,0.9)" if is_wc else "rgba(30,41,59,0.95)"
            label = f"?? ({raw_b})" if is_wc else tok
            chips.append(
                f'<span class="byte-chip" title="{html.escape(role)}" '
                f'style="border-color:{color};background:{bg};color:{color}">'
                f"{html.escape(label)}</span>"
            )
        rows.append(
            f'<div class="insn-row">'
            f'<span class="insn-meta">+{idx} {html.escape(tr.mnemonic_class)} '
            f"<small>(0x{tr.rva:X})</small></span>"
            f'<div class="insn-bytes">{"".join(chips)}</div>'
            f"</div>"
        )
    return "".join(rows)


def _render_sig_card(
    entry: SigEntry,
    rep: SigOracleReport,
    v1: BinaryImage,
    v2: BinaryImage | None,
) -> str:
    ida_pat = format_pattern(entry.tokens(), wildcard="?")
    x64_pat = format_pattern(entry.tokens(), wildcard="??")
    sig_pct = max(0.0, min(100.0, rep.survival_score))
    raw_pct = max(0.0, min(100.0, rep.naive_raw_score))

    failures_html = ""
    if rep.failures:
        items = "".join(f"<li>{html.escape(f)}</li>" for f in rep.failures)
        failures_html = f'<ul class="fail-list">{items}</ul>'

    return (
        f'<section class="card">'
        f'<div class="card-head">'
        f"<div><h2>{html.escape(entry.name)}</h2>"
        f'<p class="muted">{html.escape(entry.description or "Synthesized signature")}</p></div>'
        f'<div class="badges">'
        f"{_badge('Gate 1 Unique', rep.gate1_unique)}"
        f"{_badge('Gate 2 Anti-Fragile', rep.gate2_antifragile)}"
        f"{_badge('Gate 3 100-Trial', rep.gate3_survival)}"
        f"</div></div>"
        f"{failures_html}"
        f'<div class="grid2">'
        f'<div class="panel"><h3>Survival Score Comparison</h3>'
        f'<div class="score-row"><span>SigForge Masked</span><strong>{rep.survival_score:.2f}/100</strong></div>'
        f'<div class="bar-track"><div class="bar-fill bar-good" style="width:{sig_pct:.1f}%"></div></div>'
        f'<div class="score-row"><span>Naive Raw Bytes</span><strong>{rep.naive_raw_score:.2f}/100</strong></div>'
        f'<div class="bar-track"><div class="bar-fill bar-bad" style="width:{raw_pct:.1f}%"></div></div>'
        f'<p class="muted small">Reloc: {rep.relocation_pass_rate:.0%} | Stack: {rep.stack_pass_rate:.0%} | Hard Stress: {rep.hard_stress_pass_rate:.0%}</p>'
        f"</div>"
        f'<div class="panel"><h3>.text Match Funnel &amp; RVA Pin</h3>'
        f"{_render_funnel_svg(entry)}"
        f'<div style="margin-top:8px">{_render_rva_pin_svg(entry, v1, v2)}</div>'
        f"</div></div>"
        f'<div class="panel" style="margin-top:14px"><h3>Instruction-Aligned Byte-Volatility Heatmap</h3>'
        f'<div class="legend">'
        f'<span style="color:#34d399">&#9632; Opcode / Prefix</span>'
        f'<span style="color:#38bdf8">&#9632; ModR/M / SIB / REX</span>'
        f'<span style="color:#fbbf24">&#9632; Disp8 / Disp32 / Imm</span>'
        f'<span style="color:#fb7185">&#9632; RIP Disp32 / Rel</span>'
        f"</div>"
        f"{_render_heatmap(entry)}</div>"
        f'<div class="grid2" style="margin-top:14px">'
        f'<div class="panel"><h3>IDA Pattern</h3><pre>{html.escape(ida_pat)}</pre></div>'
        f'<div class="panel"><h3>x64dbg / Cheat Engine Pattern</h3><pre>{html.escape(x64_pat)}</pre></div>'
        f"</div></section>"
    )


def generate_html_report(
    spec: SigSpec,
    v1: BinaryImage,
    v2: BinaryImage | None = None,
    oracle: SpecOracleResult | None = None,
) -> str:
    validate_spec(spec)
    res = oracle if oracle is not None else verify_spec(spec, v1, v2)
    cpp_preview = generate_cpp_header(spec)

    cards = "".join(
        _render_sig_card(entry, res.reports[entry.name], v1, v2)
        for entry in spec.signatures
        if entry.name in res.reports
    )

    overall_badge = _badge("3-Gate Oracle", res.passed)
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>sigforge Report — {html.escape(spec.name)}</title>
<style>
  :root {{ color-scheme: dark; }}
  body {{
    margin: 0; padding: 28px; font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
    background: #0f172a; color: #e2e8f0; line-height: 1.5;
  }}
  .wrap {{ max-width: 1180px; margin: 0 auto; }}
  header {{ display: flex; flex-wrap: wrap; justify-content: space-between; align-items: center; gap: 12px; margin-bottom: 24px; }}
  h1 {{ margin: 0; font-size: 1.75rem; color: #f8fafc; }}
  h2 {{ margin: 0 0 4px 0; font-size: 1.25rem; color: #f8fafc; }}
  h3 {{ margin: 0 0 10px 0; font-size: 0.95rem; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.04em; }}
  .muted {{ color: #94a3b8; margin: 0; }}
  .small {{ font-size: 0.85rem; margin-top: 8px; }}
  .card {{ background: #1e293b; border: 1px solid #334155; border-radius: 12px; padding: 20px; margin-bottom: 20px; }}
  .card-head {{ display: flex; flex-wrap: wrap; justify-content: space-between; align-items: flex-start; gap: 12px; margin-bottom: 14px; }}
  .badges {{ display: flex; flex-wrap: wrap; gap: 8px; }}
  .badge {{ padding: 4px 10px; border-radius: 999px; font-size: 0.8rem; font-weight: 600; }}
  .badge-pass {{ background: rgba(52, 211, 153, 0.16); color: #34d399; border: 1px solid rgba(52, 211, 153, 0.45); }}
  .badge-fail {{ background: rgba(251, 113, 133, 0.16); color: #fb7185; border: 1px solid rgba(251, 113, 133, 0.45); }}
  .grid2 {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 14px; }}
  .panel {{ background: #0b1220; border: 1px solid #1e293b; border-radius: 10px; padding: 14px; }}
  .score-row {{ display: flex; justify-content: space-between; font-size: 0.9rem; margin-top: 8px; }}
  .bar-track {{ height: 10px; background: #1e293b; border-radius: 999px; overflow: hidden; margin: 4px 0 10px 0; }}
  .bar-fill {{ height: 100%; border-radius: 999px; }}
  .bar-good {{ background: #34d399; }}
  .bar-bad {{ background: #fb7185; }}
  .legend {{ display: flex; flex-wrap: wrap; gap: 14px; font-size: 0.82rem; margin-bottom: 10px; }}
  .insn-row {{ display: flex; flex-wrap: wrap; align-items: center; gap: 10px; margin-bottom: 8px; }}
  .insn-meta {{ min-width: 185px; font-family: monospace; font-size: 0.84rem; color: #cbd5e1; }}
  .insn-bytes {{ display: flex; flex-wrap: wrap; gap: 5px; }}
  .byte-chip {{ display: inline-block; padding: 2px 7px; border-radius: 6px; border: 1px solid; font-family: monospace; font-size: 0.82rem; }}
  pre {{ margin: 0; padding: 10px; background: #020617; border-radius: 8px; overflow-x: auto; font-size: 0.84rem; color: #e2e8f0; }}
  .fail-list {{ margin: 0 0 12px 0; padding-left: 18px; color: #fb7185; font-size: 0.9rem; }}
</style>
</head>
<body>
<div class="wrap">
  <header>
    <div>
      <h1>sigforge Inspection Report &mdash; {html.escape(spec.name)}</h1>
      <p class="muted">Format: {html.escape(spec.binary_format)} | Mean Survival Score: {res.mean_survival_score:.2f}/100 | {html.escape(spec.description)}</p>
    </div>
    <div class="badges">{overall_badge}</div>
  </header>
  {cards}
  <section class="card">
    <h3>Generated C++20 SIMD / std::span Header Preview</h3>
    <pre>{html.escape(cpp_preview)}</pre>
  </section>
</div>
</body>
</html>
"""
