from __future__ import annotations

import re
import struct
from typing import Sequence

from sigforge.errors import SpecValidationError
from sigforge.models import BinaryImage, RipCapture

_HEX_BYTE_RE = re.compile(r"^[0-9A-Fa-f]{2}$")


def parse_pattern(pattern: str) -> list[int | None]:
    parts = pattern.strip().split()
    if not parts:
        raise SpecValidationError("Pattern string cannot be empty")
    tokens: list[int | None] = []
    for p in parts:
        if p in ("?", "??"):
            tokens.append(None)
        elif _HEX_BYTE_RE.match(p):
            tokens.append(int(p, 16))
        else:
            raise SpecValidationError(f"Invalid pattern token '{p}'")
    return tokens


def format_pattern(tokens: Sequence[int | None], wildcard: str = "??") -> str:
    return " ".join(wildcard if t is None else f"{t:02X}" for t in tokens)


def trim_trailing_wildcards(tokens: Sequence[int | None], min_len: int = 1) -> list[int | None]:
    out = list(tokens)
    floor = max(1, min_len)
    while len(out) > floor and out[-1] is None:
        out.pop()
    return out


def _select_best_needle(tokens: Sequence[int | None]) -> tuple[int, bytes]:
    common = {0x00, 0x48, 0x90, 0xCC, 0xFF}
    best_off = -1
    best_len = 0
    best_score = (-1, -1)

    n = len(tokens)
    i = 0
    while i < n:
        if tokens[i] is None:
            i += 1
            continue
        start = i
        while i < n and tokens[i] is not None:
            i += 1
        run_len = i - start
        non_common = sum(1 for j in range(start, i) if tokens[j] not in common)
        score = (run_len, non_common)
        if score > best_score:
            best_score = score
            best_off = start
            best_len = run_len

    if best_off < 0 or best_len <= 0:
        raise SpecValidationError("Pattern must contain at least one concrete byte")
    needle = bytes(tokens[best_off + k] for k in range(best_len))  # type: ignore[arg-type]
    return best_off, needle


def scan_buffer(
    buf: bytes | bytearray, tokens: Sequence[int | None], max_hits: int = 0
) -> list[int]:
    pat_len = len(tokens)
    if pat_len == 0:
        raise SpecValidationError("Pattern tokens cannot be empty")
    if len(buf) < pat_len:
        return []

    needle_off, needle = _select_best_needle(tokens)
    needle_len = len(needle)
    needle_end = needle_off + needle_len

    checks = [
        (i, b) for i, b in enumerate(tokens) if b is not None and not (needle_off <= i < needle_end)
    ]

    hits: list[int] = []
    limit = len(buf) - pat_len
    search_end = limit + needle_end
    pos = 0
    while pos <= limit:
        found = buf.find(needle, pos + needle_off, search_end)
        if found == -1:
            break
        hit = found - needle_off
        matched = True
        for idx, val in checks:
            if buf[hit + idx] != val:
                matched = False
                break
        if matched:
            hits.append(hit)
            if max_hits > 0 and len(hits) >= max_hits:
                break
        pos = hit + 1
    return hits


def scan_exec_sections(
    image: BinaryImage, tokens: Sequence[int | None], max_hits: int = 0
) -> list[int]:
    hits: list[int] = []
    for sec in image.exec_sections():
        rem = (max_hits - len(hits)) if max_hits > 0 else 0
        for off in scan_buffer(sec.data, tokens, max_hits=rem):
            hits.append(sec.rva + off)
            if max_hits > 0 and len(hits) >= max_hits:
                return hits
    return hits


def resolve_rip_target_in_image(
    image: BinaryImage, match_rva: int, capture: RipCapture
) -> int | None:
    raw = image.read_rva(match_rva + capture.disp_offset, 4)
    if raw is None or len(raw) < 4:
        return None
    disp = struct.unpack("<i", raw)[0]
    return (match_rva + capture.next_ip_offset + disp) & 0xFFFFFFFFFFFFFFFF
