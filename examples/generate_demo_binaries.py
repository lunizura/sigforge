from __future__ import annotations

from pathlib import Path

from sigforge.synthetic_bins import make_demo_binary_pair


def main() -> None:
    root = Path(__file__).resolve().parent.parent
    out_dir = root / "examples" / "samples"
    out_dir.mkdir(parents=True, exist_ok=True)

    pair = make_demo_binary_pair()
    (out_dir / "game_v1.dll").write_bytes(pair["pe_v1"])
    (out_dir / "game_v2.dll").write_bytes(pair["pe_v2"])
    (out_dir / "engine_v1.elf").write_bytes(pair["elf_v1"])

    print(f"Generated demo binaries in {out_dir}:")
    for label, targets in (("v1", pair["targets_v1"]), ("v2", pair["targets_v2"])):
        formatted = ", ".join(f"{k}=0x{v:X}" for k, v in targets.items())
        print(f"  {label}: {formatted}")


if __name__ == "__main__":
    main()
