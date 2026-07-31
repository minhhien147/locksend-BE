"""Download CICIoT2023 subset from Hugging Face (đủ cho --combine với trustlab)."""
from __future__ import annotations

import argparse
import urllib.request
from pathlib import Path

DATA = Path(__file__).resolve().parent / "data"
HF_BASE = "https://huggingface.co/datasets/bencorn/CIC-IoT-2023/resolve/main/CSV/MERGED_CSV"

# Subset đủ train --combine (mỗi file ~140–190 MB). Tăng bằng --merged-count.
DEFAULT_MERGED = [
    "Merged01.csv",
    "Merged02.csv",
    "Merged03.csv",
    "Merged04.csv",
    "Merged10.csv",
    "Merged20.csv",
]


def _download(url: str, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.is_file() and dest.stat().st_size > 1_000_000:
        print(f"[skip] {dest.name} already exists ({dest.stat().st_size / 1e6:.1f} MB)")
        return
    print(f"[get] {url}")
    print(f"  -> {dest}")
    tmp = dest.with_suffix(dest.suffix + ".part")

    def _reporthook(block_num: int, block_size: int, total_size: int) -> None:
        if total_size <= 0:
            return
        done = min(block_num * block_size, total_size)
        pct = 100.0 * done / total_size
        if block_num % 200 == 0 or done >= total_size:
            print(f"\r  {pct:5.1f}%  {done/1e6:.1f}/{total_size/1e6:.1f} MB", end="", flush=True)

    try:
        urllib.request.urlretrieve(url, tmp, reporthook=_reporthook)
        print()
        tmp.replace(dest)
    except Exception:
        if tmp.is_file():
            tmp.unlink(missing_ok=True)
        raise


def download_ciciot(merged: list[str]) -> None:
    out = DATA / "ciciot2023"
    for name in merged:
        _download(f"{HF_BASE}/{name}", out / name)
    print(f"[ok] CICIoT2023 -> {out} ({len(list(out.glob('*.csv')))} csv)")


def main() -> None:
    p = argparse.ArgumentParser(description="Download CICIoT2023 training CSVs")
    p.add_argument(
        "--merged-count",
        type=int,
        default=0,
        help="Lay N file Merged dau (0 = dung DEFAULT_MERGED)",
    )
    args = p.parse_args()
    if args.merged_count > 0:
        merged = [f"Merged{i:02d}.csv" for i in range(1, args.merged_count + 1)]
    else:
        merged = DEFAULT_MERGED
    download_ciciot(merged)


if __name__ == "__main__":
    main()
