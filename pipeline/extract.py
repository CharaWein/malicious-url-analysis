"""Step 1 — extract: download raw CSV splits and merge them into one raw file."""
import urllib.request

import pandas as pd

from .config import HF_BASE, LABELS, RAW_DIR, SPLITS


def download() -> None:
    RAW_DIR.mkdir(parents=True, exist_ok=True)
    for split in SPLITS:
        target = RAW_DIR / f"{split}.csv"
        if target.exists():
            print(f"  [skip] {target.name} already downloaded")
            continue
        url = f"{HF_BASE}/{split}.csv"
        print(f"  [get]  {url}")
        urllib.request.urlretrieve(url, target)


def extract() -> pd.DataFrame:
    download()
    frames = []
    for split in SPLITS:
        df = pd.read_csv(RAW_DIR / f"{split}.csv", dtype={"url": str}, keep_default_na=False)
        df["split"] = split
        frames.append(df)
    raw = pd.concat(frames, ignore_index=True)
    raw["label"] = raw["labels"].map(LABELS)
    raw = raw.drop(columns="labels")
    print(f"  raw rows: {len(raw):,}")
    return raw
