"""Step 3 — cleaning: drop broken rows and duplicates, build a normalized URL.

The normalized URL has the scheme removed. Benign URLs in this dataset mostly
come without "http://", while defacement/malware URLs almost always have it,
so any string feature computed on the raw URL partly measures the collection
source rather than the URL itself.
"""
import pandas as pd

SCHEME_RE = r"^[a-zA-Z][a-zA-Z0-9+.-]*://"


def clean(raw: pd.DataFrame) -> pd.DataFrame:
    df = raw.copy()
    n0 = len(df)

    df["url"] = df["url"].str.strip()
    df = df[df["url"].notna() & (df["url"] != "")]
    n_empty = n0 - len(df)

    # The same URL with different labels cannot be trusted — drop it entirely.
    labels_per_url = df.groupby("url")["label"].transform("nunique")
    n_conflict = int((labels_per_url > 1).sum())
    df = df[labels_per_url == 1]

    before = len(df)
    df = df.drop_duplicates("url")
    n_dup = before - len(df)

    df["has_scheme"] = df["url"].str.match(SCHEME_RE).astype(int)
    df["scheme"] = df["url"].str.extract(r"^([a-zA-Z][a-zA-Z0-9+.-]*)://", expand=False).str.lower()
    df["url_norm"] = df["url"].str.replace(SCHEME_RE, "", regex=True)

    # Garbage rows: binary junk with control characters, or fragments whose
    # "host" is neither a dotted name nor an integer/hex IP (e.g. "bin/webscr?cmd=").
    host = df["url_norm"].str.extract(r"^([^/?#]*)", expand=False)
    has_ctrl = df["url"].str.contains(r"[\x00-\x1f\x7f]", regex=True)
    bad_host = ~host.str.contains(r"\.") & ~host.str.match(r"^(?:\d{8,10}|0x[0-9a-fA-F]{8})$")
    junk = has_ctrl | bad_host
    n_junk = int(junk.sum())
    df = df[~junk]

    print(f"  dropped: empty={n_empty:,}  conflicting labels={n_conflict:,}  "
          f"duplicates={n_dup:,}  malformed={n_junk:,}")
    print(f"  clean rows: {len(df):,}")
    return df.reset_index(drop=True)
