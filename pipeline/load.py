"""Step 5 — load the feature table into SQLite."""
import sqlite3

import pandas as pd

from .config import DB_PATH, PROCESSED_DIR, SQL_DIR


def load(features: pd.DataFrame) -> None:
    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    features.to_csv(PROCESSED_DIR / "urls_features.csv", index=False)

    DB_PATH.unlink(missing_ok=True)
    with sqlite3.connect(DB_PATH) as con:
        con.executescript((SQL_DIR / "schema.sql").read_text(encoding="utf-8"))
        cols = list(features.columns)
        con.executemany(
            f"INSERT INTO urls ({', '.join(cols)}) VALUES ({', '.join('?' * len(cols))})",
            features.itertuples(index=False, name=None),
        )
        n = con.execute("SELECT COUNT(*) FROM urls").fetchone()[0]
    print(f"  loaded {n:,} rows into {DB_PATH.name}")
