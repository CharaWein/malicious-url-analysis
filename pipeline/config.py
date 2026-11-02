"""Paths and constants shared by every pipeline step."""
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RAW_DIR = ROOT / "data" / "raw"
PROCESSED_DIR = ROOT / "data" / "processed"
DB_PATH = ROOT / "data" / "urls.db"
REPORTS_DIR = ROOT / "reports"
SQL_DIR = ROOT / "sql"

# Hugging Face mirror of the Kaggle "Malicious URLs dataset" (MIT license).
HF_BASE = "https://huggingface.co/datasets/bgspaditya/malicious-600k/resolve/main"
SPLITS = ["train", "val", "test"]

LABELS = {0: "benign", 1: "defacement", 2: "malware", 3: "phishing"}
CLASS_ORDER = ["benign", "defacement", "malware", "phishing"]
RANDOM_STATE = 42
