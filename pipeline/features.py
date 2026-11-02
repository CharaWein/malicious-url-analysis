"""Step 4 — lexical features computed from the URL string only (no network access).

Length and counters use `url_norm` (scheme removed) so that the presence of
"http://" — a collection artefact — does not leak into them. The raw length is
kept as `url_length_raw` to show how much the artefact distorts it.
"""
import pandas as pd

IPV4_RE = r"^\d{1,3}(?:\.\d{1,3}){3}$"
HEX_IP_RE = r"^0x[0-9a-f]{8}$"      # 0xdaf1be2b — obfuscated IPv4
INT_IP_RE = r"^\d{8,10}$"           # 772050312  — IPv4 as a single integer


def _host(url_norm: pd.Series) -> pd.Series:
    host = url_norm.str.extract(r"^([^/?#]*)", expand=False).fillna("")
    host = host.str.rsplit("@", n=1).str[-1]          # drop user:pass@
    host = host.str.replace(r":\d*$", "", regex=True)   # drop :port
    return host.str.lower().str.rstrip(".")


def build(df: pd.DataFrame) -> pd.DataFrame:
    out = pd.DataFrame({"url": df["url"], "label": df["label"], "split": df["split"]})
    norm = df["url_norm"]
    host = _host(norm)
    host_no_www = host.str.replace(r"^www\d*\.", "", regex=True)

    out["is_malicious"] = (df["label"] != "benign").astype(int)
    out["has_scheme"] = df["has_scheme"]
    out["is_https"] = (df["scheme"] == "https").astype(int)
    out["url_length_raw"] = df["url"].str.len()
    out["url_length"] = norm.str.len()
    out["host"] = host
    out["host_length"] = host.str.len()
    out["path_length"] = out["url_length"] - norm.str.extract(r"^([^/?#]*)", expand=False).str.len()
    out["has_ip"] = (host.str.match(IPV4_RE) | host.str.match(HEX_IP_RE) | host.str.match(INT_IP_RE)).astype(int)
    out["has_port"] = norm.str.match(r"^[^/?#]*:\d+").astype(int)
    out["count_at"] = norm.str.count("@")
    out["count_dot"] = norm.str.count(r"\.")
    out["count_hyphen"] = norm.str.count("-")
    out["host_hyphens"] = host.str.count("-")
    out["count_digits"] = norm.str.count(r"\d")
    out["count_query_params"] = norm.str.count(r"[?&][^=&]+=")
    # Subdomains beyond the registrable domain ("a.b.example.com" -> 2), www excluded.
    labels_in_host = host_no_www.str.count(r"\.") + 1
    out["count_subdomains"] = (labels_in_host - 2).clip(lower=0).where(out["has_ip"] == 0, 0)

    print(f"  features: {len(out.columns) - 3} columns")
    return out
