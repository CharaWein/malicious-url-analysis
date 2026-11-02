"""Run the whole pipeline: extract -> quality -> clean -> features -> SQLite -> analysis."""
from pipeline import analyze, clean, extract, features, load, quality


def main() -> None:
    print("[1/6] extract")
    raw = extract.extract()
    print("[2/6] data quality")
    quality.check(raw)
    print("[3/6] clean")
    cleaned = clean.clean(raw)
    print("[4/6] features")
    feats = features.build(cleaned)
    print("[5/6] load to SQLite")
    load.load(feats)
    print("[6/6] hypotheses")
    analyze.run()


if __name__ == "__main__":
    main()
