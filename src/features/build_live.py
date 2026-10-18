"""Construit le jeu live (caractéristiques URL) à partir de toutes les collectes.

Usage (depuis la racine du repo) :
    python -m src.features.build_live

Lit    : data/live/AAAA-MM-JJ/urls_HHMM.csv (toutes les collectes)
Écrit  : data/processed/live_url.csv
    url, label, source, collected_at, run, + les 56 colonnes URL de Hannousse
    (random_domain, nb_redirection, nb_external_redirection, statistical_report = NaN :
     non calculables depuis l'URL seule, voir src/features/url.py)

Une URL vue dans plusieurs collectes n'est gardée qu'une fois (première vue).
"""

from pathlib import Path

import pandas as pd

from .url import URL_FEATURES, url_features

ROOT = Path(__file__).resolve().parents[2]
LIVE_DIR = ROOT / "data" / "live"
OUT_FILE = ROOT / "data" / "processed" / "live_url.csv"


def load_runs():
    frames = []
    for f in sorted(LIVE_DIR.glob("*/urls_*.csv")):
        run = pd.read_csv(f)
        run["run"] = f"{f.parent.name}_{f.stem.removeprefix('urls_')}"
        frames.append(run)
    return pd.concat(frames, ignore_index=True)


def main():
    runs = load_runs()
    n_runs = runs["run"].nunique()
    live = (runs.sort_values("collected_at")
                .drop_duplicates(subset="url", keep="first")
                .reset_index(drop=True))
    print(f"{n_runs} collectes, {len(runs)} URL -> {len(live)} URL uniques")

    features = pd.DataFrame([url_features(u) for u in live["url"]], columns=URL_FEATURES)
    out = pd.concat([live[["url", "label", "source", "collected_at", "run"]], features], axis=1)

    OUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    out.to_csv(OUT_FILE, index=False)
    print(out["label"].value_counts().to_string())
    print(f"Écrit : {OUT_FILE.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
