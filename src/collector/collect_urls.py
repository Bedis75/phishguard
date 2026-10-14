"""Collecte des URL, 2 passages par jour (étape 1 du collecteur live).

OpenPhish publie une nouvelle liste à 00:00 et 12:00 UTC : lancer vers 00:15 et 12:15 UTC.

Usage (depuis la racine du repo) :
    python -m src.collector.collect_urls
    python -m src.collector.collect_urls --n-domains 100 --pages-per-domain 3

Sortie : data/live/AAAA-MM-JJ/urls_HHMM.csv (date et heure UTC du passage)
    url, label, source, domain, tranco_rank, tranco_list_id, collected_at
"""

import argparse
import csv
import random
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

from .sources import (
    fetch_openphish,
    fetch_tranco,
    internal_pages,
    new_session,
    registered_domain,
)

ROOT = Path(__file__).resolve().parents[2]
LIVE_DIR = ROOT / "data" / "live"
FIELDS = ["url", "label", "source", "domain", "tranco_rank", "tranco_list_id", "collected_at"]


def now_utc():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def collect_legit(session, ranking, list_id, n_domains, pages_per_domain, top_k, seed, workers):
    """Tire des domaines au hasard dans le top `top_k` Tranco jusqu'à en avoir `n_domains` exploitables."""
    rng = random.Random(seed)
    candidates = rng.sample(ranking[:top_k], len(ranking[:top_k]))

    rows, done, start = [], 0, 0
    with ThreadPoolExecutor(max_workers=workers) as pool:
        while done < n_domains and start < len(candidates):
            batch = candidates[start:start + workers * 2]
            start += len(batch)
            # Une graine par domaine : le tirage des pages ne dépend pas de l'ordre des threads
            results = pool.map(
                lambda rd: (rd, internal_pages(session, rd[1], pages_per_domain,
                                               random.Random(f"{seed}-{rd[1]}"))),
                batch,
            )
            for (rank, domain), pages in results:
                if not pages or done >= n_domains:
                    continue
                done += 1
                ts = now_utc()
                for url in pages:
                    rows.append({
                        "url": url, "label": "legitimate", "source": "tranco",
                        "domain": domain, "tranco_rank": rank,
                        "tranco_list_id": list_id, "collected_at": ts,
                    })
    return rows, done, start


def main():
    parser = argparse.ArgumentParser(description="Collecte quotidienne des URL PhishGuard")
    parser.add_argument("--n-domains", type=int, default=100,
                        help="nombre de domaines Tranco avec au moins une page interne")
    parser.add_argument("--pages-per-domain", type=int, default=3)
    parser.add_argument("--top-k", type=int, default=100_000,
                        help="tirer les domaines dans le top K Tranco (pas seulement les plus connus)")
    parser.add_argument("--workers", type=int, default=16)
    args = parser.parse_args()

    run = datetime.now(timezone.utc)
    run_date, run_time = run.strftime("%Y-%m-%d"), run.strftime("%H%M")
    out_dir = LIVE_DIR / run_date
    out_file = out_dir / f"urls_{run_time}.csv"
    if out_file.exists():
        raise SystemExit(f"{out_file} existe déjà.")

    session = new_session()

    # Phishing : on récupère la liste, on ne visite pas les URL
    ts = now_utc()
    phishing = [{
        "url": url, "label": "phishing", "source": "openphish",
        "domain": registered_domain(url), "tranco_rank": "",
        "tranco_list_id": "", "collected_at": ts,
    } for url in dict.fromkeys(fetch_openphish(session))]
    print(f"OpenPhish : {len(phishing)} URL de phishing")

    # Légitime : pages internes de domaines Tranco
    list_id, ranking = fetch_tranco(session, LIVE_DIR / "tranco")
    legit, n_ok, n_tried = collect_legit(
        session, ranking, list_id, args.n_domains, args.pages_per_domain,
        args.top_k, seed=f"{run_date}-{run_time}", workers=args.workers,
    )
    print(f"Tranco ({list_id}) : {len(legit)} pages internes "
          f"sur {n_ok} domaines ({n_tried} domaines essayés)")

    out_dir.mkdir(parents=True, exist_ok=True)
    with out_file.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(phishing + legit)
    print(f"Écrit : {out_file.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
