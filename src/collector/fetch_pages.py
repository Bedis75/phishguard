"""Étape 3 du collecteur : téléchargement du HTML brut des URL d'une collecte.

À LANCER UNIQUEMENT DANS LE CONTENEUR (voir src/collector/collect.sh) : ce script charge
de vraies pages de phishing.

Usage (dans le conteneur) :
    python -m src.collector.fetch_pages /data/urls_HHMM.csv

Écrit, à côté du fichier d'entrée :
    pages_HHMM.csv   une ligne par URL : statut, URL finale, redirections, IP, fichier HTML, erreur
    html/<id>.html.gz  HTML brut compressé (jamais à ouvrir dans un navigateur)

Mêmes conditions que Hannousse (feature_extractor.py, `is_URL_accessible`) : `requests`,
délai de 5 s, identifiant `python-requests` par défaut, seules les réponses 200 sont gardées.

Sécurité :
- `requests` ne fait que télécharger : aucun JavaScript exécuté, aucun formulaire envoyé ;
- redirections suivies à la main, et refusées vers une adresse privée ou locale (box, réseau local) ;
- seuls les contenus texte/HTML sont lus, 2 Mo au maximum (pas de fichiers exécutables) ;
- HTML stocké compressé (.gz) pour qu'il ne puisse pas s'ouvrir par un double-clic.
"""

import csv
import gzip
import hashlib
import ipaddress
import json
import socket
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urljoin, urlsplit

import requests
import tldextract

TIMEOUT = 5                  # comme les auteurs
MAX_REDIRECTS = 10
MAX_BYTES = 2_000_000
WORKERS = 16
FIELDS = ["url", "fetched_at", "ok", "status_code", "final_url", "content_type", "n_bytes",
          "history", "ip", "html_file", "error"]

_extract = tldextract.TLDExtract(include_psl_private_domains=False)


class BlockedAddress(Exception):
    pass


def resolve(host):
    """IP du nom d'hôte, None si la résolution échoue."""
    try:
        return socket.gethostbyname(host)
    except (socket.gaierror, UnicodeError, OSError):
        return None


def check_public(url):
    """Refuse les URL qui pointent vers une adresse privée, locale ou réservée."""
    host = urlsplit(url).hostname
    if not host:
        raise BlockedAddress("pas de nom d'hôte")
    ip = resolve(host)
    if ip is None:
        raise requests.ConnectionError(f"résolution DNS impossible : {host}")
    addr = ipaddress.ip_address(ip)
    if not addr.is_global:
        raise BlockedAddress(f"adresse non publique : {host} -> {ip}")


def read_limited(resp):
    chunks, size = [], 0
    for chunk in resp.iter_content(64 * 1024):
        chunks.append(chunk)
        size += len(chunk)
        if size >= MAX_BYTES:
            break
    return b"".join(chunks)[:MAX_BYTES]


def fetch(session, url, html_dir):
    row = dict.fromkeys(FIELDS, "")
    row.update(url=url, fetched_at=datetime.now(timezone.utc).isoformat(timespec="seconds"), ok=0)

    # IP du domaine enregistré, comme `statistical_report` des auteurs
    ext = _extract(url)
    row["ip"] = resolve(ext.domain + "." + ext.suffix) or ""

    history, current = [], url
    try:
        for _ in range(MAX_REDIRECTS + 1):
            check_public(current)
            resp = session.get(current, timeout=TIMEOUT, allow_redirects=False, stream=True)
            target = session.get_redirect_target(resp)
            if not target:
                break
            history.append(current)  # comme `page.history` de requests : une entrée par redirection
            resp.close()
            current = urljoin(current, target)
        else:
            raise requests.TooManyRedirects(f"plus de {MAX_REDIRECTS} redirections")

        content_type = resp.headers.get("Content-Type", "")
        row.update(status_code=resp.status_code, final_url=current, content_type=content_type,
                   history=json.dumps(history))

        if resp.status_code == 200 and ("html" in content_type or "text" in content_type or not content_type):
            body = read_limited(resp)
            if body.strip():
                name = hashlib.sha256(url.encode()).hexdigest()[:16] + ".html.gz"
                (html_dir / name).write_bytes(gzip.compress(body))
                row.update(ok=1, n_bytes=len(body), html_file=f"html/{name}")
        resp.close()
    except (requests.RequestException, BlockedAddress, ValueError) as exc:
        row.update(history=json.dumps(history), error=f"{type(exc).__name__}: {exc}"[:300])
    return row


def main():
    in_file = Path(sys.argv[1])
    run = in_file.stem.removeprefix("urls_")
    out_file = in_file.with_name(f"pages_{run}.csv")
    if out_file.exists():
        raise SystemExit(f"{out_file} existe déjà.")
    html_dir = in_file.parent / "html"
    html_dir.mkdir(exist_ok=True)

    with in_file.open() as f:
        urls = [r["url"] for r in csv.DictReader(f)]

    session = requests.Session()
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        rows = list(pool.map(lambda u: fetch(session, u, html_dir), urls))

    with out_file.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)

    n_ok = sum(r["ok"] for r in rows)
    print(f"Pages : {n_ok}/{len(rows)} téléchargées (200 + HTML) -> {out_file.name}")


if __name__ == "__main__":
    main()
