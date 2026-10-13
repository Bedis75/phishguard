"""Sources d'URL pour la collecte quotidienne.

- Phishing : flux public OpenPhish (on télécharge la liste, on ne visite JAMAIS ces URL ici).
- Légitime : domaines Tranco -> pages internes trouvées sur leur page d'accueil.
"""

import io
import logging
import random
import zipfile
from pathlib import Path
from urllib.parse import urljoin, urldefrag, urlparse

import requests
import tldextract
from bs4 import BeautifulSoup

OPENPHISH_FEED = "https://openphish.com/feed.txt"
TRANCO_ID_URL = "https://tranco-list.eu/top-1m-id"
TRANCO_ZIP_URL = "https://tranco-list.eu/top-1m.csv.zip"

USER_AGENT = "PhishGuard-research/0.1 (academic project; contact via GitHub Bedis75)"
TIMEOUT = 10

# Avertissement sans conséquence (caractères mal encodés sur certaines pages d'accueil) :
# on ne garde que les liens, donc on le masque pour garder des journaux lisibles.
logging.getLogger("bs4.dammit").setLevel(logging.ERROR)
MAX_HTML_BYTES = 2_000_000

# Liens qui ne sont pas des pages web
SKIP_EXTENSIONS = (
    ".pdf", ".jpg", ".jpeg", ".png", ".gif", ".svg", ".webp", ".ico", ".css", ".js",
    ".zip", ".gz", ".rar", ".exe", ".dmg", ".mp3", ".mp4", ".avi", ".mov", ".xml", ".json",
)


def registered_domain(url):
    """Domaine enregistré : 'a.b.example.co.uk' -> 'example.co.uk'."""
    return tldextract.extract(url).top_domain_under_public_suffix


def fetch_openphish(session):
    """Liste des URL de phishing du flux public OpenPhish."""
    resp = session.get(OPENPHISH_FEED, timeout=30)
    resp.raise_for_status()
    urls = [line.strip() for line in resp.text.splitlines()]
    return [u for u in urls if u.startswith(("http://", "https://"))]


def fetch_tranco(session, cache_dir):
    """Liste Tranco du jour : (list_id, [(rang, domaine), ...]). Mise en cache par identifiant."""
    list_id = session.get(TRANCO_ID_URL, timeout=30).text.strip()
    cache_dir = Path(cache_dir)
    cache_dir.mkdir(parents=True, exist_ok=True)
    cached = cache_dir / f"tranco_{list_id}.csv"

    if not cached.exists():
        resp = session.get(TRANCO_ZIP_URL, timeout=120)
        resp.raise_for_status()
        with zipfile.ZipFile(io.BytesIO(resp.content)) as zf:
            cached.write_bytes(zf.read("top-1m.csv"))

    ranking = []
    for line in cached.read_text().splitlines():
        rank, domain = line.split(",", 1)
        ranking.append((int(rank), domain.strip()))
    return list_id, ranking


def _read_limited(resp):
    """Lit au plus MAX_HTML_BYTES pour ne pas charger une page énorme."""
    chunks, size = [], 0
    for chunk in resp.iter_content(64 * 1024):
        chunks.append(chunk)
        size += len(chunk)
        if size >= MAX_HTML_BYTES:
            break
    return b"".join(chunks)


def internal_pages(session, domain, n_pages, rng):
    """Charge la page d'accueil d'un domaine légitime et tire au hasard n_pages liens internes.

    Interne = même domaine enregistré, avec un vrai chemin (pas la page d'accueil),
    sinon on recrée le raccourci de PhiUSIIL (`https://www.domaine` sans chemin).
    """
    try:
        resp = session.get(f"https://{domain}/", timeout=TIMEOUT, stream=True)
        if resp.status_code != 200 or "html" not in resp.headers.get("Content-Type", ""):
            return []
        html = _read_limited(resp)
        base_url = resp.url  # après redirections (ex. -> https://www.domaine/)
    except requests.RequestException:
        return []

    links = set()
    for a in BeautifulSoup(html, "html.parser").find_all("a", href=True):
        url, _ = urldefrag(urljoin(base_url, a["href"].strip()))
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            continue
        if parsed.path in ("", "/") and not parsed.query:
            continue
        if parsed.path.lower().endswith(SKIP_EXTENSIONS):
            continue
        if parsed.path.startswith("/cdn-cgi/"):  # pages techniques Cloudflare
            continue
        if registered_domain(url) != domain:
            continue
        links.add(url)

    links = sorted(links)  # ordre stable avant le tirage, pour la reproductibilité
    return rng.sample(links, min(n_pages, len(links)))


def new_session():
    session = requests.Session()
    session.headers["User-Agent"] = USER_AGENT
    return session
