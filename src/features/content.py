"""Caractéristiques de CONTENU de Hannousse & Yahiouche (2021), recalculées « au mieux » (option B).

ATTENTION : reproduction APPROXIMATIVE, non vérifiable (voir reports/avancement.md §3.9) :
- le code publié par les auteurs ne correspond pas à leur CSV (`nb_hyperlinks(dom)` appelé avec 6
  arguments) : on suit la version commentée de `nb_hyperlinks` (somme des liens internes + externes) ;
- 5 colonnes sont constantes (toujours 0) dans leur CSV : on renvoie 0, comme à l'entraînement ;
- `ratio_extRedirection` et `ratio_extErrors` demandent une requête vers CHAQUE lien externe :
  non calculées, remplacées par la médiane du train (0,0).

Pour le reste, on reproduit `extract_data_from_URL` et `content_features.py` des auteurs, y compris
leurs particularités (un lien absolu vers le même site n'est compté nulle part, la balise <script>
est rangée dans `Link`, toutes les balises <link> de la page comptent comme favicon…).
"""

import re
from urllib.parse import urlsplit

import tldextract
from bs4 import BeautifulSoup

CONTENT_FEATURES = [
    "nb_hyperlinks", "ratio_intHyperlinks", "ratio_extHyperlinks", "ratio_nullHyperlinks",
    "nb_extCSS", "ratio_intRedirection", "ratio_extRedirection", "ratio_intErrors",
    "ratio_extErrors", "login_form", "external_favicon", "links_in_tags", "submit_email",
    "ratio_intMedia", "ratio_extMedia", "sfh", "iframe", "popup_window", "safe_anchor",
    "onmouseover", "right_clic", "empty_title", "domain_in_title", "domain_with_copyright",
]

# Constantes dans le CSV des auteurs (bugs de leur code) -> 0, comme à l'entraînement
CONSTANT_ZERO = ["ratio_nullHyperlinks", "ratio_intRedirection", "ratio_intErrors", "submit_email", "sfh"]
# Exigent une requête vers chaque lien externe -> médiane du train
TRAIN_MEDIAN = {"ratio_extRedirection": 0.0, "ratio_extErrors": 0.0}

NULL_FORMAT = ["", "#", "#nothing", "#doesnotexist", "#null", "#void", "#whatever",
               "#content", "javascript::void(0)", "javascript::void(0);", "javascript::;", "javascript"]

_extract = tldextract.TLDExtract(include_psl_private_domains=False)


def _bucket():
    return {"internals": [], "externals": [], "null": []}


def _classify(value, hostname, domain, store, null_extra=()):
    """Règle des auteurs, répétée pour chaque type de balise."""
    dots = value.count(".")
    if hostname in value or domain in value or dots == 1 or not value.startswith("http"):
        if not value.startswith("http"):
            if not value.startswith("/"):
                store["internals"].append(hostname + "/" + value)
            elif value in NULL_FORMAT or value in null_extra:
                store["null"].append(value)
            else:
                store["internals"].append(hostname + value)
        # lien absolu vers le même site : non compté (comme chez les auteurs)
    else:
        store["externals"].append(value)


def _is_icon(rel):
    rels = rel if isinstance(rel, list) else [rel]
    return any(r.endswith("icon") for r in rels)


def content_features(url, html):
    """Les 24 caractéristiques de contenu d'une page, dans l'ordre de `CONTENT_FEATURES`."""
    hostname = urlsplit(url).hostname or ""
    ext = _extract(url)
    domain = ext.domain + "." + ext.suffix

    href, link, media, form, css, favicon = (_bucket() for _ in range(6))
    anchor = {"safe": [], "unsafe": []}
    iframe = {"visible": [], "invisible": []}

    soup = BeautifulSoup(html, "html.parser", from_encoding="iso-8859-1")

    for a in soup.find_all("a", href=True):
        v = a["href"]
        if hostname in v or domain in v or v.count(".") == 1 or not v.startswith("http"):
            if "#" in v or "javascript" in v.lower() or "mailto" in v.lower():
                anchor["unsafe"].append(v)
            _classify(v, hostname, domain, href)
        else:
            href["externals"].append(v)
            anchor["safe"].append(v)

    for tag in ("img", "audio", "embed", "iframe"):
        for t in soup.find_all(tag, src=True):
            _classify(t["src"], hostname, domain, media)

    for t in soup.find_all("link", href=True):
        _classify(t["href"], hostname, domain, link)
    for t in soup.find_all("script", src=True):
        _classify(t["src"], hostname, domain, link)

    for t in soup.find_all("link", rel="stylesheet"):
        if t.get("href"):
            _classify(t["href"], hostname, domain, css)

    for t in soup.find_all("form", action=True):
        _classify(t["action"], hostname, domain, form, null_extra=("about:blank",))

    for _ in soup.find_all("head"):
        for t in soup.find_all("link", href=True):
            _classify(t["href"], hostname, domain, favicon)
        for t in soup.find_all("link", href=True, rel=True):
            if _is_icon(t["rel"]):
                _classify(t["href"], hostname, domain, favicon)

    for border_attr, invisible_value in (("frameborder", "0"), ("border", "0"), ("style", "border:none;")):
        for t in soup.find_all("iframe", width=True, height=True, **{border_attr: True}):
            invisible = t["width"] == "0" and t["height"] == "0" and t[border_attr] == invisible_value
            iframe["invisible" if invisible else "visible"].append(t)

    title = soup.title.string if soup.title and soup.title.string else ""
    text = soup.get_text()

    groups = (href, link, media, form, css, favicon)
    n_int = sum(len(g["internals"]) for g in groups)
    n_ext = sum(len(g["externals"]) for g in groups)
    n_null = sum(len(g["null"]) for g in groups)
    total = n_int + n_ext

    def pct(part, whole):
        return part / whole * 100 if whole else 0

    php = re.compile(r"([a-zA-Z0-9\_])+.php")
    login = int(bool(form["externals"] or form["null"])
                or any(php.match(f) for f in form["internals"] + form["externals"]))

    m = re.search("(\N{COPYRIGHT SIGN}|\N{TRADE MARK SIGN}|\N{REGISTERED SIGN})", text)
    if m:
        around = text[max(m.start() - 50, 0):m.start() + 50]
        copyright_flag = 0 if ext.domain.lower() in around.lower() else 1
    else:
        copyright_flag = 0

    values = {
        "nb_hyperlinks": total,
        "ratio_intHyperlinks": n_int / total if total else 0,
        "ratio_extHyperlinks": n_ext / total if total else 0,
        "ratio_nullHyperlinks": n_null / total if total else 0,
        "nb_extCSS": len(css["externals"]),
        "login_form": login,
        "external_favicon": int(bool(favicon["externals"])),
        "links_in_tags": pct(len(link["internals"]), len(link["internals"]) + len(link["externals"])),
        "ratio_intMedia": pct(len(media["internals"]), len(media["internals"]) + len(media["externals"])),
        "ratio_extMedia": pct(len(media["externals"]), len(media["internals"]) + len(media["externals"])),
        "iframe": int(bool(iframe["invisible"])),
        "popup_window": int("prompt(" in text.lower()),
        "safe_anchor": pct(len(anchor["unsafe"]), len(anchor["safe"]) + len(anchor["unsafe"])),
        "onmouseover": int('onmouseover="window.status=' in text.lower().replace(" ", "")),
        "right_clic": int(bool(re.findall(r"event.button ?== ?2", text))),
        "empty_title": 0 if title else 1,
        "domain_in_title": 0 if ext.domain.lower() in title.lower() else 1,
        "domain_with_copyright": copyright_flag,
    }
    values.update({c: 0 for c in CONSTANT_ZERO})
    values.update(TRAIN_MEDIAN)
    return {c: values[c] for c in CONTENT_FEATURES}
