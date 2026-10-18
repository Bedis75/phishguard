"""Caractéristiques URL de Hannousse & Yahiouche (2021), recalculées pour les données live.

Reproduit `url_features.py` et la construction de ligne de `feature_extractor.py` des auteurs
(data/raw/hannousse_2021/scripts/), Y COMPRIS leurs particularités, pour que le modèle entraîné
sur Hannousse reçoive des valeurs calculées de la même façon :
- `nb_dots` compte les points de toute l'URL (pas seulement du nom d'hôte) ;
- `punycode` ne détecte que `http://xn--` (le test `https://` des auteurs est écrit `http://` deux fois) ;
- `nb_qm` compte les `?` (fonction `count_exclamation` des auteurs).

Trois groupes de colonnes ne se calculent pas à partir de l'URL seule :
- `random_domain` : module `word_with_nlp` absent des scripts publiés -> non reproductible (NaN) ;
- `nb_redirection`, `nb_external_redirection` : nécessitent de charger la page -> paramètre `history` ;
- `statistical_report` : nécessite une résolution DNS -> paramètre `ip` (None = échec DNS).
"""

import re
from pathlib import Path
from urllib.parse import urlparse, urlsplit

import tldextract

BRANDS_FILE = Path(__file__).resolve().parents[2] / "data/raw/hannousse_2021/scripts/allbrands.txt"
ALLBRAND = [line.strip() for line in BRANDS_FILE.read_text().splitlines()]

HINTS = ['wp', 'login', 'includes', 'admin', 'content', 'site', 'images', 'js', 'alibaba', 'css',
         'myaccount', 'dropbox', 'themes', 'plugins', 'signin', 'view']

SUSPICIOUS_TLDS = [
    'fit', 'tk', 'gp', 'ga', 'work', 'ml', 'date', 'wang', 'men', 'icu', 'online', 'click',
    'country', 'stream', 'download', 'xin', 'racing', 'jetzt', 'ren', 'mom', 'party', 'review',
    'trade', 'accountants', 'science', 'work', 'ninja', 'xyz', 'faith', 'zip', 'cricket', 'win',
    'accountant', 'realtor', 'top', 'christmas', 'gdn', 'link', 'asia', 'club', 'la', 'ae',
    'exposed', 'pe', 'go.id', 'rs', 'k12.pa.us', 'or.kr', 'ce.ke', 'audio', 'gob.pe', 'gov.az',
    'website', 'bj', 'mx', 'media', 'sa.gov.au',
]

IP_RE = re.compile(
    '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
    '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'
    '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)|'
    '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}|'
    '[0-9a-fA-F]{7}')

SHORTENER_RE = re.compile(
    'bit\\.ly|goo\\.gl|shorte\\.st|go2l\\.ink|x\\.co|ow\\.ly|t\\.co|tinyurl|tr\\.im|is\\.gd|cli\\.gs|'
    'yfrog\\.com|migre\\.me|ff\\.im|tiny\\.cc|url4\\.eu|twit\\.ac|su\\.pr|twurl\\.nl|snipurl\\.com|'
    'short\\.to|BudURL\\.com|ping\\.fm|post\\.ly|Just\\.as|bkite\\.com|snipr\\.com|fic\\.kr|loopt\\.us|'
    'doiop\\.com|short\\.ie|kl\\.am|wp\\.me|rubyurl\\.com|om\\.ly|to\\.ly|bit\\.do|t\\.co|lnkd\\.in|'
    'db\\.tt|qr\\.ae|adf\\.ly|goo\\.gl|bitly\\.com|cur\\.lv|tinyurl\\.com|ow\\.ly|bit\\.ly|ity\\.im|'
    'q\\.gs|is\\.gd|po\\.st|bc\\.vc|twitthis\\.com|u\\.to|j\\.mp|buzurl\\.com|cutt\\.us|u\\.bb|yourls\\.org|'
    'x\\.co|prettylinkpro\\.com|scrnch\\.me|filoops\\.info|vzturl\\.com|qr\\.net|1url\\.com|tweez\\.me|v\\.gd|'
    'tr\\.im|link\\.zip\\.net')

PORT_RE = re.compile(
    "^[a-z][a-z0-9+\\-.]*://([a-z0-9\\-._~%!$&'()*+,;=]+@)?([a-z0-9\\-._~%]+|"
    "\\[[a-z0-9\\-._~%!$&'()*+,;=:]+\\]):([0-9]+)")

STAT_URL_RE = re.compile(
    'at\\.ua|usa\\.cc|baltazarpresentes\\.com\\.br|pe\\.hu|esy\\.es|hol\\.es|sweddy\\.com|myjino\\.ru|96\\.lt|ow\\.ly')
STAT_IP_RE = re.compile(
    '146\\.112\\.61\\.108|213\\.174\\.157\\.151|121\\.50\\.168\\.88|192\\.185\\.217\\.116|78\\.46\\.211\\.158|'
    '181\\.174\\.165\\.13|46\\.242\\.145\\.103|121\\.50\\.168\\.40|83\\.125\\.22\\.219|46\\.242\\.145\\.98|'
    '107\\.151\\.148\\.44|107\\.151\\.148\\.107|64\\.70\\.19\\.203|199\\.184\\.144\\.27|107\\.151\\.148\\.108|'
    '107\\.151\\.148\\.109|119\\.28\\.52\\.61|54\\.83\\.43\\.69|52\\.69\\.166\\.231|216\\.58\\.192\\.225|'
    '118\\.184\\.25\\.86|67\\.208\\.74\\.71|23\\.253\\.126\\.58|104\\.239\\.157\\.210|175\\.126\\.123\\.219|'
    '141\\.8\\.224\\.221|10\\.10\\.10\\.10|43\\.229\\.108\\.32|103\\.232\\.215\\.140|69\\.172\\.201\\.153|'
    '216\\.218\\.185\\.162|54\\.225\\.104\\.146|103\\.243\\.24\\.98|199\\.59\\.243\\.120|31\\.170\\.160\\.61|'
    '213\\.19\\.128\\.77|62\\.113\\.226\\.131|208\\.100\\.26\\.234|195\\.16\\.127\\.102|195\\.16\\.127\\.157|'
    '34\\.196\\.13\\.28|103\\.224\\.212\\.222|172\\.217\\.4\\.225|54\\.72\\.9\\.51|192\\.64\\.147\\.141|'
    '198\\.200\\.56\\.183|23\\.253\\.164\\.103|52\\.48\\.191\\.26|52\\.214\\.197\\.72|87\\.98\\.255\\.18|'
    '209\\.99\\.17\\.27|216\\.38\\.62\\.18|104\\.130\\.124\\.96|47\\.89\\.58\\.141|78\\.46\\.211\\.158|'
    '54\\.86\\.225\\.156|54\\.82\\.156\\.19|37\\.157\\.192\\.102|204\\.11\\.56\\.48|110\\.34\\.231\\.42')

WORD_SPLIT_RE = re.compile(r"\-|\.|\/|\?|\=|\@|\&|\%|\:|\_")

# Même ordre et mêmes noms que les colonnes du CSV Hannousse (length_url -> statistical_report)
URL_FEATURES = [
    "length_url", "length_hostname", "ip", "nb_dots", "nb_hyphens", "nb_at", "nb_qm", "nb_and",
    "nb_or", "nb_eq", "nb_underscore", "nb_tilde", "nb_percent", "nb_slash", "nb_star", "nb_colon",
    "nb_comma", "nb_semicolumn", "nb_dollar", "nb_space", "nb_www", "nb_com", "nb_dslash",
    "http_in_path", "https_token", "ratio_digits_url", "ratio_digits_host", "punycode", "port",
    "tld_in_path", "tld_in_subdomain", "abnormal_subdomain", "nb_subdomains", "prefix_suffix",
    "random_domain", "shortening_service", "path_extension", "nb_redirection",
    "nb_external_redirection", "length_words_raw", "char_repeat", "shortest_words_raw",
    "shortest_word_host", "shortest_word_path", "longest_words_raw", "longest_word_host",
    "longest_word_path", "avg_words_raw", "avg_word_host", "avg_word_path", "phish_hints",
    "domain_in_brand", "brand_in_subdomain", "brand_in_path", "suspecious_tld", "statistical_report",
]

# Colonnes qui ne dépendent pas que de l'URL (voir docstring du module)
NOT_FROM_URL = ["random_domain", "nb_redirection", "nb_external_redirection", "statistical_report"]

_extract = tldextract.TLDExtract(include_psl_private_domains=False)  # défaut de tldextract en 2020


def _words(text):
    return [w for w in WORD_SPLIT_RE.split(text.lower()) if w]


def _ratio_digits(text):
    return len(re.sub("[^0-9]", "", text)) / len(text) if text else 0


def _char_repeat(words):
    count = 0
    for word in words:
        for n in (2, 3, 4, 5):
            for i in range(len(word) - n + 1):
                sub = word[i:i + n]
                if all(c == sub[0] for c in sub):
                    count += 1
    return count


def _brand_in_path(domain, path):
    return int(any('.' + b + '.' in path and b not in domain for b in ALLBRAND))


def _stats(words):
    if not words:
        return 0, 0, 0
    lengths = [len(w) for w in words]
    return min(lengths), max(lengths), sum(lengths) / len(lengths)


def url_features(url, history=None, ip=None):
    """Les 56 caractéristiques URL d'une URL, dans l'ordre de `URL_FEATURES`.

    history : liste des URL intermédiaires des redirections (None = page non chargée -> NaN).
    ip      : adresse IP résolue du domaine (None = pas tentée -> NaN ; "" = résolution échouée -> 2, comme les auteurs).
    """
    hostname = urlsplit(url).hostname or ""
    ext = _extract(url)
    domain = ext.domain + "." + ext.suffix
    subdomain, tld = ext.subdomain, ext.suffix
    # Comme les auteurs : 1re occurrence du suffixe dans l'URL (suffixe vide pour une IP -> début de l'URL)
    pth = url[url.find(tld):].partition("/")
    path = pth[1] + pth[2]
    scheme = urlparse(url).scheme

    words_raw = _words(ext.domain) + _words(pth[2]) + _words(subdomain)
    words_host = _words(ext.domain) + _words(subdomain)
    words_path = _words(pth[2])
    s_raw, l_raw, a_raw = _stats(words_raw)
    s_host, l_host, a_host = _stats(words_host)
    s_path, l_path, a_path = _stats(words_path)

    dslash = [m.start(0) for m in re.finditer("//", url)]
    n_dots_url = url.count(".")

    if history is None:
        nb_redirection = nb_external_redirection = float("nan")
    else:
        nb_redirection = len(history)
        # Reproduit la fonction des auteurs : le `return` est dans la boucle -> seul le 1er saut compte
        nb_external_redirection = int(bool(history) and domain.lower() not in history[0].lower())

    if ip is None:
        statistical_report = float("nan")
    elif ip == "":
        statistical_report = 2  # `except: return 2` des auteurs (échec DNS)
    elif STAT_URL_RE.search(url) or STAT_IP_RE.search(ip):
        statistical_report = 1
    else:
        statistical_report = 0

    values = [
        len(url), len(hostname), int(bool(IP_RE.search(url))), n_dots_url, url.count("-"),
        url.count("@"), url.count("?"), url.count("&"), url.count("|"), url.count("="),
        url.count("_"), int("~" in url), url.count("%"), url.count("/"), url.count("*"),
        url.count(":"), url.count(","), url.count(";"), url.count("$"),
        url.count(" ") + url.count("%20"),
        sum("www" in w for w in words_raw), sum("com" in w for w in words_raw),
        int(dslash[-1] > 6) if dslash else 0,
        path.count("http"), 0 if scheme == "https" else 1,
        _ratio_digits(url), _ratio_digits(hostname),
        int(url.startswith("http://xn--")), int(bool(PORT_RE.search(url))),
        int(path.lower().count(tld) > 0), int(subdomain.count(tld) > 0),
        int(bool(re.search(r"(http[s]?://(w[w]?|\d))([w]?(\d|-))", url))),
        min(n_dots_url, 3) if n_dots_url >= 1 else 3,
        int(bool(re.findall(r"https?://[^\-]+-[^\-]+/", url))),
        float("nan"), int(bool(SHORTENER_RE.search(url))), int(path.endswith(".txt")),
        nb_redirection, nb_external_redirection,
        len(words_raw), _char_repeat(words_raw),
        s_raw, s_host, s_path, l_raw, l_host, l_path, a_raw, a_host, a_path,
        sum(url.lower().count(h) for h in HINTS),
        int(ext.domain in ALLBRAND), _brand_in_path(ext.domain, subdomain), _brand_in_path(ext.domain, path),
        int(tld in SUSPICIOUS_TLDS), statistical_report,
    ]
    return dict(zip(URL_FEATURES, values))
