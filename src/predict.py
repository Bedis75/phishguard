"""PhishGuard : analyse d'une URL en cascade (modèle URL + Contenu, sinon modèle URL seule).

À LANCER DANS LE CONTENEUR de l'interface (docker/app/) : la page est réellement téléchargée.

    from src.predict import PhishGuard
    verdict = PhishGuard().analyze("https://exemple.com/login")

Cascade (décision du 18/10, reports/avancement.md §3.9) :
1. Téléchargement sécurisé de la page (src/collector/fetch_pages.download).
2. Contenu utilisable (page 200 + HTML avec au moins un lien) -> modèle URL + Contenu (notebook 06).
   Sinon (échec, page vide ou rendue en JavaScript) -> modèle URL seule (notebook 08).
3. Seuils SOC du modèle utilisé (models/thresholds.json), 3 raisons SHAP, campagne K-Means (notebook 09).
"""

import json
from pathlib import Path

import joblib
import pandas as pd
import requests
import shap

from .collector.fetch_pages import download
from .features.content import content_features
from .features.url import url_features

ROOT = Path(__file__).resolve().parents[1]
MODELS = ROOT / "models"

# Phrases pour l'analyste (codages inversés des auteurs corrigés) ; les autres colonnes gardent leur nom
PHRASES = {
    "nb_hyperlinks":        lambda v: f"{v:.0f} lien(s) sur la page",
    "nb_www":               lambda v: "pas de « www » dans l'adresse" if v == 0 else f"« www » apparaît {v:.0f} fois",
    "phish_hints":          lambda v: f"{v:.0f} mot(s) sensible(s) dans l'URL (login, signin, admin…)",
    "safe_anchor":          lambda v: f"{v:.0f} % de liens vides ou JavaScript",
    "longest_word_path":    lambda v: f"jeton de {v:.0f} caractères dans le chemin",
    "longest_words_raw":    lambda v: f"jeton de {v:.0f} caractères dans l'URL",
    "longest_word_host":    lambda v: f"mot de {v:.0f} caractères dans le nom d'hôte",
    "ratio_digits_url":     lambda v: f"{v:.0%} de chiffres dans l'URL",
    "ratio_digits_host":    lambda v: f"{v:.0%} de chiffres dans le nom d'hôte",
    "domain_in_title":      lambda v: "le titre de la page ne mentionne pas le domaine" if v == 1 else "le titre mentionne le domaine",
    "ratio_extHyperlinks":  lambda v: f"{v:.0%} des liens pointent vers d'autres sites",
    "ratio_intHyperlinks":  lambda v: f"{v:.0%} des liens restent sur le site",
    "length_url":           lambda v: f"URL de {v:.0f} caractères",
    "length_hostname":      lambda v: f"nom d'hôte de {v:.0f} caractères",
    "nb_dots":              lambda v: f"{v:.0f} point(s) dans l'URL",
    "nb_hyphens":           lambda v: f"{v:.0f} tiret(s) dans l'URL",
    "nb_slash":             lambda v: f"{v:.0f} barre(s) « / » dans l'URL",
    "nb_qm":                lambda v: f"{v:.0f} « ? » dans l'URL",
    "nb_eq":                lambda v: f"{v:.0f} paramètre(s) « = » dans l'URL",
    "nb_com":               lambda v: f"« com » apparaît {v:.0f} fois dans l'URL",
    "tld_in_subdomain":     lambda v: "une extension (.com…) apparaît dans le sous-domaine" if v else "pas d'extension dans le sous-domaine",
    "tld_in_path":          lambda v: "une extension (.com…) apparaît dans le chemin" if v else "pas d'extension dans le chemin",
    "prefix_suffix":        lambda v: "tiret dans le nom de domaine" if v else "pas de tiret dans le nom de domaine",
    "https_token":          lambda v: "pas de HTTPS" if v else "HTTPS",
    "ip":                   lambda v: "adresse IP au lieu d'un nom de domaine" if v else "nom de domaine (pas d'IP)",
    "suspecious_tld":       lambda v: "extension réputée suspecte (.xyz, .top…)" if v else "extension courante",
    "shortening_service":   lambda v: "raccourcisseur d'URL (bit.ly…)" if v else "pas de raccourcisseur",
    "abnormal_subdomain":   lambda v: "sous-domaine anormal (wwww-, ww1…)" if v else "sous-domaine normal",
    "nb_subdomains":        lambda v: f"{v:.0f} niveau(x) de sous-domaine",
    "char_repeat":          lambda v: f"{v:.0f} répétition(s) de caractères",
    "domain_in_brand":      lambda v: "le domaine est une marque connue" if v else "le domaine n'est pas une marque connue",
    "brand_in_subdomain":   lambda v: "une marque connue apparaît dans le sous-domaine" if v else "pas de marque dans le sous-domaine",
    "brand_in_path":        lambda v: "une marque connue apparaît dans le chemin" if v else "pas de marque dans le chemin",
    "length_words_raw":     lambda v: f"{v:.0f} mot(s) dans l'URL",
    "shortest_words_raw":   lambda v: f"mot le plus court de l'URL : {v:.0f} caractère(s)",
    "shortest_word_host":   lambda v: f"mot le plus court du nom d'hôte : {v:.0f} caractère(s)",
    "shortest_word_path":   lambda v: f"mot le plus court du chemin : {v:.0f} caractère(s)",
    "avg_words_raw":        lambda v: f"longueur moyenne des mots de l'URL : {v:.1f}",
    "avg_word_host":        lambda v: f"longueur moyenne des mots du nom d'hôte : {v:.1f}",
    "avg_word_path":        lambda v: f"longueur moyenne des mots du chemin : {v:.1f}",
    "nb_and":               lambda v: f"{v:.0f} « & » dans l'URL",
    "nb_underscore":        lambda v: f"{v:.0f} « _ » dans l'URL",
    "nb_percent":           lambda v: f"{v:.0f} caractère(s) encodé(s) « % »",
    "nb_dslash":            lambda v: "« // » au milieu de l'URL (redirection cachée)" if v else "pas de « // » suspect",
    "http_in_path":         lambda v: f"« http » apparaît {v:.0f} fois dans le chemin",
    "ratio_intMedia":       lambda v: f"{v:.0f} % des images/médias sont locaux",
    "ratio_extMedia":       lambda v: f"{v:.0f} % des images/médias viennent d'ailleurs",
    "ratio_extRedirection": lambda v: f"ratio_extRedirection = {v} (valeur par défaut, non mesurée)",
    "external_favicon":     lambda v: "icône du site chargée depuis un autre domaine" if v else "icône du site locale",
    "empty_title":          lambda v: "page sans titre" if v else "page avec un titre",
    "login_form":           lambda v: "formulaire de connexion suspect" if v else "pas de formulaire suspect",
    "links_in_tags":        lambda v: f"{v:.0f} % des ressources <link>/<script> sont locales",
    "nb_extCSS":            lambda v: f"{v:.0f} feuille(s) de style externe(s)",
    "domain_with_copyright": lambda v: "mention © sans le nom du domaine" if v else "mention © cohérente ou absente",
    "nb_redirection":       lambda v: f"{v:.0f} redirection(s) avant la page",
    "statistical_report":   lambda v: {0: "IP absente des listes connues", 1: "IP ou domaine dans une liste de phishing connue",
                                       2: "domaine qui ne se résout pas (DNS)"}.get(int(v), f"statistical_report = {v}"),
}


def phrase(feature, value):
    return PHRASES.get(feature, lambda v: f"{feature} = {v}")(value)


class PhishGuard:
    def __init__(self):
        cfg = json.loads((MODELS / "thresholds.json").read_text())
        self.branches = {}
        for name in ("url_content", "url_only"):
            model = joblib.load(MODELS / cfg[name]["model"])
            self.branches[name] = {**cfg[name], "rf": model, "explainer": shap.TreeExplainer(model)}
        campaigns = MODELS / "kmeans_campaigns.joblib"
        self.campaigns = joblib.load(campaigns) if campaigns.exists() else None
        self.session = requests.Session()

    def analyze(self, url, k=3):
        info, html = download(self.session, url)

        content = content_features(url, html) if html is not None else None
        usable = content is not None and content["nb_hyperlinks"] > 0
        if usable:
            branch_name = "url_content"
            history = json.loads(info["history"] or "[]")
            feats = {**url_features(url, history=history, ip=info["ip"]), **content}
            why_branch = "page téléchargée et exploitable"
        else:
            branch_name = "url_only"
            feats = url_features(url)
            why_branch = ("page non téléchargée : " + (info["error"] or f"code HTTP {info['status_code']}")
                          if html is None else "page sans aucun lien (vide ou rendue en JavaScript)")

        branch = self.branches[branch_name]
        x = pd.DataFrame([feats])[branch["columns"]]
        proba = float(branch["rf"].predict_proba(x)[0, 1])
        if proba >= branch["high"]:
            tier = "high"
        elif proba >= branch["review"]:
            tier = "review"
        else:
            tier = "none"

        contrib = pd.Series(branch["explainer"](x)[0, :, 1].values, index=branch["columns"])

        def describe(items):
            return [{"feature": f, "value": float(x[f].iloc[0]), "contribution": float(c),
                     "text": phrase(f, x[f].iloc[0])} for f, c in items]

        # Les deux côtés, quel que soit le niveau : ce qui inquiète et ce qui rassure
        concerns = describe(contrib[contrib > 0].sort_values(ascending=False).head(k).items())
        reassurances = describe(contrib[contrib < 0].sort_values().head(k).items())

        campaign = None
        if usable and self.campaigns is not None and tier != "none":
            cluster = int(self.campaigns["model"].predict(pd.DataFrame([feats])[self.campaigns["columns"]])[0])
            campaign = self.campaigns["names"][cluster]

        return {
            "url": url, "probability": proba, "tier": tier,
            "branch": branch_name, "branch_reason": why_branch,
            "thresholds": {"review": branch["review"], "high": branch["high"]},
            "base_value": float(branch["explainer"].expected_value[1]),
            "concerns": concerns, "reassurances": reassurances, "campaign": campaign,
            "fetch": {k_: info[k_] for k_ in ("status_code", "final_url", "history", "ip", "error")},
        }
