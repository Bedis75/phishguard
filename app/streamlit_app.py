"""Démo PhishGuard : une URL -> niveau d'alerte, probabilité, 3 raisons, campagne.

Lancée par `bash app/run.sh`, DANS un conteneur isolé (la page saisie est réellement téléchargée).
"""

import json

import streamlit as st

from src.predict import PhishGuard

st.set_page_config(page_title="PhishGuard", page_icon="🛡️", layout="centered")

TIERS = {
    "high":   ("🔴 ALERTE HAUTE", "error",   "Blocage automatique possible (≤ 0,1 % de faux positifs sur le train)."),
    "review": ("🟠 À REVOIR",     "warning", "À vérifier par un analyste (≤ 1 % de faux positifs sur le train)."),
    "none":   ("⚪ PAS D'ALERTE", "success", "Sous le seuil de revue."),
}
BRANCHES = {
    "url_content": "URL + Contenu (notebook 06)",
    "url_only": "URL seule (notebook 08)",
}


@st.cache_resource
def load_model():
    return PhishGuard()


st.title("🛡️ PhishGuard")
st.caption("Détection de phishing explicable — M2 Data Sciences, ISI Mahdia. "
           "Démo de recherche : ne remplace pas un outil de sécurité en production.")

with st.form("analyse"):
    url = st.text_input("URL à analyser", placeholder="https://exemple.com/connexion")
    submitted = st.form_submit_button("Analyser")

st.info("La page est téléchargée **dans un conteneur isolé**, sans exécuter de JavaScript. "
        "N'ouvrez jamais une URL suspecte dans votre navigateur.", icon="🔒")

if submitted and url.strip():
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    with st.spinner("Téléchargement et analyse…"):
        verdict = load_model().analyze(url)

    label, kind, help_text = TIERS[verdict["tier"]]
    getattr(st, kind)(f"**{label}** — probabilité de phishing : **{verdict['probability']:.2f}**")
    st.caption(help_text)

    col1, col2 = st.columns(2)
    col1.metric("Modèle utilisé", BRANCHES[verdict["branch"]])
    col2.metric("Seuils (revue / haute)", f"{verdict['thresholds']['review']:.2f} / {verdict['thresholds']['high']:.2f}")
    st.caption(f"Pourquoi ce modèle : {verdict['branch_reason']}")

    st.caption(f"Point de départ du modèle (probabilité moyenne sur le train) : {verdict['base_value']:.2f}. "
               "Chaque raison ajoute ou retire une part de probabilité (valeurs SHAP).")
    left, right = st.columns(2)
    for col, title, items in ((left, "⬆️ Ce qui inquiète", verdict["concerns"]),
                              (right, "⬇️ Ce qui rassure", verdict["reassurances"])):
        col.subheader(title)
        if not items:
            col.write("—")
        for r in items:
            col.markdown(f"- {r['text']}  \n  <small>`{r['feature']}` · {r['contribution']:+.3f}</small>",
                         unsafe_allow_html=True)

    if verdict["campaign"]:
        st.subheader("Famille d'attaque la plus proche")
        st.write(f"Ressemble au groupe **{verdict['campaign']}** (K-Means, notebook 09).")

    if verdict["branch"] == "url_content":
        st.warning("Branche URL + Contenu : les caractéristiques de contenu sont une reproduction approximative "
                   "de celles de Hannousse (résultat indicatif).", icon="⚠️")

    with st.expander("Détails techniques"):
        fetch = dict(verdict["fetch"])
        fetch["history"] = json.loads(fetch["history"] or "[]")
        st.json(fetch)
