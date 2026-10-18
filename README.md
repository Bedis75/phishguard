# 🛡️ PhishGuard

**Détection de phishing explicable, évaluée honnêtement, pensée pour un analyste SOC.**

Projet de Machine Learning — M2 Mastère Professionnel Data Sciences, ISI Mahdia (2026). Algorithmes classiques uniquement : KNN, arbre de décision, Random Forest, SVM, K-Means.

> L'objectif n'est pas « un meilleur score », mais un **score fiable**. Les publications annoncent 97–99,9 % sur des jeux de données qui contiennent des raccourcis. PhishGuard montre ces raccourcis, les évite et mesure la performance au point de fonctionnement d'un SOC.

---

## Résultats clés

| Constat | Chiffre |
| --- | --- |
| Une **regex d'une ligne** résout PhiUSIIL (UCI 2024) sans aucun ML | accuracy **0,997** |
| La même regex sur Hannousse 2021 | accuracy **0,502** (hasard) |
| Une **seule colonne de popularité** (`google_index`) sur Hannousse | accuracy **0,865** |
| Découpage **aléatoire** au lieu d'un découpage **par site** | F1 gonflé de **+3 points** |
| Modèle retenu : Random Forest, URL + Contenu (validation croisée groupée) | F1 **0,917 ± 0,018** |
| Ablation (RF) : URL → + Contenu → + Externe (popularité) | 0,878 → **0,917** → 0,955 |
| Stacking (un modèle par couche + méta-modèle) | 0,913 : **pas de gain** |
| **Au point de fonctionnement SOC** (1 % de faux positifs) | rappel **0,61** |
| Précision réelle au seuil 0,5 si 1 % du trafic est du phishing | **0,11** (89 % de fausses alertes) |

Le détail (méthode, décisions, limites) est dans [`reports/avancement.md`](reports/avancement.md).

---

## Ce que fait PhishGuard

```
URL ──► téléchargement sécurisé (conteneur) ──► contenu exploitable ?
                                                 │
                            oui ◄────────────────┴────────────────► non (échec, page vide, JavaScript)
                             │                                       │
                RF URL + Contenu (79 colonnes)              RF URL seule (52 colonnes)
                             │                                       │
                             └──► 🔴 alerte haute / 🟠 à revoir / ⚪ pas d'alerte
                                  + probabilité + 3 raisons SHAP en français
                                  + famille d'attaque la plus proche (K-Means)
```

- **Tri à deux niveaux** : 🔴 ≥ 0,1 % de faux positifs (blocage possible), 🟠 ≥ 1 % (revue par un analyste). Seuils fixés sur le train.
- **Explicable** : chaque verdict affiche ce qui inquiète et ce qui rassure le modèle (valeurs SHAP traduites en phrases).
- **Campagnes** : 8 familles d'attaque trouvées par K-Means (faux sous-domaines de marque, sites WordPress compromis, hébergement sur IP…).

---

## Données

| Source | Rôle | Accès |
| --- | --- | --- |
| **PhiUSIIL** (UCI, 2024) — 235 795 URL | Étude de cas du raccourci (pas d'entraînement) | [UCI ML Repository](https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset) |
| **Hannousse & Yahiouche** (Mendeley, 2021) — 11 430 URL, 87 caractéristiques | Jeu principal d'entraînement | [Mendeley Data, v3](https://data.mendeley.com/datasets/c2gw7fy2j4/3) |
| **Collecte live** — OpenPhish (phishing) + pages internes Tranco (légitimes) | Test en conditions réelles, dérive | `src/collector/` |

Les données ne sont **pas** dans le dépôt (`data/` est ignoré par Git).

---

## Structure

```
phishguard/
├── notebooks/            # analyse, dans l'ordre :
│   ├── 01_first_look         PhiUSIIL : aperçu, sens de l'étiquette
│   ├── 02_shortcut_check     PhiUSIIL : raccourci, ligne de base regex, fuite d'étiquette
│   ├── 03_mendeley_eda       Hannousse : doublons, codes « inconnu », biais de popularité
│   ├── 04_split              nettoyage, découpage 80/20 par site, test verrouillé (SHA-256)
│   ├── 05_baselines          4 classifieurs × 3 couches, ablation, GridSearch, stacking
│   ├── 06_threshold          seuils SOC, précision à prévalence réelle, tri à deux niveaux
│   ├── 07_shap               explicabilité globale et par alerte
│   ├── 08_live_model         modèle URL seule, seuils, sauvegarde des modèles
│   └── 09_kmeans             familles d'attaque (K-Means)
├── src/
│   ├── collector/        # collecte live : URL (OpenPhish, Tranco), pages HTML en conteneur, automatisation
│   ├── features/         # caractéristiques URL (reproduction validée) et contenu (approximative)
│   └── predict.py        # cascade PhishGuard (téléchargement → modèle → seuils → SHAP → campagne)
├── app/                  # interface Streamlit (lancée dans un conteneur)
├── docker/               # conteneurs isolés : collecteur (fetcher) et interface (app)
├── models/               # thresholds.json (versionné) ; *.joblib régénérés par 08 et 09
├── reports/avancement.md # journal détaillé : ce qui a été fait, pourquoi, résultats, limites
└── requirements.txt
```

---

## Installation

Environnement : Windows + WSL Ubuntu 24.04, conda, Docker Desktop (intégration WSL activée).

```bash
conda create -n phishguard python=3.11 -y
conda activate phishguard
pip install -r requirements.txt
```

Placer les jeux de données dans `data/raw/` (`PhiUSIIL_Phishing_URL_Dataset.csv` et `hannousse_2021/dataset_B_05_2020.csv`), puis exécuter les notebooks **dans l'ordre** de `01` à `09` (`04` crée le train et le test, `08` et `09` créent les modèles).

---

## Utilisation

**Interface** (Docker Desktop ouvert) :

```bash
bash app/run.sh          # puis http://localhost:8501
```

**Collecte live** — une passe complète (URL + pages) :

```bash
bash src/collector/collect.sh
```

Collecte automatique deux fois par jour (01:15 et 13:15, 15 minutes après chaque mise à jour d'OpenPhish) via le Planificateur de tâches Windows :

```bash
powershell.exe -ExecutionPolicy Bypass -File "$(wslpath -w src/collector/schedule_windows.ps1)"
```

**Caractéristiques URL des données live** :

```bash
python -m src.features.build_live      # -> data/processed/live_url.csv
```

---

## Sécurité

La collecte et l'interface téléchargent de **vraies pages de phishing**. Elles le font uniquement :
- avec `requests` : **aucun JavaScript exécuté**, aucun formulaire envoyé, 2 Mo maximum, texte/HTML seulement ;
- en refusant toute redirection vers une adresse **privée ou locale** (box, réseau local) ;
- **dans un conteneur Docker** en lecture seule, sans privilèges, utilisateur non-root, mémoire et CPU limités ; l'interface n'écoute que sur `127.0.0.1`.

Le HTML est stocké compressé (`.gz`) et ne doit **jamais** être ouvert dans un navigateur.

---

## Limites connues

- **Écart-type de 2 à 3 points** entre plis : les différences de moins de ~2 points ne sont pas significatives.
- **Couche contenu non reproductible fidèlement** : le code publié par les auteurs de Hannousse ne correspond pas à leur CSV, et 5 colonnes de contenu sont constantes. Le test live porte donc sur la couche URL ; l'interface utilise une reproduction approximative du contenu (signalée à l'écran).
- **Pages rendues en JavaScript** : ~45 % du phishing collecté en octobre 2026 (campagne `pages.dev`) paraît vide sans navigateur.
- **Pages de connexion légitimes** : elles ressemblent au phishing et sont rares dans les légitimes de Hannousse (ex. plateformes universitaires tunisiennes en `.tn`).
- **Rappel limité au point SOC** : environ 6 phishing sur 10 détectés à 1 % de faux positifs.

---

## Références

- A. Hannousse, S. Yahiouche (2021). *Web page phishing detection*. Mendeley Data, v3. doi:10.17632/c2gw7fy2j4.3
- PhiUSIIL Phishing URL Dataset (2024). UCI Machine Learning Repository.
- D. Arp et al. (2022). *Dos and Don'ts of Machine Learning in Computer Security*. USENIX Security.
- F. Pendlebury et al. (2019). *TESSERACT: Eliminating Experimental Bias in Malware Classification across Space and Time*. USENIX Security.
- Tranco (classement de domaines), OpenPhish (flux public de phishing).
