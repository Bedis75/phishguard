# PhishGuard — Journal d'avancement

*Mis à jour le 18 octobre 2026. Date limite du projet : 1er novembre 2026.*

Ce document résume ce qui a été fait, pourquoi, avec quels résultats, et ce qui reste à faire. Tous les chiffres viennent des notebooks `01` à `05` et des scripts de `src/`.

---

## 1. Objectif du projet

Détecter les URL de phishing avec des **algorithmes classiques** (KNN, arbre de décision, Random Forest, SVM, K-Means), en un système **multicouche** (URL, contenu de la page, informations externes), **explicable** et **évalué honnêtement**, utilisable par un analyste SOC.

**Contribution visée :** pas « un meilleur score », mais un **score fiable**. Les publications annoncent 97–99,9 % sur des jeux de données qui contiennent des raccourcis. PhishGuard montre ces raccourcis, les évite (découpage par site, lignes de base simples, test sur données réelles) et publie une **ablation couche par couche**.

---

## 2. Les trois sources de données

| Source | Taille | Rôle | Pourquoi ce rôle |
| --- | --- | --- | --- |
| **PhiUSIIL** (UCI, 2024) | 235 795 URL | Étude de cas du **raccourci** | Une regex suffit à le résoudre (voir §3.2) : inutilisable pour l'entraînement. |
| **Hannousse & Yahiouche** (Mendeley, 2021) | 11 430 URL, 87 caractéristiques | **Jeu principal** d'entraînement | Légitimes variées (pages internes, `http`, sans `www`), 3 couches de caractéristiques fournies. |
| **Collecte live** (OpenPhish + Tranco) | 4 742 URL au 18/10 | **Test réel** | Vérifier le modèle sur des attaques actuelles (dérive). |

---

## 3. Ce qui a été fait, étape par étape

### 3.1 `01_first_look` — Premier aperçu de PhiUSIIL

- **Fait :** chargement, colonnes, répartition des classes, 10 URL au hasard.
- **Résultat :** 235 795 URL × 56 colonnes. **`label = 0` = phishing (100 945), `label = 1` = légitime (134 850)** — l'inverse de l'intuition, d'où l'importance de vérifier.
- **Observation :** toutes les légitimes de l'échantillon ont la forme `https://www.domaine.tld`, sans chemin.

### 3.2 `02_shortcut_check` — Mesure du raccourci de PhiUSIIL

- **Pourquoi :** vérifier sur tout le dataset ce que l'échantillon laissait voir.

| Critère | Phishing | Légitime |
| --- | --- | --- |
| HTTPS | 49,2 % | 100 % |
| `www.` | 41,4 % | 100 % |
| Commence par `https://www.` | 2,4 % | 100 % |
| Forme exacte `https://www.domaine` | 0,62 % | 100 % |
| `URLSimilarityIndex == 100` | 0,78 % | 100 % |

- **Ligne de base regex** `https://www\.[^/?#]+` (aucun ML) : précision phishing **1,0000**, rappel **0,9938**, F1 **0,9969**, accuracy **0,9973**.
- **Conclusions :**
  - PhiUSIIL se résout par la **forme de l'URL** : un score de 97–99,9 % sur ce jeu ne prouve pas la détection du phishing.
  - `URLSimilarityIndex` **fuit l'étiquette** → à exclure de tout entraînement.
  - PhiUSIIL n'est donc **pas** utilisé pour entraîner.

### 3.3 `03_mendeley_eda` — Analyse de Hannousse

- **Téléchargement :** version 3 depuis Mendeley, empreinte SHA-256 vérifiée, avec les scripts d'extraction des auteurs. Les fichiers `.pickle` (pages DOM, ≈ 310 Mo) n'ont **pas** été téléchargés : ouvrir un pickle peut exécuter du code, et ils contiennent des pages de phishing.
- **Données :** 11 430 URL, **5 715 phishing / 5 715 légitimes**, 0 valeur manquante, étiquette en texte (`status`).
- **Le raccourci de PhiUSIIL n'existe pas ici :**

| Règle (sans ML) | Dataset | Précision | Rappel | F1 | Accuracy |
| --- | --- | --- | --- | --- | --- |
| Regex `https://www.domaine` | PhiUSIIL | 1,0000 | 0,9938 | 0,9969 | 0,9973 |
| Regex `https://www.domaine` | Hannousse | 0,5011 | 0,9991 | 0,6674 | 0,5021 |
| `google_index == 1` | Hannousse | 0,8416 | 0,8987 | 0,8692 | 0,8647 |

- **Problèmes trouvés et décisions :**

| Problème | Détail | Décision |
| --- | --- | --- |
| URL en double | 1 URL collectée 2 fois, à 13 jours d'écart | Garder la première |
| Doublons de caractéristiques | 174 lignes, toutes phishing, 0 conflit d'étiquette ; 3 **campagnes multi-domaines** (`hf*.com`, `g22*.com`) | Retirer **avant** le découpage |
| Codes « inconnu » | `domain_age` (-1, -2, -12 ; 16 %), `domain_registration_length` (-1) | → `NaN`, puis médiane + indicatrice dans le `Pipeline` |
| Caractéristiques externes | `google_index`, `page_rank`, `web_traffic` mesurent la **popularité** ; une seule colonne donne 86,5 % | Résultats **avec et sans** la couche externe |
| Sens des codes | `google_index`, `dns_record`, `whois_registered_domain` : `0` = bon signe | Noté pour l'interprétation |

### 3.4 Collecteur live — étape 1 (`src/collector/`)

- **Fait :** `python -m src.collector.collect_urls` produit `data/live/AAAA-MM-JJ/urls_HHMM.csv` (heure UTC).
  - **Phishing :** flux public OpenPhish (≈ 300 URL, mis à jour à 00:00 et 12:00 UTC). Les URL sont **listées, jamais visitées**.
  - **Légitimes :** 100 domaines tirés au hasard dans le **top 100 000 Tranco**, 3 **pages internes** par domaine, trouvées sur la page d'accueil.
- **Pourquoi ces choix :**
  - **Pages internes**, pour ne pas recréer le raccourci de PhiUSIIL (`https://www.domaine` sans chemin).
  - **Top 100 000** et pas top 1 000, pour ne pas recréer le biais de popularité.
  - **Même fenêtre de temps** pour les deux classes.
  - Identifiant de la liste Tranco enregistré (reproductibilité).
- **Lancement :** à la main, **une fois par fenêtre OpenPhish** (après 01:00 et après 13:00, heure de Tunisie).
- **Collectes faites :** 13/10 (1), 14/10 (2), 15/10 (2), 16/10 (**0**, manqué), 17/10 (2), 18/10 (1) → **8 collectes**.
- **Premiers constats live :** la regex de PhiUSIIL ne reconnaît **aucune** légitime réelle ; 72,7 % du phishing est en HTTPS (contre 49 % dans PhiUSIIL) ; le phishing se concentre sur des hébergeurs gratuits (`pages.dev`, `vercel.app`, `blogspot.com`, `github.io`…).

### 3.5 `04_split` — Nettoyage et découpage par site

- **Nettoyage :** 11 430 → **11 255** lignes (1 doublon d'URL + 174 doublons de caractéristiques). Reste 5 540 phishing / 5 715 légitimes.
- **Définition d'un « site » (clé `group`) :**
  - domaine enregistré, **en traitant les sous-domaines des plateformes** (`appspot.com`, `blogspot.com`…) comme des sites distincts (`include_psl_private_domains=True`) ;
  - **nom d'hôte** pour les URL avec **adresse IP** (sinon 94 URL formaient un seul groupe vide) et pour 4 plateformes absentes de la liste (`sharepoint.com`, `000webhostapp.com`, `tumblr.com`, `wordpress.com`).
  - Résultat : **7 438 groupes**. Le plus gros est `duilawyeryork.com` (331 URL de phishing, un site compromis).
- **Découpage :** `StratifiedGroupKFold(5, shuffle=True, random_state=42)`, premier pli = test.
  - **Pourquoi ce choix plutôt que `GroupShuffleSplit` :** il garantit à la fois des sites séparés **et** les mêmes proportions de classes.

| | Lignes | Phishing | Groupes communs |
| --- | --- | --- | --- |
| Train (`train.csv`) | 9 003 (80 %) | 49,2 % | **0** |
| Test (`test_LOCKED.csv`) | 2 252 (20 %) | 49,2 % | **0** |

- **Test verrouillé :** SHA-256 `8cf8d62e96bd9dd6a37accdbfb65c26316f5e7689ef7511fa96f1718c6059be1`. Il ne sera ouvert **qu'une fois**, à l'évaluation finale.

### 3.6 `05_baselines` — Modèles, couches, ablation

**Méthode commune :** train uniquement ; validation croisée **groupée par site** (`GroupKFold(5)`) ; classe positive = phishing ; critère = **F1** ; `random_state=42`. Les 3 couches : **URL** (56 caractéristiques), **Contenu** (24), **Externe** (7).

**a) Pourquoi découper par site (RF, couche URL)**

| Métrique | Par site (`GroupKFold`) | Aléatoire (`KFold`) | Gonflement |
| --- | --- | --- | --- |
| F1 | 0,878 | 0,908 | **+3,0** |
| Précision | 0,873 | 0,911 | +3,8 |
| Rappel | 0,884 | 0,905 | +2,1 |
| ROC-AUC | 0,952 | 0,968 | +1,5 |

→ Le découpage aléatoire gonfle le F1 de 3 points par **mémorisation des sites**. Le choix du découpage pèse plus que le choix du modèle.

**b) 4 classifieurs × 3 couches (F1, réglages par défaut)**

| Modèle | URL | Contenu | Externe |
| --- | --- | --- | --- |
| KNN | 0,837 | 0,797 | 0,880 |
| Arbre | 0,821 | 0,762 | 0,862 |
| RF | **0,878** | 0,801 | **0,899** |
| SVM | 0,868 | **0,820** | 0,874 |

→ Les **7 caractéristiques externes battent les 56 caractéristiques URL** : elles mesurent la popularité. Le meilleur algorithme change selon la couche.

**c) Ablation : ce que chaque couche ajoute (F1)**

| Modèle | URL | + Contenu | + Externe |
| --- | --- | --- | --- |
| KNN | 0,837 | 0,853 | 0,897 |
| Arbre | 0,821 | 0,828 | 0,910 |
| **RF** | 0,878 | **0,917** | 0,955 |
| SVM | 0,868 | 0,905 | 0,939 |

→ Le contenu apporte **+3,8 points** au RF : il complète l'URL. L'externe en ajoute autant, mais grâce à la popularité (l'arbre seul gagne +8,3 points en s'appuyant sur `google_index`). **Chiffre de référence retenu : 0,917 (URL + Contenu).**

**d) Réglage des hyperparamètres (GridSearch, plis groupés)**

| Modèle | Résultat |
| --- | --- |
| RF (URL + Contenu), 12 combinaisons | Réglages **par défaut** optimaux, F1 **0,917 ± 0,018** |
| SVM (Contenu), 12 combinaisons | `C=10`, `gamma="scale"` : 0,820 → **0,835 ± 0,034** (gain non significatif) |

**e) Stacking**

| Approche | F1 | Écart-type |
| --- | --- | --- |
| **Fusion précoce** (un RF sur URL + Contenu) | **0,917** | 0,018 |
| Stacking (RF URL + SVM Contenu → arbre de profondeur 3) | 0,913 | 0,025 |

- `StackingClassifier` ne transmet pas les groupes à sa validation interne : les plis internes groupés lui sont passés à la main, pour éviter une fuite.
- **Pas de gain** (égalité statistique), cohérent avec l'état de l'art (+1–2 points au mieux). Méta-modèle en régression logistique : F1 0,916, même conclusion.

**Modèle retenu : Random Forest, réglages par défaut (300 arbres), couches URL + Contenu — F1 = 0,917 ± 0,018.** C'est le meilleur, le plus stable et le plus simple, et il est compatible avec SHAP.

### 3.7 Caractéristiques URL pour le live (`src/features/`)

- **Fait :** `src/features/url.py` recalcule les 56 caractéristiques URL de Hannousse pour n'importe quelle URL, en reproduisant le code des auteurs **y compris ses particularités** (`nb_dots` sur toute l'URL, `punycode` limité à `http://xn--`…).
- **Pourquoi à l'identique :** un modèle reçoit en production des valeurs calculées autrement qu'à l'entraînement se trompe en silence (*training-serving skew*).
- **Validation :** sur les 11 430 URL de Hannousse, **52/52** colonnes calculables depuis l'URL identiques aux valeurs des auteurs pour **≥ 99,95 %** des URL.
- **Non calculables depuis l'URL seule (NaN pour l'instant) :**
  - `random_domain` : module des auteurs non publié, **non informatif** (7,7 % vs 8,1 %) → à retirer du modèle ;
  - `nb_redirection`, `nb_external_redirection` : nécessitent de charger la page ;
  - `statistical_report` : nécessite une requête DNS.
- `python -m src.features.build_live` → `data/processed/live_url.csv` : **4 742 URL uniques** (2 400 phishing, 2 342 légitimes).

---

## 4. Décisions méthodologiques (à défendre à l'oral)

| Décision | Justification |
| --- | --- |
| Ne pas entraîner sur PhiUSIIL | Une regex d'une ligne atteint 99,7 % : le jeu mesure un biais de construction. |
| Toujours une ligne de base sans ML | Regex (PhiUSIIL), `google_index` (Hannousse, 0,869) : le ML doit faire nettement mieux. |
| Dédoublonner avant de découper | Sinon une copie peut finir en train et l'autre en test. |
| Découper par **site**, pas au hasard | Le découpage aléatoire gonfle le F1 de 3 points (mesuré). |
| Test verrouillé + SHA-256 | Évalué une seule fois ; l'empreinte prouve qu'il n'a pas été modifié. |
| F1, pas l'accuracy | À 1 % de phishing réel, l'accuracy ne veut plus rien dire. |
| Prétraitement dans le `Pipeline` | Médiane et normalisation apprises sur les plis d'entraînement seulement (pas de fuite). |
| Chiffre de référence sans la couche externe | Elle mesure la popularité, dépend de services disparus (Alexa) et du biais de sélection des légitimes. |
| Modèle le plus simple à performance égale | Le stacking n'apporte rien : rasoir d'Ockham. |

---

## 5. Limites connues

- **Écart-type de 2 à 3 points** entre plis : les différences de moins de ~2 points entre modèles ne sont pas significatives (test de McNemar prévu).
- **`google.com`** (149 URL, surtout `docs.google.com` / `sites.google.com`) reste un seul groupe : impossible de séparer des attaquants sur un même nom d'hôte.
- **Hannousse date de 2020** : la dérive vers 2026 n'est mesurable que sur la collecte live.
- **Collecte live :** cloaking, pages en JavaScript, sites qui disparaissent vite ; un jour de collecte manqué (16/10) ; Tranco contient aussi des sites pour adultes et de piratage (légitimes au sens « non-phishing »).
- **Traçabilité de Hannousse :** pour quelques URL, les caractéristiques ne correspondent pas exactement à l'URL stockée.

---

## 6. Prochaines étapes

| Priorité | Tâche | Qui | Pourquoi |
| --- | --- | --- | --- |
| 1 | **Collecteur étape 3** : HTML brut, redirections et IP, dans un **conteneur Docker isolé** | Claude (plan de sécurité validé d'abord) | Le modèle retenu a besoin du contenu ; les pages de phishing disparaissent en quelques heures. |
| 2 | **Seuil SOC** : rappel à 1 % de faux positifs, par validation croisée sur le train | Bedis | Le seuil 0,5 n'est pas adapté à un SOC. |
| 3 | Retirer `random_domain` du modèle final | Bedis | Non reproductible en live, non informatif. |
| 4 | Caractéristiques de **contenu** pour le live (24 colonnes, même méthode de validation) | Claude | Tester URL + Contenu en conditions réelles. |
| 5 | **Évaluation finale (24–27 oct.)** : test verrouillé (une seule fois), test live, McNemar, calibration | Bedis | Le résultat principal du rapport. |
| 6 | **SHAP** (3 raisons par verdict) et **K-Means** (campagnes, ex. `hf*.com`) | Bedis | Explicabilité et analyse des campagnes. |
| 7 | Dérive (semaine 1 contre semaine 2) et évasion légère (2–3 transformations d'URL) | Bedis | Robustesse hors laboratoire (résultat préliminaire). |
| 8 | Démo **Streamlit** | Claude | Présentation orale. |
| 9 | **Rapport + présentation (28–31 oct.)** | Bedis | Livrables. |

**Reportés en « perspectives »** (hors délai) : Wazuh, FastAPI, Docker (déploiement), MLflow, collecteur étape 2 (WHOIS/DNS/TLS).

**Collecte :** continuer deux fois par jour jusqu'au 27 octobre au moins.

---

## 7. Reproductibilité

| Élément | Où / comment |
| --- | --- |
| Environnement | conda `phishguard` (Python 3.11), `requirements.txt` |
| Données brutes | `data/raw/` (non versionné) ; Hannousse v3, SHA-256 vérifié |
| Découpage | `notebooks/04_split.ipynb` → `data/processed/train.csv`, `test_LOCKED.csv` (SHA-256 ci-dessus) |
| Graine aléatoire | `random_state=42` partout |
| Collecte | `python -m src.collector.collect_urls` (identifiant Tranco enregistré dans chaque fichier) |
| Caractéristiques live | `python -m src.features.build_live` |
| Historique | `git log` : un commit par étape |
