# PhishGuard — Journal d'avancement

*Mis à jour le 18 octobre 2026 (soir). Date limite du projet : 1er novembre 2026.*

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

### 3.8 Collecteur live — étape 3 : pages HTML dans un conteneur isolé

- **Fait :** `bash src/collector/collect.sh` enchaîne l'étape 1 (listes d'URL) et l'étape 3 : `src/collector/fetch_pages.py` télécharge le HTML **dans un conteneur Docker** (`docker/fetcher/`).
- **Mêmes conditions que les auteurs de Hannousse :** `requests`, délai de 5 s, identifiant `python-requests`, seules les réponses 200 sont gardées.
- **Sécurité :**

| Protection | Effet |
| --- | --- |
| `requests` uniquement | Aucun JavaScript exécuté, aucun formulaire envoyé |
| Redirections suivies à la main | Refusées vers une adresse privée ou locale (box, réseau local) — testé sur `127.0.0.1`, `localhost`, `192.168.1.1` |
| Texte/HTML seulement, 2 Mo max | Pas de fichiers exécutables |
| HTML stocké en `.gz` | Ne peut pas s'ouvrir par un double-clic |
| Conteneur `--read-only`, `--cap-drop ALL`, `no-new-privileges`, utilisateur non-root, 1 Go / 2 CPU | Aucun privilège ; seul le dossier du jour est accessible en écriture |

- **Sortie :** `pages_HHMM.csv` (statut, URL finale, redirections, IP, erreur) + `html/*.html.gz`.
- **Première collecte complète (18/10, 14:35 UTC) :**

| | Légitimes | Phishing |
| --- | --- | --- |
| Pages téléchargées | 246 / 294 (84 %) | 188 / 300 (63 %) |
| Avec au moins une redirection | 6 % | **33 %** |
| Taille médiane | ~100 Ko | **715 octets** |
| Redirections bloquées | 0 | 0 |

- **Découverte : une campagne domine les données live.** 183 des 300 URL de phishing de cette collecte (et **1 078 / 2 400, soit 45 %**, sur toutes les collectes) sont sur `pages.dev`, avec la même page « Meta for Business | Page Appeal ». 84 répondent 403 ; les autres renvoient une **coquille JavaScript vide** de 715 octets, sans contenu visible sans navigateur.
- **Conséquences :** présenter les résultats live **avec et sans `pages.dev`** ; la couche contenu est aveugle sur ces pages ; c'est une **dérive** par rapport à 2020 (kits en JavaScript sur hébergeurs gratuits).

### 3.9 Couche contenu en live : non reproductible

- **Constat en lisant le code des auteurs :**
  - le code publié **n'est pas celui qui a produit le CSV** (`nb_hyperlinks(dom)` prend 1 argument mais est appelé avec 6 : il aurait planté) ;
  - **5 colonnes de contenu sont constantes (toujours 0)** dans Hannousse, à cause de bugs : `ratio_nullHyperlinks`, `ratio_intRedirection`, `ratio_intErrors`, `submit_email`, `sfh`. La couche « 24 caractéristiques » n'en a que **19 utiles** ;
  - `ratio_extRedirection` et `ratio_extErrors` envoient une requête vers **chaque** lien externe de la page (et `ratio_extRedirection` monte à 2,0 pour un ratio : médias externes comptés deux fois) ;
  - ~45 % du phishing live est rendu en JavaScript.
- **Décision (option A) :** le test live porte sur la **couche URL seule**, dont la reproductibilité est prouvée (52/52). La couche contenu est évaluée **sur Hannousse uniquement**. Une version approximative du contenu en live (option B) reste possible s'il reste du temps.
- **Décision complémentaire (18/10, proposée par Bedis) : modèle en cascade.** Pour une URL nouvelle (interface, live), la page est téléchargée dans le conteneur et le contenu calculé « au mieux » (option B). **Si le contenu pose problème, on bascule sur le modèle URL seule.** Contenu jugé inutilisable si : téléchargement échoué (erreur, code ≠ 200, pas de HTML) ou page « vide » (aucun lien, typique d'une page rendue en JavaScript). L'alerte indique quel modèle a décidé. La règle de bascule ne dépend que du téléchargement, jamais de l'étiquette : elle peut être appliquée telle quelle au test live.
- **Modèle URL pur** (52 colonnes, sans `random_domain`, `nb_redirection`, `nb_external_redirection`, `statistical_report`) : F1 **0,876**, ROC-AUC 0,951, rappel à 1 % de FP 0,535 (validation croisée groupée, train).

### 3.10 `06_threshold` — Point de fonctionnement pour un SOC

- **Modèle :** RF sur URL + Contenu **sans `random_domain`** → F1 **0,9174** (contre 0,9168 avec) : la retirer ne coûte rien. ROC-AUC 0,973.
- **Méthode :** probabilités **hors-pli** (`cross_val_predict`, `GroupKFold`) pour les 9 003 URL du train ; tous les seuils étudiés sans toucher au test.
- **Pourquoi :** un SOC raisonne en **taux de faux positifs** (fatigue d'alerte) et en **précision à prévalence réelle** (~1 % de phishing), pas en F1 sur un jeu 50/50.

| Seuil | Rappel | Faux positifs | Précision si 50 % de phishing | **Précision si 1 %** |
| --- | --- | --- | --- | --- |
| 0,5 (défaut) | 0,916 | 7,85 % | 0,92 | **0,11** |
| 0,58 | 0,881 | 4,97 % | 0,95 | 0,15 |
| **0,81** | **0,611** | **0,92 %** | 0,99 | **0,40** |
| 0,933 | 0,312 | 0,09 % | 1,00 | 0,78 |

- **Résultats clés :**
  - au seuil 0,5, en conditions réelles, **89 % des alertes seraient fausses** (théorème de Bayes : le phishing est rare) ;
  - **un F1 de 0,917 en laboratoire correspond à un rappel de 0,61 à 1 % de faux positifs** ;
  - aucun seuil unique ne satisfait à la fois l'analyste et la sécurité.
- **Décision : tri à deux niveaux** (fixé sur le train, appliqué tel quel au test) :

| Probabilité | Action |
| --- | --- |
| ≥ 0,93 | Alerte haute (blocage automatique possible) : 31 % du phishing, 78 % des alertes justes à 1 % de prévalence |
| 0,81 – 0,93 | File de revue par un analyste |
| < 0,81 | Pas d'alerte |

→ 61 % du phishing remonté pour moins de 1 % de faux positifs. Ces niveaux correspondent aux gravités d'une alerte SIEM (Wazuh, en perspectives).

### 3.11 `07_shap` — Explicabilité

- **Fait :** `shap==0.51.0` installé ; modèle final (RF, URL + Contenu sans `random_domain`, 79 colonnes) entraîné sur **tout le train** ; `TreeExplainer` sur 500 URL tirées au hasard ; graphique *beeswarm*.
- **Pourquoi :** un analyste ne peut rien faire d'une probabilité seule ; SHAP répartit la prédiction de chaque URL entre ses caractéristiques (valeurs de Shapley, théorie des jeux). Positif = pousse vers phishing.
- **Caractéristiques les plus influentes (importance SHAP moyenne) :**

| Rang | Caractéristique | Couche | Sens de l'effet |
| --- | --- | --- | --- |
| 1 | `nb_hyperlinks` | Contenu | **Peu de liens → phishing** (kits minimalistes ; pages légitimes riches) |
| 2 | `nb_www` | URL | **Pas de `www` → phishing** (signal réel mais facile à contourner) |
| 3 | `phish_hints` | URL | Mots suspects (`login`, `signin`, `admin`…) → phishing |
| 4 | `safe_anchor` | Contenu | Faible part d'ancres « vides » (`#`, `javascript`) → phishing (nom trompeur : la colonne mesure le % d'ancres **non sûres**) |
| 5 | `longest_word_path` | URL | Long jeton dans le chemin (identifiant aléatoire) → phishing |
| 7 | `domain_in_title` | Contenu | `1` = le domaine **n'est pas** dans le titre → phishing (page qui imite une marque) |

- **Lecture :** les deux couches se mélangent en tête du classement, ce qui est cohérent avec le gain du contenu dans l'ablation (+3,8 points). Aucune caractéristique de popularité. Plusieurs noms de colonnes ont un codage inversé (`domain_in_title`, `safe_anchor`) : il faudra les **traduire** en phrases claires pour l'analyste.
- **Limite :** les signaux les plus forts (`nb_hyperlinks`, `nb_www`) sont **faciles à contourner** pour un attaquant (ajouter des liens, ajouter `www.`) → à tester dans la partie évasion.
- **Explications par alerte** (modèle entraîné sur 4 plis, URL du 5e pli jamais vues) :

| URL | Probabilité | Vrai statut | 3 raisons principales | Lecture |
| --- | --- | --- | --- | --- |
| `restbetgir1.blogspot.com` | 1,00 | phishing | 14 liens seulement ; pas de `www` ; 7 % de liens internes | Blog de paris illégaux (« restbet giriş » = « connexion restbet ») qui renvoie presque tout vers un autre site |
| `shadetreetechnology.com/V4/validation/a111…a4` | 0,91 (file de revue) | phishing | jeton de 32 caractères dans le chemin ; idem sur l'URL ; 22 % de chiffres | Site compromis + identifiant hexadécimal de 32 caractères (type MD5), typique des kits |
| `scenari.software` | 0,83 (**fausse alerte**) | légitime | **0 lien** sur la page ; pas de `www` ; 0 % de liens externes | Page légitime sans liens visibles sans navigateur (probablement rendue en JavaScript) |

- **Format d'alerte PhishGuard** (noms techniques traduits en phrases, codages inversés corrigés, niveaux de `06`) :

```
🔴 ALERTE HAUTE  (probabilité 1.00)  http://restbetgir1.blogspot.com
   • seulement 14 lien(s) sur la page
   • pas de « www » dans l'adresse
   • 7% seulement des liens restent sur le site

🟠 À REVOIR  (probabilité 0.83)  https://scenari.software/
   • seulement 0 lien(s) sur la page
   • pas de « www » dans l'adresse
   • 0% des liens pointent vers d'autres sites
```

- **Le tri à deux niveaux joue son rôle :** la fausse alerte (`scenari.software`, 0,83) tombe en **« À REVOIR »**, pas en blocage automatique, et ses raisons (« 0 lien ») orientent l'analyste vers la bonne vérification.
- **Amélioration possible :** deux raisons peuvent dire la même chose (`longest_word_path` et `longest_words_raw`) ; regrouper les caractéristiques corrélées donnerait 3 raisons vraiment distinctes.
- **Enseignement :** la fausse alerte vient du même mécanisme que la campagne `pages.dev` : une page **rendue en JavaScript** paraît vide pour `requests`, et « page vide » ressemble à du phishing. Les sites légitimes modernes (applications JavaScript) risquent donc des fausses alertes → limite à documenter.


### 3.12 `08_live_model` — Modèle URL seule (branche de secours de la cascade, test live)

- **Fait :** RF sur les **52 colonnes purement URL** (`URL_ONLY` = colonnes de `src/features/url.py` sans `random_domain`, `nb_redirection`, `nb_external_redirection`, `statistical_report`). Fonction `test_url(url)` : calcule les caractéristiques **à partir du texte de l'URL** (aucune visite du site) et renvoie la probabilité.
- **Exemples (modèle entraîné sur tout le train) :** `google.com/search` 0,06 ; `fr.wikipedia.org/wiki/…` 0,15 ; faux PayPal `paypal-secure-login.verify-account.xyz/signin/update.php?id=…` 0,80 ; faux Apple ID `secure-appleid.com.account-verify.top/login` 0,89.
- **Seuils SOC** (probabilités hors-pli, même méthode qu'en `06`) — F1 0,876, ROC-AUC 0,951 :

| FP max | Seuil | Rappel | FP réel | Précision si 1 % de phishing |
| --- | --- | --- | --- | --- |
| 0,1 % | 0,979 | 0,123 | 0,09 % | 0,59 |
| 1 % | 0,862 | 0,535 | 0,96 % | 0,36 |
| 5 % | 0,663 | 0,791 | 4,97 % | 0,14 |

- **Comparaison des deux branches de la cascade (même politique d'alerte) :**

| Modèle | Seuil « à revoir » (1 % FP) | Rappel à 1 % FP | Seuil « alerte haute » (0,1 % FP) | Rappel à 0,1 % FP |
| --- | --- | --- | --- | --- |
| URL + Contenu | 0,81 | **0,611** | 0,93 | **0,312** |
| URL seule | 0,86 | 0,535 | 0,98 | 0,123 |

- **Lecture :**
  - au point de fonctionnement SOC, le contenu apporte **+7,6 points de rappel à 1 % de FP** et **2,5 fois plus de rappel à 0,1 %** : son apport est **plus grand qu'en F1** (+4 points) ;
  - le faux PayPal (0,80) reste **sous le seuil de revue (0,86)** : un phishing évident pour un humain ne déclencherait pas d'alerte avec l'URL seule. Le modèle, appris sur des URL de 2020, est prudent ; le prix de 1 % de faux positifs est un rappel d'environ 50 %.
- **Modèles sauvegardés** (`models/`, entraînés sur tout le train) : `rf_url_content.joblib` (79 colonnes) et `rf_url.joblib` (52 colonnes), fichiers binaires non versionnés (`models/*.joblib` dans `.gitignore`). `models/thresholds.json` (versionné) contient pour chaque modèle **la liste exacte de ses colonnes** et ses seuils : URL + Contenu 0,81 / 0,933 ; URL seule 0,862 / 0,979.

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
| Retirer `random_domain` | Non reproductible en live (module des auteurs non publié), non informatif ; F1 inchangé (0,9174). |
| Reproduire le code des auteurs à l'identique, bugs compris | Éviter que le modèle reçoive en live des valeurs calculées autrement qu'à l'entraînement (*training-serving skew*). |
| Test live sur la couche URL seule | Seule couche dont la reproductibilité est prouvée (52/52) ; le contenu n'est pas reproductible (code incohérent, colonnes constantes, rendu JavaScript). |
| Seuil choisi pour un SOC, pas 0,5 | Au seuil 0,5, 89 % des alertes seraient fausses à prévalence réelle ; tri à deux niveaux (0,81 / 0,93). |
| Collecte des pages dans un conteneur isolé | Les pages de phishing sont de vrais sites malveillants. |

---

## 5. Limites connues

- **Écart-type de 2 à 3 points** entre plis : les différences de moins de ~2 points entre modèles ne sont pas significatives (test de McNemar prévu).
- **`google.com`** (149 URL, surtout `docs.google.com` / `sites.google.com`) reste un seul groupe : impossible de séparer des attaquants sur un même nom d'hôte.
- **Hannousse date de 2020** : la dérive vers 2026 n'est mesurable que sur la collecte live.
- **Collecte live :** cloaking, pages en JavaScript, sites qui disparaissent vite ; un jour de collecte manqué (16/10) ; Tranco contient aussi des sites pour adultes et de piratage (légitimes au sens « non-phishing »).
- **Traçabilité de Hannousse :** pour quelques URL, les caractéristiques ne correspondent pas exactement à l'URL stockée.
- **Code de Hannousse :** le code de contenu publié ne correspond pas au CSV, 5 colonnes de contenu sont constantes, `random_domain` n'est pas reproductible.
- **Pages rendues en JavaScript :** elles paraissent vides (0 lien) et poussent vers « phishing » → fausses alertes possibles sur des sites légitimes modernes (ex. `scenari.software`, 0,83).
- **Une campagne domine le live :** 45 % du phishing collecté est sur `pages.dev`, rendu en JavaScript (couche contenu aveugle sans navigateur).
- **Point de fonctionnement SOC :** rappel de 0,61 seulement à 1 % de faux positifs ; précision de 0,40 à prévalence réelle avec ce seuil.

---

## 6. Prochaines étapes

| Priorité | Tâche | Qui | Pourquoi |
| --- | --- | --- | --- |
| ✅ | ~~Collecteur étape 3 (HTML dans Docker)~~ | Claude | Fait le 18/10 (§3.8). |
| ✅ | ~~Seuil SOC~~ | Bedis | Fait le 18/10 (§3.10) ; conclusion Markdown + commit de `06` à faire. |
| ✅ | ~~Retirer `random_domain`~~ | Bedis | Fait dans `06` (F1 inchangé). |
| ✅ | ~~Contenu pour le live~~ | Claude | Analysé : non reproductible → option A (§3.9). |
| ✅ | ~~SHAP~~ : importance globale, 3 raisons par alerte, phrases + niveau d'alerte (§3.11) ; conclusion Markdown + commit de `07` à faire | Bedis | Rendre une alerte exploitable par un analyste (explicabilité). |
| ✅ | ~~Modèle live URL seule + seuils, modèles sauvegardés dans `models/`~~ (§3.12) | Bedis | Nécessaire pour la cascade et l'interface. |
| 3 | **K-Means** sur le phishing (campagnes, ex. `hf*.com`, `pages.dev`) | Bedis | Analyse des campagnes. |
| 4 | **Évaluation finale (24–27 oct.)** : test verrouillé (une seule fois, seuils 0,81 / 0,93 inclus), test live avec et sans `pages.dev`, McNemar, calibration | Bedis | Le résultat principal du rapport. |
| 5 | Dérive (semaine 1 contre semaine 2) et évasion légère (2–3 transformations d'URL) | Bedis | Robustesse hors laboratoire (résultat préliminaire). |
| 6 | Démo **Streamlit** | Claude | Présentation orale. |
| 7 | **Rapport + présentation (28–31 oct.)** | Bedis | Livrables. |
| 3 bis | **Cascade** : contenu approximatif (option B) dans le conteneur + bascule vers le modèle URL seule si contenu inutilisable | Claude (après `08`) | Utiliser le contenu quand il est disponible, sans en dépendre. |

**Reportés en « perspectives »** (hors délai) : Wazuh, FastAPI, Docker (déploiement), MLflow, collecteur étape 2 (WHOIS/DNS/TLS).

**Collecte :** continuer deux fois par jour jusqu'au 27 octobre au moins, avec `bash src/collector/collect.sh` (Docker Desktop ouvert).

---

## 7. Reproductibilité

| Élément | Où / comment |
| --- | --- |
| Environnement | conda `phishguard` (Python 3.11), `requirements.txt` |
| Données brutes | `data/raw/` (non versionné) ; Hannousse v3, SHA-256 vérifié |
| Découpage | `notebooks/04_split.ipynb` → `data/processed/train.csv`, `test_LOCKED.csv` (SHA-256 ci-dessus) |
| Graine aléatoire | `random_state=42` partout |
| Collecte | `bash src/collector/collect.sh` (URL + pages dans le conteneur ; identifiant Tranco enregistré dans chaque fichier) |
| Caractéristiques live | `python -m src.features.build_live` (URL, validées 52/52 contre Hannousse) |
| Seuils SOC | `notebooks/06_threshold.ipynb` (probabilités hors-pli sur le train) |
| Historique | `git log` : un commit par étape |
