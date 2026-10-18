#!/usr/bin/env bash
# Lance l'interface PhishGuard dans un conteneur isolé, accessible seulement depuis ce PC.
# Usage (depuis la racine du repo, Docker Desktop ouvert) : bash app/run.sh
# Puis ouvrir http://localhost:8501 ; Ctrl+C pour arrêter.
set -euo pipefail
cd "$(dirname "$0")/.."

for f in models/rf_url.joblib models/rf_url_content.joblib models/thresholds.json; do
  [ -f "$f" ] || { echo "Manquant : $f (lancer notebooks/08_live_model.ipynb)"; exit 1; }
done

echo "Construction de l'image (longue la première fois)…"
docker build -q -t phishguard-app docker/app > /dev/null

echo "Interface : http://localhost:8501  (Ctrl+C pour arrêter)"
docker run --rm -it \
  --read-only --tmpfs /tmp \
  --cap-drop ALL --security-opt no-new-privileges \
  --memory 2g --cpus 2 --pids-limit 256 \
  --user 1000:1000 \
  -p 127.0.0.1:8501:8501 \
  -v "$PWD/src:/app/src:ro" \
  -v "$PWD/app:/app/app:ro" \
  -v "$PWD/models:/app/models:ro" \
  -v "$PWD/data/raw/hannousse_2021/scripts/allbrands.txt:/app/data/raw/hannousse_2021/scripts/allbrands.txt:ro" \
  phishguard-app
