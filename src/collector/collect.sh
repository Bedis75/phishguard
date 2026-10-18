#!/usr/bin/env bash
# Collecte complète : URL (étape 1) puis pages HTML dans un conteneur isolé (étape 3).
# Usage (depuis la racine du repo, env conda phishguard actif) : bash src/collector/collect.sh
set -euo pipefail
cd "$(dirname "$0")/../.."

# Étape 1 : listes d'URL (sur la machine, aucune URL de phishing visitée)
python -m src.collector.collect_urls
urls_file=$(ls -t data/live/*/urls_*.csv | head -1)
run_dir=$(dirname "$urls_file")
echo "Étape 3 : pages de $urls_file (conteneur isolé)"

# Étape 3 : pages, dans le conteneur
docker build -q -t phishguard-fetcher docker/fetcher > /dev/null
docker run --rm \
  --read-only --tmpfs /tmp \
  --cap-drop ALL --security-opt no-new-privileges \
  --memory 1g --cpus 2 --pids-limit 256 \
  --user 1000:1000 \
  -v "$PWD/src:/app/src:ro" \
  -v "$PWD/$run_dir:/data" \
  phishguard-fetcher \
  python -m src.collector.fetch_pages "/data/$(basename "$urls_file")"
