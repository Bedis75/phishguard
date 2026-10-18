#!/usr/bin/env bash
# Collecte automatique, lancée par le Planificateur de tâches Windows (voir src/collector/schedule_windows.ps1).
# - ne fait rien si la fenêtre OpenPhish en cours (00:00–12:00 ou 12:00–24:00 UTC) est déjà collectée ;
# - démarre Docker Desktop s'il ne tourne pas, et attend qu'il soit prêt ;
# - écrit un journal par passage dans data/live/logs/.
set -uo pipefail
cd "$(dirname "$0")/../.."

export PATH="/home/bedis/miniconda3/envs/phishguard/bin:$PATH"   # environnement conda phishguard
log_dir=data/live/logs
mkdir -p "$log_dir"
log="$log_dir/$(date -u +%Y-%m-%d_%H%M).log"
exec > >(tee -a "$log") 2>&1

echo "=== $(date -u '+%Y-%m-%d %H:%M UTC') : collecte automatique"

# Fenêtre OpenPhish en cours déjà collectée ? (fichiers urls_HHMM.csv du jour UTC)
today=$(date -u +%Y-%m-%d)
if [ "$(date -u +%H)" -lt 12 ]; then window="00 01 02 03 04 05 06 07 08 09 10 11"; else window="12 13 14 15 16 17 18 19 20 21 22 23"; fi
for h in $window; do
  if ls "data/live/$today"/urls_"$h"??.csv >/dev/null 2>&1; then
    echo "Fenêtre déjà collectée ($(ls data/live/$today/urls_${h}??.csv | head -1)) : rien à faire."
    exit 0
  fi
done

# Docker Desktop prêt ?
if ! docker info >/dev/null 2>&1; then
  echo "Docker ne répond pas : démarrage de Docker Desktop…"
  "/mnt/c/Program Files/Docker/Docker/Docker Desktop.exe" >/dev/null 2>&1 &
  for _ in $(seq 1 36); do
    sleep 5
    docker info >/dev/null 2>&1 && break
  done
  docker info >/dev/null 2>&1 || { echo "ÉCHEC : Docker indisponible après 3 minutes."; exit 1; }
  echo "Docker prêt."
fi

bash src/collector/collect.sh
status=$?
echo "=== fin (code $status)"
exit $status
