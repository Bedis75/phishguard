# Conteneur isolé pour télécharger les pages (étape 3 du collecteur).
# Construit et lancé par src/collector/collect.sh, avec les restrictions de sécurité.
FROM python:3.11-slim

RUN pip install --no-cache-dir requests==2.34.2 tldextract==5.3.2 \
    && useradd --uid 1000 --create-home fetcher

ENV TLDEXTRACT_CACHE=/tmp/tldextract \
    PYTHONDONTWRITEBYTECODE=1

USER fetcher
WORKDIR /app
