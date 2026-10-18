# Conteneur isolé de l'interface PhishGuard : la page saisie est téléchargée ICI, pas sur la machine.
# Versions identiques à l'environnement d'entraînement (indispensable pour recharger les modèles joblib).
FROM python:3.11-slim

RUN pip install --no-cache-dir \
        scikit-learn==1.9.1 numpy==2.4.6 pandas==3.0.6 scipy==1.17.1 joblib==1.6.0 \
        shap==0.51.0 requests==2.34.2 beautifulsoup4==4.15.0 tldextract==5.3.2 \
        streamlit==1.66.0 \
    && useradd --uid 1000 --create-home phishguard

ENV TLDEXTRACT_CACHE=/tmp/tldextract \
    HOME=/tmp \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app \
    STREAMLIT_BROWSER_GATHER_USAGE_STATS=false \
    STREAMLIT_SERVER_HEADLESS=true \
    STREAMLIT_SERVER_FILE_WATCHER_TYPE=none \
    NUMBA_CACHE_DIR=/tmp/numba \
    MPLCONFIGDIR=/tmp/mpl

USER phishguard
WORKDIR /app
EXPOSE 8501
CMD ["streamlit", "run", "app/streamlit_app.py", "--server.address=0.0.0.0", "--server.port=8501"]
