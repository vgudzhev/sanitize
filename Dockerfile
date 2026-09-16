FROM python:3.12-slim AS base

WORKDIR /app

RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc && \
    rm -rf /var/lib/apt/lists/*

COPY sanitize/pyproject.toml sanitize/
RUN pip install --no-cache-dir -e sanitize/

COPY sanitize/ sanitize/

RUN python -m spacy download en_core_web_sm

RUN useradd -r -s /bin/false sanitize
USER sanitize

EXPOSE 7411

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:7411/v1/health')"

CMD ["uvicorn", "sanitize.app:app", "--host", "0.0.0.0", "--port", "7411", "--workers", "2"]
