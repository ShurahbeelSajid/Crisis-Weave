ARG PYTHON_IMAGE=python:3.12.15-slim-bookworm
ARG CADDY_IMAGE=caddy:2.11.6-alpine
ARG CLAMAV_IMAGE=clamav/clamav:1.5.4_base

FROM ${PYTHON_IMAGE} AS builder
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_CACHE_DIR=1
WORKDIR /build
COPY pyproject.toml README.md ./
COPY src ./src
RUN python -m pip wheel --wheel-dir /wheels ".[telemetry]"

FROM builder AS builder-ml
RUN python -m pip wheel --wheel-dir /wheels-ml ".[ml]"

FROM ${PYTHON_IMAGE} AS builder-ui
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_CACHE_DIR=1
RUN python -m pip wheel --wheel-dir /ui-wheels "httpx==0.28.1" "streamlit==1.60.0"

FROM ${PYTHON_IMAGE} AS runtime-base
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    CRISISWEAVE_DATA_DIR=/data \
    HF_HOME=/models/huggingface \
    HF_HUB_DISABLE_TELEMETRY=1 \
    SENTENCE_TRANSFORMERS_HOME=/models/sentence-transformers
# Apply published OS security fixes on top of the base image; its tag is rebuilt only
# periodically, so fixes released since then are otherwise missing from the scanned image.
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get upgrade -y \
       -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold \
    && apt-get install --no-install-recommends -y ca-certificates ffmpeg tesseract-ocr libgomp1 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 crisisweave \
    && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin crisisweave \
    && mkdir -p /data /models /app \
    && chown -R 10001:10001 /data /models /app
WORKDIR /app

FROM runtime-base AS runtime-app
COPY --from=builder /wheels /wheels
RUN python -m pip install --no-index --find-links=/wheels "crisisweave[telemetry]" \
    && rm -rf /wheels
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=45s --retries=3 \
  CMD ["python", "-c", "import urllib.request; r=urllib.request.Request('http://127.0.0.1:8000/health/ready', headers={'Host':'api'}); urllib.request.urlopen(r, timeout=3)"]
CMD ["crisisweave", "serve", "--host", "0.0.0.0", "--port", "8000"]

# pip is only needed to install wheels. Shipped images remove it because pip vendors its own
# urllib3, msgpack, and setuptools copies, which lag behind their security releases.
FROM runtime-app AS runtime
RUN python -m pip uninstall --yes pip
USER 10001:10001

FROM runtime-app AS runtime-ml
COPY --from=builder-ml /wheels-ml /wheels-ml
RUN python -m pip install --no-index --find-links=/wheels-ml "crisisweave[ml]" \
    && rm -rf /wheels-ml \
    && python -m pip uninstall --yes pip
USER 10001:10001

# Release target: all revisions are mandatory immutable Hugging Face commit hashes.
FROM runtime-ml AS model-bundle
ARG TEXT_MODEL=BAAI/bge-small-en-v1.5
ARG TEXT_REVISION
ARG VISUAL_MODEL=sentence-transformers/clip-ViT-B-32
ARG VISUAL_REVISION
ARG RERANKER_MODEL=BAAI/bge-reranker-base
ARG RERANKER_REVISION
ARG WHISPER_MODEL=Systran/faster-whisper-small
ARG WHISPER_REVISION
COPY --chown=10001:10001 scripts/cache_models.py /app/cache_models.py
COPY --chown=10001:10001 scripts/verify_model_bundle.py /app/verify_model_bundle.py
RUN python /app/cache_models.py \
      --text-model "${TEXT_MODEL}" --text-revision "${TEXT_REVISION}" \
      --visual-model "${VISUAL_MODEL}" --visual-revision "${VISUAL_REVISION}" \
      --reranker-model "${RERANKER_MODEL}" --reranker-revision "${RERANKER_REVISION}" \
      --whisper-model "${WHISPER_MODEL}" --whisper-revision "${WHISPER_REVISION}" \
      --output /models \
    && python /app/verify_model_bundle.py --manifest /models/bundle.json
ENV CRISISWEAVE_TEXT_EMBEDDING_MODEL=/models/text \
    CRISISWEAVE_VISUAL_EMBEDDING_MODEL=/models/visual \
    CRISISWEAVE_RERANKER_MODEL=/models/reranker \
    CRISISWEAVE_WHISPER_MODEL=/models/whisper \
    CRISISWEAVE_MODEL_BUNDLE_MANIFEST=/models/bundle.json \
    CRISISWEAVE_MODEL_LOCAL_FILES_ONLY=true \
    HF_HUB_OFFLINE=1 \
    TRANSFORMERS_OFFLINE=1
ENTRYPOINT ["python", "/app/verify_model_bundle.py", "--manifest", "/models/bundle.json", "--exec"]

FROM ${PYTHON_IMAGE} AS runtime-ui
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PIP_DISABLE_PIP_VERSION_CHECK=1
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get upgrade -y \
       -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 crisisweave \
    && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin crisisweave \
    && mkdir -p /app \
    && chown -R 10001:10001 /app
COPY --from=builder-ui /ui-wheels /ui-wheels
RUN python -m pip install --no-index --find-links=/ui-wheels httpx streamlit \
    && rm -rf /ui-wheels \
    && python -m pip uninstall --yes pip
COPY --chown=10001:10001 apps /app/apps
WORKDIR /app
USER 10001:10001
EXPOSE 8501
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8501/_stcore/health', timeout=3)"]
CMD ["streamlit", "run", "/app/apps/streamlit_app.py", "--server.address=0.0.0.0", "--server.port=8501", "--server.maxUploadSize=50"]

# Production target: bind the reviewed INSTREAM ceiling into the promoted image. The strict
# replacement intentionally fails if a different upstream config layout is supplied unnoticed.
FROM ${CLAMAV_IMAGE} AS clamav-runtime
USER root
RUN apk upgrade --no-cache \
    && grep -qx '#StreamMaxLength 25M' /etc/clamav/clamd.conf \
    && sed -i 's/^#StreamMaxLength 25M$/StreamMaxLength 64M/' /etc/clamav/clamd.conf \
    && grep -qx 'StreamMaxLength 64M' /etc/clamav/clamd.conf \
    && chown root:root /etc/clamav/clamd.conf \
    && chmod 0444 /etc/clamav/clamd.conf
USER clamav

FROM ${CADDY_IMAGE} AS gateway
RUN apk upgrade --no-cache
COPY deploy/Caddyfile /etc/caddy/Caddyfile
