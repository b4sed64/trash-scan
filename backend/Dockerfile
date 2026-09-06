# Trash Scan API / worker image.
#
# Scanner binaries are pinned by version and verified against the publisher's
# checksums file at build time. The application never downloads tools during a
# scan (PRD §12, §12.6).
FROM python:3.12.8-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

# Pinned scanner tool versions.
ARG SUBFINDER_VERSION=2.6.6
ARG DNSX_VERSION=1.2.1

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl unzip ca-certificates dumb-init \
    && rm -rf /var/lib/apt/lists/*

# --- pinned ProjectDiscovery tools, checksum-verified ---------------------
RUN set -eux; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in amd64) pd_arch=amd64 ;; arm64) pd_arch=arm64 ;; *) echo "unsupported arch $arch"; exit 1 ;; esac; \
    cd /tmp; \
    for tool_spec in "subfinder:${SUBFINDER_VERSION}" "dnsx:${DNSX_VERSION}"; do \
      tool="${tool_spec%%:*}"; ver="${tool_spec##*:}"; \
      base="https://github.com/projectdiscovery/${tool}/releases/download/v${ver}"; \
      zip="${tool}_${ver}_linux_${pd_arch}.zip"; \
      curl -fsSL -o "$zip" "${base}/${zip}"; \
      curl -fsSL -o "${tool}_checksums.txt" "${base}/${tool}_${ver}_checksums.txt"; \
      grep " ${zip}\$" "${tool}_checksums.txt" | sha256sum -c -; \
      unzip -o "$zip" "${tool}" -d /usr/local/bin; \
      chmod +x "/usr/local/bin/${tool}"; \
      rm -f "$zip" "${tool}_checksums.txt"; \
    done; \
    subfinder -version; dnsx -version

WORKDIR /app

RUN adduser --system --group --home /app appuser

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p /app/artifacts && chown -R appuser:appuser /app
USER appuser

EXPOSE 8000

ENTRYPOINT ["dumb-init", "--"]
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
