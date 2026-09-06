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
ARG HTTPX_VERSION=1.6.9
ARG NUCLEI_VERSION=3.3.7

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       curl unzip ca-certificates dumb-init nmap \
       libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz0b libjpeg62-turbo libopenjp2-7 \
       fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/* \
    && nmap --version | head -1

# --- pinned ProjectDiscovery tools, checksum-verified ---------------------
# httpx is installed as /usr/local/bin/httpx-pd to avoid clashing with the
# Python `httpx` client CLI (PRD §12.4).
RUN set -eux; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in amd64) pd_arch=amd64 ;; arm64) pd_arch=arm64 ;; *) echo "unsupported arch $arch"; exit 1 ;; esac; \
    cd /tmp; \
    for tool_spec in "subfinder:${SUBFINDER_VERSION}:subfinder" "dnsx:${DNSX_VERSION}:dnsx" "httpx:${HTTPX_VERSION}:httpx-pd" "nuclei:${NUCLEI_VERSION}:nuclei"; do \
      tool="$(echo "$tool_spec" | cut -d: -f1)"; \
      ver="$(echo "$tool_spec" | cut -d: -f2)"; \
      dest="$(echo "$tool_spec" | cut -d: -f3)"; \
      base="https://github.com/projectdiscovery/${tool}/releases/download/v${ver}"; \
      zip="${tool}_${ver}_linux_${pd_arch}.zip"; \
      curl -fsSL -o "$zip" "${base}/${zip}"; \
      curl -fsSL -o "${tool}_checksums.txt" "${base}/${tool}_${ver}_checksums.txt"; \
      grep " ${zip}\$" "${tool}_checksums.txt" | sha256sum -c -; \
      unzip -o "$zip" "${tool}" -d /tmp/pd; \
      mv "/tmp/pd/${tool}" "/usr/local/bin/${dest}"; \
      chmod +x "/usr/local/bin/${dest}"; \
      rm -f "$zip" "${tool}_checksums.txt"; \
    done; \
    subfinder -version; dnsx -version; httpx-pd -version; nuclei -version

WORKDIR /app

RUN adduser --system --group --home /app appuser

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Validate the immutable Nuclei template allowlist and its content-hash manifest
# at build time; a bad template fails the build (PRD §12.5 / §12.6).
RUN HOME=/tmp nuclei -validate -duc -t templates/nuclei \
    && python -c "from app.adapters.nuclei import verify_template_set; import sys; ok,_,r=verify_template_set(__import__('pathlib').Path('templates/nuclei')); sys.exit(0 if ok else ('manifest mismatch: '+r))"

RUN mkdir -p /app/artifacts && chown -R appuser:appuser /app
USER appuser

EXPOSE 8000

ENTRYPOINT ["dumb-init", "--"]
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
