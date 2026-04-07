FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PATH="/root/go/bin:${PATH}"

WORKDIR /app

# ─────────────────────────────────────────────────────────────
# Runtime dependencies (APT packages)
# ─────────────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
  ca-certificates \
  curl \
  git \
  openjdk-21-jre-headless \
  golang-go \
  nmap \
  perl \
  libjson-perl \
  libxml-writer-perl \
  dnsutils \
  build-essential \
  libssl-dev \
  libpcap-dev \
  && rm -rf /var/lib/apt/lists/*

# AMASS nao esta disponivel no apt da imagem base (Debian trixie); instala binario oficial.
RUN set -eux; \
  ARCH="$(uname -m)"; \
  case "$ARCH" in \
    aarch64|arm64) AMASS_ARCH="arm64" ;; \
    x86_64|amd64) AMASS_ARCH="amd64" ;; \
    *) echo "Arquitetura nao suportada para AMASS: $ARCH" >&2; exit 1 ;; \
  esac; \
  AMASS_VERSION="v5.1.1"; \
  AMASS_URL="https://github.com/owasp-amass/amass/releases/download/${AMASS_VERSION}/amass_linux_${AMASS_ARCH}.tar.gz"; \
  tmpdir="$(mktemp -d)"; \
  curl -fsSL "$AMASS_URL" -o "$tmpdir/amass.tar.gz"; \
  tar -xzf "$tmpdir/amass.tar.gz" -C "$tmpdir"; \
  install -m 0755 "$tmpdir"/amass_linux_${AMASS_ARCH}/amass /usr/local/bin/amass; \
  rm -rf "$tmpdir"

# ─────────────────────────────────────────────────────────────
# RECON Tools (Amass, MassDNS, Sublist3r, Nmap)
# ─────────────────────────────────────────────────────────────
RUN set -eux; \
  # Amass (Go)
  go install github.com/owasp-amass/amass/v4/...@master || true; \
  # MassDNS (source)
  git clone --depth 1 https://github.com/blechschmidt/massdns.git /tmp/massdns 2>/dev/null || true; \
  if [ -d /tmp/massdns ]; then \
    cd /tmp/massdns && make -j$(nproc) 2>/dev/null && cp bin/massdns /usr/local/bin/massdns && chmod +x /usr/local/bin/massdns; \
    mkdir -p /usr/share/massdns/lists && cp lists/resolvers.txt /usr/share/massdns/lists/resolvers.txt; \
    cd / && rm -rf /tmp/massdns; \
  fi; \
  # Sublist3r (Python)
  git clone --depth 1 https://github.com/aboul3la/Sublist3r.git /opt/Sublist3r || true; \
  if [ -f /opt/Sublist3r/requirements.txt ]; then pip install --no-cache-dir -r /opt/Sublist3r/requirements.txt || true; fi; \
  printf '#!/bin/sh\nexec python3 /opt/Sublist3r/sublist3r.py "$@"\n' > /usr/local/bin/sublist3r; \
  chmod +x /usr/local/bin/sublist3r

# ─────────────────────────────────────────────────────────────
# OSINT Tool (Shodan.io)
# ─────────────────────────────────────────────────────────────
RUN pip install --no-cache-dir shodan

# ─────────────────────────────────────────────────────────────
# VULN Analysis Tools (Burp, Nmap Vulscan, Nikto)
# ─────────────────────────────────────────────────────────────
RUN set -eux; \
  # Nikto (via git + Perl wrapper)
  git clone --depth 1 https://github.com/sullo/nikto.git /opt/nikto 2>/dev/null || true; \
  if [ -f /opt/nikto/program/nikto.pl ]; then \
    printf '#!/bin/sh\nexec perl /opt/nikto/program/nikto.pl "$@"\n' > /usr/local/bin/nikto; \
    chmod +x /usr/local/bin/nikto; \
  fi; \
  # Nmap Vulscan script
  git clone --depth 1 https://github.com/scipag/vulscan.git /usr/share/nmap/scripts/vulscan || true; \
  # Burp CLI (requer Java + burp-cli-scan) - será configurado em runtime
  echo "Burp configuration via setup_burp.sh"

# ─────────────────────────────────────────────────────────────
# Python dependencies (from requirements.txt)
# ─────────────────────────────────────────────────────────────
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Instala cliente burp-cli + wrapper. Se rede externa falhar no build,
# mantemos o build funcional e a ferramenta sera marcada como skipped em runtime.
RUN chmod +x /app/setup_burp.sh /app/scripts/burp_cli_wrapper.sh /app/scripts/start_burp_rest.sh && \
  /app/setup_burp.sh || true

# ─────────────────────────────────────────────────────────────
# Initialize database and start server
# ─────────────────────────────────────────────────────────────

# Criar usuário não-root para segurança
RUN groupadd -r appgroup && useradd -r -g appgroup -u 1000 appuser && \
    mkdir -p /app && chown -R appuser:appgroup /app

ENV HOME=/tmp

USER appuser

CMD ["sh", "-c", "alembic -c alembic.ini upgrade head && uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload"]
