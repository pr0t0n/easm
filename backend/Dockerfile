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
  dnsutils \
  build-essential \
  libssl-dev \
  libpcap-dev \
  && rm -rf /var/lib/apt/lists/*

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

# ─────────────────────────────────────────────────────────────
# Initialize database and start server
# ─────────────────────────────────────────────────────────────
CMD ["sh", "-c", "alembic -c alembic.ini upgrade head && uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload"]
