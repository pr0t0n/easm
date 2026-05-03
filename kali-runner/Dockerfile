# Kali Linux runner — single source of truth for offensive tools.
# All EASM workers dispatch jobs HERE via HTTP; no tool ships in worker images.
FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Core: Python runtime, build deps, networking primitives, Go (for ProjectDiscovery tools)
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl wget git jq dnsutils openssl \
      python3 python3-pip python3-venv \
      pipx \
      build-essential pkg-config libssl-dev libpcap-dev \
      golang-go ruby ruby-dev \
      openssh-server \
    && rm -rf /var/lib/apt/lists/*

ENV GOPATH=/root/go \
    PATH="/root/go/bin:/usr/local/go/bin:${PATH}"

# kali-linux-everything — full offensive toolkit (every tool in Kali).
# Includes: information-gathering, vulnerability, web, database, passwords,
# exploitation, post-exploitation, forensics, reverse-engineering,
# sniffing-spoofing, social-engineering, wireless, etc.
# This is intentionally the maximum baseline so any profile YAML the team
# adds in the future already has its binary on $PATH.
# (Note: `kali-linux-all` does NOT exist — the correct name is
#  kali-linux-everything; see `apt-cache search '^kali-linux-'`.)
RUN apt-get update && apt-get install -y --no-install-recommends \
      kali-linux-everything \
    && rm -rf /var/lib/apt/lists/*

# ProjectDiscovery suite — most active recon/vuln tools we use are NOT in Kali
# metapackages (subfinder, amass, nuclei, naabu, dnsx, httpx, katana, etc.),
# so we install them from upstream via `go install`. This keeps the runner
# image authoritative for ALL tool profiles.
RUN set -eux; \
    for pkg in \
      "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest" \
      "github.com/projectdiscovery/httpx/cmd/httpx@latest" \
      "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest" \
      "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest" \
      "github.com/projectdiscovery/dnsx/cmd/dnsx@latest" \
      "github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest" \
      "github.com/projectdiscovery/alterx/cmd/alterx@latest" \
      "github.com/projectdiscovery/katana/cmd/katana@latest" \
      "github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest" \
      "github.com/owasp-amass/amass/v4/...@master" \
      "github.com/tomnomnom/assetfinder@latest" \
      "github.com/tomnomnom/waybackurls@latest" \
      "github.com/lc/gau/v2/cmd/gau@latest" \
      "github.com/hakluke/hakrawler@latest" \
      "github.com/hahwul/dalfox/v2@latest" \
      "github.com/ffuf/ffuf/v2@latest" \
      "github.com/jaeles-project/gospider@latest" \
      "github.com/haccer/subjack@latest" ; \
    do go install -v "$pkg" 2>&1 | tail -2 || echo "skip: $pkg"; done; \
    cp -v /root/go/bin/* /usr/local/bin/ 2>/dev/null || true; \
    nuclei -update-templates 2>/dev/null || true

# WPScan via Ruby (kali metapackage may not include it)
RUN gem install --no-document wpscan 2>&1 | tail -3 || true

# Python/Node CLIs that are not consistently shipped by Kali metapackages.
# Keep them in the Kali runner only; backend/worker images remain tool-free.
ENV PIPX_HOME=/opt/pipx \
    PIPX_BIN_DIR=/usr/local/bin
RUN set -eux; \
    pipx install bandit==1.9.4; \
    pipx install semgrep==1.161.0; \
    corepack prepare pnpm@9.15.4 --activate; \
    corepack enable; \
    PNPM_HOME=/usr/local/bin pnpm add -g retire@5.4.2; \
    rm -rf /root/.cache /root/.local/share/pnpm/store

# jwt_tool is distributed as a source repository, not an installable Python
# package. Clone it and expose a stable wrapper command expected by profiles.
RUN git clone --depth 1 https://github.com/ticarpi/jwt_tool.git /opt/jwt_tool && \
    pip install --break-system-packages --no-cache-dir -r /opt/jwt_tool/requirements.txt && \
    printf '#!/bin/sh\nexec python3 /opt/jwt_tool/jwt_tool.py "$@"\n' > /usr/local/bin/jwt_tool && \
    chmod +x /usr/local/bin/jwt_tool

# ParamSpider — não tem pacote pip/apt; clone direto.
RUN git clone --depth 1 https://github.com/devanshbatham/ParamSpider /opt/ParamSpider 2>&1 | tail -2 && \
    pip install --break-system-packages --no-cache-dir /opt/ParamSpider && \
    command -v paramspider

# Runner application — FastAPI HTTP server
# We use a dedicated venv to avoid conflicts with Kali-shipped python packages
# (uvicorn/pydantic/etc. installed via apt have no RECORD files and break pip).
WORKDIR /app
COPY requirements.txt .
RUN python3 -m venv /opt/runner-venv && \
    /opt/runner-venv/bin/pip install --no-cache-dir --upgrade pip && \
    /opt/runner-venv/bin/pip install --no-cache-dir -r requirements.txt
ENV PATH="/opt/runner-venv/bin:${PATH}"
COPY runner.py .
COPY profiles ./profiles

# Workspace for evidence (mounted as volume in docker-compose)
RUN mkdir -p /workspace
VOLUME ["/workspace"]

EXPOSE 8088

CMD ["uvicorn", "runner:app", "--host", "0.0.0.0", "--port", "8088"]
