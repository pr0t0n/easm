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
