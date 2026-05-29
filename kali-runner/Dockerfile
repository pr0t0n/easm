# Kali Linux runner — minimal toolset derived from profiles/*.yaml and skills.
# Replaces kali-linux-everything with only the tools actually referenced.
# Base image: kalilinux/kali-rolling (~300 MB) + targeted installs.
FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Cloudflare-backed Kali mirror — reliable in Docker Desktop
RUN printf 'deb http://kali.download/kali kali-rolling main contrib non-free non-free-firmware\n' > /etc/apt/sources.list

# ── Layer 1: Core build deps & system primitives ────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl wget git jq unzip \
      dnsutils openssl \
      python3 python3-pip python3-venv python3-setuptools \
      pipx \
      build-essential pkg-config libssl-dev libpcap-dev \
      golang-go \
      ruby ruby-dev \
      nodejs npm \
    && rm -rf /var/lib/apt/lists/*

ENV GOPATH=/root/go \
    PATH="/root/go/bin:/usr/local/go/bin:${PATH}"

# ── Layer 2: APT security tools (profiles/*.yaml binaries only) ─────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
      nmap masscan nikto \
      whatweb wafw00f \
      gobuster feroxbuster dirsearch dirb wfuzz \
      hydra medusa \
      dnsrecon dnsenum sublist3r findomain \
      theharvester \
      sslscan testssl.sh \
      hashcat \
      seclists wordlists \
    && rm -rf /var/lib/apt/lists/*

# crackmapexec was renamed nxc in Kali 2024; install whichever is available
# and expose both names so the profile cmd ["crackmapexec", ...] keeps working.
RUN apt-get update && \
    (apt-get install -y --no-install-recommends crackmapexec || \
     apt-get install -y --no-install-recommends nxc) && \
    rm -rf /var/lib/apt/lists/* && \
    (command -v crackmapexec || \
     (command -v nxc && ln -sf "$(command -v nxc)" /usr/local/bin/crackmapexec))

# massdns — required by shuffledns for bulk DNS brute-force resolution.
# Build from source (not in default Kali repos as a separate package).
RUN apt-get update && apt-get install -y --no-install-recommends build-essential git ca-certificates && \
    git clone --depth 1 https://github.com/blechschmidt/massdns.git /tmp/massdns && \
    cd /tmp/massdns && make && \
    cp /tmp/massdns/bin/massdns /usr/local/bin/ && \
    rm -rf /tmp/massdns /var/lib/apt/lists/*

# ── Layer 3: Go-based tools (ProjectDiscovery suite + recon/exploit tools) ──
# Each tool installs in its own command so one failure doesn't abort the rest,
# AND a final verification step FAILS the build if any critical binary is
# missing — previously silent 'WARN: skip' left scans without nuclei/ffuf/etc.
ENV GOFLAGS=-mod=mod GOBIN=/usr/local/bin
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
      "github.com/owasp-amass/amass/v4/cmd/amass@latest" \
      "github.com/tomnomnom/assetfinder@latest" \
      "github.com/tomnomnom/waybackurls@latest" \
      "github.com/lc/gau/v2/cmd/gau@latest" \
      "github.com/hakluke/hakrawler@latest" \
      "github.com/hahwul/dalfox/v2@latest" \
      "github.com/ffuf/ffuf/v2@latest" \
      "github.com/jaeles-project/gospider@latest" \
      "github.com/haccer/subjack@latest" \
      "github.com/gitleaks/gitleaks/v8@latest" \
      "github.com/trufflesecurity/trufflehog/v3@latest" ; \
    do echo "go install $pkg"; go install "$pkg" || echo "WARN: failed $pkg"; done; \
    nuclei -update-templates 2>/dev/null || true; \
    echo "── removing python httpx CLI wrappers (conflict with ProjectDiscovery httpx) ──"; \
    rm -f /usr/bin/httpx /bin/httpx; \
    echo "── verifying critical Go binaries ──"; \
    MISSING=""; \
    for bin in subfinder httpx naabu nuclei dnsx shuffledns alterx katana \
               amass assetfinder waybackurls gau hakrawler ffuf gospider ; do \
      command -v "$bin" >/dev/null 2>&1 && echo "  OK $bin ($(command -v $bin))" || { echo "  MISSING $bin"; MISSING="$MISSING $bin"; }; \
    done; \
    httpx -version >/dev/null 2>&1 || { echo "FATAL: httpx is not the ProjectDiscovery build"; exit 1; }; \
    if [ -n "$MISSING" ]; then echo "FATAL: missing Go binaries:$MISSING"; exit 1; fi

# ── Layer 4: Python tools (pipx) ─────────────────────────────────────────────
ENV PIPX_HOME=/opt/pipx \
    PIPX_BIN_DIR=/usr/local/bin
RUN set -eux; \
    pipx install sqlmap; \
    pipx install wapiti3; \
    pipx install arjun; \
    pipx install shodan; \
    pipx install h8mail || true; \
    pipx install bandit==1.9.4; \
    pipx install semgrep==1.161.0; \
    npm install -g retire@5.4.2; \
    rm -rf /root/.npm

# ── Layer 4b: dirsearch runtime deps ─────────────────────────────────────────
# The Kali dirsearch package ships without its Python deps resolved on
# Python 3.13 (pkg_resources removed from setuptools >=81). Pin setuptools<81
# and install every import dirsearch needs so it runs out of the box.
RUN pip install --break-system-packages --no-cache-dir \
      "setuptools<81" requests requests_ntlm requests-ntlm2 ntlm-auth \
      beautifulsoup4 cryptography defusedxml colorama jinja2 markupsafe pyparsing

# ── Layer 5: Trivy (container/IaC/secret scanner — post_exploitation profile) ─
# Trivy release naming: amd64→64bit, arm64→ARM64 (not the dpkg arch name directly)
RUN TRIVY_VER=$(curl -s https://api.github.com/repos/aquasecurity/trivy/releases/latest \
      | grep '"tag_name"' | sed 's/.*"v\([^"]*\)".*/\1/') && \
    ARCH=$(dpkg --print-architecture) && \
    case "$ARCH" in \
      amd64)   TRIVY_ARCH="64bit"  ;; \
      arm64)   TRIVY_ARCH="ARM64"  ;; \
      armhf)   TRIVY_ARCH="ARM"    ;; \
      i386)    TRIVY_ARCH="32bit"  ;; \
      *)       TRIVY_ARCH="$ARCH"  ;; \
    esac && \
    curl -sL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VER}/trivy_${TRIVY_VER}_Linux-${TRIVY_ARCH}.tar.gz" \
      -o /tmp/trivy.tar.gz && \
    tar -xzf /tmp/trivy.tar.gz -C /usr/local/bin trivy && \
    rm /tmp/trivy.tar.gz && \
    trivy --version

# ── Layer 5b: LinkFinder — JavaScript endpoint extractor ────────────────────
RUN pip install --break-system-packages --no-cache-dir linkfinder 2>/dev/null || \
    (git clone --depth 1 https://github.com/GerbenJavado/LinkFinder.git /opt/LinkFinder && \
     pip install --break-system-packages --no-cache-dir -r /opt/LinkFinder/requirements.txt && \
     printf '#!/bin/sh\nexec python3 /opt/LinkFinder/linkfinder.py "$@"\n' \
       > /usr/local/bin/linkfinder && \
     chmod +x /usr/local/bin/linkfinder) || true

# ── Layer 6: Tools only available as source/git clones ───────────────────────
# jwt_tool (JWT audit — post_exploitation profile)
RUN git clone --depth 1 https://github.com/ticarpi/jwt_tool.git /opt/jwt_tool && \
    pip install --break-system-packages --no-cache-dir \
      -r /opt/jwt_tool/requirements.txt ratelimit && \
    printf '#!/bin/sh\nexec python3 /opt/jwt_tool/jwt_tool.py "$@"\n' \
      > /usr/local/bin/jwt_tool && \
    chmod +x /usr/local/bin/jwt_tool

# ParamSpider (reconnaissance profile)
RUN git clone --depth 1 https://github.com/devanshbatham/ParamSpider /opt/ParamSpider && \
    pip install --break-system-packages --no-cache-dir /opt/ParamSpider && \
    command -v paramspider

# WPScan via Ruby gem (weaponization profile)
RUN gem install --no-document wpscan 2>&1 | tail -3 || true

# XSStrike (skill.vuln.xss optional_tool)
RUN git clone --depth 1 https://github.com/s0md3v/XSStrike /opt/XSStrike && \
    pip install --break-system-packages --no-cache-dir \
      -r /opt/XSStrike/requirements.txt && \
    printf '#!/bin/sh\nexec python3 /opt/XSStrike/xsstrike.py "$@"\n' \
      > /usr/local/bin/xsstrike && \
    chmod +x /usr/local/bin/xsstrike

# Ghauri (skill.vuln.sqli optional_tool)
RUN pip install --break-system-packages --no-cache-dir ghauri 2>/dev/null || \
    (git clone --depth 1 https://github.com/r0oth3x49/ghauri /opt/ghauri && \
     pip install --break-system-packages --no-cache-dir \
       -r /opt/ghauri/requirements.txt && \
     printf '#!/bin/sh\nexec python3 /opt/ghauri/ghauri.py "$@"\n' \
       > /usr/local/bin/ghauri && \
     chmod +x /usr/local/bin/ghauri) || true

# ── Layer 7: Runner application (FastAPI HTTP server) ───────────────────────
WORKDIR /app
COPY requirements.txt .
RUN python3 -m venv /opt/runner-venv && \
    /opt/runner-venv/bin/pip install --no-cache-dir --upgrade pip && \
    /opt/runner-venv/bin/pip install --no-cache-dir -r requirements.txt
ENV PATH="/opt/runner-venv/bin:${PATH}"
COPY runner.py .
COPY profiles ./profiles
COPY scripts /opt/runner-scripts
RUN chmod +x /opt/runner-scripts/*.py 2>/dev/null || true

# ── Sanity check: every profile binary must be on PATH ──────────────────────
RUN set -eux; \
    for tool in \
      curl nuclei ffuf sqlmap dalfox wapiti \
      subfinder httpx naabu dnsx shuffledns alterx katana \
      interactsh-client assetfinder waybackurls gau hakrawler amass \
      gospider subjack gitleaks trufflehog trivy \
      nmap masscan nikto whatweb wafw00f \
      gobuster feroxbuster dirsearch dirb wfuzz \
      hydra medusa crackmapexec \
      dnsrecon dnsenum sublist3r findomain \
      sslscan testssl.sh \
      jwt_tool paramspider wpscan xsstrike linkfinder \
      semgrep bandit retire; \
    do command -v "$tool" || echo "WARN: $tool not found"; done; \
    test -f /usr/share/seclists/Discovery/Web-Content/raft-small-directories.txt; \
    test -f /usr/share/seclists/Discovery/Web-Content/raft-small-files.txt; \
    test -f /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt; \
    test -f /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt; \
    test -f /usr/share/seclists/Usernames/top-usernames-shortlist.txt; \
    test -f /usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt

RUN mkdir -p /workspace
VOLUME ["/workspace"]

EXPOSE 8088

CMD ["uvicorn", "runner:app", "--host", "0.0.0.0", "--port", "8088"]
