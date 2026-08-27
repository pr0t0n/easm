# Kali Linux runner — LEAN base image.
#
# Only the fast/stable apt-based tools + language runtimes + the runner app are
# baked in. The heavy toolchain (Go suite, pipx tools, git tools, trivy, wpscan,
# nuclei templates) is NOT installed here — it is installed on demand from the
# admin UI into /opt/tools (a persistent volume on PATH). See modules.yaml and
# the /modules endpoints in runner.py.
#
# Rationale: Go compilation + nuclei template download were the slowest layers
# of the build. Moving them to click-to-install keeps this image small and the
# build fast, while apt tools (which build quickly) stay always-available.
FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Cloudflare-backed Kali mirror — reliable in Docker Desktop
RUN printf 'deb http://kali.download/kali kali-rolling main contrib non-free non-free-firmware\n' > /etc/apt/sources.list

# ── Layer 1: Core build deps & language runtimes ────────────────────────────
# Runtimes (go, python/pipx, node/npm, ruby) are kept so that click-to-install
# modules can COMPILE/INSTALL tools at runtime into /opt/tools.
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

ENV GOPATH=/root/go

# ── Tool-module install location (persistent volume on PATH) ─────────────────
# Both runtime execution of jobs AND click-to-install modules read this env, so
# tools installed here are immediately discoverable by the /tools endpoint.
ENV TOOLS_PREFIX=/opt/tools \
    GEM_HOME=/opt/tools/gems \
    GEM_PATH=/opt/tools/gems \
    PIPX_HOME=/opt/tools/pipx \
    PIPX_BIN_DIR=/opt/tools/bin \
    PATH="/opt/tools/bin:/opt/tools/gems/bin:/root/go/bin:/usr/local/go/bin:${PATH}"
RUN mkdir -p /opt/tools/bin /opt/tools/pipx /opt/tools/gems /opt/tools/src /opt/tools/venvs

# ── Layer 2: APT security tools (fast to install, always available) ──────────
RUN apt-get update && apt-get install -y --no-install-recommends \
      nmap masscan nikto \
      whatweb wafw00f \
      gobuster feroxbuster dirsearch dirb wfuzz \
      hydra medusa \
      dnsrecon dnsenum sublist3r findomain \
      theharvester \
      sslscan testssl.sh \
      hashcat \
      exploitdb \
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

# ── BAS (Breach & Attack Simulation) internal/AD tooling ────────────────────
# proxychains4 is the tunnel mechanism itself: BAS profiles wrap the real
# tool command with it so the tool's TCP connections route through the
# BasAgent's SOCKS5 tunnel (bas_agent_stub today) instead of leaving this
# container directly -- see bas_dispatcher.py and bas_proxychains.conf.
# Responder is installed but never dispatched in Phase 1 (poisoning needs a
# real agent on the customer's L2 segment, not a TCP-only SOCKS tunnel --
# see bas_technique_catalog.py's availability="future_agent_required").
# smbclient/samba-common-bin: enum4linux-ng shells out to nmblookup, net,
# rpcclient and smbclient itself -- without them it exits 1 with a warning
# instead of a crash, so it stays within allowed_return_codes and silently
# produces no enumeration data.
RUN apt-get update && \
    apt-get install -y --no-install-recommends proxychains4 smbmap ldap-utils \
      smbclient samba-common-bin && \
    (apt-get install -y --no-install-recommends responder python3-netifaces || true) && \
    rm -rf /var/lib/apt/lists/*
# PyPI package is named "bloodhound" (not "bloodhound-python") -- it installs
# the bloodhound-python console script kali-runner/profiles/bas_internal.yaml calls.
RUN pipx install impacket && \
    pipx install bloodhound

# enum4linux-ng isn't on PyPI (it's a git-distributed script) -- clone it and
# expose a thin wrapper on PATH instead of pipx-installing it. The wrapper
# calls /usr/bin/python3 explicitly, NOT the bare `python3` off PATH: at
# runtime the kali-runner service's own venv (/opt/runner-venv/bin) is
# prepended to PATH ahead of the system python, and requirements.txt below
# is installed into the SYSTEM python's site-packages -- an unqualified
# `python3` would silently resolve to the venv instead and fail on import
# with "No module named 'impacket'" despite the dependency being installed.
RUN git clone --depth 1 https://github.com/cddmp/enum4linux-ng.git /opt/tools/src/enum4linux-ng && \
    pip install --break-system-packages --no-cache-dir -r /opt/tools/src/enum4linux-ng/requirements.txt && \
    printf '#!/bin/sh\nexec /usr/bin/python3 /opt/tools/src/enum4linux-ng/enum4linux-ng.py "$@"\n' > /opt/tools/bin/enum4linux-ng && \
    chmod +x /opt/tools/bin/enum4linux-ng

# gitleaks: git-secrets scanner for the BAS "Hardcoded Secrets in Source Code
# Detection" technique (source_code_secrets_scan) -- not packaged in Kali's
# apt repos, so pull the official release binary directly.
RUN GITLEAKS_URL="$(curl -fsSL https://api.github.com/repos/gitleaks/gitleaks/releases/latest | \
      grep -o 'https://[^"]*linux_x64\.tar\.gz' | head -n1)" && \
    curl -fsSL "$GITLEAKS_URL" -o /tmp/gitleaks.tar.gz && \
    tar -xzf /tmp/gitleaks.tar.gz -C /opt/tools/bin gitleaks && \
    chmod +x /opt/tools/bin/gitleaks && \
    rm -f /tmp/gitleaks.tar.gz

# ── Layer 2b: dirsearch runtime deps ─────────────────────────────────────────
# The Kali dirsearch package ships without its Python deps resolved on
# Python 3.13 (pkg_resources removed from setuptools >=81). Pin setuptools<81
# and install every import dirsearch needs so it runs out of the box.
RUN pip install --break-system-packages --no-cache-dir \
      "setuptools<81" requests requests_ntlm requests-ntlm2 ntlm-auth \
      beautifulsoup4 cryptography defusedxml colorama jinja2 markupsafe pyparsing

# ── Layer 3: Runner application (FastAPI HTTP server) ───────────────────────
WORKDIR /app
COPY requirements.txt .
RUN python3 -m venv /opt/runner-venv && \
    /opt/runner-venv/bin/pip install --no-cache-dir --upgrade pip && \
    /opt/runner-venv/bin/pip install --no-cache-dir -r requirements.txt
ENV PATH="/opt/runner-venv/bin:${PATH}"
COPY runner.py .
COPY modules.yaml .
COPY profiles ./profiles
COPY scripts /opt/runner-scripts
RUN chmod +x /opt/runner-scripts/*.py 2>/dev/null || true

# ── Sanity check: every BASE (apt) tool must be on PATH ──────────────────────
# Click-to-install tools are intentionally NOT checked here — they arrive at
# runtime via the admin UI.
RUN set -eux; \
    for tool in \
      curl nmap masscan nikto whatweb wafw00f \
      gobuster feroxbuster dirsearch dirb wfuzz \
      hydra medusa crackmapexec \
      dnsrecon dnsenum sublist3r findomain \
      sslscan testssl.sh searchsploit; \
    do command -v "$tool" || echo "WARN: $tool not found"; done; \
    test -f /usr/share/seclists/Discovery/Web-Content/raft-small-directories.txt; \
    test -f /usr/share/seclists/Discovery/Web-Content/raft-small-files.txt; \
    test -f /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt; \
    test -f /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt; \
    test -f /usr/share/seclists/Usernames/top-usernames-shortlist.txt; \
    test -f /usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt

RUN mkdir -p /workspace
VOLUME ["/workspace", "/opt/tools"]

# proxychains-ng only accepts a literal IP for a proxy that's first/only in
# the chain (confirmed live: a docker-compose service hostname like
# "bas_agent_stub" is rejected even with dynamic_chain + proxy_dns). Resolve
# it once at container start and write a runtime conf BAS profiles reference
# instead of the static, hostname-based one -- re-resolved on every restart
# of this container, which is the same cadence bas_agent_stub itself gets
# recreated on in this dev stack.
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

EXPOSE 8088

ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["uvicorn", "runner:app", "--host", "0.0.0.0", "--port", "8088"]
