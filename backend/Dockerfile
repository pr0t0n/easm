FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PATH="/root/go/bin:${PATH}"

WORKDIR /app

# Dependencias de runtime para scanners CLI (apt + go + ruby)
RUN apt-get update && apt-get install -y --no-install-recommends \
	ca-certificates \
	curl \
	git \
	openjdk-21-jre-headless \
	openjdk-21-jdk-headless \
	maven \
	golang-go \
	nodejs \
	npm \
	ruby \
	ruby-dev \
	build-essential \
	libffi-dev \
	libssl-dev \
	libpcap-dev \
	python3-setuptools \
	dirb \
	dnsenum \
	dnsutils \
	nmap \
	perl \
	libjson-perl \
	sslscan \
	whois \
	&& rm -rf /var/lib/apt/lists/*

# Ferramentas Python
RUN pip install --no-cache-dir \
	setuptools \
	arjun \
	uro \
	h8mail \
	theHarvester \
	semgrep \
	pynessus \
	shodan \
	dnsgen \
	urlscanio \
	trufflehog \
	wapiti3 \
	wafw00f \
	git+https://github.com/xmendez/wfuzz.git

# Ferramentas Go
RUN set -eux; \
	go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest || true; \
	go install github.com/owasp-amass/amass/v4/...@master || true; \
	go install github.com/tomnomnom/assetfinder@latest || true; \
	go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest || true; \
	go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest || true; \
	go install github.com/projectdiscovery/httpx/cmd/httpx@latest || true; \
	go install github.com/projectdiscovery/katana/cmd/katana@latest || true; \
	go install github.com/sensepost/gowitness@latest || true; \
	go install github.com/ffuf/ffuf/v2@latest || true; \
	go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest || true; \
	go install github.com/hahwul/dalfox/v2@latest || true; \
	go install github.com/assetnote/kiterunner@latest || true; \
	go install github.com/haccer/subjack@latest || true; \
	go install github.com/trufflesecurity/trufflehog/v3@latest || true

# Ferramentas opcionais adicionais (best effort)
RUN set -eux; \
	apt-get update; \
	apt-get install -y --no-install-recommends whatweb zaproxy seclists || true; \
	# massdns from source (apt package unreliable on some base images)
	git clone --depth 1 https://github.com/blechschmidt/massdns.git /tmp/massdns 2>/dev/null || true; \
	if [ -d /tmp/massdns ]; then \
		cd /tmp/massdns && make -j$(nproc) 2>/dev/null && cp bin/massdns /usr/local/bin/massdns && chmod +x /usr/local/bin/massdns; \
		mkdir -p /usr/share/massdns/lists && cp lists/resolvers.txt /usr/share/massdns/lists/resolvers.txt; \
		cd / && rm -rf /tmp/massdns; \
	fi; \
	# DNS wordlists for massdns/dnsenum
	mkdir -p /usr/share/seclists/Discovery/DNS; \
	(curl -fsSL "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt" \
		-o /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt 2>/dev/null || true); \
	# subjack fingerprints
	mkdir -p /opt/subjack; \
	(curl -fsSL "https://raw.githubusercontent.com/haccer/subjack/master/fingerprints.json" \
		-o /opt/subjack/fingerprints.json 2>/dev/null || true); \
	mkdir -p /usr/share/seclists/Discovery/Web-Content; \
	printf 'config.inc.php\nconfig/config.inc.php\nsetup/\njs/config.js\n' > /usr/share/seclists/Discovery/Web-Content/phpmyadmin_paths.txt; \
	# nikto via git + wrapper perl (perl instalado na camada anterior)
	git clone --depth 1 https://github.com/sullo/nikto.git /opt/nikto 2>/dev/null || true; \
	if [ -f /opt/nikto/program/nikto.pl ]; then \
		printf '#!/bin/sh\nexec perl /opt/nikto/program/nikto.pl "$@"\n' > /usr/local/bin/nikto; \
		chmod +x /usr/local/bin/nikto; \
	fi; \
	# garante modulo JSON para Nikto em runtime (algumas bases arm podem falhar na primeira camada)
	if ! perl -MJSON -e 1 >/dev/null 2>&1; then \
		apt-get update; \
		apt-get install -y --no-install-recommends libjson-perl libjson-pp-perl libjson-xs-perl; \
	fi; \
	perl -MJSON -e 1 >/dev/null 2>&1; \
	# wordlist basica raft-medium-directories para feroxbuster/gobuster/ffuf
	(curl -fsSL "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-medium-directories.txt" \
		-o /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt 2>/dev/null || true); \
	rm -rf /var/lib/apt/lists/*; \
	pip install --no-cache-dir sublist3r waymore linkfinder dnspython || true; \
	go install github.com/projectdiscovery/alterx/cmd/alterx@latest || true; \
	go install github.com/projectdiscovery/chaos-client/cmd/chaos@latest || true; \
	go install github.com/d3mondev/puredns/v2@latest || true; \
	go install github.com/rverton/webanalyze/cmd/webanalyze@latest || true

# Ferramentas adicionais obrigatorias solicitadas (best effort)
RUN set -eux; \
	# feroxbuster
	ARCH=$(uname -m); \
	if [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then FEROX_URL="https://github.com/epi052/feroxbuster/releases/latest/download/aarch64-linux-feroxbuster.zip"; else FEROX_URL="https://github.com/epi052/feroxbuster/releases/latest/download/x86_64-linux-feroxbuster.zip"; fi; \
	curl -fsSL "$FEROX_URL" -o /tmp/feroxbuster.zip || true; \
	if [ -f /tmp/feroxbuster.zip ]; then apt-get update && apt-get install -y unzip || true; unzip -o /tmp/feroxbuster.zip -d /usr/local/bin || true; chmod +x /usr/local/bin/feroxbuster || true; fi; \
	# gobuster
	if [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then GOBUSTER_URL="https://github.com/OJ/gobuster/releases/download/v3.8.2/gobuster_Linux_arm64.tar.gz"; else GOBUSTER_URL="https://github.com/OJ/gobuster/releases/download/v3.8.2/gobuster_Linux_x86_64.tar.gz"; fi; \
	curl -fsSL "$GOBUSTER_URL" -o /tmp/gobuster.tar.gz || true; \
	if [ -f /tmp/gobuster.tar.gz ]; then tar -xzf /tmp/gobuster.tar.gz -C /tmp || true; install -m 0755 /tmp/gobuster /usr/local/bin/gobuster || true; fi; \
	# findomain
	if [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then FINDO_URL="https://github.com/findomain/findomain/releases/latest/download/findomain-linux-arm64.zip"; else FINDO_URL="https://github.com/findomain/findomain/releases/latest/download/findomain-linux.zip"; fi; \
	curl -fsSL "$FINDO_URL" -o /tmp/findomain.zip || true; \
	if [ -f /tmp/findomain.zip ]; then unzip -o /tmp/findomain.zip -d /usr/local/bin || true; chmod +x /usr/local/bin/findomain || true; fi; \
	# cloudenum
	git clone --depth 1 https://github.com/initstring/cloud_enum.git /opt/cloud_enum || true; \
	if [ -f /opt/cloud_enum/requirements.txt ]; then pip install --no-cache-dir -r /opt/cloud_enum/requirements.txt || true; fi; \
	ln -sf /opt/cloud_enum/cloud_enum.py /usr/local/bin/cloudenum || true; \
	# SecretFinder + dependencias obrigatorias
	git clone --depth 1 https://github.com/m4ll0k/SecretFinder.git /opt/SecretFinder || true; \
	pip install --no-cache-dir jsbeautifier requests || true; \
	if [ -f /opt/SecretFinder/requirements.txt ]; then pip install --no-cache-dir -r /opt/SecretFinder/requirements.txt || true; fi; \
	ln -sf /opt/SecretFinder/SecretFinder.py /usr/local/bin/SecretFinder.py || true; \
	chmod +x /usr/local/bin/SecretFinder.py || true; \
	# LinkFinder (git clone para garantir binario linkfinder.py)
	git clone --depth 1 https://github.com/GerbenJavado/LinkFinder.git /opt/linkfinder || true; \
	if [ -f /opt/linkfinder/requirements.txt ]; then pip install --no-cache-dir -r /opt/linkfinder/requirements.txt || true; fi; \
	ln -sf /opt/linkfinder/linkfinder.py /usr/local/bin/linkfinder.py || true; \
	chmod +x /usr/local/bin/linkfinder.py || true; \
	# sqlmap
	git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git /opt/sqlmap || true; \
	ln -sf /opt/sqlmap/sqlmap.py /usr/local/bin/sqlmap.py || true; \
	chmod +x /usr/local/bin/sqlmap.py || true; \
	# commix
	git clone --depth 1 https://github.com/commixproject/commix.git /opt/commix || true; \
	ln -sf /opt/commix/commix.py /usr/local/bin/commix || true; \
	chmod +x /usr/local/bin/commix || true; \
	# tplmap
	git clone --depth 1 https://github.com/epinna/tplmap.git /opt/tplmap || true; \
	ln -sf /opt/tplmap/tplmap.py /usr/local/bin/tplmap.py || true; \
	chmod +x /usr/local/bin/tplmap.py || true; \
	pip install --no-cache-dir -r /opt/tplmap/requirements.txt || true; \
	# CMSmap
	git clone --depth 1 https://github.com/Dionach/CMSmap.git /opt/CMSmap || true; \
	ln -sf /opt/CMSmap/cmsmap.py /usr/local/bin/cmsmap || true; \
	chmod +x /usr/local/bin/cmsmap || true; \
	# metagoofil (from git since not in PyPI)
	git clone --depth 1 https://github.com/opsdisk/metagoofil.git /opt/metagoofil || true; \
	ln -sf /opt/metagoofil/metagoofil.py /usr/local/bin/metagoofil || true; \
	chmod +x /usr/local/bin/metagoofil || true; \
	if [ -f /opt/metagoofil/requirements.txt ]; then pip install --no-cache-dir -r /opt/metagoofil/requirements.txt || true; fi; \
	# Sublist3r (modulo python costuma variar por distro; instala via git e cria wrapper fixo)
	git clone --depth 1 https://github.com/aboul3la/Sublist3r.git /opt/Sublist3r || true; \
	if [ -f /opt/Sublist3r/requirements.txt ]; then pip install --no-cache-dir -r /opt/Sublist3r/requirements.txt || true; fi; \
	printf '#!/bin/sh\nexec python3 /opt/Sublist3r/sublist3r.py "$@"\n' > /usr/local/bin/sublist3r; \
	chmod +x /usr/local/bin/sublist3r; \
	ln -sf /opt/Sublist3r/sublist3r.py /usr/local/bin/sublist3r.py || true; \
	# Wappalyzer CLI
	npm install -g wappalyzer || true; \
	# urlscan-cli (Node)
	npm install -g urlscan || true; \
	# postman-to-k6 (Node)
	npm install -g @apideck/postman-to-k6 || true; \
	# shcheck - analise de cabecalhos HTTP focada em seguranca
	pip install --no-cache-dir shcheck || true; \
	rm -rf /var/lib/apt/lists/* /tmp/*.zip

# Ferramentas Ruby
RUN gem install --no-document wpscan || true

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Templates customizados do Nuclei (obrigatorio)
RUN test -d nuclei-templates
RUN find nuclei-templates -type f \( -name '*.yaml' -o -name '*.yml' \) | grep -q .
RUN mkdir -p /root/.nuclei && rm -rf /root/.nuclei/templates && cp -R nuclei-templates /root/.nuclei/templates

# Vulscan NSE script para nmap vulnerability assessment
RUN git clone --depth 1 https://github.com/scipag/vulscan.git /usr/share/nmap/scripts/vulscan || true

# ASM Rules: prefer bundled rules in repo; fallback to remote download
RUN mkdir -p /root/.easm && \
	(if [ -d /app/asm-rules ]; then rm -rf /root/.easm/rules && cp -R /app/asm-rules /root/.easm/rules; else python3 /app/scripts/download_asm_rules.py || echo "[!] ASM rules download failed (non-critical)"; fi)

# Setup Burp CLI (Java + burp-cli-scan)
RUN bash /app/setup_burp.sh

# Download and configure Burp Suite wordlists for Repeater/Intruder
RUN bash /app/scripts/configure_burp_advanced.sh || echo "[!] Burp advanced config failed (non-critical)"

CMD ["sh", "-c", "alembic -c alembic.ini upgrade head && uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload"]
