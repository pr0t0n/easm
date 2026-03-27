# eclipse-temurin:21-jre-jammy = Ubuntu 22.04 + Java 21 JRE pré-instalado,
# funciona em amd64 e arm64 sem precisar adicionar repositórios extras.
FROM eclipse-temurin:21-jre-jammy

ENV DEBIAN_FRONTEND=noninteractive \
    DISPLAY=:99 \
    BURP_HOME=/root/.BurpSuite \
    BURP_JAR=/opt/burpsuite/burpsuite_pro.jar \
    BURP_API_HOST=0.0.0.0 \
    BURP_API_PORT=1337 \
    BURP_BROWSER_VERSION=146.0.7680.153 \
    PATH="/usr/local/go/bin:/root/go/bin:${PATH}"

# Xvfb (display virtual) + Go toolchain + utilitários; Java já está na imagem base
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    git \
    python3 \
    procps \
    xvfb \
    x11-utils \
    && rm -rf /var/lib/apt/lists/*

# Instala Go (detecta arquitetura amd64 / arm64)
RUN set -eux; \
    ARCH="$(uname -m)"; \
    case "$ARCH" in \
        aarch64|arm64) GA=arm64 ;; \
        *) GA=amd64 ;; \
    esac; \
    curl -fsSL "https://go.dev/dl/go1.22.5.linux-${GA}.tar.gz" | tar -C /usr/local -xz; \
    go version

# Compila o cliente REST cihanmehmet/burp-cli
RUN git clone --depth 1 https://github.com/cihanmehmet/burp-cli.git /tmp/burpcli \
    && cd /tmp/burpcli \
    && go build -o /usr/local/bin/burp-api-cli . \
    && rm -rf /tmp/burpcli

WORKDIR /opt/burp

# JAR do Burp Pro (deve estar em burp/burpsuite_pro.jar no build context)
COPY burpsuite_pro.jar /opt/burpsuite/burpsuite_pro.jar

# Configuração e scripts
COPY config/ /opt/burp/config/
COPY scripts/ /opt/burp/scripts/
RUN chmod +x /opt/burp/scripts/*.sh /opt/burp/scripts/*.py 2>/dev/null || true

# Cria o diretório do browser esperado pelo Burp para evitar erro de path
RUN mkdir -p "/opt/burpsuite/bin/burpbrowser/${BURP_BROWSER_VERSION}"

# Volume para persistir o estado (EULA aceite, config, projetos)
VOLUME ["/root/.BurpSuite"]

HEALTHCHECK --interval=15s --timeout=5s --start-period=120s --retries=10 \
    CMD python3 -c "import urllib.request,os; urllib.request.urlopen('http://127.0.0.1:'+os.environ.get('BURP_API_PORT','1337')+'/v0.1/',timeout=4)"

EXPOSE 1337

ENTRYPOINT ["/opt/burp/scripts/entrypoint.sh"]
