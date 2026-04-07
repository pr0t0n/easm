import json
import os
import re
import shutil
import subprocess
import sys
from typing import Any
from urllib.parse import urlparse, urlunparse

from app.core.config import settings
from app.services.asm_rules_service import get_asm_rules_service

from app.workers.worker_groups import find_group_by_tool, get_worker_groups


SAFE_TOOL_REGISTRY = {
    "recon": ["amass", "massdns", "sublist3r", "nmap"],
    "osint": ["shodan-cli"],
    "vuln": ["burp-cli", "nmap-vulscan", "nikto"],
}

TOOL_TIMEOUT_SECONDS = 90

VULSCAN_PRIORITY_TCP_PORTS = [
    20, 21, 22, 23,
    25, 53,
    80, 81, 110, 119, 123,
    135, 139, 143, 161, 162,
    389, 443, 444, 445, 465, 587, 636,
    993, 995,
    1433, 3306, 3389,
    5060,
    5432, 6379,
    8080, 8443, 8888,
    27017,
]

# Tool-specific timeouts (override default TOOL_TIMEOUT_SECONDS)
TOOL_SPECIFIC_TIMEOUTS = {
    "nmap": 600,
    "nmap-vulscan": 600,
    "amass": 120,
    "massdns": 120,
    "sublist3r": 120,
    "shodan-cli": 60,
    "burp-cli": 1860,
    "nikto": 240,
}

OFFICIALLY_DISABLED_TOOLS: dict[str, str] = {}




def _rewrite_localhost_for_docker(raw_target: str) -> str:
    raw = str(raw_target or "").strip()
    if not raw:
        return raw

    # Em workers Docker, localhost aponta para o proprio container.
    # Para scans no host da maquina (dev local), redirecionamos para host.docker.internal.
    if not os.path.exists("/.dockerenv"):
        return raw

    parsed = urlparse(raw if "://" in raw else f"http://{raw}")
    host = (parsed.hostname or "").strip().lower()
    if host not in {"localhost", "127.0.0.1", "::1"}:
        return raw

    port_part = f":{parsed.port}" if parsed.port else ""
    rewritten_netloc = f"host.docker.internal{port_part}"
    rewritten = parsed._replace(netloc=rewritten_netloc)
    rewritten_url = urlunparse(rewritten)

    # Mantem o formato de entrada sem schema quando aplicavel.
    if "://" not in raw:
        return rewritten_url.replace("http://", "", 1)
    return rewritten_url


def _first_existing_path(paths: list[str]) -> str | None:
    for path in paths:
        if os.path.exists(path):
            return path
    return None


def _target_parts(target: str) -> dict[str, str]:
    raw = _rewrite_localhost_for_docker((target or "").strip())
    if not raw:
        return {"raw": "", "host": "", "url": ""}

    parsed = urlparse(raw if "://" in raw else f"http://{raw}")
    host = parsed.hostname or raw.replace("http://", "").replace("https://", "").split("/")[0]
    url = raw if "://" in raw else f"http://{host}"
    return {"raw": raw, "host": host, "url": url}


def _tool_binary(tool_name: str) -> str:
    aliases = {
        "theharvester": "theHarvester",
        "shodan-cli": "shodan",
        "urlscan-cli": "urlscan",
        "kiterunner": "kr",
        "nmap-vulscan": "nmap",
        "vulscan": "nmap",
        "linkfinder": "linkfinder.py",
        "secretfinder": "SecretFinder.py",
        "shcheck": "shcheck.py",
        "curl-headers": "curl",
        "wappalyzer": "wappalyzer",
        "sublist3r": "python3",
        "zap": "zaproxy",
        "owasp-zap": "zaproxy",
        "sqlmap": "sqlmap.py",
        "tplmap": "python3",
        "commix": "python3",
        "burp": "burp-cli",
    }
    normalized = tool_name.strip().lower()
    return aliases.get(normalized, normalized)


def _build_tool_command(tool_name: str, target: str) -> list[str]:
    parts = _target_parts(target)
    host = parts["host"]
    url = parts["url"]
    normalized = tool_name.strip().lower()

    if normalized in {"nmap-vulscan", "vulscan"}:
        ports_csv = ",".join(str(p) for p in VULSCAN_PRIORITY_TCP_PORTS)
        return [
            "nmap",
            "-Pn",
            "-n",
            "-sV",
            "-T3",
            "-p",
            ports_csv,
            "--script=vulscan/",
            "--script-args",
            "vulscandb=cve.csv",
            host,
        ]
    if normalized in {"burp", "burp-cli"}:
        # Preferimos JSON em stdout para parser unificado no workflow.
        # Flag -a fornece verbosidade completa dos resultados.
        # O wrapper burp-cli lê BURP_API_HOST/BURP_API_PORT das env vars
        # (set via docker-compose), então NÃO passamos -t/-p no comando.
        # Para alvos sem esquema explícito, Burp tende a ser mais estável com HTTPS.
        burp_url = url
        if "://" not in str(parts.get("raw") or "") and host:
            burp_url = f"https://{host}"
        return ["burp-cli", "scan", "-a", "--url", burp_url, "--format", "json"]
    if normalized == "nmap":
        return [
            "nmap",
            "-Pn",
            "-n",
            "-sT",
            "-sV",
            "-T3",
            "-p-",
            "--script=vulscan/",
            "--script-args",
            "vulscandb=cve.csv",
            host,
        ]
    if normalized == "naabu":
        return ["naabu", "-host", host, "-top-ports", "100", "-silent", "-rate", "1000"]
    if normalized == "subfinder":
        return ["subfinder", "-d", host, "-silent", "-t", "100"]
    if normalized == "findomain":
        return ["findomain", "-t", host, "-q"]
    if normalized == "chaos":
        return ["chaos", "-d", host, "-silent"]
    if normalized == "amass":
        return ["amass", "enum", "-passive", "-d", host]
    if normalized == "sublist3r":
        return ["sublist3r", "-d", host]
    if normalized == "assetfinder":
        return ["assetfinder", "--subs-only", host]
    if normalized == "cloudenum":
        return ["python3", "/opt/cloud_enum/cloud_enum.py", "-k", host]
    if normalized == "massdns":
        resolvers = _first_existing_path([
            "/usr/share/massdns/lists/resolvers.txt",
            "/opt/massdns/lists/resolvers.txt",
            "/root/go/pkg/mod/github.com/owasp-amass/resolve@v0.6.21/example/resolvers.txt",
            "/usr/local/lib/python3.12/site-packages/wapitiCore/data/attacks/resolvers.txt",
        ])
        wordlist = _first_existing_path([
            "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
            "/root/go/pkg/mod/github.com/owasp-amass/amass/v4@v4.2.0/examples/wordlists/subdomains-top1mil-5000.txt",
            "/usr/share/seclists/Discovery/DNS/namelist.txt",
        ])
        if resolvers and wordlist:
            return ["sh", "-c", f"cat {wordlist} | sed 's/$/.{host}/' | massdns -r {resolvers} -t A -o S -q"]
        if resolvers:
            return ["sh", "-c", f"echo {host} | massdns -r {resolvers} -t A -o S -q"]
        return ["massdns", "-h"]
    if normalized == "dnsenum":
        return ["dnsenum", host]
    if normalized == "dnsgen":
        return ["dnsgen", "--help"]
    if normalized == "puredns":
        return ["puredns", "--help"]
    if normalized == "alterx":
        return ["alterx", "-h"]
    if normalized == "httpx":
        return ["httpx", "-silent", "-title", "-tech-detect", "-status-code", "-u", url]
    if normalized == "katana":
        return ["katana", "-u", url, "-silent", "-d", "3", "-c", "50", "-rl", "30", "-js-crawl"]
    if normalized == "gowitness":
        return ["gowitness", "scan", "single", "--url", url]
    if normalized == "wappalyzer":
        return ["wappalyzer", url]
    if normalized == "webanalyze":
        return ["webanalyze", "-host", url]
    if normalized == "cmsmap":
        return ["cmsmap", "-t", url]
    if normalized == "whatweb":
        return ["whatweb", url]
    if normalized == "wafw00f":
        return ["wafw00f", url, "-a"]
    if normalized == "nuclei":
        templates_path = _get_nuclei_templates_path()
        if not templates_path:
            # Obrigatorio por requisito: sem templates customizados, nao executa nuclei.
            return ["__missing_nuclei_templates__"]
        nuclei_target = parts["raw"] or host
        cmd = ["nuclei", "--target", nuclei_target]
        # Obrigatorio: usa sempre os templates customizados instalados no worker.
        cmd.extend(["-t", templates_path])
        return cmd
    if normalized == "nikto":
        return ["nikto", "-h", url, "-C", "all", "-Tuning", "1234567890"]
    if normalized == "sslscan":
        return ["sslscan", "--no-colour", host]
    if normalized == "shcheck":
        return ["shcheck.py", url]
    if normalized == "curl-headers":
        return ["curl", "-I", "-sS", "--max-time", "20", url]
    if normalized == "wapiti":
        # Sem restricao de modulos — deixa o wapiti rodar todos (CSP, MIME, HTTPS, etc.)
        return [
            "wapiti",
            "-u",
            url,
            "--flush-session",
            "--scope",
            "domain",
            "--format",
            "txt",
            "-v",
            "1",
        ]
    if normalized == "zap":
        return ["zaproxy", "-version"]
    if normalized == "dalfox":
        return ["dalfox", "url", url, "--silence"]
    if normalized == "sqlmap":
        return ["python3", "/opt/sqlmap/sqlmap.py", "-u", url, "--batch", "--level", "2", "--risk", "1", "--random-agent", "--crawl=2"]
    if normalized == "commix":
        return ["python3", "/opt/commix/commix.py", "--url", url, "--batch", "--crawl=1"]
    if normalized == "tplmap":
        return ["python3", "/opt/tplmap/tplmap.py", "-u", url]
    if normalized == "wpscan":
        # Evita falha imediata quando o banco local ainda nao existe.
        # O WPScan atualiza metadata automaticamente quando necessario.
        return ["wpscan", "--url", url, "--disable-tls-checks", "--random-user-agent"]
    if normalized == "arjun":
        # -p nao e flag de metodo nessa versao do arjun; usa apenas --stable
        return ["arjun", "-u", url, "--stable"]
    if normalized == "ffuf":
        wordlist = _first_existing_path([
            "/usr/share/seclists/Discovery/Web-Content/phpmyadmin_paths.txt",
            "/usr/share/seclists/Discovery/Web-Content/common.txt",
            "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
            "/usr/share/dirb/wordlists/common.txt",
        ])
        if wordlist:
            return ["ffuf", "-w", wordlist, "-u", f"{url.rstrip('/')}/FUZZ", "-mc", "200,301,302,307", "-t", "50"]
        return ["ffuf", "-h"]
    if normalized == "wfuzz":
        wordlist = _first_existing_path([
            "/usr/share/dirb/wordlists/common.txt",
            "/usr/share/seclists/Discovery/Web-Content/common.txt",
        ])
        if wordlist:
            # wfuzz upstream ainda depende do modulo `imp`, removido no Python 3.12.
            # Fallback operacional: usa ffuf com wordlist equivalente.
            return ["ffuf", "-w", wordlist, "-u", f"{url.rstrip('/')}/FUZZ", "-mc", "200,301,302,307", "-t", "50"]
        return ["ffuf", "-h"]
    if normalized == "feroxbuster":
        wordlist = _first_existing_path([
            "/usr/share/seclists/Discovery/Web-Content/phpmyadmin_paths.txt",
            "/usr/share/seclists/Discovery/Web-Content/common.txt",
            "/usr/share/dirb/wordlists/common.txt",
        ])
        if wordlist:
            return ["feroxbuster", "-u", url, "--silent", "--no-recursion", "-t", "50", "-w", wordlist]
        return ["feroxbuster", "-u", url, "--silent", "--no-recursion", "-t", "50"]
    if normalized == "gobuster":
        wordlist = _first_existing_path([
            "/usr/share/seclists/Discovery/Web-Content/phpmyadmin_paths.txt",
            "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
            "/usr/share/seclists/Discovery/Web-Content/common.txt",
            "/usr/share/dirb/wordlists/common.txt",
        ])
        if wordlist:
            return ["gobuster", "dir", "-u", url, "-w", wordlist, "-q", "-k", "-t", "50"]
        return ["gobuster", "help"]
    if normalized == "dirb":
        wordlist = _first_existing_path([
            "/usr/share/dirb/wordlists/common.txt",
            "/usr/share/wordlists/dirb/common.txt",
        ])
        if wordlist:
            return ["dirb", url, wordlist, "-S"]
        return ["dirb", url]
    if normalized == "semgrep":
        return ["semgrep", "--version"]
    if normalized == "linkfinder":
        return ["linkfinder.py", "-i", url, "-o", "cli"]
    if normalized == "secretfinder":
        return ["SecretFinder.py", "-i", url, "-o", "cli"]
    if normalized == "trufflehog":
        # trufflehog v3+ exige subcomando: 'git' para repositorios git
        return ["trufflehog", "git", f"https://{host}", "--no-update"]
    if normalized == "kiterunner":
        return ["kr", "help"]
    if normalized == "postman-to-k6":
        return ["postman-to-k6", "--help"]
    if normalized == "h8mail":
        return ["h8mail", "-h"]
    if normalized == "metagoofil":
        return ["metagoofil", "-h"]
    if normalized == "subjack":
        fingerprints = _first_existing_path([
            "/opt/subjack/fingerprints.json",
            "/usr/share/subjack/fingerprints.json",
            "/go/pkg/mod/github.com/haccer/subjack*/fingerprints.json",
        ])
        if fingerprints:
            return ["subjack", "-d", host, "-ssl", "-t", "100", "-timeout", "30", "-c", fingerprints]
        return ["subjack", "-d", host, "-ssl", "-t", "100", "-timeout", "30"]
    if normalized == "urlscan-cli":
        return ["urlscan", "-h"]
    if normalized == "theharvester":
        return ["theHarvester", "-d", host, "-b", "bing", "-l", "20"]
    if normalized == "shodan-cli":
        return ["shodan", "stats", "--facets", "port"]
    if normalized == "waymore":
        return ["waymore", "-i", host, "-mode", "U"]
    if normalized == "uro":
        return ["uro", "--help"]

    return [_tool_binary(normalized), target]


def _parse_open_ports(tool_name: str, stdout: str) -> list[int]:
    normalized = tool_name.strip().lower()
    ports: set[int] = set()

    if normalized in {"nmap", "nmap-vulscan", "vulscan"}:
        for match in re.findall(r"(?m)^(\d+)/tcp\s+open", stdout or ""):
            try:
                ports.add(int(match))
            except ValueError:
                continue
    elif normalized == "naabu":
        for match in re.findall(r":(\d{1,5})\b", stdout or ""):
            try:
                port = int(match)
            except ValueError:
                continue
            if 1 <= port <= 65535:
                ports.add(port)
    elif normalized == "nikto":
        # Exemplo: + Target Port: 443
        for match in re.findall(r"(?im)^\+\s*Target\s+Port:\s*(\d{1,5})\b", stdout or ""):
            try:
                port = int(match)
            except ValueError:
                continue
            if 1 <= port <= 65535:
                ports.add(port)
    elif normalized in {"httpx", "whatweb"}:
        # Heuristica: linhas com URL retornada pela ferramenta.
        for raw in (stdout or "").splitlines():
            line = str(raw or "").strip()
            if not line:
                continue
            url_match = re.search(r"https?://[^\s\]]+", line)
            if not url_match:
                continue
            parsed = urlparse(url_match.group(0))
            if parsed.port:
                port = parsed.port
            elif parsed.scheme == "https":
                port = 443
            else:
                port = 80
            if 1 <= int(port) <= 65535:
                ports.add(int(port))

    return sorted(ports)


def _run_cli_tool(tool_name: str, target: str) -> dict[str, Any]:
    normalized_tool = str(tool_name or "").strip().lower()
    if normalized_tool in OFFICIALLY_DISABLED_TOOLS:
        return {
            "status": "skipped",
            "output": OFFICIALLY_DISABLED_TOOLS[normalized_tool],
            "open_ports": [],
            "return_code": 0,
            "command": f"{normalized_tool} <disabled>",
            "stdout": "",
            "stderr": "",
        }

    if normalized_tool == "nuclei" and _get_nuclei_templates_path() is None:
        return {
            "status": "error",
            "output": "Templates do Nuclei obrigatorios nao encontrados em /root/.nuclei/templates.",
            "open_ports": [],
            "return_code": 2,
            "command": "nuclei -u <target> -t /root/.nuclei/templates",
            "stdout": "",
            "stderr": "missing mandatory nuclei templates",
        }

    if normalized_tool in {"shodan", "shodan-cli"} and not str(os.getenv("SHODAN_API_KEY", "")).strip():
        return {
            "status": "skipped",
            "output": "SHODAN_API_KEY nao configurada — shodan-cli ignorado.",
            "open_ports": [],
            "return_code": 0,
            "command": "shodan search hostname:<target>",
            "stdout": "",
            "stderr": "missing shodan api key",
        }

    if normalized_tool in {"shodan", "shodan-cli"}:
        return _run_shodan_python_query(target)

    binary = _tool_binary(tool_name)
    if shutil.which(binary) is None:
        if normalized_tool in {"burp", "burp-cli"}:
            return {
                "status": "skipped",
                "output": f"Ferramenta {tool_name} indisponivel no worker ({binary}); Burp marcado como skipped.",
                "open_ports": [],
                "return_code": 0,
                "command": f"{binary} <missing>",
                "stdout": "",
                "stderr": "missing burp-cli binary",
            }
        return {
            "status": "error",
            "output": f"Ferramenta {tool_name} nao encontrada no worker ({binary}).",
            "open_ports": [],
        }

    if normalized_tool == "curl-headers":
        return _run_curl_headers_tool(target)

    cmd = _build_tool_command(tool_name, target)
    if cmd and cmd[0] == "__missing_nuclei_templates__":
        return {
            "status": "error",
            "output": "Templates do Nuclei obrigatorios nao encontrados no worker.",
            "open_ports": [],
            "return_code": 2,
            "command": "nuclei -u <target> -t /root/.nuclei/templates",
            "stdout": "",
            "stderr": "missing mandatory nuclei templates",
        }
    timeout_seconds = TOOL_SPECIFIC_TIMEOUTS.get(normalized_tool, TOOL_TIMEOUT_SECONDS)
    try:
        proc = subprocess.run(
            cmd,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired:
        return {
            "status": "error",
            "output": f"Timeout ao executar {tool_name} em {timeout_seconds}s.",
            "open_ports": [],
        }
    except Exception as exc:
        return {
            "status": "error",
            "output": f"Falha ao executar {tool_name}: {exc}",
            "open_ports": [],
        }

    stdout = (proc.stdout or "").strip()
    stderr = (proc.stderr or "").strip()
    combined = "\n".join(part for part in [stdout, stderr] if part)
    if not combined:
        combined = f"{tool_name} executado sem output textual."

    if normalized_tool == "nuclei":
        output_limit = 30000
        stream_limit = 20000
    elif normalized_tool in {"burp", "burp-cli"}:
        # Burp retorna JSON potencialmente grande; truncar cedo quebra parser de findings.
        output_limit = 60000
        stream_limit = 50000
    else:
        output_limit = 2500
        stream_limit = 1500

    open_ports = _parse_open_ports(tool_name, stdout)
    status = "executed" if proc.returncode == 0 else "error"

    # Nmap pode retornar 0 mesmo quando nenhum alvo foi resolvido.
    if normalized_tool in {"nmap-vulscan", "vulscan", "nmap"}:
        stderr_l = (stderr or "").lower()
        stdout_l = (stdout or "").lower()
        unresolved = "failed to resolve" in stderr_l
        zero_hosts = "0 hosts up" in stdout_l or "0 hosts scanned" in stderr_l
        if unresolved and zero_hosts:
            status = "error"

    # Nikto em algumas imagens exige modulo Perl JSON; trata como dependencia ausente.
    if normalized_tool == "nikto" and (
        "Required module not found: JSON" in stderr
        or "Required module not found: XML::Writer" in stderr
    ):
        status = "skipped"

    # Burp pode ficar indisponivel quando REST API/JAR proprietario nao estao prontos.
    if normalized_tool in {"burp", "burp-cli"}:
        lowered = combined.lower()
        burp_unavailable_markers = [
            "burp rest api indisponivel",
            "burp pro jar nao encontrado",
            "missing /burp/burpsuite_pro.jar",
            "burp_not_found",
        ]
        if any(marker in lowered for marker in burp_unavailable_markers):
            status = "skipped"

    # WPScan em alvos que nao sao WordPress nao deve ser tratado como erro de execucao.
    if normalized_tool == "wpscan" and "does not seem to be running WordPress" in combined:
        status = "skipped"

    return {
        "status": status,
        "output": combined[:output_limit],
        "open_ports": open_ports,
        "return_code": proc.returncode,
        "command": " ".join(cmd),
        "stdout": stdout[:stream_limit],
        "stderr": stderr[:stream_limit],
    }


def _http_status_code_from_headers(raw_headers: str) -> int:
    for raw_line in (raw_headers or "").splitlines():
        line = str(raw_line or "").strip()
        if not line:
            continue
        match = re.match(r"^HTTP/\S+\s+(\d{3})\b", line, re.IGNORECASE)
        if match:
            try:
                return int(match.group(1))
            except ValueError:
                return 0
    return 0


def _with_scheme(target: str, scheme: str) -> str:
    raw = str(target or "").strip()
    if not raw:
        return ""
    parsed = urlparse(raw if "://" in raw else f"{scheme}://{raw}")
    host = str(parsed.hostname or "").strip()
    if not host:
        return ""
    port = f":{parsed.port}" if parsed.port else ""
    path = str(parsed.path or "").strip() or "/"
    query = f"?{parsed.query}" if parsed.query else ""
    return f"{scheme}://{host}{port}{path}{query}"


def _run_curl_headers_tool(target: str) -> dict[str, Any]:
    # Regra operacional: sempre usar schema explicito e, se HTTP responder 301/302,
    # reexecutar automaticamente com HTTPS para capturar headers finais.
    raw = str(target or "").strip()
    if not raw:
        return {
            "status": "error",
            "output": "Target vazio para curl-headers.",
            "open_ports": [],
            "return_code": 2,
            "command": "curl -I <target>",
            "stdout": "",
            "stderr": "target vazio",
        }

    if "://" in raw:
        first_url = raw
    else:
        first_url = _with_scheme(raw, "http")

    if not first_url:
        return {
            "status": "error",
            "output": "Target invalido para curl-headers.",
            "open_ports": [],
            "return_code": 2,
            "command": "curl -I <target>",
            "stdout": "",
            "stderr": "target invalido",
        }

    first_cmd = ["curl", "-I", "-sS", "--max-time", "20", first_url]
    timeout_seconds = TOOL_SPECIFIC_TIMEOUTS.get("curl-headers", 25)

    try:
        first = subprocess.run(first_cmd, check=False, capture_output=True, text=True, timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        return {
            "status": "error",
            "output": f"Timeout ao executar curl-headers em {timeout_seconds}s.",
            "open_ports": [],
            "return_code": 124,
            "command": " ".join(first_cmd),
            "stdout": "",
            "stderr": "timeout",
        }
    except Exception as exc:
        return {
            "status": "error",
            "output": f"Falha ao executar curl-headers: {exc}",
            "open_ports": [],
            "return_code": 1,
            "command": " ".join(first_cmd),
            "stdout": "",
            "stderr": str(exc),
        }

    first_stdout = str(first.stdout or "").strip()
    first_stderr = str(first.stderr or "").strip()
    first_code = _http_status_code_from_headers(first_stdout)

    combined_stdout = f"# URL: {first_url}\n{first_stdout}".strip()
    combined_stderr = first_stderr
    command_str = " ".join(first_cmd)
    return_code = first.returncode

    is_http = first_url.lower().startswith("http://")
    should_retry_https = is_http and first_code in {301, 302}

    if should_retry_https:
        https_url = _with_scheme(first_url, "https")
        if https_url:
            second_cmd = ["curl", "-I", "-sS", "--max-time", "20", https_url]
            try:
                second = subprocess.run(second_cmd, check=False, capture_output=True, text=True, timeout=timeout_seconds)
                second_stdout = str(second.stdout or "").strip()
                second_stderr = str(second.stderr or "").strip()
                combined_stdout = (
                    f"# URL: {first_url}\n{first_stdout}\n\n"
                    f"# URL: {https_url}\n{second_stdout}"
                ).strip()
                combined_stderr = "\n".join(part for part in [first_stderr, second_stderr] if part)
                command_str = f"{' '.join(first_cmd)} ; {' '.join(second_cmd)}"
                return_code = 0 if second.returncode == 0 else second.returncode
            except Exception as exc:
                combined_stderr = "\n".join(part for part in [first_stderr, f"https_retry_error={exc}"] if part)

    output = "\n".join(part for part in [combined_stdout, combined_stderr] if part).strip()
    if not output:
        output = "curl-headers executado sem output textual."

    status = "executed" if return_code == 0 else "error"
    return {
        "status": status,
        "output": output[:2500],
        "open_ports": [],
        "return_code": return_code,
        "command": command_str,
        "stdout": combined_stdout[:1500],
        "stderr": combined_stderr[:1500],
    }


def _run_shodan_python_query(target: str) -> dict[str, Any]:
    """Executa consulta Shodan via biblioteca Python, sem depender do binario CLI."""
    parsed = urlparse(target if "://" in target else f"https://{target}")
    host = (parsed.hostname or str(target or "").strip()).strip()
    if not host:
        return {
            "status": "error",
            "output": "Target vazio para shodan-cli.",
            "open_ports": [],
            "return_code": 2,
            "command": "shodan search hostname:<target>",
            "stdout": "",
            "stderr": "target vazio",
        }

    script = "\n".join([
        "import shodan, json, os",
        "api = shodan.Shodan(os.environ.get('SHODAN_API_KEY', ''))",
        f"host = {repr(host)}",
        "try:",
        "    results = api.search(f'hostname:\"{host}\"', limit=50)",
        "    print(json.dumps(results))",
        "except Exception as e:",
        "    print(json.dumps({'error': str(e), 'matches': [], 'total': 0}))",
    ])

    timeout_secs = TOOL_SPECIFIC_TIMEOUTS.get("shodan-cli", 60)
    try:
        proc = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True,
            text=True,
            timeout=timeout_secs,
            env={**os.environ},
        )
    except subprocess.TimeoutExpired:
        return {
            "status": "error",
            "output": f"Timeout ao executar shodan-cli em {timeout_secs}s.",
            "open_ports": [],
            "return_code": -1,
            "command": f"shodan search hostname:\"{host}\"",
            "stdout": "",
            "stderr": "timeout",
        }
    except Exception as exc:
        return {
            "status": "error",
            "output": f"Falha ao executar shodan-cli: {exc}",
            "open_ports": [],
            "return_code": 1,
            "command": f"shodan search hostname:\"{host}\"",
            "stdout": "",
            "stderr": str(exc),
        }

    stdout = (proc.stdout or "").strip()
    stderr = (proc.stderr or "").strip()

    # Verifica erro retornado pelo script Python
    try:
        parsed_out = json.loads(stdout) if stdout else {}
        if isinstance(parsed_out, dict) and parsed_out.get("error"):
            return {
                "status": "error",
                "output": f"Shodan API error: {parsed_out['error']}",
                "open_ports": [],
                "return_code": 1,
                "command": f"shodan search hostname:\"{host}\"",
                "stdout": stdout[:1500],
                "stderr": stderr[:1500],
            }
    except Exception:
        pass

    try:
        json.loads(stdout)
    except Exception:
        stdout = ""

    status = "executed" if stdout else "error"
    output = stdout or stderr or "shodan-cli executado sem output textual."
    # stdout precisa carregar o JSON completo para que _extract_shodan_findings consiga parsear.
    return {
        "status": status,
        "output": output[:300],
        "open_ports": [],
        "return_code": proc.returncode,
        "command": f"shodan search hostname:\"{host}\"",
        "stdout": stdout,          # JSON completo — sem truncagem
        "stderr": stderr[:1500],
    }


def get_execution_mode() -> str:
    return os.getenv("TOOL_EXECUTION_MODE", "controlled").strip().lower()


def resolve_worker_for_tool(tool_name: str, scan_mode: str = "unit") -> str:
    group = find_group_by_tool(tool_name, mode=scan_mode)
    groups = get_worker_groups(scan_mode)
    queue = groups.get(group, {}).get("queue", f"worker.{scan_mode}.reconhecimento")
    return str(queue)


def evaluate_asm_rules(output: str, tool_name: str = "") -> list[dict[str, Any]]:
    """Evaluate tool output against ASM rules and return findings."""
    try:
        asm_service = get_asm_rules_service()
        findings = asm_service.evaluate(output, tool_name=tool_name)
        return findings
    except Exception as e:
        # ASM rules optional, don't break tool execution
        return []


def _parse_nuclei_output_to_findings(output: str) -> list[dict[str, Any]]:
    """Converte linhas do nuclei para achados estruturados quando ASM rules nao cobrem o caso."""
    findings: list[dict[str, Any]] = []
    if not output:
        return findings

    # Exemplo esperado:
    # [template-id] [http] [high] http://target/path
    ansi_pattern = re.compile(r"\x1b\[[0-9;]*m")
    line_pattern = re.compile(r"^\[(?P<template>[^\]]+)\]\s+\[(?P<proto>[^\]]+)\]\s+\[(?P<severity>[^\]]+)\]\s+(?P<target>\S+)")

    seen: set[tuple[str, str, str]] = set()
    for raw in output.splitlines():
        line = ansi_pattern.sub("", (raw or "")).strip()
        if not line:
            continue
        match = line_pattern.match(line)
        if not match:
            continue

        template_id = str(match.group("template") or "").strip()
        severity = str(match.group("severity") or "medium").strip().lower()
        target = str(match.group("target") or "").strip()

        if not template_id or not target:
            continue

        dedupe_key = (template_id, severity, target)
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)

        risk_score = {
            "critical": 10,
            "high": 8,
            "medium": 5,
            "low": 3,
            "info": 1,
        }.get(severity, 5)

        findings.append(
            {
                "title": f"Nuclei hit: {template_id}",
                "severity": severity,
                "risk_score": risk_score,
                "source_worker": "vuln",
                "template_id": template_id,
                "target": target,
                "raw_line": line,
            }
        )

    return findings


def run_tool_execution(tool_name: str, target: str, scan_mode: str = "unit") -> dict[str, Any]:
    # Execucao controlada por policy/compliance na camada de orquestracao.
    worker = resolve_worker_for_tool(tool_name, scan_mode=scan_mode)
    mode = get_execution_mode()

    if tool_name.strip().lower() == "nessus":
        return _run_nessus_scan(target=target, worker=worker, mode=mode, scan_mode=scan_mode)

    execution = _run_cli_tool(tool_name=tool_name, target=target)
    
    # Mantemos apenas achados nativos das ferramentas (ASM rules desativado).
    asm_findings = []
    tool_output = execution.get("output", "") or execution.get("stdout", "")

    # Fallback especifico para nuclei: transforma stdout em achados estruturados.
    if tool_name.strip().lower() == "nuclei" and not asm_findings:
        asm_findings = _parse_nuclei_output_to_findings(tool_output)

    return {
        "tool": tool_name,
        "target": target,
        "scan_mode": scan_mode,
        "worker": worker,
        "mode": mode,
        "status": execution.get("status", "error"),
        "output": execution.get("output", ""),
        "open_ports": execution.get("open_ports", []),
        "return_code": execution.get("return_code"),
        "command": execution.get("command", ""),
        "stdout": execution.get("stdout", ""),
        "stderr": execution.get("stderr", ""),
        "asm_findings": asm_findings,
        "bypass": False,
    }


def _run_nessus_scan(target: str, worker: str, mode: str, scan_mode: str) -> dict[str, Any]:
    if not settings.nessus_enabled:
        return {
            "tool": "nessus",
            "target": target,
            "scan_mode": scan_mode,
            "worker": worker,
            "mode": mode,
            "status": "skipped",
            "output": "Nessus desabilitado em configuracao.",
        }

    if not settings.nessus_url or not settings.nessus_access_key or not settings.nessus_secret_key:
        return {
            "tool": "nessus",
            "target": target,
            "scan_mode": scan_mode,
            "worker": worker,
            "mode": mode,
            "status": "error",
            "output": "Nessus habilitado, mas sem URL/access_key/secret_key configurados.",
        }

    try:
        # Biblioteca esperada: pynessus / nessus. Mantemos import tardio para evitar quebrar o runtime.
        from nessus import NessusClient  # type: ignore
    except Exception:
        try:
            from pynessus import NessusClient  # type: ignore
        except Exception as exc:
            return {
                "tool": "nessus",
                "target": target,
                "scan_mode": scan_mode,
                "worker": worker,
                "mode": mode,
                "status": "error",
                "output": f"pynessus/nessus nao instalado no worker: {exc}",
            }

    parsed = urlparse(settings.nessus_url)
    host = parsed.hostname or settings.nessus_url.replace("https://", "").replace("http://", "")
    port = parsed.port or (8834 if parsed.scheme in {"https", ""} else 80)
    ssl = parsed.scheme != "http"

    try:
        client = NessusClient(
            host=host,
            access_key=settings.nessus_access_key,
            secret_key=settings.nessus_secret_key,
            port=port,
            ssl=ssl,
            verify=settings.nessus_verify_tls,
        )

        # Descoberta + scanner/vuln analyst: lança scan básico no alvo informado.
        scan_name = f"EASM-{scan_mode}-{target}"
        launch = client.scans.create_and_launch(
            name=scan_name,
            targets=target,
            template="basic",
        )

        return {
            "tool": "nessus",
            "target": target,
            "scan_mode": scan_mode,
            "worker": worker,
            "mode": mode,
            "status": "executed",
            "output": f"Nessus scan iniciado: {scan_name}",
            "scan_id": launch.get("scan_id") if isinstance(launch, dict) else None,
            "scan_uuid": launch.get("scan_uuid") if isinstance(launch, dict) else None,
        }
    except Exception as exc:
        return {
            "tool": "nessus",
            "target": target,
            "scan_mode": scan_mode,
            "worker": worker,
            "mode": mode,
            "status": "error",
            "output": f"Falha ao executar Nessus via pynessus: {exc}",
        }


# ============================================================================
# Burp Suite Advanced Testing (Repeater + Intruder)
# ============================================================================

def get_burp_advanced_config() -> dict[str, Any]:
    """
    Get Burp Suite advanced testing configuration.
    Returns paths to wordlists and configuration files for IDOR and SQLi testing.
    """
    from pathlib import Path
    
    config_dir = Path("/opt/burp-config")
    wordlist_dir = Path("/opt/burp-wordlists")
    
    config = {
        "burp_config_dir": str(config_dir),
        "burp_wordlist_dir": str(wordlist_dir),
        "available": bool(wordlist_dir.exists() and config_dir.exists()),
        "configurations": {},
        "wordlists": {}
    }
    
    # Load configuration files if available
    if config_dir.exists():
        for config_file in config_dir.glob("*.yaml"):
            config["configurations"][config_file.stem] = str(config_file)
        for config_file in config_dir.glob("*.json"):
            config["configurations"][config_file.stem] = str(config_file)
    
    # List available wordlists
    if wordlist_dir.exists():
        for category_dir in wordlist_dir.iterdir():
            if category_dir.is_dir():
                wordlists = [f.name for f in category_dir.glob("*.txt")]
                if wordlists:
                    config["wordlists"][category_dir.name] = {
                        "path": str(category_dir),
                        "files": wordlists,
                        "count": len(wordlists)
                    }
    
    return config


def configure_burp_intruder_attack(
    target_url: str,
    parameter: str,
    wordlist_type: str = "discovery"
) -> dict[str, Any]:
    """
    Configure a Burp Intruder attack for fuzzing.
    
    Args:
        target_url: Target URL for attack
        parameter: Parameter name to fuzz
        wordlist_type: Type of wordlist (discovery, vulnerabilities, common, credentials)
    
    Returns:
        Configuration dictionary for Burp Intruder
    """
    from pathlib import Path
    
    wordlist_dir = Path("/opt/burp-wordlists")
    
    # Map wordlist types to files
    wordlist_mapping = {
        "discovery": [
            "directory_list_2.3_medium.txt",
            "fuzz_php_special.txt",
            "lfi_all.txt",
        ],
        "vulnerabilities": [
            "sql_inj.txt",
            "xss.txt",
            "ssti.txt",
            "all_attacks.txt",
        ],
        "common": ["common.txt", "common_sql_tables.txt"],
        "credentials": ["portuguese.txt", "rockyou.txt"],
    }
    
    wordlist_choices = wordlist_mapping.get(wordlist_type, [])
    
    # Find first available wordlist
    selected_wordlist = None
    for wl in wordlist_choices:
        candidate = wordlist_dir / wordlist_type / wl
        if candidate.exists():
            selected_wordlist = str(candidate)
            break
    
    if not selected_wordlist:
        return {
            "status": "error",
            "message": f"No wordlists found for type '{wordlist_type}'",
            "target_url": target_url,
            "parameter": parameter,
        }
    
    # Determine attack parameters based on wordlist type
    attack_config = {
        "target": {
            "url": target_url,
            "parameter": parameter,
        },
        "attack": {
            "type": "Sniper",
            "wordlist": selected_wordlist,
            "wordlist_count": 0,
            "threads": 10,
            "timeout": 30,
        },
        "filters": {},
    }
    
    # Apply intelligent filters based on wordlist type
    if wordlist_type == "discovery":
        attack_config["attack"]["threads"] = 10
        attack_config["filters"]["response_code"] = "!404"
        attack_config["description"] = "Directory and parameter discovery fuzzing"
    elif wordlist_type == "vulnerabilities":
        attack_config["attack"]["threads"] = 5
        attack_config["filters"]["response_code"] = ["500", "502", "503"]
        attack_config["filters"]["keywords"] = ["error", "exception", "warning"]
        attack_config["description"] = "Vulnerability payload testing"
    elif wordlist_type == "credentials":
        attack_config["attack"]["threads"] = 3
        attack_config["attack"]["timeout"] = 60
        attack_config["filters"]["response_length"] = "!=<baseline>"
        attack_config["description"] = "Credential/password brute-force testing"
    
    # Count lines in wordlist
    try:
        with open(selected_wordlist, 'r') as f:
            attack_config["attack"]["wordlist_count"] = sum(1 for _ in f)
    except:
        pass
    
    return attack_config


def configure_burp_repeater_idor(
    target_url: str,
    parameter: str,
    original_value: str,
    test_type: str = "sequential"
) -> dict[str, Any]:
    """
    Configure Burp Repeater for IDOR (Insecure Direct Object Reference) testing.
    
    Args:
        target_url: Target URL
        parameter: Parameter prone to IDOR (id, user_id, etc.)
        original_value: Original parameter value
        test_type: Type of IDOR test (sequential, hash, uuid, timestamp)
    
    Returns:
        Configuration and test payloads for manual testing in Repeater
    """
    try:
        from app.services.burp_advanced_testing import IDORTester
        
        tester = IDORTester()
        
        config = {
            "status": "ready",
            "target_url": target_url,
            "parameter": parameter,
            "original_value": original_value,
            "test_type": test_type,
            "test_payloads": [],
            "instructions": {}
        }
        
        # Generate test payloads based on type
        if test_type == "sequential":
            payloads = tester.generate_sequential_payloads(parameter, original_value, count=20)
            config["instructions"]["description"] = "Test sequential ID increments (1, 2, 3, ...)"
            config["instructions"]["expected"] = "Same data format returned for different IDs"
        elif test_type == "hash":
            payloads = tester.generate_hash_payloads(parameter, original_value)
            config["instructions"]["description"] = "Test hash/UUID variations"
            config["instructions"]["expected"] = "Predictable hash patterns or collisions"
        elif test_type == "uuid":
            payloads = tester.generate_uuid_payloads(parameter)
            config["instructions"]["description"] = "Test common UUID patterns"
            config["instructions"]["expected"] = "UUID collision or predictability"
        elif test_type == "timestamp":
            payloads = tester.generate_timestamp_payloads(parameter)
            config["instructions"]["description"] = "Test timestamp-based ID prediction"
            config["instructions"]["expected"] = "Time-based ID correlation"
        else:
            payloads = []
            config["status"] = "error"
            config["message"] = f"Unknown test_type: {test_type}"
        
        # Format test payloads
        config["test_payloads"] = [
            {
                "value": p.test_value,
                "type": p.payload_type,
                "description": p.description,
                "url_with_payload": target_url.replace(
                    f"{parameter}={original_value}",
                    f"{parameter}={p.test_value}"
                ),
            }
            for p in payloads
        ]
        
        return config
    except ImportError:
        return {
            "status": "error",
            "message": "burp_advanced_testing module not available",
        }


def configure_burp_repeater_sqli(
    target_url: str,
    parameter: str,
    payload_type: str = "union"
) -> dict[str, Any]:
    """
    Configure Burp Repeater for SQL Injection (SQLi) testing.
    
    Args:
        target_url: Target URL
        parameter: SQL-injectable parameter
        payload_type: Type of SQLi test (union, boolean, time, error, all)
    
    Returns:
        Configuration and test payloads for manual testing in Repeater
    """
    try:
        from app.services.burp_advanced_testing import SQLiTester
        
        tester = SQLiTester()
        
        config = {
            "status": "ready",
            "target_url": target_url,
            "parameter": parameter,
            "payload_type": payload_type,
            "test_payloads": [],
            "instructions": {}
        }
        
        # Generate appropriate payloads
        if payload_type == "time":
            payloads = tester.generate_timing_payloads(parameter, delay=5)
            config["instructions"]["description"] = "Time-based blind SQLi detection"
            config["instructions"]["expected"] = "Response time increases by ~5 seconds"
            config["instructions"]["detection"] = "baseline_time + 4s or more"
        else:
            payloads = tester.generate_basic_payloads(parameter, payload_type)
            if payload_type == "union":
                config["instructions"]["description"] = "Union-based SQLi enumeration"
                config["instructions"]["expected"] = "Database version, user, or data in response"
            elif payload_type == "boolean":
                config["instructions"]["description"] = "Boolean-based blind SQLi"
                config["instructions"]["expected"] = "Different response for true vs false condition"
            elif payload_type == "error":
                config["instructions"]["description"] = "Error-based SQLi"
                config["instructions"]["expected"] = "SQL error messages in response"
            elif payload_type == "all":
                config["instructions"]["description"] = "Comprehensive SQLi testing"
                config["instructions"]["expected"] = "Various SQLi vulnerability indicators"
        
        # Format test payloads
        config["test_payloads"] = [
            {
                "payload": p.payload,
                "type": p.payload_type,
                "encoding": p.encoding,
                "description": p.description,
                "test_request": target_url.replace(
                    f"{parameter}=",
                    f"{parameter}={p.payload}"
                ),
            }
            for p in payloads[:15]  # Limit to 15 for manual testing
        ]
        
        return config
    except ImportError:
        return {
            "status": "error",
            "message": "burp_advanced_testing module not available",
        }


def detect_burp_sqli_timing(
    baseline_time: float,
    test_time: float,
    threshold: float = 2.0
) -> dict[str, Any]:
    """
    Detect SQL Injection vulnerability based on timing analysis.
    
    Args:
        baseline_time: Response time for normal request (seconds)
        test_time: Response time for SQLi payload request (seconds)
        threshold: Multiplier threshold for detection
    
    Returns:
        Analysis result with vulnerability indicators
    """
    try:
        from app.services.burp_advanced_testing import SQLiTester
        
        tester = SQLiTester()
        is_vulnerable, confidence = tester.detect_timing_based_sqli(
            "test_param",
            baseline_time,
            test_time,
            threshold
        )
        
        return {
            "status": "analyzed",
            "is_vulnerable": is_vulnerable,
            "confidence_score": confidence,
            "baseline_response_time": baseline_time,
            "test_response_time": test_time,
            "delay_ratio": test_time / baseline_time if baseline_time > 0 else 0,
            "interpretation": "Time-based blind SQLi likely vulnerable" if is_vulnerable else "No timing-based SQLi detected",
        }
    except ImportError:
        return {
            "status": "error",
            "message": "burp_advanced_testing module not available",
        }
