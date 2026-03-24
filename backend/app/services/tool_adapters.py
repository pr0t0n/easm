import os
import re
import shutil
import subprocess
from typing import Any
from urllib.parse import urlparse, urlunparse

from app.core.config import settings
from app.services.asm_rules_service import get_asm_rules_service

from app.workers.worker_groups import find_group_by_tool, get_worker_groups


SAFE_TOOL_REGISTRY = {
    "recon": ["subfinder", "amass", "assetfinder", "dnsx", "naabu", "nessus"],
    "crawler": ["httpx", "katana", "waymore", "uro", "gowitness"],
    "fuzzing": ["ffuf", "feroxbuster", "arjun", "dirb", "gobuster", "wfuzz"],
    "vuln": ["nessus", "nuclei", "dalfox", "nikto", "wpscan", "zap", "openvas", "semgrep", "nmap-vulscan", "wapiti", "sqlmap", "commix", "tplmap", "wafw00f", "sslscan", "shcheck"],
    "code_js": ["linkfinder", "secretfinder", "trufflehog"],
    "api": ["kiterunner", "postman-to-k6"],
    "osint": ["theharvester", "h8mail", "metagoofil", "urlscan-cli", "subjack", "shodan-cli", "whatweb"],
}

TOOL_TIMEOUT_SECONDS = 90

# Tool-specific timeouts (override default TOOL_TIMEOUT_SECONDS)
TOOL_SPECIFIC_TIMEOUTS = {
    "nmap": 180,
    "nuclei": 300,
    "katana": 180,
    "ffuf": 120,
    "wapiti": 240,
    "sqlmap": 300,
    "subfinder": 120,
    "amass": 120,
}

OFFICIALLY_DISABLED_TOOLS: dict[str, str] = {
    "openvas": "OpenVAS requer stack dedicada/GVM e nao e suportado por execucao local direta no worker.",
}


def _get_nuclei_templates_path() -> str | None:
    """
    Returns path to Nuclei templates directory if available.
    Checks multiple locations:
    1. /root/.nuclei/templates
    2. /home/user/.nuclei/templates
    3. /nuclei/templates
    """
    possible_paths = [
        "/app/nuclei-templates",
        "/root/.nuclei/templates",
        os.path.expanduser("~/.nuclei/templates"),
        "/nuclei/templates",
    ]
    
    for path in possible_paths:
        if os.path.isdir(path):
            # Check if there are YAML template files
            yaml_count = len(list(__import__('pathlib').Path(path).rglob("*.yaml")))
            yml_count = len(list(__import__('pathlib').Path(path).rglob("*.yml")))
            if yaml_count + yml_count > 0:
                return path
    
    return None


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
        "wappalyzer": "wappalyzer",
        "sublist3r": "python3",
        "zap": "zaproxy",
        "owasp-zap": "zaproxy",
        "sqlmap": "sqlmap.py",
        "tplmap": "python3",
        "commix": "python3",
    }
    normalized = tool_name.strip().lower()
    return aliases.get(normalized, normalized)


def _build_tool_command(tool_name: str, target: str) -> list[str]:
    parts = _target_parts(target)
    host = parts["host"]
    url = parts["url"]
    normalized = tool_name.strip().lower()

    if normalized == "nmap":
        # Top 100 portas + deteccao de versao/scripts default para baseline consistente.
        return ["nmap", "-Pn", "-sV", "-sC", "--top-ports", "100", "-T4", host]
    if normalized == "nmap-vulscan" or normalized == "vulscan":
        # nmap com vulscan NSE script para vulnerability assessment
        # Requer git clone --depth=1 https://github.com/scipag/vulscan.git /root/vulscan
        vulscan_path = "/root/vulscan"
        if not os.path.exists(vulscan_path):
            vulscan_path = "/opt/vulscan"
        if not os.path.exists(vulscan_path):
            # Fallback: sem vulscan, mantem varredura agressiva para enriquecer evidencia.
            return ["nmap", "-Pn", "-A", "--top-ports", "100", host]
        # Com vulscan: versioning + vulnerability detection
        script_path = os.path.join(vulscan_path, "vulscan.nse")
        return [
            "nmap",
            "-Pn",
            "-A",
            "--top-ports",
            "100",
            "-T4",
            f"--script={script_path}",
            f"--script-args=vulscan/mincvss=4.0",
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
        return ["python3", "-m", "sublist3r", "-d", host]
    if normalized == "assetfinder":
        return ["assetfinder", "--subs-only", host]
    if normalized == "cloudenum":
        return ["python3", "/opt/cloud_enum/cloud_enum.py", "-k", host]
    if normalized == "massdns":
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
        cmd = [
            "nuclei",
            "-u",
            url,
            "-severity",
            "critical,high",
        ]
        # Obrigatorio: usa sempre os templates customizados instalados no worker.
        cmd.extend(["-t", templates_path])
        return cmd
    if normalized == "nikto":
        return ["nikto", "-h", url, "-Tuning", "1234567890"]
    if normalized == "sslscan":
        return ["sslscan", "--no-colour", host]
    if normalized == "shcheck":
        return ["shcheck", url]
    if normalized == "wapiti":
        # Modulos validos no wapiti 3.2.x (http_header e csp nao existem nessa versao)
        return [
            "wapiti",
            "-u",
            url,
            "--flush-session",
            "--scope",
            "domain",
            "--format",
            "txt",
            "--module",
            "sql,xss,permanentxss,ssrf,xxe,exec,file,crlf,redirect,csrf,ldap",
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
        return ["wpscan", "--url", url, "--no-update"]
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
            return ["wfuzz", "-c", "-z", f"file,{wordlist}", "--hc", "404", f"{url.rstrip('/')}/FUZZ"]
        return ["wfuzz", "-h"]
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
        return ["subjack", "-h"]
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

    binary = _tool_binary(tool_name)
    if shutil.which(binary) is None:
        return {
            "status": "error",
            "output": f"Ferramenta {tool_name} nao encontrada no worker ({binary}).",
            "open_ports": [],
        }

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
    else:
        output_limit = 2500
        stream_limit = 1500

    open_ports = _parse_open_ports(tool_name, stdout)
    status = "executed" if proc.returncode == 0 else "error"
    return {
        "status": status,
        "output": combined[:output_limit],
        "open_ports": open_ports,
        "return_code": proc.returncode,
        "command": " ".join(cmd),
        "stdout": stdout[:stream_limit],
        "stderr": stderr[:stream_limit],
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
    
    # Aplicar ASM rules evaluation ao output da ferramenta
    asm_findings = []
    tool_output = execution.get("output", "") or execution.get("stdout", "")
    if tool_output:
        asm_findings = evaluate_asm_rules(tool_output, tool_name=tool_name)

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
