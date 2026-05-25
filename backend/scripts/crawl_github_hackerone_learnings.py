"""
Crawl public GitHub HackerOne report indexes and seed accepted learnings.

Targets:
- cap each crawler run at 10,000 accepted knowledge records by default;
- distribute records across P01-P22 and runtime skills as evenly as the cap allows.

Run inside backend container:
  python3 scripts/crawl_github_hackerone_learnings.py
"""
from __future__ import annotations

import argparse
import csv
import io
import json
import os
import re
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.error import URLError
from urllib.request import Request, urlopen

sys.path.insert(0, "/app")
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.db.session import SessionLocal
from app.graph.mission import PENTEST_PHASES, PHASE_CONTRACTS, SKILL_CATALOG
from app.models.models import User, VulnerabilityLearning


SOURCE_KIND = "github_hackerone_crawler"
DEFAULT_MIN_PER_PHASE = 50
DEFAULT_MIN_PER_SKILL = 150
DEFAULT_MAX_CREATED = 10_000
DEFAULT_OWNER_ID = int(os.getenv("H1_CRAWLER_OWNER_ID", "1"))
DEFAULT_MCP_URL = os.getenv("MCP_SERVER_URL", "http://mcp_server:3000").rstrip("/")

REDDELEXC_DATA_CSV = "https://raw.githubusercontent.com/reddelexc/hackerone-reports/master/data.csv"
REDDELEXC_TOPS_API = "https://api.github.com/repos/reddelexc/hackerone-reports/contents/tops_by_bug_type"
LOCAL_COVERAGE_FILES = [
    Path("/app/../docs/reddelexc_hackerone_skill_coverage.json"),
    Path("/app/../docs/hackerone_gist_skill_coverage.json"),
    Path(__file__).resolve().parents[2] / "docs/reddelexc_hackerone_skill_coverage.json",
    Path(__file__).resolve().parents[2] / "docs/hackerone_gist_skill_coverage.json",
]


def _read_url(url: str, timeout: int = 25) -> str:
    request = Request(
        url,
        headers={
            "User-Agent": "ScriptKidd.o GitHub-HackerOne-KnowledgeCrawler/1.0",
            "Accept": "application/vnd.github+json,text/csv,text/markdown,text/plain,*/*",
        },
    )
    with urlopen(request, timeout=timeout) as response:
        return response.read().decode("utf-8", errors="replace")


def _report_id(value: str) -> str:
    match = re.search(r"hackerone\.com/reports/(\d+)(?:\.json)?", str(value or ""), re.IGNORECASE)
    return match.group(1) if match else ""


def _h1_url(report_id: str) -> str:
    return f"https://hackerone.com/reports/{report_id}" if report_id else ""


def _compact(value: str, limit: int = 220) -> str:
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    return text[:limit].rstrip()


def _load_reddelexc_csv() -> list[dict[str, Any]]:
    text = _read_url(REDDELEXC_DATA_CSV)
    rows: list[dict[str, Any]] = []
    for row in csv.DictReader(io.StringIO(text)):
        report_id = _report_id(row.get("link") or "")
        if not report_id:
            continue
        rows.append(
            {
                "report_id": report_id,
                "title": _compact(row.get("title") or f"HackerOne report {report_id}"),
                "program": _compact(row.get("program") or ""),
                "vulnerability_type": _compact(row.get("vuln_type") or ""),
                "source_url": REDDELEXC_DATA_CSV,
                "report_url": _h1_url(report_id),
                "upvotes": row.get("upvotes") or "",
                "bounty": row.get("bounty") or "",
            }
        )
    return rows


def _load_reddelexc_markdown_indexes() -> list[dict[str, Any]]:
    try:
        listing = json.loads(_read_url(REDDELEXC_TOPS_API))
    except Exception:
        listing = []
    rows: list[dict[str, Any]] = []
    for item in listing if isinstance(listing, list) else []:
        raw_url = str(item.get("download_url") or "")
        if not raw_url:
            continue
        try:
            text = _read_url(raw_url)
        except Exception:
            continue
        for match in re.finditer(
            r"\[([^\]]+)\]\((https?://(?:www\.)?hackerone\.com/reports/(\d+)(?:\.json)?)\)",
            text,
            re.IGNORECASE,
        ):
            rows.append(
                {
                    "report_id": match.group(3),
                    "title": _compact(match.group(1)),
                    "program": "",
                    "vulnerability_type": _compact(Path(raw_url).stem.replace("TOP", "").replace("_", " ").title()),
                    "source_url": raw_url,
                    "report_url": _h1_url(match.group(3)),
                    "upvotes": "",
                    "bounty": "",
                }
            )
    return rows


def _load_local_coverage_examples() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    seen_files: set[Path] = set()
    for path in LOCAL_COVERAGE_FILES:
        if path in seen_files or not path.exists():
            continue
        seen_files.add(path)
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        examples = data.get("examples_by_skill") or {}
        if not isinstance(examples, dict):
            continue
        for skill_id, items in examples.items():
            for item in list(items or []):
                report_id = str(item.get("report_id") or "")
                if not report_id:
                    continue
                rows.append(
                    {
                        "report_id": report_id,
                        "title": _compact(item.get("title") or f"HackerOne report {report_id}"),
                        "program": "",
                        "vulnerability_type": _compact(item.get("vulnerability_type") or skill_id),
                        "source_url": str(item.get("source_url") or path),
                        "report_url": _h1_url(report_id),
                        "upvotes": "",
                        "bounty": "",
                    }
                )
    return rows


def crawl_github_hackerone_reports() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    errors: list[str] = []
    for loader in (_load_reddelexc_csv, _load_reddelexc_markdown_indexes):
        try:
            rows.extend(loader())
        except (URLError, TimeoutError, OSError, ValueError) as exc:
            errors.append(str(exc))
    rows.extend(_load_local_coverage_examples())

    deduped: dict[str, dict[str, Any]] = {}
    for row in rows:
        key = str(row.get("report_id") or "")
        if key and key not in deduped:
            deduped[key] = row
    if not deduped:
        raise RuntimeError(f"Nenhum report publico encontrado nos indexes do GitHub. Erros: {errors}")
    return list(deduped.values())


def _skill_catalog() -> dict[str, dict[str, Any]]:
    catalog: dict[str, dict[str, Any]] = {}
    for item in SKILL_CATALOG:
        skill_id = str(item.get("id") or "").strip()
        if skill_id:
            catalog[skill_id] = dict(item)
    for contract in PHASE_CONTRACTS.values():
        phase_id = str(contract.get("phase_id") or "")
        tools = list(contract.get("required_tools") or []) + list(contract.get("optional_tools") or [])
        for key in ("required_skills", "optional_skills"):
            for skill_id in list(contract.get(key) or []):
                catalog.setdefault(
                    str(skill_id),
                    {
                        "id": str(skill_id),
                        "category": "phase-contract",
                        "description": f"Skill operacional usada na fase {phase_id}",
                        "triggers": [],
                        "playbook": tools,
                        "phases": [phase_id],
                    },
                )
    return catalog


def _skill_phases(skill_id: str, skill: dict[str, Any]) -> list[str]:
    phases = [str(p) for p in list(skill.get("phases") or []) if str(p).startswith("P")]
    if phases:
        return phases
    for phase_id, contract in PHASE_CONTRACTS.items():
        contract_skills = list(contract.get("required_skills") or []) + list(contract.get("optional_skills") or [])
        if skill_id in {str(s) for s in contract_skills}:
            phases.append(str(phase_id))
    if phases:
        return list(dict.fromkeys(phases))
    if skill_id in {"evidence-proof-pack", "supervisor-guardrails"}:
        return ["P22"]
    return ["P12"]


COMMAND_BOOK: dict[str, str] = {
    "subfinder": "subfinder -d {domain} -all -silent | tee subdomains.txt",
    "amass": "amass enum -passive -d {domain} -o amass.txt",
    "dnsx": "dnsx -l subdomains.txt -silent -a -aaaa -cname -resp | tee resolved.txt",
    "shuffledns": "shuffledns -d {domain} -w wordlist.txt -r resolvers.txt -o shuffledns.txt",
    "assetfinder": "assetfinder --subs-only {domain} | tee assetfinder.txt",
    "alterx": "alterx -l subdomains.txt | dnsx -silent | tee permutations.txt",
    "naabu": "naabu -list live-hosts.txt -top-ports 1000 -silent -rate 2000 | tee ports.txt",
    "nmap": "nmap -sV -sC -Pn -iL live-hosts.txt -oA nmap-services",
    "masscan": "masscan -iL live-hosts.txt --top-ports 1000 --rate 5000 -oL masscan.txt",
    "httpx": "httpx -l live-hosts.txt -silent -status-code -title -tech-detect -tls-probe -include-response-header -json | tee httpx.jsonl",
    "katana": "katana -list urls.txt -d 5 -jc -kf all -silent | tee crawl.txt",
    "hakrawler": "cat urls.txt | hakrawler -depth 3 -plain | tee hakrawler.txt",
    "gau": "gau {domain} --threads 20 | tee gau.txt",
    "waybackurls": "echo {domain} | waybackurls | tee waybackurls.txt",
    "gospider": "gospider -S urls.txt -c 20 -d 3 --sitemap --robots --js | tee gospider.txt",
    "arjun": "arjun -i urls.txt -oT arjun_params.txt --stable",
    "paramspider": "paramspider -d {domain} --exclude woff,css,js,png,svg,jpg -o params.txt",
    "ffuf": "ffuf -u https://{host}/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-small-directories.txt -mc 200,204,301,302,307,401,403 -ac -t 40 -of json -o ffuf.json",
    "ffuf-params": "ffuf -u 'https://{host}/path?FUZZ=test' -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -mc all -fc 404 -ac -t 30 -of json -o ffuf-params.json",
    "ffuf-values": "ffuf -u 'https://{host}/path?param=FUZZ' -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt -mc 200,204,301,302,307,401,403 -ac -t 20",
    "wfuzz": "wfuzz -w wordlist.txt -u 'https://{host}/path?param=FUZZ' --hc 404",
    "wafw00f": "wafw00f https://{host} -o waf.json -f json",
    "whatweb": "whatweb https://{host} --log-json whatweb.json",
    "nikto": "nikto -h https://{host} -Format json -output nikto.json",
    "nuclei": "nuclei -l urls.txt -severity critical,high,medium -jsonl -o nuclei.jsonl -rate-limit 100",
    "curl-headers": "curl -skI https://{host} | tee response-headers.txt",
    "testssl": "testssl.sh --jsonfile testssl.json https://{host}",
    "sslscan": "sslscan --json https://{host} > sslscan.json",
    "dalfox": "cat urls-with-params.txt | dalfox pipe --silence --skip-bav --format json -o dalfox.json",
    "wapiti": "wapiti -u https://{host} -f json -o wapiti.json --scope page",
    "sqlmap": "sqlmap -m urls-with-params.txt --batch --smart --level 1 --risk 1 --output-dir sqlmap-output",
    "interactsh-client": "interactsh-client -json -o interactsh.json",
    "trufflehog": "trufflehog git https://github.com/{org}/{repo}.git --json --no-update > trufflehog.json",
    "gitleaks": "gitleaks detect --source . --report-format json --report-path gitleaks.json",
    "subjack": "subjack -w subdomains.txt -ssl -timeout 10 -o subjack.txt",
    "shodan": "shodan host {ip} --format json > shodan-host.json",
    "theHarvester": "theHarvester -d {domain} -b all -f theharvester",
    "hydra": "hydra -L users.txt -P passwords.txt {host} http-post-form '/login:username=^USER^&password=^PASS^:F=invalid' -V -I -t 4",
    "medusa": "medusa -h {host} -U users.txt -P passwords.txt -M http -n 80 -t 4",
}


def _skill_tools(skill_id: str, skill: dict[str, Any], phases: list[str]) -> list[str]:
    tools = [str(t) for t in list(skill.get("playbook") or []) if str(t)]
    for phase in phases:
        contract = PHASE_CONTRACTS.get(phase) or {}
        tools.extend(str(t) for t in list(contract.get("required_tools") or []) + list(contract.get("optional_tools") or []) if str(t))
    return list(dict.fromkeys(tools))[:12]


def _command_steps(tools: list[str], phases: list[str], report_title: str) -> str:
    selected = [tool for tool in tools if tool in COMMAND_BOOK][:4]
    if not selected:
        selected = ["nuclei"] if "nuclei" in COMMAND_BOOK else list(COMMAND_BOOK)[:1]
    lines = [
        "Como executar com as ferramentas do repositório:",
        "",
        "Pre-condição: use somente alvos autorizados e alimente os arquivos base conforme a fase: subdomains.txt, live-hosts.txt, urls.txt ou urls-with-params.txt.",
    ]
    for idx, tool in enumerate(selected, start=1):
        lines.append(f"{idx}. Ferramenta: {tool}")
        lines.append(f"   Comando:")
        lines.append(f"   {COMMAND_BOOK[tool]}")
        lines.append("   Como interpretar:")
        if tool in {"subfinder", "amass", "dnsx", "shuffledns", "assetfinder", "alterx"}:
            lines.append("   - aceite hosts únicos, resolvidos e dentro do escopo; descarte NXDOMAIN e wildcard sem prova.")
        elif tool in {"naabu", "nmap", "masscan"}:
            lines.append("   - confirme porta aberta, protocolo, banner e serviço; use o resultado para priorizar HTTP, TLS, auth e CVE.")
        elif tool in {"httpx", "curl-headers", "whatweb", "wafw00f"}:
            lines.append("   - registre status code, título, tecnologia, redirect, WAF e headers ausentes/fracos.")
        elif tool in {"katana", "hakrawler", "gau", "waybackurls", "gospider", "arjun", "paramspider", "ffuf", "ffuf-params", "ffuf-values", "wfuzz"}:
            lines.append("   - extraia URLs, parâmetros, rotas JS e diferenças de resposta para montar candidatos de teste.")
        elif tool in {"nuclei", "nikto", "dalfox", "wapiti", "sqlmap", "testssl", "sslscan"}:
            lines.append("   - promova finding somente com template/assinatura, request, response e stdout/json bruto reproduzível.")
        else:
            lines.append("   - salve stdout/stderr, arquivo de saída e evidência mínima que prove ou descarte a hipótese.")
    lines.extend(
        [
            "",
            f"Hipótese vinda do report público: {report_title}",
            f"Fases aplicáveis: {', '.join(phases) or '-'}",
            "Evidência obrigatória: comando completo, arquivo de entrada usado, saída específica da ferramenta, request/response quando houver HTTP, timestamp e alvo/subdomínio afetado.",
            "Critério de descarte: sem diferença observável, sem ativo vivo, fora do escopo, ou ferramenta sem evidência específica.",
        ]
    )
    return "\n".join(lines)


def _keywords_for_skill(skill_id: str, skill: dict[str, Any]) -> set[str]:
    blob = " ".join(
        [
            skill_id,
            str(skill.get("category") or ""),
            str(skill.get("description") or ""),
            " ".join(str(t) for t in list(skill.get("triggers") or [])),
        ]
    ).lower()
    aliases = {
        "xss": {"xss", "cross-site", "scripting"},
        "sqli": {"sql", "sqli", "injection"},
        "ssrf": {"ssrf", "server-side"},
        "auth": {"auth", "authentication", "authorization", "session", "cookie", "token"},
        "idor": {"idor", "access", "authorization", "object"},
        "graphql": {"graphql", "api"},
        "api": {"api", "endpoint"},
        "takeover": {"takeover", "subdomain", "dns"},
        "cloud": {"cloud", "s3", "bucket", "aws", "gcp", "azure"},
        "secret": {"secret", "token", "key", "credential", "git"},
        "header": {"header", "cors", "csp", "hsts", "tls", "ssl"},
        "cve": {"cve", "memory", "overflow", "null", "race", "dos"},
        "directory": {"path", "traversal", "directory", "file"},
        "recon": {"subdomain", "domain", "port", "service", "crawl", "endpoint"},
    }
    tokens = set(re.findall(r"[a-z0-9]+", blob))
    for marker, extra in aliases.items():
        if marker in blob:
            tokens.update(extra)
    return {t for t in tokens if len(t) >= 3}


def _rank_reports_for_skill(reports: list[dict[str, Any]], skill_id: str, skill: dict[str, Any]) -> list[dict[str, Any]]:
    keywords = _keywords_for_skill(skill_id, skill)

    def score(row: dict[str, Any]) -> tuple[int, int]:
        blob = f"{row.get('title')} {row.get('vulnerability_type')} {row.get('program')}".lower()
        matches = sum(1 for token in keywords if token in blob)
        upvotes = int(float(row.get("upvotes") or 0)) if str(row.get("upvotes") or "").replace(".", "", 1).isdigit() else 0
        return matches, upvotes

    ranked = sorted(reports, key=score, reverse=True)
    return ranked or reports


def _counts(db) -> tuple[dict[str, int], dict[str, int]]:
    phase_counts: dict[str, int] = defaultdict(int)
    skill_counts: dict[str, int] = defaultdict(int)
    rows = db.query(VulnerabilityLearning).filter(VulnerabilityLearning.status == "accepted").all()
    for row in rows:
        for phase in list(row.affected_phases or []):
            phase_counts[str(phase)] += 1
        for skill in list(row.affected_skills or []):
            skill_counts[str(skill)] += 1
    return dict(phase_counts), dict(skill_counts)


def _owner(db, owner_id: int) -> User:
    user = db.query(User).filter(User.id == owner_id).first()
    if user:
        return user
    user = db.query(User).filter(User.is_admin.is_(True)).order_by(User.id.asc()).first()
    if user:
        return user
    user = db.query(User).order_by(User.id.asc()).first()
    if not user:
        raise RuntimeError("Nenhum usuario encontrado para ser owner dos aprendizados.")
    return user


def _existing_titles(db) -> set[str]:
    return {
        str(row.title or "")
        for row in db.query(VulnerabilityLearning.title).filter(VulnerabilityLearning.source_kind == SOURCE_KIND).all()
    }


def _build_learning(
    *,
    owner_id: int,
    title: str,
    row: dict[str, Any],
    phases: list[str],
    skills: list[str],
    tools: list[str],
    ordinal: int,
    target_kind: str,
    target_id: str,
) -> VulnerabilityLearning:
    report_title = _compact(row.get("title") or f"HackerOne report {row.get('report_id')}", 180)
    vuln_type = _compact(row.get("vulnerability_type") or target_id.replace("-", " ").title(), 120)
    phase_label = ", ".join(phases)
    tool_label = ", ".join(tools[:6]) or "manual validation"
    report_url = str(row.get("report_url") or "")
    source_url = str(row.get("source_url") or REDDELEXC_DATA_CSV)
    program = str(row.get("program") or "public program").strip() or "public program"

    steps = _command_steps(tools, phases, report_title)
    summary = (
        f"Conhecimento aceito derivado de indice publico GitHub/HackerOne. "
        f"Report de referencia: {report_title}. Programa: {program}. "
        f"Aplicacao operacional: {target_kind} {target_id}, fases {phase_label}."
    )
    learned_prompt = (
        f"Para {target_id}, procure sinais semelhantes a '{report_title}'. "
        f"Priorize ferramentas: {tool_label}. Exija evidencia especifica do comando antes de criar finding."
    )
    technique = {
        "name": f"{target_id} validation pattern #{ordinal}: {report_title}",
        "phase": phases[0] if phases else "",
        "tool": tools[0] if tools else "operator-review",
        "source_report_id": str(row.get("report_id") or ""),
        "source": "github_hackerone_public_index",
    }
    now = datetime.utcnow()
    return VulnerabilityLearning(
        owner_id=owner_id,
        status="accepted",
        source_kind=SOURCE_KIND,
        source_urls=[url for url in [source_url, report_url] if url],
        url_count=len([url for url in [source_url, report_url] if url]),
        title=title[:255],
        vulnerability_type=vuln_type,
        summary=summary,
        steps_to_reproduce=steps,
        impact=(
            "Risco operacional inferido de report publico aceito: pode indicar exposicao real, bypass, vazamento, "
            "execucao, tomada de conta ou falha de controle dependendo da classe e do contexto do alvo."
        ),
        remediation=(
            "Reproduzir em ambiente autorizado, corrigir a causa raiz indicada pela classe da vulnerabilidade, "
            "adicionar teste regressivo, monitorar telemetria e validar controles preventivos/detectivos."
        ),
        learned_mission=(
            f"Durante {phase_label}, usar reports publicos HackerOne como playbook de hipotese para {target_id}; "
            "converter somente evidencia reproduzida em finding."
        ),
        learned_prompt=f"{learned_prompt}\n\n{steps}",
        learned_techniques=[technique],
        technique_count=1,
        affected_phases=phases,
        affected_skills=skills,
        recommended_tools=tools,
        raw_extraction={
            "seed_key": f"{target_kind}:{target_id}:{ordinal}",
            "target_kind": target_kind,
            "target_id": target_id,
            "github_source_url": source_url,
            "hackerone_report_url": report_url,
            "hackerone_report_id": str(row.get("report_id") or ""),
            "hackerone_report_title": report_title,
            "program": program,
            "vulnerability_type": vuln_type,
        },
        llm_model="github-hackerone-crawler-v1",
        accepted_by_id=owner_id,
        accepted_at=now,
        created_at=now,
        updated_at=now,
    )


def _ingest_mcp(row: VulnerabilityLearning, mcp_url: str) -> bool:
    payload = _mcp_document(row)
    data = json.dumps(payload).encode("utf-8")
    request = Request(
        f"{mcp_url.rstrip('/')}/rag/ingest",
        data=data,
        headers={"Content-Type": "application/json", "User-Agent": "ScriptKidd.o GitHub-HackerOne-KnowledgeCrawler/1.0"},
        method="POST",
    )
    try:
        with urlopen(request, timeout=10) as response:
            return 200 <= response.status < 300
    except Exception:
        return False


def _mcp_document(row: VulnerabilityLearning) -> dict[str, Any]:
    content = "\n".join(
        part
        for part in [
            row.title,
            row.summary or "",
            row.steps_to_reproduce or "",
            row.impact or "",
            row.remediation or "",
            row.learned_prompt or "",
        ]
        if part
    )
    return {
        "document_id": f"vulnerability_learning:{row.id}",
        "source": SOURCE_KIND,
        "metadata": {
            "learning_id": row.id,
            "status": row.status,
            "phase": (row.affected_phases or [""])[0],
            "phases": row.affected_phases or [],
            "skill": (row.affected_skills or [""])[0],
            "skills": row.affected_skills or [],
            "source_kind": row.source_kind,
            "source_urls": row.source_urls or [],
        },
        "content": content,
    }


def _ingest_mcp_bulk(rows: list[VulnerabilityLearning], mcp_url: str) -> int:
    if not rows:
        return 0
    total = 0
    batch_size = 500
    for start in range(0, len(rows), batch_size):
        batch = rows[start : start + batch_size]
        payload = {"documents": [_mcp_document(row) for row in batch]}
        data = json.dumps(payload).encode("utf-8")
        request = Request(
            f"{mcp_url.rstrip('/')}/rag/ingest-bulk",
            data=data,
            headers={"Content-Type": "application/json", "User-Agent": "ScriptKidd.o GitHub-HackerOne-KnowledgeCrawler/1.0"},
            method="POST",
        )
        try:
            with urlopen(request, timeout=120) as response:
                response_payload = json.loads(response.read().decode("utf-8", errors="replace"))
                total += int(response_payload.get("documents_ingested") or 0)
        except Exception:
            total += sum(1 for row in batch if _ingest_mcp(row, mcp_url))
    return total


def _purge_mcp_source(mcp_url: str) -> int:
    data = json.dumps({"source": SOURCE_KIND, "source_kind": SOURCE_KIND}).encode("utf-8")
    request = Request(
        f"{mcp_url.rstrip('/')}/rag/delete-source",
        data=data,
        headers={"Content-Type": "application/json", "User-Agent": "ScriptKidd.o GitHub-HackerOne-KnowledgeCrawler/1.0"},
        method="POST",
    )
    try:
        with urlopen(request, timeout=20) as response:
            payload = json.loads(response.read().decode("utf-8", errors="replace"))
            return int(payload.get("removed") or 0)
    except Exception:
        return 0


def purge_crawler_learnings(db) -> int:
    rows = db.query(VulnerabilityLearning).filter(VulnerabilityLearning.source_kind == SOURCE_KIND).all()
    total = len(rows)
    for row in rows:
        db.delete(row)
    db.commit()
    return total


def seed(
    db,
    reports: list[dict[str, Any]],
    *,
    min_per_phase: int,
    min_per_skill: int,
    owner_id: int,
    max_created: int,
) -> list[VulnerabilityLearning]:
    owner = _owner(db, owner_id)
    existing_titles = _existing_titles(db)
    phase_counts, skill_counts = _counts(db)
    skills = _skill_catalog()
    created: list[VulnerabilityLearning] = []

    skill_runtime: dict[str, dict[str, Any]] = {}
    for skill_id, skill in sorted(skills.items()):
        phases = _skill_phases(skill_id, skill)
        skill_runtime[skill_id] = {
            "skill": skill,
            "phases": phases,
            "tools": _skill_tools(skill_id, skill, phases),
            "ranked": _rank_reports_for_skill(reports, skill_id, skill),
        }

    while len(created) < max_created:
        pending = [
            (skill_counts.get(skill_id, 0), skill_id)
            for skill_id in skill_runtime
            if int(skill_counts.get(skill_id, 0)) < min_per_skill
        ]
        if not pending:
            break
        _, skill_id = min(pending)
        runtime = skill_runtime[skill_id]
        current = int(skill_counts.get(skill_id, 0))
        phases = list(runtime["phases"])
        tools = list(runtime["tools"])
        ranked = list(runtime["ranked"])
        report_index = current % len(ranked)
        while len(created) < max_created and current < min_per_skill:
            report = ranked[report_index % len(ranked)]
            ordinal = current + 1
            title = f"H1 GitHub skill {skill_id} #{ordinal:03d}: {_compact(report.get('title') or '', 120)}"
            report_index += 1
            if title in existing_titles:
                current += 1
                skill_counts[skill_id] = current
                continue
            learning = _build_learning(
                owner_id=owner.id,
                title=title,
                row=report,
                phases=phases,
                skills=[skill_id],
                tools=tools,
                ordinal=ordinal,
                target_kind="skill",
                target_id=skill_id,
            )
            db.add(learning)
            created.append(learning)
            existing_titles.add(title)
            current += 1
            skill_counts[skill_id] = current
            for phase in phases:
                phase_counts[phase] = phase_counts.get(phase, 0) + 1
            break

    while len(created) < max_created:
        phase_pending = [
            (phase_counts.get(str(p.get("id")), 0), str(p.get("id")))
            for p in PENTEST_PHASES
            if int(phase_counts.get(str(p.get("id")), 0)) < min_per_phase
        ]
        if not phase_pending:
            break
        current, phase = min(phase_pending)
        contract = PHASE_CONTRACTS.get(phase) or {}
        phase_skills = list(contract.get("required_skills") or []) + list(contract.get("optional_skills") or [])
        tools = list(contract.get("required_tools") or []) + list(contract.get("optional_tools") or [])
        ranked = reports
        report_index = int(current)
        while len(created) < max_created and int(phase_counts.get(phase, 0)) < min_per_phase:
            current = int(phase_counts.get(phase, 0))
            report = ranked[report_index % len(ranked)]
            ordinal = current + 1
            title = f"H1 GitHub phase {phase} #{ordinal:03d}: {_compact(report.get('title') or '', 120)}"
            report_index += 1
            if title in existing_titles:
                phase_counts[phase] = current + 1
                continue
            learning = _build_learning(
                owner_id=owner.id,
                title=title,
                row=report,
                phases=[phase],
                skills=[str(s) for s in phase_skills[:4]],
                tools=[str(t) for t in tools[:12]],
                ordinal=ordinal,
                target_kind="phase",
                target_id=phase,
            )
            db.add(learning)
            created.append(learning)
            existing_titles.add(title)
            phase_counts[phase] = phase_counts.get(phase, 0) + 1
            for skill_id in phase_skills[:4]:
                skill_counts[str(skill_id)] = skill_counts.get(str(skill_id), 0) + 1

    # If the requested cap is higher than the mandatory per-skill/per-phase
    # minimums, keep filling evenly by phase until the cap is reached.
    while len(created) < max_created:
        current, phase = min(
            (phase_counts.get(str(p.get("id")), 0), str(p.get("id")))
            for p in PENTEST_PHASES
        )
        contract = PHASE_CONTRACTS.get(phase) or {}
        phase_skills = [str(s) for s in list(contract.get("required_skills") or []) + list(contract.get("optional_skills") or [])]
        tools = [str(t) for t in list(contract.get("required_tools") or []) + list(contract.get("optional_tools") or [])]
        ranked = reports
        report_index = int(current)
        while len(created) < max_created:
            report = ranked[report_index % len(ranked)]
            ordinal = int(phase_counts.get(phase, 0)) + 1
            title = f"H1 GitHub phase {phase} #{ordinal:04d}: {_compact(report.get('title') or '', 120)}"
            report_index += 1
            if title in existing_titles:
                phase_counts[phase] = ordinal
                continue
            learning = _build_learning(
                owner_id=owner.id,
                title=title,
                row=report,
                phases=[phase],
                skills=phase_skills[:4],
                tools=tools[:12],
                ordinal=ordinal,
                target_kind="phase",
                target_id=phase,
            )
            db.add(learning)
            created.append(learning)
            existing_titles.add(title)
            phase_counts[phase] = phase_counts.get(phase, 0) + 1
            for skill_id in phase_skills[:4]:
                skill_counts[skill_id] = skill_counts.get(skill_id, 0) + 1
            break

    db.commit()
    for row in created:
        db.refresh(row)
    return created


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--min-per-phase", type=int, default=DEFAULT_MIN_PER_PHASE)
    parser.add_argument("--min-per-skill", type=int, default=DEFAULT_MIN_PER_SKILL)
    parser.add_argument("--owner-id", type=int, default=DEFAULT_OWNER_ID)
    parser.add_argument("--max-created", type=int, default=DEFAULT_MAX_CREATED)
    parser.add_argument("--purge-source", action="store_true")
    parser.add_argument("--mcp-url", default=DEFAULT_MCP_URL)
    parser.add_argument("--skip-mcp", action="store_true")
    args = parser.parse_args()

    reports = crawl_github_hackerone_reports()
    db = SessionLocal()
    try:
        before_phase, before_skill = _counts(db)
        purged = purge_crawler_learnings(db) if args.purge_source else 0
        if purged:
            before_phase, before_skill = _counts(db)
        created = seed(
            db,
            reports,
            min_per_phase=max(0, args.min_per_phase),
            min_per_skill=max(0, args.min_per_skill),
            owner_id=args.owner_id,
            max_created=max(1, args.max_created),
        )
        after_phase, after_skill = _counts(db)
        mcp_ingested = 0
        mcp_purged = 0
        if not args.skip_mcp and created:
            if args.purge_source:
                mcp_purged = _purge_mcp_source(args.mcp_url)
            mcp_ingested = _ingest_mcp_bulk(created, args.mcp_url)
        print(
            json.dumps(
                {
                    "ok": True,
                    "reports_crawled": len(reports),
                    "created": len(created),
                    "purged": purged,
                    "mcp_ingested": mcp_ingested,
                    "mcp_purged": mcp_purged,
                    "max_created": args.max_created,
                    "min_per_phase": args.min_per_phase,
                    "min_per_skill": args.min_per_skill,
                    "phase_counts_before_min": min(before_phase.get(str(p.get("id")), 0) for p in PENTEST_PHASES),
                    "phase_counts_after_min": min(after_phase.get(str(p.get("id")), 0) for p in PENTEST_PHASES),
                    "skill_counts_before_min": min(before_skill.get(skill_id, 0) for skill_id in _skill_catalog()),
                    "skill_counts_after_min": min(after_skill.get(skill_id, 0) for skill_id in _skill_catalog()),
                },
                ensure_ascii=False,
                indent=2,
            )
        )
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


if __name__ == "__main__":
    main()
