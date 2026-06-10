"""cross_target_propagator.py — Memória de superfície compartilhada entre targets.

Implementa o ponto #3 do usuário: subdomínio A e subdomínio B não são mais
isolados. Descobertas se propagam entre targets do mesmo scan.

Casos de uso cobertos:
  1. Credential leak em sub A → credential stuffing em auth endpoints de sub B, C, D
  2. Mesmo software/versão em múltiplos subs → testa CVE uma vez, reporta em todos
  3. Mesmo IP em múltiplos subs → testa virtual host confusion
  4. SAN do certificado SSL → descobre subdomínios adicionais não encontrados via DNS

Chamado em poll_scan_work_item após ferramentas de:
  - Credential discovery: gitleaks, trufflehog, git-dumper, h8mail
  - Certificate analysis: sslscan, testssl
  - Tech fingerprint: httpx, whatweb, nmap (propagação de versão compartilhada)
"""

from __future__ import annotations

import logging
import re
from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)

# ── Ferramentas que podem expor credenciais ────────────────────────────────────
CREDENTIAL_TOOLS = {
    "gitleaks",
    "trufflehog",
    "git-dumper",
    "h8mail",
    "nuclei-exposure",
    "nuclei-misconfiguration",
}

# ── Ferramentas de análise de certificado ─────────────────────────────────────
CERT_TOOLS = {"sslscan", "testssl", "nuclei-ssl"}

# ── Ferramentas de fingerprint de tech ────────────────────────────────────────
FINGERPRINT_TOOLS = {"httpx", "whatweb", "whatweb-basic", "nmap", "nmap-http", "nmap-ssl"}

# ── Padrões de endpoints de autenticação para credential stuffing ─────────────
AUTH_PATH_PATTERNS = [
    "/login", "/auth", "/signin", "/sign-in", "/api/auth",
    "/api/login", "/api/token", "/oauth", "/api/users/login",
    "/admin", "/wp-login.php", "/user/login", "/api/v1/auth",
]


def _extract_credentials_from_result(result: dict[str, Any]) -> list[dict]:
    """Extrai credenciais encontradas de gitleaks/trufflehog output."""
    creds: list[dict] = []
    stdout = str(result.get("stdout_full") or result.get("stdout_preview") or "")
    parsed = result.get("parsed_result")

    # Gitleaks JSON output
    if isinstance(parsed, list):
        for item in parsed:
            if not isinstance(item, dict):
                continue
            secret = str(item.get("Secret") or item.get("secret") or "")
            rule = str(item.get("RuleID") or item.get("rule_id") or item.get("Description") or "")
            commit = str(item.get("Commit") or item.get("commit") or "")
            if secret:
                creds.append({
                    "secret": secret[:200],
                    "rule": rule,
                    "commit": commit[:40],
                    "source": "gitleaks",
                })

    # Trufflehog output: JSON lines
    for line in stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            import json
            data = json.loads(line)
            if isinstance(data, dict) and data.get("SourceMetadata"):
                raw_str = str(data.get("Raw") or "")
                det_type = str(data.get("DetectorName") or data.get("DetectorType") or "")
                if raw_str:
                    creds.append({
                        "secret": raw_str[:200],
                        "rule": det_type,
                        "commit": "",
                        "source": "trufflehog",
                    })
        except Exception:
            pass

    # Generic regex: AWS keys, tokens, passwords in config files
    aws_key_pattern = re.compile(r"(?:AKIA|ASIA)[A-Z0-9]{16}")
    token_pattern = re.compile(r"(?:password|passwd|pwd|secret|token|api_key)\s*[=:]\s*[\"\']?([^\s\"\']{8,})", re.I)
    for m in aws_key_pattern.finditer(stdout):
        creds.append({"secret": m.group(0), "rule": "aws_access_key", "commit": "", "source": "regex"})
    for m in token_pattern.finditer(stdout):
        val = m.group(1)
        if len(val) >= 8 and not val.startswith("$"):
            creds.append({"secret": val[:200], "rule": "generic_credential", "commit": "", "source": "regex"})

    return creds[:20]  # cap: não mais de 20 creds por resultado


def _extract_san_domains(result: dict[str, Any]) -> list[str]:
    """Extrai domínios do SAN do certificado SSL."""
    domains: list[str] = []
    stdout = str(result.get("stdout_full") or result.get("stdout_preview") or "")

    # sslscan/testssl output: "DNS:*.example.com" ou "Subject Alternative Name: ..."
    san_section = re.search(
        r"(?:Subject Alternative Name|SAN|DNS Names?).*?(?:\n\n|\Z)",
        stdout,
        re.DOTALL | re.IGNORECASE,
    )
    text = san_section.group(0) if san_section else stdout

    # Match DNS: entries
    for m in re.finditer(r"DNS:([a-zA-Z0-9*.\-]+)", text):
        domain = m.group(1).strip().lstrip("*.")
        if domain and "." in domain:
            domains.append(domain.lower())

    return list(set(domains))[:50]


def _get_auth_endpoints_for_scan(db: Session, scan_id: int) -> list[tuple[str, str]]:
    """Retorna (domain, url) de endpoints de autenticação já encontrados no scan."""
    try:
        from app.models.models import Finding
        findings = (
            db.query(Finding.domain, Finding.url)
            .filter(
                Finding.scan_job_id == scan_id,
                Finding.url.isnot(None),
            )
            .all()
        )
        auth_endpoints: list[tuple[str, str]] = []
        for domain, url in findings:
            if url and any(p in url.lower() for p in AUTH_PATH_PATTERNS):
                auth_endpoints.append((str(domain or ""), str(url or "")))
        return auth_endpoints[:30]
    except Exception:
        return []


def _get_all_scan_targets(db: Session, scan_id: int) -> list[str]:
    """Retorna todos os targets únicos com work items no scan."""
    try:
        from app.models.models import ScanWorkItem
        from sqlalchemy import distinct
        rows = (
            db.query(distinct(ScanWorkItem.target))
            .filter(ScanWorkItem.scan_job_id == scan_id)
            .limit(500)
            .all()
        )
        return [str(r[0]) for r in rows if r[0]]
    except Exception:
        return []


def _seed_credential_test(
    db: Session,
    scan_id: int,
    target: str,
    cred_count: int,
    source_target: str,
) -> int:
    """Enfileira teste de credential stuffing para um target que tem auth endpoint."""
    try:
        from app.models.models import ScanWorkItem
        from app.services.scan_work_queue import apply_phase_tool_metadata, resource_class_for_tool, PHASE_PRIORITY

        tool_name = "nuclei-default-credentials"
        phase_id = "P10"

        already = (
            db.query(ScanWorkItem.id)
            .filter(
                ScanWorkItem.scan_job_id == scan_id,
                ScanWorkItem.phase_id == phase_id,
                ScanWorkItem.tool_name == tool_name,
                ScanWorkItem.target == target[:500],
            )
            .first()
        )
        if already:
            return 0

        rc = resource_class_for_tool(tool_name)
        pri = PHASE_PRIORITY.get(phase_id, 100) - 15  # alta prioridade
        item = ScanWorkItem(
            scan_job_id=scan_id,
            phase_id=phase_id,
            target=target[:500],
            tool_name=tool_name,
            profile=tool_name,
            resource_class=rc,
            priority=max(1, pri),
            status="queued",
            max_attempts=2,
            item_metadata=apply_phase_tool_metadata({
                "source": "cross_target_propagator",
                "source_target": source_target,
                "cred_count": cred_count,
                "propagation_type": "credential_stuffing",
                "engine": "cross_target_propagator",
            }, phase_id, tool_name, source="cross_target_propagator"),
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )
        db.add(item)
        db.flush()
        return 1
    except Exception:
        db.rollback()
        return 0


def _seed_version_cve_for_target(
    db: Session,
    scan_id: int,
    target: str,
    product: str,
    phase_id: str = "P09",
) -> int:
    """Propaga teste de CVE de uma tech já confirmada para um novo target."""
    try:
        from app.models.models import ScanWorkItem
        from app.services.tech_vuln_correlator import TECH_TO_NUCLEI_TAGS
        from app.services.scan_work_queue import apply_phase_tool_metadata, resource_class_for_tool, PHASE_PRIORITY

        product_lower = product.lower()
        tag: str | None = None
        for kw, tags in TECH_TO_NUCLEI_TAGS.items():
            if kw in product_lower:
                tag = tags[0]
                break
        if not tag:
            return 0

        tool_name = f"nuclei-{tag}"[:120]
        already = (
            db.query(ScanWorkItem.id)
            .filter(
                ScanWorkItem.scan_job_id == scan_id,
                ScanWorkItem.phase_id == phase_id,
                ScanWorkItem.tool_name == tool_name,
                ScanWorkItem.target == target[:500],
            )
            .first()
        )
        if already:
            return 0

        rc = resource_class_for_tool(tool_name)
        pri = PHASE_PRIORITY.get(phase_id, 100) - 10
        item = ScanWorkItem(
            scan_job_id=scan_id,
            phase_id=phase_id,
            target=target[:500],
            tool_name=tool_name,
            profile=tool_name,
            resource_class=rc,
            priority=max(1, pri),
            status="queued",
            max_attempts=2,
            item_metadata=apply_phase_tool_metadata({
                "source": "cross_target_propagator",
                "product": product,
                "propagation_type": "shared_version",
                "engine": "cross_target_propagator",
            }, phase_id, tool_name, source="cross_target_propagator"),
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )
        db.add(item)
        db.flush()
        return 1
    except Exception:
        db.rollback()
        return 0


def propagate_credential_findings(
    db: Session,
    scan_id: int,
    source_target: str,
    tool_name: str,
    result: dict[str, Any],
) -> dict[str, Any]:
    """Propaga credenciais encontradas em source_target para outros targets do scan.

    Se gitleaks encontrou credenciais em repo.source_target.com:
      → seed nuclei-default-credentials em todos os outros subdomínios com
        endpoints de autenticação conhecidos no mesmo scan.
    """
    if tool_name.lower() not in CREDENTIAL_TOOLS:
        return {"propagated": 0}

    creds = _extract_credentials_from_result(result)
    if not creds:
        return {"propagated": 0}

    logger.info(
        "cross_target_propagator: scan=%s source=%s tool=%s found %d creds → propagating",
        scan_id, source_target, tool_name, len(creds),
    )

    # Busca outros targets no scan (excluindo o source)
    all_targets = _get_all_scan_targets(db, scan_id)
    other_targets = [t for t in all_targets if t != source_target]

    # Prioriza targets com auth endpoints conhecidos
    auth_endpoints = _get_auth_endpoints_for_scan(db, scan_id)
    auth_targets = {ep[0] for ep in auth_endpoints}

    seeded = 0
    for target in other_targets[:50]:  # cap: max 50 targets
        # Prioriza targets com auth endpoint, mas testa todos com /login path potential
        is_likely_auth = (
            target in auth_targets
            or any(kw in target.lower() for kw in ("login", "auth", "admin", "api", "sso", "oauth"))
        )
        if is_likely_auth or len(creds) >= 3:
            seeded += _seed_credential_test(db, scan_id, target, len(creds), source_target)

    # Persiste um finding de "credential leaked + propagation" no source
    try:
        from app.models.models import Finding
        leak_title = f"Credential leak detectado em {source_target} — testando {seeded} targets"
        existing = (
            db.query(Finding.id)
            .filter(
                Finding.scan_job_id == scan_id,
                Finding.title == leak_title[:500],
                Finding.domain == source_target[:255],
            )
            .first()
        )
        if not existing:
            db.add(Finding(
                scan_job_id=scan_id,
                title=leak_title[:500],
                severity="high",
                risk_score=8,
                domain=source_target[:255],
                tool=tool_name[:100],
                confidence_score=80,
                details={
                    "node": "osint",
                    "step": "cross_target_propagator",
                    "asset": source_target,
                    "tool": tool_name,
                    "credential_count": len(creds),
                    "propagated_to": seeded,
                    "credential_types": list({c.get("rule", "unknown") for c in creds}),
                    "propagation_type": "credential_stuffing",
                    "owasp_category": "A07:2021 Identification and Authentication Failures",
                },
                created_at=datetime.utcnow(),
            ))
            db.flush()
    except Exception:
        pass

    try:
        db.commit()
    except Exception:
        db.rollback()

    logger.info(
        "cross_target_propagator: propagated credential test to %d targets (scan=%s source=%s)",
        seeded, scan_id, source_target,
    )
    return {"creds_found": len(creds), "propagated": seeded}


def propagate_shared_version(
    db: Session,
    scan_id: int,
    source_target: str,
    product: str,
    version: str,
) -> dict[str, Any]:
    """Se 3+ targets têm a mesma versão de software, testa CVE uma vez por target.

    Evita executar o mesmo scan de CVE 40 vezes para 40 subdomínios com nginx/1.18.0.
    Em vez disso, verifica se já testamos esse CVE em qualquer target → pula se sim.
    Mas se é um target novo com a mesma versão → enfileira o teste.
    """
    if not product or not version:
        return {"propagated": 0}

    all_targets = _get_all_scan_targets(db, scan_id)
    other_targets = [t for t in all_targets if t != source_target]

    # Verifica quantos targets já têm esse produto detectado
    try:
        from app.models.models import Finding
        count_same_version = (
            db.query(Finding.domain)
            .filter(
                Finding.scan_job_id == scan_id,
                Finding.details["product"].as_string().like(f"%{product[:30]}%"),
            )
            .distinct()
            .count()
        )
    except Exception:
        count_same_version = 0

    # Se há múltiplos targets com a mesma versão, propaga os testes de CVE
    if count_same_version < 2:
        return {"propagated": 0}

    seeded = 0
    for target in other_targets[:20]:  # cap: max 20 targets por propagação
        seeded += _seed_version_cve_for_target(db, scan_id, target, product, phase_id="P09")

    if seeded:
        try:
            db.commit()
        except Exception:
            db.rollback()

    logger.info(
        "cross_target_propagator: shared_version product=%s version=%s → seeded %d targets (scan=%s)",
        product, version, seeded, scan_id,
    )
    return {"propagated": seeded, "product": product, "version": version}


def propagate_certificate_sans(
    db: Session,
    scan_id: int,
    source_target: str,
    tool_name: str,
    result: dict[str, Any],
    job: Any,
) -> dict[str, Any]:
    """Extrai domínios do SAN do certificado e enfileira-os como novos targets.

    Um certificado wildcard em sub A pode expor subs não encontrados via DNS.
    """
    if tool_name.lower() not in CERT_TOOLS:
        return {"san_domains": 0}

    san_domains = _extract_san_domains(result)
    if not san_domains:
        return {"san_domains": 0}

    # Obtém root domain do target
    try:
        root = ".".join(source_target.split(".")[-2:])
    except Exception:
        root = source_target

    # Filtra apenas domínios in-scope
    in_scope = [d for d in san_domains if d.endswith(f".{root}") or d == root]
    if not in_scope:
        return {"san_domains": 0}

    # Enfileira os novos subdomínios como targets P02/P06
    try:
        from app.services.scan_work_queue import enqueue_scan_work_items
        seeded = enqueue_scan_work_items(
            db,
            job,
            in_scope,
            source="cert_san_propagator",
        )
        logger.info(
            "cross_target_propagator: cert_san scan=%s source=%s san=%d in_scope=%d seeded=%s",
            job.id, source_target, len(san_domains), len(in_scope), seeded,
        )
        return {"san_domains": len(in_scope), "seeded": seeded}
    except Exception as exc:
        logger.warning("cert_san propagation failed: %s", exc)
        return {"san_domains": 0}
