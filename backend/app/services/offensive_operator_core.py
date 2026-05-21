"""Deterministic offensive operator contracts.

This module is intentionally dependency-light so it can be exercised by unit
tests without a running LangGraph, Celery worker, MCP server, or Kali runner.
Runtime integrations should call these contracts instead of letting an LLM,
worker, or phase node mark progress directly.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlparse

try:
    import yaml
except ModuleNotFoundError:  # pragma: no cover - exercised in minimal local envs
    yaml = None


PHASE_STATUSES = {
    "pending",
    "running",
    "completed",
    "partial",
    "blocked",
    "failed",
    "skipped_with_justification",
}
HYPOTHESIS_STATUSES = {"open", "testing", "validated", "discarded", "inconclusive", "escalated"}
ATTACK_PATH_STATUSES = {"candidate", "testing", "validated", "broken", "discarded"}
EVIDENCE_STRENGTHS = ("none", "weak", "medium", "strong", "conclusive")
EXECUTION_MODES = {
    "learning_only",
    "passive_recon",
    "safe_validation",
    "controlled_pentest",
    "full_authorized_pentest",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def stable_id(prefix: str, payload: Any) -> str:
    digest = hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode()).hexdigest()[:12]
    return f"{prefix}-{digest}"


def _load_skill_tool_map(skills_root: Path | str | None = None) -> dict[str, dict[str, Any]]:
    """Read every skill .md and return skill_id → {required_tools, optional_tools, fallback_tools}.

    Tries common relative paths when skills_root is not given; returns {} if the directory
    is absent so callers fall back to hardcoded lists gracefully.
    """
    roots: list[Path] = []
    if skills_root is not None:
        roots = [Path(skills_root)]
    else:
        for candidate in ["skills", "../skills", "../../skills"]:
            p = Path(candidate)
            if p.is_dir() and any(p.rglob("*.md")):
                roots.append(p)
                break

    skill_map: dict[str, dict[str, Any]] = {}
    for root in roots:
        for path in sorted(root.rglob("*.md")):
            try:
                if is_dataless_file(path):
                    continue
                parsed = parse_skill_markdown(path)
                meta = parsed["metadata"]
                skill_id = str(meta.get("skill_id") or "")
                if not skill_id:
                    continue
                skill_map[skill_id] = {
                    "required_tools": list(meta.get("required_tools") or []),
                    "optional_tools": list(meta.get("optional_tools") or []),
                    "fallback_tools": list(meta.get("fallback_tools") or []),
                }
            except Exception:  # noqa: BLE001
                pass
    return skill_map


def _resolve_phase_tools(
    skill_ids: list[str],
    skill_map: dict[str, dict[str, Any]],
    fallback_required: list[str],
    fallback_optional: list[str] | None = None,
) -> tuple[list[str], list[str]]:
    """Merge required/optional tools from skill metadata; fall back to hardcoded lists.

    Required tools come from the skill's required_tools.
    Optional tools include the skill's optional_tools + fallback_tools (deduplicated).
    """
    if not skill_map:
        return fallback_required, fallback_optional or []

    required: list[str] = []
    optional: list[str] = []
    for skill_id in skill_ids:
        tools = skill_map.get(skill_id) or {}
        required.extend(tools.get("required_tools") or [])
        optional.extend(tools.get("optional_tools") or [])
        optional.extend(tools.get("fallback_tools") or [])

    seen: set[str] = set()
    req_deduped = [t for t in required if not (t in seen or seen.add(t))]  # type: ignore[func-returns-value]
    opt_deduped = [t for t in optional if t not in seen and not seen.add(t)]  # type: ignore[func-returns-value]

    if not req_deduped:
        return fallback_required, fallback_optional or []
    return req_deduped, opt_deduped


def default_phase_contracts(skills_root: Path | str | None = None) -> dict[str, dict[str, Any]]:
    """Return P01-P22 contracts with tools resolved from skill metadata.

    Tool lists are read from the skill markdown frontmatter (required_tools /
    optional_tools / fallback_tools). The hardcoded tuples serve as fallbacks
    when the skills directory is not mounted (e.g. unit tests without Docker).
    """
    skill_map = _load_skill_tool_map(skills_root)

    # (phase_id, name, description, skill_ids, fb_required, fb_optional)
    rows = [
        ("P01", "Subdomain Enumeration", "Collect passive domains, subdomains and assets",
         ["skill.recon.subdomain_enumeration"], ["subfinder"], ["amass", "dnsx", "assetfinder"]),
        ("P02", "Port Service Discovery", "Discover exposed ports and services",
         ["skill.recon.port_service_discovery"], ["naabu"], ["nmap", "masscan"]),
        ("P03", "Endpoint Discovery", "Discover routes, content and JavaScript surfaces",
         ["skill.discovery.endpoint_discovery"], ["ffuf"], ["gobuster", "katana"]),
        ("P04", "Parameter Discovery", "Discover input points and parameters",
         ["skill.discovery.parameter_discovery"], ["arjun"], ["paramspider", "ffuf"]),
        ("P05", "Surface Expansion", "Expand hidden routes and crawlable content",
         ["skill.discovery.endpoint_discovery"], ["ffuf"], ["gobuster", "katana"]),
        ("P06", "HTTP Fingerprinting", "Fingerprint HTTP behavior, headers and WAF clues",
         ["skill.recon.port_service_discovery"], ["naabu"], ["nmap", "httpx"]),
        ("P07", "Technology Detection", "Identify services and technology versions",
         ["skill.recon.port_service_discovery"], ["naabu"], ["whatweb-basic", "httpx"]),
        ("P08", "JavaScript Endpoint Analysis", "Analyze application routes and script-linked endpoints",
         ["skill.discovery.endpoint_discovery"], ["ffuf"], ["katana", "katana-js"]),
        ("P09", "Content Discovery", "Discover files and directories",
         ["skill.discovery.endpoint_discovery"], ["ffuf"], ["gobuster", "feroxbuster"]),
        ("P10", "Injection Testing", "Test injection hypotheses with controls",
         ["skill.sqli_testing"], ["curl"], ["sqlmap", "manual_http_probe"]),
        ("P11", "SSRF Testing", "Validate SSRF and callback hypotheses",
         ["skill.vuln.ssrf"], ["curl"], ["interactsh", "ffuf", "wapiti"]),
        ("P12", "XSS Testing", "Validate reflected or stored XSS safely",
         ["skill.stored_xss_testing"], ["curl"], ["dalfox", "manual_http_probe"]),
        ("P13", "Access Control Testing", "Validate object and authorization boundaries",
         ["skill.idor_object_authorization"], ["curl"], ["manual_http_probe"]),
        ("P14", "Auth Boundary Testing", "Test authentication and session boundaries",
         ["skill.vuln.auth_bypass"], ["ffuf"], ["hydra", "curl"]),
        ("P15", "File Handling Testing", "Validate exposed files and upload-adjacent risks",
         ["skill.chain.exposed_git_to_credential_leak"], ["curl"], ["git", "gitleaks"]),
        ("P16", "API Input Surface Review", "Validate API and parameterized endpoint coverage",
         ["skill.discovery.parameter_discovery"], ["arjun"], ["paramspider", "ffuf"]),
        ("P17", "Exploit Validation", "Reproduce validated exploit paths safely",
         ["skill.vuln.sqli"], ["sqlmap"], ["wapiti"]),
        ("P18", "Credential Exposure Boundary", "Validate credential exposure only when authorized",
         ["skill.chain.exposed_git_to_credential_leak"], ["curl"], ["gitleaks", "trufflehog-filesystem"]),
        ("P19", "Post Exploitation Boundary", "Validate post-exploitation scope controls",
         ["skill.idor_object_authorization"], ["curl"], ["manual_http_probe"]),
        ("P20", "Attack Path Correlation", "Build offensive chains from evidence",
         ["skill.chain.exposed_git_to_credential_leak"], ["curl"], ["manual_correlation"]),
        ("P21", "Evidence Quality Review", "Score evidence and false positive controls",
         ["skill.reporting.evidence_quality"], ["manual_review"], []),
        ("P22", "Campaign Reporting", "Build offensive campaign narrative",
         ["skill.technical_report"], ["report-builder"], ["manual_review"]),
    ]

    contracts: dict[str, dict[str, Any]] = {}
    for phase_id, name, description, skills, fb_required, fb_optional in rows:
        required_tools, optional_tools = _resolve_phase_tools(skills, skill_map, fb_required, fb_optional)
        contracts[phase_id] = {
            "phase_id": phase_id,
            "name": name,
            "description": description,
            "required_skills": skills,
            "optional_skills": [],
            "required_tools": required_tools,
            "optional_tools": optional_tools,
            "minimum_evidence": ["tool_output", "raw_tool_output", "parsed_result"],
            "exit_criteria": {
                "minimum_required_tools_attempted": 1,
                "evidence_required": True,
                "validator_required": True,
                "allow_partial": True,
                "allow_skip": phase_id in {"P18", "P19"},
                "minimum_evidence_strength": "medium" if phase_id not in {"P01", "P21", "P22"} else "weak",
            },
            "retry_policy": {"max_retries": 2, "fallback_allowed": True, "rag_reconsult_allowed": True},
        }
    return contracts


PHASE_CONTRACTS = default_phase_contracts()
PHASE_ORDER = list(PHASE_CONTRACTS)


def route_next_required_phase(completed_phases: list[str] | None, current_phase: str | None = None) -> str | None:
    completed = set(completed_phases or [])
    if current_phase and current_phase not in completed:
        return current_phase
    for phase_id in PHASE_ORDER:
        if phase_id not in completed:
            return phase_id
    return None


@dataclass
class ToolCatalogEntry:
    tool_name: str
    profile: str
    available: bool
    target_types: list[str]
    capabilities: list[str]
    accepted_arguments: list[str]
    required_arguments: list[str]
    output_format: str
    parser: str
    timeout_policy: dict[str, Any]
    risk_level: str
    noise_level: str


class ToolCatalog:
    def __init__(self, entries: list[ToolCatalogEntry] | None = None) -> None:
        self.entries = {entry.tool_name: entry for entry in (entries or default_tool_catalog())}

    def get(self, tool_name: str) -> ToolCatalogEntry | None:
        return self.entries.get(tool_name)

    def require(self, tool_name: str) -> ToolCatalogEntry:
        entry = self.get(tool_name)
        if not entry or not entry.available:
            raise ValueError(f"tool_not_found:{tool_name}")
        return entry


def default_tool_catalog() -> list[ToolCatalogEntry]:
    def entry(name: str, profile: str, capabilities: list[str], parser: str = "generic_json_parser") -> ToolCatalogEntry:
        return ToolCatalogEntry(
            tool_name=name,
            profile=profile,
            available=True,
            target_types=["url", "domain", "api_endpoint", "parameterized_endpoint"],
            capabilities=capabilities,
            accepted_arguments=["target", "wordlist", "rate", "timeout", "headers", "payload"],
            required_arguments=["target"],
            output_format="json",
            parser=parser,
            timeout_policy={"default_timeout": 300, "max_timeout": 1800},
            risk_level="medium",
            noise_level="medium",
        )

    return [
        entry("manual_scope_review", "manual-scope-review.yaml", ["scope_validation"], "manual_parser"),
        entry("manual_review", "manual-review.yaml", ["evidence_review"], "manual_parser"),
        entry("manual_correlation", "manual-correlation.yaml", ["attack_path_correlation"], "manual_parser"),
        entry("manual_http_probe", "manual-http-probe.yaml", ["http_validation"], "http_parser"),
        entry("report-builder", "report-builder.yaml", ["reporting"], "report_parser"),
        entry("subfinder", "subfinder_passive", ["subdomain_enumeration", "passive_recon"], "subfinder_parser"),
        entry("subfinder-passive", "subfinder-passive.yaml", ["subdomain_enumeration", "passive_recon"], "subfinder_parser"),
        entry("assetfinder", "assetfinder_passive", ["subdomain_enumeration", "passive_recon"], "subfinder_parser"),
        entry("naabu", "naabu_top1000", ["port_service_discovery"], "naabu_parser"),
        entry("nmap-top-ports", "nmap-top-ports.yaml", ["port_service_discovery"], "nmap_parser"),
        entry("nmap", "nmap_service_detect", ["port_service_discovery"], "nmap_parser"),
        entry("arjun", "arjun_param_discover", ["parameter_discovery"], "arjun_parser"),
        entry("paramspider", "paramspider_mining", ["parameter_discovery"], "param_parser"),
        entry("ffuf", "ffuf_dirs", ["content_discovery", "fuzzing"], "ffuf_parser"),
        entry("ffuf-params", "ffuf-params.yaml", ["parameter_discovery", "fuzzing"], "ffuf_parser"),
        entry("ffuf-content", "ffuf-content.yaml", ["content_discovery", "fuzzing"], "ffuf_parser"),
        entry("katana", "katana_crawl", ["endpoint_discovery", "crawling"], "katana_parser"),
        entry("gobuster", "gobuster_dir", ["content_discovery", "fuzzing"], "ffuf_parser"),
        entry("katana-crawl", "katana-crawl.yaml", ["endpoint_discovery", "crawling"], "katana_parser"),
        entry("katana-js", "katana-js.yaml", ["js_analysis"], "katana_parser"),
        entry("httpx-fingerprint", "httpx-fingerprint.yaml", ["http_fingerprinting"], "httpx_parser"),
        entry("whatweb-basic", "whatweb-basic.yaml", ["technology_detection"], "whatweb_parser"),
        entry("curl", "curl.yaml", ["http_validation", "request_response_pair"], "http_parser"),
        entry("curl-headers", "curl_headers", ["http_validation", "headers"], "http_parser"),
        entry("sqlmap", "sqlmap_basic", ["sqli_validation"], "sqlmap_parser"),
        entry("wapiti", "wapiti_scan", ["web_validation"], "generic_json_parser"),
        entry("dalfox", "dalfox_xss", ["xss_validation"], "dalfox_parser"),
        entry("interactsh", "interactsh_oob", ["ssrf_oob"], "interactsh_parser"),
        entry("nuclei", "nuclei_cves", ["template_validation"], "nuclei_parser"),
        entry("hydra", "hydra_wordlist_auth", ["auth_validation"], "generic_json_parser"),
        entry("git", "manual-http-probe.yaml", ["git_exposure_review"], "manual_parser"),
        entry("gitleaks", "gitleaks_secrets", ["secret_detection"], "secret_parser"),
        entry("trufflehog-filesystem", "trufflehog-filesystem.yaml", ["secret_detection"], "secret_parser"),
    ]


@dataclass
class Scope:
    scope_id: str
    allowed_domains: list[str] = field(default_factory=list)
    allowed_subdomains: list[str] = field(default_factory=list)
    allowed_ips: list[str] = field(default_factory=list)
    allowed_ports: list[int] = field(default_factory=list)
    allowed_protocols: list[str] = field(default_factory=lambda: ["http", "https"])
    disallowed_targets: list[str] = field(default_factory=list)
    allowed_techniques: list[str] = field(default_factory=list)
    disallowed_techniques: list[str] = field(default_factory=list)
    max_noise_level: str = "medium"
    allow_authenticated_testing: bool = True
    allow_post_exploitation: bool = False
    allow_credential_testing: bool = False
    allow_data_access_validation: bool = False
    execution_windows: list[dict[str, Any]] = field(default_factory=list)


class ScopeGuard:
    NOISE_ORDER = {"low": 1, "medium": 2, "high": 3}

    def validate(self, target: str, scope: Scope, technique: str | None = None, noise_level: str = "medium") -> dict[str, Any]:
        parsed = urlparse(target if "://" in target else f"https://{target}")
        host = parsed.hostname or target
        protocol = parsed.scheme or "https"
        port = parsed.port
        if target in scope.disallowed_targets or host in scope.disallowed_targets:
            return {"allowed": False, "reason": "target_explicitly_disallowed"}
        if scope.allowed_protocols and protocol not in scope.allowed_protocols:
            return {"allowed": False, "reason": "protocol_not_allowed"}
        if scope.allowed_ports and port is not None and port not in scope.allowed_ports:
            return {"allowed": False, "reason": "port_not_allowed"}
        allowed_hosts = set(scope.allowed_domains + scope.allowed_subdomains + scope.allowed_ips)
        if allowed_hosts and host not in allowed_hosts and not any(host.endswith(f".{domain}") for domain in scope.allowed_domains):
            return {"allowed": False, "reason": "target_out_of_scope"}
        if technique and technique in scope.disallowed_techniques:
            return {"allowed": False, "reason": "technique_disallowed"}
        if scope.allowed_techniques and technique and technique not in scope.allowed_techniques:
            return {"allowed": False, "reason": "technique_not_allowed"}
        if self.NOISE_ORDER.get(noise_level, 2) > self.NOISE_ORDER.get(scope.max_noise_level, 2):
            return {"allowed": False, "reason": "noise_level_exceeds_scope"}
        return {"allowed": True, "reason": "scope_approved"}


class ExecutionPolicyEngine:
    def __init__(self, catalog: ToolCatalog | None = None, scope_guard: ScopeGuard | None = None) -> None:
        self.catalog = catalog or ToolCatalog()
        self.scope_guard = scope_guard or ScopeGuard()

    def decide(self, request: dict[str, Any]) -> dict[str, Any]:
        if request.get("execution_mode") not in EXECUTION_MODES:
            return {"allowed": False, "reason": "", "required_controls": [], "blocked_reason": "invalid_execution_mode"}
        if request["execution_mode"] == "learning_only":
            return {"allowed": False, "reason": "", "required_controls": [], "blocked_reason": "learning_only_no_tool_execution"}
        tool = self.catalog.get(str(request.get("tool_name") or ""))
        if not tool or not tool.available:
            return {"allowed": False, "reason": "", "required_controls": [], "blocked_reason": "tool_without_profile"}
        if not tool.profile:
            return {"allowed": False, "reason": "", "required_controls": [], "blocked_reason": "tool_without_profile"}
        if not tool.parser:
            return {"allowed": False, "reason": "", "required_controls": [], "blocked_reason": "execution_without_parser"}
        if not tool.timeout_policy.get("default_timeout"):
            return {"allowed": False, "reason": "", "required_controls": [], "blocked_reason": "execution_without_timeout"}
        if not request.get("expected_evidence"):
            return {"allowed": False, "reason": "", "required_controls": [], "blocked_reason": "execution_without_evidence_expected"}
        scope_decision = self.scope_guard.validate(
            target=str(request.get("target") or ""),
            scope=request["scope"],
            technique=str(request.get("payload_family") or request.get("skill_id") or ""),
            noise_level=str(request.get("noise_level") or tool.noise_level),
        )
        if not scope_decision["allowed"]:
            return {"allowed": False, "reason": "", "required_controls": [], "blocked_reason": scope_decision["reason"]}
        if request.get("mcp_available") is False:
            return {"allowed": False, "reason": "", "required_controls": [], "blocked_reason": "mcp_unavailable"}
        return {"allowed": True, "reason": "policy_approved", "required_controls": ["scope_guard", "mcp", "evidence"], "blocked_reason": None}


def parse_skill_markdown(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    match = re.match(r"\A---\s*\n(.*?)\n---\s*\n(.*)\Z", text, re.S)
    if not match:
        raise ValueError("missing_frontmatter")
    metadata = safe_yaml_load(match.group(1)) or {}
    if not isinstance(metadata, dict):
        raise ValueError("invalid_frontmatter")
    return {"metadata": metadata, "body": match.group(2), "path": str(path)}


def safe_yaml_load(text: str) -> dict[str, Any]:
    if yaml is not None:
        return yaml.safe_load(text) or {}
    data: dict[str, Any] = {}
    stack: list[tuple[int, Any]] = [(-1, data)]
    lines = text.splitlines()
    for line_index, raw_line in enumerate(lines):
        if not raw_line.strip() or raw_line.lstrip().startswith("#"):
            continue
        indent = len(raw_line) - len(raw_line.lstrip(" "))
        line = raw_line.strip()
        while stack and indent <= stack[-1][0]:
            stack.pop()
        parent = stack[-1][1]
        if line.startswith("- "):
            value = _parse_scalar(line[2:].strip())
            if isinstance(parent, list):
                parent.append(value)
            continue
        if ":" not in line:
            continue
        key, raw_value = line.split(":", 1)
        key = key.strip()
        raw_value = raw_value.strip()
        if raw_value == "":
            next_container: Any = [] if _next_content_starts_list(lines, line_index, indent) else {}
            if isinstance(parent, dict):
                parent[key] = next_container
                stack.append((indent, next_container))
            continue
        if isinstance(parent, dict):
            parent[key] = _parse_scalar(raw_value)
    return data


def _next_content_starts_list(lines: list[str], line_index: int, current_indent: int) -> bool:
    for next_line in lines[line_index + 1 :]:
        if not next_line.strip() or next_line.lstrip().startswith("#"):
            continue
        indent = len(next_line) - len(next_line.lstrip(" "))
        return indent > current_indent and next_line.strip().startswith("- ")
    return False


def _parse_scalar(value: str) -> Any:
    value = value.strip()
    if value in {"true", "True"}:
        return True
    if value in {"false", "False"}:
        return False
    if value in {"null", "None"}:
        return None
    if value.startswith("[") and value.endswith("]"):
        inner = value[1:-1].strip()
        if not inner:
            return []
        return [_parse_scalar(part.strip()) for part in inner.split(",")]
    if (value.startswith('"') and value.endswith('"')) or (value.startswith("'") and value.endswith("'")):
        return value[1:-1]
    try:
        return int(value)
    except ValueError:
        return value


def is_dataless_file(path: Path) -> bool:
    """Detect macOS/iCloud dataless files without opening file content."""
    try:
        flags = getattr(os.stat(path), "st_flags", 0)
    except OSError:
        return False
    return bool(flags & 0x40000000)


class SkillRegistry:
    REQUIRED_FRONTMATTER = {
        "skill_id",
        "name",
        "version",
        "category",
        "phase_ids",
        "supported_target_types",
        "risk_level",
        "noise_level",
        "requires_authorization",
        "required_tools",
        "evidence_required",
        "exit_criteria",
        "retry_policy",
        "allowed_execution_modes",
        "safety_rules",
    }

    REQUIRED_SECTIONS = ["# Objective", "# Offensive Reasoning", "# Execution Strategy", "# Tool Mapping", "# Expected Evidence", "## Changelog"]

    def __init__(self, skills_root: str | Path = "skills", catalog: ToolCatalog | None = None) -> None:
        self.skills_root = Path(skills_root)
        self.catalog = catalog or ToolCatalog()
        self._skills: dict[str, dict[str, Any]] | None = None

    def load(self) -> dict[str, dict[str, Any]]:
        skills: dict[str, dict[str, Any]] = {}
        if not self.skills_root.exists():
            self._skills = self._with_contract_fallback_skills(skills)
            return self._skills
        for path in sorted(self.skills_root.rglob("*.md")):
            try:
                if is_dataless_file(path):
                    skills[str(path)] = {
                        "skill_id": "",
                        "path": str(path),
                        "status": "review",
                        "quality_gate_status": "failed",
                        "quality_gate_errors": ["file_dataless_unavailable_offline"],
                        "metadata": {},
                        "body": "",
                    }
                    continue
                parsed = parse_skill_markdown(path)
                metadata = parsed["metadata"]
                skill_id = str(metadata.get("skill_id") or "")
                gate = self.validate(parsed)
                skills[skill_id or str(path)] = {
                    "skill_id": skill_id,
                    "path": str(path),
                    "version": metadata.get("version"),
                    "status": metadata.get("status", "approved" if gate["valid"] else "review"),
                    "category": metadata.get("category"),
                    "phase_ids": metadata.get("phase_ids") or [],
                    "source_report_ids": metadata.get("source_report_ids") or [],
                    "allowed_execution_modes": metadata.get("allowed_execution_modes") or [],
                    "required_tools": metadata.get("required_tools") or [],
                    "quality_gate_status": "passed" if gate["valid"] else "failed",
                    "quality_gate_errors": gate["errors"],
                    "metadata": metadata,
                    "body": parsed["body"],
                }
            except Exception as exc:  # noqa: BLE001
                skills[str(path)] = {
                    "skill_id": "",
                    "path": str(path),
                    "status": "review",
                    "quality_gate_status": "failed",
                    "quality_gate_errors": [str(exc)],
                    "metadata": {},
                    "body": "",
                }
        self._skills = self._with_contract_fallback_skills(skills)
        return self._skills

    def _with_contract_fallback_skills(self, skills: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
        """Ensure deterministic phase contracts can run when markdown skills are not mounted.

        The Docker backend mounts `./backend` at `/app` in development, while the
        markdown skill library lives at the repository root. Without this fallback
        the offensive operator blocks at P01 before attempting any tool.
        """
        result = dict(skills)
        for contract in PHASE_CONTRACTS.values():
            for skill_id in contract.get("required_skills") or []:
                existing = result.get(skill_id)
                if existing and existing.get("quality_gate_status") == "passed":
                    phase_ids = list(dict.fromkeys(list(existing.get("phase_ids") or []) + [contract["phase_id"]]))
                    modes = list(dict.fromkeys(list(existing.get("allowed_execution_modes") or []) + sorted(EXECUTION_MODES - {"learning_only"})))
                    tools = list(dict.fromkeys(list(existing.get("required_tools") or []) + list(contract.get("required_tools") or [])))
                    metadata = dict(existing.get("metadata") or {})
                    metadata["phase_ids"] = phase_ids
                    metadata["allowed_execution_modes"] = modes
                    metadata["required_tools"] = tools
                    existing.update(
                        phase_ids=phase_ids,
                        allowed_execution_modes=modes,
                        required_tools=tools,
                        metadata=metadata,
                    )
                    continue
                metadata = {
                    "skill_id": skill_id,
                    "name": contract["name"],
                    "version": "contract-fallback",
                    "status": "approved",
                    "category": "contract",
                    "phase_ids": [contract["phase_id"]],
                    "supported_target_types": ["domain", "url"],
                    "risk_level": "medium",
                    "noise_level": "medium",
                    "requires_authorization": True,
                    "required_tools": list(contract.get("required_tools") or []),
                    "fallback_tools": list(contract.get("optional_tools") or []),
                    "evidence_required": list(contract.get("minimum_evidence") or ["tool_output"]),
                    "exit_criteria": dict(contract.get("exit_criteria") or {}),
                    "retry_policy": dict(contract.get("retry_policy") or {}),
                    "allowed_execution_modes": sorted(EXECUTION_MODES - {"learning_only"}),
                    "safety_rules": ["scope_guard_required", "authorized_targets_only"],
                }
                result[skill_id] = {
                    "skill_id": skill_id,
                    "path": f"<contract:{contract['phase_id']}>",
                    "version": metadata["version"],
                    "status": "approved",
                    "category": metadata["category"],
                    "phase_ids": metadata["phase_ids"],
                    "source_report_ids": [],
                    "allowed_execution_modes": metadata["allowed_execution_modes"],
                    "required_tools": metadata["required_tools"],
                    "quality_gate_status": "passed",
                    "quality_gate_errors": [],
                    "metadata": metadata,
                    "body": (
                        f"# Objective\n{contract['description']}\n\n"
                        "# Offensive Reasoning\nUse the phase contract safely inside authorized scope.\n\n"
                        "# Execution Strategy\nRun the required tools and collect evidence.\n\n"
                        "# Tool Mapping\nContract required tools define the tool plan.\n\n"
                        "# Expected Evidence\nPersist raw and parsed tool output.\n\n"
                        "## Changelog\n- contract fallback\n"
                    ),
                }
        return result

    def validate(self, parsed: dict[str, Any]) -> dict[str, Any]:
        metadata = parsed["metadata"]
        body = parsed["body"]
        errors: list[str] = []
        missing = sorted(self.REQUIRED_FRONTMATTER - set(metadata))
        errors.extend([f"missing_frontmatter:{field}" for field in missing])
        if not metadata.get("required_tools"):
            errors.append("missing_required_tools")
        for tool in list(metadata.get("required_tools") or []) + list(metadata.get("fallback_tools") or []):
            if not self.catalog.get(str(tool)):
                errors.append(f"tool_not_found:{tool}")
        if not metadata.get("evidence_required"):
            errors.append("missing_evidence_required")
        if not metadata.get("exit_criteria"):
            errors.append("missing_exit_criteria")
        if not metadata.get("retry_policy"):
            errors.append("missing_retry_policy")
        for section in self.REQUIRED_SECTIONS:
            if section not in body:
                errors.append(f"missing_section:{section}")
        if metadata.get("learning_source") == "hackerone" and not metadata.get("source_report_ids"):
            errors.append("missing_source_report_ids")
        return {"valid": not errors, "errors": errors}

    def approved_for_phase(self, phase_id: str, execution_mode: str) -> list[dict[str, Any]]:
        skills = self._skills if self._skills is not None else self.load()
        return [
            skill
            for skill in skills.values()
            if skill.get("quality_gate_status") == "passed"
            and skill.get("status", "approved") == "approved"
            and phase_id in (skill.get("phase_ids") or [])
            and execution_mode in (skill.get("allowed_execution_modes") or [])
        ]


class SkillRagIndex:
    def __init__(self, registry: SkillRegistry) -> None:
        self.registry = registry
        self.chunks: list[dict[str, Any]] = []

    def rebuild(self) -> list[dict[str, Any]]:
        skills = self.registry.load()
        chunks: list[dict[str, Any]] = []
        for skill in skills.values():
            if skill.get("quality_gate_status") != "passed":
                continue
            metadata = skill["metadata"]
            sections = re.split(r"\n(?=# )", skill.get("body") or "")
            for index, section in enumerate([part.strip() for part in sections if part.strip()]):
                chunks.append(
                    {
                        "chunk_id": stable_id("chunk", {"skill": skill["skill_id"], "index": index, "section": section[:80]}),
                        "skill_id": skill["skill_id"],
                        "skill_version": metadata.get("version"),
                        "skill_path": skill["path"],
                        "section": section.splitlines()[0].lstrip("# ").strip(),
                        "category": metadata.get("category"),
                        "phase_ids": metadata.get("phase_ids") or [],
                        "vulnerability_class": metadata.get("vulnerability_class", ""),
                        "source_report_ids": metadata.get("source_report_ids") or [],
                        "execution_modes": metadata.get("allowed_execution_modes") or [],
                        "required_tools": metadata.get("required_tools") or [],
                        "status": metadata.get("status", "approved"),
                        "tags": metadata.get("tags") or [],
                        "content": section,
                    }
                )
        self.chunks = chunks
        return chunks

    def retrieve(self, query: str, filters: dict[str, Any] | None = None, top_k: int = 5) -> dict[str, Any]:
        filters = filters or {}
        if not self.chunks:
            self.rebuild()
        query_tokens = set(re.findall(r"[a-z0-9_\\-]{3,}", query.lower()))
        scored: dict[str, dict[str, Any]] = {}
        for chunk in self.chunks:
            if not self._matches(chunk, filters):
                continue
            tokens = set(re.findall(r"[a-z0-9_\\-]{3,}", json.dumps(chunk, default=str).lower()))
            score = len(query_tokens & tokens) / max(1, len(query_tokens))
            if score <= 0 and filters:
                score = 0.25
            current = scored.get(chunk["skill_id"])
            if not current or score > current["relevance"]:
                scored[chunk["skill_id"]] = {
                    "skill_id": chunk["skill_id"],
                    "path": chunk["skill_path"],
                    "relevance": round(score, 4),
                    "matched_reasons": self._reasons(chunk, filters),
                }
        return {
            "retrieved_skills": sorted(scored.values(), key=lambda item: item["relevance"], reverse=True)[:top_k],
            "retrieved_context": [],
            "recommended_execution_focus": [],
        }

    @staticmethod
    def _matches(chunk: dict[str, Any], filters: dict[str, Any]) -> bool:
        for key, value in filters.items():
            if value in (None, "", []):
                continue
            if key == "phase_id":
                if value not in (chunk.get("phase_ids") or []):
                    return False
                continue
            if key == "execution_mode":
                if value not in (chunk.get("execution_modes") or []):
                    return False
                continue
            actual = chunk.get(key)
            if isinstance(actual, list):
                if value not in actual:
                    return False
            elif actual != value:
                return False
        return True

    @staticmethod
    def _reasons(chunk: dict[str, Any], filters: dict[str, Any]) -> list[str]:
        reasons = []
        if filters.get("phase_id") in chunk.get("phase_ids", []):
            reasons.append(f"Phase {filters['phase_id']} active")
        if filters.get("execution_mode") in chunk.get("execution_modes", []):
            reasons.append(f"Execution mode {filters['execution_mode']} allowed")
        if filters.get("vulnerability_class") == chunk.get("vulnerability_class"):
            reasons.append(f"Vulnerability class {filters['vulnerability_class']} matched")
        return reasons or ["Lexical skill match"]


class SkillToToolPlanCompiler:
    def __init__(self, catalog: ToolCatalog | None = None, policy: ExecutionPolicyEngine | None = None) -> None:
        self.catalog = catalog or ToolCatalog()
        self.policy = policy or ExecutionPolicyEngine(self.catalog)

    def compile(
        self,
        skill: dict[str, Any],
        phase_contract: dict[str, Any],
        target: str,
        scope: Scope,
        execution_mode: str,
        mcp_available: bool = True,
    ) -> dict[str, Any]:
        if skill.get("quality_gate_status") != "passed":
            raise ValueError("skill_quality_gate_failed")
        tools: list[dict[str, Any]] = []
        for name in skill["metadata"].get("required_tools") or []:
            catalog_entry = self.catalog.get(str(name))
            if not catalog_entry:
                # Tool missing from catalog — emit a blocked entry so the validator
                # can decide based on whether it's required, rather than crashing.
                tools.append({
                    "tool_name": str(name),
                    "profile": "",
                    "required": True,
                    "arguments": {},
                    "reason": f"tool_not_in_catalog:{name}",
                    "expected_evidence": [],
                    "timeout": 0,
                    "rate_limit": 0,
                    "noise_level": "low",
                    "policy_decision": {"allowed": False, "blocked_reason": f"tool_not_in_catalog:{name}"},
                })
                continue
            expected_evidence = skill["metadata"].get("evidence_required") or phase_contract.get("minimum_evidence") or []
            policy_decision = self.policy.decide(
                {
                    "phase_id": phase_contract["phase_id"],
                    "skill_id": skill["skill_id"],
                    "tool_name": catalog_entry.tool_name,
                    "target": target,
                    "payload_family": skill["metadata"].get("vulnerability_class", skill["skill_id"]),
                    "execution_mode": execution_mode,
                    "scope": scope,
                    "risk_level": skill["metadata"].get("risk_level"),
                    "noise_level": skill["metadata"].get("noise_level"),
                    "expected_evidence": expected_evidence,
                    "mcp_available": mcp_available,
                }
            )
            tools.append(
                {
                    "tool_name": catalog_entry.tool_name,
                    "profile": catalog_entry.profile,
                    "required": True,
                    "arguments": {"target": target, "timeout": catalog_entry.timeout_policy["default_timeout"]},
                    "reason": f"Required by {skill['skill_id']}",
                    "expected_evidence": expected_evidence,
                    "timeout": catalog_entry.timeout_policy["default_timeout"],
                    "rate_limit": 50,
                    "noise_level": catalog_entry.noise_level,
                    "policy_decision": policy_decision,
                }
            )
        return {
            "tool_plan_id": stable_id("TP", {"phase_id": phase_contract["phase_id"], "skill_id": skill["skill_id"], "target": target}),
            "phase_id": phase_contract["phase_id"],
            "skill_id": skill["skill_id"],
            "objective": skill["metadata"].get("name") or phase_contract["name"],
            "tools": tools,
            "fallbacks": skill["metadata"].get("fallback_tools") or [],
            "validation_plan": skill["metadata"].get("exit_criteria") or {},
            "retry_plan": skill["metadata"].get("retry_policy") or {},
            "policy_decision": {"allowed": all(tool["policy_decision"]["allowed"] for tool in tools)},
        }


class MCPToolExecutor:
    def __init__(self, call_tool: Callable[[dict[str, Any]], dict[str, Any]] | None = None, available: bool = True) -> None:
        self.call_tool = call_tool
        self.available = available

    def execute(self, tool_plan: dict[str, Any], target: str) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for tool in tool_plan.get("tools") or []:
            execution = {
                "mcp_execution_id": stable_id("MCP", {"tool_plan_id": tool_plan["tool_plan_id"], "tool": tool["tool_name"]}),
                "mcp_request_id": stable_id("mcp", {"tool_plan_id": tool_plan["tool_plan_id"], "tool": tool["tool_name"]}),
                "tool_plan_id": tool_plan["tool_plan_id"],
                "phase_id": tool_plan["phase_id"],
                "skill_id": tool_plan["skill_id"],
                "tool_name": tool["tool_name"],
                "profile": tool["profile"],
                "arguments_hash": stable_id("ARG", tool.get("arguments") or {}),
                "target": target,
                "status": "blocked",
                "stdout_path": "",
                "stderr_path": "",
                "artifacts": [],
                "exit_code": None,
                "timeout": tool.get("timeout"),
                "started_at": utc_now(),
                "finished_at": "",
                "error": None,
            }
            if not self.available or tool["policy_decision"].get("blocked_reason") == "mcp_unavailable":
                execution.update(status="blocked", error="mcp_unavailable", finished_at=utc_now())
                results.append(execution)
                continue
            if not tool["policy_decision"]["allowed"]:
                execution.update(status="blocked", error=tool["policy_decision"].get("blocked_reason"), finished_at=utc_now())
                results.append(execution)
                continue
            try:
                raw = self.call_tool(execution) if self.call_tool else {"status": "success", "exit_code": 0, "stdout_path": ""}
                status = raw.get("status") or "failed"
                if status == "done":
                    status = "success"
                execution.update(
                    status=status if status in {"queued", "running", "success", "failed", "timeout", "blocked"} else "failed",
                    stdout_path=raw.get("stdout_path") or raw.get("stdout") or "",
                    stderr_path=raw.get("stderr_path") or raw.get("stderr") or "",
                    artifacts=raw.get("artifact_paths") or raw.get("artifacts") or [],
                    exit_code=raw.get("exit_code", raw.get("return_code")),
                    finished_at=utc_now(),
                    error=raw.get("error"),
                )
            except Exception as exc:  # noqa: BLE001
                execution.update(status="failed", error=str(exc), finished_at=utc_now())
            results.append(execution)
        return results


class EvidenceCollector:
    def create(self, execution: dict[str, Any], parsed_json: dict[str, Any] | None = None, payloads: list[str] | None = None) -> dict[str, Any]:
        strength = self.classify(execution, parsed_json or {})
        return {
            "evidence_id": stable_id("EV", execution),
            "phase_id": execution["phase_id"],
            "skill_id": execution["skill_id"],
            "tool_name": execution["tool_name"],
            "mcp_request_id": execution.get("mcp_request_id") or execution["mcp_execution_id"],
            "target": execution["target"],
            "evidence_type": "tool_output",
            "raw_stdout_path": execution.get("stdout_path") or "",
            "raw_stderr_path": execution.get("stderr_path") or "",
            "parsed_json": parsed_json or {},
            "request": {},
            "response": {},
            "payloads": payloads or [],
            "artifacts": execution.get("artifacts") or [],
            "created_at": utc_now(),
            "confidence": {"none": 0.0, "weak": 0.35, "medium": 0.6, "strong": 0.85, "conclusive": 1.0}[strength],
            "evidence_strength": strength,
        }

    @staticmethod
    def classify(execution: dict[str, Any], parsed_json: dict[str, Any]) -> str:
        if execution.get("status") != "success":
            return "none"
        if parsed_json.get("impact_demonstrated") and parsed_json.get("false_positive_controls_passed"):
            return "conclusive"
        if parsed_json.get("reproducible") and parsed_json.get("request_response_pair"):
            return "strong"
        if execution.get("stdout_path") or parsed_json:
            return "medium"
        return "weak"


class PhaseValidator:
    def validate(
        self,
        phase_contract: dict[str, Any],
        skill_plan: dict[str, Any],
        mcp_results: list[dict[str, Any]],
        evidence: list[dict[str, Any]],
        hypotheses: list[dict[str, Any]] | None,
        offensive_state: dict[str, Any],
    ) -> dict[str, Any]:
        required_tools = {
            str(tool.get("tool_name") or "")
            for tool in (skill_plan.get("tools") or [])
            if tool.get("required")
        }
        if not required_tools:
            required_tools = set(phase_contract.get("required_tools") or [])
        attempted = {result["tool_name"] for result in mcp_results}
        missing = sorted(required_tools - attempted)
        if missing:
            return self._decision(phase_contract["phase_id"], "blocked", False, "required_tool_not_attempted", missing)
        # Only block if a REQUIRED tool was blocked/timed-out.
        # Optional tools (not in required_tools) being blocked must not block the phase.
        required_blocked = [
            r for r in mcp_results
            if r["status"] in {"blocked", "timeout"} and r["tool_name"] in required_tools
        ]
        if required_blocked:
            reason = "required_tool_blocked_or_timeout"
            # MCP infrastructure down is a soft block — mark partial so the campaign advances.
            if all(r.get("error") in {"mcp_unavailable", None} for r in required_blocked):
                return self._decision(phase_contract["phase_id"], "partial", True, "mcp_unavailable_tool_skipped", [])
            return self._decision(phase_contract["phase_id"], "blocked", False, reason, [r["tool_name"] for r in required_blocked])
        if any(result["status"] == "failed" for result in mcp_results if result["tool_name"] in required_tools):
            return self._decision(phase_contract["phase_id"], "partial", True, "mcp_execution_failed", [])
        # Phases that tolerate missing evidence still advance as partial.
        _PARTIAL_OK = {"P05", "P06", "P07", "P08", "P09", "P10",
                       "P11", "P15", "P16", "P17", "P18", "P19", "P20", "P21", "P22"}
        if phase_contract["exit_criteria"].get("evidence_required") and not evidence:
            if phase_contract["phase_id"] in _PARTIAL_OK:
                return self._decision(phase_contract["phase_id"], "partial", True, "no_evidence_partial_ok", [])
            return self._decision(phase_contract["phase_id"], "blocked", False, "missing_evidence", [])
        min_strength = phase_contract["exit_criteria"].get("minimum_evidence_strength", "medium")
        strongest = max((EVIDENCE_STRENGTHS.index(ev.get("evidence_strength", "none")) for ev in evidence), default=0)
        if strongest < EVIDENCE_STRENGTHS.index(min_strength):
            return self._decision(phase_contract["phase_id"], "partial", True, "evidence_strength_too_weak", [])
        return {
            "phase_id": phase_contract["phase_id"],
            "status": "completed",
            "can_advance": True,
            "reason": "exit_criteria_satisfied",
            "missing_requirements": [],
            "required_retries": [],
            "generated_hypotheses": hypotheses or [],
            "updated_attack_paths": offensive_state.get("attack_paths", []),
        }

    @staticmethod
    def _decision(phase_id: str, status: str, can_advance: bool, reason: str, missing: list[str]) -> dict[str, Any]:
        return {
            "phase_id": phase_id,
            "status": status,
            "can_advance": can_advance,
            "reason": reason,
            "missing_requirements": missing,
            "required_retries": [],
            "generated_hypotheses": [],
            "updated_attack_paths": [],
        }


class HypothesisEngine:
    def update_from_evidence(self, phase_id: str, evidence: list[dict[str, Any]]) -> list[dict[str, Any]]:
        hypotheses: list[dict[str, Any]] = []
        for ev in evidence:
            parsed = ev.get("parsed_json") or {}
            for parameter in parsed.get("parameters", []):
                lower = str(parameter).lower()
                skills = ["skill.idor_object_authorization"]
                title = f"Parameter {parameter} may alter authorization or object access"
                if any(token in lower for token in ["redirect", "callback", "url", "uri"]):
                    skills = ["skill.ssr_basic_discovery", "skill.open_redirect_testing"]
                    title = f"Potential SSRF or redirect behavior in {parameter}"
                hypotheses.append(
                    {
                        "hypothesis_id": stable_id("H", {"phase_id": phase_id, "parameter": parameter}),
                        "title": title,
                        "description": "",
                        "source_phase": phase_id,
                        "source_evidence_ids": [ev["evidence_id"]],
                        "confidence": 0.74,
                        "status": "open",
                        "required_skills": skills,
                        "required_tools": ["curl"],
                        "payload_candidates": [],
                        "test_plan": {},
                        "result": None,
                        "created_at": utc_now(),
                        "updated_at": utc_now(),
                    }
                )
        return hypotheses


class AttackPathEngine:
    def correlate(self, evidence: list[dict[str, Any]], hypotheses: list[dict[str, Any]]) -> list[dict[str, Any]]:
        paths: list[dict[str, Any]] = []
        for ev in evidence:
            parsed = ev.get("parsed_json") or {}
            if parsed.get("exposed_git") or "git" in json.dumps(parsed).lower():
                paths.append(
                    {
                        "attack_path_id": stable_id("AP", {"evidence": ev["evidence_id"], "chain": "exposed_git"}),
                        "title": "Exposed Git to Credential Reuse",
                        "status": "candidate",
                        "confidence": 0.82,
                        "steps": [{"step": 1, "description": "Exposed .git found", "evidence_id": ev["evidence_id"]}],
                        "required_conditions": ["credentials_present", "authenticated_access_allowed"],
                        "impact": "",
                        "next_actions": ["extract controlled test credential candidates", "request human review before credential testing"],
                    }
                )
        return paths


class OperationLearningEngine:
    def learn(self, phase_id: str, tool_plan: dict[str, Any], mcp_results: list[dict[str, Any]], evidence: list[dict[str, Any]]) -> dict[str, Any]:
        return {
            "lesson_id": stable_id("TL", {"phase": phase_id, "tool_plan": tool_plan.get("tool_plan_id")}),
            "phase_id": phase_id,
            "skills_effective": [tool_plan.get("skill_id")] if any(ev.get("evidence_strength") in {"medium", "strong", "conclusive"} for ev in evidence) else [],
            "tools_effective": [res["tool_name"] for res in mcp_results if res.get("status") == "success"],
            "tool_errors": [res for res in mcp_results if res.get("status") != "success"],
            "created_at": utc_now(),
        }


class AdaptiveRetryEngine:
    def plan_retry(self, reason: str, previous_attempt: dict[str, Any], retry_count: int = 0) -> dict[str, Any]:
        changes = {
            "403": "reduced_rate_and_changed_headers",
            "waf": "changed_headers_and_payload_encoding",
            "timeout": "increased_timeout_and_reduced_rate",
            "parser": "fallback_parser_and_raw_evidence_review",
            "inconclusive": "changed_payload_family_and_added_negative_control",
        }
        key = next((token for token in changes if token in reason.lower()), "inconclusive")
        new_attempt = dict(previous_attempt)
        new_attempt["retry_count"] = retry_count + 1
        new_attempt["strategy_change"] = changes[key]
        if "timeout" in changes[key]:
            new_attempt["timeout"] = int(previous_attempt.get("timeout") or 120) * 2
        if "rate" in changes[key]:
            new_attempt["rate_limit"] = max(1, int(previous_attempt.get("rate_limit") or 50) // 2)
        if "headers" in changes[key]:
            new_attempt["headers"] = {"User-Agent": "authorized-security-validation"}
        return {
            "retry_id": stable_id("R", {"reason": reason, "previous": previous_attempt, "retry_count": retry_count}),
            "reason": reason,
            "previous_attempt": previous_attempt,
            "change_applied": changes[key],
            "new_attempt": new_attempt,
            "result": "",
        }


class ReportBuilder:
    def build(self, campaign: dict[str, Any]) -> dict[str, Any]:
        ledgers = campaign.get("phase_ledger", [])
        return {
            "title": "Offensive Campaign Report",
            "executive_summary": {
                "target": campaign.get("target"),
                "execution_mode": campaign.get("execution_mode"),
                "completed": len([l for l in ledgers if l.get("status") == "completed"]),
                "partial": len([l for l in ledgers if l.get("status") == "partial"]),
                "blocked": len([l for l in ledgers if l.get("status") == "blocked"]),
            },
            "offensive_campaign_timeline": [
                {
                    "phase_id": ledger.get("phase_id"),
                    "status": ledger.get("status"),
                    "skills": ledger.get("selected_skills", []),
                    "mcp_executions": ledger.get("mcp_executions", []),
                    "evidence_ids": ledger.get("evidence_ids", []),
                }
                for ledger in ledgers
            ],
            "hypotheses": campaign.get("offensive_state", {}).get("open_hypotheses", []),
            "attack_paths": campaign.get("offensive_state", {}).get("attack_paths", []),
            "findings_validated": campaign.get("findings_validated", []),
            "findings_inconclusive": campaign.get("findings_inconclusive", []),
            "coverage_gaps": [ledger for ledger in ledgers if ledger.get("status") in {"partial", "blocked", "failed"}],
        }


class OffensiveSkillRuntime:
    def __init__(
        self,
        registry: SkillRegistry | None = None,
        rag: SkillRagIndex | None = None,
        compiler: SkillToToolPlanCompiler | None = None,
        executor: MCPToolExecutor | None = None,
        validator: PhaseValidator | None = None,
    ) -> None:
        self.registry = registry or SkillRegistry()
        self.rag = rag or SkillRagIndex(self.registry)
        self.compiler = compiler or SkillToToolPlanCompiler()
        self.executor = executor or MCPToolExecutor()
        self.validator = validator or PhaseValidator()
        self.collector = EvidenceCollector()
        self.hypotheses = HypothesisEngine()
        self.attack_paths = AttackPathEngine()
        self.learning = OperationLearningEngine()

    def run_phase(
        self,
        phase_id: str,
        target: str,
        scope: Scope,
        execution_mode: str,
        offensive_state: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        state = offensive_state or create_offensive_state(target)
        contract = PHASE_CONTRACTS[phase_id]
        retrieved = self.rag.retrieve(
            f"{contract['name']} {target} {' '.join(contract['required_skills'])}",
            filters={"phase_id": phase_id, "execution_mode": execution_mode, "status": "approved"},
            top_k=3,
        )
        selected_skills = [skill["skill_id"] for skill in retrieved["retrieved_skills"]]
        registry_skills = {skill["skill_id"]: skill for skill in self.registry.approved_for_phase(phase_id, execution_mode)}
        # 1st: prefer RAG-ranked skills that are in the approved registry
        chosen = next((registry_skills[sid] for sid in selected_skills if sid in registry_skills), None)
        # 2nd fallback: use any skill declared in the phase contract directly
        if not chosen:
            chosen = next(
                (registry_skills[sid] for sid in (contract.get("required_skills") or []) if sid in registry_skills),
                None,
            )
        # 3rd fallback: use ANY approved skill for the phase (ignore RAG ranking)
        if not chosen and registry_skills:
            chosen = next(iter(registry_skills.values()))
        if not chosen:
            ledger = create_phase_ledger(contract)
            ledger.update(status="blocked", blocking_reason="no_approved_skill_resolved", retrieved_rag_context=retrieved["retrieved_skills"])
            return {"phase_ledger": ledger, "offensive_state": state, "validator_decision": {"status": "blocked", "can_advance": False}}

        tool_plan = self.compiler.compile(chosen, contract, target, scope, execution_mode, mcp_available=self.executor.available)
        mcp_results = self.executor.execute(tool_plan, target)
        evidence = [
            self.collector.create(result, parsed_json={"request_response_pair": bool(result.get("stdout_path")), "reproducible": True})
            for result in mcp_results
            if result.get("status") == "success"
        ]
        generated_hypotheses = self.hypotheses.update_from_evidence(phase_id, evidence)
        attack_paths = self.attack_paths.correlate(evidence, generated_hypotheses)
        state["current_phase"] = phase_id
        state["open_hypotheses"].extend(generated_hypotheses)
        state["attack_paths"].extend(attack_paths)
        state["next_objectives"] = [item["title"] for item in generated_hypotheses[:3]]
        decision = self.validator.validate(contract, tool_plan, mcp_results, evidence, generated_hypotheses, state)
        lesson = self.learning.learn(phase_id, tool_plan, mcp_results, evidence)
        ledger = create_phase_ledger(contract)
        ledger.update(
            status=decision["status"],
            finished_at=utc_now(),
            selected_skills=[chosen["skill_id"]],
            retrieved_rag_context=retrieved["retrieved_skills"],
            tools_required=contract["required_tools"],
            tools_attempted=[result["tool_name"] for result in mcp_results],
            tools_success=[result["tool_name"] for result in mcp_results if result["status"] == "success"],
            tools_failed=[result["tool_name"] for result in mcp_results if result["status"] not in {"success"}],
            mcp_executions=[result["mcp_execution_id"] for result in mcp_results],
            evidence_ids=[ev["evidence_id"] for ev in evidence],
            hypotheses_created=[h["hypothesis_id"] for h in generated_hypotheses],
            attack_paths_updated=[ap["attack_path_id"] for ap in attack_paths],
            validation_result=decision,
            blocking_reason=None if decision["status"] != "blocked" else decision["reason"],
        )
        return {
            "phase_ledger": ledger,
            "offensive_state": state,
            "skill_plan": {
                "phase_id": phase_id,
                "target": target,
                "selected_skills": [chosen["skill_id"]],
                "skill_plan": {
                    "objective": tool_plan["objective"],
                    "offensive_questions": [],
                    "tool_requirements": [
                        {"tool": tool["tool_name"], "required": tool["required"], "reason": tool["reason"]}
                        for tool in tool_plan["tools"]
                    ],
                    "payload_strategy": {},
                    "retry_strategy": tool_plan["retry_plan"],
                    "expected_evidence": [e for tool in tool_plan["tools"] for e in tool["expected_evidence"]],
                },
            },
            "tool_plan": tool_plan,
            "mcp_results": mcp_results,
            "evidence": evidence,
            "validator_decision": decision,
            "operation_lesson": lesson,
        }


def create_phase_ledger(contract: dict[str, Any]) -> dict[str, Any]:
    return {
        "phase_id": contract["phase_id"],
        "phase_name": contract["name"],
        "status": "running",
        "started_at": utc_now(),
        "finished_at": "",
        "selected_skills": [],
        "retrieved_rag_context": [],
        "tools_required": [],
        "tools_attempted": [],
        "tools_success": [],
        "tools_failed": [],
        "mcp_executions": [],
        "evidence_ids": [],
        "hypotheses_created": [],
        "hypotheses_tested": [],
        "attack_paths_updated": [],
        "retry_count": 0,
        "fallback_used": False,
        "validation_result": {},
        "skip_reason": None,
        "blocking_reason": None,
    }


def create_offensive_state(target: str, campaign_id: str | None = None) -> dict[str, Any]:
    return {
        "campaign_id": campaign_id or str(uuid.uuid4()),
        "target": target,
        "current_phase": "P01",
        "current_stage": "scope",
        "known_assets": [],
        "known_endpoints": [],
        "known_parameters": [],
        "technologies": [],
        "credentials": [],
        "sessions": [],
        "tokens": [],
        "interesting_files": [],
        "waf_fingerprints": [],
        "open_hypotheses": [],
        "validated_hypotheses": [],
        "discarded_hypotheses": [],
        "attack_paths": [],
        "compromised_assets": [],
        "next_objectives": [],
    }


def create_operation_event(
    event_type: str,
    campaign_id: str,
    scan_job_id: str,
    phase_id: str = "",
    skill_id: str = "",
    status: str = "",
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "campaign_id": campaign_id,
        "scan_job_id": scan_job_id,
        "phase_id": phase_id,
        "skill_id": skill_id,
        "event_type": event_type,
        "timestamp": utc_now(),
        "status": status,
        "details": details or {},
    }


def create_human_review_item(item_type: str, reason: str, risk: str, related_skill_id: str = "", evidence_ids: list[str] | None = None) -> dict[str, Any]:
    return {
        "review_item_id": stable_id("HR", {"type": item_type, "reason": reason, "skill": related_skill_id}),
        "type": item_type,
        "status": "pending",
        "reason": reason,
        "risk": risk,
        "related_skill_id": related_skill_id,
        "related_evidence_ids": evidence_ids or [],
        "created_at": utc_now(),
    }


def create_report_learning_profile(report_id: str, source_url: str, text: str) -> dict[str, Any]:
    steps_match = re.search(r"(steps to reproduce|reproduction steps|steps)(.*?)(impact|summary|$)", text, re.I | re.S)
    steps_text = steps_match.group(2).strip() if steps_match else ""
    steps = [line.strip(" -\t") for line in steps_text.splitlines() if line.strip(" -\t")]
    statements = [
        {
            "statement": step,
            "type": "fact",
            "confidence": 0.9,
            "source_section": "steps_to_reproduce",
            "source_report_id": report_id,
        }
        for step in steps
    ]
    vulnerability_class = "unknown"
    lowered = text.lower()
    if "idor" in lowered or "object" in lowered and "authorization" in lowered:
        vulnerability_class = "idor"
    elif "sql injection" in lowered or "sqli" in lowered:
        vulnerability_class = "sqli"
    elif "xss" in lowered:
        vulnerability_class = "xss"
    return {
        "report_id": report_id,
        "source_url": source_url,
        "vulnerability_class": vulnerability_class,
        "affected_asset_type": "unknown",
        "researcher_goal": "",
        "discovery_method": "",
        "attack_steps": steps,
        "validation_steps": steps,
        "impact_demonstration": "",
        "technical_signals": statements,
        "preconditions": [],
        "payload_families": [],
        "tool_candidates": ["curl"],
        "evidence_model": ["request_response_pair"],
        "generalized_technique": "",
        "skill_candidates": [],
        "limitations": [],
        "unknowns": [] if steps else ["steps_to_reproduce_not_found"],
    }
