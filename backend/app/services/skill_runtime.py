from __future__ import annotations

import os
import re
from datetime import datetime
from functools import lru_cache
from pathlib import Path
from typing import Any
from uuid import uuid4

from app.graph.mission import SKILL_CATALOG

# ---------------------------------------------------------------------------
# Skills markdown loader — loads structured skill objects from skills/*.md
# ---------------------------------------------------------------------------

_SKILLS_ROOT = Path(__file__).parent.parent.parent.parent / "skills"
_FRONTMATTER_RE = re.compile(r"^---\s*\n(.*?)\n---\s*\n", re.DOTALL)


def _parse_inline_list(raw_val: str) -> list[str] | None:
    """Parse YAML inline list syntax like ["P01", "P02"] or [naabu, nmap]."""
    stripped = raw_val.strip()
    if not (stripped.startswith("[") and stripped.endswith("]")):
        return None
    inner = stripped[1:-1].strip()
    if not inner:
        return []
    items = [item.strip().strip('"').strip("'") for item in inner.split(",")]
    return [item for item in items if item]


def _parse_yaml_frontmatter(text: str) -> dict[str, Any]:
    """Parse YAML frontmatter without requiring PyYAML (simple scalar/list parser)."""
    result: dict[str, Any] = {}
    lines = text.strip().splitlines()
    i = 0
    current_key: str | None = None
    list_indent: int | None = None

    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        # List item under current key
        if current_key and stripped.startswith("- ") and list_indent is not None:
            if isinstance(result[current_key], list):
                result[current_key].append(stripped[2:].strip().strip('"').strip("'"))
            i += 1
            continue

        # Key: value line
        if ":" in line and not stripped.startswith("-"):
            colon = line.index(":")
            key = line[:colon].strip()
            raw_val = line[colon + 1:].strip()
            list_indent = None

            if not raw_val:
                # Next lines may be list items
                result[key] = []
                current_key = key
                list_indent = len(line) - len(line.lstrip())
            elif raw_val.lower() in ("true", "yes"):
                result[key] = True
                current_key = None
            elif raw_val.lower() in ("false", "no"):
                result[key] = False
                current_key = None
            else:
                # Try inline list syntax ["a", "b"]
                inline = _parse_inline_list(raw_val)
                if inline is not None:
                    result[key] = inline
                    current_key = None
                else:
                    # Try int
                    try:
                        result[key] = int(raw_val)
                    except ValueError:
                        result[key] = raw_val.strip('"').strip("'")
                    current_key = None
        i += 1

    return result


def _load_skill_file(path: Path) -> dict[str, Any] | None:
    """Load a single skill .md file and return a structured skill dict."""
    try:
        content = path.read_text(encoding="utf-8")
    except OSError:
        return None

    m = _FRONTMATTER_RE.match(content)
    if not m:
        return None

    try:
        meta = _parse_yaml_frontmatter(m.group(1))
    except Exception:
        return None

    skill_id = str(meta.get("skill_id") or "").strip()
    if not skill_id:
        return None

    # Normalize phase_ids to list of strings
    phase_ids = meta.get("phase_ids")
    if isinstance(phase_ids, str):
        phase_ids = [phase_ids]
    elif not isinstance(phase_ids, list):
        phase_ids = []

    required_tools = meta.get("required_tools")
    if isinstance(required_tools, str):
        required_tools = [required_tools]
    elif not isinstance(required_tools, list):
        required_tools = []

    optional_tools = meta.get("optional_tools")
    if isinstance(optional_tools, str):
        optional_tools = [optional_tools]
    elif not isinstance(optional_tools, list):
        optional_tools = []

    fallback_tools = meta.get("fallback_tools")
    if isinstance(fallback_tools, str):
        fallback_tools = [fallback_tools]
    elif not isinstance(fallback_tools, list):
        fallback_tools = []

    evidence_required = meta.get("evidence_required")
    if isinstance(evidence_required, str):
        evidence_required = [evidence_required]
    elif not isinstance(evidence_required, list):
        evidence_required = []

    attack_chain_opportunities = meta.get("attack_chain_opportunities")
    if isinstance(attack_chain_opportunities, str):
        attack_chain_opportunities = [attack_chain_opportunities]
    elif not isinstance(attack_chain_opportunities, list):
        attack_chain_opportunities = []

    exit_criteria = meta.get("exit_criteria") or {}
    if not isinstance(exit_criteria, dict):
        exit_criteria = {}

    retry_policy = meta.get("retry_policy") or {}
    if not isinstance(retry_policy, dict):
        retry_policy = {}

    return {
        "skill_id": skill_id,
        "name": str(meta.get("name") or skill_id),
        "version": str(meta.get("version") or "1.0.0"),
        "category": str(meta.get("category") or ""),
        "phase_ids": phase_ids,
        "supported_target_types": meta.get("supported_target_types") if isinstance(meta.get("supported_target_types"), list) else [],
        "risk_level": str(meta.get("risk_level") or "medium"),
        "noise_level": str(meta.get("noise_level") or "medium"),
        "requires_authorization": bool(meta.get("requires_authorization", True)),
        "required_tools": required_tools,
        "optional_tools": optional_tools,
        "fallback_tools": fallback_tools,
        "evidence_required": evidence_required,
        "exit_criteria": exit_criteria,
        "retry_policy": retry_policy,
        "attack_chain_opportunities": attack_chain_opportunities,
        "source_file": str(path),
        # Legacy compat fields
        "id": skill_id,
        "playbook": required_tools + optional_tools,
        "phases": phase_ids,
        "description": str(meta.get("name") or skill_id),
        "triggers": attack_chain_opportunities,
    }


@lru_cache(maxsize=1)
def load_all_md_skills() -> dict[str, dict[str, Any]]:
    """Scan skills/ directory and return all skills keyed by skill_id."""
    result: dict[str, dict[str, Any]] = {}
    if not _SKILLS_ROOT.is_dir():
        return result
    for md_file in sorted(_SKILLS_ROOT.rglob("*.md")):
        skill = _load_skill_file(md_file)
        if skill:
            result[skill["skill_id"]] = skill
    return result


def resolve_skill_for_phase(phase_id: str) -> list[dict[str, Any]]:
    """Return all .md skills that declare the given phase_id (e.g. 'P01')."""
    skills = load_all_md_skills()
    return [
        skill for skill in skills.values()
        if phase_id.upper() in [p.upper() for p in skill.get("phase_ids") or []]
    ]


def get_skill_by_id(skill_id: str) -> dict[str, Any] | None:
    """Look up a skill by its skill_id from the .md library."""
    return load_all_md_skills().get(skill_id)


PHASE_ALIASES_BY_GROUP: dict[str, list[str]] = {
    "asset_discovery": ["P01", "P02", "P03", "P04", "P05", "P06", "P15", "P18"],
    "recon": ["P01", "P02", "P03", "P04", "P05", "P06", "P15", "P18"],
    "reconnaissance": ["P01", "P02", "P03", "P04", "P05", "P06", "P15", "P18"],
    "threat_intel": ["P07", "P08", "P09", "P10", "P11", "P21", "P22"],
    "weaponization": ["P07", "P08", "P09", "P10", "P11", "P21", "P22"],
    "adversarial_hypothesis": ["P04", "P11", "P12", "P13", "P14", "P15", "P16", "P19"],
    "risk_assessment": ["P11", "P12", "P13", "P14", "P15", "P16", "P19", "P20", "P22"],
    "vuln": ["P11", "P12", "P13", "P14", "P15", "P16", "P19", "P20", "P22"],
    "exploitation": ["P11", "P12", "P13", "P14", "P15", "P16", "P19", "P20", "P22"],
    "evidence_adjudication": ["P11", "P12", "P13", "P14", "P16", "P19", "P22"],
    "governance": ["P06", "P18", "P22"],
}

GROUP_CATEGORY_HINTS: dict[str, set[str]] = {
    "asset_discovery": {"reconnaissance", "technologies", "protocols"},
    "recon": {"reconnaissance", "technologies", "protocols"},
    "reconnaissance": {"reconnaissance", "technologies", "protocols"},
    "threat_intel": {"osint", "code", "vulnerabilities"},
    "weaponization": {"osint", "code", "vulnerabilities"},
    "adversarial_hypothesis": {"vulnerabilities", "tooling"},
    "risk_assessment": {"vulnerabilities", "protocols", "technologies"},
    "vuln": {"vulnerabilities", "protocols", "technologies"},
    "exploitation": {"vulnerabilities", "protocols", "technologies"},
    "evidence_adjudication": {"vulnerabilities", "tooling", "code"},
    "governance": {"protocols", "tooling", "orchestration"},
}

SEMANTIC_SKILL_ALIASES: dict[str, set[str]] = {
    "sqli": {"vuln-injection"},
    "sql injection": {"vuln-injection"},
    "injection_battery": {"vuln-injection"},
    "injection battery": {"vuln-injection"},
    "xss": {"vuln-injection"},
    "ssti": {"vuln-injection"},
    "xxe": {"vuln-injection"},
    "idor": {"vuln-idor-access-control"},
    "bola": {"vuln-idor-access-control"},
    "access control": {"vuln-idor-access-control"},
    "api": {"vuln-api-graphql"},
    "graphql": {"vuln-api-graphql"},
    "auth": {"vuln-auth-bypass"},
    "jwt": {"vuln-auth-bypass", "weak-cryptography"},
    "weak crypto": {"weak-cryptography"},
    "cryptography": {"weak-cryptography"},
    "information disclosure": {"vuln-information-disclosure"},
    "info disclosure": {"vuln-information-disclosure"},
    "score board": {"vuln-information-disclosure"},
    "hidden route": {"recon-web-crawl", "vuln-information-disclosure"},
    "path disclosure": {"vuln-information-disclosure"},
    # Worker-group → skill_id mappings — accepted learnings often label
    # `affected_skills` with the worker group name instead of the catalog id.
    # Without these aliases the scorer never credits learning-skill overlap.
    "asset_discovery": {"recon-subdomain-enum", "recon-web-crawl", "recon-port-service"},
    "reconnaissance": {"recon-subdomain-enum", "recon-web-crawl", "recon-port-service"},
    "recon": {"recon-subdomain-enum", "recon-web-crawl", "recon-port-service"},
    "threat_intel": {"osint-exposure-intel", "osint-email-infra", "osint-subdomain-takeover", "osint-cloud-exposure"},
    "weaponization": {"vuln-nuclei-cve", "vuln-injection"},
    "risk_assessment": {
        "vuln-injection", "vuln-ssrf-redirect", "vuln-auth-bypass", "vuln-directory-enum",
        "vuln-idor-access-control", "vuln-api-graphql", "vuln-nuclei-cve", "vuln-ssl-tls",
        "vuln-information-disclosure",
    },
    "exploitation": {"vuln-injection", "vuln-auth-bypass", "vuln-ssrf-redirect", "vuln-idor-access-control"},
    "actions_on_objectives": {"vuln-injection", "vuln-auth-bypass", "weak-cryptography"},
    "command_and_control": {"vuln-auth-bypass"},
    "tool_usage": set(),  # generic; no specific skill alias
}

# Direct map worker_group → SKILL_CATALOG ids. Used as a hard bridge when
# an accepted learning references a worker group instead of a catalog skill.
WORKER_GROUP_TO_SKILL_IDS: dict[str, set[str]] = {
    "asset_discovery": {"recon-subdomain-enum", "recon-web-crawl", "recon-port-service"},
    "threat_intel": {"osint-exposure-intel", "osint-email-infra", "osint-subdomain-takeover", "osint-cloud-exposure"},
    "risk_assessment": {
        "vuln-injection", "vuln-ssrf-redirect", "vuln-auth-bypass", "vuln-directory-enum",
        "vuln-idor-access-control", "vuln-api-graphql", "vuln-nuclei-cve", "vuln-ssl-tls",
        "vuln-information-disclosure", "weak-cryptography",
    },
    "exploitation": {"vuln-injection", "vuln-auth-bypass", "vuln-ssrf-redirect", "vuln-idor-access-control"},
    "evidence_adjudication": {"evidence-proof-pack"},
    "governance": {"supervisor-guardrails"},
}

# Tech-stack tag → skill_ids that should be boosted when the tag is detected.
TECH_STACK_SKILL_BOOST: dict[str, set[str]] = {
    "asp.net":     {"vuln-injection", "tech-http-fingerprint", "vuln-auth-bypass"},
    "iis":         {"vuln-injection", "tech-http-fingerprint", "tech-owasp-header-analysis"},
    "mssql":       {"vuln-injection"},
    "php":         {"vuln-injection", "vuln-information-disclosure"},
    "mysql":       {"vuln-injection"},
    "mariadb":     {"vuln-injection"},
    "postgresql":  {"vuln-injection"},
    "oracle":      {"vuln-injection"},
    "wordpress":   {"tech-cms-fingerprint", "vuln-injection"},
    "joomla":      {"tech-cms-fingerprint"},
    "drupal":      {"tech-cms-fingerprint"},
    "node.js":     {"vuln-injection", "vuln-api-graphql"},
    "express":     {"vuln-injection", "vuln-api-graphql"},
    "django":      {"vuln-injection"},
    "flask":       {"vuln-injection"},
    "java":        {"vuln-injection", "vuln-auth-bypass"},
    "spring":      {"vuln-injection"},
    "tomcat":      {"vuln-injection", "tech-http-fingerprint"},
    "cloudflare":  {"waf-aware-validation"},
    "akamai":      {"waf-aware-validation"},
    "imperva":     {"waf-aware-validation"},
    "sucuri":      {"waf-aware-validation"},
    "kubernetes":  {"osint-cloud-exposure"},
    "aws":         {"osint-cloud-exposure"},
    "azure":       {"osint-cloud-exposure"},
    "gcp":         {"osint-cloud-exposure"},
}


def _clean_text(value: Any) -> str:
    return " ".join(str(value or "").strip().split())


def _clean_list(value: Any, limit: int = 80) -> list[str]:
    if isinstance(value, str):
        raw = [value]
    elif isinstance(value, (list, tuple, set)):
        raw = [str(item) for item in value if str(item or "").strip()]
    else:
        raw = []
    return list(dict.fromkeys(_clean_text(item) for item in raw if _clean_text(item)))[:limit]


def _lower_set(items: Any) -> set[str]:
    return {item.lower() for item in _clean_list(items)}


def _phase_tokens(worker_group: str, phase: str | None) -> set[str]:
    tokens: set[str] = set()
    phase_text = _clean_text(phase).lower()
    if phase_text:
        tokens.add(phase_text)
        if phase_text.startswith("p") and phase_text[1:].isdigit():
            tokens.add(phase_text.upper().lower())
    group_key = _clean_text(worker_group).lower()
    tokens.update(item.lower() for item in PHASE_ALIASES_BY_GROUP.get(group_key, []))
    return tokens


def _skill_pool(active_skills: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    by_id: dict[str, dict[str, Any]] = {
        str(skill.get("id") or ""): dict(skill)
        for skill in SKILL_CATALOG
        if str(skill.get("id") or "").strip()
    }
    for active in active_skills or []:
        skill_id = str(active.get("id") or "").strip()
        if not skill_id:
            continue
        if skill_id in by_id:
            merged = dict(by_id[skill_id])
            merged.update({k: v for k, v in dict(active).items() if v not in (None, "", [])})
            by_id[skill_id] = merged
        else:
            by_id[skill_id] = {
                "id": skill_id,
                "category": active.get("category") or "custom",
                "description": active.get("description") or "",
                "triggers": _clean_list(active.get("triggers")),
                "playbook": _clean_list(active.get("playbook")),
                "phases": _clean_list(active.get("phases")),
            }
    return list(by_id.values())


def _extract_learning(playbook: dict[str, Any] | None) -> dict[str, Any]:
    playbook = dict(playbook or {})
    techniques = [dict(item) for item in list(playbook.get("techniques") or []) if isinstance(item, dict)]
    tools: list[str] = []
    skills: list[str] = []
    phases: list[str] = []
    signals: list[str] = []
    tools.extend(_clean_list(playbook.get("recommended_tools")))
    skills.extend(_clean_list(playbook.get("affected_skills")))
    phases.extend(_clean_list(playbook.get("affected_phases")))
    signals.extend(_clean_list(playbook.get("evidence_signals")))
    for source in list(playbook.get("sources") or []):
        if not isinstance(source, dict):
            continue
        tools.extend(_clean_list(source.get("recommended_tools")))
        skills.extend(_clean_list(source.get("affected_skills")))
        phases.extend(_clean_list(source.get("affected_phases")))
    for technique in techniques:
        tools.extend(_clean_list(technique.get("recommended_kali_tools") or technique.get("tools")))
        skills.extend(_clean_list(technique.get("affected_skills") or technique.get("skills")))
        phases.extend(_clean_list(technique.get("affected_phases") or technique.get("phases")))
        signals.extend(_clean_list(technique.get("evidence_signals") or technique.get("signals")))
    return {
        "tools": list(dict.fromkeys(tools)),
        "skills": list(dict.fromkeys(skills)),
        "phases": list(dict.fromkeys(phases)),
        "signals": list(dict.fromkeys(signals)),
        "techniques": techniques,
    }


def _skill_matches_learning(skill: dict[str, Any], learning_skill: str) -> bool:
    skill_id = str(skill.get("id") or "").lower()
    if not skill_id:
        return False
    needle = _clean_text(learning_skill).lower()
    if not needle:
        return False
    if needle == skill_id or needle in skill_id or skill_id in needle:
        return True
    aliases = SEMANTIC_SKILL_ALIASES.get(needle, set())
    if skill_id in aliases:
        return True
    haystack = " ".join(
        [
            skill_id,
            str(skill.get("category") or ""),
            str(skill.get("description") or ""),
            " ".join(_clean_list(skill.get("triggers"))),
        ]
    ).lower()
    return needle in haystack


def _ordered_intersection(preferred: list[str], candidates: list[str]) -> list[str]:
    candidate_by_lower = {str(tool).lower(): str(tool) for tool in candidates if str(tool or "").strip()}
    out: list[str] = []
    seen: set[str] = set()
    for tool in preferred:
        key = str(tool).strip().lower()
        if not key or key not in candidate_by_lower or key in seen:
            continue
        seen.add(key)
        out.append(candidate_by_lower[key])
    return out


def _score_skill(
    *,
    skill: dict[str, Any],
    worker_group: str,
    phase_tokens: set[str],
    candidate_tools: list[str],
    active_ids: set[str],
    learning: dict[str, Any],
    target: str,
    tech_stack: list[str] | None = None,
) -> tuple[int, list[str]]:
    skill_id = str(skill.get("id") or "").strip()
    skill_tools = _lower_set(skill.get("playbook"))
    skill_phases = _lower_set(skill.get("phases"))
    candidate_set = _lower_set(candidate_tools)
    learning_tools = _lower_set(learning.get("tools"))
    learning_phases = _lower_set(learning.get("phases"))
    category = str(skill.get("category") or "").lower()
    group_key = _clean_text(worker_group).lower()
    tech_stack = [str(item).strip().lower() for item in (tech_stack or []) if str(item).strip()]

    score = 0
    matched_by: list[str] = []

    # ── Tech-stack boost (strongest single signal when env is detected) ──
    if tech_stack:
        boosted_skills: set[str] = set()
        matched_tags: list[str] = []
        for tag in tech_stack:
            for sid in TECH_STACK_SKILL_BOOST.get(tag, set()):
                if sid == skill_id:
                    boosted_skills.add(sid)
                    matched_tags.append(tag)
        if boosted_skills:
            score += min(40, 12 * len(matched_tags))
            matched_by.append("tech_stack:" + ",".join(matched_tags[:4]))

    # Worker_group → skill_id hard bridge for accepted-learning content that
    # labels affected_skills with the worker group name.
    if skill_id in WORKER_GROUP_TO_SKILL_IDS.get(group_key, set()):
        score += 6
        matched_by.append("worker_group_bridge:" + group_key)

    if skill_id in active_ids:
        score += 4
        matched_by.append("active_skill")

    tool_overlap = sorted(skill_tools & candidate_set)
    if tool_overlap:
        score += min(21, 7 * len(tool_overlap))
        matched_by.append("candidate_tools:" + ",".join(tool_overlap[:6]))

    learning_tool_overlap = sorted(skill_tools & learning_tools)
    if learning_tool_overlap:
        score += min(20, 5 * len(learning_tool_overlap))
        matched_by.append("learning_tools:" + ",".join(learning_tool_overlap[:6]))

    phase_overlap = sorted(skill_phases & phase_tokens)
    if phase_overlap:
        score += min(12, 4 * len(phase_overlap))
        matched_by.append("phase:" + ",".join(phase_overlap[:6]))

    learning_phase_overlap = sorted(skill_phases & learning_phases)
    if learning_phase_overlap:
        score += min(8, 3 * len(learning_phase_overlap))
        matched_by.append("learning_phase:" + ",".join(learning_phase_overlap[:6]))

    learning_skill_matches = [
        item for item in _clean_list(learning.get("skills"))
        if _skill_matches_learning(skill, item)
    ]
    if learning_skill_matches:
        score += min(72, 48 * len(learning_skill_matches))
        matched_by.append("learning_skill:" + ",".join(learning_skill_matches[:4]))

    category_hints = GROUP_CATEGORY_HINTS.get(group_key, set())
    if category in category_hints:
        score += 18
        matched_by.append("group_category:" + category)
    elif category_hints:
        score -= 8

    target_text = _clean_text(target).lower()
    if target_text.startswith(("http://", "https://")) and skill_id in {
        "recon-web-crawl",
        "tech-http-fingerprint",
        "tech-owasp-header-analysis",
        "vuln-information-disclosure",
        "vuln-injection",
    }:
        score += 2
        matched_by.append("web_target")

    if not skill_tools and not skill_phases and not learning_skill_matches:
        score -= 6

    return score, matched_by


def _relevant_techniques(
    selected_skill: dict[str, Any],
    learning: dict[str, Any],
    candidate_tools: list[str],
    phase_tokens: set[str],
) -> list[dict[str, Any]]:
    skill_tools = _lower_set(selected_skill.get("playbook"))
    candidate_set = _lower_set(candidate_tools)
    selected_id = str(selected_skill.get("id") or "")
    relevant: list[dict[str, Any]] = []
    for technique in list(learning.get("techniques") or []):
        technique_tools = _lower_set(technique.get("recommended_kali_tools") or technique.get("tools"))
        technique_phases = _lower_set(technique.get("affected_phases") or technique.get("phases"))
        technique_skills = _clean_list(technique.get("affected_skills") or technique.get("skills"))
        skill_match = any(_skill_matches_learning(selected_skill, item) for item in technique_skills)
        tool_match = bool(technique_tools & (skill_tools | candidate_set))
        phase_match = bool(technique_phases & phase_tokens)
        if skill_match or tool_match or phase_match:
            item = dict(technique)
            item.setdefault("matched_skill", selected_id)
            relevant.append(item)
    return relevant[:8]


def _worker_rule_context(worker_group: str, phase: str | None, candidate_tools: list[str]) -> dict[str, Any]:
    try:
        from app.workers.worker_groups import get_sub_agent_rules, get_worker_rules

        rules = get_worker_rules(worker_group)
        sub_agents = get_sub_agent_rules(worker_group, phase=phase, tools=candidate_tools)
    except Exception:
        return {
            "worker_group": worker_group,
            "global": {},
            "rules": [],
            "sub_agents": [],
            "selected_sub_agents": [],
            "mcp_required": True,
            "reanalysis_required": False,
        }

    global_rules = dict(rules.get("global") or {})
    return {
        "worker_group": rules.get("worker_group") or worker_group,
        "global": global_rules,
        "rules": list(rules.get("rules") or []),
        "sub_agents": list(rules.get("sub_agents") or []),
        "selected_sub_agents": sub_agents,
        "mcp_required": True,
        "reanalysis_required": bool(sub_agents) or str(worker_group or "").lower() in {"asset_discovery", "recon", "reconnaissance"},
        "reanalysis_triggers": list(global_rules.get("reanalysis_triggers") or []),
    }


def resolve_skill_invocation(
    *,
    worker_group: str,
    phase: str | None,
    target: str,
    candidate_tools: list[str] | None,
    active_skills: list[dict[str, Any]] | None,
    playbook: dict[str, Any] | None = None,
    tech_stack: list[str] | None = None,
) -> dict[str, Any]:
    """Select and record the operational skill that must guide tool choice.

    This is intentionally deterministic. LLM output may be partial or absent,
    but a worker still needs an explicit skill contract before dispatching
    Kali/MCP tools.
    """
    tools = _clean_list(candidate_tools)
    active = list(active_skills or [])
    active_ids = {str(item.get("id") or "") for item in active if str(item.get("id") or "").strip()}
    learning = _extract_learning(playbook)
    phase_scope = _phase_tokens(worker_group, phase)
    worker_rules = _worker_rule_context(worker_group, phase, tools)

    scored: list[tuple[int, int, dict[str, Any], list[str]]] = []
    catalog_order = {str(skill.get("id") or ""): idx for idx, skill in enumerate(SKILL_CATALOG)}
    for skill in _skill_pool(active):
        score, matched_by = _score_skill(
            skill=skill,
            worker_group=worker_group,
            phase_tokens=phase_scope,
            candidate_tools=tools,
            active_ids=active_ids,
            learning=learning,
            target=target,
            tech_stack=tech_stack,
        )
        if matched_by or score > 0:
            scored.append((score, catalog_order.get(str(skill.get("id") or ""), 10_000), skill, matched_by))

    if not scored and active:
        fallback_skill = dict(active[0])
        scored.append((1, 10_000, fallback_skill, ["fallback_active_skill"]))

    if not scored:
        return {
            "called": False,
            "reason": "no_skill_candidates",
            "worker_group": worker_group,
            "phase": phase,
            "candidate_tools": tools,
            "recommended_tools": [],
            "techniques": [],
            "worker_rules": worker_rules,
            "sub_agent_plan": [],
            "confidence": 0.0,
        }

    scored.sort(key=lambda item: (-item[0], item[1], str(item[2].get("id") or "")))
    score, _, selected_skill, matched_by = scored[0]
    selected_id = str(selected_skill.get("id") or worker_group)
    techniques = _relevant_techniques(selected_skill, learning, tools, phase_scope)

    # Enrich with .md skill data when available for the current phase
    md_skills = resolve_skill_for_phase(phase or "")
    md_skill: dict[str, Any] | None = None
    if md_skills:
        # Prefer the .md skill whose required_tools overlap most with candidate_tools
        candidate_set_lower = {t.lower() for t in tools}
        best_overlap = -1
        for ms in md_skills:
            overlap = len({t.lower() for t in ms.get("required_tools") or []} & candidate_set_lower)
            if overlap > best_overlap:
                best_overlap = overlap
                md_skill = ms
    if md_skill is None and md_skills:
        md_skill = md_skills[0]

    learned_preferred: list[str] = []
    for technique in techniques:
        learned_preferred.extend(_clean_list(technique.get("recommended_kali_tools") or technique.get("tools")))
    learned_preferred.extend(_clean_list(learning.get("tools")))

    # If .md skill found, its required_tools take priority in recommendations
    if md_skill:
        md_required = _clean_list(md_skill.get("required_tools"))
        md_optional = _clean_list(md_skill.get("optional_tools"))
        learned_preferred = md_required + md_optional + learned_preferred

    preferred_source = list(dict.fromkeys(learned_preferred))
    if not preferred_source:
        preferred_source = _clean_list(selected_skill.get("playbook"))
    recommended = _ordered_intersection(preferred_source, tools)

    confidence = round(max(0.35, min(0.98, score / 45.0)), 2)
    result: dict[str, Any] = {
        "called": True,
        "invocation_id": f"skill-{uuid4().hex[:12]}",
        "skill_id": selected_id,
        "skill": dict(selected_skill),
        "worker_group": worker_group,
        "phase": phase,
        "target": target,
        "candidate_tools": tools,
        "recommended_tools": recommended,
        "learned_recommended_tools": list(dict.fromkeys(learned_preferred))[:20],
        "techniques": techniques,
        "worker_rules": worker_rules,
        "sub_agent_plan": list(worker_rules.get("selected_sub_agents") or []),
        "matched_by": matched_by,
        "score": score,
        "confidence": confidence,
        "source": "accepted_learning+skill_catalog" if learning.get("techniques") else "skill_catalog",
        "playbook_title": (playbook or {}).get("title"),
        "created_at": datetime.utcnow().isoformat(),
    }

    # Attach structured .md skill contract when found
    if md_skill:
        result["md_skill"] = md_skill
        result["md_skill_id"] = md_skill["skill_id"]
        result["evidence_required"] = md_skill.get("evidence_required") or []
        result["exit_criteria"] = md_skill.get("exit_criteria") or {}
        result["retry_policy"] = md_skill.get("retry_policy") or {}
        result["attack_chain_opportunities"] = md_skill.get("attack_chain_opportunities") or []
        result["risk_level"] = md_skill.get("risk_level") or "medium"
        result["noise_level"] = md_skill.get("noise_level") or "medium"
        result["source"] = "md_skill_library+skill_catalog"

    return result


def build_skill_guided_fallback_decision(
    *,
    skill_invocation: dict[str, Any],
    execution_context: dict[str, Any],
    candidate_tools: list[str],
    playbook: dict[str, Any] | None,
    reason: str,
) -> dict[str, Any] | None:
    if not skill_invocation.get("called"):
        return None

    preferred = [
        tool for tool in _clean_list(skill_invocation.get("recommended_tools"))
        if tool in set(candidate_tools)
    ]
    techniques = list(skill_invocation.get("techniques") or [])
    if not techniques:
        techniques = [item for item in list((playbook or {}).get("techniques") or []) if isinstance(item, dict)]

    selected = dict(techniques[0]) if techniques else {
        "name": f"{skill_invocation.get('skill_id')} guided validation",
        "objective": "Executar a skill selecionada com ferramentas autorizadas e evidencias reproduziveis.",
        "recommended_kali_tools": preferred or candidate_tools[:1],
        "evidence_signals": list((playbook or {}).get("evidence_signals") or [])[:8],
    }
    if not preferred:
        preferred = _ordered_intersection(
            _clean_list(selected.get("recommended_kali_tools") or selected.get("tools")),
            candidate_tools,
        )
    if not preferred and candidate_tools:
        preferred = [candidate_tools[0]]

    return {
        "execution_decision": "proceed",
        "decision_source": "skill_runtime_fallback",
        "fallback_reason": _clean_text(reason)[:300],
        "selected_technique": selected,
        "execution_context": dict(execution_context),
        "worker_rules": dict(skill_invocation.get("worker_rules") or {}),
        "sub_agent_plan": list(skill_invocation.get("sub_agent_plan") or []),
        "signals_to_validate": _clean_list(selected.get("evidence_signals") or (playbook or {}).get("evidence_signals"))[:8],
        "confidence": max(float(skill_invocation.get("confidence") or 0.55), 0.55),
        "preferred_tools": preferred,
        "memory_context": {
            "recommended_tools": preferred,
            "knowledge_items": [],
            "skill_invocation": {
                "skill_id": skill_invocation.get("skill_id"),
                "matched_by": list(skill_invocation.get("matched_by") or []),
                "source": skill_invocation.get("source"),
            },
        },
        "playbook_title": (playbook or {}).get("title") or skill_invocation.get("playbook_title"),
    }
