"""Offensive Reasoning Engine.

Transforms findings into attacker-perspective observations.
Drives the platform to behave as an iterative attacker, not a scanner.

For every finding, asks:
  - What does this allow me to access?
  - Does this allow pivot, privesc, lateral movement, credential harvest, bypass, chaining?
  - Does this reduce unknown surface or increase offensive capability?

Outputs:
  - offensive_observations: what each finding means offensively
  - new_hypotheses: attack hypotheses to pursue
  - attack_path_fragments: pieces of emerging attack paths
  - phase_promotions: phases that should be executed earlier
  - noise_profile_adjustment: stealth/aggressive decision
  - post_exploitation_tasks: what to do after successful exploitation
"""
from __future__ import annotations

import logging
import re
from datetime import datetime
from typing import Any
from uuid import uuid4

from app.graph.offensive_state import (
    OFFENSIVE_QUESTIONS,
    OFFENSIVE_STAGES,
    PHASE_PROMOTION_RULES,
    advance_offensive_stage,
    get_next_offensive_stage,
    select_noise_profile,
)

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Signal extractors — deterministic pattern matching on finding details
# ─────────────────────────────────────────────────────────────────────────────

def _text_of(finding: dict[str, Any]) -> str:
    """Flatten a finding to a searchable lowercase text blob."""
    parts = [
        str(finding.get("title") or ""),
        str(finding.get("severity") or ""),
        str(finding.get("details") or ""),
    ]
    details = finding.get("details") if isinstance(finding.get("details"), dict) else {}
    for key in ("evidence", "tool", "description", "path", "endpoint", "url", "cve",
                "parameter", "payload", "response", "matched_at"):
        parts.append(str(details.get(key) or ""))
    return " ".join(parts).lower()


def _contains_any(text: str, keywords: list[str]) -> bool:
    return any(kw in text for kw in keywords)


# ── Signal detectors (each returns bool) ─────────────────────────────────────

def _signal_credentials_found(text: str) -> bool:
    return _contains_any(text, [
        "credential", "password", "passwd", "secret", "api_key", "api key",
        "token", "private_key", "private key", "auth_token", ".env",
        "id_rsa", "id_dsa", "htpasswd", "aws_access", "aws_secret",
        "db_pass", "database_password", "bearer", "basic auth",
    ])


def _signal_git_exposed(text: str) -> bool:
    return _contains_any(text, [
        ".git/", "/.git", "git repository", "exposed git", "git config",
        "git_head", ".git/config", ".git/HEAD",
    ])


def _signal_ssrf(text: str) -> bool:
    return _contains_any(text, [
        "ssrf", "server-side request forgery", "open redirect", "url redirection",
        "interactsh", "oob interaction", "dns rebinding", "169.254.169.254",
        "metadata.google.internal", "metadata endpoint",
    ])


def _signal_jwt(text: str) -> bool:
    return _contains_any(text, [
        "jwt", "json web token", "eyj", "none algorithm", "alg:none",
        "weak signing", "hs256", "rs256", "jwt_tool", "token forgery",
    ])


def _signal_api_endpoints(text: str) -> bool:
    return _contains_any(text, [
        "/api/", "/rest/", "/v1/", "/v2/", "/graphql", "swagger",
        "openapi", "api endpoint", "rest endpoint", "json api",
        "rate limit", "rate limiting", "/api/v", ".json endpoint",
    ])


def _signal_admin_panel(text: str) -> bool:
    return _contains_any(text, [
        "admin panel", "admin login", "/admin", "/administrator", "/wp-admin",
        "/phpmyadmin", "/cpanel", "/plesk", "/manager", "management console",
        "dashboard login", "/console", "/control", "/portal",
    ])


def _signal_upload_endpoint(text: str) -> bool:
    return _contains_any(text, [
        "upload", "file upload", "multipart", "attach", "webshell",
        "unrestricted upload", "bypass upload", "mime type bypass",
    ])


def _signal_cms_detected(text: str) -> bool:
    return _contains_any(text, [
        "wordpress", "joomla", "drupal", "wpscan", "wp-content",
        "wp-login", "joomla administrator", "drupal admin",
    ])


def _signal_subdomain_takeover(text: str) -> bool:
    return _contains_any(text, [
        "takeover", "cname", "dangling", "subdomain takeover", "subjack",
        "azure websites", "github pages", "heroku", "s3 bucket", "cloudfront",
    ])


def _signal_sql_injection(text: str) -> bool:
    return _contains_any(text, [
        "sql injection", "sqli", "sqlmap", "union select", "or 1=1",
        "sql error", "syntax error in sql", "mysql error", "postgres error",
        "ora-", "microsoft sql", "parameter injection",
    ])


def _signal_xss(text: str) -> bool:
    return _contains_any(text, [
        "xss", "cross-site scripting", "reflected xss", "stored xss",
        "dom xss", "<script", "dalfox", "alert(", "document.cookie",
        "javascript:", "onerror=",
    ])


def _signal_rce(text: str) -> bool:
    return _contains_any(text, [
        "rce", "remote code execution", "command injection", "os command",
        "shell injection", "code injection", "eval injection", "deserialization",
        "log4j", "log4shell", "spring4shell", "cve-2021", "cve-2022",
        "arbitrary command", "exec(", "system(", "; cat /etc/passwd",
    ])


def _signal_idor(text: str) -> bool:
    return _contains_any(text, [
        "idor", "bola", "insecure direct object", "access control",
        "unauthorized access", "object reference", "user_id", "account_id",
        "privilege", "horizontal escalation", "vertical escalation",
    ])


def _signal_open_port_service(text: str) -> bool:
    return _contains_any(text, [
        "open port", "service banner", "banner grab", "smb", "rdp", "ssh",
        "ftp", "telnet", "mysql", "mssql", "redis", "elasticsearch",
        "mongodb", "cassandra", "memcached", "amqp", "rabbitmq",
    ])


def _signal_cloud_exposure(text: str) -> bool:
    return _contains_any(text, [
        "s3 bucket", "gcp bucket", "azure blob", "cloud storage",
        "public bucket", "aws", "google cloud", "azure", "iam",
        "metadata api", "instance metadata", "ecs metadata",
    ])


def _signal_weak_crypto(text: str) -> bool:
    return _contains_any(text, [
        "md5", "sha1", "weak cipher", "rc4", "des ", "3des",
        "ssl 2", "ssl 3", "tls 1.0", "tls 1.1", "sslv2", "sslv3",
        "self-signed", "expired certificate", "weak key", "rsa 512",
    ])


# Signal map: signal_id → (detector_fn, offensive_questions_triggered, objective_id, stage_elevation)
SIGNAL_MAP: list[dict[str, Any]] = [
    {
        "id": "credentials_found",
        "detector": _signal_credentials_found,
        "questions": ["enables_credential_harvest", "enables_bypass", "enables_chaining"],
        "objective": "credential_harvesting",
        "stage_elevation": "credential_access",
        "impact": "critical",
    },
    {
        "id": "git_exposed",
        "detector": _signal_git_exposed,
        "questions": ["enables_credential_harvest", "enables_enum", "enables_chaining"],
        "objective": "credential_harvesting",
        "stage_elevation": "credential_access",
        "impact": "high",
    },
    {
        "id": "ssrf_found",
        "detector": _signal_ssrf,
        "questions": ["enables_pivot", "enables_access", "enables_chaining", "enables_enum"],
        "objective": "trust_breaking",
        "stage_elevation": "internal_discovery",
        "impact": "high",
    },
    {
        "id": "jwt_found",
        "detector": _signal_jwt,
        "questions": ["enables_bypass", "enables_credential_harvest", "enables_chaining"],
        "objective": "session_exploitation",
        "stage_elevation": "session_abuse",
        "impact": "high",
    },
    {
        "id": "api_endpoints_found",
        "detector": _signal_api_endpoints,
        "questions": ["enables_enum", "enables_access", "enables_chaining", "reduces_unknown"],
        "objective": "surface_expansion",
        "stage_elevation": "surface_expansion",
        "impact": "medium",
    },
    {
        "id": "admin_panel_found",
        "detector": _signal_admin_panel,
        "questions": ["enables_access", "enables_bypass", "enables_privesc", "enables_chaining"],
        "objective": "credential_harvesting",
        "stage_elevation": "session_abuse",
        "impact": "high",
    },
    {
        "id": "upload_endpoint_found",
        "detector": _signal_upload_endpoint,
        "questions": ["enables_access", "enables_chaining", "increases_offensive_capability"],
        "objective": "remote_execution",
        "stage_elevation": "privilege_escalation",
        "impact": "critical",
    },
    {
        "id": "cms_detected",
        "detector": _signal_cms_detected,
        "questions": ["enables_enum", "enables_access", "reduces_unknown"],
        "objective": "surface_expansion",
        "stage_elevation": "surface_expansion",
        "impact": "medium",
    },
    {
        "id": "subdomain_takeover_candidate",
        "detector": _signal_subdomain_takeover,
        "questions": ["enables_access", "enables_chaining", "enables_pivot"],
        "objective": "trust_breaking",
        "stage_elevation": "lateral_movement",
        "impact": "critical",
    },
    {
        "id": "sql_injection_parameter",
        "detector": _signal_sql_injection,
        "questions": ["enables_access", "enables_credential_harvest", "enables_chaining", "enables_privesc"],
        "objective": "credential_harvesting",
        "stage_elevation": "credential_access",
        "impact": "critical",
    },
    {
        "id": "xss_found",
        "detector": _signal_xss,
        "questions": ["enables_bypass", "enables_session_harvest", "enables_chaining"],
        "objective": "session_exploitation",
        "stage_elevation": "session_abuse",
        "impact": "high",
    },
    {
        "id": "rce_found",
        "detector": _signal_rce,
        "questions": ["enables_access", "enables_lateral", "enables_privesc", "enables_credential_harvest"],
        "objective": "remote_execution",
        "stage_elevation": "privilege_escalation",
        "impact": "critical",
    },
    {
        "id": "idor_found",
        "detector": _signal_idor,
        "questions": ["enables_access", "enables_lateral", "enables_credential_harvest", "enables_privesc"],
        "objective": "trust_breaking",
        "stage_elevation": "lateral_movement",
        "impact": "high",
    },
    {
        "id": "open_port_service",
        "detector": _signal_open_port_service,
        "questions": ["enables_enum", "enables_pivot", "reduces_unknown", "increases_offensive_capability"],
        "objective": "surface_expansion",
        "stage_elevation": "surface_expansion",
        "impact": "medium",
    },
    {
        "id": "cloud_exposure",
        "detector": _signal_cloud_exposure,
        "questions": ["enables_access", "enables_credential_harvest", "enables_enum", "reduces_unknown"],
        "objective": "credential_harvesting",
        "stage_elevation": "internal_discovery",
        "impact": "high",
    },
    {
        "id": "weak_crypto",
        "detector": _signal_weak_crypto,
        "questions": ["enables_bypass", "enables_credential_harvest", "enables_chaining"],
        "objective": "trust_breaking",
        "stage_elevation": "session_abuse",
        "impact": "medium",
    },
]


# ─────────────────────────────────────────────────────────────────────────────
# Offensive observation builder
# ─────────────────────────────────────────────────────────────────────────────

def evaluate_finding_offensively(finding: dict[str, Any]) -> dict[str, Any]:
    """Applies all SIGNAL_MAP detectors to a finding and returns offensive observations.

    Returns an offensive observation dict:
    {
      observation_id: str
      finding_title: str
      severity: str
      signals_triggered: [signal_id, ...]
      offensive_questions_answered: {question_id: answer}
      objectives_advanced: [objective_id, ...]
      stage_elevation: str|None  — highest stage this finding unlocks
      phase_promotions: [phase_id, ...]  — phases to run earlier
      attack_capability_gained: str      — human-readable capability
      chaining_tags: [tag, ...]          — for exploit chain matching
      impact_score: int (1-10)
    }
    """
    text = _text_of(finding)
    signals_triggered: list[str] = []
    questions_answered: dict[str, str] = {}
    objectives_advanced: set[str] = set()
    highest_stage: str | None = None
    phase_promotions: list[str] = []
    chaining_tags: list[str] = []
    capabilities_gained: list[str] = []
    impact_score = 0

    for signal in SIGNAL_MAP:
        if signal["detector"](text):
            sig_id = str(signal["id"])
            signals_triggered.append(sig_id)
            objectives_advanced.add(str(signal["objective"]))
            chaining_tags.append(sig_id)

            # Record which offensive questions were answered
            for qid in (signal.get("questions") or []):
                q = next((q for q in OFFENSIVE_QUESTIONS if q["id"] == qid), None)
                if q:
                    questions_answered[qid] = q["question"]

            # Track stage elevation
            stage = str(signal.get("stage_elevation") or "")
            if stage and stage in OFFENSIVE_STAGES:
                if highest_stage is None:
                    highest_stage = stage
                else:
                    current_idx = OFFENSIVE_STAGES.index(highest_stage)
                    new_idx = OFFENSIVE_STAGES.index(stage)
                    if new_idx > current_idx:
                        highest_stage = stage

            # Check phase promotions
            for rule in PHASE_PROMOTION_RULES:
                if rule["trigger"] == sig_id:
                    for ph in (rule.get("promote_phases") or []):
                        if ph not in phase_promotions:
                            phase_promotions.append(ph)

            # Capability gained
            impact = str(signal.get("impact") or "medium")
            impact_map = {"critical": 9, "high": 7, "medium": 4, "low": 2, "info": 1}
            score = impact_map.get(impact, 4)
            if score > impact_score:
                impact_score = score
            capabilities_gained.append(
                f"{sig_id.replace('_', ' ')} ({impact})"
            )

    # Severity boost from finding severity
    severity = str(finding.get("severity") or "info").lower()
    sev_boost = {"critical": 3, "high": 2, "medium": 1, "low": 0, "info": 0}
    impact_score = min(10, impact_score + sev_boost.get(severity, 0))

    attack_capability_gained = (
        "; ".join(capabilities_gained[:3]) if capabilities_gained
        else "no offensive capability identified"
    )

    return {
        "observation_id": f"obs-{uuid4().hex[:8]}",
        "finding_title": str(finding.get("title") or ""),
        "severity": severity,
        "signals_triggered": signals_triggered,
        "offensive_questions_answered": questions_answered,
        "objectives_advanced": sorted(objectives_advanced),
        "stage_elevation": highest_stage,
        "phase_promotions": phase_promotions,
        "attack_capability_gained": attack_capability_gained,
        "chaining_tags": chaining_tags,
        "impact_score": impact_score,
        "ts": datetime.now().isoformat(),
    }


# ─────────────────────────────────────────────────────────────────────────────
# Hypothesis generator
# ─────────────────────────────────────────────────────────────────────────────

HYPOTHESIS_TEMPLATES: list[dict[str, Any]] = [
    {
        "trigger_signal": "credentials_found",
        "hypothesis": "Exposed credentials may allow direct authentication to admin or API endpoints.",
        "test_phases": ["P14"],
        "priority": "critical",
    },
    {
        "trigger_signal": "git_exposed",
        "hypothesis": "Exposed .git directory may contain hardcoded credentials, API keys, or deployment secrets.",
        "test_phases": ["P21", "P14"],
        "priority": "critical",
    },
    {
        "trigger_signal": "ssrf_found",
        "hypothesis": "SSRF vulnerability may allow access to cloud metadata, internal services, or credential stores.",
        "test_phases": ["P13", "P10"],
        "priority": "high",
    },
    {
        "trigger_signal": "jwt_found",
        "hypothesis": "JWT implementation may be vulnerable to algorithm confusion, none-attack, or weak key brute-force.",
        "test_phases": ["P14"],
        "priority": "high",
    },
    {
        "trigger_signal": "api_endpoints_found",
        "hypothesis": "Discovered API endpoints may lack proper authentication, expose IDOR, or allow rate-limit bypass.",
        "test_phases": ["P16", "P19"],
        "priority": "medium",
    },
    {
        "trigger_signal": "admin_panel_found",
        "hypothesis": "Admin panel may be accessible with default/weak credentials or auth bypass.",
        "test_phases": ["P14", "P15"],
        "priority": "critical",
    },
    {
        "trigger_signal": "upload_endpoint_found",
        "hypothesis": "File upload endpoint may allow webshell upload via MIME type or extension bypass.",
        "test_phases": ["P17"],
        "priority": "critical",
    },
    {
        "trigger_signal": "subdomain_takeover_candidate",
        "hypothesis": "Dangling CNAME may be claimed to intercept traffic or host phishing content.",
        "test_phases": ["P09"],
        "priority": "critical",
    },
    {
        "trigger_signal": "sql_injection_parameter",
        "hypothesis": "Injectable parameter may allow database dump, authentication bypass, or file read.",
        "test_phases": ["P12"],
        "priority": "critical",
    },
    {
        "trigger_signal": "open_port_service",
        "hypothesis": "Exposed service may accept default credentials, have known CVEs, or allow unauthenticated access.",
        "test_phases": ["P11", "P14"],
        "priority": "medium",
    },
    {
        "trigger_signal": "cloud_exposure",
        "hypothesis": "Misconfigured cloud asset may allow public read, credential theft via IMDS, or data exfiltration.",
        "test_phases": ["P10", "P07"],
        "priority": "high",
    },
    {
        "trigger_signal": "rce_found",
        "hypothesis": "RCE vector enables post-exploitation: credential harvest, lateral movement, persistence.",
        "test_phases": ["P14", "P21"],
        "priority": "critical",
    },
    {
        "trigger_signal": "idor_found",
        "hypothesis": "IDOR may allow access to other users' data, escalate to admin role, or dump user database.",
        "test_phases": ["P19", "P16"],
        "priority": "high",
    },
    {
        "trigger_signal": "xss_found",
        "hypothesis": "XSS may enable session token theft, credential harvesting via phishing, or admin action replay.",
        "test_phases": ["P12", "P14"],
        "priority": "high",
    },
    {
        "trigger_signal": "cms_detected",
        "hypothesis": "Identified CMS may have unpatched CVEs, weak admin credentials, or exposed plugin vulnerabilities.",
        "test_phases": ["P20", "P11"],
        "priority": "medium",
    },
]


def generate_hypotheses(observations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Generates attack hypotheses based on offensive observations."""
    hypotheses: list[dict[str, Any]] = []
    triggered_signals: set[str] = set()

    for obs in observations:
        for sig in (obs.get("signals_triggered") or []):
            triggered_signals.add(sig)

    for template in HYPOTHESIS_TEMPLATES:
        if template["trigger_signal"] in triggered_signals:
            hypotheses.append({
                "hypothesis_id": f"hyp-{uuid4().hex[:8]}",
                "trigger": template["trigger_signal"],
                "statement": template["hypothesis"],
                "test_phases": list(template["test_phases"]),
                "priority": template["priority"],
                "status": "open",
                "created_at": datetime.now().isoformat(),
                "validated": False,
                "validation_result": None,
            })

    return hypotheses


# ─────────────────────────────────────────────────────────────────────────────
# Attack path builder
# ─────────────────────────────────────────────────────────────────────────────

def build_attack_path_fragment(
    observation: dict[str, Any],
    target: str,
    phase_id: str,
) -> dict[str, Any] | None:
    """Builds an attack path fragment from an offensive observation."""
    signals = list(observation.get("signals_triggered") or [])
    stage = str(observation.get("stage_elevation") or "")
    if not signals or not stage:
        return None

    return {
        "fragment_id": f"frag-{uuid4().hex[:8]}",
        "phase_id": phase_id,
        "target": target,
        "signals": signals,
        "stage_reached": stage,
        "capability_gained": str(observation.get("attack_capability_gained") or ""),
        "chaining_tags": list(observation.get("chaining_tags") or []),
        "impact_score": int(observation.get("impact_score") or 0),
        "ts": datetime.now().isoformat(),
    }


def consolidate_attack_paths(fragments: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Groups fragments into coherent attack paths ordered by stage progression."""
    if not fragments:
        return []

    # Group by stage
    by_stage: dict[str, list[dict[str, Any]]] = {}
    for frag in fragments:
        stage = str(frag.get("stage_reached") or "initial_access")
        by_stage.setdefault(stage, []).append(frag)

    paths: list[dict[str, Any]] = []
    stage_chain = [s for s in OFFENSIVE_STAGES if s in by_stage]

    if not stage_chain:
        return []

    # Build a single progressive path
    path_steps: list[dict[str, Any]] = []
    total_impact = 0
    all_tags: set[str] = set()

    for stage in stage_chain:
        frags = sorted(by_stage[stage], key=lambda f: int(f.get("impact_score") or 0), reverse=True)
        best = frags[0]
        path_steps.append({
            "stage": stage,
            "phase_id": best.get("phase_id"),
            "capability": best.get("capability_gained"),
            "signals": best.get("signals", []),
        })
        total_impact = max(total_impact, int(best.get("impact_score") or 0))
        all_tags.update(best.get("chaining_tags") or [])

    if len(path_steps) < 2:
        return []

    start_stage = STAGE_LABELS.get(path_steps[0]["stage"], path_steps[0]["stage"])
    end_stage = STAGE_LABELS.get(path_steps[-1]["stage"], path_steps[-1]["stage"])

    paths.append({
        "path_id": f"path-{uuid4().hex[:8]}",
        "stages": [s["stage"] for s in path_steps],
        "steps": path_steps,
        "start": start_stage,
        "end": end_stage,
        "depth": len(path_steps),
        "impact_score": total_impact,
        "chaining_tags": sorted(all_tags),
        "created_at": datetime.now().isoformat(),
        "validated": False,
    })

    return paths


# ─────────────────────────────────────────────────────────────────────────────
# Post-exploitation task generator
# ─────────────────────────────────────────────────────────────────────────────

POST_EXPLOITATION_TEMPLATES: dict[str, list[dict[str, Any]]] = {
    "rce_found": [
        {"task": "harvest_credentials", "description": "Read /etc/passwd, .ssh/, env vars, config files", "priority": "critical"},
        {"task": "enumerate_internal_network", "description": "Run internal network discovery from compromised host", "priority": "high"},
        {"task": "establish_persistence", "description": "Plant cron job, SSH key, or backdoor user", "priority": "high"},
        {"task": "lateral_movement", "description": "Use credentials from host to access other services", "priority": "high"},
    ],
    "credentials_found": [
        {"task": "test_credential_reuse", "description": "Try credentials against all discovered endpoints", "priority": "critical"},
        {"task": "test_admin_access", "description": "Attempt admin panel access with found credentials", "priority": "critical"},
        {"task": "enumerate_accessible_resources", "description": "List what authenticated access reveals", "priority": "high"},
    ],
    "sql_injection_parameter": [
        {"task": "dump_user_table", "description": "Extract user credentials from database", "priority": "critical"},
        {"task": "read_sensitive_files", "description": "Use LOAD_FILE or equivalent to read server files", "priority": "high"},
        {"task": "write_webshell", "description": "Attempt INTO OUTFILE for webshell placement", "priority": "medium"},
    ],
    "upload_endpoint_found": [
        {"task": "upload_webshell", "description": "Attempt webshell upload via type/extension bypass", "priority": "critical"},
        {"task": "test_path_traversal", "description": "Test if upload destination is traversable", "priority": "high"},
    ],
    "ssrf_found": [
        {"task": "probe_cloud_metadata", "description": "Fetch http://169.254.169.254/latest/meta-data/", "priority": "critical"},
        {"task": "probe_internal_services", "description": "Scan common internal ports via SSRF", "priority": "high"},
        {"task": "probe_gcp_metadata", "description": "Fetch http://metadata.google.internal/", "priority": "high"},
    ],
    "idor_found": [
        {"task": "enumerate_all_user_ids", "description": "Iterate user IDs to access other accounts", "priority": "critical"},
        {"task": "test_admin_idor", "description": "Try to access admin-level object IDs", "priority": "critical"},
    ],
}


def generate_post_exploitation_tasks(observations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Generates post-exploitation tasks based on triggered signals."""
    tasks: list[dict[str, Any]] = []
    seen_tasks: set[str] = set()

    for obs in observations:
        for signal in (obs.get("signals_triggered") or []):
            for template in (POST_EXPLOITATION_TEMPLATES.get(signal) or []):
                task_id = template["task"]
                if task_id not in seen_tasks:
                    seen_tasks.add(task_id)
                    tasks.append({
                        "task_id": f"postex-{uuid4().hex[:8]}",
                        "task": task_id,
                        "description": template["description"],
                        "priority": template["priority"],
                        "triggered_by_signal": signal,
                        "status": "pending",
                        "created_at": datetime.now().isoformat(),
                    })

    tasks.sort(key=lambda t: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(t["priority"], 4))
    return tasks


# ─────────────────────────────────────────────────────────────────────────────
# Noise profile decision
# ─────────────────────────────────────────────────────────────────────────────

def decide_noise_profile(campaign: dict[str, Any], new_findings: list[dict[str, Any]]) -> tuple[str, str]:
    """Decides noise profile based on WAF/blocking signals in findings.

    Returns (profile_id, reason).
    """
    all_text = " ".join(_text_of(f) for f in new_findings).lower()
    waf_detected = campaign.get("offensive_state", {}).get("waf_detected", False)
    rate_limited = _contains_any(all_text, ["rate limit", "too many requests", "429", "throttle"])
    blocked = _contains_any(all_text, ["blocked", "forbidden", "403", "captcha", "honeypot"])
    waf_in_findings = _contains_any(all_text, ["cloudflare", "modsecurity", "imperva", "akamai", "waf"])

    waf_detected = waf_detected or waf_in_findings

    profile = select_noise_profile(campaign, waf_detected, rate_limited, blocked)
    reasons = []
    if blocked:
        reasons.append("active blocking detected")
    if waf_detected:
        reasons.append("WAF detected")
    if rate_limited:
        reasons.append("rate limiting detected")
    if not reasons:
        reasons.append("no protection signals")

    return profile, " + ".join(reasons)


# ─────────────────────────────────────────────────────────────────────────────
# Main entry point — apply_offensive_reasoning
# ─────────────────────────────────────────────────────────────────────────────

def apply_offensive_reasoning(
    campaign: dict[str, Any],
    new_findings: list[dict[str, Any]],
    phase_id: str,
    target: str,
) -> dict[str, Any]:
    """Core offensive reasoning loop.

    Takes findings from a phase execution and produces:
    - Updated campaign with new observations, hypotheses, paths, post-ex tasks
    - Phase promotions (phases to run earlier)
    - Noise profile adjustment
    - Stage advancement

    Returns the updated campaign dict.
    """
    if not new_findings:
        return campaign

    campaign = dict(campaign)
    offensive_obs = list(campaign.get("offensive_observations") or [])
    active_hypotheses = list(campaign.get("active_hypotheses") or [])
    attack_paths = list(campaign.get("attack_paths") or [])
    post_ex_queue = list(campaign.get("post_exploitation_queue") or [])
    phase_promotions = list(campaign.get("phase_promotions") or [])
    chaining_candidates = list(campaign.get("chaining_candidates") or [])
    offensive_state = dict(campaign.get("offensive_state") or {})

    new_observations: list[dict[str, Any]] = []
    new_fragments: list[dict[str, Any]] = []
    highest_stage_reached: str | None = None

    for finding in new_findings:
        severity = str(finding.get("severity") or "info").lower()
        if severity in ("info",) and not any(
            sig["detector"](_text_of(finding)) for sig in SIGNAL_MAP
        ):
            continue  # Skip noise-only findings

        obs = evaluate_finding_offensively(finding)
        if obs["signals_triggered"]:
            new_observations.append(obs)
            offensive_obs.append(obs)

            # Track stage elevation
            stage = obs.get("stage_elevation")
            if stage and stage in OFFENSIVE_STAGES:
                if highest_stage_reached is None:
                    highest_stage_reached = stage
                else:
                    current_idx = OFFENSIVE_STAGES.index(highest_stage_reached)
                    new_idx = OFFENSIVE_STAGES.index(stage)
                    if new_idx > current_idx:
                        highest_stage_reached = stage

            # Build attack path fragment
            fragment = build_attack_path_fragment(obs, target, phase_id)
            if fragment:
                new_fragments.append(fragment)
                chaining_candidates.append(fragment)

            # Register phase promotions
            for ph in (obs.get("phase_promotions") or []):
                existing = next((p for p in phase_promotions if p["phase_id"] == ph), None)
                if not existing:
                    phase_promotions.append({
                        "phase_id": ph,
                        "reason": obs["attack_capability_gained"],
                        "priority_boost": 8,
                        "ts": datetime.now().isoformat(),
                    })
                    logger.info(
                        "OFFENSIVE_REASONING [%s] phase_promotion=%s reason=%s",
                        phase_id, ph, obs["attack_capability_gained"][:80],
                    )

            # Update offensive_state known assets / compromised
            title_lower = str(finding.get("title") or "").lower()
            if "subdomain" in title_lower or "asset" in title_lower:
                asset = str((finding.get("details") or {}).get("asset") or target)
                if asset and asset not in offensive_state.get("known_assets", []):
                    offensive_state.setdefault("known_assets", []).append(asset)

            if obs.get("impact_score", 0) >= 9:
                if target not in offensive_state.get("high_value_targets", []):
                    offensive_state.setdefault("high_value_targets", []).append(target)

    # Generate hypotheses from new observations
    new_hypotheses = generate_hypotheses(new_observations)
    existing_hyp_statements = {h.get("statement") for h in active_hypotheses}
    for hyp in new_hypotheses:
        if hyp["statement"] not in existing_hyp_statements:
            active_hypotheses.append(hyp)
            logger.info(
                "OFFENSIVE_REASONING [%s] new_hypothesis priority=%s: %s",
                phase_id, hyp["priority"], hyp["statement"][:80],
            )

    # Generate post-exploitation tasks
    new_post_ex = generate_post_exploitation_tasks(new_observations)
    existing_tasks = {t.get("task") for t in post_ex_queue}
    for task in new_post_ex:
        if task["task"] not in existing_tasks:
            post_ex_queue.append(task)
            existing_tasks.add(task["task"])

    # Consolidate attack paths from new fragments + existing
    all_fragments = chaining_candidates
    new_paths = consolidate_attack_paths(all_fragments)
    existing_path_ids = {p["path_id"] for p in attack_paths}
    for path in new_paths:
        if path["path_id"] not in existing_path_ids:
            attack_paths.append(path)

    # Advance offensive stage
    if highest_stage_reached:
        campaign = advance_offensive_stage(
            campaign,
            highest_stage_reached,
            reason=f"Phase {phase_id} findings triggered stage elevation",
        )

    # Noise profile decision
    noise_profile, noise_reason = decide_noise_profile(campaign, new_findings)
    if noise_profile != campaign.get("noise_profile"):
        logger.info(
            "OFFENSIVE_REASONING [%s] noise_profile %s→%s reason=%s",
            phase_id, campaign.get("noise_profile"), noise_profile, noise_reason,
        )
        campaign["noise_profile"] = noise_profile
        campaign["noise_profile_reason"] = noise_reason
        offensive_state["waf_detected"] = noise_profile in ("stealthy", "evasive", "balanced")

    # Update next objectives
    triggered_objectives: set[str] = set()
    for obs in new_observations:
        triggered_objectives.update(obs.get("objectives_advanced") or [])
    next_objs = list(campaign.get("next_objectives") or [])
    for obj_id in triggered_objectives:
        if obj_id not in next_objs:
            next_objs.insert(0, obj_id)
    campaign["next_objectives"] = next_objs[:10]

    # Persist updates
    campaign["offensive_observations"] = offensive_obs[-200:]
    campaign["active_hypotheses"] = active_hypotheses
    campaign["attack_paths"] = attack_paths
    campaign["post_exploitation_queue"] = post_ex_queue
    campaign["phase_promotions"] = phase_promotions
    campaign["chaining_candidates"] = chaining_candidates[-100:]
    campaign["offensive_state"] = offensive_state
    campaign["last_reasoning_at"] = datetime.now().isoformat()
    campaign["last_reasoning_phase"] = phase_id

    logger.info(
        "OFFENSIVE_REASONING [%s] findings=%d observations=%d hypotheses=%d "
        "promotions=%d paths=%d stage=%s noise=%s",
        phase_id,
        len(new_findings),
        len(new_observations),
        len(new_hypotheses),
        len([p for p in phase_promotions]),
        len(attack_paths),
        campaign.get("current_stage"),
        campaign.get("noise_profile"),
    )

    return campaign


def get_offensive_priority_phases(
    campaign: dict[str, Any],
    pending_phases: list[str],
) -> list[str]:
    """Reorders pending phases based on offensive priority and phase promotions.

    Phase promotions from offensive reasoning are injected at the front.
    Other phases retain their P01–P22 sequential order.
    """
    promotions = list(campaign.get("phase_promotions") or [])
    promoted_ids = [p["phase_id"] for p in sorted(promotions, key=lambda x: -int(x.get("priority_boost", 0)))]

    # Build priority-ordered list:
    # 1. Promoted phases that are still pending (in original order if multiple)
    # 2. Remaining pending phases in sequential order
    priority_first: list[str] = []
    for ph in promoted_ids:
        if ph in pending_phases and ph not in priority_first:
            priority_first.append(ph)

    remaining = [ph for ph in pending_phases if ph not in priority_first]
    return priority_first + remaining
