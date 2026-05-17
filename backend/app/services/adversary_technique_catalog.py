from __future__ import annotations

import json
from typing import Any


DetectionSource = dict[str, Any]
AdversaryTechnique = dict[str, Any]


def _technique(
    *,
    technique_id: str,
    name: str,
    description: str,
    framework_refs: dict[str, list[str]],
    kill_chain_stage: str,
    app_phases: list[str],
    skills: list[str],
    candidate_tools: list[str],
    control_objectives: list[str],
    prerequisites: list[str],
    max_risk: str,
    expected_telemetry: list[DetectionSource],
    offensive_success_criteria: list[str],
    defensive_success_criteria: list[str],
    failure_modes: list[str],
    report_mapping: dict[str, str],
    requires_operator_approval: bool = False,
) -> AdversaryTechnique:
    return {
        "id": technique_id,
        "name": name,
        "description": description,
        "framework_refs": framework_refs,
        "kill_chain_stage": kill_chain_stage,
        "app_phases": app_phases,
        "skills": skills,
        "candidate_tools": candidate_tools,
        "control_objectives": control_objectives,
        "prerequisites": prerequisites,
        "safe_execution": {
            "max_risk": max_risk,
            "requires_operator_approval": requires_operator_approval,
            "destructive_actions_allowed": False,
            "data_extraction_allowed": False,
            "persistence_allowed": False,
            "credential_dumping_allowed": False,
        },
        "expected_telemetry": expected_telemetry,
        "offensive_success_criteria": offensive_success_criteria,
        "defensive_success_criteria": defensive_success_criteria,
        "failure_modes": failure_modes,
        "report_mapping": report_mapping,
    }


ADVERSARY_TECHNIQUE_CATALOG: list[AdversaryTechnique] = [
    _technique(
        technique_id="web-exploit-public-app",
        name="Exploit Public-Facing Application Attempt",
        description="Controlled emulation of exploit attempts against an authorized internet-facing web application.",
        framework_refs={"mitre_attack": ["T1190"], "owasp": ["A03", "A05"], "nist": ["DE.CM", "PR.PT"]},
        kill_chain_stage="EXPLOITATION",
        app_phases=["P11", "P12", "P13", "P16", "P20"],
        skills=["vuln-nuclei-cve", "vuln-injection", "vuln-ssrf-redirect", "vuln-api-graphql", "tech-cms-fingerprint"],
        candidate_tools=["nuclei", "nikto", "sqlmap", "dalfox", "wapiti", "wpscan", "curl-headers"],
        control_objectives=[
            "WAF should block, challenge, or alert exploit-class payloads.",
            "SIEM should correlate exploit attempts by source, target URL, and technique.",
            "SOC alert should contain target, URI, payload class, action, and correlation id.",
        ],
        prerequisites=["authorized web target", "live URL discovered", "active validation allowed by risk policy"],
        max_risk="medium",
        expected_telemetry=[
            {"source": "WAF", "signals": ["blocked_request", "attack_signature", "rule_id", "target_url", "source_ip"]},
            {"source": "SIEM", "signals": ["web_attack_alert", "correlation_id", "technique_id", "asset", "severity"]},
        ],
        offensive_success_criteria=["request_response_artifact_captured", "payload_class_recorded", "proof_pack_complete"],
        defensive_success_criteria=["alert_created_within_sla", "alert_contains_correlation_id", "alert_maps_to_web_exploit"],
        failure_modes=["vulnerability_verified_but_no_alert", "waf_blocked_but_siem_no_correlation", "alert_missing_target_context"],
        report_mapping={"category": "Web Exploitation", "control_family": "Detect and Protect", "finding_type": "detection_validation"},
    ),
    _technique(
        technique_id="web-sqli-attempt",
        name="SQL Injection Attempt",
        description="Read-only SQL injection validation using benign boolean, error, or timing probes without data extraction.",
        framework_refs={"mitre_attack": ["T1190"], "owasp": ["A03"], "cwe": ["CWE-89"]},
        kill_chain_stage="EXPLOITATION",
        app_phases=["P04", "P12", "P16"],
        skills=["recon-web-crawl", "vuln-injection", "vuln-api-graphql"],
        candidate_tools=["sqlmap", "nuclei", "wapiti", "curl-headers", "arjun"],
        control_objectives=[
            "WAF should detect SQL injection payload class.",
            "SIEM should alert repeated SQLi probes against the same endpoint.",
            "Application logs should include normalized parameter and response status.",
        ],
        prerequisites=["parameterized endpoint discovered", "data extraction disabled", "authorized active validation"],
        max_risk="medium",
        expected_telemetry=[
            {"source": "WAF", "signals": ["sqli_signature", "action", "rule_id", "target_url", "parameter"]},
            {"source": "SIEM", "signals": ["sql_injection_alert", "correlation_id", "source_ip", "target_url"]},
            {"source": "APP_LOG", "signals": ["request_id", "parameter_name", "status_code", "correlation_id"]},
        ],
        offensive_success_criteria=["response_delta_or_db_error_observed", "request_artifact_saved", "no_sensitive_data_extracted"],
        defensive_success_criteria=["waf_or_siem_alert_created", "correlation_id_present", "severity_medium_or_higher"],
        failure_modes=["sqli_signal_without_detection", "detection_without_payload_context", "only_app_error_no_security_alert"],
        report_mapping={"category": "Injection", "control_family": "WAF/SIEM Detection", "finding_type": "bas_detection_gap"},
    ),
    _technique(
        technique_id="web-xss-attempt",
        name="Cross-Site Scripting Attempt",
        description="Controlled XSS probe that validates reflection or DOM sinks with non-malicious markers.",
        framework_refs={"mitre_attack": ["T1189", "T1190"], "owasp": ["A03"], "cwe": ["CWE-79"]},
        kill_chain_stage="EXPLOITATION",
        app_phases=["P03", "P04", "P12"],
        skills=["recon-web-crawl", "vuln-injection"],
        candidate_tools=["dalfox", "nuclei", "wapiti", "curl-headers", "katana"],
        control_objectives=[
            "WAF should detect reflected or stored script payload classes.",
            "SIEM should correlate script injection attempts by endpoint and source.",
            "CSP posture should be captured for compensating-control analysis.",
        ],
        prerequisites=["input or sink discovered", "benign marker payload selected", "authorized active validation"],
        max_risk="medium",
        expected_telemetry=[
            {"source": "WAF", "signals": ["xss_signature", "rule_id", "action", "payload_class"]},
            {"source": "SIEM", "signals": ["xss_alert", "correlation_id", "target_url", "source_ip"]},
        ],
        offensive_success_criteria=["marker_reflected_or_sink_identified", "context_recorded", "proof_pack_complete"],
        defensive_success_criteria=["alert_created_within_sla", "payload_class_is_xss", "target_url_present"],
        failure_modes=["xss_reflection_no_alert", "alert_missing_context", "csp_absent_and_no_detection"],
        report_mapping={"category": "Injection", "control_family": "WAF/SIEM Detection", "finding_type": "bas_detection_gap"},
    ),
    _technique(
        technique_id="ssrf-oob-callback",
        name="SSRF Out-of-Band Callback Attempt",
        description="Controlled server-side request callback validation using authorized OOB infrastructure.",
        framework_refs={"mitre_attack": ["T1190"], "owasp": ["A10"], "cwe": ["CWE-918"]},
        kill_chain_stage="EXPLOITATION",
        app_phases=["P04", "P13", "P16"],
        skills=["recon-web-crawl", "vuln-ssrf-redirect", "vuln-api-graphql"],
        candidate_tools=["nuclei", "interactsh-client", "arjun", "curl-headers"],
        control_objectives=[
            "WAF should alert URL-based SSRF payloads.",
            "DNS/proxy telemetry should capture outbound callback attempt.",
            "SIEM should correlate inbound trigger and outbound egress event.",
        ],
        prerequisites=["URL-like parameter discovered", "authorized OOB domain", "egress callback allowed for test"],
        max_risk="medium",
        expected_telemetry=[
            {"source": "WAF", "signals": ["ssrf_signature", "target_url", "parameter", "correlation_id"]},
            {"source": "DNS_OR_PROXY", "signals": ["outbound_dns_query", "http_callback", "source_workload", "correlation_id"]},
            {"source": "SIEM", "signals": ["ssrf_or_egress_alert", "correlation_id", "asset"]},
        ],
        offensive_success_criteria=["oob_callback_or_block_evidence", "parameter_recorded", "artifact_saved"],
        defensive_success_criteria=["egress_or_waf_alert_created", "inbound_outbound_events_correlated", "correlation_id_present"],
        failure_modes=["callback_observed_no_alert", "waf_alert_no_egress_correlation", "unknown_source_workload"],
        report_mapping={"category": "SSRF", "control_family": "Egress Detection", "finding_type": "bas_detection_gap"},
    ),
    _technique(
        technique_id="directory-enumeration",
        name="Web Content Discovery Burst",
        description="Rate-limited discovery of hidden paths and files using authorized wordlists.",
        framework_refs={"mitre_attack": ["T1595", "T1592"], "owasp": ["A05"]},
        kill_chain_stage="RECONNAISSANCE",
        app_phases=["P03", "P04", "P15"],
        skills=["recon-web-crawl", "vuln-directory-enum"],
        candidate_tools=["ffuf", "ffuf-files", "ffuf-params", "gobuster", "feroxbuster", "dirsearch", "wfuzz", "katana"],
        control_objectives=[
            "WAF/CDN should identify abnormal enumeration patterns.",
            "SIEM should alert excessive 404/403 path probing by source.",
            "Web logs should preserve user-agent and correlation id.",
        ],
        prerequisites=["live web target", "rate limit configured", "authorized wordlist"],
        max_risk="low",
        expected_telemetry=[
            {"source": "WAF_OR_CDN", "signals": ["path_enumeration", "rate_anomaly", "source_ip", "target_host"]},
            {"source": "SIEM", "signals": ["web_scan_alert", "correlation_id", "status_code_distribution"]},
        ],
        offensive_success_criteria=["enumeration_summary_saved", "interesting_paths_recorded", "rate_limit_respected"],
        defensive_success_criteria=["scan_or_enumeration_alert_created", "status_distribution_available", "correlation_id_present"],
        failure_modes=["high_volume_no_alert", "alert_without_source_or_target", "logs_missing_user_agent"],
        report_mapping={"category": "Reconnaissance", "control_family": "Web Anomaly Detection", "finding_type": "bas_detection_gap"},
    ),
    _technique(
        technique_id="password-spray-controlled",
        name="Controlled Password Spray",
        description="Small, operator-approved credential validation to test lockout, rate limits, and alerting.",
        framework_refs={"mitre_attack": ["T1110.003"], "owasp": ["A07"], "nist": ["DE.CM", "PR.AC"]},
        kill_chain_stage="EXPLOITATION",
        app_phases=["P14"],
        skills=["vuln-auth-bypass"],
        candidate_tools=["hydra", "medusa", "crackmapexec", "curl-headers"],
        control_objectives=[
            "Identity controls should enforce lockout, backoff, or MFA challenge.",
            "SIEM should alert password spray pattern across accounts or services.",
            "SOC alert should include account set, service, source, and attempt count.",
        ],
        prerequisites=["explicit operator approval", "operator-supplied user/pass lists", "attempt budget configured"],
        max_risk="high",
        requires_operator_approval=True,
        expected_telemetry=[
            {"source": "IAM_OR_IDP", "signals": ["failed_login_series", "lockout_or_mfa", "source_ip", "account_set"]},
            {"source": "SIEM", "signals": ["password_spray_alert", "correlation_id", "attempt_count", "service"]},
        ],
        offensive_success_criteria=["attempt_count_within_budget", "auth_responses_recorded", "no_account_takeover_performed"],
        defensive_success_criteria=["spray_alert_created", "alert_contains_account_set", "control_action_recorded"],
        failure_modes=["spray_no_alert", "no_lockout_or_rate_limit", "alert_missing_account_context"],
        report_mapping={"category": "Credential Access", "control_family": "Identity Detection", "finding_type": "bas_detection_gap"},
    ),
    _technique(
        technique_id="jwt-abuse-attempt",
        name="JWT Abuse Attempt",
        description="JWT algorithm, key confusion, and claim manipulation validation without unauthorized privilege use.",
        framework_refs={"mitre_attack": ["T1550"], "owasp": ["A01", "A07"], "cwe": ["CWE-287"]},
        kill_chain_stage="EXPLOITATION",
        app_phases=["P14", "P16"],
        skills=["vuln-auth-bypass", "vuln-api-graphql"],
        candidate_tools=["jwt_tool", "nuclei", "curl-headers"],
        control_objectives=[
            "Application should reject manipulated tokens.",
            "SIEM should alert token tampering or repeated auth failures.",
            "API gateway should log token validation errors with request context.",
        ],
        prerequisites=["JWT observed or operator supplied", "no forged-token access beyond authorized test", "active validation allowed"],
        max_risk="medium",
        expected_telemetry=[
            {"source": "APP_OR_API_GATEWAY", "signals": ["token_validation_error", "claim_anomaly", "correlation_id"]},
            {"source": "SIEM", "signals": ["token_tampering_alert", "source_ip", "target_api", "correlation_id"]},
        ],
        offensive_success_criteria=["token_validation_behavior_recorded", "tamper_attempt_artifact_saved", "no_privilege_abuse"],
        defensive_success_criteria=["token_tamper_alert_created", "api_context_present", "correlation_id_present"],
        failure_modes=["tamper_attempt_no_alert", "app_rejects_but_no_security_signal", "alert_missing_claim_context"],
        report_mapping={"category": "Authentication", "control_family": "API/Auth Detection", "finding_type": "bas_detection_gap"},
    ),
    _technique(
        technique_id="idor-two-account-validation",
        name="IDOR Two-Identity Access Attempt",
        description="Authorized two-account comparison to validate object-level authorization and detection of access anomalies.",
        framework_refs={"mitre_attack": ["T1190"], "owasp": ["A01", "API1"], "cwe": ["CWE-639"]},
        kill_chain_stage="EXPLOITATION",
        app_phases=["P14", "P16", "P19"],
        skills=["vuln-idor-access-control", "vuln-api-graphql", "vuln-auth-bypass"],
        candidate_tools=["katana", "arjun", "curl-headers", "nuclei"],
        control_objectives=[
            "Application should deny cross-user or cross-tenant object access.",
            "API gateway/SIEM should flag repeated forbidden object access.",
            "Audit logs should include actor, object id, tenant, and decision.",
        ],
        prerequisites=["two authorized test identities", "object ids approved for test", "no real data exposure beyond test accounts"],
        max_risk="medium",
        requires_operator_approval=True,
        expected_telemetry=[
            {"source": "APP_AUDIT", "signals": ["authorization_denied", "actor_id", "object_id", "tenant_id", "correlation_id"]},
            {"source": "SIEM", "signals": ["idor_or_bola_attempt", "correlation_id", "api_route"]},
        ],
        offensive_success_criteria=["two_identity_response_delta_recorded", "object_scope_documented", "proof_pack_complete"],
        defensive_success_criteria=["authz_denial_or_anomaly_logged", "alert_contains_actor_and_object", "correlation_id_present"],
        failure_modes=["access_delta_no_alert", "audit_log_missing_object_id", "alert_missing_tenant_context"],
        report_mapping={"category": "Access Control", "control_family": "Authorization Detection", "finding_type": "bas_detection_gap"},
    ),
    _technique(
        technique_id="subdomain-takeover-validation",
        name="Subdomain Takeover Validation",
        description="CNAME dangling and takeover-condition validation without claiming or modifying third-party resources.",
        framework_refs={"mitre_attack": ["T1584.001", "T1190"], "owasp": ["A05"]},
        kill_chain_stage="VULNERABILITY_ANALYSIS",
        app_phases=["P01", "P09", "P10"],
        skills=["recon-subdomain-enum", "osint-subdomain-takeover", "osint-cloud-exposure"],
        candidate_tools=["subjack", "nuclei", "dnsx", "httpx"],
        control_objectives=[
            "External exposure monitoring should detect dangling DNS records.",
            "SIEM or ASM control should create an exposure alert for takeover candidates.",
            "DNS inventory should map owner and service provider for the record.",
        ],
        prerequisites=["authorized domain scope", "no resource claiming", "DNS resolution available"],
        max_risk="low",
        expected_telemetry=[
            {"source": "ASM_OR_SIEM", "signals": ["dangling_cname_alert", "subdomain", "provider", "correlation_id"]},
            {"source": "DNS_INVENTORY", "signals": ["cname_target", "record_owner", "last_seen"]},
        ],
        offensive_success_criteria=["dangling_condition_artifact_saved", "dns_record_recorded", "no_takeover_claim_performed"],
        defensive_success_criteria=["exposure_alert_created", "provider_context_present", "asset_owner_present"],
        failure_modes=["takeover_candidate_no_alert", "dns_inventory_missing_owner", "alert_missing_provider"],
        report_mapping={"category": "External Exposure", "control_family": "ASM Detection", "finding_type": "bas_detection_gap"},
    ),
    _technique(
        technique_id="cloud-storage-exposure",
        name="Cloud Storage Exposure Check",
        description="Controlled discovery of public cloud storage exposure without bulk download or destructive operations.",
        framework_refs={"mitre_attack": ["T1530", "T1619"], "owasp": ["A01", "A05"], "nist": ["DE.CM"]},
        kill_chain_stage="VULNERABILITY_ANALYSIS",
        app_phases=["P10", "P21"],
        skills=["osint-cloud-exposure", "osint-exposure-intel", "code-secrets-sast"],
        candidate_tools=["nuclei", "shodan-cli", "trufflehog", "gitleaks"],
        control_objectives=[
            "Cloud security controls should detect public bucket or object exposure.",
            "SIEM/CSPM should alert externally accessible storage.",
            "Alert should include bucket/object, cloud provider, and sensitivity hint.",
        ],
        prerequisites=["authorized cloud namespace or domain", "no bulk object download", "read-only metadata validation"],
        max_risk="low",
        expected_telemetry=[
            {"source": "CSPM_OR_CLOUD_LOG", "signals": ["public_storage_alert", "bucket_or_container", "provider", "correlation_id"]},
            {"source": "SIEM", "signals": ["cloud_exposure_alert", "asset", "severity", "owner"]},
        ],
        offensive_success_criteria=["public_exposure_metadata_saved", "sample_listing_minimized", "no_bulk_download"],
        defensive_success_criteria=["cloud_exposure_alert_created", "asset_owner_present", "severity_matches_exposure"],
        failure_modes=["public_storage_no_alert", "alert_missing_owner", "sensitivity_not_classified"],
        report_mapping={"category": "Cloud Exposure", "control_family": "CSPM/SIEM Detection", "finding_type": "bas_detection_gap"},
    ),
    _technique(
        technique_id="secret-exposure-validation",
        name="Secret Exposure Validation",
        description="Read-only validation of exposed credentials or tokens in code, public files, or repositories.",
        framework_refs={"mitre_attack": ["T1552.001", "T1589"], "owasp": ["A02", "A05"]},
        kill_chain_stage="ACTIONS_ON_OBJECTIVES",
        app_phases=["P07", "P21", "P22"],
        skills=["osint-exposure-intel", "code-secrets-sast", "code-supply-chain-deps"],
        candidate_tools=["trufflehog", "gitleaks", "semgrep", "nuclei"],
        control_objectives=[
            "Secret scanning controls should detect exposed credentials.",
            "SIEM/SOAR should open or route an exposure incident.",
            "Alert should include secret type, location, and rotation guidance.",
        ],
        prerequisites=["authorized repo or public asset", "no credential use", "secret value redaction enabled"],
        max_risk="low",
        expected_telemetry=[
            {"source": "SECRET_SCANNER", "signals": ["secret_match", "secret_type", "location", "redacted_value"]},
            {"source": "SIEM_OR_SOAR", "signals": ["secret_exposure_incident", "asset_owner", "correlation_id"]},
        ],
        offensive_success_criteria=["secret_pattern_recorded_redacted", "location_artifact_saved", "no_secret_use"],
        defensive_success_criteria=["secret_alert_created", "redaction_present", "owner_or_rotation_workflow_present"],
        failure_modes=["valid_secret_no_alert", "alert_contains_unredacted_secret", "no_owner_or_ticket"],
        report_mapping={"category": "Credential Exposure", "control_family": "Secret Detection", "finding_type": "bas_detection_gap"},
    ),
    _technique(
        technique_id="tls-downgrade-risk",
        name="TLS Downgrade and Weak Cipher Exposure",
        description="TLS protocol and cipher posture validation for downgrade or weak crypto detection coverage.",
        framework_refs={"mitre_attack": ["T1040"], "owasp": ["A02"], "cwe": ["CWE-326"]},
        kill_chain_stage="VULNERABILITY_ANALYSIS",
        app_phases=["P05", "P18"],
        skills=["tech-http-fingerprint", "vuln-ssl-tls", "weak-cryptography"],
        candidate_tools=["sslscan", "testssl", "nmap", "curl-headers"],
        control_objectives=[
            "ASM or compliance controls should detect legacy TLS and weak ciphers.",
            "SIEM should surface weak transport exposure for internet-facing assets.",
            "Certificate inventory should capture expiry, chain, and owner.",
        ],
        prerequisites=["HTTPS endpoint reachable", "read-only TLS handshake probing", "authorized asset"],
        max_risk="low",
        expected_telemetry=[
            {"source": "ASM_OR_COMPLIANCE", "signals": ["weak_tls_alert", "protocol", "cipher", "certificate_subject"]},
            {"source": "SIEM", "signals": ["transport_security_alert", "asset", "correlation_id"]},
        ],
        offensive_success_criteria=["tls_report_saved", "weak_protocol_or_cipher_classified", "cert_metadata_recorded"],
        defensive_success_criteria=["weak_tls_alert_created", "asset_owner_present", "severity_matches_policy"],
        failure_modes=["weak_tls_no_alert", "asset_owner_missing", "certificate_expiry_not_detected"],
        report_mapping={"category": "Transport Security", "control_family": "ASM/Compliance Detection", "finding_type": "bas_detection_gap"},
    ),
]


def list_adversary_techniques() -> list[AdversaryTechnique]:
    return [dict(item) for item in ADVERSARY_TECHNIQUE_CATALOG]


def get_adversary_technique(technique_id: str) -> AdversaryTechnique | None:
    key = str(technique_id or "").strip().lower()
    for item in ADVERSARY_TECHNIQUE_CATALOG:
        if str(item.get("id") or "").lower() == key:
            return dict(item)
    return None


def _normalize_set(values: Any) -> set[str]:
    if isinstance(values, str):
        raw = [values]
    elif isinstance(values, (list, tuple, set)):
        raw = list(values)
    else:
        raw = []
    return {str(item).strip().lower() for item in raw if str(item or "").strip()}


def match_adversary_techniques(
    *,
    skill_id: str | None = None,
    tools: list[str] | None = None,
    phase_refs: list[str] | None = None,
    kill_chain_stage: str | None = None,
    limit: int = 5,
) -> list[AdversaryTechnique]:
    """Return catalog techniques compatible with the current tactical context."""
    skill_key = str(skill_id or "").strip().lower()
    tool_set = _normalize_set(tools)
    phase_set = {item.upper() for item in _normalize_set(phase_refs)}
    stage_key = str(kill_chain_stage or "").strip().upper()

    scored: list[tuple[int, int, str, AdversaryTechnique]] = []
    for item in ADVERSARY_TECHNIQUE_CATALOG:
        item_skills = _normalize_set(item.get("skills"))
        item_tools = _normalize_set(item.get("candidate_tools"))
        item_phases = {phase.upper() for phase in _normalize_set(item.get("app_phases"))}
        item_stage = str(item.get("kill_chain_stage") or "").strip().upper()

        score = 0
        if skill_key and skill_key in item_skills:
            score += 60
        if tool_set:
            score += min(30, len(tool_set & item_tools) * 10)
        if phase_set:
            score += min(20, len(phase_set & item_phases) * 8)
        if stage_key and stage_key == item_stage:
            score += 18
        if score <= 0:
            continue
        specificity_penalty = len(list(item.get("candidate_tools") or [])) + len(list(item.get("skills") or []))
        scored.append((score, specificity_penalty, str(item.get("id") or ""), dict(item)))

    scored.sort(key=lambda row: (-row[0], row[1], row[2]))
    return [item for _, _, _, item in scored[: max(1, limit)]]


def detection_proof_pack_template(technique: AdversaryTechnique | str) -> dict[str, Any]:
    item = get_adversary_technique(technique) if isinstance(technique, str) else dict(technique or {})
    technique_id = str((item or {}).get("id") or "")
    return {
        "technique_id": technique_id,
        "detection_status": "unknown",
        "correlation_id": "",
        "alert_id": "",
        "alert_source": "",
        "detection_latency_seconds": None,
        "rule_name": "",
        "telemetry_observed": [],
        "expected_telemetry": list((item or {}).get("expected_telemetry") or []),
        "control_gap": "",
        "defensive_success_criteria": list((item or {}).get("defensive_success_criteria") or []),
    }


def render_adversary_technique_catalog_for_prompt(limit: int = 10) -> str:
    items = []
    for technique in ADVERSARY_TECHNIQUE_CATALOG[: max(1, limit)]:
        refs = technique.get("framework_refs") or {}
        ref_text = ", ".join(
            f"{key}:{'/'.join(values[:3])}"
            for key, values in refs.items()
            if isinstance(values, list) and values
        )
        telemetry = [
            f"{source.get('source')}({', '.join(list(source.get('signals') or [])[:4])})"
            for source in list(technique.get("expected_telemetry") or [])[:3]
            if isinstance(source, dict)
        ]
        items.append(
            {
                "id": technique.get("id"),
                "name": technique.get("name"),
                "stage": technique.get("kill_chain_stage"),
                "refs": ref_text,
                "skills": list(technique.get("skills") or [])[:5],
                "tools": list(technique.get("candidate_tools") or [])[:6],
                "control_objectives": list(technique.get("control_objectives") or [])[:3],
                "expected_telemetry": telemetry,
                "safe_execution": technique.get("safe_execution"),
            }
        )
    return json.dumps(items, ensure_ascii=False, indent=2)


__all__ = [
    "ADVERSARY_TECHNIQUE_CATALOG",
    "detection_proof_pack_template",
    "get_adversary_technique",
    "list_adversary_techniques",
    "match_adversary_techniques",
    "render_adversary_technique_catalog_for_prompt",
]
