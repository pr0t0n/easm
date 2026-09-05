"""HTTP client for the Kali runner sidecar.

Workers call `execute_via_kali(tool, target, ...)` which:
  1. Maps `tool_name` → `profile` via TOOL_TO_PROFILE
  2. POSTs /jobs to the Kali runner
  3. Polls GET /jobs/{id} until terminal
  4. Returns a dict shaped exactly like the legacy `_execute_local` result
     so downstream parsing in workflow.py keeps working unchanged.

There is no local fallback. If the runner is unreachable or the tool has no
mapped profile, the workflow receives a structured error.
"""
from __future__ import annotations

import logging
import os
import re
import time
from typing import Any, Optional

import requests

from app.services.guardrail_policy import sanitize_tool_args


logger = logging.getLogger(__name__)


# ── Configuration ────────────────────────────────────────────────────────────
def _runner_url() -> str:
    return str(os.getenv("KALI_RUNNER_URL", "http://kali_runner:8088")).rstrip("/")


def resolve_authorized_scope_for_dispatch(scan_id: Any) -> list[str]:
    """Roots (domains/IPs/CIDRs) `scan_id` is authorized to touch.

    The Kali runner's own `/jobs` endpoint fail-closes (400) any request whose
    `authorized_scope` is empty (SEC-001) — every dispatch path must supply
    it, not just the work-queue path that already resolves this correctly.
    Returns [] (and lets the runner reject the job) for a non-integer/missing
    scan_id — there is no ScanJob to derive scope from.
    """
    if not isinstance(scan_id, int):
        return []
    try:
        from app.db.session import SessionLocal
        from app.services.scan_scope import authorized_scope_for_scan

        db = SessionLocal()
        try:
            return authorized_scope_for_scan(db, scan_id)
        finally:
            db.close()
    except Exception:
        logger.warning("resolve_authorized_scope_for_dispatch failed for scan_id=%s", scan_id, exc_info=True)
        return []


def _record_dispatch_audit_event(
    *, tool_name: str, profile: str | None, target: str, scan_id: Any, job_id: str,
) -> None:
    """Best-effort durable audit record for a direct (non-MCP) Kali dispatch.

    MCP-001: browser_capture_service.py, exploit_browser_xss.py and
    business_logic_test.py all call execute_via_kali directly, bypassing
    MCP's own request audit trail entirely. Auditing here, rather than at
    each of those call sites, covers all of them (and any future direct
    caller) from one place. Never allowed to block or fail the actual
    dispatch — audit-write failures are logged and swallowed.
    """
    try:
        from app.db.session import SessionLocal
        from app.services.audit_service import log_audit

        db = SessionLocal()
        try:
            log_audit(
                db,
                event_type="kali.direct_dispatch",
                message=f"Direct Kali dispatch tool={tool_name} profile={profile} target={target}",
                scan_job_id=scan_id if isinstance(scan_id, int) else None,
                metadata={
                    "tool": tool_name,
                    "profile": profile,
                    "target": target,
                    "job_id": job_id,
                    "execution_path": "direct_kali_bypasses_mcp",
                },
            )
            db.commit()
        finally:
            db.close()
    except Exception:
        logger.warning("kali dispatch audit write failed tool=%s job_id=%s", tool_name, job_id, exc_info=True)


def cancel_scan_jobs_in_kali_runner(
    scan_id: int,
    *,
    reason: str = "cancelled_by_scan_control",
    timeout: int = 15,
) -> dict[str, Any]:
    """Cancel queued/running Kali runner jobs for a scan.

    Celery revoke only stops the Python task.  Tool subprocesses launched in
    the Kali sidecar live in a different process tree and must be cancelled
    explicitly, otherwise stopped/deleted scans can keep generating network
    activity and contaminate the next scan of the same target.
    """
    base = _runner_url()
    try:
        response = requests.post(
            f"{base}/jobs/cancel",
            params={"scan_id": int(scan_id), "reason": str(reason or "cancelled_by_scan_control")},
            timeout=timeout,
        )
        response.raise_for_status()
        payload = response.json()
        if not isinstance(payload, dict):
            payload = {"raw": payload}
        return {"ok": True, **payload}
    except Exception as exc:  # noqa: BLE001
        logger.warning("kali_runner scan cancel failed scan_id=%s: %s", scan_id, exc)
        return {"ok": False, "scan_id": scan_id, "error": str(exc)}


def kali_enabled_for_tool(tool_name: str) -> bool:
    """Back-compat helper: true only when a Kali profile exists."""
    return bool(profile_for_tool(tool_name))


# ── Batch profile mapping ─────────────────────────────────────────────────────
# When multiple targets are provided, prefer these batch profiles that accept
# a targets file (-iL / -list / -l) so the tool runs once for ALL hosts.
# This eliminates the serialised 1-by-1 loop and lets nmap/naabu/nuclei/httpx
# parallelise internally.
BATCH_TOOL_TO_PROFILE: dict[str, str] = {
    "naabu":      "naabu_top1000_batch",
    "nmap":       "nmap_service_detect_batch",
    "httpx":      "httpx_probe_batch",
    "dnsx":       "dnsx_resolve_batch",
    "nuclei":     "nuclei_cves_batch",
    "nuclei-cves": "nuclei_cves_batch",
    "nmap-vulscan": "nmap_vuln_scripts_batch",
    "subjack":    "domain_takeover_batch",
}

# ── Tool name → profile id mapping ───────────────────────────────────────────
# Profiles live in kali-runner/profiles/*.yaml. The agent uses tool names from
# tool_catalog.py — we translate at the dispatch boundary so the rest of the
# codebase is unaffected by Kali.
TOOL_TO_PROFILE: dict[str, str] = {
    # Reconnaissance
    "subfinder": "subfinder_passive",
    "amass": "amass_enum",
    "amass-brute": "amass_brute",
    "amass-intel": "amass_intel",
    "ghdb-public-indexes": "ghdb_public_indexes",
    "sublist3r": "sublist3r_basic",
    "findomain": "findomain_passive",
    "dnsrecon-brt": "dnsrecon_brute",
    "dnsrecon-zt": "dnsrecon_zone_transfer",
    "dnsenum": "dnsenum_basic",
    "assetfinder": "assetfinder_passive",
    "dnsx": "dnsx_resolve",
    "shuffledns": "shuffledns_brute",
    "alterx": "alterx_permutations",
    "naabu": "naabu_top1000",
    "nmap": "nmap_service_detect",
    "masscan": "masscan_full",
    "httpx": "httpx_probe",
    "whatweb": "whatweb_fingerprint",
    "wafw00f": "wafw00f_detect",
    "sslscan": "sslscan_audit",
    "testssl": "testssl_audit",
    "katana": "katana_crawl",
    "hakrawler": "hakrawler_crawl",
    "gospider": "gospider_crawl",
    "gau": "gau_archives",
    "waybackurls": "waybackurls_archives",
    "arjun": "arjun_param_discover",
    "paramspider": "paramspider_mining",
    "curl-headers": "curl_headers",
    "curl": "curl_probe",
    "linkfinder": "linkfinder_js",
    "whatweb-basic": "whatweb_fingerprint",

    # Weaponization / Vuln Scanning
    "nuclei": "nuclei_cves",
    "nuclei-cves": "nuclei_cves",
    "nuclei-rce": "nuclei_rce",
    "nuclei-auth": "nuclei_auth",
    "nuclei-auth-bypass": "nuclei_auth",
    "nuclei-deserialization": "nuclei_deserialization",
    "nuclei-sqli": "nuclei_sqli",
    "nuclei-ssti": "nuclei_ssti",
    "nuclei-xxe": "nuclei_xxe",
    "nuclei-crlf": "nuclei_crlf",
    "nuclei-ssrf": "nuclei_ssrf",
    "nuclei-xss": "nuclei_xss",
    "nuclei-csrf": "nuclei_csrf",
    "nuclei-idor": "nuclei_idor",
    "nuclei-redirect": "nuclei_open_redirect",
    "nuclei-jwt": "nuclei_jwt",
    "nuclei-exposure": "nuclei_exposure",
    "nuclei-js-secrets": "nuclei_js_secrets",
    "nuclei-js-analysis": "nuclei_js_analysis",
    "nuclei-lfi": "nuclei_lfi",
    "nuclei-misconfiguration": "nuclei_misconfiguration",
    "nuclei-file-upload": "nuclei_file_upload",
    "nuclei-graphql": "nuclei_graphql",
    "nuclei-swagger": "nuclei_swagger",
    "nuclei-cloud": "nuclei_cloud",
    "nuclei-cors": "nuclei_cors",
    "nuclei-race": "nuclei_race",
    "nuclei-takeover": "nuclei_takeover",
    "nmap-vulscan": "nmap_vuln_scripts",
    "nmap-vuln": "nmap_vuln_scripts",
    "nmap-db-creds": "nmap_db_credential_probe",
    "nmap-http-enum": "nmap_http_enum",
    "nmap-smb-vuln": "nmap_smb_vuln",
    "nmap-dns-vuln": "nmap_dns_vuln",
    "nmap-ssh-audit": "nmap_ssh_audit",
    "nmap-ssl-vuln": "nmap_ssl_vuln",
    "nikto": "nikto_basic",
    # OWASP ZAP profiles
    "zap-baseline": "zap_baseline",   # passive scan + quick spider
    "zap-ajax": "zap_ajax_spider",    # AJAX spider for SPAs
    "zap-active": "zap_active_scan",  # full active scan (OWASP Top 10)
    "zap-api": "zap_api_scan",        # OpenAPI/Swagger-driven scan
    "shodan-cli": "shodan_lookup",
    "theharvester": "theharvester_passive",
    "h8mail": "h8mail_breach",
    "trufflehog": "trufflehog_secrets",

    # Delivery / Exploitation
    "ffuf": "ffuf_dirs",
    "ffuf-files": "ffuf_files",
    "ffuf-params": "ffuf_param_names",
    "ffuf-values": "ffuf_param_values",
    "ffuf-post": "ffuf_post_form",
    "wfuzz": "wfuzz_param_names",
    "gobuster": "gobuster_dir",
    "feroxbuster": "feroxbuster_recursive",
    "dirsearch": "dirsearch_paths",
    "dirsearch-api": "dirsearch_api_conventions",
    "dirsearch-api-post": "dirsearch_api_conventions_post",
    "sqlmap": "sqlmap_basic",
    "dalfox": "dalfox_xss",
    "browser-xss": "browser_xss",  # headless chromium → dispara XSS client-side (DOM)
    "chromium-capture": "chromium_capture",  # CDP: captura requisicoes/storage/cookies p/ analise BL
    "wapiti": "wapiti_scan",
    "wpscan": "wpscan_basic",
    "interactsh-client": "interactsh_oob",
    "subjack": "subjack_takeover",

    # Installation / C2 / AOO
    "hydra": "hydra_wordlist_auth",
    "medusa": "medusa_smb",
    "crackmapexec": "crackmapexec_smb",
    "jwt_tool": "jwt_tool_audit",
    # Backend-local SAST. Semgrep needs source/artifact context and should not
    # be counted as a Kali web target scanner.
    "semgrep": "semgrep_backend",
    "bandit": "bandit_python",
    "trivy": "trivy_fs",
    "gitleaks": "gitleaks_secrets",
    "retire": "retire_js",
    "manual_scope_review": "manual_scope_review",
    "manual_review": "manual_review",
    "report-builder": "report_builder",

    # Backend-local virtual tool (no Kali profile). Sentinel value is
    # checked by `worker_dispatcher.execute_tool_with_workers` to short-
    # circuit the dispatch into `app.services.code_analyzer.run_as_tool`.
    "code-analyzer": "code_analyzer_backend",
    # Backend-local: teste ativo de business logic (worker_dispatcher short-circuit).
    "bl-test": "business_logic_backend",

    # Backend-local P18-P22 phase reviewers (offensive_operator_runner short-
    # circuits these into phase_control_tools.run_phase_control_tool — never
    # dispatched to Kali).
    "credential-boundary-review": "backend_control",
    "post-exploitation-boundary-review": "backend_control",
    "attack-path-correlator": "backend_control",
    "evidence-adjudicator": "backend_control",
    "report-snapshot-builder": "backend_control",

    # BAS (Breach & Attack Simulation) — proxychains-wrapped profiles, ONLY
    # ever dispatched by bas_dispatcher.py. "-bas" suffixed so these never
    # collide with the same tool's untunneled profile used by the external
    # P01-P22 pipeline (e.g. plain "crackmapexec" above).
    "crackmapexec-bas": "crackmapexec_smb_bas_tunnel",
    "enum4linux-ng-bas": "enum4linux_ng_basic",
    "bloodhound-python-bas": "bloodhound_python_collect",
    "getuserspns-bas": "impacket_kerberoast",
    "ntlmrelayx-bas": "impacket_ntlmrelayx",
    "curl-vmware-bas": "vmware_vcenter_default_creds_check",
    "nmap-firewall-bas": "firewall_segmentation_probe",
    "smbmap-bas": "smbmap_share_discovery",
    "ldapsearch-bas": "ad_ldap_scouting",
    "curl-clouddir-bas": "cloud_directory_scouting_check",
    "nmap-portscan-bas": "port_service_scan",
    "curl-chatwebhook-bas": "chat_webhook_discovery_check",
    "zerologon-bas": "netlogon_zerologon_check",
    "nikto-owasp-bas": "owasp_web_app_scan",
    "curl-pipelinelogs-bas": "pipeline_secrets_harvest",
    "gitleaks-bas": "source_code_secrets_scan",
    # Deliberately dispatched (not gated future_agent_required) per an
    # explicit product decision: let the architectural limit (proxychains
    # can't help a bind()/listen() tool reach a network segment it was never
    # on) show up as a real, observed dispatch failure/no-signal result,
    # rather than a silent guardrail block. See bas_internal.yaml's
    # responder_analyze_attempt for the full rationale.
    "responder-bas": "responder_analyze_attempt",
}


def canonical_tool_name(tool_name: str) -> str:
    name = str(tool_name or "").strip().lower()
    if name.startswith("nuclei-cve-"):
        return "nuclei-cves"
    return name


def profile_for_tool(tool_name: str, *, batch: bool = False) -> str | None:
    name = canonical_tool_name(tool_name)
    if batch:
        return BATCH_TOOL_TO_PROFILE.get(name) or TOOL_TO_PROFILE.get(name)
    return TOOL_TO_PROFILE.get(name)


# ── Public API: HTTP execution ───────────────────────────────────────────────
TERMINAL_STATES = {"done", "failed", "timeout", "skipped"}
LOST_JOB_RETRIES = 2

# Hosts that the operator types but that, inside the Kali container, would
# loop back to the runner itself (useless). Translate them at dispatch time
# to `host.docker.internal` — kept here in the BACKEND on purpose so we can
# evolve routing without rebuilding the Kali image.
_LOCAL_HOST_ALIASES = {"localhost", "127.0.0.1", "0.0.0.0", "::1"}


def normalize_target_for_kali(target: str) -> str:
    """Rewrites `localhost` and 127.0.0.1 to `host.docker.internal` so the
    Kali container can reach the operator's machine. Preserves scheme/port/
    path/query/fragment.

    The Kali image already resolves `host.docker.internal` (Linux via
    `extra_hosts: host-gateway`, Mac/Windows natively).
    """
    raw = str(target or "").strip()
    if not raw:
        return raw
    # No scheme: simple host token like "localhost:3001/path"
    has_scheme = "://" in raw
    work = raw if has_scheme else f"//{raw}"
    try:
        from urllib.parse import urlparse, urlunparse
        parsed = urlparse(work)
    except Exception:  # noqa: BLE001
        return raw
    host = (parsed.hostname or "").lower()
    if host not in _LOCAL_HOST_ALIASES:
        return raw
    new_host = "host.docker.internal"
    new_netloc = f"{new_host}:{parsed.port}" if parsed.port else new_host
    if not has_scheme:
        # Preserve the operator's original style (no scheme) but still emit
        # the rewritten host so anything downstream that splits on `://`
        # gets the docker-routable hostname.
        suffix = parsed.path or ""
        if parsed.query:
            suffix = f"{suffix}?{parsed.query}"
        return f"{new_netloc}{suffix}"
    rewritten = urlunparse((
        parsed.scheme or "http",
        new_netloc,
        parsed.path or "",
        parsed.params or "",
        parsed.query or "",
        parsed.fragment or "",
    ))
    return rewritten


def execute_via_kali(
    tool_name: str,
    target: str,
    *,
    targets: list[str] | None = None,
    scan_id: Optional[int] = None,
    scan_mode: str = "unit",
    poll_interval: float = 3.0,
    max_wait: int = 1800,
    skill_context: dict[str, Any] | None = None,
    extra_args: list[str] | None = None,
    env_vars: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Dispatches `tool` to the Kali runner via HTTP and waits for completion.

    When `targets` contains more than one host, the call automatically upgrades
    to a batch profile (e.g. naabu_top1000_batch, nmap_service_detect_batch)
    so the tool runs ONCE against ALL hosts instead of being called N times in
    a serial loop.  Tools without a batch profile fall back to single-target.

    Returns a dict matching the shape produced by `run_tool_execution` so
    downstream code (`_run_tools_and_collect`) needs no special-case branch.
    """
    norm_tool = str(tool_name or "").strip().lower()
    profile_tool = canonical_tool_name(norm_tool)

    # Deduplicate and normalise the batch list (skip blanks / duplicates)
    batch_targets: list[str] = []
    if targets and len(targets) > 1:
        seen: set[str] = set()
        for t in targets:
            nt = normalize_target_for_kali(str(t or "").strip())
            if nt and nt not in seen:
                seen.add(nt)
                batch_targets.append(nt)

    # Choose batch or single-target profile
    use_batch = len(batch_targets) > 1 and profile_tool in BATCH_TOOL_TO_PROFILE
    if use_batch:
        profile = profile_for_tool(profile_tool, batch=True)
        # Use the first target as the nominal "target" field (runner uses it
        # only for logging when target_type=targets_file; the real targets come
        # from the file written from req.targets).
        dispatch_target = batch_targets[0]
        dispatch_targets = batch_targets
    else:
        profile = profile_for_tool(norm_tool)
        if not profile:
            return _kali_failure(tool_name, target, scan_mode, "no_profile_mapping")
        dispatch_target = normalize_target_for_kali(target)
        dispatch_targets = []

    original_target = target
    base = _runner_url()
    started = time.perf_counter()
    try:
        # P2 — o guardrail tem que rodar no caminho DIRETO ao Kali também. Antes
        # a sanitização só acontecia no gateway MCP; quando MCP_EXECUTE_TOOLS_VIA_MCP
        # é false (ou no caminho direto), flags destrutivas (--dump, --os-shell,
        # --file-write…) passavam sem filtro. SSOT em guardrail_policy.sanitize_tool_args.
        _raw_extra = [str(arg) for arg in (extra_args or []) if str(arg).strip()]
        _clean_extra, _removed_extra = sanitize_tool_args(norm_tool or tool_name, _raw_extra)
        if _removed_extra:
            logger.warning(
                "guardrail stripped args tool=%s removed=%s", norm_tool or tool_name, _removed_extra
            )
        payload: dict[str, Any] = {
            "profile": profile,
            "target": dispatch_target,
            "scan_id": scan_id,
            "tool": tool_name,
            "timeout": int(max_wait),
            "skill_context": dict(skill_context or {}),
            "extra_args": _clean_extra,
            "authorized_scope": resolve_authorized_scope_for_dispatch(scan_id),
        }
        _env_vars = dict(env_vars or {})
        _auth_headers = _auth_headers_from_skill_context(skill_context)
        if norm_tool == "jwt_tool" and not _env_vars.get("SCAN_JWT_TOKEN"):
            _bearer = _auth_headers.get("Authorization") or ""
            if _bearer.lower().startswith("bearer "):
                _env_vars["SCAN_JWT_TOKEN"] = _bearer.split(" ", 1)[1].strip()
        if _env_vars:
            payload["env_vars"] = _env_vars
        if _auth_headers:
            payload["auth_headers"] = _auth_headers
        if dispatch_targets:
            payload["targets"] = dispatch_targets
        if original_target != dispatch_target and not dispatch_targets:
            payload["original_target"] = original_target

        post = requests.post(
            f"{base}/jobs",
            json=payload,
            timeout=10,
        )
        post.raise_for_status()
        body = post.json()
        job_id = body["job_id"]
    except Exception as exc:  # noqa: BLE001
        logger.warning("kali_runner enqueue failed: %s", exc)
        return _kali_failure(tool_name, target, scan_mode, f"enqueue_error: {exc}")

    # MCP-001: this direct-to-runner path has no equivalent of MCP's own
    # request-level audit log, so record one here — this is the ONE choke
    # point shared by every caller of execute_via_kali (direct/legacy
    # fallback, browser capture, business-logic capture), rather than
    # threading an audit call through each of them individually.
    _record_dispatch_audit_event(
        tool_name=tool_name, profile=profile, target=dispatch_target,
        scan_id=scan_id, job_id=job_id,
    )

    # Poll until terminal (job runner side does the heavy lifting)
    lost_job_count = 0
    while True:
        elapsed = time.perf_counter() - started
        if elapsed > max_wait:
            return _kali_failure(
                tool_name,
                target,
                scan_mode,
                f"client_timeout after {int(elapsed)}s",
                dispatch_task_id=job_id,
            )
        try:
            r = requests.get(f"{base}/jobs/{job_id}", timeout=10)
            r.raise_for_status()
            status = r.json().get("status", "unknown")
            lost_job_count = 0
        except requests.HTTPError as exc:
            status_code = exc.response.status_code if exc.response is not None else None
            if status_code == 404:
                lost_job_count += 1
                logger.warning(
                    "kali_runner job %s not found while polling (%s/%s)",
                    job_id,
                    lost_job_count,
                    LOST_JOB_RETRIES,
                )
                if lost_job_count >= LOST_JOB_RETRIES:
                    return _kali_failure(
                        tool_name,
                        target,
                        scan_mode,
                        f"runner_lost_job:{job_id}",
                        dispatch_task_id=job_id,
                    )
                time.sleep(min(poll_interval, 1.0))
                continue
            logger.warning("kali_runner poll failed: %s", exc)
            time.sleep(poll_interval)
            continue
        except requests.RequestException as exc:
            logger.warning("kali_runner poll failed: %s", exc)
            time.sleep(poll_interval)
            continue
        except Exception as exc:  # noqa: BLE001
            logger.warning("kali_runner poll failed: %s", exc)
            time.sleep(poll_interval)
            continue
        if status in TERMINAL_STATES:
            break
        time.sleep(poll_interval)

    # Fetch the rich result
    try:
        rr = requests.get(f"{base}/jobs/{job_id}/result", timeout=15)
        rr.raise_for_status()
        result = rr.json()
    except requests.HTTPError as exc:
        status_code = exc.response.status_code if exc.response is not None else None
        if status_code == 404:
            return _kali_failure(
                tool_name,
                target,
                scan_mode,
                f"runner_lost_result:{job_id}",
                dispatch_task_id=job_id,
            )
        return _kali_failure(
            tool_name,
            target,
            scan_mode,
            f"result_fetch_error: {exc}",
            dispatch_task_id=job_id,
        )
    except Exception as exc:  # noqa: BLE001
        return _kali_failure(
            tool_name,
            target,
            scan_mode,
            f"result_fetch_error: {exc}",
            dispatch_task_id=job_id,
        )

    normalized = normalize_kali_result(tool_name, target, scan_mode, result)
    if skill_context:
        normalized["skill_context"] = dict(skill_context)
        if skill_context.get("skill_id"):
            normalized["skill_id"] = skill_context.get("skill_id")
    return normalized


def normalize_kali_result(
    tool_name: str, target: str, scan_mode: str, result: dict
) -> dict[str, Any]:
    runner_status = result.get("status")
    # The runner already applies each profile's allowed_return_codes and
    # skip markers before emitting its terminal status. Trust that decision
    # here so tools like gospider can treat rc=1/no-output as a completed
    # no-finding run instead of a platform error.
    stdout = result.get("stdout") or ""
    stderr = result.get("stderr") or ""
    stderr_lower = stderr.lower()
    # A profile's allowed_return_codes (e.g. [0, 1]) exists for a tool's own
    # legitimate "ran fine, nothing found" exit codes -- it can't distinguish
    # that from the tool crashing before it ever ran its scan and happening
    # to exit with one of those same codes (missing binary, or a Python
    # traceback from a broken/mismatched interpreter environment). Catch
    # both patterns here instead of trusting allowed_return_codes alone.
    tool_execution_failed = (
        "can't load process" in stderr_lower
        or "no such file or directory" in stderr_lower
        or "traceback (most recent call last):" in stderr_lower
    )
    is_ok = runner_status == "done" and not tool_execution_failed
    status = "executed" if is_ok else "failed"
    if runner_status == "skipped":
        status = "skipped"
    open_ports = result.get("open_ports") or _extract_nmap_open_ports(stdout)
    nmap_summary = result.get("nmap_summary") or _extract_nmap_summary(stdout)
    return {
        "tool": tool_name,
        "target": target,
        "scan_mode": scan_mode,
        "status": status,
        "command": result.get("command") or "",
        "return_code": result.get("return_code"),
        "stdout": stdout,
        "stderr": stderr,
        "parsed": result.get("parsed"),
        "egress_context": result.get("egress_context") or {},
        "egress_observation": result.get("egress_observation") or {},
        "source_agent_id": "kali_runner",
        "source_agent_name": "Kali Runner",
        "dispatch_task_name": f"kali:{result.get('profile')}",
        "dispatch_task_id": result.get("job_id"),
        "evidence_path": result.get("workdir"),
        "duration_seconds": result.get("duration_seconds"),
        "open_ports": open_ports,
        "nmap_summary": nmap_summary,
    }


def _extract_nmap_open_ports(stdout: str) -> list[dict[str, Any]]:
    current_host = ""
    ports: list[dict[str, Any]] = []
    for raw_line in str(stdout or "").splitlines():
        line = raw_line.strip()
        if line.lower().startswith("nmap scan report for"):
            target_text = line[len("Nmap scan report for "):].strip()
            match = re.search(r"\((\d{1,3}(?:\.\d{1,3}){3})\)", target_text)
            current_host = match.group(1) if match else target_text.split()[0]
            continue
        match = re.match(r"^(\d+)/(tcp|udp)\s+open\s+(\S+)(?:\s+(.*))?$", line, re.IGNORECASE)
        if not match or not current_host:
            continue
        ports.append({
            "host": current_host,
            "port": int(match.group(1)),
            "protocol": match.group(2).lower(),
            "service": match.group(3),
            "version": (match.group(4) or "").strip(),
            "source": "nmap",
        })
    return ports[:500]


def _extract_nmap_summary(stdout: str) -> dict[str, Any]:
    summary: dict[str, Any] = {}
    report_count = 0
    no_open_count = 0
    for raw_line in str(stdout or "").splitlines():
        line = raw_line.strip()
        if line.lower().startswith("nmap scan report for"):
            report_count += 1
        if line.lower().startswith("all ") and " scanned ports " in line.lower() and " ignored states" in line.lower():
            no_open_count += 1
        match = re.match(
            r"^Nmap done:\s+(?P<addresses>\d+)\s+IP addresses\s+\((?P<hosts>\d+)\s+hosts up\)\s+scanned in\s+(?P<seconds>[\d.]+)\s+seconds",
            line,
            re.IGNORECASE,
        )
        if match:
            summary.update({
                "ip_addresses": int(match.group("addresses")),
                "hosts_up": int(match.group("hosts")),
                "duration_seconds": float(match.group("seconds")),
            })
    if report_count:
        summary.setdefault("reported_hosts", report_count)
    if no_open_count:
        summary.setdefault("hosts_without_open_ports", no_open_count)
    return summary


def _kali_failure(
    tool_name: str,
    target: str,
    scan_mode: str,
    reason: str,
    *,
    dispatch_task_id: str | None = None,
) -> dict[str, Any]:
    return {
        "tool": tool_name,
        "target": target,
        "scan_mode": scan_mode,
        "status": "error",
        "command": "",
        "return_code": None,
        "stdout": "",
        "stderr": "",
        "dispatch_error": reason,
        "source_agent_id": "kali_runner",
        "source_agent_name": "Kali Runner",
        "dispatch_task_id": dispatch_task_id,
        "open_ports": [],
    }


def _auth_headers_from_skill_context(skill_context: dict[str, Any] | None) -> dict[str, str]:
    ctx = dict(skill_context or {})
    auth = dict(ctx.get("auth_context") or {})
    headers = {str(k): str(v) for k, v in dict(auth.get("headers") or {}).items() if str(v).strip()}
    cookies = {str(k): str(v) for k, v in dict(auth.get("cookies") or {}).items() if str(v).strip()}
    if cookies and not any(k.lower() == "cookie" for k in headers):
        headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in cookies.items())
    return headers


def runner_health() -> dict[str, Any]:
    """Probes the runner. Used by /api/health and the dispatcher fallback."""
    try:
        r = requests.get(f"{_runner_url()}/healthz", timeout=5)
        r.raise_for_status()
        return {"reachable": True, **r.json()}
    except Exception as exc:  # noqa: BLE001
        return {"reachable": False, "error": str(exc)}
