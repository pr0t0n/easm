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
import time
from typing import Any, Optional

import requests

from app.services.guardrail_policy import sanitize_tool_args


logger = logging.getLogger(__name__)


# ── Configuration ────────────────────────────────────────────────────────────
def _runner_url() -> str:
    return str(os.getenv("KALI_RUNNER_URL", "http://kali_runner:8088")).rstrip("/")


def kali_enabled_for_tool(tool_name: str) -> bool:
    """Back-compat helper: true only when a Kali profile exists."""
    name = str(tool_name or "").strip().lower()
    return bool(name and name in TOOL_TO_PROFILE)


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

    # Weaponization / Vuln Scanning
    "nuclei": "nuclei_cves",
    "nmap-vulscan": "nmap_vuln_scripts",
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
}


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
    use_batch = len(batch_targets) > 1 and norm_tool in BATCH_TOOL_TO_PROFILE
    if use_batch:
        profile = BATCH_TOOL_TO_PROFILE[norm_tool]
        # Use the first target as the nominal "target" field (runner uses it
        # only for logging when target_type=targets_file; the real targets come
        # from the file written from req.targets).
        dispatch_target = batch_targets[0]
        dispatch_targets = batch_targets
    else:
        profile = TOOL_TO_PROFILE.get(norm_tool)
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
            "skill_context": dict(skill_context or {}),
            "extra_args": _clean_extra,
        }
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
    is_ok = runner_status == "done"
    status = "executed" if is_ok else "failed"
    if runner_status == "skipped":
        status = "skipped"
    return {
        "tool": tool_name,
        "target": target,
        "scan_mode": scan_mode,
        "status": status,
        "command": result.get("command") or "",
        "return_code": result.get("return_code"),
        "stdout": result.get("stdout") or "",
        "stderr": result.get("stderr") or "",
        "parsed": result.get("parsed"),
        "source_agent_id": "kali_runner",
        "source_agent_name": "Kali Runner",
        "dispatch_task_name": f"kali:{result.get('profile')}",
        "dispatch_task_id": result.get("job_id"),
        "evidence_path": result.get("workdir"),
        "duration_seconds": result.get("duration_seconds"),
        "open_ports": [],  # extracted later by workflow normalization, if applicable
    }


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


def runner_health() -> dict[str, Any]:
    """Probes the runner. Used by /api/health and the dispatcher fallback."""
    try:
        r = requests.get(f"{_runner_url()}/healthz", timeout=5)
        r.raise_for_status()
        return {"reachable": True, **r.json()}
    except Exception as exc:  # noqa: BLE001
        return {"reachable": False, "error": str(exc)}
