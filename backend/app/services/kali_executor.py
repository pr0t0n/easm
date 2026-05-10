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


logger = logging.getLogger(__name__)


# ── Configuration ────────────────────────────────────────────────────────────
def _runner_url() -> str:
    return str(os.getenv("KALI_RUNNER_URL", "http://kali_runner:8088")).rstrip("/")


def kali_enabled_for_tool(tool_name: str) -> bool:
    """Back-compat helper: true only when a Kali profile exists."""
    name = str(tool_name or "").strip().lower()
    return bool(name and name in TOOL_TO_PROFILE)


# ── Tool name → profile id mapping ───────────────────────────────────────────
# Profiles live in kali-runner/profiles/*.yaml. The agent uses tool names from
# tool_catalog.py — we translate at the dispatch boundary so the rest of the
# codebase is unaffected by Kali.
TOOL_TO_PROFILE: dict[str, str] = {
    # Reconnaissance
    "subfinder": "subfinder_passive",
    "amass": "amass_enum",
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
    "nikto": "nikto_basic",
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
    "wapiti": "wapiti_scan",
    "wpscan": "wpscan_basic",
    "interactsh-client": "interactsh_oob",
    "subjack": "subjack_takeover",

    # Installation / C2 / AOO
    "hydra": "hydra_wordlist_auth",
    "medusa": "medusa_smb",
    "crackmapexec": "crackmapexec_smb",
    "jwt_tool": "jwt_tool_audit",
    "semgrep": "semgrep_sast",
    "bandit": "bandit_python",
    "trivy": "trivy_fs",
    "gitleaks": "gitleaks_secrets",
    "retire": "retire_js",
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
    scan_id: Optional[int] = None,
    scan_mode: str = "unit",
    poll_interval: float = 3.0,
    max_wait: int = 1800,
) -> dict[str, Any]:
    """Dispatches `tool` to the Kali runner via HTTP and waits for completion.

    Returns a dict matching the shape produced by `run_tool_execution` so
    downstream code (`_run_tools_and_collect`) needs no special-case branch.
    """
    profile = TOOL_TO_PROFILE.get(str(tool_name or "").strip().lower())
    if not profile:
        return _kali_failure(tool_name, target, scan_mode, "no_profile_mapping")

    # Rewrite operator-friendly localhost into a docker-routable hostname.
    # We keep the original in the failure trail for audit.
    original_target = target
    target = normalize_target_for_kali(target)

    base = _runner_url()
    started = time.perf_counter()
    try:
        post = requests.post(
            f"{base}/jobs",
            json={
                "profile": profile,
                "target": target,
                "scan_id": scan_id,
                "tool": tool_name,
                "original_target": original_target if original_target != target else None,
            },
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

    return normalize_kali_result(tool_name, target, scan_mode, result)


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
