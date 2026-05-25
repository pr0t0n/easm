"""Kali runner — HTTP API that executes vulnerability analysis tools inside the Kali container.

Architecture:
  POST /jobs           → enqueue {profile, target, scan_id, tool} → returns job_id
  GET  /jobs/{id}      → status (queued | running | done | failed | timeout)
  GET  /jobs/{id}/result → final stdout/stderr/parsed JSON + evidence path
  GET  /profiles       → list of available tool profiles
  GET  /healthz        → liveness

All jobs run in a ThreadPoolExecutor with per-tool timeouts. Evidence is
written to /workspace/{scan_id}/{tool}/{job_id}/ for forensic auditability.
"""
from __future__ import annotations

import json
import os
import ipaddress
import re
import shlex
import socket
import subprocess
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, Future
from datetime import datetime
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlparse, urlunparse

import yaml
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field


# ── Configuration ────────────────────────────────────────────────────────────
WORKSPACE = Path(os.getenv("KALI_WORKSPACE", "/workspace"))
JOBS_DIR = WORKSPACE / ".runner_jobs"
PROFILES_DIR = Path(__file__).parent / "profiles"
MAX_PARALLEL = int(os.getenv("KALI_MAX_PARALLEL", "8"))
DEFAULT_TIMEOUT = int(os.getenv("KALI_DEFAULT_TIMEOUT", "300"))
WORKSPACE_TTL_HOURS = int(os.getenv("KALI_WORKSPACE_TTL_HOURS", "24"))
VOLATILE_JOB_STATES = {"queued", "running"}
TERMINAL_STATES = {"done", "failed", "timeout", "skipped"}
STALE_JOB_GRACE_SECONDS = int(os.getenv("KALI_STALE_JOB_GRACE_SECONDS", "30"))

WORKSPACE.mkdir(parents=True, exist_ok=True)
JOBS_DIR.mkdir(parents=True, exist_ok=True)


# ── Profile loading ──────────────────────────────────────────────────────────
def _load_profiles() -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    if not PROFILES_DIR.exists():
        return out
    for path in sorted(PROFILES_DIR.glob("*.yaml")) + sorted(PROFILES_DIR.glob("*.yml")):
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            for name, spec in data.items():
                if not isinstance(spec, dict):
                    continue
                spec.setdefault("source_file", path.name)
                out[name] = spec
        except Exception as exc:  # noqa: BLE001
            print(f"[profiles] failed to load {path}: {exc}")
    return out


PROFILES: dict[str, dict[str, Any]] = _load_profiles()
print(f"[profiles] loaded {len(PROFILES)} profiles")


# ── Target safety guardrails ─────────────────────────────────────────────────
# Hard block on loopback (127.0.0.1) and link-local. The 10/172.16-31/192.168
# nets used to be blocked too, but the runner shares the docker bridge with
# in-scope test targets (juice-shop, internal staging hosts), so we trust the
# upstream ScanAuthorization gate instead. Operators who need stricter rules
# can set ALLOWED_TARGETS regex via env.
PRIVATE_NET_RE = re.compile(
    r"^(?:127\.|0\.0\.0\.0|169\.254\.|::1$|fe80:)"
)


def _is_unsafe_target(target: str) -> tuple[bool, str]:
    t = (target or "").strip()
    if not t:
        return True, "empty target"
    # Strip URL prefix to evaluate just the host portion
    host = t
    for prefix in ("http://", "https://"):
        if host.startswith(prefix):
            host = host[len(prefix):]
    host = host.split("/")[0].split(":")[0]
    if PRIVATE_NET_RE.match(host):
        return True, f"loopback/link-local blocked: {host}"
    if any(ch in t for ch in [";", "&&", "||", "`", "$(", "\n", "\r"]):
        return True, f"shell metacharacter in target: {t!r}"
    return False, ""


# ── Job model ────────────────────────────────────────────────────────────────
class JobRequest(BaseModel):
    profile: str = Field(..., description="Profile id (see GET /profiles)")
    target: str
    targets: list[str] = Field(default_factory=list, description="Optional batch target list materialized as {target_file}")
    scan_id: Optional[int] = None
    tool: Optional[str] = Field(None, description="Override profile tool name (legacy bridge)")
    extra_args: list[str] = Field(default_factory=list)
    timeout: Optional[int] = None
    auth_headers: dict[str, str] = Field(default_factory=dict, description="Authentication headers injected into tool command")


class JobStatus(BaseModel):
    job_id: str
    profile: str
    tool: str
    target: str
    status: str
    command: Optional[str] = None
    enqueued_at: str
    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    duration_seconds: Optional[float] = None
    return_code: Optional[int] = None
    error: Optional[str] = None
    workdir: Optional[str] = None


class JobResult(JobStatus):
    stdout: Optional[str] = None
    stderr: Optional[str] = None
    parsed: Optional[Any] = None


_JOBS_LOCK = threading.Lock()
_EXECUTOR = ThreadPoolExecutor(max_workers=MAX_PARALLEL, thread_name_prefix="kali-job")


def _job_path(job_id: str) -> Path:
    safe_job_id = re.sub(r"[^A-Za-z0-9_.-]", "_", str(job_id or ""))
    return JOBS_DIR / f"{safe_job_id}.json"


def _json_safe_job(job: dict[str, Any]) -> dict[str, Any]:
    safe: dict[str, Any] = {}
    for key, value in job.items():
        try:
            json.dumps(value)
            safe[key] = value
        except TypeError:
            safe[key] = str(value)
    return safe


def _persist_job_record(job: dict[str, Any]) -> None:
    job_id = str(job.get("job_id") or "").strip()
    if not job_id:
        return
    try:
        path = _job_path(job_id)
        tmp_path = path.with_suffix(".tmp")
        tmp_path.write_text(
            json.dumps(_json_safe_job(job), ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        tmp_path.replace(path)
    except Exception as exc:  # noqa: BLE001
        print(f"[jobs] failed to persist {job_id}: {exc}")


def _load_job_from_disk(job_id: str) -> dict[str, Any] | None:
    path = _job_path(job_id)
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        print(f"[jobs] failed to load {job_id}: {exc}")
        return None
    if not isinstance(data, dict):
        return None
    data["job_id"] = str(data.get("job_id") or job_id)
    return data


def _load_persisted_jobs() -> dict[str, dict[str, Any]]:
    jobs: dict[str, dict[str, Any]] = {}
    for path in sorted(JOBS_DIR.glob("*.json")):
        job = _load_job_from_disk(path.stem)
        if not job:
            continue
        if job.get("status") in VOLATILE_JOB_STATES:
            job["status"] = "failed"
            job["error"] = job.get("error") or "runner_restarted_before_job_finished"
            job["finished_at"] = job.get("finished_at") or datetime.utcnow().isoformat()
            _persist_job_record(job)
        jobs[str(job["job_id"])] = job
    return jobs


_JOBS: dict[str, dict[str, Any]] = _load_persisted_jobs()
print(f"[jobs] loaded {len(_JOBS)} persisted jobs")


def _parse_iso_ts(value: Any) -> float | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value)).timestamp()
    except Exception:
        return None


def _job_timeout_seconds(job: dict[str, Any]) -> int:
    try:
        if job.get("timeout"):
            return int(job.get("timeout") or DEFAULT_TIMEOUT)
    except Exception:
        pass
    profile = PROFILES.get(str(job.get("profile") or "")) or {}
    try:
        return int(profile.get("timeout") or DEFAULT_TIMEOUT)
    except Exception:
        return DEFAULT_TIMEOUT


def _mark_stale_job_if_needed(job: dict[str, Any]) -> dict[str, Any]:
    status = str(job.get("status") or "")
    if status not in VOLATILE_JOB_STATES:
        return job
    started_or_enqueued = _parse_iso_ts(job.get("started_at") or job.get("enqueued_at"))
    if started_or_enqueued is None:
        return job
    timeout = _job_timeout_seconds(job)
    if time.time() - started_or_enqueued <= timeout + STALE_JOB_GRACE_SECONDS:
        return job
    job_id = str(job.get("job_id") or "")
    if not job_id:
        return job
    return _set_job_fields(
        job_id,
        status="timeout",
        finished_at=datetime.utcnow().isoformat(),
        duration_seconds=round(time.time() - started_or_enqueued, 3),
        error=f"runner watchdog marked stale {status} job after {timeout}s timeout",
        stdout=job.get("stdout") or "",
        stderr=job.get("stderr") or "",
    )


def _set_job_fields(job_id: str, **fields: Any) -> dict[str, Any]:
    with _JOBS_LOCK:
        job = _JOBS[job_id]
        job.update(fields)
        snapshot = dict(job)
    # Write to disk only for terminal state, stdout arrival, or finished_at
    # (the final bookkeeping write).  All other intermediate updates (running,
    # workdir, command) stay in-memory — keeps crash-recovery intact while
    # eliminating ~8 of the 11 disk writes per job.
    if fields.get("status") in TERMINAL_STATES or "stdout" in fields or "finished_at" in fields:
        _persist_job_record(snapshot)
    return snapshot


def _get_job_record(job_id: str) -> dict[str, Any] | None:
    with _JOBS_LOCK:
        job = _JOBS.get(job_id)
    if job:
        return _mark_stale_job_if_needed(job)

    job = _load_job_from_disk(job_id)
    if not job:
        return None
    with _JOBS_LOCK:
        _JOBS[str(job["job_id"])] = job
    return _mark_stale_job_if_needed(job)


def _new_job_record(req: JobRequest, profile: dict[str, Any]) -> dict[str, Any]:
    timeout = int(req.timeout or profile.get("timeout") or DEFAULT_TIMEOUT)
    return {
        "job_id": str(uuid.uuid4()),
        "profile": req.profile,
        "tool": profile.get("tool") or req.tool or req.profile,
        "target": req.target or (f"{len(req.targets)} targets" if req.targets else ""),
        "scan_id": req.scan_id,
        "status": "queued",
        "enqueued_at": datetime.utcnow().isoformat(),
        "started_at": None,
        "finished_at": None,
        "duration_seconds": None,
        "return_code": None,
        "command": None,
        "stdout": None,
        "stderr": None,
        "parsed": None,
        "error": None,
        "workdir": None,
        "timeout": timeout,
    }


def _render_template(value: str, context: dict[str, str]) -> str:
    # Profiles may use either Python format placeholders ({host}) or the
    # operator-facing contract placeholders ({{domain}}, {{url}}, {{out}}).
    template = re.sub(r"\{\{\s*([A-Za-z_][A-Za-z0-9_]*)\s*\}\}", r"{\1}", str(value))
    return template.format(**context)


def _inject_auth_headers(argv: list[str], auth_headers: dict[str, str], tool: str) -> list[str]:
    """Inject authentication headers into supported tool commands.

    Different tools use different flags for headers:
      ffuf, gobuster, nuclei, httpx, feroxbuster, wfuzz, dirsearch: -H "Key: Value"
      curl: -H "Key: Value"
      sqlmap: --header="Key: Value"  OR  --cookie="..." for cookies
      dalfox: --header "Key: Value"
      wpscan: --headers "Key: Value"
    """
    if not auth_headers:
        return argv
    tool_lower = tool.lower().strip()
    headers_pairs = [f"{k}: {v}" for k, v in auth_headers.items() if v]
    if not headers_pairs:
        return argv

    new_argv = list(argv)

    # Tools that use -H "Key: Value" syntax
    H_SYNTAX = {"ffuf", "gobuster", "nuclei", "httpx", "feroxbuster", "wfuzz", "dirsearch", "curl"}
    # Tools that use --header
    LONG_HEADER_SYNTAX = {"sqlmap", "dalfox"}
    # Tools that use --headers (plural, with all in one)
    HEADERS_SYNTAX = {"wpscan"}

    if tool_lower in H_SYNTAX or any(tool_lower.startswith(t) for t in H_SYNTAX):
        for pair in headers_pairs:
            new_argv.extend(["-H", pair])
    elif tool_lower in LONG_HEADER_SYNTAX:
        if tool_lower == "sqlmap":
            # sqlmap special-cases Cookie via --cookie
            cookie_val = auth_headers.get("Cookie") or auth_headers.get("cookie")
            other = {k: v for k, v in auth_headers.items() if k.lower() != "cookie" and v}
            if cookie_val:
                new_argv.append(f"--cookie={cookie_val}")
            if other:
                # --headers="Header1: v1\nHeader2: v2"
                joined = "\\n".join(f"{k}: {v}" for k, v in other.items())
                new_argv.append(f'--headers={joined}')
        else:  # dalfox
            for pair in headers_pairs:
                new_argv.extend(["--header", pair])
    elif tool_lower in HEADERS_SYNTAX:
        joined = ",".join(headers_pairs)
        new_argv.extend(["--headers", joined])
    # For unsupported tools, leave argv unchanged.
    return new_argv


def _build_command(
    profile: dict[str, Any],
    target: str,
    extra_args: list[str],
    workdir: Path | None = None,
    target_file: Path | None = None,
) -> list[str]:
    """Materialize the argv for a profile. Profile spec:
        tool: subfinder
        cmd:  ["subfinder", "-d", "{host}", "-silent"]
        timeout: 300
    """
    raw_cmd = profile.get("cmd") or []
    raw = shlex.split(raw_cmd) if isinstance(raw_cmd, str) else list(raw_cmd)
    if not raw:
        raise ValueError(f"profile {profile.get('source_file')} missing 'cmd'")
    needs_host_ip = any(_template_needs_host_ip(str(part)) for part in raw)
    context = _target_context(
        target,
        workdir=workdir,
        target_file=target_file,
        resolve_ip=needs_host_ip,
    )
    materialized = [_render_template(str(part), context) for part in raw]
    materialized.extend(str(a) for a in (extra_args or []))
    return materialized


def _target_context(
    target: str,
    workdir: Path | None = None,
    target_file: Path | None = None,
    resolve_ip: bool = False,
) -> dict[str, str]:
    raw = str(target or "").strip()
    parsed = urlparse(raw if "://" in raw else f"http://{raw}")
    host = parsed.hostname or raw.replace("http://", "").replace("https://", "").split("/")[0]
    port = str(parsed.port or "")
    netloc = f"{host}:{parsed.port}" if parsed.port else host
    scheme = parsed.scheme if "://" in raw else "http"
    path = parsed.path or ""
    query = parsed.query or ""
    url = urlunparse((scheme, netloc, path, "", query, ""))
    https_url = urlunparse(("https", netloc, path, "", query, ""))
    host_ip = _resolve_host_ip(host) if resolve_ip else host
    context = {
        "target": raw,
        "url": url,
        "https_url": https_url,
        "host": host,
        "host_ip": host_ip,
        "domain": host,
        "subdomain": host,
        "netloc": netloc,
        "port": port,
        "scheme": scheme,
        "path": raw,
        "out": str(workdir or WORKSPACE),
        "target_file": str(target_file or ""),
        **{f"env_{key}": value for key, value in os.environ.items()},
    }
    for env_name in (
        "SHODAN_API_KEY",
        "SCAN_AUTH_USERNAME",
        "SCAN_AUTH_PASSWORD",
        "SCAN_AUTH_USERLIST",
        "SCAN_AUTH_PASSLIST",
        "SCAN_AUTH_PROTOCOL",
        "SCAN_JWT_TOKEN",
        "SCAN_FUZZ_PARAM",
        "SCAN_FUZZ_POST_DATA",
        "SCAN_FUZZ_CONTENT_TYPE",
    ):
        context.setdefault(f"env_{env_name}", "")
    if not context.get("env_SCAN_FUZZ_CONTENT_TYPE", "").strip():
        context["env_SCAN_FUZZ_CONTENT_TYPE"] = "application/x-www-form-urlencoded"
    return context


def _resolve_host_ip(host: str) -> str:
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    try:
        result = subprocess.run(
            ["getent", "ahosts", host],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        for line in (result.stdout or "").splitlines():
            candidate = line.split()[0] if line.split() else ""
            try:
                ipaddress.ip_address(candidate)
                return candidate
            except ValueError:
                continue
    except Exception:
        pass
    socket.setdefaulttimeout(5)
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        for info in infos:
            candidate = str(info[4][0])
            try:
                ipaddress.ip_address(candidate)
                return candidate
            except ValueError:
                continue
    except OSError:
        return host
    return host


def _template_needs_host_ip(template: str) -> bool:
    return "{host_ip}" in template or "{{host_ip}}" in template


def _materialize_template(
    template: str | None,
    target: str,
    workdir: Path | None = None,
) -> str | None:
    if template is None:
        return None
    raw_template = str(template)
    return _render_template(
        raw_template,
        _target_context(
            target,
            workdir=workdir,
            resolve_ip=_template_needs_host_ip(raw_template),
        ),
    )


def _target_validation_error(profile: dict[str, Any], target: str) -> str:
    target_type = str(profile.get("target_type") or "").strip().lower()
    if target_type in {"resolved_ip", "ip"}:
        context = _target_context(target, resolve_ip=True)
        host = context.get("host", "")
        host_ip = context.get("host_ip", "")
        try:
            ipaddress.ip_address(host_ip)
        except ValueError:
            return f"target_type {target_type} requires a resolvable IP for host: {host}"
        return ""
    if target_type in {"target_list", "targets_file"}:
        return ""
    if target_type != "local_path":
        return ""
    raw = str(target or "").strip()
    if not raw:
        return "target_type local_path requires a non-empty directory path"
    candidate = Path(raw).expanduser()
    if not candidate.exists():
        return f"target_type local_path requires an existing directory: {candidate}"
    if not candidate.is_dir():
        return f"target_type local_path requires a directory, got file: {candidate}"
    return ""


def _parse_output(profile: dict[str, Any], stdout: str) -> Any:
    """Best-effort parse based on profile.parser (json|lines|raw)."""
    parser = (profile.get("parser") or "raw").lower()
    if parser == "json":
        try:
            return json.loads(stdout) if stdout.strip() else None
        except json.JSONDecodeError:
            return None
    if parser == "jsonl":
        out = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return out
    if parser == "lines":
        return [l for l in stdout.splitlines() if l.strip()]
    return None


def _run_job(job_id: str, profile: dict[str, Any], req: JobRequest) -> None:
    """Worker thread — executes the tool, streams stdout/stderr to disk."""
    started = time.perf_counter()
    # Batch the two initial field writes (status=running + workdir) into one
    # lock acquisition instead of two.
    tool_name = str(profile.get("tool") or req.tool or req.profile)
    workdir = WORKSPACE / str(req.scan_id or "ad-hoc") / tool_name / job_id
    workdir.mkdir(parents=True, exist_ok=True)
    job = _set_job_fields(
        job_id,
        status="running",
        started_at=datetime.utcnow().isoformat(),
        workdir=str(workdir),
    )
    # Refresh tool_name from stored job record in case it differs from profile
    tool_name = str(job.get("tool") or tool_name)

    try:
        _set_job_fields(job_id, stage="checking_env")
        missing_env = [
            str(name)
            for name in (profile.get("requires_env") or [])
            if not str(os.getenv(str(name), "")).strip()
        ]
        if missing_env:
            _set_job_fields(
                job_id,
                status="skipped",
                return_code=0,
                command=f"{profile.get('tool') or req.profile} <requires_env:{','.join(missing_env)}>",
                stdout="",
                stderr=f"missing required environment: {', '.join(missing_env)}",
            )
            return

        _set_job_fields(job_id, stage="checking_required_scheme")
        required_schemes = {
            str(item).strip().lower()
            for item in (profile.get("requires_scheme") or [])
            if str(item).strip()
        }
        # Auto-promote bare hostnames to https when profile requires a scheme.
        # The backend sends 'example.com' but TLS tools need 'https://example.com'.
        if required_schemes and "://" not in str(req.target):
            preferred = "https" if "https" in required_schemes else next(iter(required_schemes))
            req.target = f"{preferred}://{req.target}"
        _set_job_fields(job_id, stage="materializing_target_scheme")
        target_scheme = _target_context(req.target).get("scheme", "").lower()
        if required_schemes and target_scheme not in required_schemes:
            _set_job_fields(
                job_id,
                status="skipped",
                return_code=0,
                command=f"{profile.get('tool') or req.profile} <requires_scheme:{','.join(sorted(required_schemes))}>",
                stdout="",
                stderr=f"target scheme {target_scheme or '-'} not supported by this profile",
            )
            return

        _set_job_fields(job_id, stage="validating_target")
        target_error = _target_validation_error(profile, req.target)
        if target_error:
            _set_job_fields(
                job_id,
                status="skipped",
                return_code=0,
                command=f"{profile.get('tool') or req.profile} <target_validation>",
                stdout="",
                stderr=target_error,
            )
            return

        # Tier 3: if a batch target list was provided, write it to disk so
        # profiles can reference it as {target_file}.  Only meaningful when the
        # profile's cmd actually contains {target_file}; otherwise it's ignored.
        batch_target_file: Path | None = None
        if req.targets:
            _set_job_fields(job_id, stage="writing_targets_file")
            batch_target_file = workdir / "targets.txt"
            batch_target_file.write_text(
                "\n".join(str(t).strip() for t in req.targets if str(t).strip()),
                encoding="utf-8",
            )

        _set_job_fields(job_id, stage="building_command")
        argv = _build_command(profile, req.target, req.extra_args, workdir=workdir, target_file=batch_target_file)
        # Inject authentication headers into supported tools (ffuf, curl, gobuster,
        # nuclei, httpx, wfuzz, sqlmap, dalfox, wpscan, feroxbuster, dirsearch).
        if req.auth_headers:
            _set_job_fields(job_id, stage="injecting_auth_headers")
            argv = _inject_auth_headers(argv, req.auth_headers, str(profile.get("tool") or ""))
        timeout = int(req.timeout or profile.get("timeout") or DEFAULT_TIMEOUT)
        _set_job_fields(job_id, stage="materializing_stdin")
        stdin_text = _materialize_template(profile.get("stdin_template"), req.target, workdir=workdir)
        command = " ".join(shlex.quote(a) for a in argv)
        _set_job_fields(job_id, stage="executing", command=command)

        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            input=stdin_text,
            timeout=timeout,
            check=False,
            cwd=str(workdir),
        )
        stdout, stderr = proc.stdout or "", proc.stderr or ""
        return_code = proc.returncode

        (workdir / "stdout.txt").write_text(stdout, encoding="utf-8", errors="replace")
        (workdir / "stderr.txt").write_text(stderr, encoding="utf-8", errors="replace")
        (workdir / "exit_code.txt").write_text(str(return_code), encoding="utf-8")
        (workdir / "command.txt").write_text(command, encoding="utf-8")

        parse_source = stdout
        output_file_template = profile.get("output_file")
        if output_file_template:
            output_file = Path(str(_materialize_template(str(output_file_template), req.target, workdir=workdir)))
            if output_file.exists() and output_file.is_file():
                try:
                    parse_source = output_file.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    parse_source = stdout

        parsed = _parse_output(profile, parse_source)
        if parsed is not None:
            try:
                (workdir / "parsed.json").write_text(
                    json.dumps(parsed, ensure_ascii=False, indent=2),
                    encoding="utf-8",
                )
            except Exception:  # noqa: BLE001
                pass

        allowed_return_codes = {int(c) for c in (profile.get("allowed_return_codes") or [0])}
        skipped_markers = [str(m).lower() for m in (profile.get("skip_if_output_contains") or [])]
        combined_lower = f"{stdout}\n{stderr}".lower()
        status = "done" if return_code in allowed_return_codes else "failed"
        if skipped_markers and any(marker in combined_lower for marker in skipped_markers):
            status = "skipped"

        # Cap raised to 500K for stdout (was 100K) because verbose scanners
        # like nikto/nuclei can emit >150K of useful output where the
        # critical `+` finding lines are at the *start*, not the end.
        # Truncating the head silently dropped 12+ findings/scan. The
        # parsers read all lines and only retain matches, so larger
        # buffers are safe; stderr stays at 20K (mostly progress/errors).
        _set_job_fields(
            job_id,
            command=command,
            status=status,
            return_code=return_code,
            stdout=stdout[-500_000:] if stdout else "",
            stderr=stderr[-20_000:] if stderr else "",
            parsed=parsed,
        )
    except subprocess.TimeoutExpired as exc:
        _set_job_fields(
            job_id,
            command=command,
            status="timeout",
            error=f"timeout after {exc.timeout}s",
            stdout=str(exc.stdout or ""),
            stderr=str(exc.stderr or ""),
        )
    except Exception as exc:  # noqa: BLE001
        _set_job_fields(job_id, status="failed", error=f"{type(exc).__name__}: {exc}")
    finally:
        # Batch finished_at + duration into one call; persist because finished_at
        # should survive a restart even if status was already written.
        _set_job_fields(
            job_id,
            finished_at=datetime.utcnow().isoformat(),
            duration_seconds=round(time.perf_counter() - started, 3),
        )


def _run_job_safely(job_id: str, profile: dict[str, Any], req: JobRequest) -> None:
    try:
        _run_job(job_id, profile, req)
    except Exception as exc:  # noqa: BLE001
        _set_job_fields(
            job_id,
            status="failed",
            error=f"uncaught runner error {type(exc).__name__}: {exc}",
            finished_at=datetime.utcnow().isoformat(),
        )


def _cleanup_old_workspace(ttl_hours: int = WORKSPACE_TTL_HOURS) -> dict[str, int]:
    """Delete job work-dirs and JSON records older than ttl_hours.

    Only removes entries that are not in VOLATILE_JOB_STATES (queued/running)
    so that an in-progress job's files are never touched.
    """
    cutoff = time.time() - ttl_hours * 3600
    removed_dirs = removed_jsons = 0

    # Collect job_ids that are still active so we never delete their files.
    with _JOBS_LOCK:
        active_ids = {jid for jid, j in _JOBS.items() if j.get("status") in VOLATILE_JOB_STATES}

    # Remove stale .runner_jobs JSON files.
    for json_path in list(JOBS_DIR.glob("*.json")):
        if json_path.stem in active_ids:
            continue
        try:
            if json_path.stat().st_mtime < cutoff:
                json_path.unlink(missing_ok=True)
                removed_jsons += 1
        except OSError:
            pass

    # Remove stale per-scan/tool/job_id work directories.
    for scan_dir in WORKSPACE.iterdir():
        if scan_dir.name.startswith(".") or not scan_dir.is_dir():
            continue
        for tool_dir in scan_dir.iterdir():
            if not tool_dir.is_dir():
                continue
            for job_dir in tool_dir.iterdir():
                if not job_dir.is_dir() or job_dir.name in active_ids:
                    continue
                try:
                    if job_dir.stat().st_mtime < cutoff:
                        import shutil as _shutil
                        _shutil.rmtree(job_dir, ignore_errors=True)
                        removed_dirs += 1
                except OSError:
                    pass

    # Evict cleaned-up job_ids from the in-memory cache.
    if removed_jsons:
        with _JOBS_LOCK:
            stale = [jid for jid in list(_JOBS) if jid not in active_ids
                     and not (JOBS_DIR / f"{jid}.json").exists()]
            for jid in stale:
                _JOBS.pop(jid, None)

    print(f"[cleanup] removed {removed_dirs} job dirs, {removed_jsons} JSON records (ttl={ttl_hours}h)")
    return {"removed_dirs": removed_dirs, "removed_jsons": removed_jsons}


def _schedule_periodic_cleanup(interval_hours: int = 6) -> None:
    """Run _cleanup_old_workspace every interval_hours using a daemon timer thread."""
    def _run():
        _cleanup_old_workspace()
        t = threading.Timer(interval_hours * 3600, _run)
        t.daemon = True
        t.start()
    t = threading.Timer(interval_hours * 3600, _run)
    t.daemon = True
    t.start()


# Run cleanup at startup to reclaim disk from previous container runs,
# then schedule periodic cleanup every 6 hours.
_cleanup_old_workspace()
_schedule_periodic_cleanup(interval_hours=int(os.getenv("KALI_CLEANUP_INTERVAL_HOURS", "6")))


# ── FastAPI surface ──────────────────────────────────────────────────────────
app = FastAPI(title="ScriptKidd.o Kali Runner", version="1.0.0")


@app.get("/healthz")
def healthz() -> dict[str, Any]:
    with _JOBS_LOCK:
        jobs_snapshot = list(_JOBS.values())
    for job in jobs_snapshot:
        _mark_stale_job_if_needed(job)
    with _JOBS_LOCK:
        active_jobs = sum(1 for j in _JOBS.values() if j["status"] in VOLATILE_JOB_STATES)
        total_jobs = len(_JOBS)
    return {
        "status": "ok",
        "profiles_loaded": len(PROFILES),
        "kali_tools_detected": len(_discover_kali_tools()),
        "active_jobs": active_jobs,
        "total_jobs": total_jobs,
        "workspace": str(WORKSPACE),
    }


@app.post("/cleanup")
def trigger_cleanup(ttl_hours: int = WORKSPACE_TTL_HOURS) -> dict[str, Any]:
    """Delete job dirs and JSON records older than ttl_hours (default: KALI_WORKSPACE_TTL_HOURS)."""
    result = _cleanup_old_workspace(ttl_hours=ttl_hours)
    return {"status": "ok", **result}


@app.get("/profiles")
def list_profiles() -> dict[str, Any]:
    def _profile_payload(name: str, spec: dict[str, Any]) -> dict[str, Any]:
        command = list(spec.get("cmd") or [])
        return {
            "tool": spec.get("tool", name),
            "category": spec.get("category"),
            "phase": spec.get("phase"),
            "description": spec.get("description"),
            "timeout": spec.get("timeout", DEFAULT_TIMEOUT),
            "source": spec.get("source_file"),
            "command": command,
            "command_executable": command[0] if command else spec.get("tool", name),
        }

    return {
        "count": len(PROFILES),
        "profiles": {
            name: _profile_payload(name, spec)
            for name, spec in PROFILES.items()
        },
    }


@app.get("/tools")
def list_kali_tools() -> dict[str, Any]:
    tools = _discover_kali_tools()
    profiles_by_tool: dict[str, list[str]] = {}
    for profile_name, spec in PROFILES.items():
        profiles_by_tool.setdefault(str(spec.get("tool") or profile_name), []).append(profile_name)
        cmd = list(spec.get("cmd") or [])
        if cmd:
            profiles_by_tool.setdefault(str(cmd[0]), []).append(profile_name)
    return {
        "count": len(tools),
        "tools": [
            {
                "name": name,
                "path": path,
                "profiles": sorted(profiles_by_tool.get(name, [])),
                "profiled": bool(profiles_by_tool.get(name)),
            }
            for name, path in sorted(tools.items())
        ],
    }


def _discover_kali_tools() -> dict[str, str]:
    ignored = {
        "python", "python3", "pip", "pip3", "sh", "bash", "dash", "env",
        "cat", "cp", "mv", "rm", "ls", "find", "grep", "awk", "sed",
    }
    out: dict[str, str] = {}
    for raw_dir in os.getenv("PATH", "").split(":"):
        directory = Path(raw_dir)
        if not directory.exists() or not directory.is_dir():
            continue
        for item in directory.iterdir():
            try:
                if not item.is_file() or not os.access(item, os.X_OK):
                    continue
            except OSError:
                continue
            name = item.name
            if name in ignored or name.startswith(("python", "pip")):
                continue
            out.setdefault(name, str(item))
    return out


@app.post("/profiles/reload")
def reload_profiles() -> dict[str, Any]:
    global PROFILES  # noqa: PLW0603
    PROFILES = _load_profiles()
    return {"reloaded": True, "count": len(PROFILES)}


@app.post("/jobs")
def enqueue_job(req: JobRequest) -> dict[str, Any]:
    profile = PROFILES.get(req.profile)
    if not profile:
        raise HTTPException(status_code=404, detail=f"profile not found: {req.profile}")

    unsafe, reason = _is_unsafe_target(req.target)
    if unsafe:
        raise HTTPException(status_code=400, detail=f"unsafe target: {reason}")

    job = _new_job_record(req, profile)
    job_id = job["job_id"]
    with _JOBS_LOCK:
        _JOBS[job_id] = job
    _persist_job_record(job)

    _EXECUTOR.submit(_run_job_safely, job_id, profile, req)
    return {
        "job_id": job_id,
        "status": "queued",
        "profile": req.profile,
        "tool": job["tool"],
        "target": req.target,
    }


@app.get("/jobs/{job_id}")
def get_job(job_id: str) -> JobStatus:
    job = _get_job_record(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="job not found")
    return JobStatus(**{k: job.get(k) for k in JobStatus.model_fields.keys()})


@app.get("/jobs/{job_id}/result")
def get_job_result(job_id: str, stdout_cap: int = 0) -> JobResult:
    """Return job result.

    stdout_cap: if > 0, truncate stdout/stderr in the response to this many bytes.
    The full output is always available in workdir/stdout.txt.
    Default 0 = no cap (full stdout returned).
    """
    job = _get_job_record(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="job not found")
    data = {k: job.get(k) for k in JobResult.model_fields.keys()}
    if stdout_cap > 0:
        if data.get("stdout") and len(str(data["stdout"])) > stdout_cap:
            data["stdout"] = str(data["stdout"])[-stdout_cap:]
        if data.get("stderr") and len(str(data["stderr"])) > stdout_cap:
            data["stderr"] = str(data["stderr"])[-stdout_cap:]
    return JobResult(**data)


@app.get("/jobs")
def list_jobs(status: Optional[str] = None, limit: int = 50) -> dict[str, Any]:
    with _JOBS_LOCK:
        items = list(_JOBS.values())
    if status:
        items = [j for j in items if j["status"] == status]
    items.sort(key=lambda j: j.get("enqueued_at", ""), reverse=True)
    return {"count": len(items), "items": items[:limit]}
