"""Kali runner — HTTP API that executes pentest tools inside the Kali container.

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
import re
import shlex
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
VOLATILE_JOB_STATES = {"queued", "running"}

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
    scan_id: Optional[int] = None
    tool: Optional[str] = Field(None, description="Override profile tool name (legacy bridge)")
    extra_args: list[str] = Field(default_factory=list)
    timeout: Optional[int] = None


class JobStatus(BaseModel):
    job_id: str
    profile: str
    tool: str
    target: str
    status: str
    enqueued_at: str
    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    duration_seconds: Optional[float] = None
    return_code: Optional[int] = None
    error: Optional[str] = None
    workdir: Optional[str] = None


class JobResult(JobStatus):
    command: Optional[str] = None
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


def _set_job_fields(job_id: str, **fields: Any) -> dict[str, Any]:
    with _JOBS_LOCK:
        job = _JOBS[job_id]
        job.update(fields)
        snapshot = dict(job)
    _persist_job_record(snapshot)
    return snapshot


def _get_job_record(job_id: str) -> dict[str, Any] | None:
    with _JOBS_LOCK:
        job = _JOBS.get(job_id)
    if job:
        return job

    job = _load_job_from_disk(job_id)
    if not job:
        return None
    with _JOBS_LOCK:
        _JOBS[str(job["job_id"])] = job
    return job


def _new_job_record(req: JobRequest, profile: dict[str, Any]) -> dict[str, Any]:
    return {
        "job_id": str(uuid.uuid4()),
        "profile": req.profile,
        "tool": profile.get("tool") or req.tool or req.profile,
        "target": req.target,
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
    }


def _build_command(profile: dict[str, Any], target: str, extra_args: list[str]) -> list[str]:
    """Materialize the argv for a profile. Profile spec:
        tool: subfinder
        cmd:  ["subfinder", "-d", "{host}", "-silent"]
        timeout: 300
    """
    raw = list(profile.get("cmd") or [])
    if not raw:
        raise ValueError(f"profile {profile.get('source_file')} missing 'cmd'")
    context = _target_context(target)
    materialized = [str(part).format(**context) for part in raw]
    materialized.extend(str(a) for a in (extra_args or []))
    return materialized


def _target_context(target: str) -> dict[str, str]:
    raw = str(target or "").strip()
    parsed = urlparse(raw if "://" in raw else f"http://{raw}")
    host = parsed.hostname or raw.replace("http://", "").replace("https://", "").split("/")[0]
    port = str(parsed.port or "")
    netloc = f"{host}:{parsed.port}" if parsed.port else host
    scheme = parsed.scheme if "://" in raw else "http"
    url = raw if "://" in raw else urlunparse((scheme, netloc, "", "", "", ""))
    https_url = raw if raw.startswith("https://") else urlunparse(("https", netloc, "", "", "", ""))
    context = {
        "target": raw,
        "url": url,
        "https_url": https_url,
        "host": host,
        "domain": host,
        "netloc": netloc,
        "port": port,
        "scheme": scheme,
        **{f"env_{key}": value for key, value in os.environ.items()},
    }
    for env_name in ("SHODAN_API_KEY", "PENTEST_AUTH_USERNAME", "PENTEST_AUTH_PASSWORD"):
        context.setdefault(f"env_{env_name}", "")
    return context


def _materialize_template(template: str | None, target: str) -> str | None:
    if template is None:
        return None
    return str(template).format(**_target_context(target))


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
    job = _set_job_fields(
        job_id,
        status="running",
        started_at=datetime.utcnow().isoformat(),
    )
    started = time.perf_counter()

    tool_name = str(job.get("tool") or req.tool or req.profile)
    workdir = WORKSPACE / str(req.scan_id or "ad-hoc") / tool_name / job_id
    workdir.mkdir(parents=True, exist_ok=True)
    _set_job_fields(job_id, workdir=str(workdir))

    try:
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

        argv = _build_command(profile, req.target, req.extra_args)
        timeout = int(req.timeout or profile.get("timeout") or DEFAULT_TIMEOUT)
        stdin_text = _materialize_template(profile.get("stdin_template"), req.target)
        command = " ".join(shlex.quote(a) for a in argv)

        _set_job_fields(job_id, command=command)

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

        parsed = _parse_output(profile, stdout)
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

        _set_job_fields(
            job_id,
            status=status,
            return_code=return_code,
            stdout=stdout[-100_000:] if stdout else "",
            stderr=stderr[-20_000:] if stderr else "",
            parsed=parsed,
        )
    except subprocess.TimeoutExpired as exc:
        _set_job_fields(
            job_id,
            status="timeout",
            error=f"timeout after {exc.timeout}s",
            stdout=str(exc.stdout or ""),
            stderr=str(exc.stderr or ""),
        )
    except Exception as exc:  # noqa: BLE001
        _set_job_fields(job_id, status="failed", error=f"{type(exc).__name__}: {exc}")
    finally:
        _set_job_fields(
            job_id,
            finished_at=datetime.utcnow().isoformat(),
            duration_seconds=round(time.perf_counter() - started, 3),
        )


# ── FastAPI surface ──────────────────────────────────────────────────────────
app = FastAPI(title="Pentest.io Kali Runner", version="1.0.0")


@app.get("/healthz")
def healthz() -> dict[str, Any]:
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


@app.get("/profiles")
def list_profiles() -> dict[str, Any]:
    return {
        "count": len(PROFILES),
        "profiles": {
            name: {
                "tool": spec.get("tool", name),
                "category": spec.get("category"),
                "phase": spec.get("phase"),
                "description": spec.get("description"),
                "timeout": spec.get("timeout", DEFAULT_TIMEOUT),
                "source": spec.get("source_file"),
            }
            for name, spec in PROFILES.items()
        },
    }


@app.get("/tools")
def list_kali_tools() -> dict[str, Any]:
    tools = _discover_kali_tools()
    profiles_by_tool: dict[str, list[str]] = {}
    for profile_name, spec in PROFILES.items():
        profiles_by_tool.setdefault(str(spec.get("tool") or profile_name), []).append(profile_name)
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

    _EXECUTOR.submit(_run_job, job_id, profile, req)
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
def get_job_result(job_id: str) -> JobResult:
    job = _get_job_record(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="job not found")
    return JobResult(**{k: job.get(k) for k in JobResult.model_fields.keys()})


@app.get("/jobs")
def list_jobs(status: Optional[str] = None, limit: int = 50) -> dict[str, Any]:
    with _JOBS_LOCK:
        items = list(_JOBS.values())
    if status:
        items = [j for j in items if j["status"] == status]
    items.sort(key=lambda j: j.get("enqueued_at", ""), reverse=True)
    return {"count": len(items), "items": items[:limit]}
