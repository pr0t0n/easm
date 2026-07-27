from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_network_profiles_cannot_auto_expand_or_follow_redirects() -> None:
    source = (ROOT / "kali-runner" / "profiles" / "reconnaissance.yaml").read_text(encoding="utf-8")
    executable_lines = [line for line in source.splitlines() if not line.lstrip().startswith("#")]
    executable_source = "\n".join(executable_lines)
    assert '"-tls-probe"' not in executable_source
    assert '"-follow-redirects"' not in executable_source
    assert '"-L"' not in executable_source
    assert '"--location"' not in executable_source
    assert executable_source.count('"-location"') >= 2
    assert executable_source.count('"-dr"') >= 3
    assert '"--no-redirect"' in executable_source
    assert '"--whitelist-domain", "{host}"' in executable_source


def test_runner_requires_authorized_scope() -> None:
    runner_source = (ROOT / "kali-runner" / "runner.py").read_text(encoding="utf-8")
    assert 'raise HTTPException(status_code=400, detail="authorized_scope is required")' in runner_source
    assert 'return False, "no_authorized_scope_provided"' in runner_source


def test_runner_returns_durable_batch_input_manifest() -> None:
    runner_source = (ROOT / "kali-runner" / "runner.py").read_text(encoding="utf-8")

    assert "batch_targets: list[str]" in runner_source
    assert "batch_target_count: int" in runner_source
    assert "batch_target_file_sha256" in runner_source
    assert "materialized_targets = list(dict.fromkeys(" in runner_source
    assert "hashlib.sha256(" in runner_source


def test_runner_can_cancel_scan_jobs_without_leaving_subprocesses_alive() -> None:
    runner_source = (ROOT / "kali-runner" / "runner.py").read_text(encoding="utf-8")

    assert '@app.post("/jobs/cancel")' in runner_source
    assert "cancel_requested=True" in runner_source
    assert "_job_cancel_requested(job_id)" in runner_source
    assert "_kill_orphaned_process(pid_i, pgid_i)" in runner_source
    assert 'status="skipped"' in runner_source
    assert "scan_id: Optional[int] = None" in runner_source


def test_runner_stale_job_clock_uses_utc_and_kills_process_group() -> None:
    runner_source = (ROOT / "kali-runner" / "runner.py").read_text(encoding="utf-8")

    assert "datetime.now(timezone.utc).isoformat()" in runner_source
    assert "dt = dt.replace(tzinfo=timezone.utc)" in runner_source
    assert "_kill_orphaned_process(pid_i, pgid_i)" in runner_source
    assert "killed_process=" in runner_source
    assert "items = [_mark_stale_job_if_needed(job) for job in items]" in runner_source
    assert "hard_ceiling = timeout" in runner_source


def test_httpx_batch_profile_uses_conservative_waf_safe_concurrency() -> None:
    source = (ROOT / "kali-runner" / "profiles" / "reconnaissance.yaml").read_text(encoding="utf-8")
    section = source.split("httpx_probe_batch:", 1)[1].split("whatweb_fingerprint:", 1)[0]

    assert '"/opt/runner-scripts/httpx_proxy_wrapper.py"' in section
    assert '"-threads", "10"' in section
    assert '"-rate-limit", "20"' in section
    assert '"-retries", "2"' in section
    assert '"-timeout", "10"' in section


def test_httpx_single_profile_uses_proxy_wrapper_not_python_httpx_cli() -> None:
    source = (ROOT / "kali-runner" / "profiles" / "reconnaissance.yaml").read_text(encoding="utf-8")
    section = source.split("httpx_probe:", 1)[1].split("httpx_probe_batch:", 1)[0]

    assert '"/opt/runner-scripts/httpx_proxy_wrapper.py"' in section


def test_httpx_proxy_wrapper_does_not_force_unhealthy_proxy() -> None:
    source = (ROOT / "kali-runner" / "scripts" / "httpx_proxy_wrapper.py").read_text(encoding="utf-8")

    assert "proxy_unreachable" in source
    assert "fallback=direct" in source
    assert "socket.create_connection" in source
    assert "_proxy_clean_env" in source
    assert '"direct"' in source


def test_kali_proxy_is_health_checked_for_httpx_not_global() -> None:
    source = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    kali_section = source.split("\n  kali_runner:", 1)[1].split("\n    ports:", 1)[0]

    assert 'KALI_OUTBOUND_PROXY: "${KALI_OUTBOUND_PROXY:-http://192.168.65.7:3128}"' in kali_section
    assert 'HTTP_PROXY: "${KALI_HTTP_PROXY:-}"' in kali_section
    assert 'HTTPS_PROXY: "${KALI_HTTPS_PROXY:-}"' in kali_section


def test_naabu_batch_profile_avoids_resolver_and_nat_exhaustion() -> None:
    source = (ROOT / "kali-runner" / "profiles" / "reconnaissance.yaml").read_text(encoding="utf-8")
    section = source.split("naabu_top1000_batch:", 1)[1].split("httpx_probe:", 1)[0]

    assert '"-rate", "200"' in section
    assert '"-c", "10"' in section
    assert "timeout: 1200" in section


def test_subjack_batch_profile_matches_installed_cli_contract() -> None:
    source = (ROOT / "kali-runner" / "profiles" / "reconnaissance.yaml").read_text(encoding="utf-8")
    section = source.split("domain_takeover_batch:", 1)[1].split("nuclei_takeover:", 1)[0]

    assert '"subjack", "-w", "{target_file}"' in section
    assert '"-c"' not in section
