from __future__ import annotations

from app.services.scan_work_queue import (
    BATCH_CAPABLE_TOOLS,
    BATCH_PROFILE_OVERRIDE,
    _batch_tool_profile,
)


def test_batch_capable_tools_all_have_a_verified_batch_profile_override() -> None:
    # Every tool allowed to be dispatched as a "__batch__" work item must
    # resolve to a real <profile>_batch id — see the incident this guards
    # against: tools without one silently ran their default {host}/{url}
    # command against the literal string "__batch__".
    missing = BATCH_CAPABLE_TOOLS - set(BATCH_PROFILE_OVERRIDE)
    assert not missing, f"batch-capable tools without a verified batch profile: {missing}"


def test_batch_tool_profile_uses_the_batch_variant() -> None:
    assert _batch_tool_profile("naabu") == "naabu_top1000_batch"
    assert _batch_tool_profile("nmap") == "nmap_service_detect_batch"
    assert _batch_tool_profile("nmap-vulscan") == "nmap_vuln_scripts_batch"
    assert _batch_tool_profile("httpx") == "httpx_probe_batch"
    assert _batch_tool_profile("dnsx") == "dnsx_resolve_batch"
    assert _batch_tool_profile("subjack") == "domain_takeover_batch"
    assert _batch_tool_profile("nuclei") == "nuclei_cves_batch"
    assert _batch_tool_profile("nuclei-cves") == "nuclei_cves_batch"
    assert _batch_tool_profile("katana") == "katana_crawl_batch"
    assert _batch_tool_profile("nikto") == "nikto_basic_batch"


def test_tools_without_a_batch_profile_are_not_batch_capable() -> None:
    # These were removed from BATCH_CAPABLE_TOOLS because no <profile>_batch
    # exists for them in kali-runner/profiles/*.yaml — they must be
    # dispatched per-target (single_items), never as "__batch__".
    no_batch_profile = {
        "nmap-ssl", "nmap-vuln", "nmap-http",
        "katana-js", "hakrawler", "gospider",
        "whatweb", "whatweb-basic", "gau", "waybackurls",
        "nuclei-xss", "nuclei-sqli", "nuclei-ssrf", "nuclei-lfi",
        "nuclei-exposure", "nuclei-auth", "nuclei-race", "nuclei-cors", "nuclei-csrf",
    }
    assert not (no_batch_profile & BATCH_CAPABLE_TOOLS)
