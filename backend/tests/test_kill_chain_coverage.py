from app.graph.kill_chain import advance_kill_chain_stage


def _runs(*tools: str) -> list[str]:
    return [f"step|http://target.local|{tool}" for tool in tools]


def test_recon_holds_until_two_p04_parameter_tools_run() -> None:
    state = {
        "kill_chain_stage": "RECONNAISSANCE",
        "detected_tech_stack": ["asp.net", "iis"],
        "executed_tool_runs": _runs(
            "subfinder",
            "amass",
            "dnsx",
            "dnsenum",
            "nmap",
            "naabu",
            "httpx",
            "whatweb",
            "code-analyzer",
            "katana",
            "gau",
            "arjun",
        ),
    }

    new_stage, advanced, reason = advance_kill_chain_stage(state)

    assert new_stage == "RECONNAISSANCE"
    assert advanced is False
    assert reason.startswith("missing_min_tools:P04 Parameter Discovery")


def test_recon_advances_after_two_p04_parameter_tools_run() -> None:
    state = {
        "kill_chain_stage": "RECONNAISSANCE",
        "detected_tech_stack": ["asp.net", "iis"],
        "executed_tool_runs": _runs(
            "subfinder",
            "amass",
            "dnsx",
            "dnsenum",
            "nmap",
            "naabu",
            "httpx",
            "whatweb",
            "code-analyzer",
            "katana",
            "gau",
            "arjun",
            "paramspider",
        ),
    }

    new_stage, advanced, reason = advance_kill_chain_stage(state)

    assert new_stage == "VULNERABILITY_ANALYSIS"
    assert advanced is True
    assert reason == "criteria_met"


def test_vulnerability_analysis_requires_nuclei_and_nikto() -> None:
    missing_nikto = {
        "kill_chain_stage": "VULNERABILITY_ANALYSIS",
        "executed_tool_runs": _runs("nuclei", "sslscan", "curl-headers", "nmap-http-enum", "wafw00f"),
    }
    new_stage, advanced, reason = advance_kill_chain_stage(missing_nikto)

    assert new_stage == "VULNERABILITY_ANALYSIS"
    assert advanced is False
    assert reason == "missing_group:nikto"

    complete = {
        "kill_chain_stage": "VULNERABILITY_ANALYSIS",
        "executed_tool_runs": _runs("nuclei", "nikto", "sslscan", "curl-headers", "nmap-http-enum"),
    }
    new_stage, advanced, reason = advance_kill_chain_stage(complete)

    assert new_stage == "EXPLOITATION"
    assert advanced is True
    assert reason == "criteria_met"
