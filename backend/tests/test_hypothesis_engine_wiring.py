from __future__ import annotations

from app.services.offensive_operator_core import HypothesisEngine, create_offensive_state


def _evidence(evidence_id: str, tool_name: str, target: str, parsed_json: dict | None = None) -> dict:
    return {
        "evidence_id": evidence_id,
        "tool_name": tool_name,
        "target": target,
        "parsed_json": parsed_json or {},
    }


def test_update_from_evidence_goes_beyond_the_old_idor_ssrf_duo() -> None:
    state = create_offensive_state("app.example.com")
    state["known_assets"] = ["http://app.example.com/search?q=1"]
    engine = HypothesisEngine()

    hypotheses = engine.update_from_evidence(
        "P10", [_evidence("EV-1", "httpx", "http://app.example.com/search?q=1")], state
    )
    families = {h["family"] for h in hypotheses}

    # The old stub only ever produced idor/ssrf. "q" is a search-style param —
    # the ported engine's matrix maps it to sqli/xss/lfi/ssti/rce too.
    assert "sqli" in families
    assert "xss" in families
    assert families - {"idor", "bola", "mass_assign", "ssrf", "redirect", "crlf"}


def test_sqli_hypothesis_suggests_sqlmap_not_generic_curl() -> None:
    state = create_offensive_state("app.example.com")
    state["known_assets"] = ["http://app.example.com/search?q=1"]
    engine = HypothesisEngine()

    hypotheses = engine.update_from_evidence("P10", [], state)
    sqli = next(h for h in hypotheses if h["family"] == "sqli" and "search" in h["test_plan"]["target"])

    assert sqli["required_tools"] == ["sqlmap"]
    assert sqli["required_skills"] == ["vuln-injection"]
    assert sqli["confidence"] > 0.7


def test_wordpress_evidence_produces_cms_hypothesis_with_wpscan() -> None:
    state = create_offensive_state("app.example.com")
    state["known_assets"] = ["http://app.example.com"]
    engine = HypothesisEngine()

    evidence = [_evidence("EV-1", "httpx", "http://app.example.com", {"body_snippet": "wp-content/plugins"})]
    hypotheses = engine.update_from_evidence("P07", evidence, state)

    cms = [h for h in hypotheses if h["family"] == "cms"]
    assert cms
    assert cms[0]["required_tools"] == ["wpscan"]


def test_hypothesis_ids_are_stable_across_calls_for_dedup() -> None:
    state = create_offensive_state("app.example.com")
    state["known_assets"] = ["http://app.example.com/search?q=1"]
    engine = HypothesisEngine()

    first = engine.update_from_evidence("P10", [], state)
    second = engine.update_from_evidence("P10", [], state)

    assert {h["hypothesis_id"] for h in first} == {h["hypothesis_id"] for h in second}
