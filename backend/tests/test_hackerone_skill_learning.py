from __future__ import annotations

import importlib
import os
from types import SimpleNamespace


os.environ.setdefault("DATABASE_URL", "sqlite:///test.db")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")
os.environ.setdefault("CELERY_BROKER_URL", "redis://localhost:6379/0")
os.environ.setdefault("CELERY_RESULT_BACKEND", "redis://localhost:6379/0")

learning = importlib.import_module("app.services.vulnerability_learning_service")


def test_hackerone_reproduction_steps_heading_is_extracted():
    body = """
Description:
The website located at https://www.uber.com/ suffers from XSS.

Reproduction Steps:

Open the latest Chrome web browser

Navigate to the following URL's "find a city input field":
https://www.uber.com/

Type in the following:
<script>alert(1)</script>

Note that the autocomplete result being generated from the server side is raw javascript and payload was fired.
"""
    sections = learning._extract_report_sections(body)
    assert "Open the latest Chrome" in sections["steps_to_reproduce"]
    assert "<script>alert(1)</script>" in sections["steps_to_reproduce"]


def test_hackerone_report_builds_xss_skill_update_candidate():
    reports = [
        {
            "ok": True,
            "url": "https://hackerone.com/reports/124975.json",
            "final_url": "https://hackerone.com/reports/124975.json",
            "title": "Cross-site Scripting (XSS) autocomplete generation in https://www.uber.com/",
            "vulnerability_type_hint": "Cross-site Scripting (XSS) - Generic",
            "steps_to_reproduce": "Source: https://hackerone.com/reports/124975.json\nType in the following:\n<script>alert(1)</script>",
            "impact": "",
            "remediation": "",
        }
    ]
    normalized = {
        "title": reports[0]["title"],
        "vulnerability_type": reports[0]["vulnerability_type_hint"],
        "summary": "Autocomplete renders user-controlled input.",
        "steps_to_reproduce": reports[0]["steps_to_reproduce"],
        "impact": "",
        "recommended_tools": ["dalfox", "curl-headers"],
    }

    profile = learning._build_report_learning_profile(reports, normalized)
    candidate = learning._build_skill_update_candidate(profile, normalized)

    assert profile["report_id"] == "124975"
    assert profile["technical_signals"][0]["type"] == "fact"
    assert candidate["target_skill_id"] == "skill.vuln.xss"
    assert "HackerOne Report 124975" in candidate["candidate_markdown"]
    assert "<script>alert(1)</script>" in candidate["candidate_markdown"]


def test_hackerone_manifest_expands_more_than_100_reports():
    text = "\n".join(f"https://hackerone.com/reports/{100000 + i}" for i in range(150))

    urls = learning._extract_hackerone_report_urls_from_text(text)

    assert len(urls) == 150
    assert urls[0] == "https://hackerone.com/reports/100000.json"
    assert urls[-1] == "https://hackerone.com/reports/100149.json"


def test_hackerone_learning_maps_common_gist_classes_to_real_skills():
    cases = {
        "Cross-Site Request Forgery (CSRF)": "skill.vuln.csrf",
        "Open Redirect": "skill.vuln.open_redirect",
        "Clickjacking misconfiguration": "skill.vuln.clickjacking",
        "Path Traversal": "skill.vuln.path_traversal",
        "OS Command Injection": "skill.vuln.command_injection",
        "Information Disclosure": "skill.vuln.information_disclosure",
        "Uncontrolled Resource Consumption": "skill.vuln.resource_consumption",
        "Heap Overflow": "skill.vuln.component_memory_corruption",
        "Double Free": "skill.vuln.component_memory_corruption",
        "XML Entity Expansion": "skill.vuln.xxe",
        "CORS bypass on API endpoint": "skill.vuln.cors_misconfiguration",
        "Cleartext Storage of Sensitive Information": "skill.vuln.crypto_storage",
        "Business Logic Errors": "skill.vuln.business_logic",
        "Privilege Escalation": "skill.vuln.business_logic",
    }

    for vulnerability_type, skill_id in cases.items():
        target = learning._skill_target_for_learning(vulnerability_type, vulnerability_type)
        assert target["skill_id"] == skill_id


def test_accepting_learning_promotes_candidate_into_skill(tmp_path, monkeypatch):
    skill = tmp_path / "skills" / "vulnerability_testing" / "xss.md"
    skill.parent.mkdir(parents=True)
    skill.write_text(
        """---
skill_id: "skill.vuln.xss"
name: "Cross-Site Scripting Testing"
version: "1.0.0"
---

# Objective

Test XSS safely.

## Changelog

### 1.0.0
- Initial version.
""",
        encoding="utf-8",
    )
    monkeypatch.setattr(learning, "_repo_root", lambda: tmp_path)
    row = SimpleNamespace(
        raw_extraction={
            "skill_update_candidate": {
                "status": "pending_human_review",
                "report_id": "124975",
                "target_skill_path": "skills/vulnerability_testing/xss.md",
                "candidate_markdown": "### HackerOne Report 124975\n\n#### Source Facts\n\n- <script>alert(1)</script>\n",
            }
        }
    )
    reviewer = SimpleNamespace(id=1, email="reviewer@example.com")

    learning._promote_learning_candidate_to_skill(row, reviewer)

    text = skill.read_text(encoding="utf-8")
    assert 'version: "1.1.0"' in text
    assert "## Learned Reproduction Techniques" in text
    assert "HackerOne Report 124975" in text
    assert "Approved by: reviewer@example.com" in text
    assert row.raw_extraction["skill_update_candidate"]["status"] == "promoted_to_skill"
