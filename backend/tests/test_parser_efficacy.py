"""Tests for parser efficacy — dalfox and wapiti per-finding extraction."""
from __future__ import annotations

import json

from app.graph.tool_parsers import _extract_dalfox_findings, _extract_wapiti_findings


# ── Dalfox ────────────────────────────────────────────────────────────────────

DALFOX_OUTPUT_MULTI = """
[*] 2024/01/01 10:00:00 Start Scanning
[V] Verified XSS on https://target.com/search?q=test ~ V[reflected] p[q] > <sCript>alert(XSS)</sCript>
[V] Verified XSS on https://target.com/user?name=foo ~ V[reflected] p[name] > <img src=x onerror=alert(1)>
[V] Verified XSS on https://target.com/profile?bio=x ~ V[stored] p[bio] > <script>document.cookie</script>
[G] Potential XSS on https://target.com/comment?text=a ~ p[text] > reflected
[*] Scan completed
"""

DALFOX_OUTPUT_SINGLE = """
[V] Verified XSS on https://app.example.com/search?q=test ~ V[reflected] p[q] > <sCript>alert(1)</sCript>
"""

DALFOX_OUTPUT_EMPTY = """
[*] No XSS found
[*] Scanning done
"""


def test_dalfox_creates_one_finding_per_xss() -> None:
    findings = _extract_dalfox_findings(DALFOX_OUTPUT_MULTI, "P12.dalfox", "https://target.com")
    # 3 verified + 1 candidate = 4 distinct findings
    assert len(findings) == 4, f"Expected 4 findings, got {len(findings)}: {[f['title'] for f in findings]}"


def test_dalfox_extracts_parameter_from_finding() -> None:
    findings = _extract_dalfox_findings(DALFOX_OUTPUT_SINGLE, "P12.dalfox", "https://app.example.com")
    assert len(findings) == 1
    assert findings[0]["details"]["parameter"] == "q"
    assert findings[0]["severity"] == "high"
    assert findings[0]["details"]["validation_status"] == "verified"


def test_dalfox_empty_output_returns_no_findings() -> None:
    findings = _extract_dalfox_findings(DALFOX_OUTPUT_EMPTY, "P12.dalfox", "https://target.com")
    assert findings == []


def test_dalfox_deduplicates_same_url_and_param() -> None:
    dup = DALFOX_OUTPUT_SINGLE + DALFOX_OUTPUT_SINGLE
    findings = _extract_dalfox_findings(dup, "P12.dalfox", "https://app.example.com")
    assert len(findings) == 1


def test_dalfox_stored_xss_has_correct_title() -> None:
    output = "[V] Verified XSS on https://site.com/bio?x=1 ~ V[stored] p[x] > <script>alert(1)</script>"
    findings = _extract_dalfox_findings(output, "P12.dalfox", "https://site.com")
    assert any("Armazenado" in f["title"] for f in findings)


# ── Wapiti JSON ───────────────────────────────────────────────────────────────

WAPITI_JSON_REPORT = {
    "vulnerabilities": {
        "Cross Site Scripting": [
            {"path": "/search", "parameter": "q", "method": "GET", "info": "XSS in search param", "wstg": ["WSTG-INPV-01"]},
            {"path": "/contact", "parameter": "message", "method": "POST", "info": "XSS in message field", "wstg": []},
        ],
        "SQL Injection": [
            {"path": "/login", "parameter": "username", "method": "POST", "info": "Error-based SQLi", "payload": "' OR '1'='1"},
        ],
        "HTTP Strict Transport Security": [
            {"path": "/", "parameter": "", "method": "GET", "info": "HSTS not set"},
        ],
    },
    "anomalies": {},
}

WAPITI_TEXT_OUTPUT = """
[*] Scanning https://target.com...
[!] SQL injection on https://target.com/api?id=1
[!] XSS on https://target.com/search?q=test
[!] Open Redirect on https://target.com/redirect?url=evil
"""


def test_wapiti_json_creates_one_finding_per_vuln_entry() -> None:
    findings = _extract_wapiti_findings("", "P10.wapiti", "https://target.com", parsed_json=WAPITI_JSON_REPORT)
    # 2 XSS + 1 SQLi + 1 HSTS = 4
    assert len(findings) == 4, f"Expected 4, got {len(findings)}: {[f['title'] for f in findings]}"


def test_wapiti_json_sqli_has_high_severity() -> None:
    findings = _extract_wapiti_findings("", "P10.wapiti", "https://target.com", parsed_json=WAPITI_JSON_REPORT)
    sqli = [f for f in findings if "SQL" in f["title"]]
    assert len(sqli) == 1
    assert sqli[0]["severity"] == "high"


def test_wapiti_json_xss_constructs_full_url() -> None:
    findings = _extract_wapiti_findings("", "P10.wapiti", "https://target.com", parsed_json=WAPITI_JSON_REPORT)
    xss = [f for f in findings if "Cross Site Scripting" in f["title"]]
    urls = {f["details"]["url"] for f in xss}
    assert "https://target.com/search" in urls
    assert "https://target.com/contact" in urls


def test_wapiti_text_fallback_parses_three_findings() -> None:
    findings = _extract_wapiti_findings(WAPITI_TEXT_OUTPUT, "P10.wapiti", "https://target.com")
    assert len(findings) == 3, f"Expected 3, got {len(findings)}: {[f['title'] for f in findings]}"


def test_wapiti_json_string_input_also_works() -> None:
    findings = _extract_wapiti_findings("", "P10.wapiti", "https://target.com", parsed_json=json.dumps(WAPITI_JSON_REPORT))
    assert len(findings) == 4
