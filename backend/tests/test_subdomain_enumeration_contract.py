from __future__ import annotations

from app.graph.workflow import _extract_assets_from_findings, _extract_assets_from_result


def test_extract_assets_from_findings_accepts_structured_subdomain_contract() -> None:
    findings = [
        {
            "title": "Subdomínios descobertos",
            "details": {
                "tool": "subfinder",
                "discovered_subdomains": [
                    "api.example.com",
                    "https://admin.example.com/login",
                    "outside.example.org",
                    "example.com",
                ],
                "resolved_records": [
                    {"subdomain": "cdn.example.com", "type": "CNAME", "value": "edge.example.net"},
                ],
            },
        },
        {
            "title": "Legacy parser",
            "details": {
                "tool": "amass",
                "subdomains": ["dev.example.com", "api.example.com"],
            },
        },
    ]

    assert _extract_assets_from_findings(findings, "example.com") == [
        "admin.example.com",
        "api.example.com",
        "cdn.example.com",
        "dev.example.com",
        "example.com",
    ]


def test_extract_assets_from_result_keeps_stdout_fallback_for_plain_tool_output() -> None:
    result = {
        "tool": "subfinder",
        "stdout": "\n".join(
            [
                "api.example.com",
                "admin.example.com",
                "outside.example.org",
            ]
        ),
    }

    assert _extract_assets_from_result(result, "example.com") == [
        "admin.example.com",
        "api.example.com",
    ]
