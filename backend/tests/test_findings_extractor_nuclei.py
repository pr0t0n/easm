from __future__ import annotations


def test_nuclei_parser_accepts_canonical_extracted_results_list() -> None:
    from app.services.findings_extractor import _extract_nuclei_findings

    findings = _extract_nuclei_findings(
        [{
            "template-id": "exposed-panel",
            "info": {
                "name": "Exposed panel",
                "severity": "medium",
                "tags": ["exposure", "panel"],
                "classification": {"cvss-score": 5.3},
            },
            "matched-at": "https://app.example.test/admin",
            "extracted-results": ["Admin Console", "v1.2.3"],
        }],
        "",
        "app.example.test",
        tool_name="nuclei-exposure",
    )

    assert len(findings) == 1
    details = findings[0]["details"]
    assert details["extracted_results"] == ["Admin Console", "v1.2.3"]
    assert details["cvss"] == 5.3


def test_nuclei_parser_normalizes_string_tags_and_non_mapping_info() -> None:
    from app.services.findings_extractor import _extract_nuclei_findings

    findings = _extract_nuclei_findings(
        [{
            "template-id": "CVE-2025-1234",
            "info": {
                "severity": "high",
                "tags": "cve, rce",
                "classification": "not-a-mapping",
            },
            "extracted-results": "single value",
        }],
        "",
        "app.example.test",
    )

    assert findings[0]["details"]["nuclei_tags"] == ["cve", "rce"]
    assert findings[0]["details"]["extracted_results"] == ["single value"]
    assert findings[0]["details"]["cve_id"] == "CVE-2025-1234"

    assert _extract_nuclei_findings(
        [{"template-id": "minimal", "info": "not-a-mapping"}],
        "",
        "app.example.test",
    )[0]["title"] == "minimal"


def test_nuclei_takeover_evidence_surfaces_extracted_resource_not_just_host() -> None:
    """Regression for a real, confirmed finding whose evidence text was just
    "Nuclei template aws-bucket-takeover matched at https://byxcapital.com.br"
    -- unreproducible: it named the host the request was sent to (a CDN
    whose origin is misconfigured) but never the actual claimable resource
    nuclei itself extracted (the orphaned bucket name), which is the one
    fact needed to reproduce or remediate the finding."""
    from app.services.findings_extractor import _extract_nuclei_findings

    findings = _extract_nuclei_findings(
        [{
            "template-id": "aws-bucket-takeover",
            "info": {
                "name": "AWS Bucket Takeover Detection",
                "severity": "high",
                "tags": ["takeover", "aws", "bucket", "vuln"],
                "description": "AWS Bucket takeover was detected.",
            },
            "host": "byxcapital.com.br",
            "matched-at": "https://byxcapital.com.br",
            "extracted-results": ["redirect-byxcapital"],
        }],
        "",
        "byxcapital.com.br",
        tool_name="nuclei-cloud",
    )

    assert len(findings) == 1
    details = findings[0]["details"]
    evidence = details["evidence"]
    assert "redirect-byxcapital" in evidence
    assert "https://byxcapital.com.br" in evidence
    # The distinction between "where the request landed" and "what's
    # actually claimable" must be explicit, not left for the reader to infer.
    assert "não o host em si" in evidence or "recurso reivindicável" in evidence
    assert details["reproduction_notes"]
    assert "redirect-byxcapital" in details["reproduction_notes"][0]


def test_nuclei_takeover_without_extracted_result_flags_manual_confirmation() -> None:
    from app.services.findings_extractor import _extract_nuclei_findings

    findings = _extract_nuclei_findings(
        [{
            "template-id": "some-subdomain-takeover",
            "info": {"name": "Takeover", "severity": "high", "tags": ["takeover"]},
            "matched-at": "https://stale.example.test",
        }],
        "",
        "example.test",
    )

    evidence = findings[0]["details"]["evidence"]
    assert "confirmar manualmente" in evidence
    assert findings[0]["details"]["reproduction_notes"] is None


def test_work_item_extractor_records_parser_error_metadata(monkeypatch) -> None:
    from app.services import findings_extractor as fe

    def boom(*_args, **_kwargs):
        raise ValueError("bad tool output")

    monkeypatch.setattr(fe, "_extract_whatweb_findings", boom)
    result = {"stdout_full": "broken", "stdout_full_chars": 6}

    findings = fe.extract_findings_from_work_item("whatweb", "app.example.test", "P07", result)

    assert findings == []
    meta = result["findings_extractor_meta"]
    assert meta["status"] == "parser_error"
    assert "ValueError" in meta["parser_error"]
    assert meta["findings_candidate_count"] == 0


def test_work_item_extractor_records_truncated_stdout_metadata() -> None:
    from app.services.findings_extractor import extract_findings_from_work_item

    result = {
        "stdout_full": "",
        "stdout_full_chars": 250_000,
        "stdout_parser_limit_chars": 200_000,
        "stdout_truncated_for_parser": True,
        "parsed_result": [],
    }

    extract_findings_from_work_item("httpx", "app.example.test", "P06", result)

    meta = result["findings_extractor_meta"]
    assert meta["stdout_full_chars"] == 250_000
    assert meta["stdout_parser_limit_chars"] == 200_000
    assert meta["stdout_truncated_for_parser"] is True
