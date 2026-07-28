from app.services.evidence_gate import validate_finding_grounding


def test_no_raw_output_is_not_checked() -> None:
    result = validate_finding_grounding(["https://valid.com/admin"], None)

    assert result["checked"] is False
    assert result["grounded"] is True


def test_no_usable_anchor_is_not_checked() -> None:
    result = validate_finding_grounding([None, ""], "some raw tool output")

    assert result["checked"] is False
    assert result["grounded"] is True


def test_anchor_present_in_raw_output_is_grounded() -> None:
    raw = "[10:01:03] [matcher-name] [http] https://valid.com/admin/login"

    result = validate_finding_grounding(["https://valid.com/admin/login"], raw)

    assert result["checked"] is True
    assert result["grounded"] is True
    assert result["reason"] == "anchor_matched"


def test_anchor_missing_from_raw_output_is_not_grounded() -> None:
    raw = "nmap scan report for valid.com\nPORT 443/tcp open https"

    result = validate_finding_grounding(["https://valid.com/admin/login"], raw)

    assert result["checked"] is True
    assert result["grounded"] is False
    assert "none_of_1_anchors" in result["reason"]


def test_second_anchor_can_satisfy_grounding() -> None:
    raw = "CVE-2021-26855 confirmed via ProxyLogon matcher"

    result = validate_finding_grounding(
        ["https://valid.com/owa/", "CVE-2021-26855"],
        raw,
    )

    assert result["grounded"] is True


def test_matching_is_whitespace_and_case_tolerant() -> None:
    raw = "matched at:\r\n  HTTPS://VALID.COM/Admin/Login  \r\nstatus 200"

    result = validate_finding_grounding(["https://valid.com/admin/login"], raw)

    assert result["grounded"] is True
