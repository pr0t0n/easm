from __future__ import annotations

from types import SimpleNamespace

from app.services.bas_proof import build_bas_proof
from app.services.bas_technique_catalog import get_technique


def _job(**overrides):
    base = dict(id=7, schedule_id=3, scan_job_id=11, target="10.10.10.5", status="completed")
    base.update(overrides)
    return SimpleNamespace(**base)


def test_bas_proof_requires_the_full_evidence_contract():
    proof = build_bas_proof(
        technique=get_technique("owasp_web_app_scan"),
        job=_job(),
        agent=SimpleNamespace(id=5, kind="real"),
        result={
            "status": "executed",
            "command": "nikto -h 10.10.10.5",
            "stdout": "+ [007352] /: The X-Content-Type-Options header is not set.\n",
        },
        key_findings=["+ [007352] /: The X-Content-Type-Options header is not set."],
        severity="medium",
    )

    assert proof["valid"] is True
    assert proof["status"] == "validated"
    assert all(proof["requirements"].values())
    assert proof["replay"]["command"] == "nikto -h 10.10.10.5"


def test_bas_proof_rejects_real_execution_without_parsed_evidence():
    proof = build_bas_proof(
        technique=get_technique("network_share_discovery"),
        job=_job(),
        agent=SimpleNamespace(id=5, kind="real"),
        result={"status": "executed", "command": "smbmap -H 10.10.10.5", "stdout": "scan finished"},
        key_findings=[],
        severity="info",
    )

    assert proof["valid"] is False
    assert proof["status"] == "insufficient_evidence"
    assert proof["requirements"]["parsed_evidence"] is False


def test_bas_proof_rejects_stub_agent_output():
    proof = build_bas_proof(
        technique=get_technique("smb_enum_cme"),
        job=_job(),
        agent=SimpleNamespace(id=1, kind="stub"),
        result={"status": "executed", "command": "crackmapexec smb 10.10.10.5", "stdout": "SMB fake"},
        key_findings=["SMB fake"],
        severity="medium",
    )

    assert proof["valid"] is False
    assert proof["status"] == "simulated"


def test_bas_proof_accepts_cloud_identity_posture_evidence_with_info_severity():
    proof = build_bas_proof(
        technique=get_technique("azure_entra_id_discovery"),
        job=_job(target="example.com"),
        agent=SimpleNamespace(id=5, kind="real"),
        result={
            "status": "executed",
            "command": "curl https://login.microsoftonline.com/getuserrealm.srf?login=user@example.com",
            "stdout": "{\"NameSpaceType\":\"Managed\",\"FederationBrandName\":\"Example\"}",
        },
        key_findings=["{\"NameSpaceType\":\"Managed\",\"FederationBrandName\":\"Example\"}"],
        severity="info",
    )

    assert proof["valid"] is True
    assert proof["requirements"]["impact_or_control_observed"] is True
