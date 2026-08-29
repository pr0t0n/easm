"""bas_reporting.py: the BAS Operations Center panels (framework coverage,
exposure, findings, crown jewels, MITRE heatmap, risk score). Every number
here must be real -- either a coverage/activity metric, or (for risk_score)
a real worked-vs-blocked ratio over actual BasJob outcomes -- never an
invented verdict, since Phase 1 technique content is simulated."""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from app.services import bas_reporting


def _query_chain(rows):
    """A MagicMock query object where every chained call (.filter/.join/
    .distinct/.order_by/.limit) returns itself, and .all() returns `rows`."""
    q = MagicMock()
    q.filter.return_value = q
    q.join.return_value = q
    q.outerjoin.return_value = q
    q.distinct.return_value = q
    q.order_by.return_value = q
    q.limit.return_value = q
    q.all.return_value = rows
    return q


def _proof(valid=True, status="validated"):
    return {"valid": valid, "status": status}


def test_framework_coverage_counts_only_relevant_techniques_as_tested():
    db = MagicMock()
    db.query.return_value = _query_chain([("smb_enum_cme",)])  # only this technique was ever dispatched

    result = bas_reporting.framework_coverage(db)

    # smb_enum_cme is category "smb", relevant to nist/iso27001/cis_v8 (not pci)
    assert result["nist"]["tested"] == 1
    assert result["pci"]["tested"] == 0
    for fw in result.values():
        assert 0 <= fw["coverage_pct"] <= 100


def test_framework_coverage_joins_against_basagent_kind_real():
    """A stub-agent dispatch must never count as coverage -- catches a
    regression that drops the join/filter entirely (see the live-verified
    behavior: a completed stub job for a never-tested technique does not
    change framework_coverage). Confirmed live against a real DB during
    development; this just guards the query shape doesn't regress."""
    db = MagicMock()
    query = _query_chain([])
    db.query.return_value = query

    bas_reporting.framework_coverage(db)

    assert query.join.called
    join_args = query.join.call_args[0]
    assert bas_reporting.BasAgent in join_args


def test_control_matrix_links_framework_controls_to_defensive_outcomes():
    db = MagicMock()
    jobs = [
        (SimpleNamespace(technique_key="smb_enum_cme", status="completed", result={"bas_proof": _proof(True)}, target="10.0.0.5"), SimpleNamespace(id=1, kind="real", local_network_cidr="10.0.0.0/24")),
        (SimpleNamespace(technique_key="ad_kerberoast", status="failed", result={}, target="10.0.0.10"), SimpleNamespace(id=1, kind="real", local_network_cidr="10.0.0.0/24")),
        (SimpleNamespace(technique_key="port_service_scan", status="completed", result={"defensive_status": "detected"}, target="10.0.0.20"), SimpleNamespace(id=1, kind="real", local_network_cidr="10.0.0.0/24")),
        (SimpleNamespace(technique_key="owasp_web_app_scan", status="completed", result={"bas_proof": _proof(False)}, target="https://app.local"), SimpleNamespace(id=1, kind="real", local_network_cidr="10.0.0.0/24")),
    ]

    def query_side_effect(*args):
        if args and args[0] is bas_reporting.BasNetworkSegmentTag:
            return _query_chain([])
        return _query_chain(jobs)

    db.query.side_effect = query_side_effect

    result = bas_reporting.control_matrix(db)
    cells = {(cell["framework"], cell["control_id"], cell["technique_key"]): cell for cell in result["cells"]}

    assert result["summary"]["missed"] >= 1
    assert result["summary"]["prevented"] >= 1
    assert result["summary"]["detected"] >= 1
    assert cells[("mitre_attack", "T1135", "smb_enum_cme")]["status"] == "missed"
    assert cells[("nist", "DE.CM", "smb_enum_cme")]["status"] == "missed"
    assert cells[("pci", "PCI-1", "port_service_scan")]["status"] == "detected"
    assert cells[("pci", "PCI-6", "owasp_web_app_scan")]["status"] == "tested"


def test_control_matrix_includes_custom_segment_controls():
    db = MagicMock()
    tag = SimpleNamespace(
        match_type="cidr",
        match_value="10.0.0.0/24",
        controls=[{"name": "EDR telemetry", "vendor": "internal-soc"}],
    )
    jobs = [
        (SimpleNamespace(technique_key="smb_enum_cme", status="completed", result={"defensive_status": "detected"}, target="10.0.0.5"), SimpleNamespace(id=1, kind="real", local_network_cidr="10.0.0.0/24")),
    ]

    def query_side_effect(*args):
        if args and args[0] is bas_reporting.BasNetworkSegmentTag:
            return _query_chain([tag])
        return _query_chain(jobs)

    db.query.side_effect = query_side_effect

    result = bas_reporting.control_matrix(db)
    custom_cells = [cell for cell in result["cells"] if cell["framework"] == "custom"]

    assert custom_cells
    assert custom_cells[0]["control_name"] == "EDR telemetry"
    assert custom_cells[0]["vendor"] == "internal-soc"
    assert custom_cells[0]["status"] == "detected"


def test_risk_score_joins_against_basagent_kind_real():
    db = MagicMock()
    query = _query_chain([])
    db.query.return_value = query

    bas_reporting.risk_score(db)

    assert query.join.called
    join_args = query.join.call_args[0]
    assert bas_reporting.BasAgent in join_args


def test_exposure_summary_counts_real_tunnel_roundtrips_as_completed_jobs_only():
    db = MagicMock()
    jobs = [
        SimpleNamespace(technique_key="smb_enum_cme", status="completed", target="10.10.10.5"),
        SimpleNamespace(technique_key="smb_enum_cme", status="failed", target="10.10.10.5"),
        SimpleNamespace(technique_key="ad_kerberoast", status="completed", target="admin-portal.corp.local"),
    ]
    db.query.return_value = _query_chain(jobs)

    result = bas_reporting.exposure_summary(db)

    assert result["total_dispatches"] == 3
    assert result["real_tunnel_roundtrips"] == 2
    assert result["failed_dispatches"] == 1
    assert result["distinct_targets_tested"] == 2
    assert set(result["categories_tested"]) == {"smb", "ad"}


def test_bas_findings_view_marks_every_row_simulated():
    db = MagicMock()
    finding = SimpleNamespace(
        id=1, title="BAS: test (simulado)", created_at="now", severity="info", cve=None, cvss=None,
        details={"technique_key": "smb_enum_cme", "category": "smb", "risk_tier": "safe"},
    )
    db.query.return_value = _query_chain([finding])

    rows = bas_reporting.bas_findings_view(db)

    assert rows[0]["simulated"] is True
    assert rows[0]["technique_key"] == "smb_enum_cme"
    assert rows[0]["proof_valid"] is False
    # No CVE on this finding -- EPSS/exploit-availability must stay a real
    # "n/a" (None), never a fabricated score.
    assert rows[0]["cve"] is None
    assert rows[0]["epss"] is None
    assert rows[0]["exploit_available"] is None
    assert rows[0]["affected_assets"] == []


def test_bas_findings_view_extracts_affected_assets_from_evidence():
    db = MagicMock()
    finding = SimpleNamespace(
        id=7, title="BAS: exposed service", created_at="now", severity="low", cve=None, cvss=None,
        details={
            "technique_key": "port_service_scan",
            "category": "network",
            "risk_tier": "safe",
            "target": "10.99.0.0/24",
            "key_findings": ["10.99.0.12: 8080/tcp open http-proxy"],
            "proof": {"valid": True, "target": "10.99.0.0/24", "evidence": "10.99.0.12: 8080/tcp open http-proxy"},
            "simulated": False,
        },
    )
    db.query.return_value = _query_chain([finding])

    rows = bas_reporting.bas_findings_view(db)

    assert rows[0]["affected_assets"][0]["ip"] == "10.99.0.12"
    assert rows[0]["affected_assets"][0]["source"] == "log_text"
    assert rows[0]["observation_summary"] == "1 porta(s) aberta(s): 10.99.0.12: 8080/tcp open http-proxy"


def test_bas_findings_view_summarizes_no_open_ports_observation():
    db = MagicMock()
    finding = SimpleNamespace(
        id=8, title="BAS: Port & Service Scanning", created_at="now", severity="info", cve=None, cvss=None,
        details={
            "technique_key": "port_service_scan",
            "category": "network",
            "risk_tier": "safe",
            "target": "10.125.143.240/28",
            "key_findings": [
                "Alvo varrido: 10.125.143.240/28",
                "Portas TCP testadas: 22,80,88,389,443,445,464,636,3389,3268,3269",
                "Resumo nmap: 16 IP(s) varrido(s), 16 host(s) tratados como ativos pelo -Pn, duração 1.07s.",
                "Nenhuma das portas TCP BAS foi observada aberta no alvo.",
            ],
            "proof": {"valid": True, "target": "10.125.143.240/28"},
            "simulated": False,
        },
    )
    db.query.return_value = _query_chain([finding])

    rows = bas_reporting.bas_findings_view(db)

    assert rows[0]["observation_summary"] == (
        "Resumo nmap: 16 IP(s) varrido(s), 16 host(s) tratados como ativos pelo -Pn, duração 1.07s. | "
        "Portas TCP testadas: 22,80,88,389,443,445,464,636,3389,3268,3269 | "
        "Nenhuma das portas TCP BAS foi observada aberta no alvo."
    )


def test_bas_findings_view_expands_portscan_range_findings_by_host():
    from datetime import datetime

    result = {
        "target": "10.99.0.0/30",
        "command": "proxychains4 nmap -Pn -sT -T4 --open -p 22,80 10.99.0.0/30",
        "stdout": "Nmap done: 4 IP addresses (4 hosts up) scanned in 0.21 seconds",
        "nmap_summary": {"ip_addresses": 4, "hosts_up": 4, "duration_seconds": 0.21},
        "bas_proof": _proof(True),
    }
    job = SimpleNamespace(id=101, target="10.99.0.0/30", technique_key="port_service_scan", result=result)
    finding = SimpleNamespace(
        id=8, title="BAS: Port & Service Scanning", created_at=datetime(2026, 8, 28, 12, 0), severity="info", cve=None, cvss=None,
        details={
            "technique_key": "port_service_scan",
            "category": "network",
            "risk_tier": "safe",
            "target": "10.99.0.0/30",
            "bas_job_id": 101,
            "key_findings": [
                "Alvo varrido: 10.99.0.0/30",
                "Portas TCP testadas: 22,80",
                "Resumo nmap: 4 IP(s) varrido(s), 4 host(s) tratados como ativos pelo -Pn, duração 0.21s.",
                "Nenhuma das portas TCP BAS foi observada aberta no alvo.",
            ],
            "proof": {"valid": True, "target": "10.99.0.0/30"},
            "simulated": False,
        },
    )
    db = MagicMock()

    def query_side_effect(*args):
        if args and args[0] is bas_reporting.Finding:
            return _query_chain([finding])
        if args and args[0] is bas_reporting.BasJob:
            return _query_chain([job])
        return _query_chain([])

    db.query.side_effect = query_side_effect

    rows = bas_reporting.bas_findings_view(db)

    assert [row["target"] for row in rows] == ["10.99.0.0", "10.99.0.1", "10.99.0.2", "10.99.0.3"]
    assert rows[0]["id"] == "8:10.99.0.0"
    assert rows[0]["finding_id"] == 8
    assert rows[0]["raw_target"] == "10.99.0.0/30"
    assert rows[0]["affected_assets"] == [{
        "ip": "10.99.0.0",
        "hostname": "10.99.0.0",
        "domain": "",
        "source": "nmap_target",
        "evidence": "10.99.0.0 testado no alvo 10.99.0.0/30",
        "mac_address": "",
        "mac_vendor": "",
        "arp_status": "not_observed",
        "mask": 30,
        "netmask": "255.255.255.252",
        "cidr": "10.99.0.0/30",
    }]
    assert "Host testado: 10.99.0.0" in rows[0]["key_findings"]
    assert "Nenhuma das portas TCP BAS foi observada aberta neste host." in rows[0]["key_findings"]
    assert rows[0]["observation_summary"] == "Host 10.99.0.0 testado no range 10.99.0.0/30; portas 22,80; nenhuma porta TCP BAS aberta observada."


def test_bas_findings_view_includes_agent_and_test_context():
    from datetime import datetime

    result = {
        "target": "10.99.0.10",
        "command": "nmap -Pn -sT -T4 -p 445 10.99.0.10",
        "open_ports": [{"host": "10.99.0.10", "port": 445, "protocol": "tcp", "service": "microsoft-ds"}],
        "bas_proof": _proof(True),
        "defensive_status": "detected",
    }
    job = SimpleNamespace(
        id=111, agent_id=19, schedule_id=12, scan_job_id=301, target="10.99.0.10",
        technique_key="port_service_scan", status="completed", result=result, created_at=datetime(2026, 8, 28, 12, 0),
        finished_at=datetime(2026, 8, 28, 12, 1),
    )
    agent = SimpleNamespace(
        id=19, label="sensor-sp", hostname="kali-agent", os="linux", arch="arm64", kind="real",
        status="online", last_seen_ip="203.0.113.10", local_network_cidr="10.99.0.10/24",
    )
    schedule = SimpleNamespace(id=12, name="BAS semanal")
    finding = SimpleNamespace(
        id=9, title="BAS: Port & Service Scanning", created_at=datetime(2026, 8, 28, 12, 1), severity="low", cve=None, cvss=None,
        details={
            "technique_key": "port_service_scan",
            "category": "network",
            "risk_tier": "safe",
            "target": "10.99.0.10",
            "bas_job_id": 111,
            "key_findings": ["10.99.0.10: 445/tcp open microsoft-ds"],
            "proof": {"valid": True, "target": "10.99.0.10"},
            "simulated": False,
        },
    )
    db = MagicMock()

    def query_side_effect(*args):
        if args and args[0] is bas_reporting.Finding:
            return _query_chain([finding])
        if args and args[0] is bas_reporting.BasJob:
            return _query_chain([job])
        if args and args[0] is bas_reporting.BasAgent:
            return _query_chain([agent])
        if args and args[0] is bas_reporting.BasSchedule:
            return _query_chain([schedule])
        return _query_chain([])

    db.query.side_effect = query_side_effect

    rows = bas_reporting.bas_findings_view(db)

    assert rows[0]["agent"]["label"] == "sensor-sp"
    assert rows[0]["agent"]["local_network_cidr"] == "10.99.0.10/24"
    assert rows[0]["test"]["job_id"] == 111
    assert rows[0]["test"]["scan_job_id"] == 301
    assert rows[0]["test"]["schedule_name"] == "BAS semanal"
    assert rows[0]["test"]["technique_name"] == "Port & Service Scanning"
    assert rows[0]["test"]["defensive_status"] == "detected"
    assert rows[0]["test"]["command"] == "nmap -Pn -sT -T4 -p 445 10.99.0.10"


def test_asset_refs_ignore_proxychains_infrastructure_ips():
    refs = bas_reporting._asset_refs_from_text(
        "\n".join([
            "[proxychains] Dynamic chain  ...  172.20.0.10:20020  ...  192.168.16.220:445 <--socket error or timeout!",
            "[*] Target ........... 192.168.16.220",
        ])
    )

    assert [ref["ip"] for ref in refs] == ["192.168.16.220"]


def test_crown_jewels_view_reuses_the_real_keyword_identifier():
    db = MagicMock()
    schedules = [SimpleNamespace(id=1, target_hint="admin-portal.corp.local")]

    def query_side_effect(*args):
        if args and args[0] is bas_reporting.BasSchedule:
            return _query_chain(schedules)
        return _query_chain([])

    db.query.side_effect = query_side_effect

    rows = bas_reporting.crown_jewels_view(db)

    assert len(rows) == 1
    assert rows[0]["target"] == "admin-portal.corp.local"
    assert rows[0]["label"] == "admin_panel"


def test_crown_jewels_view_empty_for_generic_hostnames():
    db = MagicMock()
    schedules = [SimpleNamespace(id=1, target_hint="10.10.10.5")]

    def query_side_effect(*args):
        if args and args[0] is bas_reporting.BasSchedule:
            return _query_chain(schedules)
        return _query_chain([])

    db.query.side_effect = query_side_effect

    assert bas_reporting.crown_jewels_view(db) == []


def test_crown_jewels_view_splits_a_multi_target_schedule_before_scoring():
    """target_hint can now be a list ("10.0.0.5, admin-portal.corp.local") --
    passing that whole string as ONE hint to identify_crown_jewels would
    never match its keyword patterns; each piece must be scored separately."""
    db = MagicMock()
    schedules = [SimpleNamespace(id=1, target_hint="10.10.10.5, admin-portal.corp.local")]

    def query_side_effect(*args):
        if args and args[0] is bas_reporting.BasSchedule:
            return _query_chain(schedules)
        return _query_chain([])

    db.query.side_effect = query_side_effect

    rows = bas_reporting.crown_jewels_view(db)

    assert len(rows) == 1
    assert rows[0]["target"] == "admin-portal.corp.local"  # the generic "10.10.10.5" piece scores nothing


def test_attack_heatmap_includes_every_cataloged_mitre_ref_even_untested():
    db = MagicMock()
    db.query.return_value = _query_chain([])  # nothing dispatched yet

    rows = bas_reporting.attack_heatmap(db)

    assert any(r["times_tested"] == 0 for r in rows)  # coverage gaps are visible, not hidden
    assert all(r["outcome"] == "not_tested" for r in rows)
    assert all("mitre_id" in r for r in rows)


def test_attack_heatmap_counts_completed_separately_from_total_dispatches():
    db = MagicMock()
    db.query.return_value = _query_chain([
        ("smb_enum_cme", "completed", {"bas_proof": _proof(True)}, "real"),
        ("smb_enum_cme", "failed", {}, "real"),
    ])

    rows = bas_reporting.attack_heatmap(db)
    cme_rows = [r for r in rows if r["technique_key"] == "smb_enum_cme"]

    assert cme_rows[0]["times_tested"] == 2
    assert cme_rows[0]["times_completed"] == 1
    assert cme_rows[0]["outcome"] == "proven"


def test_attack_heatmap_outcome_excludes_stub_dispatches():
    """A stub agent always fabricates its result -- it must never make a
    technique look 'proven'."""
    db = MagicMock()
    db.query.return_value = _query_chain([
        ("smb_enum_cme", "completed", {"bas_proof": _proof(True)}, "stub"),
    ])

    rows = bas_reporting.attack_heatmap(db)
    cme_rows = [r for r in rows if r["technique_key"] == "smb_enum_cme"]

    assert cme_rows[0]["times_tested"] == 1
    assert cme_rows[0]["outcome"] == "not_tested"


def test_risk_score_is_none_when_no_jobs_have_resolved():
    db = MagicMock()
    db.query.return_value = _query_chain([])

    result = bas_reporting.risk_score(db)

    assert result["score"] is None
    assert result["resolved_total"] == 0


def test_risk_score_excludes_queued_and_skipped_from_the_ratio():
    db = MagicMock()
    db.query.return_value = _query_chain([
        ("completed",), ("completed",), ("completed",),
        ("failed",),
        ("queued",), ("skipped",), ("running",),
    ])

    result = bas_reporting.risk_score(db)

    # 3 completed / (3 completed + 1 failed) = 75 -- queued/skipped/running never enter the ratio
    assert result["score"] == 75
    assert result["worked"] == 3
    assert result["blocked"] == 1
    assert result["unproven"] == 0
    assert result["resolved_total"] == 4


def test_risk_score_counts_completed_without_proof_as_unproven():
    db = MagicMock()
    db.query.return_value = _query_chain([
        SimpleNamespace(status="completed", result={"bas_proof": _proof(True)}),
        SimpleNamespace(status="completed", result={"bas_proof": _proof(False, "insufficient_evidence")}),
        SimpleNamespace(status="failed", result={}),
        SimpleNamespace(status="running", result={}),
    ])

    result = bas_reporting.risk_score(db)

    assert result["score"] == 33
    assert result["worked"] == 1
    assert result["unproven"] == 1
    assert result["blocked"] == 1
    assert result["resolved_total"] == 3


def test_risk_score_all_blocked_is_zero():
    db = MagicMock()
    db.query.return_value = _query_chain([("failed",), ("failed",)])

    result = bas_reporting.risk_score(db)

    assert result["score"] == 0


def test_executive_report_narrative_reflects_zero_resolved_jobs():
    """executive_report is a thin combiner over the already-tested panel
    functions -- patch those directly rather than re-deriving every db.query
    shape they each need."""
    db = MagicMock()
    with patch.object(bas_reporting, "framework_coverage", return_value={}), \
         patch.object(bas_reporting, "exposure_summary", return_value={
             "distinct_targets_tested": 0, "categories_tested": [], "total_dispatches": 0,
             "real_tunnel_roundtrips": 0, "failed_dispatches": 0,
         }), \
         patch.object(bas_reporting, "risk_score", return_value={"score": None, "worked": 0, "blocked": 0, "unproven": 0, "resolved_total": 0}), \
         patch.object(bas_reporting, "crown_jewels_view", return_value=[]), \
         patch.object(bas_reporting, "attack_heatmap", return_value=[
             {"technique_key": "smb_enum_cme", "times_tested": 0}, {"technique_key": "ad_kerberoast", "times_tested": 0},
         ]), \
         patch.object(bas_reporting, "bas_findings_view", return_value=[]), \
         patch.object(bas_reporting, "action_priorities", return_value=[]), \
         patch.object(bas_reporting, "port_scan_observability", return_value={"scans": [], "summary": {}}), \
         patch.object(bas_reporting, "chain_attack_path", return_value=[]):
        result = bas_reporting.executive_report(db)

    assert "Nenhum job BAS foi resolvido" in result["narrative"]
    assert result["risk_score"]["score"] is None
    assert result["total_techniques"] > 0
    assert result["tested_techniques"] == 0
    assert result["chain_attack_paths"] == []


def test_executive_report_narrative_reflects_real_resolved_jobs():
    db = MagicMock()
    with patch.object(bas_reporting, "framework_coverage", return_value={}), \
         patch.object(bas_reporting, "exposure_summary", return_value={
             "distinct_targets_tested": 1, "categories_tested": ["smb"], "total_dispatches": 2,
             "real_tunnel_roundtrips": 1, "failed_dispatches": 1,
         }), \
         patch.object(bas_reporting, "risk_score", return_value={"score": 50, "worked": 1, "blocked": 1, "unproven": 0, "resolved_total": 2}), \
         patch.object(bas_reporting, "crown_jewels_view", return_value=[{"target": "admin-portal.corp.local", "jobs_run": 1}]), \
         patch.object(bas_reporting, "attack_heatmap", return_value=[
             {"technique_key": "smb_enum_cme", "times_tested": 2}, {"technique_key": "ad_kerberoast", "times_tested": 0},
         ]), \
         patch.object(bas_reporting, "bas_findings_view", return_value=[
             {"id": 1, "title": "BAS: smb_enum_cme", "severity": "info", "simulated": False, "proof_valid": True},
         ]), \
         patch.object(bas_reporting, "action_priorities", return_value=[]), \
         patch.object(bas_reporting, "port_scan_observability", return_value={"scans": [], "summary": {}}), \
         patch.object(bas_reporting, "chain_attack_path", return_value=[]):
        result = bas_reporting.executive_report(db)

    assert result["risk_score"]["resolved_total"] == 2
    assert "50" in result["narrative"]
    assert result["tested_techniques"] == 1
    assert "Nenhum achado com prova BAS indicou risco concreto" in result["narrative"]


def test_executive_report_narrative_calls_out_real_vulnerable_findings():
    db = MagicMock()
    with patch.object(bas_reporting, "framework_coverage", return_value={}), \
         patch.object(bas_reporting, "exposure_summary", return_value={
             "distinct_targets_tested": 1, "categories_tested": ["web"], "total_dispatches": 1,
             "real_tunnel_roundtrips": 1, "failed_dispatches": 0,
         }), \
         patch.object(bas_reporting, "risk_score", return_value={"score": 100, "worked": 1, "blocked": 0, "unproven": 0, "resolved_total": 1}), \
         patch.object(bas_reporting, "crown_jewels_view", return_value=[]), \
         patch.object(bas_reporting, "attack_heatmap", return_value=[]), \
         patch.object(bas_reporting, "bas_findings_view", return_value=[
             {"id": 1, "title": "BAS: OWASP Web Application Scan", "severity": "medium", "simulated": False, "proof_valid": True},
             {"id": 2, "title": "BAS: stub finding", "severity": "critical", "simulated": True, "proof_valid": False},
         ]), \
         patch.object(bas_reporting, "action_priorities", return_value=[{"priority": "P1"}]), \
         patch.object(bas_reporting, "port_scan_observability", return_value={"scans": [], "summary": {}}), \
         patch.object(bas_reporting, "chain_attack_path", return_value=[{"chain_key": "web_to_secrets_chain"}]):
        result = bas_reporting.executive_report(db)

    assert result["severity_counts"]["medium"] == 1
    assert result["severity_counts"]["critical"] == 0  # the stub one is excluded
    assert "1 achado(s) real(is) indicam risco concreto" in result["narrative"]
    assert result["action_priorities"] == [{"priority": "P1"}]
    assert result["chain_attack_paths"] == [{"chain_key": "web_to_secrets_chain"}]
    assert result["technical_pentest_report"]["scope"]["validated_findings"] == 1
    assert result["technical_pentest_report"]["evidence_model"] == "proof_based_bas_finding"


def test_action_priorities_extracts_smbv1_and_unsigned_smb_from_real_job_stdout():
    from datetime import datetime

    stdout = "\n".join([
        "SMB                      10.125.133.225  445    BR-SEN1-PC0214   [*] Windows 11 / Server 2025 Build 26100 x64 (name:BR-SEN1-PC0214) (domain:falconcorp.net) (signing:False) (SMBv1:False)",
        "SMB                      10.125.135.102  445    NBK-DANIEL       [*] Windows 10 Home Single Language 26200 x64 (name:NBK-DANIEL) (domain:NBK-DANIEL) (signing:False) (SMBv1:True)",
        "SMB                      10.125.138.34   445    BBTMF-9RK90L3    [*] Windows 11 / Server 2025 Build 26100 x64 (name:BBTMF-9RK90L3) (domain:BBTMF-9RK90L3) (signing:True) (SMBv1:False)",
    ])
    job = SimpleNamespace(
        id=74, technique_key="smb_enum_cme", result={"stdout": stdout, "bas_proof": _proof(True)}, created_at=datetime(2026, 8, 26, 21, 21),
    )
    agent = SimpleNamespace(id=19, kind="real", label=None, hostname="kali")
    schedule = SimpleNamespace(id=10, name="teste")
    query = _query_chain([(job, agent, schedule)])
    db = MagicMock()
    db.query.return_value = query

    rows = bas_reporting.action_priorities(db)

    assert [row["priority"] for row in rows] == ["P0", "P1", "P2"]
    assert rows[0]["affected_targets"] == ["10.125.135.102 (NBK-DANIEL)"]
    assert rows[1]["affected_count"] == 2
    assert rows[2]["affected_count"] == 3


def test_attack_path_inventory_builds_cmdb_apps_vulnerabilities_and_steps():
    from datetime import datetime

    stdout = "\n".join([
        "SMB                      10.125.133.225  445    BR-SEN1-PC0214   [*] Windows 11 / Server 2025 Build 26100 x64 (name:BR-SEN1-PC0214) (domain:falconcorp.net) (signing:False) (SMBv1:False)",
        "SMB                      10.125.135.102  445    NBK-DANIEL       [*] Windows 10 Home Single Language 26200 x64 (name:NBK-DANIEL) (domain:NBK-DANIEL) (signing:False) (SMBv1:True)",
    ])
    job = SimpleNamespace(
        id=75, technique_key="smb_enum_cme", status="completed", result={"stdout": stdout, "bas_proof": _proof(True)}, created_at=datetime(2026, 8, 26, 22, 2),
    )
    agent = SimpleNamespace(id=19, kind="real")
    schedule = SimpleNamespace(id=10, name="teste")
    db = MagicMock()

    def query_side_effect(*args):
        if args and args[0] is bas_reporting.BasNetworkSegmentTag:
            return _query_chain([])  # no operator-declared segment tags in this test
        return _query_chain([(job, agent, schedule)])

    db.query.side_effect = query_side_effect

    result = bas_reporting.attack_path_inventory(db)

    assert result["summary"] == {
        "assets": 2,
        "applications": 2,
        "vulnerabilities": 2,
        "high_risk_assets": 1,
        "medium_risk_assets": 1,
    }
    assert [asset["ip"] for asset in result["cmdb_assets"]] == ["10.125.135.102", "10.125.133.225"]
    assert {app["version"] for app in result["applications"]} == {"SMBv1 habilitado", "SMBv2/3 observado"}
    assert {v["id"] for v in result["vulnerabilities"]} == {"smbv1_enabled", "smb_signing_disabled"}
    assert [step["title"] for step in result["attack_steps"]] == [
        "Entrada pelo segmento do agente",
        "Possibilidade de relay SMB/NTLM",
        "Exploração de legado SMBv1",
    ]


def test_attack_path_inventory_builds_assets_from_scan_logs_and_links_finding():
    from datetime import datetime

    job = SimpleNamespace(
        id=91,
        scan_job_id=123,
        finding_id=77,
        technique_key="controlled_exploit_validation",
        status="completed",
        target="10.99.0.0/24",
        result={"bas_proof": _proof(True)},
        created_at=datetime(2026, 8, 28, 13, 5),
    )
    agent = SimpleNamespace(id=19, kind="real")
    schedule = SimpleNamespace(id=10, name="teste")
    log = SimpleNamespace(scan_job_id=123, message="validated internal host 10.99.0.12 responded with service banner", created_at=datetime(2026, 8, 28, 13, 6))
    finding = SimpleNamespace(
        id=77,
        title="BAS: Controlled exploit validation",
        severity="medium",
        details={"technique_key": "controlled_exploit_validation", "recommendation": "Corrigir serviço exposto."},
    )
    db = MagicMock()

    def query_side_effect(*args):
        if args and args[0] is bas_reporting.BasNetworkSegmentTag:
            return _query_chain([])
        if args and args[0] is bas_reporting.ScanLog:
            return _query_chain([log])
        if args and args[0] is bas_reporting.Finding:
            return _query_chain([finding])
        return _query_chain([(job, agent, schedule)])

    db.query.side_effect = query_side_effect

    result = bas_reporting.attack_path_inventory(db)

    asset = result["cmdb_assets"][0]
    assert asset["ip"] == "10.99.0.12"
    assert asset["vulnerabilities"][0]["finding_id"] == 77
    assert asset["observations"][0]["source"] == "log_text"


def test_attack_path_inventory_includes_attempted_host_without_valid_finding():
    from datetime import datetime

    job = SimpleNamespace(
        id=92,
        scan_job_id=124,
        schedule_id=10,
        finding_id=None,
        technique_key="smb_enum_enum4linux",
        status="completed",
        target="192.168.16.220",
        result={"status": "executed", "stderr": "connection refused"},
        created_at=datetime(2026, 8, 28, 13, 9),
    )
    agent = SimpleNamespace(id=19, kind="real")
    schedule = None
    log = SimpleNamespace(scan_job_id=124, message="Target 192.168.16.220 connection refused", created_at=datetime(2026, 8, 28, 13, 10))
    db = MagicMock()

    def query_side_effect(*args):
        if args and args[0] is bas_reporting.BasNetworkSegmentTag:
            return _query_chain([])
        if args and args[0] is bas_reporting.ScanLog:
            return _query_chain([log])
        return _query_chain([(job, agent, schedule)])

    db.query.side_effect = query_side_effect

    result = bas_reporting.attack_path_inventory(db)

    assert [asset["ip"] for asset in result["cmdb_assets"]] == ["192.168.16.220"]
    assert result["cmdb_assets"][0]["schedule_ids"] == [10]
    assert result["cmdb_assets"][0]["vulnerabilities"] == []
    assert result["cmdb_assets"][0]["observations"]


def test_attack_path_inventory_includes_all_portscan_range_hosts_with_network_metadata():
    from datetime import datetime

    result_payload = {
        "target": "10.99.0.0/30",
        "command": "proxychains4 nmap -Pn -sT -T4 --open -p 22,80 10.99.0.0/30",
        "stdout": "\n".join([
            "Nmap scan report for printer.local (10.99.0.2)",
            "MAC Address: AA:BB:CC:11:22:33 (Example Vendor)",
            "Nmap done: 4 IP addresses (4 hosts up) scanned in 0.19 seconds",
        ]),
        "nmap_summary": {"ip_addresses": 4, "hosts_up": 4, "duration_seconds": 0.19},
        "bas_proof": _proof(True),
    }
    job = SimpleNamespace(
        id=102,
        scan_job_id=125,
        schedule_id=10,
        finding_id=None,
        technique_key="port_service_scan",
        status="completed",
        target="10.99.0.0/30",
        result=result_payload,
        created_at=datetime(2026, 8, 28, 13, 9),
    )
    agent = SimpleNamespace(id=19, kind="real")
    schedule = SimpleNamespace(id=10, name="range")
    db = MagicMock()

    def query_side_effect(*args):
        if args and args[0] is bas_reporting.BasNetworkSegmentTag:
            return _query_chain([])
        if args and args[0] is bas_reporting.ScanLog:
            return _query_chain([])
        return _query_chain([(job, agent, schedule)])

    db.query.side_effect = query_side_effect

    result = bas_reporting.attack_path_inventory(db)
    assets = {asset["ip"]: asset for asset in result["cmdb_assets"]}

    assert sorted(assets) == ["10.99.0.0", "10.99.0.1", "10.99.0.2", "10.99.0.3"]
    assert assets["10.99.0.1"]["mask"] == 30
    assert assets["10.99.0.1"]["netmask"] == "255.255.255.252"
    assert assets["10.99.0.1"]["tested_tcp_ports"] == [22, 80]
    assert assets["10.99.0.1"]["arp_status"] == "not_observed"
    assert assets["10.99.0.2"]["hostname"] == "printer.local"
    assert assets["10.99.0.2"]["hostname_resolution_status"] == "resolved_from_nmap"
    assert assets["10.99.0.2"]["mac_address"] == "AA:BB:CC:11:22:33"
    assert assets["10.99.0.2"]["mac_vendor"] == "Example Vendor"
    assert assets["10.99.0.2"]["observed_by_agents"][0]["label"] == "agente #19"
    assert assets["10.99.0.2"]["tests_observed"][0]["technique_name"] == "Port & Service Scanning"
    assert assets["10.99.0.2"]["tests_observed"][0]["job_id"] == 102


def test_chain_attack_path_groups_steps_by_the_shadow_scan_job_in_order():
    from datetime import datetime

    db = MagicMock()
    agent = SimpleNamespace(id=13, kind="real")
    schedule = SimpleNamespace(
        id=6, name="Web chain", chain_key="web_to_secrets_chain", agent_id=13, target_hint="192.168.1.65:8001",
    )
    jobs = [
        SimpleNamespace(scan_job_id=42, technique_key="port_service_scan", status="completed",
                         risk_tier="safe", finding_id=101, result={"bas_proof": _proof(True)},
                         created_at=datetime(2026, 8, 19, 18, 48, 49)),
        SimpleNamespace(scan_job_id=42, technique_key="owasp_web_app_scan", status="completed",
                         risk_tier="safe", finding_id=102, result={"bas_proof": _proof(True)},
                         created_at=datetime(2026, 8, 19, 18, 48, 50)),
    ]
    rows = [(jobs[0], schedule, agent), (jobs[1], schedule, agent)]

    query = MagicMock()
    query.join.return_value = query
    query.filter.return_value = query
    query.order_by.return_value = query
    query.all.return_value = rows
    db.query.return_value = query

    paths = bas_reporting.chain_attack_path(db)

    assert len(paths) == 1
    path = paths[0]
    assert path["scan_job_id"] == 42
    assert path["chain_key"] == "web_to_secrets_chain"
    assert path["simulated"] is False
    assert [s["technique_key"] for s in path["steps"]] == ["port_service_scan", "owasp_web_app_scan"]
    assert path["steps"][1]["mitre_refs"]  # populated from the real technique catalog
    assert all(step["proof_valid"] is True for step in path["steps"])
