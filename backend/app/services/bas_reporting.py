"""BAS Operations Center reporting: framework coverage, exposure, findings,
crown jewels, a MITRE ATT&CK heatmap, and a risk score.

Honesty rule carried through every panel here: nothing computes a fabricated
verdict implying a real posture gap was found or a real vulnerability was
proven when it wasn't. Whether a given BasJob/Finding is real or simulated
depends entirely on which BasAgent ran it (`agent.kind` -- "stub" for
bas_agent_stub, which always fabricates its tunnel's response content;
"real" for a genuine agent, cryptographically proven via a CA-signed mTLS
cert at enroll -- see bas_ca.py -- whose relay and result are real). This
module never assumes one or the other; every row it returns carries its own
`simulated` flag sourced from the underlying Finding/BasJob (see
bas_exclusion.py, bas_scheduler.py).
"""
from __future__ import annotations

from collections import Counter
import ipaddress
import re
from typing import Any

from sqlalchemy.orm import Session

from app.models.models import BasAgent, BasJob, BasNetworkSegmentTag, BasSchedule, Finding, ScanJob
from app.services.bas_exclusion import BAS_FINDING_TOOL
from app.services.bas_scheduler import _split_targets
from app.services.bas_technique_catalog import list_techniques
from app.services.crown_jewel_analyzer import identify_crown_jewels

# Compliance-framework relevance per BAS category. This is a coarse, static,
# code-defined mapping (like the rest of this module's catalogs) -- a full
# control-by-control crosswalk is out of scope; this says "this category of
# internal test is broadly relevant to this framework family", not "this
# finding maps to control X.Y.Z".
_CATEGORY_FRAMEWORK_RELEVANCE: dict[str, set[str]] = {
    "ad": {"nist", "iso27001", "pci", "cis_v8"},
    "ntlm": {"nist", "iso27001", "pci", "cis_v8"},
    "smb": {"nist", "iso27001", "cis_v8"},
    "windows": {"nist", "iso27001", "cis_v8"},
    "linux": {"nist", "iso27001", "cis_v8"},
    "vmware": {"nist", "iso27001", "cis_v8"},
    "firewall": {"nist", "pci", "cis_v8"},
    "cloud": {"nist", "iso27001", "pci", "cis_v8"},
    "network": {"nist", "pci", "cis_v8"},
    "web": {"nist", "iso27001", "pci", "cis_v8"},
    "cicd": {"nist", "iso27001", "cis_v8"},
    "identity": {"nist", "iso27001", "pci", "cis_v8"},
    "lateral_movement": {"nist", "iso27001", "pci", "cis_v8"},
    "exploit_validation": {"nist", "iso27001", "pci", "cis_v8"},
    "cloud_identity": {"nist", "iso27001", "pci", "cis_v8"},
    "saas": {"nist", "iso27001", "pci", "cis_v8"},
}
_FRAMEWORK_LABELS = {"mitre_attack": "MITRE ATT&CK", "nist": "NIST CSF", "iso27001": "ISO 27001", "pci": "PCI DSS 4.0", "cis_v8": "CIS Controls"}
_FRAMEWORK_COVERAGE_LABELS = {key: value for key, value in _FRAMEWORK_LABELS.items() if key != "mitre_attack"}
_CONTROL_MATRIX_STATUSES = ("tested", "prevented", "detected", "missed", "not_applicable")
_CONTROL_DEFS: dict[str, list[dict[str, Any]]] = {
    "nist": [
        {"id": "ID.AM", "name": "Asset management", "categories": {"network", "cloud", "cloud_identity", "saas"}},
        {"id": "PR.AC", "name": "Identity and access control", "categories": {"ad", "identity", "cloud_identity", "saas"}},
        {"id": "PR.IP", "name": "Protective technology and hardening", "categories": {"windows", "linux", "vmware", "firewall", "cicd"}},
        {"id": "DE.CM", "name": "Security continuous monitoring", "categories": {"ntlm", "smb", "lateral_movement", "exploit_validation", "cloud_identity"}},
        {"id": "RS.AN", "name": "Response analysis", "categories": {"web", "exploit_validation", "cloud", "saas"}},
    ],
    "cis_v8": [
        {"id": "CIS-1", "name": "Inventory and control of enterprise assets", "categories": {"network", "cloud", "saas"}},
        {"id": "CIS-4", "name": "Secure configuration", "categories": {"windows", "linux", "vmware", "firewall"}},
        {"id": "CIS-5", "name": "Account management", "categories": {"ad", "identity", "cloud_identity"}},
        {"id": "CIS-8", "name": "Audit log management", "categories": {"ntlm", "lateral_movement", "exploit_validation", "cloud_identity", "saas"}},
        {"id": "CIS-12", "name": "Network infrastructure management", "categories": {"network", "firewall", "smb"}},
        {"id": "CIS-16", "name": "Application software security", "categories": {"web", "cicd", "exploit_validation"}},
    ],
    "iso27001": [
        {"id": "A.5.15", "name": "Access control", "categories": {"ad", "identity", "cloud_identity", "saas"}},
        {"id": "A.8.8", "name": "Management of technical vulnerabilities", "categories": {"web", "windows", "linux", "vmware", "exploit_validation", "cloud"}},
        {"id": "A.8.16", "name": "Monitoring activities", "categories": {"ntlm", "smb", "lateral_movement", "cloud_identity", "saas"}},
        {"id": "A.8.20", "name": "Network security", "categories": {"network", "firewall", "smb", "ntlm"}},
        {"id": "A.8.28", "name": "Secure coding", "categories": {"web", "cicd"}},
    ],
    "pci": [
        {"id": "PCI-1", "name": "Network security controls", "categories": {"network", "firewall", "smb"}},
        {"id": "PCI-2", "name": "Secure configurations", "categories": {"windows", "linux", "vmware", "cloud"}},
        {"id": "PCI-6", "name": "Secure systems and software", "categories": {"web", "cicd", "exploit_validation"}},
        {"id": "PCI-8", "name": "Identify users and authenticate access", "categories": {"ad", "identity", "cloud_identity", "saas"}},
        {"id": "PCI-10", "name": "Log and monitor all access", "categories": {"ntlm", "lateral_movement", "cloud_identity", "saas"}},
        {"id": "PCI-11", "name": "Test security of systems and networks", "categories": {"network", "web", "exploit_validation", "cloud"}},
    ],
}
_SMB_LINE_RE = re.compile(
    r"^SMB\s+(?P<ip>\d+\.\d+\.\d+\.\d+)\s+445\s+(?P<host>\S+)\s+\[\*\]\s+(?P<os>.*?)\s+\(name:.*?\)\s+\(domain:(?P<domain>.*?)\)\s+\(signing:(?P<signing>True|False)\)\s+\(SMBv1:(?P<smbv1>True|False)\)"
)


def _smb_observations(stdout: str) -> list[dict[str, Any]]:
    observations = []
    seen = set()
    for line in str(stdout or "").splitlines():
        match = _SMB_LINE_RE.search(line.strip())
        if not match:
            continue
        item = match.groupdict()
        key = (item["ip"], item["host"])
        if key in seen:
            continue
        seen.add(key)
        observations.append({
            "ip": item["ip"],
            "host": item["host"],
            "os": item["os"].strip(),
            "domain": item["domain"].strip(),
            "signing_required": item["signing"] == "True",
            "smbv1_enabled": item["smbv1"] == "True",
            "evidence": line.strip(),
        })
    return observations


def _nmap_open_ports(result: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    seen = set()
    for item in result.get("open_ports") or []:
        if not isinstance(item, dict):
            continue
        host = str(item.get("host") or item.get("ip") or item.get("target") or "").strip()
        port = str(item.get("port") or "").strip()
        protocol = str(item.get("protocol") or "tcp").strip() or "tcp"
        service = str(item.get("service") or item.get("name") or "").strip() or "unknown"
        if not host or not port:
            continue
        key = (host, port, protocol)
        if key in seen:
            continue
        seen.add(key)
        rows.append({"host": host, "port": int(port), "protocol": protocol, "service": service})

    current_host = ""
    for line in str(result.get("stdout") or "").splitlines():
        clean = line.strip()
        if clean.lower().startswith("nmap scan report for"):
            current_host = clean[len("Nmap scan report for "):].strip()
            match = re.search(r"\((\d+\.\d+\.\d+\.\d+)\)", current_host)
            if match:
                current_host = match.group(1)
            else:
                current_host = current_host.split()[0]
            continue
        match = re.match(r"^(?P<port>\d+)/(?P<protocol>\S+)\s+open\s+(?P<service>\S+)", clean)
        if not match or not current_host:
            continue
        key = (current_host, match.group("port"), match.group("protocol"))
        if key in seen:
            continue
        seen.add(key)
        rows.append({
            "host": current_host,
            "port": int(match.group("port")),
            "protocol": match.group("protocol"),
            "service": match.group("service"),
        })
    return rows


def _nmap_summary(result: dict[str, Any]) -> dict[str, Any]:
    summary = dict(result.get("nmap_summary") or {})
    stdout = str(result.get("stdout") or "")
    report_count = 0
    no_open_count = 0
    for line in stdout.splitlines():
        clean = line.strip()
        if clean.lower().startswith("nmap scan report for"):
            report_count += 1
        if clean.lower().startswith("all ") and " scanned ports " in clean.lower() and " ignored states" in clean.lower():
            no_open_count += 1
        match = re.match(
            r"^Nmap done:\s+(?P<addresses>\d+)\s+IP addresses\s+\((?P<hosts>\d+)\s+hosts up\)\s+scanned in\s+(?P<seconds>[\d.]+)\s+seconds",
            clean,
            re.IGNORECASE,
        )
        if match:
            summary.update({
                "ip_addresses": int(match.group("addresses")),
                "hosts_up": int(match.group("hosts")),
                "duration_seconds": float(match.group("seconds")),
            })
    if report_count:
        summary.setdefault("reported_hosts", report_count)
    if no_open_count:
        summary.setdefault("hosts_without_open_ports", no_open_count)
    return summary


def _proof_from_result(result: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(result, dict):
        return {}
    proof = result.get("bas_proof") or result.get("proof") or {}
    return proof if isinstance(proof, dict) else {}


def _proof_valid_from_result(result: dict[str, Any] | None) -> bool:
    return bool(_proof_from_result(result).get("valid"))


def _proof_valid_from_finding(finding: Finding) -> bool:
    details = finding.details or {}
    proof = details.get("proof") or {}
    return bool(isinstance(proof, dict) and proof.get("valid"))


def _status_from_risk_row(row: Any) -> str:
    if isinstance(row, tuple):
        return str(row[0] or "")
    return str(getattr(row, "status", "") or "")


def _risk_row_is_legacy_status_tuple(row: Any) -> bool:
    return isinstance(row, tuple) and row and isinstance(row[0], str)


def _risk_row_has_valid_proof(row: Any) -> bool:
    if _risk_row_is_legacy_status_tuple(row):
        return _status_from_risk_row(row) == "completed"
    return _proof_valid_from_result(getattr(row, "result", None))


def _real_agent_technique_keys(
    db: Session, *, group_ids: list[int] | None = None, schedule_id: int | None = None
) -> set[str]:
    """Technique keys dispatched at least once through a REAL (non-stub)
    agent. A stub-agent dispatch always fabricates its response content, so
    it's not a genuine "this was tested" signal -- only a real-agent
    dispatch counts as coverage/tested here."""
    query = (
        db.query(BasJob.technique_key)
        .join(BasAgent, BasAgent.id == BasJob.agent_id)
        .filter(BasAgent.kind == "real")
        .distinct()
    )
    if group_ids is not None:
        query = query.filter(BasJob.access_group_id.in_(group_ids))
    if schedule_id is not None:
        query = query.filter(BasJob.schedule_id == schedule_id)
    return {row[0] for row in query.all()}


def framework_coverage(
    db: Session, *, group_ids: list[int] | None = None, schedule_id: int | None = None
) -> dict[str, Any]:
    """Per framework: how many of the BAS-catalog techniques relevant to it
    have actually been dispatched at least once through a REAL agent
    (tested_count/total_count). A stub-only dispatch never counts as
    coverage -- see _real_agent_technique_keys."""
    tested_keys = _real_agent_technique_keys(db, group_ids=group_ids, schedule_id=schedule_id)

    result: dict[str, Any] = {}
    for fw, label in _FRAMEWORK_COVERAGE_LABELS.items():
        relevant = [t for t in list_techniques() if fw in _CATEGORY_FRAMEWORK_RELEVANCE.get(t["category"], set())]
        tested = [t for t in relevant if t["technique_key"] in tested_keys]
        total = len(relevant)
        result[fw] = {
            "label": label,
            "tested": len(tested),
            "total": total,
            "coverage_pct": round(100 * len(tested) / total, 1) if total else 0,
        }
    return result


def _defensive_status_from_result(result: dict[str, Any] | None) -> str:
    if not isinstance(result, dict):
        return ""
    candidates = [
        result.get("defensive_status"),
        result.get("control_status"),
        result.get("bas_control_status"),
        (result.get("defensive_observation") or {}).get("status") if isinstance(result.get("defensive_observation"), dict) else None,
        (result.get("control_observation") or {}).get("status") if isinstance(result.get("control_observation"), dict) else None,
    ]
    for value in candidates:
        status = str(value or "").strip().lower()
        if status in _CONTROL_MATRIX_STATUSES:
            return status
    detection_keys = ("telemetry_detected", "siem_alert", "edr_alert", "ids_alert", "alerted", "detected_by_control")
    if any(bool(result.get(key)) for key in detection_keys):
        return "detected"
    prevention_keys = ("blocked_by_control", "prevented_by_control", "control_blocked")
    if any(bool(result.get(key)) for key in prevention_keys):
        return "prevented"
    return ""


def _matrix_job_status(job: Any) -> str:
    result = getattr(job, "result", None)
    explicit = _defensive_status_from_result(result)
    if explicit and explicit != "not_applicable":
        return explicit
    status = str(getattr(job, "status", "") or "").lower()
    if status == "failed":
        return "prevented"
    if status == "completed" and _proof_valid_from_result(result):
        return "missed"
    if status == "completed":
        return "tested"
    return "tested"


def _strongest_matrix_status(statuses: list[str]) -> str:
    rank = {"missed": 5, "detected": 4, "prevented": 3, "tested": 2, "not_applicable": 1}
    return max(statuses or ["not_applicable"], key=lambda status: rank.get(status, 0))


def _matrix_control_key(framework: str, control_id: str, name: str = "") -> str:
    return f"{framework}:{control_id or name}".strip().lower()


def _control_matrix_defs(tags: list[BasNetworkSegmentTag], jobs_by_custom_control: dict[str, set[str]]) -> list[dict[str, Any]]:
    techniques = list_techniques()
    controls = []
    by_mitre: dict[str, set[str]] = {}
    for technique in techniques:
        for mitre_id in technique.get("mitre_refs") or []:
            by_mitre.setdefault(mitre_id, set()).add(technique["technique_key"])
    for mitre_id, technique_keys in sorted(by_mitre.items()):
        controls.append({
            "framework": "mitre_attack",
            "framework_label": _FRAMEWORK_LABELS["mitre_attack"],
            "control_id": mitre_id,
            "control_name": mitre_id,
            "technique_keys": technique_keys,
            "categories": set(),
            "custom": False,
        })
    for framework, rows in _CONTROL_DEFS.items():
        for row in rows:
            controls.append({
                "framework": framework,
                "framework_label": _FRAMEWORK_LABELS[framework],
                "control_id": row["id"],
                "control_name": row["name"],
                "technique_keys": set(row.get("technique_keys") or []),
                "categories": set(row.get("categories") or []),
                "custom": False,
            })
    seen_custom = set()
    for tag in tags:
        for control in tag.controls or []:
            name = str(control.get("name") or "").strip()
            if not name:
                continue
            vendor = str(control.get("vendor") or "custom").strip() or "custom"
            control_id = str(control.get("id") or name).strip()
            key = _matrix_control_key("custom", f"{vendor}:{control_id}", name)
            if key in seen_custom:
                continue
            seen_custom.add(key)
            controls.append({
                "framework": "custom",
                "framework_label": "Controles internos",
                "control_id": control_id,
                "control_name": name,
                "vendor": vendor,
                "technique_keys": set(control.get("technique_keys") or []) | set(jobs_by_custom_control.get(key, set())),
                "categories": set(control.get("categories") or []),
                "custom": True,
                "custom_key": key,
            })
    return controls


def _control_applies_to_technique(control: dict[str, Any], technique: dict[str, Any]) -> bool:
    if control["technique_keys"]:
        return technique["technique_key"] in control["technique_keys"]
    if control["categories"]:
        return technique["category"] in control["categories"]
    return False


def control_matrix(
    db: Session, *, group_ids: list[int] | None = None, schedule_id: int | None = None
) -> dict[str, Any]:
    tags = _segment_tags(db, group_ids=group_ids)
    query = db.query(BasJob, BasAgent).join(BasAgent, BasAgent.id == BasJob.agent_id).filter(BasAgent.kind == "real")
    if group_ids is not None:
        query = query.filter(BasJob.access_group_id.in_(group_ids))
    if schedule_id is not None:
        query = query.filter(BasJob.schedule_id == schedule_id)
    jobs = query.all()

    statuses_by_technique: dict[str, list[str]] = {}
    counts_by_technique: dict[str, int] = {}
    statuses_by_custom_control: dict[tuple[str, str], list[str]] = {}
    jobs_by_custom_control: dict[str, set[str]] = {}
    cidr_tags = [tag for tag in tags if tag.match_type == "cidr" and tag.controls]
    for job, agent in jobs:
        technique_key = str(getattr(job, "technique_key", "") or "")
        if not technique_key:
            continue
        status = _matrix_job_status(job)
        statuses_by_technique.setdefault(technique_key, []).append(status)
        counts_by_technique[technique_key] = counts_by_technique.get(technique_key, 0) + 1
        target_value = getattr(job, "target", None) or getattr(agent, "local_network_cidr", None) or ""
        matching_tags = [tag for tag in cidr_tags if _target_or_cidr_within(target_value, tag.match_value)]
        for tag in matching_tags:
            for control in tag.controls or []:
                name = str(control.get("name") or "").strip()
                if not name:
                    continue
                vendor = str(control.get("vendor") or "custom").strip() or "custom"
                control_id = str(control.get("id") or name).strip()
                key = _matrix_control_key("custom", f"{vendor}:{control_id}", name)
                statuses_by_custom_control.setdefault((key, technique_key), []).append(status)
                jobs_by_custom_control.setdefault(key, set()).add(technique_key)

    techniques = list_techniques()
    controls = _control_matrix_defs(tags, jobs_by_custom_control)
    cells = []
    framework_rows: dict[str, dict[str, Any]] = {}
    for control in controls:
        framework = framework_rows.setdefault(control["framework"], {
            "framework": control["framework"],
            "label": control["framework_label"],
            "controls": {},
            "status_counts": {status: 0 for status in _CONTROL_MATRIX_STATUSES},
            "applicable": 0,
            "tested": 0,
            "coverage_pct": 0.0,
        })
        control_key = control.get("custom_key") or _matrix_control_key(control["framework"], control["control_id"], control["control_name"])
        framework["controls"].setdefault(control_key, {
            "id": control["control_id"],
            "name": control["control_name"],
            "vendor": control.get("vendor", ""),
            "custom": control["custom"],
            "cells": 0,
            "status_counts": {status: 0 for status in _CONTROL_MATRIX_STATUSES},
        })
        for technique in techniques:
            if not _control_applies_to_technique(control, technique):
                continue
            technique_key = technique["technique_key"]
            if control["framework"] == "custom":
                statuses = statuses_by_custom_control.get((control_key, technique_key), [])
            else:
                statuses = statuses_by_technique.get(technique_key, [])
            status = _strongest_matrix_status(statuses) if statuses else "not_applicable"
            cell = {
                "framework": control["framework"],
                "framework_label": control["framework_label"],
                "control_id": control["control_id"],
                "control_name": control["control_name"],
                "vendor": control.get("vendor", ""),
                "technique_key": technique_key,
                "technique_name": technique["display_name"],
                "category": technique["category"],
                "mitre_refs": technique.get("mitre_refs") or [],
                "status": status,
                "tested": bool(statuses),
                "times_tested": counts_by_technique.get(technique_key, 0),
                "reason": "" if statuses else "not_tested",
            }
            cells.append(cell)
            framework["applicable"] += 1
            framework["status_counts"][status] += 1
            if status != "not_applicable":
                framework["tested"] += 1
            control_row = framework["controls"][control_key]
            control_row["cells"] += 1
            control_row["status_counts"][status] += 1

    frameworks = []
    for framework in framework_rows.values():
        framework["controls"] = sorted(framework["controls"].values(), key=lambda item: (item["id"], item["name"]))
        framework["coverage_pct"] = round(100 * framework["tested"] / framework["applicable"], 1) if framework["applicable"] else 0.0
        frameworks.append(framework)
    return {
        "statuses": list(_CONTROL_MATRIX_STATUSES),
        "frameworks": sorted(frameworks, key=lambda item: item["label"]),
        "cells": sorted(cells, key=lambda item: (item["framework_label"], item["control_id"], item["technique_key"])),
        "summary": {
            "frameworks": len(frameworks),
            "controls": sum(len(framework["controls"]) for framework in frameworks),
            "cells": len(cells),
            "tested": sum(1 for cell in cells if cell["status"] != "not_applicable"),
            "prevented": sum(1 for cell in cells if cell["status"] == "prevented"),
            "detected": sum(1 for cell in cells if cell["status"] == "detected"),
            "missed": sum(1 for cell in cells if cell["status"] == "missed"),
            "not_applicable": sum(1 for cell in cells if cell["status"] == "not_applicable"),
        },
    }


def exposure_summary(
    db: Session, *, group_ids: list[int] | None = None, schedule_id: int | None = None
) -> dict[str, Any]:
    """Raw dispatch ACTIVITY (including stub-agent smoke-test traffic) --
    unlike framework_coverage/risk_score, this never claims coverage was
    proven, so blending stub + real dispatches here is fine."""
    query = db.query(BasJob)
    if group_ids is not None:
        query = query.filter(BasJob.access_group_id.in_(group_ids))
    if schedule_id is not None:
        query = query.filter(BasJob.schedule_id == schedule_id)
    jobs = query.all()

    # BasJob.target (one row per technique x target actually dispatched) is
    # the accurate source now -- a schedule's target_hint can be a list or a
    # CIDR range, so counting distinct BasSchedule.target_hint values would
    # count "10.0.0.5, app-db.internal" as ONE target instead of two, and
    # would count schedules that were created but never actually fired.
    targets = {j.target for j in jobs if j.target}

    categories_tested = {
        t["category"] for t in list_techniques() if t["technique_key"] in {j.technique_key for j in jobs}
    }
    real_tunnel_roundtrips = sum(1 for j in jobs if j.status == "completed")

    return {
        "distinct_targets_tested": len(targets),
        "categories_tested": sorted(categories_tested),
        "total_dispatches": len(jobs),
        "real_tunnel_roundtrips": real_tunnel_roundtrips,
        "failed_dispatches": sum(1 for j in jobs if j.status == "failed"),
    }


def port_scan_observability(
    db: Session, *, group_ids: list[int] | None = None, schedule_id: int | None = None, limit: int = 10
) -> dict[str, Any]:
    query = (
        db.query(BasJob, BasAgent)
        .join(BasAgent, BasAgent.id == BasJob.agent_id)
        .filter(
            BasAgent.kind == "real",
            BasJob.technique_key.in_(("port_service_scan", "firewall_segmentation_test")),
            BasJob.status == "completed",
        )
    )
    if group_ids is not None:
        query = query.filter(BasJob.access_group_id.in_(group_ids))
    if schedule_id is not None:
        query = query.filter(BasJob.schedule_id == schedule_id)

    scans = []
    total_open_ports = 0
    total_scanned_ips = 0
    for job, agent in query.order_by(BasJob.created_at.desc()).limit(limit).all():
        result = job.result or {}
        open_ports = _nmap_open_ports(result)
        summary = _nmap_summary(result)
        scanned_ips = int(summary.get("ip_addresses") or summary.get("reported_hosts") or 0)
        total_scanned_ips += scanned_ips
        total_open_ports += len(open_ports)
        scans.append({
            "job_id": job.id,
            "agent_id": agent.id,
            "agent_label": agent.label or agent.os or f"agente #{agent.id}",
            "target": job.target,
            "created_at": job.created_at,
            "finished_at": job.finished_at,
            "last_error": job.last_error,
            "scanned_ips": scanned_ips,
            "hosts_up": int(summary.get("hosts_up") or summary.get("reported_hosts") or 0),
            "duration_seconds": summary.get("duration_seconds") or result.get("duration_seconds"),
            "open_ports": open_ports[:50],
            "open_port_count": len(open_ports),
            "hosts_without_open_ports": int(summary.get("hosts_without_open_ports") or 0),
        })

    return {
        "scans": scans,
        "summary": {
            "scan_count": len(scans),
            "scanned_ips": total_scanned_ips,
            "open_port_count": total_open_ports,
            "scans_without_open_ports": sum(1 for scan in scans if scan["open_port_count"] == 0),
        },
    }


def bas_findings_view(
    db: Session, *, group_ids: list[int] | None = None, schedule_id: int | None = None, limit: int = 100
) -> list[dict[str, Any]]:
    query = db.query(Finding).filter(Finding.tool == BAS_FINDING_TOOL).order_by(Finding.created_at.desc())
    if group_ids is not None or schedule_id is not None:
        query = query.join(BasJob, BasJob.finding_id == Finding.id)
        if group_ids is not None:
            query = query.filter(BasJob.access_group_id.in_(group_ids))
        if schedule_id is not None:
            query = query.filter(BasJob.schedule_id == schedule_id)
    rows = query.limit(limit).all()

    # BAS technique findings rarely carry a CVE (Kerberoasting, SMB signing,
    # etc. are misconfigurations, not CVE-numbered bugs) -- EPSS/exploit-db
    # only ever applies to the subset that does. Batch the EPSS lookup (one
    # real FIRST.org call for every CVE at once, same service the main
    # pentest module already uses) and never invent a score for the rest.
    cves = sorted({f.cve for f in rows if f.cve})
    epss_by_cve: dict[str, dict] = {}
    if cves:
        try:
            from app.services.epss_service import get_epss_scores
            epss_by_cve = get_epss_scores(cves)
        except Exception:
            epss_by_cve = {}
    exploit_by_cve: dict[str, dict] = {}
    if cves:
        from app.services.exploitdb_check import check_exploitdb
        for cve in cves:
            try:
                exploit_by_cve[cve] = check_exploitdb(cve)
            except Exception:
                exploit_by_cve[cve] = {"available": None, "refs": []}

    results = []
    for f in rows:
        cve = f.cve
        epss_row = epss_by_cve.get(str(cve or "").upper()) if cve else None
        exploit_row = exploit_by_cve.get(cve) if cve else None
        results.append({
            "id": f.id, "title": f.title, "created_at": f.created_at,
            "severity": f.severity,
            "technique_key": (f.details or {}).get("technique_key"),
            "category": (f.details or {}).get("category"),
            "risk_tier": (f.details or {}).get("risk_tier"),
            "target": (f.details or {}).get("target"),
            "mitre_refs": (f.details or {}).get("mitre_refs", []),
            "recommendation": (f.details or {}).get("recommendation", ""),
            # Real content extracted from the tool's actual output (see
            # bas_scheduler._extract_key_findings) -- empty for a stub
            # dispatch or a real one that genuinely found nothing.
            "key_findings": (f.details or {}).get("key_findings", []),
            "simulated": bool((f.details or {}).get("simulated", True)),
            "proof": (f.details or {}).get("proof") or {},
            "proof_status": (f.details or {}).get("proof_status") or ((f.details or {}).get("proof") or {}).get("status"),
            "proof_valid": _proof_valid_from_finding(f),
            "cve": cve,
            "cvss": f.cvss,
            # None (not 0/"n/a" string) when there's no CVE to look up at all
            # -- the frontend renders that as "n/a", distinct from a CVE that
            # was looked up and genuinely has no EPSS/exploit-db record.
            "epss": epss_row.get("epss") if epss_row else None,
            "epss_percentile": epss_row.get("percentile") if epss_row else None,
            "exploit_available": exploit_row.get("available") if exploit_row else None,
            "exploit_refs": exploit_row.get("refs", []) if exploit_row else [],
        })
    return results


def active_runs(
    db: Session, *, group_ids: list[int] | None = None, schedule_id: int | None = None, limit: int = 20
) -> list[dict[str, Any]]:
    scan_query = db.query(ScanJob).filter(
        ScanJob.mode == "bas",
        ScanJob.status.in_(("queued", "running")),
    )
    if group_ids is not None:
        scan_query = scan_query.filter(ScanJob.access_group_id.in_(group_ids))
    scans = scan_query.order_by(ScanJob.updated_at.desc()).limit(limit).all()
    rows = []
    for scan in scans:
        scan_state = dict(getattr(scan, "state_data", None) or {})
        jobs = db.query(BasJob).filter(BasJob.scan_job_id == scan.id).order_by(BasJob.created_at.asc()).all()
        scan_schedule_id = scan_state.get("bas_schedule_id")
        if schedule_id is not None and scan_schedule_id != schedule_id and not any(job.schedule_id == schedule_id for job in jobs):
            continue
        first_job = jobs[0] if jobs else None
        active_job = next(
            (job for job in reversed(jobs) if str(job.status or "").lower() in {"queued", "dispatched_to_kali", "running"}),
            jobs[-1] if jobs else None,
        )
        schedule_lookup_id = getattr(first_job, "schedule_id", None) or scan_schedule_id
        agent_lookup_id = getattr(first_job, "agent_id", None) or scan_state.get("bas_agent_id")
        schedule = db.query(BasSchedule).filter(BasSchedule.id == schedule_lookup_id).first() if schedule_lookup_id else None
        agent = db.query(BasAgent).filter(BasAgent.id == agent_lookup_id).first() if agent_lookup_id else None
        terminal_count = sum(1 for job in jobs if str(job.status or "").lower() in {"completed", "failed", "skipped", "cancelled"})
        total_hint = max(len(getattr(schedule, "technique_keys", None) or scan_state.get("bas_technique_keys") or []), len(jobs), 1)
        progress = int(getattr(scan, "mission_progress", None) or 0)
        rows.append({
            "scan_job_id": scan.id,
            "status": scan.status,
            "current_step": scan.current_step or "Preparando execução",
            "mission_progress": max(0, min(99, progress)),
            "target_query": scan.target_query,
            "schedule_id": getattr(schedule, "id", None),
            "schedule_name": getattr(schedule, "name", "") or (f"scan BAS #{scan.id}"),
            "chain_key": getattr(schedule, "chain_key", None),
            "agent_id": getattr(agent, "id", None),
            "agent_label": getattr(agent, "label", "") or getattr(agent, "hostname", "") or "",
            "agent_status": getattr(agent, "status", None),
            "active_job_id": getattr(active_job, "id", None),
            "active_technique_key": getattr(active_job, "technique_key", None),
            "active_target": getattr(active_job, "target", None),
            "jobs_total_seen": len(jobs),
            "jobs_resolved": terminal_count,
            "jobs_failed": sum(1 for job in jobs if str(job.status or "").lower() == "failed"),
            "jobs_skipped": sum(1 for job in jobs if str(job.status or "").lower() == "skipped"),
            "total_hint": total_hint,
            "created_at": scan.created_at,
            "updated_at": scan.updated_at,
            "last_error": scan.last_error,
        })
    return rows


def action_priorities(
    db: Session, *, group_ids: list[int] | None = None, schedule_id: int | None = None, limit: int = 20
) -> list[dict[str, Any]]:
    query = (
        db.query(BasJob, BasAgent, BasSchedule)
        .join(BasAgent, BasAgent.id == BasJob.agent_id)
        .join(BasSchedule, BasSchedule.id == BasJob.schedule_id)
        .filter(BasAgent.kind == "real", BasJob.status == "completed")
    )
    if group_ids is not None:
        query = query.filter(BasJob.access_group_id.in_(group_ids))
    if schedule_id is not None:
        query = query.filter(BasJob.schedule_id == schedule_id)

    rows = query.order_by(BasJob.created_at.desc()).limit(200).all()
    items_by_key: dict[tuple[str, str], dict[str, Any]] = {}

    def add_item(item: dict[str, Any]) -> None:
        key = (item["priority"], item["title"])
        existing = items_by_key.get(key)
        if existing is None:
            item["source_job_ids"] = [item["job_id"]]
            items_by_key[key] = item
            return
        seen_targets = set(existing["affected_targets"])
        for target in item["affected_targets"]:
            if target not in seen_targets:
                existing["affected_targets"].append(target)
                seen_targets.add(target)
        seen_evidence = set(existing["evidence"])
        for evidence in item["evidence"]:
            if evidence not in seen_evidence:
                existing["evidence"].append(evidence)
                seen_evidence.add(evidence)
        existing["affected_count"] = len(existing["affected_targets"])
        existing["source_job_ids"].append(item["job_id"])
        if item["created_at"] > existing["created_at"]:
            existing.update({
                "job_id": item["job_id"],
                "schedule_id": item["schedule_id"],
                "schedule_name": item["schedule_name"],
                "agent_id": item["agent_id"],
                "agent_name": item["agent_name"],
                "created_at": item["created_at"],
            })

    for job, agent, schedule in rows:
        if not _proof_valid_from_result(getattr(job, "result", None)):
            continue
        result = job.result or {}
        if job.technique_key == "smb_enum_cme":
            observations = _smb_observations(str(result.get("stdout") or ""))
            smbv1_hosts = [o for o in observations if o["smbv1_enabled"]]
            unsigned_hosts = [o for o in observations if not o["signing_required"]]
            reachable_hosts = observations

            if smbv1_hosts:
                add_item({
                    "id": f"smbv1-{job.id}",
                    "priority": "P0",
                    "title": "Desativar SMBv1 nos hosts encontrados",
                    "category": "smb",
                    "impact": "SMBv1 habilitado aumenta exposição a exploração lateral e protocolos legados inseguros.",
                    "next_action": "Desabilitar SMBv1 por GPO/MDM, validar exceções e repetir o teste BAS na mesma máscara.",
                    "affected_count": len(smbv1_hosts),
                    "affected_targets": [f"{h['ip']} ({h['host']})" for h in smbv1_hosts],
                    "evidence": [h["evidence"] for h in smbv1_hosts],
                    "job_id": job.id,
                    "schedule_id": schedule.id,
                    "schedule_name": schedule.name,
                    "agent_id": agent.id,
                    "agent_name": agent.label or agent.hostname,
                    "created_at": job.created_at,
                })
            if unsigned_hosts:
                add_item({
                    "id": f"smb-signing-{job.id}",
                    "priority": "P1",
                    "title": "Exigir SMB signing onde o teste mostrou signing desabilitado",
                    "category": "smb",
                    "impact": "Hosts sem SMB signing são candidatos a relay/man-in-the-middle em redes internas.",
                    "next_action": "Aplicar política de assinatura SMB obrigatória em servidores e estações compatíveis, priorizando os ativos listados.",
                    "affected_count": len(unsigned_hosts),
                    "affected_targets": [f"{h['ip']} ({h['host']})" for h in unsigned_hosts],
                    "evidence": [h["evidence"] for h in unsigned_hosts],
                    "job_id": job.id,
                    "schedule_id": schedule.id,
                    "schedule_name": schedule.name,
                    "agent_id": agent.id,
                    "agent_name": agent.label or agent.hostname,
                    "created_at": job.created_at,
                })
            if reachable_hosts:
                add_item({
                    "id": f"smb-reachable-{job.id}",
                    "priority": "P2",
                    "title": "Revisar segmentação dos hosts SMB alcançáveis",
                    "category": "smb",
                    "impact": "O agente conseguiu alcançar SMB/445 em múltiplos ativos dentro da máscara testada.",
                    "next_action": "Confirmar se esses hosts deveriam estar acessíveis a partir desse segmento e bloquear fluxos desnecessários.",
                    "affected_count": len(reachable_hosts),
                    "affected_targets": [f"{h['ip']} ({h['host']})" for h in reachable_hosts],
                    "evidence": [h["evidence"] for h in reachable_hosts],
                    "job_id": job.id,
                    "schedule_id": schedule.id,
                    "schedule_name": schedule.name,
                    "agent_id": agent.id,
                    "agent_name": agent.label or agent.hostname,
                    "created_at": job.created_at,
                })

    priority_rank = {"P0": 0, "P1": 1, "P2": 2, "P3": 3}
    items = list(items_by_key.values())
    return sorted(items, key=lambda item: (priority_rank.get(item["priority"], 9), -item["affected_count"]))[:limit]


def _segment_tags(db: Session, *, group_ids: list[int] | None = None) -> list[BasNetworkSegmentTag]:
    query = db.query(BasNetworkSegmentTag)
    if group_ids is not None:
        query = query.filter(BasNetworkSegmentTag.access_group_id.in_(group_ids))
    return query.all()


def _ip_matches_cidr(ip: str, cidr: str) -> bool:
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False


def _resolve_segment_tag(
    ip: str, domain: str, tags: list[BasNetworkSegmentTag]
) -> BasNetworkSegmentTag | None:
    """Domain match wins over a CIDR match -- a domain is a more specific,
    intentional declaration than "falls inside this /24"."""
    domain_norm = str(domain or "").strip().lower()
    if domain_norm:
        for tag in tags:
            if tag.match_type == "domain" and str(tag.match_value or "").strip().lower() == domain_norm:
                return tag
    if ip:
        for tag in tags:
            if tag.match_type == "cidr" and _ip_matches_cidr(ip, tag.match_value):
                return tag
    return None


def _segment_tag_view(tag: BasNetworkSegmentTag | None) -> dict[str, Any]:
    if tag is None:
        return {"business_unit": None, "criticality": None, "controls": [], "classified": False}
    return {
        "business_unit": tag.business_unit or None,
        "criticality": tag.criticality,
        "controls": list(tag.controls or []),
        "classified": True,
    }


def attack_path_inventory(
    db: Session, *, group_ids: list[int] | None = None, schedule_id: int | None = None
) -> dict[str, Any]:
    query = (
        db.query(BasJob, BasAgent, BasSchedule)
        .join(BasAgent, BasAgent.id == BasJob.agent_id)
        .join(BasSchedule, BasSchedule.id == BasJob.schedule_id)
        .filter(BasAgent.kind == "real", BasJob.status == "completed")
    )
    if group_ids is not None:
        query = query.filter(BasJob.access_group_id.in_(group_ids))
    if schedule_id is not None:
        query = query.filter(BasJob.schedule_id == schedule_id)

    rows = query.order_by(BasJob.created_at.desc()).limit(200).all()
    assets: dict[str, dict[str, Any]] = {}

    def ensure_asset(ip: str, job: BasJob, agent: BasAgent, schedule: BasSchedule) -> dict[str, Any]:
        asset = assets.get(ip)
        if asset is None:
            asset = {
                "ip": ip,
                "hostname": ip,
                "os": "",
                "domain": "",
                "first_seen": job.created_at,
                "last_seen": job.created_at,
                "source_job_ids": [],
                "agent_ids": [],
                "schedule_ids": [],
                "services": [],
                "vulnerabilities": [],
                "risk_level": "low",
            }
            assets[ip] = asset
        asset["last_seen"] = max(asset["last_seen"], job.created_at)
        asset["first_seen"] = min(asset["first_seen"], job.created_at)
        if job.id not in asset["source_job_ids"]:
            asset["source_job_ids"].append(job.id)
        if agent.id not in asset["agent_ids"]:
            asset["agent_ids"].append(agent.id)
        if schedule.id not in asset["schedule_ids"]:
            asset["schedule_ids"].append(schedule.id)
        return asset

    for job, agent, schedule in rows:
        if not _proof_valid_from_result(getattr(job, "result", None)):
            continue
        result = job.result or {}
        if job.technique_key in {"port_service_scan", "firewall_segmentation_test"}:
            for port in _nmap_open_ports(result):
                asset = ensure_asset(port["host"], job, agent, schedule)
                service = {
                    "name": str(port["service"]).upper() if str(port["service"]).lower() != "unknown" else f"TCP/{port['port']}",
                    "port": port["port"],
                    "protocol": port["protocol"],
                    "application": "HTTP service" if port["port"] in {80, 443, 8000, 8008, 8080, 8443, 8888} or "http" in str(port["service"]).lower() else str(port["service"]),
                    "version": str(port["service"]),
                    "evidence": f"{port['host']}: {port['port']}/{port['protocol']} open {port['service']}",
                }
                if not any(s["port"] == service["port"] and s["protocol"] == service["protocol"] for s in asset["services"]):
                    asset["services"].append(service)
            continue
        if job.technique_key != "smb_enum_cme":
            continue
        for observation in _smb_observations(str(result.get("stdout") or "")):
            asset = ensure_asset(observation["ip"], job, agent, schedule)
            asset["hostname"] = observation["host"]
            asset["os"] = observation["os"]
            asset["domain"] = observation["domain"]

            service = {
                "name": "SMB",
                "port": 445,
                "protocol": "tcp",
                "application": "Microsoft SMB",
                "version": "SMBv1 habilitado" if observation["smbv1_enabled"] else "SMBv2/3 observado",
                "evidence": observation["evidence"],
            }
            if not any(s["name"] == service["name"] and s["port"] == service["port"] for s in asset["services"]):
                asset["services"].append(service)

            if observation["smbv1_enabled"] and not any(v["id"] == "smbv1_enabled" for v in asset["vulnerabilities"]):
                asset["vulnerabilities"].append({
                    "id": "smbv1_enabled",
                    "severity": "high",
                    "title": "SMBv1 habilitado",
                    "recommendation": "Desativar SMBv1 e validar compatibilidade de aplicações legadas.",
                })
                asset["risk_level"] = "high"
            if not observation["signing_required"] and not any(v["id"] == "smb_signing_disabled" for v in asset["vulnerabilities"]):
                asset["vulnerabilities"].append({
                    "id": "smb_signing_disabled",
                    "severity": "medium",
                    "title": "SMB signing não obrigatório",
                    "recommendation": "Exigir SMB signing por política nos hosts compatíveis.",
                })
                if asset["risk_level"] != "high":
                    asset["risk_level"] = "medium"

    sorted_assets = sorted(
        assets.values(),
        key=lambda asset: ({"high": 0, "medium": 1, "low": 2}.get(asset["risk_level"], 9), asset["ip"]),
    )
    segment_tags = _segment_tags(db, group_ids=group_ids)
    for asset in sorted_assets:
        tag = _resolve_segment_tag(asset["ip"], asset.get("domain", ""), segment_tags)
        asset.update(_segment_tag_view(tag))

    applications: dict[tuple[str, str], dict[str, Any]] = {}
    vulnerability_summary: dict[str, dict[str, Any]] = {}

    for asset in sorted_assets:
        for service in asset["services"]:
            key = (service["application"], service["version"])
            app = applications.setdefault(key, {
                "name": service["application"],
                "version": service["version"],
                "protocol": service["protocol"],
                "port": service["port"],
                "hosts": [],
            })
            app["hosts"].append({"ip": asset["ip"], "hostname": asset["hostname"], "risk_level": asset["risk_level"]})
        for vulnerability in asset["vulnerabilities"]:
            summary = vulnerability_summary.setdefault(vulnerability["id"], {
                "id": vulnerability["id"],
                "severity": vulnerability["severity"],
                "title": vulnerability["title"],
                "recommendation": vulnerability["recommendation"],
                "affected_assets": [],
            })
            summary["affected_assets"].append({"ip": asset["ip"], "hostname": asset["hostname"]})

    attack_steps = []
    if sorted_assets:
        attack_steps.append({
            "order": 1,
            "title": "Entrada pelo segmento do agente",
            "description": "O agente real alcançou serviços internos a partir da máscara reportada.",
            "evidence": f"{len(sorted_assets)} ativo(s) SMB/445 alcançável(is)",
            "status": "observed",
        })
    if any(v["id"] == "smb_signing_disabled" for asset in sorted_assets for v in asset["vulnerabilities"]):
        attack_steps.append({
            "order": 2,
            "title": "Possibilidade de relay SMB/NTLM",
            "description": "Hosts sem assinatura SMB obrigatória aumentam a viabilidade de relay em rede interna.",
            "evidence": f"{len(vulnerability_summary.get('smb_signing_disabled', {}).get('affected_assets', []))} ativo(s) sem signing obrigatório",
            "status": "needs_fix",
        })
    if any(v["id"] == "smbv1_enabled" for asset in sorted_assets for v in asset["vulnerabilities"]):
        attack_steps.append({
            "order": 3,
            "title": "Exploração de legado SMBv1",
            "description": "SMBv1 habilitado indica protocolo legado com risco elevado e deve ser removido.",
            "evidence": f"{len(vulnerability_summary.get('smbv1_enabled', {}).get('affected_assets', []))} ativo(s) com SMBv1",
            "status": "critical_fix",
        })

    recommended_tests = []
    tested_keys = {job.technique_key for job, _, _ in rows}
    if "smb_enum_cme" in tested_keys and "network_share_discovery" not in tested_keys:
        recommended_tests.append("network_share_discovery para validar compartilhamentos e permissões por host.")
    if "smb_enum_cme" in tested_keys and "ad_scouting_ldap" not in tested_keys:
        recommended_tests.append("ad_scouting_ldap para correlacionar hosts SMB com domínio, OU e contas.")
    if "port_service_scan" not in tested_keys:
        recommended_tests.append("port_service_scan na mesma máscara para enriquecer CMDB com portas e versões além de SMB.")

    return {
        "summary": {
            "assets": len(sorted_assets),
            "applications": len(applications),
            "vulnerabilities": len(vulnerability_summary),
            "high_risk_assets": sum(1 for asset in sorted_assets if asset["risk_level"] == "high"),
            "medium_risk_assets": sum(1 for asset in sorted_assets if asset["risk_level"] == "medium"),
        },
        "attack_steps": attack_steps,
        "cmdb_assets": sorted_assets[:50],
        "applications": sorted(applications.values(), key=lambda app: (-len(app["hosts"]), app["name"], app["version"])),
        "vulnerabilities": sorted(
            vulnerability_summary.values(),
            key=lambda item: ({"critical": 0, "high": 1, "medium": 2, "low": 3}.get(item["severity"], 9), -len(item["affected_assets"])),
        ),
        "recommended_tests": recommended_tests,
    }


def _target_or_cidr_within(value: str, tag_cidr: str) -> bool:
    """value is either a bare IP or a CIDR (accepts_range techniques store
    the whole range as BasJob.target) -- match if it's inside, equal to, or
    overlapping the tag's declared CIDR."""
    try:
        tag_net = ipaddress.ip_network(tag_cidr, strict=False)
    except ValueError:
        return False
    value = str(value or "").strip()
    if not value:
        return False
    try:
        if "/" in value:
            return ipaddress.ip_network(value, strict=False).overlaps(tag_net)
        return ipaddress.ip_address(value) in tag_net
    except ValueError:
        return False


def protection_layers(
    db: Session, *, group_ids: list[int] | None = None, schedule_id: int | None = None
) -> list[dict[str, Any]]:
    """For every named control an operator declared on a network-segment tag
    (BasNetworkSegmentTag.controls), the real Proven/Blocked split of every
    REAL-agent job whose target resolves into that segment.

    Segment resolution here is CIDR-only (job.target/agent.local_network_cidr
    vs tag.match_value) -- unlike attack_path_inventory's per-asset view, a
    job's target domain isn't known until SMB/AD enumeration parses it out of
    the tool's own output, so a domain tag can't be matched at dispatch time.
    A job whose target matches no tagged segment contributes to no control --
    real absence of instrumentation, not a guess. No "detected" state: same
    2-state Proven/Blocked honesty rule as attack_heatmap/kill_chain_stages.
    Controls with fewer than 3 resolved jobs are marked low_confidence rather
    than shown as a misleadingly precise 100%/0%."""
    tags = [t for t in _segment_tags(db, group_ids=group_ids) if t.match_type == "cidr" and t.controls]
    if not tags:
        return []

    query = (
        db.query(BasJob, BasAgent)
        .join(BasAgent, BasAgent.id == BasJob.agent_id)
        .filter(BasAgent.kind == "real", BasJob.status.in_(["completed", "failed"]))
    )
    if group_ids is not None:
        query = query.filter(BasJob.access_group_id.in_(group_ids))
    if schedule_id is not None:
        query = query.filter(BasJob.schedule_id == schedule_id)

    tallies: dict[tuple[str, str], dict[str, int]] = {}

    def tally_for(name: str, vendor: str) -> dict[str, int]:
        return tallies.setdefault((name, vendor), {"proven": 0, "blocked": 0, "unproven": 0})

    for job, agent in query.all():
        target_value = job.target or agent.local_network_cidr or ""
        matching_tags = [t for t in tags if _target_or_cidr_within(target_value, t.match_value)]
        if not matching_tags:
            continue
        if job.status == "completed" and _proof_valid_from_result(job.result):
            outcome = "proven"
        elif job.status == "completed":
            outcome = "unproven"
        else:
            outcome = "blocked"
        for tag in matching_tags:
            for control in tag.controls or []:
                name = str(control.get("name") or "").strip()
                vendor = str(control.get("vendor") or "").strip()
                if not name:
                    continue
                tally_for(name, vendor)[outcome] += 1

    rows = []
    for (name, vendor), counts in tallies.items():
        resolved = counts["proven"] + counts["blocked"]
        sample_size = resolved + counts["unproven"]
        rows.append({
            "name": name,
            "vendor": vendor,
            "prevented_pct": round(100 * counts["blocked"] / resolved, 1) if resolved else None,
            "missed_pct": round(100 * counts["proven"] / resolved, 1) if resolved else None,
            "sample_size": sample_size,
            "low_confidence": sample_size < 3,
        })
    return sorted(rows, key=lambda r: -r["sample_size"])


def crown_jewels_view(
    db: Session, *, group_ids: list[int] | None = None, schedule_id: int | None = None
) -> list[dict[str, Any]]:
    """Reuses the platform's real crown-jewel keyword identifier
    (crown_jewel_analyzer.identify_crown_jewels) against BAS schedules'
    target_hints -- the same "does this hostname look high-value" signal
    used for external targets, applied to internal ones."""
    query = db.query(BasSchedule)
    if group_ids is not None:
        query = query.filter(BasSchedule.access_group_id.in_(group_ids))
    if schedule_id is not None:
        query = query.filter(BasSchedule.id == schedule_id)
    schedules = query.all()

    # target_hint can now be a comma/semicolon/newline-separated list -- split
    # it the same way bas_scheduler.fire_schedule does before handing hints to
    # the crown-jewel identifier, or a multi-target string like
    # "10.0.0.5, app-db.internal" would be scored as one garbled hint instead
    # of two real ones.
    hints = [target for s in schedules if s.target_hint for target in _split_targets(s.target_hint, "")]
    hints = [h for h in hints if h]
    jewels = identify_crown_jewels(hints)
    jewel_map = {t: (boost, label) for t, boost, label in jewels}

    # BasJob.target (the actual per-dispatch target) is the accurate count
    # now -- a schedule's raw target_hint is no longer 1:1 with what a single
    # job ran against.
    job_count_query = db.query(BasJob)
    if schedule_id is not None:
        job_count_query = job_count_query.filter(BasJob.schedule_id == schedule_id)
    job_counts = Counter(row.target for row in job_count_query.all() if row.target)

    return [
        {"target": target, "label": label, "boost": boost, "jobs_run": job_counts.get(target, 0)}
        for target, (boost, label) in sorted(jewel_map.items(), key=lambda kv: kv[1][0])
    ]


def risk_score(
    db: Session, *, group_ids: list[int] | None = None, schedule_id: int | None = None
) -> dict[str, Any]:
    """0-100: share of REAL-agent dispatches whose relay actually completed
    vs. genuinely failed/blocked at the network or tool level -- exactly the
    "how many techniques worked vs. were blocked" metric requested. Stub
    dispatches are excluded entirely: bas_agent_stub always fabricates its
    response content, so its "completed" status carries no security signal
    at all -- counting it here would make the score meaningless the moment
    any real agent activity mixes in. A high score means most REAL
    dispatches completed their relay; it does not by itself mean a specific
    vulnerability was proven. Jobs still queued/running/skipped are excluded
    from the ratio -- they have no resolved outcome yet."""
    query = db.query(BasJob).join(BasAgent, BasAgent.id == BasJob.agent_id).filter(BasAgent.kind == "real")
    if group_ids is not None:
        query = query.filter(BasJob.access_group_id.in_(group_ids))
    if schedule_id is not None:
        query = query.filter(BasJob.schedule_id == schedule_id)
    rows = query.all()
    completed = sum(1 for row in rows if _status_from_risk_row(row) == "completed" and _risk_row_has_valid_proof(row))
    unproven = sum(1 for row in rows if _status_from_risk_row(row) == "completed" and not _risk_row_has_valid_proof(row))
    failed = sum(1 for row in rows if _status_from_risk_row(row) == "failed")
    resolved = completed + failed + unproven
    return {
        "score": round(100 * completed / resolved) if resolved else None,
        "worked": completed,
        "blocked": failed,
        "unproven": unproven,
        "proof_validated": completed,
        "resolved_total": resolved,
    }


def attack_heatmap(
    db: Session, *, group_ids: list[int] | None = None, schedule_id: int | None = None
) -> list[dict[str, Any]]:
    """One row per cataloged MITRE technique reference: how many times it's
    been dispatched (0 = never tested -- a coverage gap, not a finding).
    Dispatch/completion counts here are raw ACTIVITY (stub + real blended),
    same scope note as exposure_summary -- for a real-agent-only coverage
    claim use framework_coverage instead.

    `outcome` is a real, 2-state signal (no fabricated "detected" middle
    state -- see risk_score's docstring for why): "proven" if any REAL-agent
    dispatch of this technique produced valid bas_proof, "blocked" if every
    resolved REAL-agent dispatch failed, "unproven" if it completed without
    valid proof, "not_tested" if no real-agent dispatch exists at all."""
    query = (
        db.query(BasJob.technique_key, BasJob.status, BasJob.result, BasAgent.kind)
        .join(BasAgent, BasAgent.id == BasJob.agent_id)
    )
    if group_ids is not None:
        query = query.filter(BasJob.access_group_id.in_(group_ids))
    if schedule_id is not None:
        query = query.filter(BasJob.schedule_id == schedule_id)
    counts = Counter()
    completed_counts = Counter()
    proven_counts = Counter()
    unproven_counts = Counter()
    blocked_counts = Counter()
    for technique_key, job_status, result, agent_kind in query.all():
        # times_tested/times_completed stay blended activity (stub + real) --
        # same scope as the module-level "coverage gaps are visible" rule.
        # The Proven/Unproven/Blocked outcome, however, is a REAL-agent-only
        # signal (a stub always fabricates its result, so it has no outcome).
        counts[technique_key] += 1
        if job_status == "completed":
            completed_counts[technique_key] += 1
        if agent_kind != "real":
            continue
        if job_status == "completed":
            if _proof_valid_from_result(result):
                proven_counts[technique_key] += 1
            else:
                unproven_counts[technique_key] += 1
        elif job_status == "failed":
            blocked_counts[technique_key] += 1

    def outcome_for(key: str) -> str:
        if proven_counts.get(key):
            return "proven"
        if blocked_counts.get(key):
            return "blocked"
        if unproven_counts.get(key):
            return "unproven"
        return "not_tested"

    rows = []
    for t in list_techniques():
        for mitre_id in t["mitre_refs"]:
            rows.append({
                "mitre_id": mitre_id,
                "technique_key": t["technique_key"],
                "display_name": t["display_name"],
                "category": t["category"],
                "availability": t["availability"],
                "times_tested": counts.get(t["technique_key"], 0),
                "times_completed": completed_counts.get(t["technique_key"], 0),
                "times_proven": proven_counts.get(t["technique_key"], 0),
                "times_unproven": unproven_counts.get(t["technique_key"], 0),
                "times_blocked": blocked_counts.get(t["technique_key"], 0),
                "outcome": outcome_for(t["technique_key"]),
            })
    return sorted(rows, key=lambda r: (-r["times_tested"], r["mitre_id"]))


# Best-effort grouping of the real BAS catalog's `category` field into the
# classic cyber-kill-chain phases, for the Painel's "Test depth" bar. This is
# an editorial judgment call, not an authoritative MITRE tactic mapping (the
# catalog was never annotated with tactic-per-technique) -- every count it
# produces is a real dispatch, only the phase LABEL a technique is bucketed
# under is approximate.
KILL_CHAIN_STAGES: list[tuple[str, str, set[str]]] = [
    ("reconnaissance", "Reconnaissance", {"network"}),
    ("initial_access", "Initial access", {"ntlm", "exploit_validation", "web"}),
    ("execution", "Execution", {"windows", "linux", "cicd"}),
    ("persistence", "Persistence", {"identity"}),
    ("privilege_escalation", "Privilege escalation", {"ad", "vmware"}),
    ("defense_evasion", "Defense evasion", {"firewall"}),
    ("lateral_movement", "Lateral movement", {"lateral_movement", "smb"}),
    ("exfiltration", "Exfiltration / Impact", {"cloud"}),
]


def kill_chain_stages(
    db: Session, *, group_ids: list[int] | None = None, schedule_id: int | None = None
) -> list[dict[str, Any]]:
    """Per kill-chain stage: how many cataloged techniques in that stage were
    ever dispatched through a REAL agent, and the real Proven/Unproven/Blocked
    split of those dispatches (see attack_heatmap's outcome semantics --
    deliberately 2 resolved states, no fabricated "detected")."""
    heatmap = attack_heatmap(db, group_ids=group_ids, schedule_id=schedule_id)
    by_technique: dict[str, dict[str, Any]] = {}
    for row in heatmap:
        by_technique.setdefault(row["technique_key"], row)

    techniques_by_category: dict[str, list[str]] = {}
    for t in list_techniques():
        techniques_by_category.setdefault(t["category"], []).append(t["technique_key"])

    stages = []
    for key, label, categories in KILL_CHAIN_STAGES:
        keys = [k for cat in categories for k in techniques_by_category.get(cat, [])]
        total = len(keys)
        proven = sum(1 for k in keys if by_technique.get(k, {}).get("outcome") == "proven")
        unproven = sum(1 for k in keys if by_technique.get(k, {}).get("outcome") == "unproven")
        blocked = sum(1 for k in keys if by_technique.get(k, {}).get("outcome") == "blocked")
        tested = proven + unproven + blocked
        stages.append({
            "stage": key, "label": label, "total": total, "tested": tested,
            "proven_pct": round(100 * proven / total, 1) if total else 0.0,
            "unproven_pct": round(100 * unproven / total, 1) if total else 0.0,
            "blocked_pct": round(100 * blocked / total, 1) if total else 0.0,
        })
    return stages


def category_coverage(
    db: Session, *, group_ids: list[int] | None = None, schedule_id: int | None = None
) -> list[dict[str, Any]]:
    """Per real BAS catalog category: how many of its techniques have been
    dispatched at least once through a REAL agent (tested/total), plus the
    safe/elevated/high_risk mix of the TESTED ones -- mirrors framework_coverage's
    "REAL agent only counts as tested" rule."""
    tested_keys = _real_agent_technique_keys(db, group_ids=group_ids, schedule_id=schedule_id)
    by_category: dict[str, list[dict[str, Any]]] = {}
    for t in list_techniques():
        by_category.setdefault(t["category"], []).append(t)

    rows = []
    for category, techniques in by_category.items():
        tested = [t for t in techniques if t["technique_key"] in tested_keys]
        rows.append({
            "category": category,
            "tested": len(tested),
            "total": len(techniques),
            "safe": sum(1 for t in tested if t["risk_tier"] == "safe"),
            "elevated": sum(1 for t in tested if t["risk_tier"] == "elevated"),
            "high_risk": sum(1 for t in tested if t["risk_tier"] == "high_risk"),
        })
    return sorted(rows, key=lambda r: (-r["tested"], r["category"]))


def resilience_score(
    db: Session, *, group_ids: list[int] | None = None, schedule_id: int | None = None, window_days: int = 7
) -> dict[str, Any]:
    """risk_score() over the last `window_days`, plus the same computation for
    the immediately-preceding window of equal length -- a real delta with no
    external benchmark. There is no "industry median": no benchmark data
    source exists for this platform, so the frontend must not show one."""
    from datetime import datetime, timedelta

    now = datetime.now()
    current_start = now - timedelta(days=window_days)
    previous_start = now - timedelta(days=2 * window_days)

    def score_between(start, end):
        query = db.query(BasJob).join(BasAgent, BasAgent.id == BasJob.agent_id).filter(
            BasAgent.kind == "real", BasJob.created_at >= start, BasJob.created_at < end,
        )
        if group_ids is not None:
            query = query.filter(BasJob.access_group_id.in_(group_ids))
        if schedule_id is not None:
            query = query.filter(BasJob.schedule_id == schedule_id)
        rows = query.all()
        completed = sum(1 for row in rows if row.status == "completed" and _proof_valid_from_result(row.result))
        failed = sum(1 for row in rows if row.status == "failed")
        unproven = sum(1 for row in rows if row.status == "completed" and not _proof_valid_from_result(row.result))
        resolved = completed + failed + unproven
        return round(100 * completed / resolved) if resolved else None

    current = score_between(current_start, now)
    previous = score_between(previous_start, current_start)
    delta = (current - previous) if current is not None and previous is not None else None
    return {"score": current, "previous_score": previous, "delta": delta, "window_days": window_days}


def score_trend(
    db: Session, *, group_ids: list[int] | None = None, schedule_id: int | None = None, weeks: int = 12
) -> list[dict[str, Any]]:
    """risk_score() recomputed per week-bucket from real BasJob.created_at
    timestamps -- no snapshot table, no synthetic interpolation. A week with
    no resolved real-agent jobs reports score=None (rendered as a gap in the
    trend line), never a fabricated value."""
    from datetime import datetime, timedelta

    now = datetime.now()
    points = []
    for i in range(weeks, 0, -1):
        end = now - timedelta(days=7 * (i - 1))
        start = end - timedelta(days=7)
        query = db.query(BasJob).join(BasAgent, BasAgent.id == BasJob.agent_id).filter(
            BasAgent.kind == "real", BasJob.created_at >= start, BasJob.created_at < end,
        )
        if group_ids is not None:
            query = query.filter(BasJob.access_group_id.in_(group_ids))
        if schedule_id is not None:
            query = query.filter(BasJob.schedule_id == schedule_id)
        rows = query.all()
        completed = sum(1 for row in rows if row.status == "completed" and _proof_valid_from_result(row.result))
        failed = sum(1 for row in rows if row.status == "failed")
        unproven = sum(1 for row in rows if row.status == "completed" and not _proof_valid_from_result(row.result))
        resolved = completed + failed + unproven
        points.append({
            "week_start": start.date().isoformat(),
            "score": round(100 * completed / resolved) if resolved else None,
            "resolved": resolved,
        })
    return points


def chain_attack_path(
    db: Session, *, group_ids: list[int] | None = None, schedule_id: int | None = None, limit: int = 10
) -> list[dict[str, Any]]:
    """The actual kill-chain path for each fired chain schedule (BasSchedule.
    chain_key set) -- a real, ordered sequence of what was attempted and what
    genuinely happened at each step, grouped by the shadow ScanJob one
    fire_schedule() call created. This is deliberately BAS-specific rather
    than feeding into the platform's general attack_path.py graph: that
    graph is selected by picking a real external Scan, and BAS shadow
    ScanJobs (mode="bas") are intentionally hidden from that scan list (see
    routes_scans.py) so they never clutter it -- this is the dedicated view
    for exactly that data instead."""
    from app.services.bas_technique_catalog import get_technique

    query = (
        db.query(BasJob, BasSchedule, BasAgent)
        .join(BasSchedule, BasSchedule.id == BasJob.schedule_id)
        .join(BasAgent, BasAgent.id == BasSchedule.agent_id)
        .filter(BasSchedule.chain_key.isnot(None))
    )
    if group_ids is not None:
        query = query.filter(BasJob.access_group_id.in_(group_ids))
    if schedule_id is not None:
        query = query.filter(BasJob.schedule_id == schedule_id)
    rows = query.order_by(BasJob.created_at.asc()).all()

    from app.services.bas_chain_catalog import get_chain

    paths_by_scan_job: dict[int, dict[str, Any]] = {}
    for job, schedule, agent in rows:
        entry = paths_by_scan_job.get(job.scan_job_id)
        if entry is None:
            chain = get_chain(schedule.chain_key) or {}
            entry = {
                "scan_job_id": job.scan_job_id,
                "schedule_id": schedule.id,
                "schedule_name": schedule.name,
                "chain_key": schedule.chain_key,
                "chain_display_name": chain.get("display_name", schedule.chain_key),
                "agent_id": schedule.agent_id,
                "simulated": agent.kind != "real",
                "target_hint": schedule.target_hint,
                "fired_at": job.created_at,
                "steps": [],
            }
            paths_by_scan_job[job.scan_job_id] = entry
        technique = get_technique(job.technique_key) or {}
        proof = _proof_from_result(getattr(job, "result", None))
        entry["steps"].append({
            "technique_key": job.technique_key,
            "display_name": technique.get("display_name", job.technique_key),
            "mitre_refs": technique.get("mitre_refs", []),
            "status": job.status,
            "risk_tier": job.risk_tier,
            "finding_id": job.finding_id,
            "proof_valid": bool(proof.get("valid")),
            "proof_status": proof.get("status") or "missing",
        })

    paths = sorted(paths_by_scan_job.values(), key=lambda p: p["fired_at"], reverse=True)
    return paths[:limit]


def _technical_pentest_report_payload(
    *,
    findings: list[dict[str, Any]],
    priorities: list[dict[str, Any]],
    chain_paths: list[dict[str, Any]],
    port_scan: dict[str, Any],
    score: dict[str, Any],
) -> dict[str, Any]:
    proofed_findings = [f for f in findings if not f.get("simulated") and f.get("proof_valid")]
    unproven_findings = [f for f in findings if not f.get("simulated") and not f.get("proof_valid")]
    return {
        "mode": "internal_pentest_from_agent",
        "evidence_model": "proof_based_bas_finding",
        "scope": {
            "validated_findings": len(proofed_findings),
            "unproven_findings": len(unproven_findings),
            "proof_validated_jobs": score.get("proof_validated", score.get("worked", 0)),
            "unproven_jobs": score.get("unproven", 0),
            "blocked_jobs": score.get("blocked", 0),
        },
        "methodology": [
            "asset_discovery_internal",
            "service_fingerprint",
            "vuln_validation",
            "safe_credential_checks",
            "ad_enumeration",
            "safe_lateral_movement_simulation",
            "controlled_exploit_validation",
            "cloud_identity_validation",
            "saas_exposure_validation",
            "conditional_access_telemetry_validation",
            "replayable_retest",
        ],
        "validated_findings": proofed_findings,
        "unproven_findings": unproven_findings,
        "technical_priorities": priorities,
        "attack_paths": chain_paths,
        "service_fingerprint": port_scan,
    }


def executive_report(
    db: Session, *, group_ids: list[int] | None = None, schedule_id: int | None = None
) -> dict[str, Any]:
    """Assembles the "Relatório BAS" document payload from the panels above --
    no new computation beyond a short narrative summary string built from
    those same real numbers. Every figure here is either a coverage/activity
    metric or the worked-vs-blocked risk_score ratio -- same honesty rule as
    the rest of this module (see module docstring). schedule_id, when given,
    scopes every panel to that one named test/agendamento instead of the
    platform-wide aggregate -- the operator picking "just this one report"
    from the report page instead of "all reports"."""
    selected_schedule_name = None
    if schedule_id is not None:
        schedule_row = db.query(BasSchedule).filter(BasSchedule.id == schedule_id).first()
        selected_schedule_name = schedule_row.name if schedule_row else None

    coverage = framework_coverage(db, group_ids=group_ids, schedule_id=schedule_id)
    exposure = exposure_summary(db, group_ids=group_ids, schedule_id=schedule_id)
    score = risk_score(db, group_ids=group_ids, schedule_id=schedule_id)
    jewels = crown_jewels_view(db, group_ids=group_ids, schedule_id=schedule_id)
    heatmap = attack_heatmap(db, group_ids=group_ids, schedule_id=schedule_id)
    findings = bas_findings_view(db, group_ids=group_ids, schedule_id=schedule_id, limit=50)
    chain_paths = chain_attack_path(db, group_ids=group_ids, schedule_id=schedule_id)
    priorities = action_priorities(db, group_ids=group_ids, schedule_id=schedule_id)
    port_scan = port_scan_observability(db, group_ids=group_ids, schedule_id=schedule_id)

    total_techniques = len(list_techniques())
    tested_techniques = sum(1 for row in heatmap if row["times_tested"] > 0)
    jewels_touched = sum(1 for j in jewels if j["jobs_run"] > 0)

    real_findings = [f for f in findings if not f["simulated"] and f.get("proof_valid")]
    severity_order = ["critical", "high", "medium", "low", "info"]
    severity_counts = {sev: sum(1 for f in real_findings if f["severity"] == sev) for sev in severity_order}
    vulnerable_findings = [f for f in real_findings if f["severity"] != "info"]
    blocking_priorities = [p for p in priorities if p["priority"] in {"P0", "P1"}]

    if score["resolved_total"] == 0:
        narrative = (
            f"Nenhum job BAS foi resolvido ainda neste escopo. "
            f"{tested_techniques}/{total_techniques} técnicas catalogadas já foram disparadas ao menos uma vez."
        )
    else:
        if vulnerable_findings:
            risk_clause = (
                f"{len(vulnerable_findings)} achado(s) real(is) indicam risco concreto "
                f"({severity_counts['critical']} crítico(s), {severity_counts['high']} alto(s), {severity_counts['medium']} médio(s), "
                f"{severity_counts['low']} baixo(s))."
            )
        elif blocking_priorities:
            risk_clause = (
                f"{len(blocking_priorities)} prioridade(s) P0/P1 foram extraídas dos resultados reais e exigem correção."
            )
        else:
            risk_clause = "Nenhum achado com prova BAS indicou risco concreto até agora; resultados sem evidência suficiente ficam como hipótese."
        narrative = (
            f"Neste escopo, {tested_techniques}/{total_techniques} técnicas catalogadas foram disparadas, "
            f"cobrindo {len(exposure['categories_tested'])} categoria(s) em {exposure['distinct_targets_tested']} alvo(s) interno(s). "
            f"Dos {score['resolved_total']} disparo(s) com resultado resolvido, {score['worked']} tiveram prova objetiva "
            f"({score['score']}/100), {score['unproven']} ficaram sem evidência suficiente e {score['blocked']} falharam/foram bloqueados. "
            f"{jewels_touched}/{len(jewels)} alvo(s) de alto valor já foram testados ao menos uma vez. "
            f"{risk_clause}"
        )

    return {
        "narrative": narrative,
        "schedule_id": schedule_id,
        "schedule_name": selected_schedule_name,
        "total_techniques": total_techniques,
        "tested_techniques": tested_techniques,
        "risk_score": score,
        "severity_counts": severity_counts,
        "framework_coverage": coverage,
        "exposure": exposure,
        "crown_jewels": jewels,
        "attack_heatmap": heatmap,
        "findings": findings,
        "action_priorities": priorities,
        "chain_attack_paths": chain_paths,
        "technical_pentest_report": _technical_pentest_report_payload(
            findings=findings, priorities=priorities, chain_paths=chain_paths, port_scan=port_scan, score=score,
        ),
    }
