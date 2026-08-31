from __future__ import annotations

from typing import Any


WEB_PORTS = {80, 443, 8000, 8001, 8008, 8080, 8081, 8443, 8888, 3000, 5000, 5601, 9000, 9443}
SMB_PORTS = {139, 445}
LDAP_PORTS = {389, 636}
KERBEROS_PORTS = {88, 464}
GLOBAL_CATALOG_PORTS = {3268, 3269}
DNS_PORTS = {53}
VMWARE_PORTS = {5480, 902, 9443}


def capabilities_for_ports(ports: set[int]) -> set[str]:
    caps: set[str] = set()
    if ports & WEB_PORTS:
        caps.add("web")
    if ports & SMB_PORTS:
        caps.add("smb")
    if ports & DNS_PORTS:
        caps.add("dns")
    if ports & LDAP_PORTS:
        caps.add("ldap")
    if ports & KERBEROS_PORTS:
        caps.add("kerberos")
    if ports & GLOBAL_CATALOG_PORTS:
        caps.add("global_catalog")
    if (ports & LDAP_PORTS and ports & KERBEROS_PORTS) or ports & GLOBAL_CATALOG_PORTS:
        caps.add("ad_dc")
    if ports & VMWARE_PORTS:
        caps.add("vmware")
    return caps


def capabilities_by_host(open_ports_by_host: dict[str, set[int]]) -> dict[str, set[str]]:
    return {host: capabilities_for_ports(set(ports or set())) for host, ports in open_ports_by_host.items()}


def required_capabilities(technique: dict[str, Any]) -> set[str]:
    values = technique.get("required_capabilities") or []
    return {str(value).strip() for value in values if str(value).strip()}


def filter_targets_for_capability(
    targets: list[str],
    technique: dict[str, Any],
    open_ports_by_host: dict[str, set[int]],
    known_hosts: set[str],
) -> tuple[list[str], list[dict[str, str]]]:
    required = required_capabilities(technique)
    required_ports = set(int(port) for port in (technique.get("required_ports") or []) if str(port).isdigit())
    if not required and not required_ports:
        return targets, []
    caps_by_host = capabilities_by_host(open_ports_by_host)
    allowed = []
    skipped = []
    for target in targets:
        if target not in known_hosts:
            skipped.append({
                "technique_key": technique["technique_key"],
                "target": target,
                "reason": "service_fingerprint_missing_per_port_scan",
            })
            continue
        host_caps = caps_by_host.get(target, set())
        host_ports = open_ports_by_host.get(target, set())
        if required and not required.issubset(host_caps):
            skipped.append({
                "technique_key": technique["technique_key"],
                "target": target,
                "reason": f"capability_not_observed_per_port_scan:{sorted(required)}",
            })
            continue
        if required_ports and not (host_ports & required_ports):
            skipped.append({
                "technique_key": technique["technique_key"],
                "target": target,
                "reason": f"port_not_open_per_port_scan:{sorted(required_ports)}",
            })
            continue
        allowed.append(target)
    return allowed, skipped
