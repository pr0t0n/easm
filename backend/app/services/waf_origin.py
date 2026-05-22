"""WAF Origin Discovery.

When a WAF/CDN fronts a target, every recon tool hits the edge — open ports,
banners and even "vulnerabilities" belong to the WAF, not the application. A
real pentest must locate the *origin* server (the box the WAF proxies to) and
re-validate findings directly against it.

This module finds origin candidates WITHOUT paid APIs, using data the scan
already collected:

  1. WAF/CDN netblock classification — IPs inside a known edge range are the
     edge; IPs outside are candidate origins.
  2. Subdomain IP divergence — operators routinely forget to put every
     subdomain behind the WAF. A subdomain resolving to a non-edge IP is a
     strong origin lead (mail., vpn., dev., cpanel., direct., origin., ...).
  3. DNS record mining — SPF `ip4:` entries and resolved MX hosts expose
     infrastructure IPs often co-located with (or equal to) the origin.

The runner turns candidates into findings with a verification recipe
(Host-header request) so an analyst can confirm and pivot.
"""
from __future__ import annotations

import ipaddress
import re
from typing import Any


# Known WAF/CDN edge netblocks. An IP inside one of these is the proxy edge,
# never the origin. Lists are intentionally the major published ranges.
_WAF_NETBLOCKS: dict[str, list[str]] = {
    "incapsula": [
        "45.60.0.0/16", "149.126.72.0/21", "103.28.248.0/22",
        "198.143.32.0/19", "192.230.64.0/18", "107.154.0.0/16",
    ],
    "cloudflare": [
        "104.16.0.0/13", "172.64.0.0/13", "131.0.72.0/22", "108.162.192.0/18",
        "141.101.64.0/18", "162.158.0.0/15", "173.245.48.0/20",
        "188.114.96.0/20", "190.93.240.0/20", "197.234.240.0/22", "198.41.128.0/17",
    ],
    "akamai": ["23.0.0.0/12", "104.64.0.0/10", "184.24.0.0/13", "2.16.0.0/13", "96.16.0.0/15"],
    "fastly": ["151.101.0.0/16", "199.232.0.0/16", "23.235.32.0/20"],
    "sucuri": ["192.88.134.0/23", "185.93.228.0/22", "66.248.200.0/22"],
    "aws-cloudfront": [
        "13.32.0.0/15", "13.224.0.0/14", "52.84.0.0/15",
        "54.182.0.0/16", "54.192.0.0/16", "99.84.0.0/16",
    ],
}

# Subdomain prefixes that very often point straight at origin infrastructure.
_ORIGIN_HINT_PREFIXES = (
    "origin", "direct", "www-origin", "origin-www", "real", "backend", "back",
    "mail", "smtp", "webmail", "mx", "ftp", "sftp", "cpanel", "whm", "ssh",
    "vpn", "remote", "dev", "staging", "stage", "test", "uat", "old", "legacy",
    "admin", "portal", "intranet", "internal", "api-direct",
)

_IP4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def _ip_in_netblocks(ip: str) -> tuple[bool, str]:
    """Return (is_edge, vendor) — whether the IP sits in a known WAF/CDN range."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False, ""
    for vendor, cidrs in _WAF_NETBLOCKS.items():
        for cidr in cidrs:
            try:
                if addr in ipaddress.ip_network(cidr):
                    return True, vendor
            except ValueError:
                continue
    return False, ""


def classify_ip(ip: str) -> dict[str, str]:
    """Classify a single IP as WAF edge or candidate origin."""
    is_edge, vendor = _ip_in_netblocks(ip)
    return {
        "ip": ip,
        "classification": "waf-edge" if is_edge else "candidate-origin",
        "waf_vendor": vendor,
    }


def _hint_score(host: str, root: str) -> int:
    """Higher = more likely to be origin infrastructure based on the hostname."""
    label = host.lower()
    if root and label.endswith("." + root):
        label = label[: -(len(root) + 1)]
    first = label.split(".")[0]
    if first in _ORIGIN_HINT_PREFIXES:
        return 3
    if any(first.startswith(p) for p in _ORIGIN_HINT_PREFIXES):
        return 2
    return 1


def mine_dns_record_ips(mcp_results: list[dict[str, Any]]) -> list[str]:
    """Extract IPv4s from SPF (TXT) and MX-related tool output already collected."""
    ips: set[str] = set()
    for mcp in mcp_results or []:
        if not isinstance(mcp, dict):
            continue
        tool = str(mcp.get("tool_name") or "").lower()
        if tool not in {"dnsrecon-brt", "dnsrecon-zt", "dnsenum", "dnsx", "theharvester", "amass", "amass-intel"}:
            continue
        stdout = str(mcp.get("stdout") or "")
        for line in stdout.splitlines():
            low = line.lower()
            # SPF ip4: entries, or any A/MX record line
            if "ip4:" in low:
                for m in re.findall(r"ip4:(\d{1,3}(?:\.\d{1,3}){3})", low):
                    ips.add(m)
            elif any(k in low for k in (" a ", "mx", "txt", "-->")):
                for m in _IP4_RE.findall(line):
                    ips.add(m)
    # drop obvious noise (private / loopback)
    clean: list[str] = []
    for ip in ips:
        try:
            a = ipaddress.ip_address(ip)
            if a.is_private or a.is_loopback or a.is_reserved or a.is_multicast:
                continue
            clean.append(ip)
        except ValueError:
            continue
    return sorted(clean)


def discover_origin_candidates(
    root: str,
    host_ip_map: dict[str, str],
    mcp_results: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Find candidate origin IPs behind the WAF.

    Returns a structured report:
      waf_edge_ips:        IPs confirmed on a WAF/CDN netblock
      candidate_origins:   [{ip, source, hosts, hint_score, verify}]
      apex_behind_waf:     bool
      summary:             one-line human summary
    """
    mcp_results = mcp_results or []
    edge_ips: dict[str, str] = {}        # ip -> vendor
    candidate_ips: dict[str, dict[str, Any]] = {}  # ip -> info

    # 1. Subdomain IP divergence
    for host, ip in (host_ip_map or {}).items():
        if not ip:
            continue
        is_edge, vendor = _ip_in_netblocks(ip)
        if is_edge:
            edge_ips[ip] = vendor
        else:
            entry = candidate_ips.setdefault(ip, {
                "ip": ip, "source": "subdomain_resolution", "hosts": [],
                "hint_score": 0,
            })
            if host not in entry["hosts"]:
                entry["hosts"].append(host)
            entry["hint_score"] = max(entry["hint_score"], _hint_score(host, root))

    # 2. DNS-record-mined IPs (SPF/MX)
    for ip in mine_dns_record_ips(mcp_results):
        is_edge, vendor = _ip_in_netblocks(ip)
        if is_edge:
            edge_ips.setdefault(ip, vendor)
        elif ip not in candidate_ips:
            candidate_ips[ip] = {
                "ip": ip, "source": "dns_record_mining", "hosts": [],
                "hint_score": 1,
            }

    apex_ip = (host_ip_map or {}).get(root)
    apex_behind_waf = bool(apex_ip and _ip_in_netblocks(apex_ip)[0])

    # Rank candidates: hint score, then fewer hosts (more specific)
    ranked = sorted(
        candidate_ips.values(),
        key=lambda c: (-c["hint_score"], len(c["hosts"])),
    )
    for c in ranked:
        c["verify"] = (
            f"curl -sk -H 'Host: {root}' --resolve {root}:443:{c['ip']} https://{root}/ "
            f"# compare body to the WAF response — a match confirms {c['ip']} as origin"
        )
        c["confidence"] = (
            "high" if c["hint_score"] >= 3 else
            "medium" if c["hint_score"] == 2 else "low"
        )

    summary = (
        f"WAF edge confirmed ({', '.join(sorted(set(edge_ips.values())) or ['unknown'])}); "
        f"{len(ranked)} candidate origin IP(s) outside WAF netblocks"
        if apex_behind_waf else
        f"Apex not behind a known WAF netblock; {len(ranked)} non-edge IP(s) observed"
    )

    return {
        "apex": root,
        "apex_ip": apex_ip,
        "apex_behind_waf": apex_behind_waf,
        "waf_edge_ips": [{"ip": ip, "vendor": v} for ip, v in sorted(edge_ips.items())],
        "candidate_origins": ranked,
        "summary": summary,
    }
