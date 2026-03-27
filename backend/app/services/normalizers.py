class NucleiNormalizer:
    @staticmethod
    def parse_json(content: str) -> List[Dict[str, Any]]:
        vulnerabilities = []
        for line in content.split("\n"):
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            vuln = {
                "tool": "nuclei",
                "title": str(item.get("name") or item.get("template-id") or "Nuclei finding"),
                "host": str(item.get("host") or "").strip(),
                "matched_at": str(item.get("matched-at") or "").strip(),
                "severity": str(item.get("severity") or "medium").lower(),
                "description": str(item.get("description") or ""),
                "cve_id": str(item.get("cve-id") or "").strip() or None,
                "cvss_score": float(item.get("cvss-score") or 0),
                "fair_pillar": "patching_hygiene",
                "timestamp": str(item.get("timestamp") or datetime.utcnow().isoformat()),
            }
            if item.get("payload"):
                vuln["payload"] = str(item.get("payload"))
            vulnerabilities.append(vuln)
        return vulnerabilities

class NiktoNormalizer:
    @staticmethod
    def parse_json(content: str) -> List[Dict[str, Any]]:
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return []
        vulnerabilities = []
        scan = data.get("scan", {})
        site = str(scan.get("site") or "").strip()
        niktoscan = scan.get("niktoscan", {})
        items = niktoscan.get("item", [])
        if not isinstance(items, list):
            items = [items]
        for item in items:
            severity_map = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low", "INFO": "info"}
            severity = severity_map.get(str(item.get("severity", "").upper()), "medium")
            vuln = {
                "tool": "nikto",
                "title": str(item.get("description") or "Nikto finding"),
                "host": site,
                "uri": str(item.get("uri") or ""),
                "severity": severity,
                "http_code": str(item.get("http_code") or ""),
                "osvdb": str(item.get("osvdb") or ""),
                "fair_pillar": "patching_hygiene",
                "timestamp": datetime.utcnow().isoformat(),
            }
            if item.get("payload"):
                vuln["payload"] = str(item.get("payload"))
            vulnerabilities.append(vuln)
        return vulnerabilities

class SQLMapNormalizer:
    @staticmethod
    def parse_json(content: str) -> List[Dict[str, Any]]:
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return []
        vulnerabilities = []
        scan = data.get("scan", {})
        target = scan.get("target", {})
        url = str(target.get("url") or "").strip()
        for result in scan.get("results", []):
            vuln = {
                "tool": "sqlmap",
                "title": f"SQL Injection - {result.get('technique', 'SQL Injection')}",
                "host": url,
                "parameter": str(result.get("parameter") or ""),
                "place": str(result.get("place") or ""),
                "dbms": str(result.get("dbms") or ""),
                "confidence": int(result.get("confidence", 0)),
                "severity": "critical" if int(result.get("confidence", 0)) >= 100 else "high",
                "fair_pillar": "patching_hygiene",
                "timestamp": datetime.utcnow().isoformat(),
            }
            if result.get("payload"):
                vuln["payload"] = str(result.get("payload"))
            vulnerabilities.append(vuln)
        return vulnerabilities

class NessusNormalizer:
    @staticmethod
    def parse_xml_string(content: str) -> List[Dict[str, Any]]:
        vulnerabilities = []
        report_item_pattern = r"<ReportItem.*?Port=\"(\d+)\".*?pluginID=\"(\d+)\".*?severity=\"(\d+)\".*?>(.*?)</ReportItem>"
        for match in re.finditer(report_item_pattern, content, re.DOTALL):
            port, plugin_id, severity, content_inner = match.groups()
            plugin_name_match = re.search(r"<plugin_name>(.*?)</plugin_name>", content_inner)
            plugin_name = plugin_name_match.group(1) if plugin_name_match else f"Plugin {plugin_id}"
            desc_match = re.search(r"<description>(.*?)</description>", content_inner)
            description = desc_match.group(1) if desc_match else ""
            severity_map = {"4": "critical", "3": "high", "2": "medium", "1": "low", "0": "info"}
            severity_text = severity_map.get(severity, "medium")
            vuln = {
                "tool": "nessus",
                "title": plugin_name,
                "port": int(port),
                "plugin_id": plugin_id,
                "description": description,
                "severity": severity_text,
                "fair_pillar": "patching_hygiene",
                "timestamp": datetime.utcnow().isoformat(),
            }
            vulnerabilities.append(vuln)
        return vulnerabilities

class DalfoxNormalizer:
    @staticmethod
    def parse_json(content: str) -> List[Dict[str, Any]]:
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return []
        findings = []
        for item in data.get("data", []):
            vuln = {
                "tool": "dalfox",
                "title": str(item.get("type") or "Dalfox finding"),
                "host": str(item.get("url") or "").strip(),
                "severity": str(item.get("severity") or "medium").lower(),
                "description": str(item.get("description") or ""),
                "fair_pillar": "patching_hygiene",
                "timestamp": datetime.utcnow().isoformat(),
            }
            if item.get("payload"):
                vuln["payload"] = str(item.get("payload"))
            findings.append(vuln)
        return findings
"""
Normalizers for converting tool-specific outputs into unified EASM evidence format.

Tools supported:
- Subfinder (JSON) -> Asset discoveries
- Nuclei (JSON) -> Vulnerabilities
- Shodan (JSON/CLI) -> Asset fingerprints
- Nessus (XML) -> Vulnerabilities
- Nmap/Naabu (JSON) -> Port discoveries
"""

import json
import re
from datetime import datetime
from typing import Any, Dict, List, Optional


# ──────────────────────────────────────────────────────────────────────────────
# ASSET DISCOVERY NORMALIZERS (Subfinder, Shodan, DNS tools)
# ──────────────────────────────────────────────────────────────────────────────


class SubfinderNormalizer:
    """Normaliza output Subfinder JSON -> Asset Discovery Event"""

    @staticmethod
    def parse_json(content: str) -> List[Dict[str, Any]]:
        """
        Subfinder saída: {"test.example.com":"1.2.3.4"}
        Retorna lista de descobertas de ativos
        """
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return []

        discoveries = []
        for domain, ip in (data.items() if isinstance(data, dict) else []):
            discoveries.append({
                "asset_type": "domain",
                "domain": str(domain).strip(),
                "ip": str(ip).strip() if ip else None,
                "tool": "subfinder",
                "fair_pillar": "perimeter_resilience",
                "timestamp": datetime.utcnow().isoformat(),
            })
        return discoveries


class NmapNormalizer:
    """Normaliza Nmap/Naabu JSON -> Port Discovery"""

    @staticmethod
    def parse_json(content: str) -> List[Dict[str, Any]]:
        """
        Namp/Naabu JSON format típico:
        [{"host":"1.2.3.4","port":80,"protocol":"tcp","service":"http"}]
        """
        try:
            data = json.loads(content)
            if not isinstance(data, list):
                data = [data]
        except json.JSONDecodeError:
            return []

        discoveries = []
        for item in data:
            discoveries.append({
                "asset_type": "port",
                "host": str(item.get("host") or ""),
                "port": int(item.get("port") or 0),
                "protocol": str(item.get("protocol") or "tcp").lower(),
                "service": str(item.get("service") or "unknown"),
                "tool": "nmap",
                "fair_pillar": "perimeter_resilience",
                "timestamp": datetime.utcnow().isoformat(),
            })
        return discoveries


class ShodanNormalizer:
    """Normaliza Shodan JSON -> Asset Fingerprint + Risk"""

    @staticmethod
    def parse_json(content: str) -> List[Dict[str, Any]]:
        """
        Shodan JSON típico per IP:
        {
          "ip_str": "1.2.3.4",
          "ports": [80, 443, 22],
          "data": [{"_shodan": {"module": "http"}, "title": "...", "html": "..."}],
          "org": "Company Inc",
          "cves": ["CVE-2021-1234"],
          ...
        }
        """
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return []

        if not isinstance(data, dict):
            return []

        discoveries = []
        ip = str(data.get("ip_str") or "").strip()
        if not ip:
            return discoveries

        # Ports
        for port in data.get("ports") or []:
            discoveries.append({
                "asset_type": "port",
                "host": ip,
                "port": int(port),
                "tool": "shodan",
                "fair_pillar": "perimeter_resilience",
                "timestamp": datetime.utcnow().isoformat(),
            })

        # CVEs found
        for cve in data.get("cves") or []:
            discoveries.append({
                "asset_type": "vulnerability",
                "host": ip,
                "cve_id": str(cve).strip(),
                "tool": "shodan",
                "fair_pillar": "patching_hygiene",
                "timestamp": datetime.utcnow().isoformat(),
            })

        # Organization (criticality hint)
        org = str(data.get("org") or "").strip()
        if org:
            discoveries.append({
                "asset_type": "organization",
                "host": ip,
                "organization": org,
                "tool": "shodan",
                "timestamp": datetime.utcnow().isoformat(),
            })

        return discoveries


class H8mailNormalizer:
    """Normaliza h8mail (email breach scanner) -> OSINT Exposure"""

    @staticmethod
    def parse_json(content: str) -> List[Dict[str, Any]]:
        """
        h8mail JSON típico:
        {
          "targets": ["email@example.com"],
          "breaches": [
            {"name": "breach_name", "exposed_keys": ["password", "email", ...]},
            ...
          ]
        }
        """
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return []

        discoveries = []
        for breach in data.get("breaches") or []:
            exposed_keys = breach.get("exposed_keys", [])
            discoveries.append({
                "asset_type": "breach",
                "breach_name": str(breach.get("name") or ""),
                "exposed_data": exposed_keys,
                "tool": "h8mail",
                "fair_pillar": "osint_exposure",
                "severity": "high" if "password" in exposed_keys else "medium",
                "timestamp": datetime.utcnow().isoformat(),
            })
        return discoveries


# ──────────────────────────────────────────────────────────────────────────────
# VULNERABILITY NORMALIZERS (Nuclei, Nikto, SQLMap, Nessus)
# ──────────────────────────────────────────────────────────────────────────────


class NucleiNormalizer:
    """Normaliza Nuclei JSON -> Vulnerability Evidence"""

    @staticmethod
    def parse_json(content: str) -> List[Dict[str, Any]]:
        """
        Nuclei JSON lines format (um JSON objeto por linha):
        {
          "template-id": "...",
          "template-url": "...",
          "name": "...",
          "type": "http",
          "host": "https://example.com",
          "matched-at": "https://example.com/path",
          "severity": "high",
          "description": "...",
          "cve-id": "CVE-2021-1234",
          "cvss-score": 7.5,
          "timestamp": "2026-03-25T10:00:00Z"
        }
        """
        vulnerabilities = []
        
        for line in content.split("\n"):
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue

            vuln = {
                "tool": "nuclei",
                "title": str(item.get("name") or item.get("template-id") or "Nuclei finding"),
                "host": str(item.get("host") or "").strip(),
                "matched_at": str(item.get("matched-at") or "").strip(),
                "severity": str(item.get("severity") or "medium").lower(),
                "description": str(item.get("description") or ""),
                "cve_id": str(item.get("cve-id") or "").strip() or None,
                "cvss_score": float(item.get("cvss-score") or 0),
                "fair_pillar": "patching_hygiene",
                "timestamp": str(item.get("timestamp") or datetime.utcnow().isoformat()),
            }
            vulnerabilities.append(vuln)

        return vulnerabilities


class NiktoNormalizer:
    """Normaliza Nikto JSON -> Vulnerability Evidence"""

    @staticmethod
    def parse_json(content: str) -> List[Dict[str, Any]]:
        """
        Nikto JSON:
        {
          "scan": {
            "start time": "...",
            "site": "http://example.com",
            "niktoscan": {
              "item": [
                {
                @staticmethod
                def parse_json(content: str) -> List[Dict[str, Any]]:
                "method": "GET",
                "osvdb": "123",
                "http_code": "200",
                "severity": "HIGH"
                }
              ]
            }
          }
        }
        """
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return []

        vulnerabilities = []
        scan = data.get("scan", {})
        site = str(scan.get("site") or "").strip()
        niktoscan = scan.get("niktoscan", {})
        items = niktoscan.get("item", [])

        if not isinstance(items, list):
            items = [items]

        for item in items:
            severity_map = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low", "INFO": "info"}
            severity = severity_map.get(str(item.get("severity", "")).upper(), "medium")

            vuln = {
                "tool": "nikto",
                "title": str(item.get("description") or "Nikto finding"),
                "host": site,
                "uri": str(item.get("uri") or ""),
                "severity": severity,
                "http_code": str(item.get("http_code") or ""),
                "osvdb": str(item.get("osvdb") or ""),
                "fair_pillar": "patching_hygiene",
                "timestamp": datetime.utcnow().isoformat(),
            }
            if item.get("payload"):
                vuln["payload"] = str(item.get("payload"))
            vulnerabilities.append(vuln)



class NessusNormalizer:
    """Normaliza Nessus XML -> Vulnerability Evidence (simplified)"""

    @staticmethod
    def parse_xml_string(content: str) -> List[Dict[str, Any]]:
        """
        Nessus XML is complex. Este é um parser simplificado que busca
        por ReportItem com severity.
        Recomendado: usar 'python-nessus' package em produção.
        """
        vulnerabilities = []
        
        # Padrão simples para ReportItem
        report_item_pattern = r"<ReportItem.*?Port=\"(\d+)\".*?pluginID=\"(\d+)\".*?severity=\"(\d+)\".*?>(.*?)</ReportItem>"
        
        for match in re.finditer(report_item_pattern, content, re.DOTALL):
            port, plugin_id, severity, content_inner = match.groups()
            plugin_name_match = re.search(r"<plugin_name>(.*?)</plugin_name>", content_inner)
            plugin_name = plugin_name_match.group(1) if plugin_name_match else f"Plugin {plugin_id}"
            desc_match = re.search(r"<description>(.*?)</description>", content_inner)
            description = desc_match.group(1) if desc_match else ""
            severity_map = {"4": "critical", "3": "high", "2": "medium", "1": "low", "0": "info"}
            severity_text = severity_map.get(severity, "medium")
            vuln = {
                "tool": "nessus",
                "title": plugin_name,
                "port": int(port),
                "plugin_id": plugin_id,
                "description": description,
                "severity": severity_text,
                "fair_pillar": "patching_hygiene",
                "timestamp": datetime.utcnow().isoformat(),
            }
            vulnerabilities.append(vuln)
        return vulnerabilities


# ──────────────────────────────────────────────────────────────────────────────
# UNIFIED NORMALIZER (Factory pattern)
# ──────────────────────────────────────────────────────────────────────────────


class EvidenceNormalizer:
    """Unified normalizer - converts any tool output to EASM Evidence format"""

    NORMALIZERS = {
        "subfinder": SubfinderNormalizer,
        "nmap": NmapNormalizer,
        "naabu": NmapNormalizer,
        "shodan": ShodanNormalizer,
        "h8mail": H8mailNormalizer,
        "nuclei": NucleiNormalizer,
        "nikto": NiktoNormalizer,
        "sqlmap": SQLMapNormalizer,
        "nessus": NessusNormalizer,
        "dalfox": DalfoxNormalizer,
    }


class DalfoxNormalizer:
    @staticmethod
    def parse_json(content: str) -> list[dict[str, Any]]:
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return []
        findings = []
        for item in data.get("data", []):
            vuln = {
                "tool": "dalfox",
                "title": str(item.get("type") or "Dalfox finding"),
                "host": str(item.get("url") or "").strip(),
                "severity": str(item.get("severity") or "medium").lower(),
                "description": str(item.get("description") or ""),
                "fair_pillar": "patching_hygiene",
                "timestamp": datetime.utcnow().isoformat(),
            }
            # Extrai payload se disponível
            if item.get("payload"):
                vuln["payload"] = str(item.get("payload"))
            findings.append(vuln)
        return findings

EvidenceNormalizer.NORMALIZERS["dalfox"] = DalfoxNormalizer

    @staticmethod
    def deduplicate_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Remove duplicatas por signature"""
        seen = set()
        unique = []
        for finding in findings:
            # Signature: host + title + severity
            signature = (
                finding.get("host") or finding.get("target") or "",
                finding.get("title") or finding.get("name") or "",
                finding.get("severity") or "unknown",
            )
            sig_str = "|".join(str(s) for s in signature).lower()
            if sig_str not in seen:
                seen.add(sig_str)
                unique.append(finding)
        return unique
