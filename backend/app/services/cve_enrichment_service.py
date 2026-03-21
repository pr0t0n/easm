from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx


_CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class CVEEnrichmentService:
    def __init__(self):
        self._cve_cache: dict[str, tuple[datetime, dict[str, Any]]] = {}
        self._kev_cache_until: datetime = datetime.min.replace(tzinfo=timezone.utc)
        self._kev_index: dict[str, dict[str, Any]] = {}

    def extract_cve(self, payload: dict[str, Any], title: str | None = None) -> str | None:
        direct = str(payload.get("cve") or "").strip().upper()
        if direct and _CVE_PATTERN.search(direct):
            return _CVE_PATTERN.search(direct).group(0).upper()

        candidates = [
            title or "",
            str(payload.get("title") or ""),
            str(payload.get("name") or ""),
            str(payload.get("evidence") or ""),
            str(payload.get("description") or ""),
            str(payload.get("details") or ""),
        ]
        for text in candidates:
            match = _CVE_PATTERN.search(text)
            if match:
                return match.group(0).upper()
        return None

    def enrich(self, cve_id: str | None) -> dict[str, Any]:
        if not cve_id:
            return {}
        normalized = cve_id.strip().upper()
        if not normalized:
            return {}

        now = datetime.now(timezone.utc)
        cached = self._cve_cache.get(normalized)
        if cached and cached[0] > now:
            return dict(cached[1])

        nvd = self._fetch_nvd(normalized)
        kev = self._fetch_kev(normalized)

        payload = {
            "cve": normalized,
            **nvd,
            **kev,
        }
        self._cve_cache[normalized] = (now + timedelta(hours=12), payload)
        return dict(payload)

    def _fetch_nvd(self, cve_id: str) -> dict[str, Any]:
        try:
            with httpx.Client(timeout=4.5) as client:
                response = client.get(_NVD_URL, params={"cveId": cve_id})
                if response.status_code != 200:
                    return {}
                data = response.json()
        except Exception:
            return {}

        vulns = data.get("vulnerabilities") or []
        if not vulns:
            return {}
        cve = (vulns[0] or {}).get("cve") or {}

        result: dict[str, Any] = {
            "cve_published_at": cve.get("published"),
            "cve_last_modified_at": cve.get("lastModified"),
        }

        metrics = cve.get("metrics") or {}
        cvss_v31 = metrics.get("cvssMetricV31") or []
        cvss_v30 = metrics.get("cvssMetricV30") or []
        cvss_v2 = metrics.get("cvssMetricV2") or []
        metric = None
        if cvss_v31:
            metric = (cvss_v31[0] or {}).get("cvssData")
        elif cvss_v30:
            metric = (cvss_v30[0] or {}).get("cvssData")
        elif cvss_v2:
            metric = (cvss_v2[0] or {}).get("cvssData")

        if metric:
            result.update(
                {
                    "cvss_base_score": metric.get("baseScore"),
                    "cvss_vector": metric.get("vectorString"),
                    "cvss_severity": metric.get("baseSeverity"),
                    "cvss_created_at": cve.get("published"),
                }
            )
        return {k: v for k, v in result.items() if v is not None}

    def _fetch_kev(self, cve_id: str) -> dict[str, Any]:
        now = datetime.now(timezone.utc)
        if now >= self._kev_cache_until:
            self._refresh_kev_index()

        entry = self._kev_index.get(cve_id)
        if not entry:
            return {}

        kev_date = entry.get("dateAdded")
        return {
            "known_exploited": True,
            "kev_added_at": kev_date,
            "exploit_published_at": kev_date,
            "kev_ransomware_use": entry.get("knownRansomwareCampaignUse"),
        }

    def _refresh_kev_index(self):
        now = datetime.now(timezone.utc)
        try:
            with httpx.Client(timeout=5.0) as client:
                response = client.get(_KEV_URL)
                if response.status_code != 200:
                    self._kev_cache_until = now + timedelta(hours=2)
                    return
                data = response.json()
        except Exception:
            self._kev_cache_until = now + timedelta(hours=2)
            return

        index: dict[str, dict[str, Any]] = {}
        for item in data.get("vulnerabilities", []) or []:
            cve_id = str(item.get("cveID") or "").strip().upper()
            if cve_id:
                index[cve_id] = item

        self._kev_index = index
        self._kev_cache_until = now + timedelta(hours=24)


enrichment_service = CVEEnrichmentService()
