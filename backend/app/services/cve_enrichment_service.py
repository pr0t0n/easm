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

    # ─────────────────────────────────────────────────────────────────────────
    # DB-level enrichment: enrich all CVE findings in a scan with NVD data
    # ─────────────────────────────────────────────────────────────────────────

    def enrich_scan_findings(self, db: Any, scan_id: int) -> dict[str, Any]:
        """Enrich all CVE-bearing findings in scan_id with NVD CVSS + KEV data.

        Called automatically at scan completion from dispatch_scan_work_items().
        Also callable manually (e.g., from admin API).

        Updates:
          - finding.cvss from NVD if currently None
          - finding.details["cvss_v3"], finding.details["cvss_v31"]
          - finding.details["kev"] = True if in CISA KEV catalogue
          - finding.details["kev_ransomware"] = True if ransomware campaign used it
          - finding.severity upgraded to "critical" if CVSS >= 9.0 and was "high"

        Returns: {"enriched": N, "skipped_no_cve": N, "skipped_cached": N, "errors": N}
        """
        try:
            from app.models.models import Finding as _Finding
        except ImportError:
            return {"error": "models not available"}

        enriched = skipped_no_cve = skipped_cached = errors = 0

        findings_with_cve = (
            db.query(_Finding)
            .filter(
                _Finding.scan_job_id == scan_id,
                _Finding.cve.isnot(None),
                _Finding.cve != "",
            )
            .all()
        )

        for f in findings_with_cve:
            cve_id = str(f.cve or "").strip().upper()
            if not cve_id or not cve_id.startswith("CVE-"):
                skipped_no_cve += 1
                continue
            try:
                data = self.enrich(cve_id)
                if not data:
                    skipped_cached += 1
                    continue

                details = dict(f.details or {})
                changed = False

                # CVSS score: prefer NVD v3.1 > v3.0 > v2
                cvss_v31 = data.get("cvss_v31")
                cvss_v3 = data.get("cvss_v3")
                cvss_v2 = data.get("cvss_v2")
                best_cvss = cvss_v31 or cvss_v3 or cvss_v2
                if best_cvss is not None:
                    try:
                        best_cvss_f = float(best_cvss)
                        if f.cvss is None:
                            f.cvss = best_cvss_f
                            changed = True
                        details["cvss_v31"] = cvss_v31
                        details["cvss_v3"] = cvss_v3
                        details["nvd_cvss"] = best_cvss_f
                        # Upgrade severity: CVSS >= 9.0 → critical
                        if best_cvss_f >= 9.0 and str(f.severity or "").lower() == "high":
                            f.severity = "critical"
                            details["severity_upgraded_by_cvss"] = True
                            changed = True
                    except (TypeError, ValueError):
                        pass

                # KEV (Known Exploited Vulnerabilities) flag
                if data.get("kev_date_added"):
                    details["kev"] = True
                    details["kev_date_added"] = str(data.get("kev_date_added") or "")
                    details["kev_ransomware"] = bool(data.get("kev_ransomware_use"))
                    details["kev_short_description"] = str(data.get("kev_short_description") or "")[:300]
                    # KEV finding → always HIGH minimum
                    if str(f.severity or "").lower() in ("info", "low", "medium"):
                        f.severity = "high"
                    details["kev_source"] = "CISA KEV Catalogue"
                    changed = True

                # NVD description
                nvd_desc = str(data.get("description") or "").strip()
                if nvd_desc and not details.get("nvd_description"):
                    details["nvd_description"] = nvd_desc[:500]
                    changed = True

                if changed:
                    f.details = details
                    enriched += 1
            except Exception:
                errors += 1
                continue

        try:
            if enriched > 0:
                db.commit()
        except Exception:
            db.rollback()

        import logging as _log
        _log.getLogger(__name__).info(
            "cve_enrich: scan=%d enriched=%d skipped_no_cve=%d errors=%d",
            scan_id, enriched, skipped_no_cve, errors,
        )
        return {
            "enriched": enriched,
            "skipped_no_cve": skipped_no_cve,
            "skipped_cached": skipped_cached,
            "errors": errors,
        }


enrichment_service = CVEEnrichmentService()
