"""poc_validator.py — PoC Sandbox Execution (DeepAudit pattern).

PENTEST PRINCIPLE: "No exploit, no report."
  When a HIGH/CRITICAL finding is created as 'candidate' (not yet confirmed),
  this service automatically creates a P21 ScanWorkItem that runs the most
  appropriate validation tool against the SPECIFIC endpoint where the finding
  was detected — not the broad domain.

Architecture:
  1. findings_extractor.persist_findings_from_work_item() creates a Finding
  2. If severity=HIGH/CRITICAL and verification_status='candidate' → call schedule_poc_validation()
  3. This creates a P21 ScanWorkItem with item_metadata.verifies_finding_id=finding.id
  4. kali_runner executes the validation tool against the specific matched_at URL
  5. tasks.py T1 block fires when P21 item completes:
       completed → finding.verification_status = 'confirmed'
       failed    → finding.verification_status = 'refuted'
  6. Only 'confirmed' findings appear as HIGH/CRITICAL in the pentest report

Tool selection strategy (DeepAudit-inspired, pentest-ai 0% FP approach):
  - XSS candidate → dalfox (callback-confirmed)
  - SQLi candidate → sqlmap (payload-confirmed, --level=2 for speed)
  - SSRF candidate → nuclei-ssrf + interactsh-client
  - JWT flaw → jwt_tool (alg:none, key confusion)
  - Secret/git exposure → nuclei-exposure (curl to verify accessibility)
  - RCE candidate → nuclei-rce (template re-run on specific matched_at)
  - LFI candidate → nuclei-lfi (template re-run)
  - Auth bypass → nuclei-auth-bypass (template re-run)
  - Subdomain takeover → nuclei-takeover (CNAME claim verification)
  - Generic nuclei candidate → re-run original template on matched_at URL
"""

from __future__ import annotations

import logging
import re
from typing import Any

logger = logging.getLogger(__name__)

# ── Maximum PoC validation items per scan ─────────────────────────────────────
# Prevents creating hundreds of P21 items for noisy scans (e.g. nikto + nmap
# generating 500 high findings). Cap ensures we validate the MOST CRITICAL findings.
MAX_POC_VALIDATIONS_PER_SCAN = 50

# ── Tools that already prove the finding — no re-validation needed ─────────────
SELF_VALIDATING_TOOLS = {
    # Active exploitation — output proves the condition
    "sqlmap", "dalfox", "wapiti", "wpscan", "hydra",
    "gitleaks", "trufflehog", "semgrep", "jwt_tool",
    # OOB callback = irrefutable proof of interaction
    "interactsh-client",
    # Chain correlation and SAST with high confidence
    "exploit_chain_engine", "trivy", "bandit",
    # Prototype pollution analyzer — active test
    "js_pollution_analyzer",
}


def _select_validation_tool(finding: Any) -> tuple[str | None, str]:
    """Select the best tool + target URL to validate a candidate finding.

    Returns:
        (tool_name, target_url)
        tool_name is None if no suitable validator exists.
    """
    title = str(getattr(finding, "title", "") or "").lower()
    tool_orig = str(getattr(finding, "tool", "") or "").lower()
    details = dict(getattr(finding, "details", None) or {})
    domain = str(getattr(finding, "domain", "") or "")

    # Resolve the most specific URL available (matched_at > url > asset > domain)
    target_url = str(
        getattr(finding, "url", None)
        or details.get("matched_at")
        or details.get("matched-at")
        or details.get("asset")
        or domain
        or ""
    ).strip()[:500]

    if not target_url:
        return None, ""

    # ── Tool selection by finding type ────────────────────────────────────────

    # SQL Injection
    if any(k in title for k in ("sql injection", "sqli", "sql")):
        return "sqlmap", target_url
    if tool_orig.startswith("nuclei-sqli") or tool_orig == "nuclei-sqli":
        return "sqlmap", target_url

    # XSS
    if any(k in title for k in ("xss", "cross-site scripting", "reflected xss", "stored xss")):
        return "dalfox", target_url
    if tool_orig.startswith("nuclei-xss") or tool_orig == "dalfox":
        return "dalfox", target_url

    # SSRF
    if "ssrf" in title or "server-side request forgery" in title:
        return "nuclei-ssrf", target_url

    # JWT / OAuth
    if any(k in title for k in ("jwt", "json web token", "jwt alg", "jwt none")):
        return "jwt_tool", target_url
    if any(k in title for k in ("oauth", "open id connect")):
        return "nuclei-oauth", target_url

    # RCE / Command Injection
    if any(k in title for k in ("rce", "remote code execution", "command injection", "os injection")):
        return "nuclei-rce", target_url

    # LFI / Path Traversal
    if any(k in title for k in ("path traversal", "lfi", "local file inclusion", "directory traversal")):
        return "nuclei-lfi", target_url

    # Secret / Credential Exposure
    if any(k in title for k in (".git", "git repository", "git config", "git exposed")):
        return "nuclei-exposure", target_url
    if any(k in title for k in ("api key", "secret", "credential", "password exposed", "token exposed")):
        return "nuclei-exposure", target_url
    if tool_orig in ("gitleaks", "trufflehog"):
        # Already self-validating but if somehow candidate, re-run exposure check
        return "nuclei-exposure", target_url

    # Auth Bypass / Default Credentials
    if any(k in title for k in ("auth bypass", "authentication bypass", "default credential", "default password")):
        return "nuclei-auth-bypass", target_url
    if any(k in title for k in ("default credentials", "weak password")):
        return "nuclei-default-credentials", target_url

    # IDOR / Access Control
    if any(k in title for k in ("idor", "insecure direct object", "broken access")):
        return "nuclei-idor", target_url

    # Open Redirect
    if any(k in title for k in ("open redirect", "unvalidated redirect")):
        return "nuclei-redirect", target_url

    # Subdomain Takeover
    if "subdomain takeover" in title or "dangling cname" in title:
        return "nuclei-takeover", target_url

    # CORS Misconfiguration
    if "cors" in title:
        return "nuclei-cors", target_url

    # Header misconfigs (clickjacking, CSP, HSTS) — verify via nuclei-headers
    if any(k in title for k in ("clickjacking", "x-frame-options", "content security policy",
                                 "hsts", "missing security header")):
        return "nuclei-headers", target_url

    # Generic Nuclei candidate: re-run original template on the specific matched_at URL
    if tool_orig.startswith("nuclei"):
        template_id = str(details.get("template_id") or "").strip()
        if template_id:
            # Use the original tool name — ensures same template is re-run
            return tool_orig, target_url
        return "nuclei", target_url  # generic nuclei run on specific URL

    # Nikto candidate findings — validate via nuclei exposure check
    if tool_orig == "nikto":
        return "nuclei-exposure", target_url

    # No specific validator
    return None, target_url


def _count_existing_poc_items(db: Any, scan_job_id: int) -> int:
    """Count P21 PoC validation items already scheduled for this scan."""
    try:
        from app.models.models import ScanWorkItem as _SWI
        return (
            db.query(_SWI)
            .filter(
                _SWI.scan_job_id == scan_job_id,
                _SWI.phase_id == "P21",
            )
            .count()
        )
    except Exception:
        return 0


def schedule_poc_validation(
    db: Any,
    finding: Any,
    job: Any,
) -> bool:
    """Create a P21 ScanWorkItem to validate a candidate HIGH/CRITICAL finding.

    Called from findings_extractor.persist_findings_from_work_item() immediately
    after persisting a new HIGH/CRITICAL candidate finding.

    Returns True if a validation item was successfully scheduled.
    """
    from app.models.models import ScanWorkItem
    from app.services.scan_work_queue import apply_phase_tool_metadata

    # ── Guards ────────────────────────────────────────────────────────────────

    # Only HIGH and CRITICAL severity warrant PoC validation cost
    severity = str(getattr(finding, "severity", "") or "").lower()
    if severity not in ("critical", "high"):
        return False

    # Already confirmed — no need to validate again
    v_status = str(getattr(finding, "verification_status", "") or "candidate")
    if v_status == "confirmed":
        return False

    # Self-validating tools already prove the finding — skip
    tool_name = str(getattr(finding, "tool", "") or "").lower()
    if tool_name in SELF_VALIDATING_TOOLS:
        return False

    # Cap: don't flood the queue with validation items
    existing_count = _count_existing_poc_items(db, job.id)
    if existing_count >= MAX_POC_VALIDATIONS_PER_SCAN:
        return False

    # Check if this finding already has a validation item scheduled
    finding_id = getattr(finding, "id", None)
    if finding_id:
        try:
            _existing_for_finding = (
                db.query(ScanWorkItem)
                .filter(
                    ScanWorkItem.scan_job_id == job.id,
                    ScanWorkItem.phase_id == "P21",
                    ScanWorkItem.item_metadata["verifies_finding_id"].astext == str(finding_id),
                )
                .first()
            )
            if _existing_for_finding:
                return False
        except Exception:
            pass  # JSONB path query error — proceed without the check

    # ── Select validation tool ────────────────────────────────────────────────
    val_tool, val_target = _select_validation_tool(finding)
    if not val_tool or not val_target:
        return False

    # ── Determine resource class ──────────────────────────────────────────────
    # sqlmap/dalfox are heavy; nuclei variants are medium
    _HEAVY_VAL = {"sqlmap", "dalfox", "wapiti", "jwt_tool"}
    resource_class = "heavy" if val_tool in _HEAVY_VAL else "medium"

    # ── Build metadata ────────────────────────────────────────────────────────
    details = dict(getattr(finding, "details", None) or {})
    meta: dict[str, Any] = {
        "verifies_finding_id": finding_id,
        "original_finding_title": str(getattr(finding, "title", "") or "")[:200],
        "original_severity": severity,
        "original_tool": tool_name,
        "original_verification_status": v_status,
        "poc_validation": True,
        "poc_scheduled_reason": (
            f"Auto-PoC: {tool_name} {severity} candidate → validate with {val_tool}"
        ),
    }

    # Pass template_id for nuclei re-runs
    template_id = str(details.get("template_id") or "").strip()
    if template_id:
        meta["nuclei_template_id"] = template_id

    # Pass original payload/parameter if available (for sqlmap/dalfox)
    if val_tool in ("sqlmap", "dalfox"):
        param = str(details.get("parameter") or details.get("param") or "").strip()
        if param:
            meta["target_parameter"] = param

    # ── Create the P21 validation item ───────────────────────────────────────
    try:
        # Use (phase_id=P21, tool=val_tool, target=val_target) as the unique key.
        # If the same finding spawns a duplicate (edge case), the DB unique constraint
        # will silently skip it via on_conflict_do_nothing in claim_work_items.
        val_item = ScanWorkItem(
            scan_job_id=job.id,
            phase_id="P21",
            target=val_target,
            tool_name=val_tool,
            profile=val_tool,
            resource_class=resource_class,
            # Priority 30 = high priority (lower number = dispatched first).
            # Normal items are 100. PoC items jump the queue because they
            # unblock report generation.
            priority=30,
            status="queued",
            max_attempts=1,  # PoC gets one shot — fail = refuted
            item_metadata=apply_phase_tool_metadata(meta, "P21", val_tool, source="poc_validator"),
        )
        db.add(val_item)
        db.flush()

        logger.info(
            "poc_validator: scheduled P21 item=%d scan=%d finding=%s "
            "severity=%s tool=%s→%s target=%.80s",
            val_item.id,
            job.id,
            finding_id,
            severity,
            tool_name,
            val_tool,
            val_target,
        )
        return True

    except Exception as exc:
        # Unique constraint violation = already scheduled; other errors = log + skip
        logger.debug("poc_validator: schedule failed finding=%s: %s", finding_id, exc)
        db.rollback()
        return False


def batch_schedule_poc_validations(
    db: Any,
    scan_job_id: int,
    max_findings: int = 30,
) -> dict[str, int]:
    """Bulk-schedule PoC validations for all unvalidated HIGH/CRITICAL findings.

    Called from tasks.py after P09 gate opens to catch any findings that were
    created before poc_validator was wired in, or for manual re-trigger.

    Returns:
        {"scheduled": N, "skipped_confirmed": N, "skipped_cap": N, "skipped_no_tool": N}
    """
    from app.models.models import Finding as _Finding, ScanJob as _ScanJob

    job = db.query(_ScanJob).filter(_ScanJob.id == scan_job_id).first()
    if not job:
        return {"error": "scan not found"}

    # Get all HIGH/CRITICAL non-confirmed findings without existing P21 items
    candidates = (
        db.query(_Finding)
        .filter(
            _Finding.scan_job_id == scan_job_id,
            _Finding.severity.in_(["critical", "high"]),
            _Finding.verification_status != "confirmed",
            _Finding.is_false_positive.is_(False),
        )
        .order_by(_Finding.risk_score.desc())
        .limit(max_findings * 3)  # over-fetch to account for skips
        .all()
    )

    scheduled = 0
    skipped_confirmed = 0
    skipped_cap = 0
    skipped_no_tool = 0

    for f in candidates:
        if scheduled >= max_findings:
            skipped_cap += 1
            continue

        if str(getattr(f, "verification_status", "") or "") == "confirmed":
            skipped_confirmed += 1
            continue

        existing_count = _count_existing_poc_items(db, scan_job_id)
        if existing_count >= MAX_POC_VALIDATIONS_PER_SCAN:
            skipped_cap += 1
            continue

        val_tool, val_target = _select_validation_tool(f)
        if not val_tool:
            skipped_no_tool += 1
            continue

        ok = schedule_poc_validation(db, f, job)
        if ok:
            scheduled += 1

    try:
        db.commit()
    except Exception as exc:
        logger.warning("batch_schedule_poc_validations commit failed: %s", exc)
        db.rollback()

    logger.info(
        "batch_poc_validation: scan=%d scheduled=%d skipped_confirmed=%d "
        "skipped_cap=%d skipped_no_tool=%d",
        scan_job_id, scheduled, skipped_confirmed, skipped_cap, skipped_no_tool,
    )
    return {
        "scheduled": scheduled,
        "skipped_confirmed": skipped_confirmed,
        "skipped_cap": skipped_cap,
        "skipped_no_tool": skipped_no_tool,
    }
