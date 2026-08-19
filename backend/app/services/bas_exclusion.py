"""BAS Finding exclusion — SSOT for keeping SIMULATED BAS data out of every
real risk aggregation.

BAS writes real `Finding` rows so they're inspectable in the normal Findings
UI, all `tool="bas-agent"`. Whether one counts as real is `details["simulated"]`
-- set per-dispatch by bas_scheduler.py from the BasAgent that ran it:
`agent.kind == "stub"` (bas_agent_stub, kept in place to validate
Kali<->agent traffic) always fabricates its tunnel's response content, so
that Finding is excluded here; `agent.kind == "real"` (cryptographically
proven via a CA-signed mTLS cert -- see bas_ca.py) actually relayed to a
real destination, so its Finding is real and must NOT be excluded -- it
counts toward severity/score/attack-path/reports exactly like any other
Finding.

There is no single choke point that already covers every Finding query in
this codebase -- `_authorized_finding_query` (routes_scans.py) covers most
dashboard/cockpit endpoints, but attack_path.py, exploit_chain.py, and
report_generator.py each run their own direct `db.query(Finding)`. Apply
`exclude_simulated(query)` at each site individually (see the plan's
exhaustive call-site list) rather than relying on one shared query builder.
"""
from __future__ import annotations

from typing import Any

from sqlalchemy import and_, not_

from app.models.models import Finding

BAS_FINDING_TOOL = "bas-agent"


def exclude_simulated(query):
    """Filter a Finding query (or a query joined against Finding) to drop
    only SIMULATED BAS-sourced rows (stub-agent dispatches) -- a real-agent
    BAS Finding is never excluded. Safe to chain onto any SQLAlchemy query
    object that already selects/joins the Finding model."""
    return query.filter(
        not_(and_(
            Finding.tool == BAS_FINDING_TOOL,
            Finding.details["simulated"].astext == "true",
        ))
    )


def is_bas_finding(finding: Any) -> bool:
    return str(getattr(finding, "tool", "") or "") == BAS_FINDING_TOOL


def is_simulated_bas_finding(finding: Any) -> bool:
    if not is_bas_finding(finding):
        return False
    details = getattr(finding, "details", None) or {}
    return bool(details.get("simulated", True))
