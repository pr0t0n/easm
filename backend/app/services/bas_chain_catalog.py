"""Static, code-defined BAS attack-chain catalog: named, ordered sequences
of techniques that model a real kill-chain process instead of a flat,
uncorrelated list of independent dispatches.

Never a DB table, same rationale as bas_technique_catalog.py: the sequence
itself is a trusted, code-reviewed property, not something an operator
should be able to quietly reorder into something unsafe.

A schedule with a chain_key set (see BasSchedule.chain_key) has its
technique_keys stamped FROM this catalog server-side at creation/patch time
(routes_bas.py) -- the client never supplies the sequence directly for a
chain schedule. bas_scheduler.fire_schedule dispatches technique_keys in
list order (already true for a flat list) but additionally STOPS EARLY when
schedule.stop_on_failure is set and a step's real dispatch outcome is
"failed" -- every chain schedule gets stop_on_failure=True automatically,
since running step 3 after step 1 already failed produces noise, not signal.
"""
from __future__ import annotations

from typing import Any

BAS_CHAIN_CATALOG: list[dict[str, Any]] = [
    {
        "chain_key": "ad_enumeration_chain",
        "display_name": "AD Enumeration Chain",
        "description": (
            "Sequential AD/SMB reconnaissance: share discovery -> LDAP scouting -> "
            "BloodHound collection -> Kerberoasting. Each step only makes sense if the "
            "previous one found something reachable, so a real failure stops the chain."
        ),
        "technique_keys": ["network_share_discovery", "ad_scouting_ldap", "ad_bloodhound_collect", "ad_kerberoast"],
    },
    {
        "chain_key": "web_to_secrets_chain",
        "display_name": "Web Recon to Secrets Chain",
        "description": (
            "Port/service discovery -> web application scan -> pipeline log secrets "
            "harvesting -- a realistic recon-to-exposure path against a web-facing target."
        ),
        "technique_keys": ["port_service_scan", "owasp_web_app_scan", "pipeline_secrets_harvesting"],
    },
    {
        "chain_key": "supply_chain_secrets_chain",
        "display_name": "Supply Chain Secrets Chain",
        "description": (
            "Cloud identity fingerprinting -> source-code secrets scan -- checks whether "
            "a target's cloud tenancy and its code repositories both leak information."
        ),
        "technique_keys": ["cloud_directory_scouting", "source_code_secrets_scan"],
    },
    {
        "chain_key": "internal_pentest_from_agent",
        "display_name": "Internal Pentest From Agent",
        "description": (
            "Agent-based internal pentest flow: asset discovery, service fingerprint, SMB/credential boundary checks, "
            "AD enumeration, safe lateral movement reachability, controlled validation, and secrets exposure evidence."
        ),
        "technique_keys": [
            "port_service_scan",
            "network_share_discovery",
            "smb_enum_cme",
            "safe_credential_checks",
            "ad_scouting_ldap",
            "ad_bloodhound_collect",
            "lateral_movement_simulation_safe",
            "controlled_exploit_validation",
            "source_code_secrets_scan",
        ],
    },
]

_CATALOG_BY_KEY: dict[str, dict[str, Any]] = {row["chain_key"]: row for row in BAS_CHAIN_CATALOG}


def list_chains() -> list[dict[str, Any]]:
    return list(BAS_CHAIN_CATALOG)


def get_chain(chain_key: str) -> dict[str, Any] | None:
    return _CATALOG_BY_KEY.get(str(chain_key or ""))
