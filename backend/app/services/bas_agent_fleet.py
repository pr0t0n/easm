from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any


def metadata_dict(agent: Any) -> dict[str, Any]:
    value = getattr(agent, "agent_metadata", None) or {}
    return dict(value) if isinstance(value, dict) else {}


def fleet_defaults() -> dict[str, Any]:
    return {
        "tags": [],
        "agent_group": "",
        "site": "",
        "business_unit": "",
        "local_policy": {
            "allow_remote_config": True,
            "allow_auto_update": False,
            "max_parallel_jobs": 1,
            "allowed_technique_tiers": ["safe"],
        },
        "remote_config": {
            "config_revision": 1,
            "heartbeat_interval_seconds": 30,
            "relay_failover": [],
            "auto_update": {"enabled": False, "channel": "stable", "version": ""},
            "policy": {},
        },
        "capabilities": {},
        "health": {"score": 0, "grade": "unknown", "reasons": ["never_seen"]},
    }


def merged_metadata(agent: Any) -> dict[str, Any]:
    base = fleet_defaults()
    current = metadata_dict(agent)
    for key, value in current.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            nested = dict(base[key])
            nested.update(value)
            base[key] = nested
        else:
            base[key] = value
    return base


def normalize_tags(values: list[str] | None) -> list[str]:
    seen = set()
    tags = []
    for value in values or []:
        tag = str(value or "").strip()
        if not tag or tag in seen:
            continue
        seen.add(tag)
        tags.append(tag[:64])
    return tags[:20]


def health_score(agent: Any, now: datetime | None = None) -> dict[str, Any]:
    now = now or datetime.now()
    meta = merged_metadata(agent)
    score = 0
    reasons = []
    heartbeat_at = getattr(agent, "last_heartbeat_at", None)
    if heartbeat_at and heartbeat_at >= now - timedelta(minutes=2):
        score += 35
    else:
        reasons.append("heartbeat_stale")
    if str(getattr(agent, "status", "") or "") == "online":
        score += 15
    else:
        reasons.append("agent_offline")
    if getattr(agent, "local_network_cidr", None):
        score += 10
    else:
        reasons.append("network_unknown")
    capabilities = meta.get("capabilities") or {}
    if capabilities:
        score += 15
    else:
        reasons.append("capabilities_missing")
    relay = capabilities.get("proxy") or {}
    if relay.get("socks_port") or meta.get("remote_config", {}).get("relay_failover"):
        score += 10
    else:
        reasons.append("relay_unreported")
    if meta.get("local_policy"):
        score += 10
    else:
        reasons.append("policy_missing")
    if meta.get("agent_group") or meta.get("site") or meta.get("tags"):
        score += 5
    else:
        reasons.append("untagged")
    grade = "healthy" if score >= 80 else "degraded" if score >= 50 else "critical"
    return {"score": score, "grade": grade, "reasons": reasons}


def apply_heartbeat(agent: Any, payload: Any) -> dict[str, Any]:
    meta = merged_metadata(agent)
    if payload is not None:
        capabilities = getattr(payload, "capabilities", None)
        if isinstance(capabilities, dict) and capabilities:
            meta["capabilities"] = capabilities
        local_policy = getattr(payload, "local_policy", None)
        if isinstance(local_policy, dict) and local_policy:
            meta["local_policy"] = local_policy
        config_revision = getattr(payload, "config_revision", None)
        if config_revision is not None:
            meta["agent_config_revision"] = int(config_revision or 0)
        relay_status = getattr(payload, "relay_status", None)
        if isinstance(relay_status, dict) and relay_status:
            meta["relay_status"] = relay_status
        auto_update = getattr(payload, "auto_update", None)
        if isinstance(auto_update, dict) and auto_update:
            meta["auto_update_status"] = auto_update
    agent.agent_metadata = meta
    meta["health"] = health_score(agent)
    agent.agent_metadata = meta
    return meta


def remote_config_payload(agent: Any) -> dict[str, Any]:
    meta = merged_metadata(agent)
    config = dict(meta.get("remote_config") or {})
    policy = dict(meta.get("local_policy") or {})
    if not config.get("policy"):
        config["policy"] = policy
    config.setdefault("agent_group", meta.get("agent_group") or "")
    config.setdefault("site", meta.get("site") or "")
    config.setdefault("tags", meta.get("tags") or [])
    return config


def agent_to_fleet_dict(agent: Any) -> dict[str, Any]:
    meta = merged_metadata(agent)
    health = health_score(agent)
    return {
        "id": getattr(agent, "id", None),
        "label": getattr(agent, "label", ""),
        "hostname": getattr(agent, "hostname", ""),
        "os": getattr(agent, "os", ""),
        "os_version": getattr(agent, "os_version", ""),
        "arch": getattr(agent, "arch", ""),
        "agent_version": getattr(agent, "agent_version", ""),
        "status": getattr(agent, "status", ""),
        "kind": getattr(agent, "kind", ""),
        "last_heartbeat_at": getattr(agent, "last_heartbeat_at", None),
        "last_seen_ip": getattr(agent, "last_seen_ip", None),
        "local_network_cidr": getattr(agent, "local_network_cidr", None),
        "tags": meta.get("tags") or [],
        "agent_group": meta.get("agent_group") or "",
        "site": meta.get("site") or "",
        "business_unit": meta.get("business_unit") or "",
        "capabilities": meta.get("capabilities") or {},
        "health": health,
        "local_policy": meta.get("local_policy") or {},
        "remote_config": meta.get("remote_config") or {},
        "relay_status": meta.get("relay_status") or {},
        "auto_update_status": meta.get("auto_update_status") or {},
    }


def fleet_summary(agents: list[Any]) -> dict[str, Any]:
    rows = [agent_to_fleet_dict(agent) for agent in agents]
    groups: dict[str, dict[str, Any]] = {}
    for row in rows:
        key = row["agent_group"] or row["site"] or "ungrouped"
        group = groups.setdefault(key, {"key": key, "agents": 0, "online": 0, "sites": set(), "tags": set(), "health_avg": 0})
        group["agents"] += 1
        if row["status"] == "online":
            group["online"] += 1
        if row["site"]:
            group["sites"].add(row["site"])
        for tag in row["tags"]:
            group["tags"].add(tag)
        group["health_avg"] += int((row.get("health") or {}).get("score") or 0)
    normalized_groups = []
    for group in groups.values():
        agents_count = max(1, group["agents"])
        normalized_groups.append({
            "key": group["key"],
            "agents": group["agents"],
            "online": group["online"],
            "sites": sorted(group["sites"]),
            "tags": sorted(group["tags"]),
            "health_avg": round(group["health_avg"] / agents_count),
        })
    return {
        "agents": rows,
        "groups": sorted(normalized_groups, key=lambda item: (-item["online"], item["key"])),
        "summary": {
            "agents": len(rows),
            "online": sum(1 for row in rows if row["status"] == "online"),
            "healthy": sum(1 for row in rows if row["health"]["grade"] == "healthy"),
            "degraded": sum(1 for row in rows if row["health"]["grade"] == "degraded"),
            "critical": sum(1 for row in rows if row["health"]["grade"] == "critical"),
        },
    }
