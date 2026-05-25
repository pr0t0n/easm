---
skill_id: skill.recon.port_service_discovery
name: Port and Service Discovery
version: 1.0.0
category: reconnaissance
phase_ids:
- P02
- P06
- P07
status: approved
supported_target_types:
- domain
- subdomain
- ip_address
- cidr
risk_level: medium
noise_level: medium
requires_authorization: true
required_tools:
- naabu
optional_tools:
- nmap
- nmap-vuln
- nmap-ssl
- nmap-ssh
- nmap-smb
- nmap-dns
- nmap-http
- masscan
- httpx
- whatweb
- wafw00f
- sslscan
- testssl
- shodan-cli
- nuclei-headers
- nuclei-cors
- nuclei-clickjacking
- nuclei-spoofing
- nuclei-crlf
fallback_tools:
- nmap
evidence_required:
- open_ports_list
- service_banners
- protocol_per_port
exit_criteria:
  minimum_tools_attempted: 1
  minimum_evidence_items: 1
  validator_required: true
retry_policy:
  max_attempts: 2
  reduce_rate_on_retry: true
  change_tool_on_retry: true
attack_chain_opportunities:
- exposed_internal_service
- open_port_service
- admin_panel_found
- credentials_found
allowed_execution_modes:
- safe_validation
- controlled_pentest
- full_authorized_pentest
safety_rules:
  destructive_payloads_allowed: false
  scope_guard_required: true
source_report_ids: []
---

# Objective

Identify all open TCP ports and running services on discovered hosts. Combine fast port scanning (naabu) with deep service/version detection (nmap) to build a service inventory that drives all subsequent exploitation phases.

# When To Use

Select this skill when:
- `offensive_state.known_assets` contains hosts from P01
- `discovered_ports` in state is empty or incomplete
- Phase P02 is the current `current_pentest_phase_id`

# Preconditions

- Live host list available from P01 (subdomain enumeration)
- Authorization scope includes active probing
- Raw socket capability available in Kali container (naabu/masscan)

# Offensive Reasoning

Every open port is a potential entry point. A pentester thinks:

- "Which services are running that shouldn't be exposed to the internet?"
- "Are there database ports (3306, 5432, 27017) open without authentication?"
- "Is there an admin panel on a non-standard port?"
- "Are there services running old versions with known CVEs?"
- "Does the service banner reveal exact version info for CVE matching?"

Questions for every open port:
- What service is running?
- What version?
- Is there a known CVE for this version?
- Is this service expected to be public-facing?
- Does this port indicate a broader internal exposure?

# Execution Strategy

1. **Pre-screen** with `naabu` (top-1000 ports, fast SYN scan) → get open port list
2. **Deep scan** with `nmap -sV -sC` on open ports only → get service/version + NSE scripts
3. **HTTP probe** with `httpx` on ports 80, 443, 8080, 8443, and any HTTP-like ports from nmap → get live web targets for P03+
4. For large networks (>50 hosts), use `masscan` for initial discovery before naabu

# Tool Mapping

| Tool | Purpose | When |
|------|---------|------|
| naabu | Fast TCP port pre-screen (top-1000) | Always first |
| nmap | Service/version detection + NSE scripts | On ports found by naabu |
| masscan | Internet-scale stateless scan | Large CIDR ranges |
| httpx | HTTP/HTTPS probe on discovered ports | After port scan |

# Payload Candidates

Not applicable (port scanning, not payload injection).

Port ranges:
- Top-1000 (default naabu)
- Web ports: 80, 443, 8080, 8443, 3000, 5000, 8000, 9000
- Database ports: 3306, 5432, 27017, 6379, 9200
- Admin ports: 9090, 9443, 4848, 8161, 15672

# MCP Execution Requirements

```json
{
  "mcp_request_id": "mcp_P02_naabu",
  "phase_id": "P02",
  "skill_id": "skill.recon.port_service_discovery",
  "tool_name": "naabu",
  "profile": "naabu_top1000",
  "target": "{{host_ip}}",
  "arguments": {
    "top_ports": 1000,
    "silent": true,
    "rate": 1000
  },
  "expected_evidence": ["open_ports", "host_port_pairs"]
}
```

## Changelog

### 1.0.0
- Initial version created for the offensive operator skill library.

# Expected Evidence

| Evidence Type | Description | Required |
|--------------|-------------|---------|
| `open_ports_list` | List of open TCP ports per host | Yes |
| `service_banners` | Service name + version from nmap -sV | Yes |
| `protocol_per_port` | TCP/UDP protocol per port | Yes |
| `nse_findings` | NSE script output (default scripts) | Recommended |
| `http_live_targets` | HTTP/HTTPS URLs confirmed live by httpx | Yes (if web) |

# Validation Logic

**SUCCESS**: At least 1 open port found and service banner obtained

**PARTIAL**: Ports found but nmap service detection failed (timeout on deep scan)

**FAILURE**: naabu did not complete — log failure reason

**FALSE POSITIVE risk**: Filtered ports (RST vs. DROP) may appear closed under firewall rate limiting. Adjust scan rate.

# Retry Strategy

Attempt 1: `naabu` at rate=1000

Attempt 2 (on timeout/filtered):
- Reduce rate to 200
- Try `nmap --top-ports 200 -T3` as fallback
- Log: "naabu_timeout, rate_reduced, fallback=nmap"

# Chaining Opportunities

| Signal | Creates Hypothesis | Feeds Skill |
|--------|-------------------|------------|
| Port 22 open (SSH) | `brute_force_ssh_viable` | `vulnerability_testing/auth_bypass.md` |
| Port 3306/5432 open | `database_exposed_to_internet` | `vulnerability_testing/auth_bypass.md` |
| Port 27017 open (MongoDB) | `noauth_mongodb_candidate` | `vulnerability_testing/auth_bypass.md` |
| Port 6379 open (Redis) | `unauthenticated_redis` | `vulnerability_testing/auth_bypass.md` |
| Port 8080/9090 open | `admin_panel_on_alt_port` | `discovery/endpoint_discovery.md` |

# Post-Execution Updates

```json
{
  "discovered_ports": ["<port list>"],
  "offensive_state.known_assets": ["<host:port pairs>"],
  "cross_phase_memory.services": {"<host:port>": "<service/version>"},
  "cross_phase_memory.http_targets": ["<live web targets from httpx>"],
  "active_hypotheses": ["<per chaining signal>"],
  "phase_ledger.P02.status": "completed|partial|blocked",
  "phase_ledger.P02.evidence_ids": ["<evidence_id>"],
  "pentest_phase_index": 2
}
```
