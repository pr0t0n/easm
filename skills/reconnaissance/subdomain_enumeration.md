---
skill_id: skill.recon.subdomain_enumeration
name: Subdomain Enumeration
version: 1.0.0
category: reconnaissance
phase_ids:
- P01
status: approved
supported_target_types:
- domain
- apex_domain
risk_level: low
noise_level: low
requires_authorization: true
required_tools:
- subfinder
optional_tools:
- amass
- amass-brute
- amass-intel
- theharvester
- dnsx
- assetfinder
- sublist3r
- findomain
- dnsrecon-brt
- dnsrecon-zt
- dnsenum
- shuffledns
- alterx
- nuclei-takeover
fallback_tools:
- assetfinder
evidence_required:
- subdomain_list
- dns_resolution_proof
- source_tool_name
exit_criteria:
  minimum_tools_attempted: 1
  minimum_evidence_items: 1
  validator_required: true
retry_policy:
  max_attempts: 2
  change_tool_on_retry: true
  rag_reconsult_allowed: true
attack_chain_opportunities:
- subdomain_takeover_candidate
- expanded_attack_surface
- internal_service_exposure
allowed_execution_modes:
- passive_recon
- safe_validation
- controlled_pentest
- full_authorized_pentest
safety_rules:
  destructive_payloads_allowed: false
  scope_guard_required: true
source_report_ids: []
---

# Objective

Enumerate all subdomains of a target apex domain to expand the authorized attack surface. The goal is to discover hosts that may be running services unknown to the target's security team, including development environments, staging servers, forgotten applications, and internal tooling accidentally exposed to the internet.

# When To Use

Select this skill when:
- The target is an apex domain (e.g., `example.com`)
- No subdomain inventory exists yet in `offensive_state.known_assets`
- `pentest_phase_index` points to P01

Do NOT use when:
- Target is already a specific subdomain or IP address
- `lista_ativos` already contains >10 subdomains from a previous run

# Preconditions

- Target must be an apex domain with valid DNS
- Authorization scope must include `*.target.com`
- Internet egress must be available from the Kali runner

# Offensive Reasoning

Subdomains are the first expansion vector. A pentester thinks:

- "What assets does this company run that I don't know about?"
- "Can I find dev/staging environments with weaker controls than production?"
- "Are there forgotten subdomains pointing at abandoned cloud services (takeover candidates)?"
- "Do any subdomains resolve to internal RFC-1918 ranges that reveal network topology?"
- "Can dangling CNAMEs lead to subdomain takeover and session/credential hijacking?"

Questions to answer for every discovered subdomain:
- Does this subdomain resolve? (live vs. dead)
- What service is running on it?
- Does it have a dangling CNAME pointing to an unclaimed service?
- Is it in scope for further testing?

# Execution Strategy

1. Run `subfinder` passively — fastest, no target traffic, uses CT logs and DNS databases
2. Run `assetfinder` in parallel to supplement with Wayback Machine and certspotter sources
3. If subfinder yields < 5 results, run `amass` for active enumeration
4. Pipe all results through `dnsx` to validate DNS resolution (filters dead subdomains)
5. For known subdomains, run `alterx` permutation generation to find pattern-based subdomains
6. Run `shuffledns` if target appears to have many internal/stealth subdomains

# Tool Mapping

| Tool | Purpose | When |
|------|---------|------|
| subfinder | Passive CT-log and DNS-DB enumeration | Always first |
| assetfinder | Fast Wayback/certspotter supplement | Parallel with subfinder |
| amass | Deep active enumeration with ASN mapping | When passive yields < 10 results |
| dnsx | DNS resolution validation and filtering | After enumeration to filter live |
| alterx | Permutation generation from known subdomains | After base enumeration |
| shuffledns | Brute-force with massdns backend | When deep coverage required |

# Payload Candidates

Not applicable (enumeration, not injection).

Wordlists used by `shuffledns`:
- `/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt`
- Permutations from `alterx` based on discovered pattern

# MCP Execution Requirements

```json
{
  "mcp_request_id": "mcp_P01_subfinder",
  "phase_id": "P01",
  "skill_id": "skill.recon.subdomain_enumeration",
  "tool_name": "subfinder",
  "profile": "subfinder_passive",
  "target": "{{domain}}",
  "arguments": {
    "silent": true,
    "threads": 100
  },
  "expected_evidence": ["subdomain_list", "source_counts"]
}
```

## Changelog

### 1.0.0
- Initial version created for the offensive operator skill library.

# Expected Evidence

| Evidence Type | Description | Required |
|--------------|-------------|---------|
| `subdomain_list` | List of discovered subdomains with DNS resolution status | Yes |
| `dns_resolution_proof` | DNS A/CNAME records for each live subdomain | Yes |
| `source_tool_name` | Which tool found each subdomain | Yes |
| `takeover_candidates` | Subdomains with dangling CNAMEs | If found |
| `wildcard_detection` | Whether apex domain has wildcard DNS | Recommended |

# Validation Logic

**SUCCESS**: At least 1 subdomain resolved successfully, tool completed with exit_code=0

**PARTIAL**: Tool ran but zero subdomains resolved — may indicate wildcard DNS or restricted scope

**FAILURE**: Tool did not complete (timeout, error, no profile mapping)

**FALSE POSITIVE risk**: Wildcard DNS — all random names resolve. Detect via `dnsx` wildcard probe.

# Retry Strategy

Attempt 1: `subfinder` (passive, fast)

Attempt 2 (on failure/timeout):
- Switch to `assetfinder` as fallback
- Reduce thread count if rate-limited
- Log: "subfinder_failed, fallback=assetfinder"

Attempt 3 (if both fail):
- Mark phase as `partial` — log `mcp_unavailable` or `tool_not_found`
- Do NOT mark as `completed`
- Record `skip_reason` in `phase_ledger`

# Chaining Opportunities

| Signal | Creates Hypothesis | Feeds Skill |
|--------|-------------------|------------|
| Dangling CNAME found | `subdomain_takeover_candidate` | `attack_chains/subdomain_takeover_chain.md` |
| Dev/staging subdomain | `weaker_auth_controls` | `vulnerability_testing/auth_bypass.md` |
| Many subdomains (>50) | `broad_attack_surface` | `reconnaissance/port_service_discovery.md` |
| IP range discovered | `network_topology_exposure` | `reconnaissance/port_service_discovery.md` |

# Post-Execution Updates

After execution, update:

```json
{
  "offensive_state.known_assets": ["<all resolved subdomains>"],
  "offensive_state.known_endpoints": [],
  "cross_phase_memory.subdomains": ["<subdomain list>"],
  "cross_phase_memory.dns_records": {"<subdomain>": "<A/CNAME>"},
  "attack_paths": ["<if takeover candidate found>"],
  "active_hypotheses": ["<if dangling CNAME found>"],
  "phase_ledger.P01.status": "completed|partial|blocked",
  "phase_ledger.P01.evidence_ids": ["<evidence_id>"],
  "phase_ledger.P01.tools_success": ["subfinder"],
  "pentest_phase_index": 1
}
```
