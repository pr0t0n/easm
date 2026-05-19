---
skill_id: "skill.discovery.parameter_discovery"
name: "Parameter and Input Discovery"
version: "1.0.0"
category: "discovery"
phase_ids: ["P04"]
supported_target_types: ["url", "subdomain", "domain"]
risk_level: "medium"
noise_level: "medium"
requires_authorization: true
required_tools:
  - arjun
optional_tools:
  - paramspider
  - ffuf
  - gau
  - waybackurls
fallback_tools:
  - paramspider
evidence_required:
  - discovered_parameters
  - parameter_types
  - endpoints_with_params
exit_criteria:
  minimum_tools_attempted: 1
  minimum_evidence_items: 1
  validator_required: true
retry_policy:
  max_attempts: 2
  reduce_rate_on_retry: true
  change_tool_on_retry: true
attack_chain_opportunities:
  - injectable_parameter_found
  - reflected_parameter_found
  - file_path_parameter_found
  - url_parameter_found
  - id_parameter_found
---

# Objective

Discover all HTTP request parameters (GET, POST, JSON, headers) that an application accepts. Parameter discovery is the prerequisite for all injection testing — you cannot test what you cannot find. Focus on finding hidden parameters, non-documented API fields, and parameters that suggest dangerous processing (file paths, URLs, SQL IDs).

# When To Use

Select this skill when:
- `offensive_state.known_endpoints` contains web application URLs from P03
- Parameter inventory is empty in `cross_phase_memory`
- Phase P04 is the current `current_pentest_phase_id`

# Preconditions

- HTTP/HTTPS endpoints from P03 endpoint discovery
- Authorization scope includes parameter fuzzing
- Arjun and paramspider available in Kali container

# Offensive Reasoning

Parameters are injection points. A pentester thinks:

- "Does this endpoint accept a `url=` or `redirect=` parameter I can use for SSRF?"
- "Is there a hidden `debug=` or `admin=` parameter that changes application behavior?"
- "Does the search endpoint accept a `q=` parameter? That's an XSS/SQLi candidate."
- "Is there an `id=` or `user_id=` parameter that I can enumerate (IDOR)?"
- "Does the file download have a `path=` or `file=` parameter? Path traversal candidate."
- "Are there parameters in JavaScript files that aren't in the HTML forms?"

Parameter naming patterns that signal vulnerability classes:
- `url=`, `redirect=`, `next=`, `return_to=` → SSRF/Open Redirect
- `id=`, `user_id=`, `account=` → IDOR
- `file=`, `path=`, `include=`, `page=` → LFI/Path Traversal
- `q=`, `search=`, `query=`, `name=` → XSS/SQLi
- `cmd=`, `exec=`, `command=` → RCE (critical priority)
- `template=`, `view=`, `lang=` → SSTI

# Execution Strategy

1. **Historical parameter mining** with `gau` and `waybackurls` → mine archived URLs for parameter names
2. **Active parameter discovery** with `arjun` → smart wordlist + behavior difference detection
3. **Spider for form parameters** with `katana` → extract form fields, JS-injected params
4. **POST body fuzzing** with `ffuf` on API endpoints → discover JSON/form body keys
5. Deduplicate and classify by parameter name patterns (see offensive reasoning)

Arjun strategy:
- GET params: default scan with `--get`
- POST params: `--post` with `application/x-www-form-urlencoded`
- JSON params: `--json` for API endpoints returning `Content-Type: application/json`
- Headers: check for `X-Forwarded-For`, `X-Real-IP`, `X-Original-URL` behavior changes

# Tool Mapping

| Tool | Purpose | When |
|------|---------|------|
| arjun | Active parameter discovery via behavior diff | Always first |
| paramspider | Historical parameter mining from web archives | Parallel with arjun |
| gau | GetAllURLs — mine URLs from multiple sources | For URL parameter harvest |
| waybackurls | Wayback Machine URL parameter harvest | Supplement gau |
| ffuf | POST/JSON body parameter fuzzing | API endpoints |
| katana | Active crawler for form/JS parameters | After fuzzing |

# Payload Candidates

Not injection testing (parameter discovery only). Detection signals:

```
# Parameters that indicate dangerous processing:
url, redirect, return, next, dest, destination, forward, target
file, path, include, page, view, template, load
id, uid, user_id, account_id, order_id, invoice_id
cmd, exec, command, shell, run, ping, test
q, query, search, keyword, term, input, name
callback, jsonp, domain, host, endpoint
```

# MCP Execution Requirements

```json
{
  "mcp_request_id": "mcp_P04_arjun",
  "phase_id": "P04",
  "skill_id": "skill.discovery.parameter_discovery",
  "tool_name": "arjun",
  "profile": "arjun_param_discover",
  "target": "{{http_endpoint_url}}",
  "arguments": {
    "stable": true,
    "rate": 100,
    "delay": 0,
    "timeout": 10
  },
  "expected_evidence": ["discovered_parameters", "parameter_types", "endpoints_with_params"]
}
```

# Expected Evidence

| Evidence Type | Description | Required |
|--------------|-------------|---------|
| `discovered_parameters` | List of parameter names per endpoint | Yes |
| `parameter_types` | GET/POST/JSON/header classification | Yes |
| `endpoints_with_params` | Full URL + param pairs | Yes |
| `dangerous_param_patterns` | Parameters matching high-risk naming patterns | If found |
| `historical_params` | Params from web archive mining | Recommended |
| `js_parameters` | Parameters extracted from JavaScript files | Recommended |

# Validation Logic

**SUCCESS**: At least 1 parameter discovered per target endpoint, parameter type classified

**PARTIAL**: Tool ran but 0 parameters found — may indicate server-side rendering with no params, or strict WAF

**FAILURE**: Arjun did not complete or target unreachable

**FALSE POSITIVE risk**: Arjun may report parameters that don't actually change behavior. Verify by comparing baseline vs. parameter response sizes.

# Retry Strategy

Attempt 1: `arjun` with stable mode, rate=100

Attempt 2 (on timeout/WAF blocking):
- Reduce rate to 20, add delay between requests
- Switch to `paramspider` (passive, no active probing)
- Log: "arjun_blocked, rate_reduced, fallback=paramspider"

# Chaining Opportunities

| Signal | Creates Hypothesis | Feeds Skill |
|--------|-------------------|------------|
| `url=` or `redirect=` found | `ssrf_candidate_parameter` | `vulnerability_testing/ssrf.md` |
| `id=` or `user_id=` found | `idor_candidate_parameter` | `vulnerability_testing/auth_bypass.md` |
| `q=` or `search=` found | `xss_sqli_candidate_parameter` | `vulnerability_testing/xss.md`, `vulnerability_testing/sqli.md` |
| `file=` or `path=` found | `lfi_traversal_candidate` | `vulnerability_testing/ssrf.md` |
| `cmd=` or `exec=` found | `rce_candidate_parameter` | `vulnerability_testing/auth_bypass.md` |
| `template=` or `view=` found | `ssti_candidate_parameter` | `vulnerability_testing/xss.md` |

# Post-Execution Updates

```json
{
  "cross_phase_memory.parameters": {"<endpoint>": ["<param_list>"]},
  "cross_phase_memory.dangerous_params": ["<high_risk_parameter_endpoints>"],
  "active_hypotheses": ["<per chaining signal>"],
  "attack_paths": ["<if cmd= or exec= found>"],
  "phase_ledger.P04.status": "completed|partial|blocked",
  "phase_ledger.P04.evidence_ids": ["<evidence_id>"],
  "pentest_phase_index": 4
}
```
