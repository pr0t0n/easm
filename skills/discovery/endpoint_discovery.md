---
skill_id: "skill.discovery.endpoint_discovery"
name: "Endpoint and Content Discovery"
version: "1.0.0"
category: "discovery"
phase_ids: ["P03", "P05", "P08", "P09"]
status: "approved"
supported_target_types: ["domain", "subdomain", "url", "ip_address"]
risk_level: "medium"
noise_level: "high"
requires_authorization: true
required_tools:
  - ffuf
optional_tools:
  - nuclei
  - gobuster
  - feroxbuster
  - dirsearch
  - katana
  - katana-js
  - hakrawler
  - gospider
  - gau
  - waybackurls
  - nmap-http
  - httpx
  - whatweb
  - nikto
  - curl-headers
  - wafw00f
fallback_tools:
  - gobuster
evidence_required:
  - discovered_paths
  - http_status_codes
  - response_sizes
exit_criteria:
  minimum_tools_attempted: 1
  minimum_evidence_items: 1
  validator_required: true
retry_policy:
  max_attempts: 2
  reduce_rate_on_retry: true
  change_tool_on_retry: true
  change_wordlist_on_retry: true
attack_chain_opportunities:
  - admin_panel_found
  - backup_file_found
  - git_exposed
  - config_file_exposed
  - api_endpoint_found
  - upload_endpoint_found
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

Discover all accessible endpoints, directories, files, and administrative panels on HTTP/HTTPS targets. Map the complete application attack surface by combining wordlist fuzzing with crawling, focusing on endpoints that expose functionality, sensitive data, or administrative access.

# When To Use

Select this skill when:
- `cross_phase_memory.http_targets` contains live HTTP/HTTPS URLs from P02
- `discovered_paths` in state is empty or incomplete
- Phase P03 is the current `current_pentest_phase_id`

# Preconditions

- Live HTTP/HTTPS targets from P02 httpx probe
- Authorization scope includes directory/content enumeration
- SecLists wordlists available in Kali container

# Offensive Reasoning

Every web application has hidden endpoints. A pentester thinks:

- "Is there an `/admin` or `/wp-admin` panel accessible without authentication?"
- "Are there backup files like `config.php.bak`, `database.sql`, `.env` exposed?"
- "Does the app have a `.git/` directory that leaks source code?"
- "Are there API endpoints at `/api/v1/`, `/api/v2/`, `/graphql`?"
- "Are there file upload endpoints at `/upload`, `/files`, `/attachments`?"
- "Does `/actuator/` or `/metrics` expose Spring Boot internals?"

Questions for every discovered path:
- What HTTP methods does it accept? (GET, POST, PUT, DELETE)
- Does it require authentication? (200 vs 401 vs 302 to login)
- What does the response size tell us? (same size = soft 404, different = real content)
- Does this path reveal framework, version, or technology?
- Is this path linked from the homepage or entirely hidden?

# Execution Strategy

1. **Fast wordlist fuzz** with `ffuf` on top-level paths (common directories, admin panels, backup extensions)
2. **Recursive fuzz** with `feroxbuster` on interesting paths found in step 1
3. **Crawl** with `katana` or `hakrawler` to find JS-linked paths that wordlists miss
4. **Filter false positives** — exclude same-size responses, WAF catch-alls
5. For APIs, run dedicated API wordlists (`/api/v1`, `/v2`, `/graphql`, `/swagger`, `/openapi`)

Priority wordlists:
- `raft-large-directories.txt` — 60k+ directories
- `common.txt` — quick wins (admin, backup, config, etc.)
- `api-endpoints.txt` — REST/GraphQL API paths
- `backup-ext.txt` — `.bak`, `.old`, `.orig`, `.swp`, `.zip`

# Tool Mapping

| Tool | Purpose | When |
|------|---------|------|
| ffuf | Fast HTTP fuzzer with wordlist | Always first |
| feroxbuster | Recursive directory brute-force | After initial ffuf hits |
| gobuster | Alternate directory brute-forcer | Fallback when ffuf unavailable |
| dirsearch | Python-based directory scanner | Fallback |
| katana | Active JS-aware crawler | After fuzzing for linked paths |
| hakrawler | Fast passive crawler | Alternative to katana |

# Payload Candidates

Not injection-focused (content discovery). Key file/path targets:

```

## Changelog

### 1.0.0
- Initial version created for the offensive operator skill library.
# Admin panels
/admin, /administrator, /wp-admin, /cpanel, /panel

# Sensitive files
/.env, /.git/HEAD, /.git/config, /config.php, /database.sql
/backup.zip, /backup.tar.gz, /.htpasswd, /web.config

# API paths
/api, /api/v1, /api/v2, /graphql, /swagger-ui.html, /openapi.json, /v1, /v2

# Framework paths
/actuator, /actuator/env, /actuator/health, /metrics, /health
/phpinfo.php, /info.php, /server-status, /server-info

# File upload
/upload, /uploads, /files, /attachments, /media
```

# MCP Execution Requirements

```json
{
  "mcp_request_id": "mcp_P03_ffuf",
  "phase_id": "P03",
  "skill_id": "skill.discovery.endpoint_discovery",
  "tool_name": "ffuf",
  "profile": "ffuf_dirs",
  "target": "{{http_target_url}}",
  "arguments": {
    "wordlist": "/usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt",
    "threads": 50,
    "timeout": 10,
    "filter_status": "404,400,403",
    "output_format": "json"
  },
  "expected_evidence": ["discovered_paths", "http_status_codes", "response_sizes"]
}
```

# Expected Evidence

| Evidence Type | Description | Required |
|--------------|-------------|---------|
| `discovered_paths` | List of valid URLs with status codes | Yes |
| `http_status_codes` | HTTP response code per path | Yes |
| `response_sizes` | Content-Length per response (dedup filter) | Yes |
| `interesting_files` | Backup/config/source files found | If found |
| `admin_panels` | Admin/management interfaces discovered | If found |
| `api_endpoints` | REST/GraphQL API paths discovered | If found |
| `redirect_targets` | 301/302 redirect destinations | Recommended |

# Validation Logic

**SUCCESS**: At least 5 valid paths discovered (status 200/301/302/403), at least 1 non-homepage response

**PARTIAL**: ffuf completed but < 5 unique paths found — may indicate WAF filtering or sparse app

**FAILURE**: ffuf failed to connect, all responses same size (WAF catch-all), or tool not found

**FALSE POSITIVE risk**: WAF returns 200 for every path with same content. Detect by checking response size variance. Use `ffuf` `-fs` to filter by size.

# Retry Strategy

Attempt 1: `ffuf` with `raft-large-directories.txt` at 50 threads

Attempt 2 (on WAF/rate-limit):
- Reduce threads to 10, add delay
- Switch wordlist to `common.txt` (smaller, less noisy)
- Try `gobuster` as fallback
- Log: "ffuf_rate_limited, threads_reduced, fallback=gobuster"

# Chaining Opportunities

| Signal | Creates Hypothesis | Feeds Skill |
|--------|-------------------|------------|
| `.git/HEAD` accessible | `git_source_code_exposed` | `attack_chains/exposed_git_to_credential_leak.md` |
| `/admin` returns 200 | `admin_panel_no_auth` | `vulnerability_testing/auth_bypass.md` |
| `/upload` endpoint found | `file_upload_attack_surface` | `vulnerability_testing/file_upload.md` |
| `/.env` accessible | `env_credentials_exposed` | `attack_chains/exposed_git_to_credential_leak.md` |
| `/api/v1` found | `api_surface_found` | `discovery/parameter_discovery.md` |
| `/actuator/env` returns 200 | `spring_boot_internals_exposed` | `vulnerability_testing/ssrf.md` |
| `phpinfo.php` found | `tech_fingerprint_phpinfo` | `vulnerability_testing/sqli.md` |

# Post-Execution Updates

```json
{
  "offensive_state.known_endpoints": ["<discovered URLs>"],
  "cross_phase_memory.http_targets": ["<updated with new endpoints>"],
  "cross_phase_memory.interesting_paths": ["<admin/upload/api paths>"],
  "active_hypotheses": ["<per chaining signal>"],
  "attack_paths": ["<if .git or .env found>"],
  "phase_ledger.P03.status": "completed|partial|blocked",
  "phase_ledger.P03.evidence_ids": ["<evidence_id>"],
  "pentest_phase_index": 3
}
```
