---
skill_id: "skill.chain.exposed_git_to_credential_leak"
name: "Exposed Git Repository to Credential Leak Chain"
version: "1.0.0"
category: "attack_chains"
phase_ids: ["P03", "P14", "P15", "P18", "P20"]
status: "approved"
supported_target_types: ["url", "subdomain", "domain"]
risk_level: "high"
noise_level: "low"
requires_authorization: true
required_tools:
  - curl
optional_tools:
  - git
  - gitleaks
  - trufflehog
  - trufflehog-filesystem
  - bandit
  - semgrep
  - trivy
  - retire
  - h8mail
  - theharvester
fallback_tools:
  - gitleaks
evidence_required:
  - git_repository_accessible
  - source_code_downloaded
  - credentials_found_in_source
exit_criteria:
  minimum_tools_attempted: 1
  minimum_evidence_items: 2
  validator_required: true
  human_review_required: true
retry_policy:
  max_attempts: 2
  change_tool_on_retry: true
attack_chain_opportunities:
  - credentials_reuse_candidate
  - database_connection_string_found
  - api_key_found
  - aws_credentials_found
  - hardcoded_secrets_found
allowed_execution_modes:
  - controlled_pentest
  - full_authorized_pentest
safety_rules:
  destructive_payloads_allowed: false
  scope_guard_required: true
  human_review_required_for_credentials: true
source_report_ids: []
changelog:
  - version: "1.0.0"
    date: "2025-01-01"
    change: "Initial chain definition"
    requires_human_review: true
    review_reason: "Attack chain involving credential extraction requires human review before escalation"
---

# Objective

## Changelog

### 1.0.0
- Initial version created for the offensive operator skill library.

Execute the full attack chain from exposed `.git/` directory discovery to credential/secret extraction from source code. This is one of the highest-yield low-noise attack chains in web application security — a misconfigured web server exposing `.git/` allows complete source code reconstruction without authentication.

**CRITICAL**: This chain produces real credentials. Do NOT use extracted credentials to access production systems without explicit authorization. Document the finding and stop.

# Attack Chain Description

```
P03: Endpoint Discovery finds /.git/HEAD (HTTP 200)
  ↓
Reconstruct git repository from exposed objects
  ↓
Extract full source code from git objects
  ↓
P14: Scan source code for secrets (API keys, DB passwords, AWS creds)
  ↓
P15: Validate credentials are live (check, don't exploit)
  ↓
Finding: Critical — source code + credentials exposed
```

# When To Use

Select this skill when:
- P03 endpoint discovery found `/.git/HEAD` returning HTTP 200
- `attack_paths` contains `git_source_code_exposed`
- Active hypotheses include `git_source_code_exposed`
- Phase P03/P14/P15 is current

# Preconditions

- `/.git/HEAD` confirmed accessible and returning content (not redirect)
- Authorization includes source code analysis
- Human review required before any credential validation step

# Offensive Reasoning

Exposed `.git/` is a critical misconfiguration. A pentester thinks:

- "`.git/HEAD` returns `ref: refs/heads/main` — the git directory is public."
- "I can reconstruct the entire source tree by fetching git pack objects."
- "With the source code, I can find database connection strings, API keys, AWS credentials."
- "Hardcoded credentials in `config.php`, `.env`, `application.properties`, `secrets.yml`."
- "Git history may contain secrets that were 'deleted' in later commits but still exist in old commits."
- "AWS access keys follow the pattern `AKIA[A-Z0-9]{16}` — easy to grep for."

High-value secret patterns to scan for:
- `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`
- `DATABASE_URL`, `DB_PASSWORD`, `MYSQL_PASSWORD`
- `API_KEY`, `SECRET_KEY`, `STRIPE_SECRET`
- `PRIVATE_KEY`, `-----BEGIN RSA PRIVATE KEY-----`
- `password = "..."`, `passwd = "..."`

# Execution Strategy

1. **Confirm git exposure** — `curl -s https://target.com/.git/HEAD` must return `ref:` content
2. **Reconstruct repository** — use `git-dumper` or manual pack-file reconstruction
3. **Scan for secrets** — run `gitleaks` or `trufflehog` on reconstructed source tree
4. **Scan git history** — check old commits for rotated secrets (`git log -p | grep -E 'password|secret|key'`)
5. **Document findings** — record all secrets found, do NOT use them
6. **Human review** — all credential findings require human review before any further action

Never:
- Use found credentials to authenticate to any system
- Exfiltrate credentials to external systems
- Use found API keys to make API calls
- Share credentials outside the authorized report

# Tool Mapping

| Tool | Purpose | When |
|------|---------|------|
| curl | Confirm .git/HEAD accessibility | Always first |
| git (git-dumper) | Reconstruct repository from exposed objects | After confirmation |
| gitleaks | Scan source code + git history for secrets | After reconstruction |
| trufflehog | High-entropy secret scanning | Supplement gitleaks |

# Payload Candidates

Not applicable (this chain reconstructs, doesn't inject).

Key files to check after reconstruction:
```
.env, .env.local, .env.production
config/database.yml, config/secrets.yml
application.properties, application.yml
wp-config.php, config.php, settings.py
docker-compose.yml, docker-compose.prod.yml
.aws/credentials, ~/.ssh/id_rsa
```

# MCP Execution Requirements

Step 1 — Confirm access:
```json
{
  "mcp_request_id": "mcp_chain_git_confirm",
  "phase_id": "P03",
  "skill_id": "skill.chain.exposed_git_to_credential_leak",
  "tool_name": "curl",
  "profile": "curl_headers",
  "target": "{{target_url}}/.git/HEAD",
  "arguments": {
    "method": "GET",
    "follow_redirects": false,
    "timeout": 10
  },
  "expected_evidence": ["git_repository_accessible"]
}
```

Step 2 — Scan for secrets (after reconstruction):
```json
{
  "mcp_request_id": "mcp_chain_gitleaks",
  "phase_id": "P14",
  "skill_id": "skill.chain.exposed_git_to_credential_leak",
  "tool_name": "gitleaks",
  "profile": "gitleaks_detect",
  "target": "{{reconstructed_repo_path}}",
  "arguments": {
    "report_format": "json",
    "no_git": false
  },
  "expected_evidence": ["credentials_found_in_source"]
}
```

# Expected Evidence

| Evidence Type | Description | Required |
|--------------|-------------|---------|
| `git_repository_accessible` | HTTP 200 response from `/.git/HEAD` with `ref:` content | Yes |
| `source_code_downloaded` | Confirmation of successful source reconstruction | Yes |
| `credentials_found_in_source` | Secret type + file + line (NOT the actual secret value in logs) | Yes (if found) |
| `git_history_secrets` | Secrets found in old commits | If found |
| `secret_types` | Classification: AWS/DB/API key/private key/etc. | Yes (if found) |
| `files_affected` | List of files containing secrets | Yes (if found) |

**IMPORTANT**: Evidence records MUST NOT contain the raw secret value. Log secret_type, file, line_number, and a masked preview (first 4 + `***`) only.

# Validation Logic

**SUCCESS**: `.git/HEAD` accessible + source code reconstructed + at least 1 secret type identified

**PARTIAL**: `.git/HEAD` accessible but incomplete repository reconstruction (missing pack files)

**FAILURE**: `.git/HEAD` returns 403/404, git reconstruction fails, or `gitleaks` unavailable

**FALSE POSITIVE risk**: Some apps serve a custom 404 page with 200 status. Verify `.git/HEAD` content starts with `ref: refs/heads/` or is a 40-char SHA.

# Retry Strategy

Attempt 1: curl confirm + git-dumper + gitleaks

Attempt 2:
- If git-dumper fails, try manual object fetching (`/.git/objects/pack/*.idx`)
- If gitleaks unavailable, use `trufflehog` with `--filesystem` mode
- Log: "git_dumper_failed, manual_object_fetch_attempted"

# Chaining Opportunities

| Signal | Creates Hypothesis | Feeds Skill |
|--------|-------------------|------------|
| AWS creds found | `aws_credential_exfil_candidate` | (requires explicit authorization) |
| DB connection string found | `db_credential_direct_access` | (requires explicit authorization) |
| JWT secret found | `jwt_forgery_all_users` | `vulnerability_testing/auth_bypass.md` |
| Private SSH key found | `ssh_key_based_auth_bypass` | `vulnerability_testing/auth_bypass.md` |
| API key found | `third_party_api_access` | (document only) |

# Post-Execution Updates

```json
{
  "vulnerabilidades_encontradas": ["<Critical: exposed git + credentials, files affected, secret types>"],
  "cross_phase_memory.git_exposure": {"url": "{{target_url}}/.git", "secrets_found": true, "secret_types": []},
  "active_hypotheses": ["<per chaining signal>"],
  "validated_chains": ["<chain name, evidence_ids, confidence>"],
  "attack_paths": ["<attack path: .git exposure → source code → credentials>"],
  "phase_ledger.P03.status": "completed",
  "phase_ledger.P14.status": "completed|partial",
  "phase_ledger.P15.status": "pending_human_review"
}
```
