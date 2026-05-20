---
skill_id: "skill.scope_authorization"
name: "Scope Authorization"
version: "1.0.0"
status: "approved"
category: "governance"
phase_ids: ["P01"]
supported_target_types: ["url", "domain", "api_endpoint"]
risk_level: "low"
noise_level: "low"
requires_authorization: true
required_tools:
  - manual_scope_review
optional_tools: []
fallback_tools:
  - manual_review
evidence_required:
  - scope_record
  - authorization_record
  - execution_mode
exit_criteria:
  minimum_tools_attempted: 1
  minimum_evidence_items: 1
  validator_required: true
retry_policy:
  max_attempts: 1
  require_scope_update_on_retry: true
allowed_execution_modes:
  - passive_recon
  - safe_validation
  - controlled_pentest
  - full_authorized_pentest
safety_rules:
  destructive_payloads_allowed: false
  post_exploitation_requires_human_review: true
source_report_ids: []
tags: ["scope", "authorization", "governance"]
---

# Objective

Validate that the campaign target, mode, tools and techniques are authorized before any offensive action executes.

# When To Use

Use at P01 for every campaign and whenever a later phase expands target scope.

# Preconditions

- A target is present.
- A scope object declares allowed domains, protocols and intensity.

# Offensive Reasoning

- O que essa descoberta pode permitir? It prevents accidental work against unauthorized assets.
- Isso pode gerar pivo? No, it gates pivots before they execute.
- Isso pode expor credenciais? No.
- Isso pode aumentar superficie? It may authorize known surface only.
- Isso pode virar attack path? No, but it constrains attack paths.

# Execution Strategy

1. Compare target host, protocol and port against authorized scope.
2. Compare execution mode against allowed engagement rules.
3. Confirm post-exploitation and credential testing flags before later phases.
4. Persist the authorization evidence.

# Tool Mapping

- manual_scope_review: controlled scope validation and evidence capture.

# Payload Candidates

No payloads are executed.

# MCP Execution Requirements

Create an MCP execution contract for `manual_scope_review`; if MCP is unavailable, mark P01 blocked.

# Expected Evidence

- Scope record.
- Authorization record.
- Execution mode record.

# Validation Logic

Success requires scope evidence and policy approval. Failure or missing evidence blocks the phase.

# Retry Strategy

Retry only after scope data is corrected.

# Chaining Opportunities

No offensive chain is created by this Skill.

# False Positive Controls

- Confirm exact host matching.
- Confirm protocol and port matching.

# Post-Execution Updates

Update offensive_state, cross_phase_memory, hypothesis_engine, attack_path_engine and phase_ledger with scope status.

## Changelog

### 1.0.0
- Initial version created for deterministic P01 governance.
