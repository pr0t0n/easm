---
skill_id: "skill.technical_report"
name: "Technical Campaign Report"
version: "1.0.0"
status: "approved"
category: "reporting"
phase_ids: ["P22"]
supported_target_types: ["url", "domain", "api_endpoint"]
risk_level: "low"
noise_level: "low"
requires_authorization: true
required_tools:
  - report-builder
optional_tools: []
fallback_tools:
  - manual_review
evidence_required:
  - phase_ledger
  - evidence_index
  - mcp_execution_index
exit_criteria:
  minimum_tools_attempted: 1
  minimum_evidence_items: 1
  validator_required: true
retry_policy:
  max_attempts: 2
  refresh_phase_ledger_on_retry: true
allowed_execution_modes:
  - passive_recon
  - safe_validation
  - controlled_pentest
  - full_authorized_pentest
source_report_ids: []
safety_rules:
  destructive_payloads_allowed: false
vulnerability_class: "reporting"
tags: ["reporting", "campaign", "phase-ledger"]
---

# Objective

Build a campaign report from phase ledger, evidence, hypotheses, attack paths and operational failures.

# When To Use

Use at P22 after prior phases are completed, partial, blocked or explicitly skipped.

# Preconditions

- Phase ledger exists.
- Evidence index exists, even if empty phases are blocked.

# Offensive Reasoning

- O que essa descoberta pode permitir? It explains offensive coverage and limitations.
- Isso pode gerar pivo? It can identify next authorized steps.
- Isso pode expor credenciais? No.
- Isso pode aumentar superficie? No.
- Isso pode virar attack path? It reports attack paths, it does not create them.

# Execution Strategy

1. Read phase ledger.
2. Summarize MCP executions and evidence by phase.
3. Separate validated findings from inconclusive hypotheses.
4. Report blocked phases and coverage gaps.

# Tool Mapping

- report-builder: compile campaign narrative from structured state.

# Payload Candidates

No payloads are executed.

# MCP Execution Requirements

Create an MCP execution contract for `report-builder` to keep report generation auditable.

# Expected Evidence

- Phase ledger.
- Evidence index.
- MCP execution index.

# Validation Logic

Report is complete only if it includes phases, skills, MCP executions, evidence, hypotheses and attack paths.

# Retry Strategy

Refresh ledger and evidence inputs, then regenerate.

# Chaining Opportunities

Report next authorized attack path candidates.

# False Positive Controls

- Do not promote inconclusive hypotheses to validated findings.
- Preserve evidence strength labels.

# Post-Execution Updates

Persist report artifact, phase_ledger reference and campaign summary.

## Changelog

### 1.0.0
- Initial version created for campaign narrative reporting.
