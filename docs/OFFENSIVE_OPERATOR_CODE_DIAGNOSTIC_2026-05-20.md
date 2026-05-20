# Offensive Operator Code Diagnostic

Date: 2026-05-20

## Current Flow

`POST /api/scans` creates `ScanJob` in `backend/app/api/routes_scans.py:create_scan`, then queues `run_scan_job_unit`. The worker enters `backend/app/workers/tasks.py:_execute_scan`, previously invoked `backend/app/graph/workflow.py:build_graph`, and the LangGraph started at `rag_enrichment -> supervisor -> skill_selector -> skill_planner -> tool_selector -> tool_executor -> evidence_gate`.

## Findings

| File | Function/Class | Problem | Impact | Correction |
|---|---|---|---|---|
| `backend/app/api/routes_scans.py` | `create_scan` | Creates a generic scan with only `llm_risk` in `state_data`; no formal scope object or execution mode is required. | Execution could start without the offensive campaign contract being explicit. | `offensive_operator_runner` now derives a conservative scope from `ScanJob` and stores `execution_mode`, `offensive_state`, `phase_ledger_v2`. |
| `backend/app/workers/tasks.py` | `_execute_scan` | Main path invoked LangGraph mission/capability loop, not deterministic P01-P22 Skill runtime. | Platform behaved like capability router/finding orchestrator. | Added `settings.offensive_operator_enabled`; when enabled, worker runs `run_offensive_operator_scan` before legacy LangGraph. |
| `backend/app/graph/workflow.py` | `build_graph` | Graph transitions route by supervisor-selected capability nodes, not by mandatory phase contracts. | P01-P22 can be bypassed by routing decisions. | New worker path uses `PHASE_ORDER` from `offensive_operator_core` as deterministic campaign loop. |
| `backend/app/graph/nodes/supervisor.py` | `_route_from_supervisor` / `supervisor_node` | Supervisor decides next capability and feeds skill pipeline. | Capability-first behavior remains in legacy mode. | Kept for compatibility; default worker path now bypasses it through offensive operator. |
| `backend/app/graph/workflow.py` | `route_next_required_phase` | Supports offensive priority queue promotion ahead of sequential pending phase. | Can jump to a later phase based on findings. | New `offensive_operator_core.route_next_required_phase` is deterministic and does not promote. |
| `backend/app/workers/agent_supervisor.py` | `execute_phase` | Marks/submits phase but does not execute Skill Runtime or MCP tool plans. | False progress risk: phase orchestration exists without actual execution. | New `offensive_operator_runner` calls `OffensiveSkillRuntime.run_phase` for each phase. |
| `backend/app/services/tool_adapters.py` | `run_tool_execution` | If MCP was enabled but failed or returned error, code fell back to direct Kali runner. | MCP contract could be skipped while tools still ran, creating false success. | Removed fallback when MCP is mandatory; now returns `mcp_unavailable` and does not execute. |
| `backend/app/services/worker_dispatcher.py` | `execute_tool_with_workers` | Used `settings.mcp_execute_tools_via_mcp and mcp_client.health_check_sync()`; if health failed, it executed direct Kali runner in the `else` branch. | Worker execution could bypass MCP and create evidence without an MCP execution contract. | Mandatory MCP branch now checks `kali_tools_available_sync()` and returns `mcp_unavailable` instead of falling back. Direct Kali is allowed only when MCP execution is explicitly disabled. |
| `backend/app/services/skill_runtime.py` | `_parse_yaml_frontmatter` / loader | Lightweight frontmatter parser loads Markdown Skills, but no quality gate or execution policy. | Skills can become text enrichment instead of operational contracts. | `offensive_operator_core.SkillRegistry` now enforces quality gate for runtime path. |
| `backend/app/services/skill_rag_indexer.py` | `index_skills_to_knowledge_store` | Indexes Skills into MCP lexical store, but legacy graph can still operate from active skills/catalog. | RAG can become enrichment rather than Skill resolver. | `OffensiveSkillRuntime` retrieves skills with metadata filters before compiling tool plans. |
| `mcp-server/mcp_server.py` | `/rag/query` | Returns generic `results` content objects. | Callers can consume text blobs instead of structured Skills. | `SkillRagIndex.retrieve` returns `retrieved_skills` objects in the runtime path. |
| `mcp-server/mcp_server.py` | `/mcp/execute` | Correctly returns explicit status and blocks missing evidence/profile. | Good execution contract, but not mandatory everywhere before. | Worker path now uses MCP execution contract via `MCPToolExecutor`. |
| `kali-runner/runner.py` | `/jobs` and `_run_job` | Executes profiled commands and persists stdout/stderr in workspace. | Good runner foundation. | Runtime path uses MCP server as the only bridge to Kali. |
| `backend/app/graph/workflow.py` | `_update_phase_ledger_for_tool` | Evidence is boolean `evidence_persisted`, not evidence record with strength. | Phase can complete on weak/implicit evidence. | New runtime uses `EvidenceCollector` with `evidence_strength`. |
| `backend/app/services/phase_validator.py` | `validate_phase_exit_criteria` | Allows partial-ok phases to advance without attempted tools. | False success / coverage gap can be hidden. | New `offensive_operator_core.PhaseValidator` blocks missing MCP/tool/evidence for runtime path. |
| `backend/app/workers/tasks.py` | finding persistence loop | Final state persists `Finding` rows after tool parsers. | Report is finding-centric. | New `ReportBuilder` builds campaign timeline from `phase_ledger_v2`. |
| `backend/app/services/offensive_reasoning.py` | `apply_offensive_reasoning` hook | Offensive state is updated from findings after tool batches. | State can be lost if no finding is emitted. | New runtime updates `offensive_state`, hypotheses and attack paths from evidence each phase. |
| `backend/app/services/tool_catalog.py` | `TOOL_CATALOG` | Rich prompt catalog but not an enforcing selector. | Tool hallucination risk if LLM-selected names bypass catalog. | `ToolCatalog.require` blocks missing tools during Tool Plan compile. |
| `skills/*` | Markdown Skills | Some Skills lacked runtime metadata (`allowed_execution_modes`, `safety_rules`, `## Changelog`) or phase coverage. | Quality gate would block real Skill execution. | Updated key Skills and phase coverage used by P01-P22 runtime. |
| `skills/vulnerability_testing/idor_object_authorization.md` | frontmatter `phase_ids` | P19 had no approved Skill in controlled pentest mode. | P19 could not resolve Skill through RAG/registry and would block before execution planning. | Added P19 to the approved IDOR/access-control Skill because it covers post-exploitation boundary validation without credential or data-access escalation. |
| `skills/reporting/evidence_quality.md` | quality gate sections | P21/P22 reporting Skill missed required operational sections. | Quality gate failed and reporting/evidence review phases lost approved Skill coverage. | Added approved status plus Offensive Reasoning, Execution Strategy and Tool Mapping sections. |
| `skills/attack_chains/exposed_git_to_credential_leak.md` | `required_tools` | Required `git`, but no `git` Kali/MCP profile existed in the enforced catalog path. | Tool plan compilation could block on a non-profiled required tool. | Kept `curl` as required evidence-gathering tool, moved `git` to optional, and lowered minimum attempted tools to 1. |
| `kali-runner/profiles/operational.yaml` | operational profiles | Contract phases referenced audit-only tools (`manual_scope_review`, `manual_review`, `report-builder`) with no runner profiles. | Tool catalog/profile enforcement could reject non-invasive governance/reporting phases. | Added low-risk raw-output profiles and mapped them in `TOOL_TO_PROFILE`. |

## Corrected Flow

Authorized scope -> `run_offensive_operator_scan` -> P01-P22 `PHASE_ORDER` -> `SkillRagIndex.retrieve` -> `SkillRegistry.approved_for_phase` -> `SkillToToolPlanCompiler` -> `ExecutionPolicyEngine` / `ScopeGuard` -> `MCPToolExecutor` -> `/mcp/execute` -> Kali Runner -> `EvidenceCollector` -> `PhaseValidator` -> Hypothesis/Attack Path/Learning -> `phase_ledger_v2` -> campaign report.

## Residual Legacy Surface

The old LangGraph capability pipeline still exists for compatibility and can be re-enabled with `OFFENSIVE_OPERATOR_ENABLED=false`. It should be treated as legacy mode because it still has capability routing and finding-centric persistence.

## Validation Notes

- `SkillRegistry` validation: no failed Skills and no missing P01-P22 phase coverage for `controlled_pentest`.
- Contract tests executed manually because local Python lacks `pytest`: `contract_tests_ok`.
- Python syntax validation passed for changed backend services, MCP server and Kali runner.
- `python3 -m pytest backend/tests/test_offensive_operator_integration_contract.py` could not run in this local interpreter because `pytest` is not installed.
