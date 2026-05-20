from __future__ import annotations

from typing import Any, TypedDict

# Mapeamento de fases/atividades para grupos de worker
MISSION_PHASE_TO_GROUP = {
    "Recon": "recon",
    "Vuln Scan": "vuln",
    "Content": "recon",
    "SSL/TLS": "recon",
    "Auth": "vuln",
    "Injection": "vuln",
    "SSRF": "vuln",
    "IDOR": "vuln",
    "API": "vuln",
    "Upload": "vuln",
    "RCE": "vuln",
    "Race": "vuln",
    "Takeover": "recon",
    "Email": "osint",
    "Cloud": "osint",
    "WebSocket": "vuln",
    "CMS": "vuln",
    "Links": "recon",
    "Supply Chain": "osint",
    "Report": "recon",
}

TOOL_CAPABILITY_NODES = {"asset_discovery", "threat_intel", "risk_assessment"}

# Preferred skill categories per capability node — used by supervisor to select
# the operational skill before handing off to the skill pipeline.
CAPABILITY_SKILL_CATEGORIES: dict[str, tuple[str, ...]] = {
    "asset_discovery": ("reconnaissance", "technologies", "protocols"),
    "threat_intel": ("osint", "code", "vulnerabilities"),
    "risk_assessment": ("vulnerabilities", "protocols", "technologies"),
}


class AgentState(TypedDict):
    trace_id: str
    scan_id: int
    target: str
    scan_mode: str                          # "unit" | "scheduled"
    target_type: str                        # "site" | "dominio" — controla expansão de subdomínios
    easm_segment: str                       # Segmento de mercado inferido
    input_targets: list[str]
    lista_ativos: list[str]
    logs_terminais: list[str]
    vulnerabilidades_encontradas: list[dict[str, Any]]
    proxima_ferramenta: str
    discovered_ports: list[int]
    pending_port_tests: list[int]
    pending_asset_scans: list[str]
    scanned_assets: list[str]
    discovered_subdomains_persisted: list[str]  # Subdomínios já salvos no banco (idempotência)
    port_followup_done: bool
    activity_metrics: list[dict[str, Any]]
    mission_metrics: dict[str, int]
    node_history: list[str]
    mission_index: int
    mission_items: list[str]
    known_vulnerability_patterns: list[str]
    executed_tool_runs: list[str]
    # Governance fields (preenchidos pelo GovernanceNode)
    asset_fingerprints: dict[str, dict]     # asset -> {waf, tech, ports, cvss}
    fair_decomposition: dict[str, Any]      # 3-pillar FAIR breakdown
    easm_rating: dict[str, Any]             # {score, grade, factors, methodology}
    # Executive fields (preenchidos pelo ExecutiveAnalystNode)
    executive_summary: str                  # Narrativa LLM gerada
    # Senior framework contracts
    analyst_framework: dict[str, Any]       # Framework ativo e política de decisão
    operation_plan: dict[str, Any]          # Plano estruturado por fases
    confidence_state: dict[str, Any]        # Confiança por hipótese/fase
    evidence_contract: dict[str, Any]       # Regras de promoção de achados
    completed_capabilities: list[str]       # Capacidades já executadas no ciclo atual
    loop_iteration: int                      # Iteração atual do supervisor
    max_iterations: int                      # Orçamento máximo de iterações
    objective_met: bool                      # Flag de término de operação
    termination_reason: str                  # Motivo de término da operação
    routing_next_node: str                   # Próximo nó escolhido pelo supervisor
    pending_capability_node: str             # Capability aguardando skill/tool pipeline
    current_phase: str                       # Fase atual (usado para proteção contra loop)
    last_completed_node: str                 # Último nó de capacidade concluído
    agent_validation: dict[str, Any]         # Score de qualidade da execução
    owner_id: int                            # ID do usuário dono do scan
    # Autonomous agent runtime
    active_skills: list[dict[str, Any]]
    active_skill: str
    current_skill: str
    skill_selector_ready: bool
    skill_selector_gate: dict[str, Any]
    skill_invocation: dict[str, Any]
    skill_contract: dict[str, Any]
    skill_plan_contract: dict[str, Any]
    skill_invocations: list[dict[str, Any]]
    selected_skill: dict[str, Any]          # Skill escolhida pelo supervisor para o próximo ciclo
    capability_context: dict[str, Any]
    tool_selection_contract: dict[str, Any]
    tool_execution_results: list[dict[str, Any]]
    delegated_tasks: list[dict[str, Any]]
    delegation_log: list[dict[str, Any]]
    autonomy_notes: list[dict[str, Any]]
    autonomy_todos: list[dict[str, Any]]
    autonomy_actions: list[dict[str, Any]]
    autonomy_observations: list[dict[str, Any]]
    autonomy_errors: list[dict[str, Any]]
    execution_control: dict[str, Any]
    tool_runtime: dict[str, dict[str, int]]
    validation_backlog: list[dict[str, Any]]
    # ── Ciclo supervisor ↔ agente ────────────────────────────────────────────
    current_activity_demand: dict[str, Any]      # Demanda emitida pelo supervisor ao agente
    completed_activity_types: list[str]          # activity_types já aprovados neste scan
    agent_report: dict[str, Any]                 # Relatório compilado pelo agente após execução
    supervisor_evaluations: list[dict[str, Any]] # Histórico de avaliações do supervisor
    kill_chain_progress: dict[str, Any]          # {phase: {status, approved_activities}}
    current_activity_log_id: int | None          # ID do AgentActivityLog corrente
    # ── Offensive Reasoning Model ────────────────────────────────────────────
    campaign: dict[str, Any]                     # Active offensive campaign (id, stage, objectives, paths)
    attack_paths: list[dict[str, Any]]           # Discovered attack paths (fragments → consolidated paths)
    active_hypotheses: list[dict[str, Any]]      # Open attack hypotheses (statement, priority, test_phases)
    validated_chains: list[dict[str, Any]]       # Confirmed exploit chains from exploit_chain engine
    offensive_observations: list[dict[str, Any]] # Per-finding offensive observations (signals, questions)
    post_exploitation_queue: list[dict[str, Any]]# Post-exploitation tasks (harvest, enum, lateral)
    noise_profile: str                           # Current stealth/aggressive profile
    offensive_priority_queue: list[dict[str, Any]]  # Priority-ordered next phases/actions
    chaining_candidates: list[dict[str, Any]]    # Attack path fragments for chain detection
    # ── Phased pentest execution (P01–P22) ──────────────────────────────────
    pentest_phase_index: int                     # Index into PENTEST_PHASES (0-based); 0 = P01
    current_pentest_phase_id: str                # Current phase ID e.g. "P04"
    phase_ledger: dict[str, Any]                 # Per-phase execution record keyed by phase_id
    # phase_ledger[phase_id] = {
    #   status: pending|running|completed|partial|failed|skipped
    #   started_at, completed_at
    #   tools_attempted, tools_succeeded, tools_failed, tools_skipped
    #   evidence_ids, evidence_persisted, parser_result
    #   exit_criteria_met, can_advance
    #   validation_result: {status, reason, can_advance}
    #   retry_count, skip_reason
    #   mcp_status: available|unavailable|not_attempted
    #   mcp_failures: [{tool, error, ts}]
    #   skill_context: {skill_id, technique, evidence_required}
    #   tool_execution_log: [{tool, status, exit_code, evidence_id, ts, mcp_used}]
    #   learning_feedback: {payloads_effective, tool_errors, next_phase_recommendations}
    # }
