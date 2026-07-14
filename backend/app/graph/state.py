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
    capability_ledger: dict[str, Any]       # Registro explícito de capacidades exercidas
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
    operational_strategy: dict[str, Any]
    strategic_rag_context: list[dict[str, Any]]
    mcp_adapter_contracts: list[dict[str, Any]]
    agent_orchestration: dict[str, Any]
    llm_reasoning: list[dict[str, Any]]
    pentest_strategy: dict[str, Any]
    pending_pentest_tactic: dict[str, Any]
    pentest_tactics_completed: list[dict[str, Any]]
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
    # ── Goal-oriented execution (ponto #1) ───────────────────────────────────
    # crown_jewels: ativos de alto valor identificados durante recon
    # Estrutura: [{asset: str, asset_type: str, value: int, reason: str, domain: str}]
    crown_jewels: list[dict[str, Any]]
    # scan_objective: objetivo da operação derivado dos crown jewels
    # Estrutura: {primary_goal: str, target_assets: [str], priority_phases: [str],
    #              attack_hypothesis: str, replan_count: int, objective_met_at: str|None}
    scan_objective: dict[str, Any]
    # phase_priority_override: lista de phase_ids que devem ser executados ANTES da ordem padrão
    # Atualizado sempre que novos crown jewels são descobertos
    phase_priority_override: list[str]
