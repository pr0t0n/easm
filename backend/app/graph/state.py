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
    # Phase walker / kill-chain / offensive runtime — DECLARADOS de propósito:
    # chaves ausentes no TypedDict eram descartadas no merge entre nós do grafo,
    # então o walker decidia sobre state que nunca chegava ao pipeline (scan #39:
    # fases travadas em P02, ledger vazio, kill-chain parado em RECONNAISSANCE).
    pentest_phase_index: int                    # Índice do walker P01→P22
    current_pentest_phase_id: str               # Fase técnica atual (P01..P22)
    phase_ledger: dict[str, Any]                # Ledger de evidências por fase
    last_routed_phase_id: str                   # Fase no último roteamento (anti-loop)
    kill_chain_stage: str                       # Estágio atual da Cyber Kill Chain
    current_activity_demand: dict[str, Any]     # Demanda de atividade p/ o agente
    noise_profile: str                          # Perfil de ruído da campanha
    campaign: dict[str, Any]                    # Estado da campanha ofensiva
    active_hypotheses: list[dict[str, Any]]     # Hipóteses adversariais ativas
    validated_chains: list[dict[str, Any]]      # Cadeias de exploit validadas
    offensive_priority_queue: list[dict[str, Any]]  # Fases promovidas por sinal ofensivo
    strategy_runtime_timeline: list[dict[str, Any]] # Eventos da estratégia operacional
    # Segundo passe — chaves top-level usadas pelo grafo mas ausentes do schema
    # (mesma classe de bug: silenciosamente descartadas entre nós).
    max_iterations: int                     # Orçamento de iterações do supervisor
    scan_profile: dict[str, Any]            # Perfil ativo (asm/full/aggressive/api)
    detected_tech_stack: list[str]          # Tags de stack detectadas (httpx/whatweb)
    tech_stack_signature: str               # Assinatura de stack p/ invalidação de skill
    authorization_gate: dict[str, Any]      # Resultado do gate de autorização
    auth_summary: dict[str, Any]            # Resumo de preparação de auth
    agent_report: dict[str, Any]            # Último relatório do agente ao supervisor
    attack_paths: list[dict[str, Any]]      # Caminhos de ataque correlacionados
    chaining_candidates: list[dict[str, Any]]  # Candidatos a cadeia de exploit
    completed_activity_types: list[str]     # Tipos de atividade já exercidos
    current_activity_log_id: Any            # ID do log de atividade corrente
    current_node: str                       # Nó corrente (métricas de fluxo)
    kill_chain_progress: dict[str, Any]     # Progresso da kill chain
    llm_reasoning_feedback: list[dict[str, Any]]  # Feedback do raciocínio LLM
    offensive_observations: list[Any]       # Observações ofensivas do workflow
    pending_skill_refresh: bool             # Skill stale p/ refresh de stack
    pentest_hypotheses: list[dict[str, Any]]     # Hipóteses do motor de hipóteses
    post_exploitation_queue: list[dict[str, Any]]  # Fila pós-exploração
    rag_enriched: bool                      # RAG de enriquecimento executado
    rag_patterns: list[Any]                 # Padrões recuperados via RAG
    recon_coverage: dict[str, Any]          # Cobertura de recon
    recon_coverage_gaps: list[Any]          # Gaps de cobertura de recon
    recon_graph: dict[str, Any]             # Grafo de recon (recomendações)
    recon_reanalyze_queue: list[Any]        # Itens de reanálise de recon
    recon_skill_recommendations: list[dict[str, Any]]  # Recomendações de skill de recon
    risk_targets_resolvable: list[str]      # Alvos de risco resolvíveis
    risk_targets_unresolved: list[str]      # Alvos de risco não resolvidos
    skill_library_context: dict[str, Any]   # Contexto da biblioteca de skills
    subdomain_coverage: dict[str, Any]      # Cobertura de subdomínios
    supervisor_evaluations: list[dict[str, Any]]  # Avaliações do supervisor
    loop_guard_runs_at_route: int                 # Contador de runs no último roteamento (anti-loop honesto)
    envelope_findings: list[dict[str, Any]]       # Achados brutos do envelope v1 (MCP), com cap
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
