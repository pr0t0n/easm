"""Best-of platform capability blueprint.

This module turns the external platform analysis into an executable product
contract: what we borrow from each reference, what ScriptKidd.o already has,
what is missing, and which acceptance gates make the capability real.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class CapabilityBlueprint:
    id: str
    name: str
    product_goal: str
    inspired_by: tuple[str, ...]
    execution_pattern: str
    current_anchors: tuple[str, ...]
    next_steps: tuple[str, ...]
    acceptance_gates: tuple[str, ...]
    status: str
    priority: int
    category: str
    operator_visibility: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "product_goal": self.product_goal,
            "inspired_by": list(self.inspired_by),
            "execution_pattern": self.execution_pattern,
            "current_anchors": list(self.current_anchors),
            "next_steps": list(self.next_steps),
            "acceptance_gates": list(self.acceptance_gates),
            "status": self.status,
            "priority": self.priority,
            "category": self.category,
            "operator_visibility": list(self.operator_visibility),
        }


CAPABILITY_BLUEPRINTS: tuple[CapabilityBlueprint, ...] = (
    CapabilityBlueprint(
        id="objective-driven-autonomy",
        name="Autonomia por objetivo",
        category="agent_execution",
        priority=1,
        status="partial",
        inspired_by=("PentAGI", "Pentest Swarm AI", "NetworkAttackSimulator"),
        product_goal=(
            "Executar pentest automatizado por objetivos mensuraveis, nao apenas "
            "por lista fixa de fases."
        ),
        execution_pattern=(
            "Supervisor define objetivo, agentes especialistas escolhem skills, "
            "evidence gate decide se a missao avancou, bloqueou ou precisa de reteste."
        ),
        current_anchors=(
            "backend/app/graph/nodes/supervisor.py",
            "backend/app/graph/mission.py",
            "backend/app/services/offensive_operator_runner.py",
            "backend/app/services/orchestration_contract_service.py",
        ),
        next_steps=(
            "Persistir MissionObjective com sucesso esperado, budget, risco e criterio de parada.",
            "Gerar score de autonomia por objetivo: atingido, bloqueado, falso positivo, custo e tempo.",
            "Exibir no Centro Operacional a fila de objetivos ativos e o motivo da proxima acao.",
        ),
        acceptance_gates=(
            "Todo objetivo precisa de criterio de sucesso e criterio de parada.",
            "Nenhum objetivo pode disparar ferramenta fora do escopo autorizado.",
            "Objetivo critico so fecha como sucesso com proof pack confirmado.",
        ),
        operator_visibility=("Centro Operacional", "Agent Flow", "Relatorio de Pentest"),
    ),
    CapabilityBlueprint(
        id="specialist-agent-swarm",
        name="Agentes especialistas",
        category="agent_execution",
        priority=2,
        status="partial",
        inspired_by=("Pentest Swarm AI", "pentest-ai-agents", "Pentest Copilot"),
        product_goal=(
            "Tornar explicitos os papeis ja existentes: escopo, recon, API, auth, "
            "validacao, evidencia, relatorio e seguranca de IA."
        ),
        execution_pattern=(
            "Cada agente possui contrato de entrada, ferramentas permitidas, evidencias "
            "esperadas e pergunta de retorno ao supervisor."
        ),
        current_anchors=(
            "backend/app/workers/worker_groups.py",
            "backend/app/api/routes_agent_flow.py",
            "frontend/src/pages/OperationsCenterPage.jsx",
            "frontend/src/pages/AgentFlowPage.jsx",
        ),
        next_steps=(
            "Mapear workers/capabilities para papeis visiveis de agente.",
            "Adicionar trilha 'demanda -> decisao -> execucao -> evidencia -> avaliacao'.",
            "Criar health por agente: disponibilidade, filas, falhas e cobertura.",
        ),
        acceptance_gates=(
            "Toda acao de agente precisa de owner/capability visivel.",
            "Supervisor deve registrar por que aprovou, rejeitou ou replanejou.",
            "Falha de agente deve criar backlog acionavel, nao sumir em logs brutos.",
        ),
        operator_visibility=("Agent Flow", "Centro Operacional", "Workers"),
    ),
    CapabilityBlueprint(
        id="safe-tool-adapter-layer",
        name="Adapter seguro de ferramentas",
        category="tooling",
        priority=3,
        status="partial",
        inspired_by=("HexStrike AI", "kali_mcp", "Burp MCP Toolkit", "trivy-mcp", "semgrep-mcp"),
        product_goal=(
            "Absorver o melhor do ecossistema MCP e CLI sem virar um wrapper livre "
            "de ferramentas ofensivas."
        ),
        execution_pattern=(
            "Ferramenta externa entra por schema tipado, classificacao de risco, "
            "guardrail, escopo, dry-run, parser esperado e contrato de evidencia."
        ),
        current_anchors=(
            "backend/app/services/kali_executor.py",
            "backend/app/services/tool_catalog.py",
            "backend/app/services/tool_health_service.py",
            "mcp-server/mcp_server.py",
            "kali-runner/runner.py",
        ),
        next_steps=(
            "Criar registro de adapters com schema, risco, parser, timeout e proof pack esperado.",
            "Permitir importar MCP externo apenas em modo allowlisted e auditado.",
            "Adicionar score por ferramenta: disponibilidade, taxa de erro, qualidade de evidencia.",
        ),
        acceptance_gates=(
            "Toda ferramenta precisa de perfil, parser/fallback e guardrail.",
            "Argumentos perigosos devem ser sanitizados antes da execucao.",
            "Tool call deve persistir comando normalizado, saida resumida e workspace_path.",
        ),
        operator_visibility=("Tool Health", "Guardrails", "Centro Operacional"),
    ),
    CapabilityBlueprint(
        id="ai-rag-agent-security",
        name="Pentest de IA, RAG e agentes",
        category="ai_security",
        priority=4,
        status="emerging",
        inspired_by=("promptfoo", "garak", "PyRIT", "AI-Infra-Guard", "Rebuff", "GhostPrompt"),
        product_goal=(
            "Tratar aplicacoes de IA como superficie de pentest: prompts, RAG, "
            "ferramentas, MCP, documentos e agentes."
        ),
        execution_pattern=(
            "Suite de probes, detectores e juizes separados; respostas do alvo sempre "
            "quarentenadas antes de alimentar qualquer LLM avaliador."
        ),
        current_anchors=(
            "backend/app/services/llm_risk_service.py",
            "backend/app/services/untrusted_content.py",
            "backend/app/services/benchmark_registry.py",
        ),
        next_steps=(
            "Adicionar suites versionadas para prompt injection, jailbreak, RAG poisoning e tool abuse.",
            "Persistir canary leak, transcript, detector_result e risk_label como EvidenceArtifact.",
            "Expor AI Security Score por alvo e por release de prompt/modelo.",
        ),
        acceptance_gates=(
            "Probes e detectores devem ser separados.",
            "Conteudo controlado pelo alvo nunca pode entrar em prompt sem envelope.",
            "Teste de IA precisa gerar transcript e decisao reproduzivel.",
        ),
        operator_visibility=("AI Security", "Benchmarks", "Relatorio de Pentest"),
    ),
    CapabilityBlueprint(
        id="benchmark-regression-center",
        name="Benchmark e regressao",
        category="quality",
        priority=5,
        status="partial",
        inspired_by=("vuln-bank", "AIGoat", "DVAIA", "DVMCP", "NetworkAttackSimulator"),
        product_goal=(
            "Medir se a autonomia melhorou de verdade: cobertura, falso positivo, "
            "falso negativo, proof pack, tempo e seguranca do agente."
        ),
        execution_pattern=(
            "Rodadas versionadas contra labs locais/simulados, com score comparavel por release."
        ),
        current_anchors=(
            "backend/app/services/benchmark_registry.py",
            "backend/app/services/benchmark_evaluator.py",
            "backend/tests/test_benchmark_registry.py",
            "backend/tests/test_benchmark_evaluator.py",
        ),
        next_steps=(
            "Persistir BenchmarkRun com versao do codigo, alvo, score e gates.",
            "Adicionar matriz expected findings vs found/confirmed/refuted.",
            "Bloquear claims de melhoria sem comparacao contra rodada anterior.",
        ),
        acceptance_gates=(
            "Benchmark externo so pode rodar em container local ou rede simulada.",
            "High/critical sem proof pack nao conta como sucesso.",
            "Score deve separar cobertura de fase, ferramenta, evidencia e boundary de agente.",
        ),
        operator_visibility=("Benchmarks", "Centro Operacional", "Release Readiness"),
    ),
    CapabilityBlueprint(
        id="dast-sast-evidence-fusion",
        name="Fusao DAST, SAST e evidencia",
        category="evidence",
        priority=6,
        status="partial",
        inspired_by=("llm-sast-scanner", "semgrep-mcp", "trivy-mcp", "codesucks-ai", "vulnfix"),
        product_goal=(
            "Conectar achado dinamico, rota/codigo, dependencia vulneravel, causa raiz "
            "e correcao recomendada."
        ),
        execution_pattern=(
            "DAST descobre e valida, SAST localiza a origem provavel, supply-chain "
            "enriquece CVE/dependencia, relatorio entrega correcao rastreavel."
        ),
        current_anchors=(
            "backend/app/services/code_analyzer.py",
            "backend/app/services/semgrep_local.py",
            "backend/app/services/supply_chain_analyzer.py",
            "backend/app/services/evidence_contract_service.py",
        ),
        next_steps=(
            "Criar correlacao finding -> endpoint -> arquivo/funcao -> pacote/CVE.",
            "Separar sugestao de correcao de patch automatico.",
            "Exigir evidencia dinamica antes de elevar severidade por inferencia de codigo.",
        ),
        acceptance_gates=(
            "CVE por versao sem prova fica como hypothesis.",
            "Patch sugerido precisa apontar causa raiz e risco residual.",
            "Relatorio deve diferenciar explorado, inferido e refutado.",
        ),
        operator_visibility=("Vulnerabilidades", "Relatorio de Pentest", "Learning"),
    ),
)


def list_capability_blueprints(*, category: str | None = None) -> list[dict[str, Any]]:
    records = list(CAPABILITY_BLUEPRINTS)
    if category:
        category_l = category.strip().lower()
        records = [item for item in records if item.category.lower() == category_l]
    return [item.to_dict() for item in sorted(records, key=lambda item: (item.priority, item.name.lower()))]


def capability_blueprint_summary() -> dict[str, Any]:
    records = list(CAPABILITY_BLUEPRINTS)
    by_status: dict[str, int] = {}
    by_category: dict[str, int] = {}
    for item in records:
        by_status[item.status] = by_status.get(item.status, 0) + 1
        by_category[item.category] = by_category.get(item.category, 0) + 1
    return {
        "total": len(records),
        "by_status": by_status,
        "by_category": by_category,
        "north_star": (
            "Pentest automatizado orientado por objetivos, executado por agentes "
            "especialistas, governado por escopo, validado por evidencia e medido "
            "por benchmarks."
        ),
        "implementation_order": [item.id for item in sorted(records, key=lambda item: item.priority)],
        "non_goal": "Nao competir por volume de wrappers; absorver capacidades com governanca e prova.",
    }
