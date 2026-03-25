"""
Task Broker / Workflow Orchestrator - gerencia dependências entre agentes EASM.

Workflow:
1. Asset Discovery finaliza
   ↓ (dispara apenas em assets novos/alterados)
2. Risk Assessment executa
   ↓ (dispara sumarização de riscos)
3. Governance node calcula FAIR+AGE
   ↓
4. Executive Analyst gera narrativa
   ↓
5. Temporal tracking registra histórico
   ↓
6. Check for alerts & webhooks

Alternativa: Prefect/Dagster para complexidade futura.
Atual: LangGraph + custom dependency logic.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from enum import Enum
import asyncio
import logging

from sqlalchemy.orm import Session

from app.models.models import Asset, ScanJob, Vulnerability, AssetRatingHistory, EASMAlert
from app.db.session import SessionLocal
from app.core.config import settings


logger = logging.getLogger(__name__)


class WorkflowPhase(str, Enum):
    """Pipeline phases"""
    ASSET_DISCOVERY = "asset_discovery"
    RISK_ASSESSMENT = "risk_assessment"
    THREAT_INTEL = "threat_intel"
    GOVERNANCE = "governance"
    EXECUTIVE_ANALYST = "executive_analyst"
    TEMPORAL_TRACKING = "temporal_tracking"
    ALERT_CHECK = "alert_check"


class DependencyNode:
    """Nó de dependência no workflow"""

    def __init__(
        self,
        phase: WorkflowPhase,
        depends_on: Optional[List[WorkflowPhase]] = None,
        condition_fn: Optional[callable] = None,
    ):
        self.phase = phase
        self.depends_on = depends_on or []
        self.condition_fn = condition_fn or (lambda state: True)  # default: sempre executa

    async def execute(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """Executa o nó e retorna estado atualizado"""
        logger.info(f"[Workflow] Executando fase: {self.phase}")
        return state


class WorkflowOrchestrator:
    """Orquestra execução sequencial de fases com dependências"""

    def __init__(self):
        self.nodes: Dict[WorkflowPhase, DependencyNode] = {}
        self._register_default_pipeline()

    def _register_default_pipeline(self):
        """Registra pipeline padrão EASM"""
        
        # Asset Discovery - entrada do workflow
        self.register_node(
            DependencyNode(
                WorkflowPhase.ASSET_DISCOVERY,
                depends_on=[],
                condition_fn=lambda state: state.get("target_query") is not None,
            )
        )

        # Risk Assessment - executa apenas se novos assets descobertos
        self.register_node(
            DependencyNode(
                WorkflowPhase.RISK_ASSESSMENT,
                depends_on=[WorkflowPhase.ASSET_DISCOVERY],
                condition_fn=lambda state: len(state.get("asset_fingerprints", {})) > 0,
            )
        )

        # Threat Intel - executa em paralelo com Risk Assessment, mas depende de Asset Discovery
        self.register_node(
            DependencyNode(
                WorkflowPhase.THREAT_INTEL,
                depends_on=[WorkflowPhase.ASSET_DISCOVERY],
            )
        )

        # Governance - depende de Risk Assessment + Threat Intel
        self.register_node(
            DependencyNode(
                WorkflowPhase.GOVERNANCE,
                depends_on=[WorkflowPhase.RISK_ASSESSMENT, WorkflowPhase.THREAT_INTEL],
                condition_fn=lambda state: len(state.get("findings", [])) > 0,
            )
        )

        # Executive Analyst - depende de Governance
        self.register_node(
            DependencyNode(
                WorkflowPhase.EXECUTIVE_ANALYST,
                depends_on=[WorkflowPhase.GOVERNANCE],
            )
        )

        # Temporal Tracking - registra histórico (executa sempre ao final)
        self.register_node(
            DependencyNode(
                WorkflowPhase.TEMPORAL_TRACKING,
                depends_on=[WorkflowPhase.EXECUTIVE_ANALYST],
            )
        )

        # Alert Check - verifica gatilhos (executa sempre ao final)
        self.register_node(
            DependencyNode(
                WorkflowPhase.ALERT_CHECK,
                depends_on=[WorkflowPhase.TEMPORAL_TRACKING],
            )
        )

    def register_node(self, node: DependencyNode):
        """Registra um nó no workflow"""
        self.nodes[node.phase] = node
        logger.debug(f"[Workflow] Nó registrado: {node.phase}")

    def validate_dependencies(self) -> bool:
        """Valida se há ciclos ou dependências não resolveáveis"""
        visited = set()
        rec_stack = set()

        def has_cycle(phase: WorkflowPhase) -> bool:
            visited.add(phase)
            rec_stack.add(phase)

            node = self.nodes.get(phase)
            if not node:
                return False

            for dep in node.depends_on:
                if dep not in visited:
                    if has_cycle(dep):
                        return True
                elif dep in rec_stack:
                    return True

            rec_stack.remove(phase)
            return False

        for phase in self.nodes:
            if phase not in visited:
                if has_cycle(phase):
                    logger.error(f"[Workflow] Ciclo detectado em dependências: {phase}")
                    return False

        return True

    def get_execution_order(self) -> List[WorkflowPhase]:
        """Retorna ordem topológica de execução (respeitando dependências)"""
        visited = set()
        order = []

        def topo_sort(phase: WorkflowPhase):
            if phase in visited:
                return
            visited.add(phase)

            node = self.nodes.get(phase)
            if node:
                for dep in node.depends_on:
                    topo_sort(dep)

            order.append(phase)

        for phase in self.nodes:
            topo_sort(phase)

        return order

    async def execute_pipeline(self, job_id: int, state: Dict[str, Any]) -> Dict[str, Any]:
        """
        Executa pipeline completo respeitando dependências

        Args:
            job_id: ID do ScanJob
            state: Estado inicial do workflow (state_data)

        Returns:
            Estado final com todos os resultados
        """
        logger.info(f"[Workflow {job_id}] Iniciando pipeline EASM")

        if not self.validate_dependencies():
            logger.error(f"[Workflow {job_id}] Validação de dependências falhou")
            raise ValueError("Dependências inválidas no workflow")

        execution_order = self.get_execution_order()
        logger.info(f"[Workflow {job_id}] Ordem de execução: {execution_order}")

        for phase in execution_order:
            node = self.nodes.get(phase)
            if not node:
                continue

            # Check se dependências estão completas
            if not all(
                state.get(f"completed_{dep.value}", False)
                for dep in node.depends_on
            ):
                logger.debug(f"[Workflow {job_id}] Dependências não completadas, pulando: {phase}")
                continue

            # Check condição de execução
            if not node.condition_fn(state):
                logger.debug(f"[Workflow {job_id}] Condição não atendida, pulando: {phase}")
                state[f"completed_{phase.value}"] = True
                continue

            # Executa nó
            try:
                state = await node.execute(state)
                state[f"completed_{phase.value}"] = True
                logger.info(f"[Workflow {job_id}] ✓ Fase completada: {phase}")
            except Exception as e:
                logger.error(f"[Workflow {job_id}] ✗ Erro em {phase}: {e}")
                state[f"error_{phase.value}"] = str(e)
                # Decide se continua ou falha
                if phase in {WorkflowPhase.GOVERNANCE, WorkflowPhase.EXECUTIVE_ANALYST}:
                    raise  # Fases críticas falham
                # Else: continua com fases subsequentes

        logger.info(f"[Workflow {job_id}] Pipeline completo")
        return state


class TemporalTracker:
    """Registra histórico temporal de ratings EASM por asset"""

    @staticmethod
    def record_asset_snapshot(
        db: Session,
        asset_id: int,
        scan_id: Optional[int],
        easm_rating: float,
        easm_grade: str,
        open_counts: Dict[str, int],  # {critical: 2, high: 5, ...}
        pillar_scores: Dict[str, float],
        remediated_count: int,
    ) -> AssetRatingHistory:
        """
        Registra snapshot temporal de um asset

        Args:
            asset_id: ID do asset
            scan_id: ID do scan que gerou o rating
            easm_rating: Score 0-100
            easm_grade: A-F
            open_counts: contagem por severidade
            pillar_scores: scores dos pillares FAIR
            remediated_count: quantas falhas foram remediadas neste período

        Returns:
            AssetRatingHistory registrado
        """
        history = AssetRatingHistory(
            asset_id=asset_id,
            scan_id=scan_id,
            easm_rating=easm_rating,
            easm_grade=easm_grade,
            open_critical_count=open_counts.get("critical", 0),
            open_high_count=open_counts.get("high", 0),
            open_medium_count=open_counts.get("medium", 0),
            remediated_this_period=remediated_count,
            pillar_scores=pillar_scores,
            recorded_at=datetime.now(timezone.utc),
        )
        db.add(history)
        db.flush()
        return history

    @staticmethod
    def get_rating_history(
        db: Session,
        asset_id: int,
        days: int = 30,
    ) -> List[AssetRatingHistory]:
        """Recupera histórico de ratings do asset nos últimos N dias"""
        from datetime import timedelta
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        return (
            db.query(AssetRatingHistory)
            .filter(
                AssetRatingHistory.asset_id == asset_id,
                AssetRatingHistory.recorded_at >= cutoff,
            )
            .order_by(AssetRatingHistory.recorded_at)
            .all()
        )


# Global orchestrator instance
_orchestrator = None


def get_orchestrator() -> WorkflowOrchestrator:
    """Singleton accessor para orchestrator"""
    global _orchestrator
    if _orchestrator is None:
        _orchestrator = WorkflowOrchestrator()
    return _orchestrator
