---
name: EASM Architecture Status
description: Status da arquitetura do grafo, correções aplicadas e débitos pendentes
type: project
---

## Arquitetura correta (confirmada)

Fluxo ativo no grafo LangGraph:
```
rag_enrichment → supervisor → skill_selector → skill_planner → tool_selector → tool_executor → evidence_gate → supervisor (loop)
supervisor → governance → supervisor
supervisor → executive_analyst → supervisor → END
```

Fases como **capability labels** (não nós do grafo): `asset_discovery`, `threat_intel`, `risk_assessment`
- O supervisor roteia para elas via `skill_selector` (pending_capability_node)
- Ficam em `completed_capabilities` quando o `tool_executor` as marca como concluídas

## Correções aplicadas em 2026-05-11

1. **kill_chain.py NODE_TO_PHASE** — corrigido para mapear nós reais do grafo
   - Antes: `strategic_planning`, `adversarial_hypothesis`, `evidence_adjudication` (não existiam)
   - Depois: `supervisor`, `skill_selector`, `evidence_gate` (nós reais)
   - Capabilities `asset_discovery`, `threat_intel`, `risk_assessment` usam check via `completed_capabilities`

2. **Filtragem de subdomain expansion para target_type=site** — integrada ao pipeline ativo
   - Estava só nos nós mortos `asset_discovery_node` (que não estava no grafo)
   - Movida para `_candidate_tools_for_skill_bootstrap` no caminho ativo

3. **Remoção de código morto** — 210 linhas deletadas de workflow.py (5009 → 4799)
   - `asset_discovery_node`, `recon_node` — preparavam contexto mas não estavam no grafo
   - `risk_assessment_node`, `vuln_node` — idem
   - `threat_intel_node`, `osint_node` — idem
   - Lógica valiosa (site filtering, OSINT target validation) foi migrada para pipeline ativo

4. **test_skill_runtime_contract.py** — removidas importações e teste de código morto

## Débito técnico pendente

- **workflow.py ainda tem 4799 linhas** — maior problema estrutural, precisa ser dividido em sessão dedicada
  - `graph/state.py` — AgentState TypedDict (~70 campos, muitos de audit log)
  - `graph/nodes/skill_pipeline.py` — skill_selector, skill_planner, tool_selector, tool_executor, evidence_gate
  - `graph/nodes/reporting.py` — governance_node, executive_analyst_node
  - `graph/nodes/supervisor.py` — supervisor_node + routing helpers
  - `graph/workflow.py` — apenas build_graph() e initial_state()

- **AgentState com ~60 campos** — campos autonomy_* (notes/todos/actions/observations/errors) são audit log expostos pela API, não influenciam roteamento

- **Sistema de delegação** (delegated_tasks, delegation_log) — complexidade sem ROI claro; só ativa após ciclo completo

**Why:** O acúmulo de camadas veio de iterações rápidas sem refatoração estrutural entre elas.
**How to apply:** Ao adicionar funcionalidade nova, verificar primeiro se não existe código morto ou duplicação antes de adicionar mais.
