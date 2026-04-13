# Processo de Clean Code e Code Smell para fluxo de ferramentas

## Objetivo
Garantir que o fluxo de execucao de ferramentas (unit e scheduled) permaneça consistente, previsivel e auditavel sem regressao silenciosa.

## Fonte unica de verdade
- Arquivo: backend/app/workers/worker_groups.py
- Regra: a lista de ferramentas deve ser definida apenas em CANONICAL_GROUP_TOOLS.
- Regra: UNIT_WORKER_GROUPS e SCHEDULED_WORKER_GROUPS devem ser gerados por builder a partir dessa fonte canonica.
- Regra: divergencia entre modos deve ser apenas de prioridade/fila, nunca de ferramentas.

## Smells alvo (e acao)
- Smell: duplicacao de listas de ferramentas em multiplos arquivos.
  - Acao: consumir get_canonical_group_tools() onde for necessario.
- Smell: divergencia silenciosa entre unit e scheduled.
  - Acao: validacao em import (_validate_tool_parity) + testes em CI.
- Smell: aliases com conjunto diferente do grupo primario.
  - Acao: testes dedicados para recon/reconhecimento e vuln/analise_vulnerabilidade.
- Smell: alteracao ad-hoc de ferramenta sem impacto no fluxo.
  - Acao: toda alteracao deve atualizar CANONICAL_GROUP_TOOLS e passar testes de consistencia.

## Gate minimo de qualidade (PR)
1. Rodar testes de consistencia:
   - pytest backend/tests/test_worker_groups_consistency.py
2. Rodar validacao de fluxo real:
   - BACKEND_URL=http://localhost:8001 POLL_INTERVAL=5 ./scripts/test_langgraph_nodes.sh valid.com single
3. Confirmar evidencia de vulnerabilidade no report_v2:
   - campo vulnerability_analysis_evidence preenchido.

## Checklist de revisao (foco no fluxo)
- A ferramenta nova/removida esta em CANONICAL_GROUP_TOOLS?
- Unit e scheduled ficaram identicos em recon/osint/vuln?
- SAFE_TOOL_REGISTRY continua sincronizado via get_canonical_group_tools()?
- A ordem do recon faz sentido para a missao (amass antes de expansao DNS)?
- O script E2E comprovou execucao de vulnerabilidade no fluxo real?

## Politica de mudanca
- Qualquer mudanca em ferramentas deve ser small batch (1 PR) e conter:
  - ajuste de configuracao,
  - teste automatizado,
  - evidencia de execucao real.
- Nao aceitar mudanca que so valide binario/dependencia isolada sem pipeline fim-a-fim.
