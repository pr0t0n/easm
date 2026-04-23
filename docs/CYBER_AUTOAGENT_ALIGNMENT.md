# Cyber-AutoAgent Alignment (Prompt, Arquitetura, Ferramentas, Modelo, Validacao, Docker)

Este documento registra o alinhamento aplicado na plataforma EASM com os principios do repositório Cyber-AutoAgent.

## 1) Prompt (Execution Contract)

Foi incorporado um contrato de prompt metacognitivo e evidence-first com:

- GOAL-FIRST
- KNOW -> THINK -> TEST -> VALIDATE
- confianca numerica por decisao
- Proof Pack obrigatorio para achados criticos/altos
- checkpoints em 20/40/60/80 do budget
- encerramento somente por objetivo+evidencia ou budget esgotado

Implementacao:

- backend/app/services/cyber_autoagent_alignment.py
- backend/app/graph/workflow.py (strategic_planning_node + analyst_framework.prompt_contract)

## 2) Arquitetura

A arquitetura operacional permanece supervisor-centric com roteamento dinamico de capacidades e loop metacognitivo.

Capacidades no loop:

- strategic_planning
- asset_discovery
- threat_intel
- adversarial_hypothesis
- risk_assessment
- evidence_adjudication
- governance
- executive_analyst

Implementacao:

- backend/app/graph/workflow.py
- backend/app/api/routes_management.py (validacao de trilha senior vs legacy)

## 3) Ferramentas

Foi adicionado um catalogo conceitual alinhado ao Cyber-AutoAgent para guiar evolucao de capacidades sem quebrar o comportamento atual de filas.

Catalogo:

- core_orchestration
- native_execution
- memory_and_reflection
- meta_tooling
- supported_scan_tools

Implementacao:

- backend/app/workers/worker_groups.py (CYBER_AUTOAGENT_TOOL_CATALOG)

## 4) Modelo

Foi padronizada configuracao de provider/model principal e modelo de avaliacao:

- LLM_PRIMARY_PROVIDER
- LLM_PRIMARY_MODEL
- LLM_EVALUATION_MODEL

Implementacao:

- backend/app/core/config.py
- .env.example
- backend/app/services/llm_risk_service.py (telemetria de provider/model/evaluation_model)

## 5) Validacao

Foi incorporado avaliador de execucao com rubrica:

- methodology
- tooling
- evidence
- outcome

Saida persiste em state_data.agent_validation e loga score final.

Implementacao:

- backend/app/services/cyber_autoagent_alignment.py (evaluate_execution_quality)
- backend/app/workers/tasks.py

Script de verificacao de aderencia:

```bash
python scripts/validate_cyber_autoagent_alignment.py
```

## 6) Docker e Imagem

Fluxo operacional para validar stack, validar imagem e publicar:

```bash
./scripts/validate_docker_and_image.sh easm-backend:cyber-autoagent

REGISTRY=ghcr.io/pr0t0n \
IMAGE_REPO=easm/backend \
IMAGE_TAG=cyber-autoagent-vision \
./scripts/build_and_publish_image.sh
```

Observacoes:

- O publish depende de login no registry (`docker login`).
- A validacao de imagem executa smoke test de import do backend no container.
