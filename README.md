# VALID ASM - vASM (LangGraph + FastAPI + React)

VALID ASM - vASM e uma plataforma de External Attack Surface Management (EASM) orientada a operacao defensiva.
Ela centraliza descoberta, triagem e monitoramento continuo do ambiente externo com controle de compliance e auditoria.

## Aviso de seguranca

Este projeto foi estruturado para **uso defensivo e autorizado**. Toda execucao depende de autorizacao valida de escopo e policy/allowlist ativa.

## Arquitetura

- Backend: FastAPI
- Orquestracao de tarefas: Celery + Redis
- Banco relacional e persistencia principal: PostgreSQL
- Grafo de agentes: LangGraph StateGraph
- IA local: Ollama (modelo configuravel via `.env`)
- Memoria vetorial de falsos positivos: ChromaDB
- Frontend: React + Tailwind + Vite

## O que a aplicacao faz

- Gerencia scans de superficie externa com orquestracao por LangGraph.
- Executa workers separados por grupo funcional (recon, fuzzing, vuln, code_js, api).
- Exige autorizacao formal por escopo de scan (singular ou agendado) antes da execucao.
- Registra trilha de auditoria de ponta a ponta (criacao, gate, execucao, falhas, aprovacoes).
- Entrega dashboard, relatorios e status de execucao com progresso e retestes.

## Fluxo da aplicacao

1. Admin define um SCAN singular ou um agendamento de SCAN em grupo.
2. Admin clica em Autorizar, informando prova de ownership e escopo do SCAN; o sistema gera um authorization_code unico.
3. O authorization_code e aprovado no fluxo de compliance e vinculado ao SCAN/agendamento.
4. No momento de iniciar, a execucao valida: authorization_code + validade da aprovacao + policy/allowlist do cliente.
5. Se o gate passar, o worker manager inicia a missao de 100 itens no LangGraph:
	- cada etapa da missao define o objetivo operacional;
	- cada nodo do grafo segue instrucoes e decide o proximo nodo via estado global;
	- as ferramentas sao delegadas para grupos de workers (recon, fuzzing, vuln, code_js, api) conforme prioridade.
6. O ScanNode registra portas descobertas e cria retestes automaticos antes de avancar no fluxo.
7. Logs sao transmitidos por WebSocket em tempo real e persistidos no banco.
8. O estado do grafo e salvo via checkpointer PostgreSQL para continuidade apos reinicio.
9. Resultados ficam disponiveis em Relatorios e indicadores no Dashboard.

## Perfis e permissoes

- Administrador:
	- pode autorizar e executar scans;
	- pode acessar Dashboard, Relatorios, Agendamento, Scan, Configuracao e Gestao de Usuarios;
	- pode aprovar/revogar autorizacoes e consultar auditoria.
- Usuario:
	- acesso apenas a Dashboard e Relatorios;
	- nao pode executar scan, agendar ou alterar configuracoes.

Modelo de execucao dos agentes:

- O LangGraph decide o proximo passo no grafo.
- Cada categoria de ferramenta e delegada para um worker especializado.
- Antes da execucao, o scan passa por gate de compliance com autorizacao formal por escopo de scan (singular ou agendado).
- Todos os eventos criticos sao registrados em trilha de auditoria.

## Missao e Instrucoes Operacionais

- A missao contem 100 itens ordenados em [backend/app/graph/mission.py](backend/app/graph/mission.py).
- O estado da execucao (AgentState) carrega contexto, progresso, ativos, vulnerabilidades e metrica de interacao.
- Cada nodo opera com instrucoes especificas:
	- ReconNode: descoberta e enriquecimento de ativos.
	- ScanNode: validacao de servicos, descoberta de portas e retestes.
	- FuzzingNode: exploracao de superficie web e descoberta lateral.
	- VulnNode: correlacao tecnica de achados.
	- AnalistaIANode: triagem e priorizacao de risco.
- A decisao de roteamento e ciclica e contextual, com retorno para scans profundos quando necessario.

## Worker Groups, Prioridades e Crescimento Lateral

- Worker groups definidos com filas e funcoes em [backend/app/workers/worker_groups.py](backend/app/workers/worker_groups.py).
- Prioridade operacional editavel no Worker Manager via `position` em OperationLine.
- Indicadores de interacao disponiveis no endpoint de overview:
	- tempo medio e maximo por nodo;
	- contagem de transicoes entre nodos;
	- media de crescimento lateral por scan;
	- media de portas descobertas.

## Policy e Allowlist por Cliente

- Cada cliente possui policy default com allowlist de alvos.
- O gate de policy valida padrao de alvo e grupo de ferramenta antes da execucao.
- Endpoints dedicados:
	- `GET /api/policy/allowlist`
	- `POST /api/policy/allowlist`
	- `PUT /api/policy/allowlist/{entry_id}`
	- `DELETE /api/policy/allowlist/{entry_id}`

## Regras de Autorizacao

- Sem authorization_code aprovado, o scan nao executa de forma alguma.
- A autorizacao e por SCAN singular ou por agendamento de SCAN em grupo.
- Em agendamento, a autorizacao e realizada uma vez para o escopo configurado e reutilizada nas execucoes subsequentes enquanto valida.

## Checkpointing e Continuidade

- Checkpointer primario: PostgreSQL (`langgraph-checkpoint-postgres`).
- Fallback de desenvolvimento: MemorySaver.
- O estado permite retomada de scans apos restart do backend/worker.

## Streaming de Logs

- Endpoint WebSocket: `GET ws://<host>/ws/scans/{scan_id}/logs?token=<jwt>`
- O frontend recebe eventos incrementais de log sem polling.

## Persistencia de Vulnerabilidades e IA

- Cada worker/nodo grava achados no banco na tabela `findings` com `source_worker` em `details`.
- Dashboard e Relatorios usam exclusivamente dados persistidos no banco.
- A IA Ollama (Qwen e CloudCode) gera recomendacoes em portugues e salva no `details` de cada finding:
	- `qwen_recomendacao_pt`
	- `cloudcode_recomendacao_pt`

Prompt operacional aplicado para recomendacoes:

"Voce e um analista senior de ciberseguranca. Responda SOMENTE em portugues do Brasil e em JSON valido. Objetivo: recomendar mitigacoes praticas para vulnerabilidades encontradas no EASM. Formato JSON obrigatorio: {\"resumo\":\"...\",\"impacto\":\"...\",\"mitigacoes\":[\"...\"],\"prioridade\":\"baixa|media|alta|critica\",\"validacoes\":[\"...\"]}."

## Auto Aprendizado no LangGraph

- Antes de cada execucao, o worker carrega vulnerabilidades conhecidas do banco e injeta no estado do grafo.
- O nodo de vulnerabilidade aumenta prioridade/risk_score quando encontra padrao ja conhecido.
- Esse ciclo melhora priorizacao e triagem a cada nova execucao.

Servicos no Docker Compose:

- `postgres`
- `redis`
- `ollama`
- `backend`
- `worker_unit`
- `worker_scheduled`
- `frontend`

## Backlog Solicitado (Concluido)

Itens solicitados e status atual no repositorio:

- Backend FastAPI base: concluido.
	- API principal em [backend/app/main.py](backend/app/main.py)
	- Rotas em [backend/app/api/routes_auth.py](backend/app/api/routes_auth.py), [backend/app/api/routes_scans.py](backend/app/api/routes_scans.py), [backend/app/api/routes_management.py](backend/app/api/routes_management.py)
- LangGraph com estado persistente: concluido.
	- Grafo em [backend/app/graph/workflow.py](backend/app/graph/workflow.py)
	- Checkpointer Postgres + fallback em [backend/app/graph/checkpointer.py](backend/app/graph/checkpointer.py)
- Celery e workers: concluido.
	- App Celery em [backend/app/workers/celery_app.py](backend/app/workers/celery_app.py)
	- Tasks/filas em [backend/app/workers/tasks.py](backend/app/workers/tasks.py)
	- Mapeamento de grupos em [backend/app/workers/worker_groups.py](backend/app/workers/worker_groups.py)
	- Servicos docker separados em [docker-compose.yml](docker-compose.yml)
- Frontend React: concluido.
	- App em [frontend/src/App.jsx](frontend/src/App.jsx)
	- Paginas em [frontend/src/pages](frontend/src/pages)
	- Cliente API em [frontend/src/api/client.js](frontend/src/api/client.js)
- Documentacao de execucao: concluido e atualizado neste README.

## Execucao Rapida (Stack Completa)

1. Preparar ambiente:

```bash
cp .env.example .env
```

2. Subir backend + workers + frontend:

```bash
docker compose up --build
```

### Com perfis de ambiente

Desenvolvimento:

```bash
docker compose --profile dev up --build
```

Producao:

```bash
docker compose --profile prod up --build -d
```

3. Validar servicos:

- API Health: `http://localhost:8000/health`
- Frontend: `http://localhost:5173`

## Execucao de Validacao E2E

Script de validacao de fluxo completo:

```bash
python scripts/validate_e2e_flow.py
```

Arquivo: [scripts/validate_e2e_flow.py](scripts/validate_e2e_flow.py)

Runbook operacional (incidente, restart seguro e rollback):

- [docs/RUNBOOK.md](docs/RUNBOOK.md)

## Grafo LangGraph

Estado global (`AgentState`) com:

- `lista_ativos`
- `logs_terminais`
- `vulnerabilidades_encontradas`
- `proxima_ferramenta`
- `mission_index`
- `mission_items`

Nos:

- `ReconNode`
- `ScanNode`
- `FuzzingNode`
- `VulnNode`
- `AnalistaIANode`

Fluxo ciclico:

- O `FuzzingNode` pode sinalizar novo ativo e redirecionar para `ScanNode`.
- O roteamento e feito por decisao condicional ate concluir os 100 itens da missao.
- Quando o `ScanNode` encontra novas portas, o grafo agenda retestes automaticamente antes de seguir.

## Missao de 100 itens

A lista completa foi carregada em [backend/app/graph/mission.py](backend/app/graph/mission.py).

## Funcionalidades Web

- Login e registro com JWT persistido no navegador
- Criacao de scan unitario e modo agendado
- Terminal de logs com reconexao por leitura da tabela `scan_logs`
- Consulta de relatorios por scan
- Marcacao de falso positivo com ingestao no ChromaDB
- Dashboard de evolucao com visao ISO 27001, NIST, CIS v8 e PCI
- Menu lateral com: Dashboard, Agendamento, Configuracao e Scan
- Configuracao com status da IA local (Ollama), modelos disponiveis e erros recentes
- Flags de runtime por usuario para `debug_mode`, `verbose_mode` e retry automatico de scans
- Configuracao de workers na UI: stale timeout, cutoff de orfaos e limite de requeue
- Status de scan com metadados de retry (tentativa atual, maximo, proxima tentativa e ultimo erro)

## Estrutura Principal

- [docker-compose.yml](docker-compose.yml)
- [backend/app/main.py](backend/app/main.py)
- [backend/app/graph/workflow.py](backend/app/graph/workflow.py)
- [backend/app/workers/tasks.py](backend/app/workers/tasks.py)
- [frontend/src/App.jsx](frontend/src/App.jsx)

## Como executar

1. Copie o arquivo de ambiente:

```bash
cp .env.example .env
```

2. Suba todos os servicos:

```bash
docker compose up --build
```

3. Acesse:

- Frontend: `http://localhost:5173`
- Backend: `http://localhost:8000`
- Healthcheck: `http://localhost:8000/health`

## Endpoints principais

- `POST /api/auth/register`
- `POST /api/auth/login`
- `POST /api/scans`
- `GET /api/scans`
- `GET /api/scans/{scan_id}/logs`
- `GET /api/scans/{scan_id}/report`
- `POST /api/findings/{finding_id}/false-positive`
- `GET /api/dashboard`
- `GET /api/scans/{scan_id}/status`
- `POST /api/compliance/authorizations/request`
- `GET /api/compliance/authorizations`
- `PUT /api/compliance/authorizations/{authorization_id}/approve`
- `PUT /api/compliance/authorizations/{authorization_id}/revoke`
- `GET /api/audit/events`
- `GET /api/worker-manager/overview`
- `GET /api/worker-manager/health`
- `POST /api/worker-manager/requeue-orphans`
- `GET /api/config/runtime`
- `PUT /api/config/runtime`
- `GET /api/policy/allowlist`
- `POST /api/policy/allowlist`
- `PUT /api/policy/allowlist/{entry_id}`
- `DELETE /api/policy/allowlist/{entry_id}`
- `POST /api/schedules/{schedule_id}/execute`

## Status de implementacao

- Checkpointer PostgreSQL para LangGraph: implementado (com fallback local).
- Policy/allowlist por cliente: implementado.
- WebSocket para streaming de logs: implementado.
- Migrations Alembic versionadas: implementado.

## Validacao do fluxo completo (alvo ate relatorio)

Fluxo validado na aplicacao:

1. Solicitar autorizacao de escopo (`/api/compliance/authorizations/request`).
2. Aprovar autorizacao (`/api/compliance/authorizations/{id}/approve`).
3. Criar scan singular (`/api/scans`) ou agendamento (`/api/schedules`) com `authorization_code`.
4. Executar agendamento sob demanda, quando aplicavel (`/api/schedules/{schedule_id}/execute`).
5. Acompanhar execucao (`/api/scans/{scan_id}/status` e WebSocket de logs).
6. Consultar relatorio final no banco (`/api/scans/{scan_id}/report`).

Observacao de ambiente: quando a fila Celery estiver indisponivel, a API aplica fallback de execucao imediata para nao interromper o fluxo operacional.

Script automatizado de validacao:

- [scripts/validate_e2e_flow.py](scripts/validate_e2e_flow.py)
- Executa login admin, autorizacao, aprovacao, criacao de scan, polling de status e validacao do relatorio final.