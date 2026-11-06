# Plano — LangGraph como cérebro da plataforma

Data: 2026-11-04
Status: aprovado — decisões do sponsor registradas em §0

## 0. Decisões (2026-11-04)

1. **Perfil padrão = agressivo/profundo.** O scan `standard` deve ser profundo a ponto de, por exemplo, o sqlmap mapear tabelas do banco quando houver indício de SQLi (referência de profundidade, não exceção). Perfis menores (`quick`) existem para exceções, não como default.
2. **RAG no Kali como sidecar** no compose — não dentro da imagem do `kali_runner` (evita rebuild do container de ~55 GB e não afeta a plataforma). Sidecar compartilha a rede do compose e o volume de conhecimento.
3. **LLM de triagem = Ollama local** (sem licença Anthropic). Começar com o maior modelo viável em CPU (candidato `qwen2.5:7b-instruct`; cair para 3B se a latência inviabilizar o lote de 10k).
4. **Adoção gradual das fases, montadas como um pentest humano.** Núcleo inicial obrigatório (recon/escopo P01–P02 + qualificação), demais fases P entram por decisão do supervisor fundamentada em evidência (hipótese, stack, findings), com justificativa registrada no trace — não marcha fixa P01→P22.

## 1. Contexto e motivação

A plataforma hoje tem **dois motores de execução concorrentes**:

1. **LangGraph** (`backend/app/graph/`) — supervisor + capability nodes + pipeline de skills. Está **quebrado desde mai/2026**: `supervisor_node` usa `remaining` (linha 1717) sem definição no módulo (`NameError` garantido, introduzido no split do monólito `workflow.py`, commit `e1c3d65`). Como `settings.offensive_operator_enabled=True` (default, `core/config.py:129`), o LangGraph **nunca executa em produção** — o caminho real é `run_offensive_operator_scan`.
2. **Offensive operator** (`offensive_operator_runner.py`, 7.4k linhas) — fila de work items + contrato P01–P22. É o motor vivo, mas a profundidade é negociada por orçamento (`phase_task_budget=4`), gates de qualificação e esgotamento de fila — o que produz o comportamento observado: scans superficiais em alvos grandes, profundos mas incompletos em alvos com hipóteses fortes, e finalizações por `completed_with_gaps`/`blocked`.

Sintomas relatados: bloqueios, gargalos, ausência de padrão de teste, profundidade imprevisível.

Conclusão do diagnóstico: o problema não é falta de componentes — é **falta de um cérebro único com contrato determinístico de cobertura**, e de um laço de aprendizado que use o corpus de ~10k reports do HackerOne (hoje travado).

## 2. Visão de arquitetura-alvo

```
                    ┌─────────────────────────────────────────────┐
                    │            LangGraph (CÉREBRO)              │
                    │                                             │
                    │  supervisor ──► task planner                │
                    │       │            │ (tasks = unidades de    │
                    │       │            │  trabalho com contrato) │
                    │       ▼            ▼                        │
                    │  capability    P01..P22 como nodes/         │
                    │  nodes         subgraphs determinísticos    │
                    │       │            │                        │
                    │       └────► state checkpoint (Postgres)    │
                    └───────┬──────────────────────┬──────────────┘
                            │ decide O QUÊ         │ decide COMO/quando
                            ▼                      ▼
                    ┌──────────────┐      ┌───────────────────────────┐
                    │     MCP      │      │   Kali Runner (MÃOS)      │
                    │              │      │                           │
                    │ • normaliza  │─────►│ • RAG local (pgvector)    │
                    │   resultados │      │ • retrieve-and-operate:   │
                    │ • envelope   │      │   skill + learnings do    │
                    │   de evidência│     │   H1 injetados no job     │
                    │ • re-teste   │      │ • execução argv + evidência│
                    │   de validação│     │                           │
                    └──────────────┘      └───────────────────────────┘
```

Princípios:

- **LangGraph decide o quê** (tasks, ordem, profundidade, critério de pronto por fase). **MCP/Kali decidem como** (execução, normalização, velocidade).
- **Skill = contrato legível por máquina** (playbook: ferramentas, templates de args, evidência esperada, critério de aceite) — usada tanto pelo planner do LangGraph quanto pelo RAG do Kali.
- **RAG roda junto ao Kali**: antes de executar um job, o runner recupera o conhecimento operacional relevante (skill da fase + learnings H1 aceitos + casos semelhantes) e injeta no contexto do comando. O cérebro não precisa carregar 10k reports no prompt — ele aponta a fase/skill, o retrieve acontece na borda.
- **O corpus H1 deixa de depender de revisão humana serial**: triagem automática (dedup, família, confiança, safe-to-accept), aceite humano só para exceções e conteúdo de alto risco.

## 3. Diagnóstico detalhado (evidências)

### 3.1 Dois motores, um quebrado

- `tasks.py:2538` — `if settings.offensive_operator_enabled:` retorna antes do `app.invoke`. Default `True` (`core/config.py:129`).
- `supervisor.py:1717` — `remaining` indefinido (AST/bytecode confirmam: carga como global, zero stores no módulo). Herdado do split `e1c3d65` (mai/2026); no `workflow.py` original existia `remaining = int(ctrl.get("remaining_iterations", max_iterations))`.
- Exceção capturada em `tasks.py:3125` → scan `failed` com `last_error="name 'remaining' is not defined"` se o caminho LangGraph fosse usado.
- **Zero dos 206 arquivos de teste em `backend/tests/` importam `supervisor_node`** — o bug sobreviveu 6 meses porque a suíte cobre o operator, não o grafo.

### 3.2 Corpus H1 (~10k) subutilizado

- `scripts/crawl_github_hackerone_learnings.py` semeia até **10.000 registros `pending_review`** (cap padrão `DEFAULT_MAX_CREATED = 10_000`).
- Só `accepted` influencia agentes; aceite é manual, um a um ou em lote na tela — 10k não escala assim.
- Prompt do supervisor: `render_accepted_learning_for_prompt(limit=8)` — **top-8 por recência** (`accepted_at desc`), sem relevância semântica.
- Playbook de runtime: `build_runtime_learning_playbook(limit=12)` — pool de 80 mais recentes + boost de +20 por termo de tech-stack no texto. Ainda recency-pool: a maioria do corpus nunca entra na disputa.
- Busca semântica **existe** (`learning_semantic_index.semantic_search_learnings`, pgvector) mas só é chamada por `pentest_synthesis` e `tech_vuln_correlator` — lado de relatório, **fora do laço de execução**.

### 3.3 RAG hoje: corpus de skills, não de learnings

- `skill_rag_indexer.warm_skill_rag` indexa o corpus de skills (`skills/*.md`) no pgvector na inicialização.
- `rag_repository.query` é chamado via `mcp_client` por `skill_pipeline` (seleção de skill) e `pentest_strategy_service`.
- Learnings H1 moram em `vulnerability_learnings` (SQL + keyword), fora do store RAG — dois silos de conhecimento que não conversam.

### 3.4 MCP hoje: proxy puro

- `mcp_server.py` = resolve profile/alias + guardrail espelhado + proxy de jobs. **Sem normalização de resultados, sem protocolo de re-teste.**
- Normalização existe, mas dispersa no backend: `tool_parsers.py` (1.822 linhas de extratores regex por ferramenta) + `findings_extractor.py` (3.8k linhas) — longe do ponto de execução, reexecutada em cada consumidor.

### 3.5 Performance: gargalos identificados

- **Kali é chokepoint único**: `KALI_MAX_PARALLEL=16` (compose), semáforos por classe de recurso + AIMD, timeouts de profile até 900s. Orquestração inteira disputa esses 16 slots.
- **Polling**: resultados voltam por `worker_poll` (GET `/jobs/{id}` em loop). O runner já é FastAPI async — dá para empurrar resultado (callback/SSE) em vez de puxar.
- **DB chatty no grafo**: 12 `SessionLocal()` nos módulos do grafo; `render_accepted_learning_for_prompt` e `build_runtime_learning_playbook` abrem conexão **por iteração do supervisor**; `_sync_step_to_db` grava `ScanJob` a cada step. Em scan longo isso é milhares de transações de apoio.
- **Estado monolítico**: `AgentState` com dezenas de chaves, persistido em `ScanJob.state_data` (JSONB) — cresce sem bound, checkpoint carrega/grava tudo.
- **Threads em camadas**: `ThreadPoolExecutor(max_workers=6)` no grafo + workers Celery `--pool=threads` + fila paralela — concorrência real limitada pelo semáforo do Kali, mas overhead de scheduling e filas Redis em cada salto.

## 4. Plano por fases

### Fase 0 — Estabilização e fundação (1–2 semanas)

Objetivo: um motor só, executando, com contrato de cobertura visível.

1. **Corrigir o `NameError`** em `supervisor_node` (restaurar o cálculo de `remaining_iterations`) + **teste de fumaça** que invoca o nó uma vez (há cobertura zero).
2. **Feature flag único de engine**: `ENGINE=langgraph|operator` com default explícito e logado no início do scan (`scan_log`). Elimina a ambiguidade de qual cérebro rodou — hoje só quem lê o código sabe.
3. **Definition of done por fase** (`offensive_operator_core.PHASE_CONTRACTS`): `completed` exige todos `required_tools` executados (ou skip explícito com motivo); `min_attempted=1/min_succeeded=1` vira `ceil(|required| * 0.75)` ou configuração por fase. O Phase Monitor passa a mostrar o contrato vs. o executado lado a lado.
4. **Métricas de término**: `termination_reason` + fases completas vs. puladas **sempre** no relatório e no `Jobs Registry`. Sem isso, não há como medir as fases seguintes.

Entregável verificável: scan E2E no Juice Shop com engine=langgraph, relatório mostrando cobertura P01–P22 e motivo de término.

**Notas de implementação (2026-11-04, executado):**
- `remaining`/`ctrl`/`max_iterations` restaurados em `supervisor.py` (kill switch + guardrails) com tolerância a checkpoints legados (`remaining_iterations=None`); 6 smoke tests em `tests/test_supervisor_node_smoke.py`.
- Engine: `settings.scan_engine` (`operator`|`langgraph`) + override por scan via `state_data["scan_engine"]` (exposto em `ScanCreate.scan_engine`), resolução em `tasks._resolve_scan_engine`, logada (`scan_log` + audit `scan.engine_selected`); testes em `tests/test_scan_engine_resolution.py`.
- Definition-of-done: `mission._build_mission_phase_contracts` agora **preserva** os campos ricos do core (`allow_partial`, `minimum_evidence_strength`, `validator_required` — antes descartados) e eleva mínimos para `attempted ≥ ceil(0.75·|required|)`, `succeeded ≥ ceil(0.5·|required|)` com piso 1. Desvio da letra do plano (0.75/0.75): `succeeded` em 0.5 evita stall em fase com sucesso+falha mista, pois o escape "all required failed" não cobre esse caso; skips contam como attempted; testes em `tests/test_phase_contract_exit_criteria.py`.
- Corrigido teste de contrato pré-existente `test_platform_profile_contract` (perfil `api` adicionado em commit anterior sem atualizar o contrato).
- **Precheck de tool health consciente de escopo** (`tool_health_service.partition_broken_required_tools` + `routes_scans.py`): ferramentas SAST/SCA (bandit/retire/trivy/semgrep) só bloqueiam scan full quando há `source_config` — antes, 3 binários ausentes no Kali bloqueavam **todo** scan full web da plataforma. Registrado em `state_data.tool_health_precheck` com `broken_tools`/`excluded_not_applicable` (skip explícito com motivo, no espírito do item 3).
- **Guard de loop do supervisor consciente de fase** (`supervisor.py`): `loop_on_same_phase` abortava o scan quando o phase walker avançava P01→P02 dentro da mesma capability — visto no scan #38 (morreu no iter 8 no meio do recon). Agora compara (capability, `current_pentest_phase_id`); mesma capability + fase avançada = progresso. Regressão em `test_same_capability_with_advanced_phase_is_progress_not_loop`.
- **Evidência do E2E (scan #38, engine=langgraph)**: pipeline completo supervisor→skills→Kali→evidence→report; P01 completa (16 ferramentas), P02 com httpx/naabu/nmap/masscan (porta 3000 descoberta), 21 `ExecutedToolRun`, 8 findings, métricas `tools_attempted=26/success=16`, `termination_reason` registrado. O status REST fatia campos do state — leitura de cobertura deve usar `state_data`/DB (`executed_tool_runs`, `phase_ledger`), não o `/status`.
- **Evidência do E2E #2 (scan #39)**: com o guard de fase, o scan viveu até o kill switch (13 iters), mas expôs duas lacunas de wiring que viraram o primeiro trabalho da Fase 1: (1) o phase-walker (`_next_pentest_tactic`) mantém progresso próprio e **nunca popula** `phase_ledger`/`current_pentest_phase_id` — logo `_validate_and_advance_phase` (definition-of-done da Fase 0) e os critérios de kill-chain nunca veem o progresso; (2) quando todos os tools da táctica foram dedupados, a iteração vira no-op (nada executa, fase não avança) e iterações queimam até o kill switch. Fase 0 **provada** com essas ressalvas documentadas; profundidade/cobertura previsível é prova da Fase 1.

**Notas de implementação da Fase 1 (2026-11-04, executado):**
- **Raiz sistêmica encontrada**: 12+31 chaves top-level usadas pelo grafo (`pentest_phase_index`, `phase_ledger`, `kill_chain_stage`, `detected_tech_stack`, `max_iterations`, ...) **não declaradas** no `AgentState` (TypedDict) — o LangGraph as descartava no merge entre nós. O supervisor decidia sobre state que nunca chegava ao pipeline. É a causa estrutural do "superficial/não finaliza" no motor de grafo. Script de auditoria cruzou `state["x"]`/`state.get("x")` vs schema; teste `tests/test_graph_state_phase_keys.py` trava o contrato (merge no checkpoint + 22 fases no ledger).
- **Walker→ledger**: fases puladas/completadas pelo walker agora gravam `skipped`/`completed` com motivo no `phase_ledger` (definition-of-done visível no Phase Monitor). Scan #40 (com o fix): walker marchou P01→P17+, 35 tool runs, ffuf de parâmetros ativo no Kali.
- **Montagem dinâmica de fases** (`mission.phase_entry_applicable` + `PHASE_ENTRY_RULES`): núcleo sempre roda; P01/P07/P08/P10 exigem domínio; P09 subdomínios; P06/P12–P17/P19 serviço web confirmado; P18 HTTPS. Skip vai para o ledger com justificativa (decisão 4 do sponsor). Testes em `tests/test_phase_entry_rules.py`.
- **Orçamento por perfil**: `initial_state` mapeia depth→`max_iterations` (asm/low=10, full/medium=24, aggressive/high=48); default `ScanCreate.scan_level="aggressive"` (decisão 1 do sponsor: agressivo é o standard).

### Fase 1 — LangGraph como cérebro (4–6 semanas)

Objetivo: o grafo é a única fonte de decisão; a fila vira braço executor.

1. **Modelar tasks como nós determinísticos**: cada fase P01–P22 vira um subgraph com: contrato de entrada (deps da fase), conjunto de ferramentas esperado, critério de saída (evidência mínima), orçamento próprio. O supervisor faz **planejamento e replanejamento** (ordem, prioridade, aprofundamento), não seleção ferramenta a ferramenta.
2. **Slim state + persistência incremental**: `AgentState` dividido em (a) índice/dedup state pequeno no checkpoint, (b) payload pesado (logs, findings brutos) em tabelas com cursor. Checkpoint por task, não por iteração de nó.
3. **Work queue como API do grafo**: `dispatch_scan_work_items` vira ferramenta chamada pelos nós de fase (LangGraph tool-calling), com contrato de admissão FIFO + semáforo. O grafo enxerga capacidade do Kali (AIMD) como restrição de scheduling, não como estresse oculto.
4. **Orçamento explícito por perfil de scan**: `quick|standard|deep`, sendo **`standard` = agressivo por decisão do sponsor** (profundidade de referência: sqlmap mapeando tabelas). Perfil mapeia para (fases obrigatórias, orçamento de ferramentas por fase, timeout total). Fases fora do núcleo entram por decisão do supervisor fundamentada em evidência — como um pentest humano monta o plano — com justificativa no trace.
5. **Adoção gradual**: o grafo assume o comando fase a fase (núcleo P01–P02 primeiro), com flag por fase e o operator como fallback até a paridade de cobertura.

Entregável: mesmo alvo executado nos 3 perfis produzindo cobertura previsível e mensurável; supervisor decide replanejamento ao encontrar WAF/SSO/stack específico (comportamento observável nos logs de trace).

### Fase 2 — MCP: normalização e re-teste (3–4 semanas, paralelizável com Fase 1)

**Notas de implementação (2026-11-04, executado):**
- **Envelope v1** (`mcp-server/result_envelope.py`, stdlib puro): `result-envelope/v1` com `findings_raw` conservador por família (nuclei/sqlmap/ffuf/httpx — família sem extrator retorna []), `quality_flags` (empty_output/timeout/error_exit/high_noise), `evidence_refs`. Aplicado em `/mcp/jobs/{id}/result` e `/mcp/execute` (campos legados preservados). 12 testes unittest rodam no host sem deps.
- **Protocolo de re-teste**: `POST /mcp/retest` {tool, target, scan_id, authorized_scope, evidence_expected[]} → re-executa via runner → `compare_evidence` → `confirmed|not_reproducible|inconclusive`. Guardrail vale igual; scope obrigatório (fail-close do runner).
- **Prova ao vivo**: finding **#671 (high)** do scan #40 — "SSL legado habilitado" com evidência *"SSLv2 disabled"* — retestado: claim `SSLv2 enabled` → **not_reproducible** (falso positivo real detectado pelo protocolo); sinal real `SSLv2` → **confirmed**. Veredito persistido em `Finding.details.retest_verdict`.

Objetivo: MCP deixa de ser proxy e vira camada de contrato de resultado.

1. **Envelope de resultado padronizado** no runner/MCP: `{tool, target, status, parsed, findings_raw, evidence_refs, duration, quality_flags}`. `parsed.json` por família de ferramenta (nuclei/sqlmap/ffuf/katana...) com schema versionado — `tool_parsers.py` migra para o lado da execução (o backend consome o envelope, não regex em stdout).
2. **Normalização na borda**: extração de findings no MCP/runner (o que hoje é `findings_extractor` rodando no worker sob demanda), com dedup por (tool, template-id, host, path) ainda quente.
3. **Protocolo de re-teste de validação**: item de validação vira job próprio com `proof_pack_required`, execução com a mesma skill + evidência esperada; MCP orquestra execução → comparação → veredito (`confirmed|not_reproducible|inconclusive`) gravado em `ExecutedToolRun` + `Finding.details`. Este é o laço que hoje só existe como `validation_backlog` sem executor garantido.
4. **Guardrail unificado** (não mais espelhado à mão): policy versionada servida pelo backend, consumida por MCP e runner do mesmo jeito.

Entregável: finding crítico/alto só sobe para `confirmed` com re-teste registrado; relatório mostra o fio da meada (job, evidência, veredito).

### Fase 3 — Skills + RAG no Kali (4–6 semanas)

**Notas de implementação (2026-11-04, executado):**
- **Sidecar `kali_rag`** (`kali-rag/`, serviço no compose — fora da imagem de 55 GB): `POST /retrieve` com dois modos: lexical/estrutural (caminho quente, medido 9–52ms < orçamento 100ms) e vetorial (query_embedding opcional). Retorna skill docs (rag_knowledge_store) + learnings aceitos. Fallback sem contexto se indisponível (nunca bloqueia job).
- **Retrieve-and-operate no runner**: `runner._attach_operational_context` consulta o sidecar em thread daemon por job e grava `operational_context` no job; `_run_job` materializa `context.json` no workdir para wrappers.
- **Descoberta de corpus**: das ~10k linhas `accepted`, **nenhuma** tinha `raw_llm_response` (o gate de "síntese" era o problema de visibilidade — o conteúdo steps/mission/summary estava lá). Filtro corrigido nas duas pontas (kali_rag + playbook).
- **Triagem** (`scripts/triage_h1_learnings.py`): llama3.2:3b via Ollama (qwen2.5:7b **OOM no host 8GB** — fallback documentado), lotes de 10 com `keep_alive` + retry/backoff (llama-server morre sob pressão de memória durante scans), classifica família/fases/skills/confiança/risco, dedup Jaccard com stopwords do boilerplate H1. **Conclusão da dedup: o corpus pending é massivamente duplicado dos aceitos** (similaridade 1.0 no sample — o mesmo report semeado em múltiplos buckets). Cada decisão audita `raw_extraction.triage` + `review_notes`.
- **Retrieval semântico no laço**: `build_runtime_learning_playbook` usa `semantic_search_learnings` com contexto (fase/ferramentas/stack), filtrando `status='accepted'` (o índice não filtra — teste trava isso); fallback para pool por recência.

Objetivo: os 10k reports operam as ferramentas na borda.

1. **Skill como contrato**: cada skill (`skills/vulnerability_testing/*.md`) ganha front-matter estruturado (ferramentas, templates de args, evidência esperada, critério de aceite, riscos) — as skills já possuem front-matter YAML (required_tools/optional_tools/phase_ids) usado pelo contrato de fases; planner e RAG consomem esse formato.
2. **RAG colocalizado com o runner, como sidecar**: novo serviço no compose (`kali_rag`, imagem leve própria — nunca dentro da imagem de ~55 GB do runner) que consulta o índice antes de executar: dado (fase, skill, tool, tech_stack do alvo) → top-N (skill steps + learnings H1 aceitos + casos semelhantes) → injetado no job como `operational_context`. Latência de retrieve < 100ms no caminho quente; índice atualizado por evento (novo aceite → reindex incremental). Sidecar compartilha a rede do compose; runner o chama por HTTP com fallback para sem contexto se indisponível (não afetar a plataforma).
3. **Destravar o corpus H1**:
   - Triage automática dos ~10k `pending_review` com **Ollama local** (decisão do sponsor; sem Anthropic): LLM local classifica família/fase/skills, deduplica contra aceitos, estima confiança e risco; acima de limiar → `accepted` com auditoria; zona cinzenta → fila de revisão humana enxuta (de 10k para dezenas). Modelo candidato `qwen2.5:7b-instruct` em CPU; cair para o 3B atual se a latência do lote inviabilizar. **Executado com llama3.2:3b** (7B deu OOM no host 8GB).
   - `embedding IS NOT NULL` backfill em lote (`backfill_learning_embeddings` já existe) para todo o corpus aceito.
4. **Runtime retrieval no cérebro**: `build_runtime_learning_playbook` passa a usar `semantic_search_learnings` com o contexto do alvo (target + tech_stack + endpoints + fase), substituindo o pool por recência. Top-8 recência → top-K semântico com limiar de similaridade.

Entregável: scan mostrando no trace "learning #X aplicada na P12 com tool Y"; cobertura do corpus medida (% dos 10k triados, % aceitos, retrieval hits por scan).

### Fase 4 — Performance (contínua, começa após Fase 1)

**Notas de implementação (2026-11-04, executado):**
- **Push de resultado**: runner (`_push_terminal_status`) POSTa o status terminal para `POST /api/internal/kali-result-callback` (token interno) ao fim de cada job; backend grava em Redis (`kali:result:{job_id}`, TTL 1h, sem DB); o poll loop do `kali_executor` consulta Redis antes do GET e short-circuita (0 polls quando o push chegou — 1 request de resultado em vez de N polls). Ativado por `KALI_RESULT_PUSH_ENABLED` (default on); falha no push = comportamento antigo (polling).
- **DB batched (cache de prompt)**: `render_accepted_learning_for_prompt` tem cache TTL 120s — o prompt do supervisor é remontado por iteração e relia os mesmos learnings aceitos; o cache corta transações de apoio repetidas em scan longo.
- **Lanes fast/slow no runner (F4 item 2, 2026-11-04)**: dois pools físicos (`KALI_LANE_FAST`/`KALI_LANE_SLOW`, default 10/6 sobre `KALI_MAX_PARALLEL=16`; classificação por timeout do profile, limiar 240s). Ferramentas lentas (sqlmap/nuclei/nmap) não bloqueiam mais as rápidas (httpx/dnsx) — fim do head-of-line blocking.
- **Envelope consumido pelo grafo (F2)**: `MCPClient.execute_kali_tool_sync` anexa o envelope v1 ao resultado legado (cópia versionada do builder em `backend/app/services/result_envelope.py` — mesmo contrato `result-envelope/v1`); `_run_tools_and_collect` acumula `findings_raw` em `state.envelope_findings` (cap 200) com métrica `envelope_findings_total` — evidence gate/findings_extractor consomem sem re-varrer stdout.
- **State slim (F1 item 2, bounded, 2026-11-04)**: `StateDataJSON.process_bind_param` aplica caps em listas de telemetria append-only (activity_metrics 500, node_history 400, autonomy_* 300, llm_reasoning 200, envelope_findings 200, tool_execution_results 300, delegation_log 200, supervisor_evaluations 200). Listas de decisão NUNCA cortadas (executed_tool_runs, vulnerabilidades_encontradas, logs_terminais). O checkpointer LangGraph é em memória; `scan_jobs.state_data` é a persistência durável — caps atuam em todo write via TypeDecorator.
- **Guard de restarts do platform health corrigido**: busy-check filtrava `mode="scope"` mas heartbeats gravam por hostname/mode=unit (nunca casava → guard reiniciava worker_scope no meio de scans); o guard agora grava o watchdog heartbeat (latência de fila não dispara falso "watchdog stale").
- Concorrência por classe de recurso: mantidos os semáforos AIMD existentes; medidos na validação final.

1. **Push no lugar de poll**: runner notifica resultado (webhook interno/SSE para o `worker_poll`); elimina latência de polling e requests repetidas.
2. **Concorrência real no Kali**: `KALI_MAX_PARALLEL` sobe de 16 para classe de recurso (network-bound vs CPU-bound), com AIMD já existente; filas separadas para ferramentas rápidas (httpx/dnsx) vs lentas (sqlmap/nmap).
3. **DB**: batch de `ScanLog`/audit writes; cache de prompt parts (learnings, contratos) por scan com invalidação por evento; índice parcial em `vulnerability_learnings(status, accepted_at)`.
4. **Celery enxuto**: dispatcher único (grafo) elimina a cadeia worker→MCP→runner→poll quando o grafo chama o runner direto para tools simples; filas pesadas (browser, evidence) permanecem.

Metas sugeridas: tempo de scan padrão no Juice Shop −40%; transações de apoio no Postgres −70%; zero polls por resultado.

## 5. Métricas de sucesso da plataforma

| Métrica | Hoje (referência) | Alvo |
| --- | --- | --- |
| Cobertura em scan `standard` (agressivo) | imprevisível (budget/gates) | 100% das fases aplicáveis ao alvo com contrato cumprido ou skip motivado; justificativa de cada fase no trace |
| Motivo de término visível | parcial | 100% dos scans com `termination_reason` + mix de fases |
| Learnings H1 em uso por scan | ≤ 12 (recência) | top-K semântico com ≥ 1 retrieval hit em ≥ 60% das fases de ataque |
| Corpus H1 adjudicado | ~10k travados em pending | 100% triado; aceite humano só na zona cinzenta |
| Latência fim-a-fim (Juice Shop, standard) | baseline a medir na Fase 0 | −40% |
| Findings críticos/alto com re-teste | ad hoc | 100% com veredito registrado |

## 6. Riscos e mitigações

- **Risco: Fase 1 reescrever demais.** Mitigação: Fase 0 mantém o operator funcionando; o grafo assume fase a fase (P01–P06 primeiro, depois o restante), com flag por fase.
- **Risco: triagem automática de H1 aceitar conteúdo ruim/duplicado.** Mitigação: limiar conservador, dedup obrigatório, auditoria total, revisão humana na zona cinzenta, conteúdo ofensivo-pesado sempre manual.
- **Risco: RAG no Kali adicionar latência no caminho quente.** Mitigação: retrieve assíncrono com cache por (tool, tech, fase); métrica de latência no envelope; fallback para sem contexto se índice indisponível.
- **Risco: MCP virar monólito 2.0.** Mitigação: MCP segue com responsabilidade única (contrato de resultado + re-teste); regras de negócio e rating ficam no backend.

## 7. O que NÃO muda

- Kali continua único executor de ferramentas (princípio Kali-only intacto).
- Guardrails de escopo/redirect e auditoria permanecem fail-close.
- Aceite humano continua existindo — só deixa de ser gargalo serial.
