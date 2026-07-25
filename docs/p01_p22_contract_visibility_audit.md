# Auditoria de contratos P01→P22, visibilidade e qualidade

Data: 2026-07-25

## Objetivo

Esta auditoria fecha a divergência entre três camadas da plataforma:

1. **Execução real**: `PHASE_CONTRACTS`, `PHASE_GATE`, aplicabilidade de ferramenta e `preflight`.
2. **Dashboard/API**: nomes, status, progresso e fase corrente exibidos ao usuário.
3. **Análise final/quality**: cálculo de cobertura, fallback de ferramenta e gaps reportados.

O bug recorrente não era apenas “scan travado”. A causa raiz era a existência de contratos paralelos e parcialmente antigos: uma fase podia executar com uma semântica, ser exibida com outra e ser cobrada no quality gate por uma terceira.

## Matriz canônica atual

| Fase | Nome canônico | Gate | Ferramenta obrigatória | Natureza |
|---|---|---:|---|---|
| P01 | Subdomain Enumeration | — | subfinder | descoberta/inventário |
| P02 | Port Service Discovery | — | naabu | reachability TCP |
| P03 | Endpoint Discovery | P06 | ffuf | web-heavy |
| P04 | Parameter Discovery | P06 | arjun | web-heavy |
| P05 | Surface Expansion | P06 | ffuf | web-heavy |
| P06 | HTTP Fingerprinting & WAF Detection | P02 | httpx | gate HTTP-live |
| P07 | Technology Detection | P06 | whatweb | web-heavy |
| P08 | JavaScript Endpoint Analysis | P06 | linkfinder, chromium-capture | web-heavy |
| P09 | Vulnerability Template Scan | P06 | nuclei | web-heavy |
| P10 | Injection Testing | P09 | wapiti | web-heavy + evidência |
| P11 | SSRF Testing | P09 | nuclei | web-heavy + evidência |
| P12 | XSS Testing | P09 | dalfox | web-heavy + evidência |
| P13 | Access Control & Business Logic | P09 | bl-test | web-heavy + credenciais/contexto |
| P14 | Auth Boundary Testing | P09 | nuclei-auth-bypass | web-heavy + auth |
| P15 | File Handling Testing | P06 | nuclei-exposure | web-heavy |
| P16 | API Input Surface Review | P06 | arjun | web-heavy |
| P17 | Exploit Validation | P09 | nuclei | web-heavy + evidência |
| P18 | Credential Exposure Boundary | — | theharvester | passivo/credencial |
| P19 | Post Exploitation Boundary | P09 | nuclei | web-heavy + contexto |
| P20 | Attack Path Correlation | P09 | nuclei | correlação sobre evidência |
| P21 | Evidence Quality Review | — | manual_review | análise pura |
| P22 | Campaign Reporting | — | report-builder | relatório |

## Correções aplicadas nesta rodada

- `qualification_contract_version` agora falha fechado quando ausente ou menor que v2. Antes, qualquer scan sem esse campo liberava todos os targets silenciosamente.
- `_merge_runtime_scan_state` agora preserva evidência monotônica de qualificação (`preflight`, `tcp_live_targets`, `http_live_targets`, `qualified_target_set`). Antes, um snapshot antigo do dispatcher podia apagar uma conclusão nova de P02/P06.
- P18 não é mais bypass para alvo morto (`invalid`, `dns_dead`, `dead`, `unresolved`, `no_tcp`).
- P18 só é preservado sem HTTP para a raiz/entrada original do scan; subdomínio descoberto sem HTTP-live não recebe P18 automaticamente.
- `triage_dead_target` deixou de preservar P18 para alvo morto e agora usa `FOR UPDATE SKIP LOCKED` antes de marcar work items como `skipped`.
- `nuclei-cloud` entrou na lista de ferramentas HTTP/nuclei que exigem superfície HTTP.
- O reorder pós-claim do dispatcher recebeu desempate estável por ordem original/id.
- `_force_release_chain_lock` deixou de fazer `DEL` cego e agora usa compare-and-delete do valor observado no Redis.
- `recover_scan_if_orphaned` passou a bloquear a linha do scan com `FOR UPDATE` antes de alterar `recovery.redrive_count`.
- `skill_execution_scores` voltou a receber sinal útil: `productive/unproductive` alimenta utilidade operacional sem contaminar precisão validada.
- `expand_attack_surface` passou a bloquear a linha do scan antes de atualizar `state_data`, evitando lost-update entre crawlers concorrentes.
- Ordenação de endpoints e SANs ficou determinística (`len + valor`, `sorted(set(...))`).
- P09 agora exige P06 HTTP-live inclusive em contrato v2. Antes, a checagem transitiva só rodava em v3.
- `evaluate_finding_promotion` não promove mais finding para `confirmed` apenas porque existe artifact candidate; exige status confirmado, artifact confirmado ou par baseline/exploit.
- `classify_endpoint_auth_requirements` passou a usar duas amostras estáveis antes de classificar anonymous/authenticated; instabilidade vira `unknown` com motivo explícito.
- Fallback de LLM agora retorna `fallback=true` e `llm_error`, em vez de parecer decisão normal sem injeção.
- `_PHASE_CONTRACTS_FALLBACK` em `mission.py` não reintroduz mais P18 como SSL/TLS.
- `scan_quality.py` deixou de cobrar P18 como SSL/TLS (`sslscan`, `testssl`, `nmap-ssl-vuln`) e passou a usar fallback compatível com credenciais/segredos.
- `_PHASE_DEPS` em `scan_intelligence.py` foi alinhado aos gates reais: P15 depende de P06, P18 não depende de P06, P10–P14/P17/P19/P20 dependem de P09.
- API runtime de fases e `/scan` foram alinhados aos nomes canônicos.
- O catálogo narrativo de ferramentas deixou de associar TLS à P18.

## Como isso deve aparecer no dashboard

- `current_step` e `mission_progress` devem refletir a work queue real quando há itens de fila.
- P18 deve aparecer como “Credenciais e segredos” / “Credential Exposure Boundary”, não como TLS, JS ou OSINT genérico.
- P15 deve aparecer como “File Handling Testing” / “Arquivos e exposição web”, não como recon histórico.
- Fases com `skipped` por não aplicabilidade contam como término operacional, mas reduzem `success_pct`; isso evita “travado falso” sem fingir sucesso.
- Quality deve mostrar explicitamente quando a baixa profundidade vem de reachability (`p06_no_http_targets`, `hypotheses_blocked_reachability`) e não de ausência de vulnerabilidade.

## Como isso deve aparecer na análise final

- P01/P02/P06 devem separar inventário, TCP e HTTP:
  - DNS resolvido não é `qualified_target`.
  - P02 executado sem porta aberta não libera teste web profundo.
  - P06 sem resposta HTTP é negativo terminal para web-heavy.
- P18/P21/P22 não devem ser usados como prova de superfície explorável.
- Fallback de qualidade deve escolher ferramentas da mesma intenção da fase. Exemplo: falha de P18 tenta `theharvester/h8mail/nuclei-exposure/nuclei-cloud`, não `sslscan`.

## Testes de regressão adicionados

- `backend/tests/test_phase_contract_consistency.py`
  - P18 é credencial/segredo, não TLS.
  - DAG de inteligência bate com `PHASE_GATE`.
  - P15 só tem uma entrada de gate.
  - API runtime não usa nomes antigos.
  - Catálogo efetivo não reintroduz TLS em P18.
- `backend/tests/test_recon_qualification_barrier.py`
  - contrato de qualificação ausente falha fechado;
  - merge runtime preserva qualificação P02/P06;
  - P18 não roda para alvo comprovadamente morto;
  - subdomínio sem HTTP não recebe P18;
  - raiz do scan ainda pode receber P18 passivo sem HTTP.
  - chain lock órfão usa compare-and-delete;
  - redrive de scan órfão bloqueia a linha antes de atualizar orçamento.
- `backend/tests/test_scan_work_queue_applicability.py`
  - `productive/unproductive` alimenta utilidade operacional sem virar precisão validada.
- `backend/tests/test_endpoint_discovery_scope_expansion.py`
  - extração/ordenação de endpoints e SANs é determinística.
- `backend/tests/test_pentest_automation_contracts.py`
  - artifact candidate sozinho não confirma finding.
- `backend/tests/test_pentest_intelligence_refactor.py`
  - auth classification instável fica inconclusiva.

## Resultado de validação

Executado no backend:

- `tests/test_recon_qualification_barrier.py`
- `tests/test_scan_work_queue_applicability.py`
- `tests/test_phase_contract_consistency.py`
- `tests/test_recon_observability.py`
- `tests/test_scan_quality_visibility.py`
- `tests/test_scan_quality_phase_scope.py`

Resultado: `61 passed, 1 skipped`.

Após validação dos pontos adicionais do Claude:

- Resultado atualizado: `100 passed, 1 skipped`.

## Classificação final dos pontos do Claude

O PDF `ScriptKidd.o — Auditoria de Instabilidade de Scan.pdf` foi lido após esta rodada. Ele lista 109 achados em 10 padrões:

- ordem instável;
- race sem lock;
- amostra única;
- exceção engolida;
- código morto;
- LLM sem seed;
- dois juízes;
- cache global;
- infra/recursos;
- gate de qualificação.

Esta rodada não tentou “zerar 109 achados” em um único commit. O foco foi corrigir os pontos que explicavam diretamente scans diferentes para o mesmo alvo: perda de estado P02/P06, gating fail-open, P18/P15 sem contrato consistente, concorrência no dispatcher/watchdog, amostra única em auth, promoção de finding por timing e visibilidade divergente entre execução/dashboard/quality.

### Confirmados e corrigidos

- Perda de `preflight`/P02/P06 no merge de runtime.
- Feedback loop `skill_execution_scores` sem vocabulário compatível.
- P09 com gate transitivo dependente de versão v3.
- P18 preservado para alvo morto via `triage_dead_target`.
- Tie-break de reorder pós-claim sem desempate estável.
- `_force_release_chain_lock` com delete cego.
- `redrive_count` atualizado sem lock de linha.
- Ordenação instável por `set()` em endpoints/SANs.
- Lost-update em `expand_attack_surface`.
- Artifact candidate promovendo finding por timing.
- Auth classifier com amostra única.
- Fallback LLM mascarando falha como ausência normal de decisão.
- Fallback P18 de `mission.py` desatualizado.

### Já mitigados antes desta rodada

- P15 depender só de P02/P01: agora depende de P06 HTTP-live.
- P18 como bypass de dead-status no check principal.
- Dedup com contagens voláteis em títulos principais de subdomínio.
- LLM operacional sem temperature/seed.
- Auth matrix de BFLA com `_response_signature` de uma amostra: já usa duas amostras.
- P21/PoC tratando falha/timeout como refutação: `poc_outcome.py` classifica falha/timeout como candidate.
- Retest sem material operacional: `retest_service.py` retorna inconclusive, não refuted.

### Débito estrutural restante

- Criar um wrapper único para chamadas LLM/Ollama determinísticas e substituir chamadas espalhadas em serviços de risco, narrativa, estratégia, relatório e agents.
- Unificar validadores de fase (`phase_validator.py`, `graph/workflow.py`, `offensive_operator_core.PhaseValidator`) em uma única fonte efetiva.
- Resolver truncamento de stdout do runner/backend com artifact completo lido por path, sem inflar JSONB.
- Tornar falha de parser visível como gap de qualidade estruturado, não apenas warning de log.
- Estabilizar denominadores de coverage com snapshot de escopo por geração.
- Auditar títulos específicos de parsers restantes, como `wpscan`, para remover qualquer campo não ordenado/volátil.
- Separar aprendizado global por owner em janelas com decaimento e contexto de alvo/tecnologia para evitar envenenamento permanente.
- Revisar caches globais e caches de processo (`NVD`, DNS, RAG/embedding fallback, websocket/admin logs) para escopo, TTL e sinalização de fallback.
- Reduzir “dois juízes” restantes em API/frontend: mission progress, scan status agregado e timeline/final report devem consumir a mesma síntese de execução.
- Trocar validadores/probes restantes de amostra única por política de estabilidade com retry/conclusão `inconclusive`, especialmente probes de API, NoSQL, BOLA/IDOR e business logic.

`git diff --check`: sem erros.

## Próximos pontos ainda recomendados

- Centralizar nomes de fase em um único módulo compartilhado por API, dashboard e relatórios.
- Adicionar endpoint de “contract diagnostics” por scan mostrando: fase, gate, alvo, evidência que liberou, motivo de skip/bloqueio.
- Exibir no dashboard a diferença entre `expanded_targets`, `dns_resolved_targets`, `tcp_live_targets`, `http_live_targets` e `qualified_target_set`.
- Criar harness determinístico N-runs para separar variação legítima de alvo/rede de variação causada por contrato ou LLM.
- Unificar os validadores de fase. Hoje há `app/services/phase_validator.py`, `app/graph/workflow.py` e `offensive_operator_core.PhaseValidator`; isso ainda permite drift de semântica.
- Separar, no aprendizado global, sucesso operacional de ferramenta, precisão validada e yield por alvo/tecnologia com decaimento temporal.
