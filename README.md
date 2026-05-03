# Pentest.io - Plataforma EASM e Pentest Automatizado

Pentest.io e uma plataforma de External Attack Surface Management e pentest automatizado orientada por agentes. O backend orquestra a missao com LangGraph, distribui o trabalho em workers Celery por fases da Cyber Kill Chain e executa as ferramentas ofensivas exclusivamente dentro do container Kali, que funciona como repositorio central de ferramentas e evidencias.

Este README descreve o fluxo real de operacao da plataforma: o que acontece quando um scan nasce, como as ferramentas sao escolhidas e executadas, onde cada dado e persistido, como a UI enxerga o progresso e como investigar falhas.

## Sumario rapido

| Item | Detalhe |
| --- | --- |
| Arquitetura | Kali-only para tools - backend/worker tool-free - LangGraph para fluxo |
| Containers | 16 servicos (1 Kali - 1 backend - 9 workers Kill Chain - 5 infra/UI) |
| Imagem backend | 4.06 GB lean (era 21.3 GB com tools embarcadas) |
| Imagem Kali | ~55 GB (kali-linux-everything + ProjectDiscovery + jwt_tool/paramspider) |
| Tool count | 4 077 binarios no Kali, 48 profiles YAML, 22 fases tecnicas |
| Visibilidade | 5 paineis frontend + 8 endpoints REST de telemetria |

## Diagrama do fluxo (cerebro vs. maos)

```
       usuario (browser)
              |
              v
       Frontend React 18                       http://localhost:5174
              |
              | JWT Bearer
              v
       Backend FastAPI                         http://localhost:8001
              |  POST /api/scans
              |  GET  /api/scans/{id}/phase-monitor
              |  GET  /api/kali-runner/health
              v
            Redis (broker Celery)
              |
   +----------+----------+----------+----------+----------+----------+
   |          |          |          |          |          |          |
worker     worker     worker     worker     worker     worker     worker
scope      recon      weapon     delivery   exploit    install    ...
   |          |          |          |          |          |          |
   +----------+----------+--POST----+----------+----------+----------+
                            /jobs
                              |
                              v
                       Kali Runner FastAPI         http://kali_runner:8088
                              |  POST /jobs
                              |  GET  /jobs/{id}
                              |  GET  /jobs/{id}/result
                              v
                       subprocess.run dentro do container Kali
                              |
                              v
                       /workspace/{scan_id}/{tool}/{job_id}/
                              command.txt
                              stdout.txt
                              stderr.txt
                              exit_code.txt
                              parsed.json
                              |
                              v
                       PostgreSQL: scan_jobs.state_data, executed_tool_runs, findings
```

Princípio fundamental: o **cerebro** (LangGraph supervisor) decide *quando* e *qual* ferramenta usar; as **maos** (container Kali) executam. Backend e workers carregam apenas codigo Python; toda a superficie ofensiva vive em uma unica imagem Kali, mantida pelos kali-maintainers.

## Principios Operacionais

- Uso defensivo e autorizado: scans devem ser executados somente contra alvos sob escopo aprovado.
- Execucao centralizada: workers nao executam ferramentas ofensivas localmente; todos chamam o `kali_runner`.
- Evidencia primeiro: achados criticos e altos precisam de evidencia tecnica, impacto e reprodutibilidade para serem promovidos.
- Visibilidade continua: progresso, logs, jobs, ferramentas usadas, findings, ratings e workers ficam expostos via API e frontend.
- Auditoria por scan: cada scan possui `trace_id`, logs, audit trail, execucoes de ferramentas, estado do grafo e evidencias no volume do Kali.

## Stack Atual

| Camada | Tecnologia | Responsabilidade |
| --- | --- | --- |
| Frontend | React + Vite + Tailwind/CSS do produto | Dashboard, scans, targets, phase monitor, workers, jobs, vulnerabilidades, evolucao e relatorios |
| Backend API | FastAPI + SQLAlchemy + Alembic | Autenticacao, autorizacao, criacao de scans, consultas, agregacoes, relatorios e proxy do Kali |
| Orquestracao | LangGraph | Supervisor autonomo, roteamento de capacidades, loop de decisao e estado da missao |
| Filas | Celery + Redis | Execucao assincrona de scans, schedules, workers e pos-processamentos |
| Banco | PostgreSQL | ScanJob, logs, findings, assets, vulnerabilities, historico de rating, auditoria e heartbeats |
| Execucao de ferramentas | Kali Runner FastAPI | Perfis YAML, execucao de CLI, persistencia de jobs e evidencias em `/workspace` |
| LLM local | Ollama | Narrativas, recomendacoes e apoio ao relatorio, quando configurado |

## Servicos Docker

O `docker-compose.yml` usa profiles `dev` e `prod`. No profile `dev`, os servicos principais sao:

| Servico | Container | Funcao |
| --- | --- | --- |
| `postgres` | `pentest_postgres` | Banco transacional |
| `redis` | `pentest_redis` | Broker/result backend Celery |
| `ollama` | `pentest_ollama` | Runtime LLM local |
| `kali_runner` | `pentest_kali_runner` | Unico local de execucao das ferramentas |
| `backend` | `pentest_backend` | API FastAPI |
| `worker_scope` | `pentest_worker_scope` | Validacao de escopo e entrada |
| `worker_recon` | `pentest_worker_recon` | Reconhecimento |
| `worker_weaponization` | `pentest_worker_weaponization` | Correlacao CVE/OSINT/leaks |
| `worker_delivery` | `pentest_worker_delivery` | Descoberta de caminhos, parametros e vetores |
| `worker_exploitation` | `pentest_worker_exploitation` | Validacao de vulnerabilidades |
| `worker_installation` | `pentest_worker_installation` | Risco de persistencia, auth e credenciais |
| `worker_c2` | `pentest_worker_c2` | Risco de C2 e canais externos |
| `worker_actions` | `pentest_worker_actions` | Secrets, SAST, dependencias e impacto |
| `worker_reporting` | `pentest_worker_reporting` | Narrativa e consolidacao |
| `celery_beat` | `pentest_celery_beat` | Agendamentos |
| `frontend` | `pentest_frontend` | Interface web |

Portas sao configuraveis por `.env`. Defaults do compose:

| Variavel | Default | Uso |
| --- | --- | --- |
| `BACKEND_HOST_PORT` | `8000` | FastAPI no host |
| `FRONTEND_HOST_PORT` | `5173` | Frontend no host |
| `KALI_RUNNER_HOST_PORT` | `8088` | Runner Kali no host |
| `POSTGRES_HOST_PORT` | `5432` | PostgreSQL |
| `REDIS_HOST_PORT` | `6379` | Redis |
| `OLLAMA_HOST_PORT` | `11434` | Ollama |

Para conferir o ambiente real:

```bash
docker compose --profile dev ps
```

## Fluxo de Operacao Completo

### 1. Usuario acessa a plataforma

O usuario autentica no frontend via `/api/auth/login`. O token JWT e salvo no cliente e usado nas chamadas subsequentes. As rotas sensiveis verificam usuario, admin e grupos de acesso.

Visibilidade:

- Frontend: tela de login e shell autenticado.
- Backend: `/api/auth/me`.
- Banco: usuarios, grupos e permissoes.

### 2. Operador define alvo e cria scan

Um scan pode nascer por:

- Pagina `Targets`: operador cadastra ou escolhe alvo autorizado e dispara scan.
- Pagina `Scans`: operador cria scan manual.
- `Schedules`: `celery_beat` dispara execucoes recorrentes.
- API: `POST /api/scans`.

Ao criar o scan, o backend cria um `ScanJob` com:

- `owner_id`
- `target_query`
- `mode` (`unit` ou `scheduled`)
- `status=queued`
- `compliance_status`
- `current_step`
- `state_data` inicial com configuracoes complementares, como `llm_risk`

Em seguida, o backend registra auditoria (`scan.created`, `compliance.gate_pass`) e enfileira a task Celery:

- `run_scan_job_unit` na fila `scan.unit`
- `run_scan_job_scheduled` na fila `scan.scheduled`

Visibilidade:

- `GET /api/scans`
- `GET /api/jobs/registry`
- Pagina `Scans`
- Pagina `Jobs Registry`
- Audit trail em `/api/audit/events`

### 3. Worker assume o scan

Quando uma task Celery pega o scan:

1. O worker abre sessao no PostgreSQL.
2. Atualiza `ScanJob.status` para `running`.
3. Define `current_step="Iniciando grafo"`.
4. Cria logs em `ScanLog`.
5. Atualiza `WorkerHeartbeat` com `status=busy`, `current_scan_id` e `last_task_name`.
6. Inicia um pulse periodico para progresso.

Visibilidade:

- `GET /api/scans/{scan_id}/status`
- `GET /api/scans/{scan_id}/logs`
- WebSocket `/ws/scans/{scan_id}/logs?token=...`
- Pagina `Workers`
- Pagina `Scans`

### 4. LangGraph inicializa o estado da missao

O worker chama `initial_state()` em `backend/app/graph/workflow.py`. O estado inclui:

- `trace_id`
- `scan_id`
- `owner_id`
- `target`
- `scan_mode`
- `target_type`
- `input_targets`
- `lista_ativos`
- `discovered_ports`
- `vulnerabilidades_encontradas`
- `mission_items`
- `mission_metrics`
- `node_history`
- `completed_capabilities`
- `analyst_framework`
- `operation_plan`
- `confidence_state`
- `evidence_contract`
- `autonomy_notes`
- `autonomy_todos`
- `autonomy_actions`
- `autonomy_observations`
- `autonomy_errors`
- `tool_runtime`
- `validation_backlog`
- `easm_rating`
- `fair_decomposition`
- `executive_summary`

Esse estado e o "caderno de trabalho" dos agentes. Ao final do scan ele e persistido em `ScanJob.state_data`.

Visibilidade:

- `GET /api/scans/{scan_id}/status` mostra fatias do estado.
- `GET /api/scans/{scan_id}/autonomy` mostra memoria operacional.
- `GET /api/scans/{scan_id}/phase-monitor` cruza esse estado com ferramentas e findings.

### 5. Supervisor decide o proximo node

O grafo tem entrada em `supervisor`. Ele roteia dinamicamente para as capacidades:

1. `strategic_planning`
2. `asset_discovery`
3. `threat_intel`
4. `adversarial_hypothesis`
5. `risk_assessment`
6. `evidence_adjudication`
7. `governance`
8. `executive_analyst`

Cada capability node retorna ao `supervisor`. O supervisor avalia:

- cobertura de ferramentas
- progresso de missao
- confianca global
- evidencia coletada
- erros e skips
- nodes ainda nao visitados
- limite de iteracoes
- objetivo atingido

O loop encerra quando o objetivo e atingido ou quando o orcamento de iteracoes acaba. O default atual e `max_iterations=18`.

Visibilidade:

- `node_history`
- `completed_capabilities`
- `loop_iteration`
- `termination_reason`
- `objective_met`
- `agent_validation`
- Pagina `Phase Monitor`

### 6. As fases de pentest sao mapeadas para a Cyber Kill Chain

A plataforma expoe 9 fases executivas de Cyber Kill Chain:

| Fase | Node associado | O que representa |
| --- | --- | --- |
| `SCOPE_VALIDATION` | `strategic_planning` | Validacao de escopo, contrato e plano |
| `RECONNAISSANCE` | `asset_discovery` | Subdominios, DNS, portas, crawling e fingerprint |
| `WEAPONIZATION_SIMULATION` | `threat_intel` | CVEs, OSINT, leaks e sinais de explorabilidade |
| `DELIVERY_MAPPING` | `adversarial_hypothesis` | Vetores de entrega, paths, parametros e hipoteses |
| `EXPLOITATION_VALIDATION` | `risk_assessment` | Probes read-only para confirmar risco |
| `INSTALLATION_RISK_ANALYSIS` | `evidence_adjudication` | Persistencia, auth fraca e qualidade de evidencia |
| `COMMAND_AND_CONTROL_RISK` | `governance` | Risco de C2, governanca, FAIR e priorizacao |
| `ACTIONS_ON_OBJECTIVES` | derivado de evidencias | Impacto, secrets, SAST e supply chain |
| `REPORTING` | `executive_analyst` | Narrativa, rating, recomendacoes e relatorio |

Por baixo, existem 22 fases tecnicas (`P01` a `P22`) em `backend/app/graph/mission.py`. O `Phase Monitor` usa essas fases para verificar se as ferramentas esperadas foram tentadas.

### Catálogo de ferramentas por fase técnica

| Fase | Node | Worker principal | Objetivo | Ferramentas Kali/profileadas |
| --- | --- | --- | --- | --- |
| `P01` | `asset_discovery` | `worker_recon` | Subdomain Enumeration | `subfinder`, `amass`, `dnsx`, `shuffledns`, `assetfinder`, `alterx` |
| `P02` | `asset_discovery` | `worker_recon` | Port & Service Scan | `naabu`, `nmap`, `masscan`, `httpx` |
| `P03` | `asset_discovery` | `worker_recon` | Web Crawling & JS Extraction | `katana`, `hakrawler`, `gau`, `waybackurls`, `gospider` |
| `P04` | `asset_discovery` | `worker_recon` / `worker_delivery` | Parameter Discovery | `arjun`, `paramspider`, `ffuf` |
| `P05` | `asset_discovery` | `worker_recon` | HTTP/TLS Fingerprint | `httpx`, `whatweb`, `nikto`, `curl-headers`, `sslscan`, `wafw00f` |
| `P06` | `asset_discovery` | `worker_recon` | WAF Detection & Evasion Profile | `wafw00f`, `curl-headers` |
| `P07` | `threat_intel` | `worker_weaponization` | OSINT & Leak Intelligence | `shodan-cli`, `theHarvester`, `h8mail`, `trufflehog`, `gitleaks` |
| `P08` | `threat_intel` | `worker_weaponization` | Email Security Posture | `theHarvester` |
| `P09` | `threat_intel` | `worker_weaponization` | Subdomain Takeover | `subjack`, `nuclei` |
| `P10` | `threat_intel` | `worker_weaponization` | Cloud Asset Exposure | `nuclei`, `shodan-cli`, `trufflehog` |
| `P11` | `risk_assessment` | `worker_weaponization` / `worker_exploitation` | CVE & Misconfiguration Scan | `nuclei`, `nmap-vulscan` |
| `P12` | `risk_assessment` | `worker_exploitation` | Web Injection | `sqlmap`, `dalfox`, `wapiti`, `nikto` |
| `P13` | `risk_assessment` | `worker_exploitation` / `worker_c2` | SSRF & Open Redirect | `nuclei`, `interactsh-client` |
| `P14` | `risk_assessment` | `worker_installation` | Authentication Bypass & Brute Force | `hydra`, `medusa`, `jwt_tool`, `nuclei`, `crackmapexec` |
| `P15` | `risk_assessment` | `worker_delivery` | Directory & File Enumeration | `ffuf`, `gobuster`, `feroxbuster`, `dirsearch` |
| `P16` | `risk_assessment` | `worker_exploitation` | API Security | `nuclei`, `arjun`, `wapiti` |
| `P17` | `risk_assessment` | `worker_exploitation` | Upload & WebShell Bypass | `nuclei` |
| `P18` | `risk_assessment` | `worker_recon` / `worker_c2` | SSL/TLS Weakness & Cipher Audit | `sslscan`, `nmap`, `testssl` |
| `P19` | `risk_assessment` | `worker_exploitation` | IDOR & Access Control Flaws | `nuclei` |
| `P20` | `risk_assessment` | `worker_exploitation` | CMS-Specific Scan | `wpscan`, `nuclei`, `nikto` |
| `P21` | `threat_intel` | `worker_actions` / `worker_weaponization` | Secret & Credential Exposure | `trufflehog`, `gitleaks`, `semgrep`, `bandit` |
| `P22` | `risk_assessment` | `worker_actions` | Dependency & Supply Chain Risk | `retire`, `trivy`, `semgrep`, `bandit`, `gitleaks` |

Este catálogo é intencionalmente o contrato operacional: se uma ferramenta aparece aqui, ela deve existir como profile no `kali_runner`, ser executada dentro do container Kali e aparecer no `Phase Monitor` como `executed`, `skipped` com motivo, ou `attempted_failed` com erro rastreável.

### 7. Ferramentas sao selecionadas e disparadas

Cada node escolhe uma lista de ferramentas esperadas para o alvo atual. A execucao ocorre por `_run_tools_and_collect()`:

1. Monta `run_id = step|target|tool`.
2. Evita repetir ferramenta ja executada no mesmo passo.
3. Consulta `ExecutedToolRun` para evitar duplicidade ja persistida.
4. Dispara ferramentas pendentes em paralelo com `ThreadPoolExecutor(max_workers=6)`.
5. Para cada resultado, registra acao de autonomia.
6. Normaliza stdout/stderr/return code.
7. Atualiza metricas de missao.
8. Persiste execucao em `ExecutedToolRun`.

Importante: o worker nao executa CLI local. Ele chama `execute_tool_with_workers()`, que chama `execute_via_kali()`.

Visibilidade:

- `ExecutedToolRun`
- `ScanLog` com source `graph`, `worker`, `worker.progress_detail`, `validation`
- `Phase Monitor` em `tool_inventory`, `phases[]`, `issues[]`
- `Workers` em heartbeats e grupos

### 8. O Kali Runner executa a ferramenta

O `kali_runner` e uma API FastAPI dentro do container Kali.

Fluxo HTTP:

```text
worker/backend
  -> POST http://kali_runner:8088/jobs
       { profile, target, scan_id, tool }
  <- { job_id, status, profile, tool, target }

worker/backend
  -> GET /jobs/{job_id}
       ate status terminal

worker/backend
  -> GET /jobs/{job_id}/result
       stdout, stderr, parsed, command, return_code, workdir
```

Estados de job no runner:

- `queued`
- `running`
- `done`
- `failed`
- `timeout`
- `skipped`

O runner:

1. Carrega perfis YAML de `kali-runner/profiles/*.yaml`.
2. Valida alvo contra guardrails basicos.
3. Materializa comando com placeholders como `{host}`, `{url}`, `{https_url}`.
4. Aplica `requires_env` quando a ferramenta depende de segredo ou credencial.
5. Executa o argv dentro do container Kali, sem shell string.
6. Escreve evidencias no volume.
7. Persiste o job em `/workspace/.runner_jobs/{job_id}.json`.
8. Mantem resultado consultavel apos restart do runner.

Estrutura de evidencia:

```text
/workspace/{scan_id}/{tool}/{job_id}/
  command.txt
  stdout.txt
  stderr.txt
  exit_code.txt
  parsed.json        # quando o parser do perfil conseguir extrair JSON/JSONL

/workspace/.runner_jobs/{job_id}.json
  estado operacional do job
```

Visibilidade:

- `GET /api/kali-runner/health`
- `GET /api/kali-runner/catalog`
- `GET /api/kali-runner/profiles`
- `GET /api/kali-runner/tools`
- `curl http://localhost:8088/healthz`
- `curl http://localhost:8088/jobs/{job_id}`
- Volume Docker `kali_workspace`
- Badge `Kali ativo/offline` no topo do frontend

### 9. Resultados voltam ao grafo

O backend normaliza o resultado do Kali para o formato legado esperado pelo workflow:

```json
{
  "tool": "nuclei",
  "target": "example.com",
  "status": "executed",
  "command": "nuclei ...",
  "return_code": 0,
  "stdout": "...",
  "stderr": "",
  "parsed": [],
  "source_agent_id": "kali_runner",
  "dispatch_task_id": "uuid-do-job",
  "evidence_path": "/workspace/27/nuclei/uuid-do-job",
  "duration_seconds": 12.3
}
```

Falhas tambem voltam estruturadas:

```json
{
  "status": "error",
  "dispatch_error": "runner_lost_job:uuid-do-job",
  "source_agent_id": "kali_runner",
  "dispatch_task_id": "uuid-do-job"
}
```

Isso permite que o grafo marque ferramenta como `attempted_failed`, registre o erro e continue a missao sem travar indefinidamente.

### 10. Achados sao normalizados e persistidos

Ao final do grafo, o worker percorre `vulnerabilidades_encontradas` e cria registros em:

- `Finding`
- `Asset`
- `Vulnerability`
- `AssetRatingHistory`

O worker tambem:

- deduplica findings por titulo, severidade, worker, asset, porta, step e ferramenta;
- enriquece CVE quando detectado;
- calcula ou propaga CVSS;
- gera recomendacoes em portugues;
- preenche colunas estruturadas (`tool`, `domain`, `cve`, `cvss`, `recommendation`, `confidence_score`);
- preserva detalhes brutos em `Finding.details`.

Visibilidade:

- Pagina `Vulnerabilities`
- Pagina `Dashboard`
- Pagina `Attack Evolution`
- Relatorios por scan ou por target
- `GET /api/findings/page`
- `GET /api/dashboard/assets`
- `GET /api/dashboard/vulnerabilities`
- `GET /api/dashboard/trends/{asset_id}`

### 11. Rating, governanca e relatorio sao gerados

Os nodes `governance` e `executive_analyst` consolidam:

- `fair_decomposition`
- `easm_rating`
- `executive_summary`
- `agent_validation`
- `confidence_state`
- `evidence_contract`
- `report_v2`

O rating considera pilares FAIR/AGE:

- `perimeter_resilience`
- `patching_hygiene`
- `osint_exposure`

O relatorio pode ser gerado por scan ou por target, com persona tecnica por padrao no frontend atual.

Visibilidade:

- Pagina `Reports`
- `GET /api/scans/{scan_id}/report`
- `GET /api/scans/{scan_id}/easm-report`
- `GET /api/reports/by-target`
- `GET /api/reports/by-target/latest`

### 12. Aprendizado de vulnerabilidades com aceite humano

A página `Aprendizado` permite enviar uma ou várias URLs públicas separadas por ponto e vírgula (`;`), quebra de linha ou espaço, por exemplo:

```text
https://hackerone.com/reports/2586641; https://hackerone.com/reports/...
```

O backend busca as páginas com guardrails contra SSRF. Para reports do HackerOne, a plataforma tenta primeiro o endpoint JSON publico do report (`/reports/{id}.json`) e extrai especificamente `Steps to reproduce`, `Impact` e `Remediation`/`Suggested Mitigation`. O HTML da página fica como fallback.

O registro `vulnerability_learnings` guarda esses três blocos em colunas próprias:

- `steps_to_reproduce`: playbook aprendido de exploração/reprodução defensiva;
- `impact`: impacto original preservado para o relatório;
- `remediation`: orientação de correção preservada para o relatório.

Depois disso, o conjunto é enviado para a LLM local para gerar missão, prompt e técnicas operacionais, criando o aprendizado com status `pending_review`.

Para acelerar a maturidade inicial, a tela também tem `Antecipar catálogo`. Essa ação cria aprendizados pendentes, sem depender de download externo, para as famílias:

- SQL Injection, Resource Injection, Remote File Inclusion, Path Traversal;
- NULL Pointer Dereference, Information Exposure/Disclosure;
- Improper Authorization, IDOR, User Enumeration;
- XSS, CSRF, Code Injection, CRLF Injection;
- Brute Force, SSRF, Unprotected Transport of Credentials;
- Weak Password Recovery, Weak Cryptography for Passwords;
- XML Entity Expansion, XXE e Clickjacking.

URLs de diretórios conhecidos do repositório `aldaor/HackerOneReports` e listas públicas de disclosed reports são mapeadas para esse catálogo curado quando a rede do container não consegue baixar o conteúdo. Isso evita que a aprendizagem fique travada por egress/proxy, mantendo o aceite humano antes de influenciar agentes.

O operador vê antes do aceite:

- resumo da vulnerabilidade aprendida;
- quantidade de técnicas recebidas;
- fases, skills e ferramentas sugeridas;
- `steps_to_reproduce`, usado como aprendizado de exploração/reprodução;
- `impact`, que será levado para o relatório;
- `remediation`, que será levado para o relatório;
- `learned_mission`, que descreve como a missão deve se adaptar;
- `learned_prompt`, que é o trecho proposto para orientar os agentes;
- lista de técnicas com sinais de evidência e passos seguros de validação.

Somente registros com status `accepted` entram no prompt do supervisor em `ACCEPTED VULNERABILITY LEARNING`. Registros pendentes ou rejeitados ficam armazenados para auditoria, mas não alteram o comportamento dos agentes. A tela permite aceite individual e aceite/rejeição em lote: selecione os aprendizados pendentes no histórico e use `Aceitar selecionados` ou `Rejeitar selecionados`. O endpoint usado é `POST /api/learning/vulnerabilities/bulk-review`.

Quando um agente identifica uma possível vulnerabilidade, os aprendizados aceitos são comparados com o finding por tipo de vulnerabilidade, título, ferramenta, fase, skill e evidência observada. Se houver correspondência, o finding recebe em `details`:

- `learning_match`: qual aprendizado aceito foi aplicado;
- `reproduction_playbook`: missão, prompt delta, técnicas, ferramentas Kali recomendadas, passos seguros de validação e critérios de aceite;
- `learned_steps_to_reproduce`, `learned_impact` e `learned_remediation`: campos preservados para enriquecer o relatório;
- `repro_steps`: passos que o agente deve tentar reproduzir;
- `technical_evidence_expected`: sinais que precisam aparecer na evidência;
- `proof_pack_required=true`.

Esse enriquecimento é usado em `risk_assessment` e `evidence_adjudication`. Se um achado crítico/alto não tiver prova suficiente, ele entra em `validation_backlog` com o playbook aprendido para que o próximo ciclo priorize as ferramentas e passos corretos. O relatório preserva esses campos em `Finding.details`, permitindo mostrar não só o achado, mas também como ele foi reproduzido ou o que faltou para comprovação.

## Workers e Filas

Os workers sao especializados por fase, mas todos chamam o mesmo executor Kali. Cada grupo tem contrato próprio em `backend/app/workers/worker_groups.py`:

- `mission`: objetivo operacional do agente;
- `techniques`: técnicas que o agente deve aplicar;
- `phases`: fases Cyber Kill Chain/Pxx sob responsabilidade;
- `evidence_focus`: quais evidências precisa produzir;
- `decision_rules`: regras de promoção, skip e prova;
- `tools`: ferramentas Kali permitidas/esperadas para aquele grupo.

Esses contratos aparecem em `GET /api/worker-manager/groups`, em `GET /api/worker-manager/pipeline`, no prompt do supervisor em `WORKER / AGENT MISSIONS` e no resultado de execução como `agent_profile`.

| Worker | Filas principais | Ferramentas esperadas |
| --- | --- | --- |
| `worker_scope` | `scan.unit`, `scan.scheduled`, `worker.*.scope_validation` | Sem tools ofensivas; escopo e entrada |
| `worker_recon` | `worker.*.reconnaissance` | subfinder, amass, dnsx, shuffledns, assetfinder, alterx, naabu, nmap, masscan, httpx, whatweb, wafw00f, curl-headers, sslscan, testssl, katana, hakrawler, gau, waybackurls, gospider, arjun, paramspider |
| `worker_weaponization` | `worker.*.weaponization` | nuclei, nmap-vulscan, shodan-cli, theHarvester, h8mail, trufflehog, gitleaks, subjack |
| `worker_delivery` | `worker.*.delivery` | ffuf, gobuster, feroxbuster, dirsearch, arjun, paramspider |
| `worker_exploitation` | `worker.*.exploitation` | nuclei, sqlmap, dalfox, wapiti, wpscan, nikto, interactsh-client |
| `worker_installation` | `worker.*.installation` | hydra, medusa, crackmapexec, jwt_tool |
| `worker_c2` | `worker.*.command_control` | nuclei, interactsh-client, testssl |
| `worker_actions` | `worker.*.actions_on_objectives` | semgrep, bandit, trufflehog, gitleaks, retire, trivy |
| `worker_reporting` | `worker.*.reporting` | Sem CLI ofensiva; consolidacao |

`backend/app/workers/worker_groups.py` e a fonte canonica dos grupos, prioridades e aliases legados.

## Perfis Kali

Cada ferramenta executavel pelo runner precisa de um profile YAML. Os perfis atuais ficam em:

```text
kali-runner/profiles/reconnaissance.yaml
kali-runner/profiles/weaponization.yaml
kali-runner/profiles/delivery_exploitation.yaml
kali-runner/profiles/post_exploitation.yaml
```

Cada profile define:

```yaml
nuclei_cves:
  tool: nuclei
  category: vuln
  phase: WEAPONIZATION_SIMULATION
  description: "CVE & misconfiguration template-driven scan."
  cmd: ["nuclei", "-u", "{url}", "-silent", "-jsonl"]
  timeout: 900
  parser: jsonl
```

Campos relevantes:

| Campo | Funcao |
| --- | --- |
| `tool` | Nome humano/canonico da ferramenta |
| `category` | Recon, vuln, osint, exploit, code etc. |
| `phase` | Fase Cyber Kill Chain |
| `description` | Explicacao usada para operacao e catalogo |
| `cmd` | Array de argv, sem shell string |
| `timeout` | Timeout por ferramenta |
| `parser` | `raw`, `lines`, `json` ou `jsonl` |
| `requires_env` | Variaveis obrigatorias; se ausentes, o job vira `skipped` |
| `stdin_template` | Entrada padronizada quando a ferramenta exige stdin |
| `allowed_return_codes` | Codigos que ainda contam como sucesso |
| `skip_if_output_contains` | Marcadores que transformam falha em skip explicado |

## Modelo de Dados e Visibilidade

| Entidade | Onde nasce | O que guarda | Onde aparece |
| --- | --- | --- | --- |
| `ScanJob` | `POST /api/scans` | alvo, status, progresso, estado LangGraph, report_v2 | Scans, Jobs Registry, Phase Monitor, Reports |
| `ScanLog` | worker/grafo/validacao | logs temporais por scan | Scans, Targets, WebSocket, Worker Logs |
| `ExecutedToolRun` | `_run_tools_and_collect()` | ferramenta, alvo, status, erro, tempo | Phase Monitor, Workers, auditoria tecnica |
| `Finding` | pos-processamento do grafo | vulnerabilidade normalizada | Vulnerabilities, Dashboard, Reports |
| `Asset` | persistencia de findings/ativos | host, porta, protocolo, criticidade, last_seen | Dashboard, Targets, Trends |
| `Vulnerability` | upsert por finding | CVE, severidade, CVSS, age, FAIR pillar | Dashboard, Evolution, Reports |
| `AssetRatingHistory` | final do scan | rating temporal por asset | Attack Evolution, Trends |
| `WorkerHeartbeat` | inicio/pulse de worker | worker online, scan atual, fase | Workers |
| `ScanAuditLog` | autonomia/execucao | notas, acoes, observacoes, erros | `/api/scans/{id}/autonomy` |
| Kali job JSON | `kali_runner` | status, comando, stdout/stderr, workdir | `/jobs/{id}`, volume `kali_workspace` |

## Telas e o que cada uma mostra

| Tela | Rota | Visibilidade principal |
| --- | --- | --- |
| Dashboard | `/` | rating consolidado, tendencia, top riscos, ativos, alertas e resumo executivo |
| Targets | `/targets` | alvos sob escopo, scans por target, logs e status |
| Scans | `/scan` | criacao de scan, allowlist, status, progresso, WebSocket e logs |
| Phase Monitor | `/phase-monitor` | cobertura por 22 fases, tools usadas, falhas, skips, gaps e nodes visitados |
| Vulnerabilities | `/vulnerabilidades` | findings filtrados por severidade, target e periodo |
| Attack Evolution | `/evolucao` | evolucao temporal, comparacao, lifecycle e tendencia |
| Reports | `/relatorios` | relatorio por scan/target, persona, severidade minima e comparacao |
| Workers | `/workers` | heartbeats, agentes, filas, workers ao vivo e fase atual |
| Jobs Registry | `/jobs` | scans recentes, status, duracao, findings e audit events |
| Worker Logs | `/worker-logs` | logs administrativos agregados |
| Settings | `/configuracao` | runtime, IA, workers e parametros operacionais |
| Kali Catalog | `/workers` | profiles Kali, binario executavel, worker, skills e fases |

## Phase Monitor: como interpretar

O `Phase Monitor` cruza quatro fontes:

1. `ScanJob.state_data`
2. `ExecutedToolRun`
3. `Finding`
4. catalogo de fases/ferramentas

Campos importantes:

| Campo | Significado |
| --- | --- |
| `tools_expected` | Ferramentas esperadas para a fase |
| `tools_installed` | Alias legado para ferramentas prontas no Kali Runner |
| `tools_uninstalled` | Alias legado para ferramentas sem profile/binario no Kali Runner |
| `tools_available` | Ferramentas esperadas com profile e executavel vivo no Kali |
| `tools_unavailable` | Ferramentas esperadas sem profile ou sem binario no Kali |
| `tools_used` | Ferramentas com pelo menos uma tentativa |
| `tools_success` | Ferramentas com sucesso |
| `tools_failed` | Ferramentas tentadas que falharam em todas as tentativas |
| `tools_skipped` | Ferramentas puladas com explicacao, por exemplo falta de env |
| `tools_missing_unused` | Ferramentas prontas no Kali mas nao tentadas |
| `tools_missing_uninstalled` | Ferramentas esperadas sem profile/binario no Kali |

Quando a coluna de ferramentas aparece em vermelho, normalmente significa uma destas condicoes:

- a ferramenta foi tentada e falhou (`tools_failed`);
- o node foi visitado, mas uma ferramenta pronta no Kali nao foi executada (`tools_missing_unused`);
- uma capability critica nao foi visitada;
- a cobertura das ferramentas prontas no Kali ficou abaixo do alvo.

Isso nao significa que a ferramenta esta no backend. Pode significar erro de profile Kali, timeout, falta de credencial, target sem contexto adequado ou regra de roteamento do agente que encerrou antes de varrer tudo.

## Logs e Auditoria

Fontes principais de logs:

| Source | Conteudo |
| --- | --- |
| `worker` | inicio/fim da execucao, status geral |
| `worker.plan` | plano de execucao apresentado no inicio |
| `worker.trace` | `trace_id` do scan |
| `worker.batch` | lotes de targets |
| `worker.progress_detail` | pulso periodico de progresso |
| `graph` | linhas produzidas pelo LangGraph e execucao das ferramentas |
| `validation` | avaliacao Cyber AutoAgent |
| `llm-risk` | execucao de teste LLM Risk, quando habilitado |
| `ia` | recomendacoes em portugues |

Consultas uteis:

```bash
# Logs de um scan pela API
curl -H "Authorization: Bearer <JWT>" \
  http://localhost:${BACKEND_HOST_PORT:-8000}/api/scans/27/logs

# Logs do container Kali
docker compose --profile dev logs --tail 200 kali_runner

# Logs dos workers
docker compose --profile dev logs --tail 200 worker_recon worker_exploitation
```

## Endpoints Operacionais

| Endpoint | Funcao |
| --- | --- |
| `POST /api/scans` | cria scan |
| `GET /api/scans` | lista scans autorizados |
| `GET /api/scans/{id}/status` | status resumido e progresso |
| `GET /api/scans/{id}/logs` | logs do scan |
| `GET /api/scans/{id}/autonomy` | memoria/autonomia do agente |
| `GET /api/scans/{id}/phase-monitor` | cobertura por fases e tools |
| `POST /api/scans/{id}/stop` | interrompe scan |
| `DELETE /api/scans/{id}` | remove scan |
| `GET /api/jobs/registry` | registro operacional de scans/jobs |
| `GET /api/kali-runner/health` | saude do Kali e mappings |
| `GET /api/kali-runner/catalog` | mapeamento tool -> profile -> worker -> skill/fase |
| `GET /api/kali-runner/profiles` | profiles YAML expostos pelo runner |
| `GET /api/kali-runner/tools` | catalogo vivo do PATH dentro do Kali |
| `GET /api/worker-manager/health` | workers online/offline e scan atual |
| `GET /api/worker-manager/pipeline` | grupos/agentes e pipeline |
| `GET /api/findings/page` | findings paginados |
| `GET /api/dashboard/insights` | dados agregados do dashboard |
| `GET /api/vulnerability-management/dashboard` | evolucao e gestao de vulnerabilidades |
| `GET /api/scans/{id}/report` | relatorio tecnico/executivo |

## Operacao Local

### 1. Preparar `.env`

```bash
cp .env.example .env
```

Variaveis importantes:

| Variavel | Funcao |
| --- | --- |
| `SECRET_KEY` | assinatura JWT |
| `FRONTEND_ORIGIN` / `FRONTEND_ORIGINS` | CORS |
| `VITE_API_URL` | URL publica do backend para o frontend |
| `KALI_RUNNER_URL` | URL interna do runner para backend/workers |
| `SHODAN_API_KEY` | habilita `shodan-cli` |
| `PENTEST_AUTH_USERNAME` / `PENTEST_AUTH_PASSWORD` | habilitam perfis que exigem credencial |

### 2. Subir stack

```bash
docker compose --profile dev up --build -d
```

### 3. Aplicar migracoes

O backend executa `alembic upgrade head` no startup. Para rodar manualmente:

```bash
docker compose --profile dev exec backend alembic -c alembic.ini upgrade head
```

### 4. Validar saude

```bash
docker compose --profile dev ps
curl -fsS http://localhost:${KALI_RUNNER_HOST_PORT:-8088}/healthz | jq
curl -fsS http://localhost:${KALI_RUNNER_HOST_PORT:-8088}/profiles | jq '.count'
curl -fsS http://localhost:${KALI_RUNNER_HOST_PORT:-8088}/tools | jq '.count'
```

### 5. Executar um job direto no Kali Runner

```bash
JOB_ID=$(
  curl -fsS -X POST http://localhost:${KALI_RUNNER_HOST_PORT:-8088}/jobs \
    -H "Content-Type: application/json" \
    -d '{"profile":"curl_headers","target":"https://example.com","scan_id":0,"tool":"curl-headers"}' \
  | jq -r .job_id
)

curl -fsS http://localhost:${KALI_RUNNER_HOST_PORT:-8088}/jobs/$JOB_ID | jq
curl -fsS http://localhost:${KALI_RUNNER_HOST_PORT:-8088}/jobs/$JOB_ID/result | jq
```

### 6. Rebuild seletivo

```bash
# Runner Kali
docker compose --profile dev build kali_runner
docker compose --profile dev up -d --no-deps --force-recreate kali_runner

# Backend e workers
docker compose --profile dev build backend worker_scope worker_recon worker_weaponization worker_delivery worker_exploitation worker_installation worker_c2 worker_actions worker_reporting celery_beat
docker compose --profile dev restart backend worker_scope worker_recon worker_weaponization worker_delivery worker_exploitation worker_installation worker_c2 worker_actions worker_reporting celery_beat
```

### 7. Validar que o backend nao tem ferramentas de analise

A imagem final do backend e dos workers deve conter apenas runtime Python. Nao devem existir `curl`, `wget`, `jq`, `dnsutils`, `nmap`, `nuclei`, `sqlmap` ou scanners equivalentes:

```bash
docker compose --profile dev run --rm backend sh -lc \
  'for t in curl wget jq dig nslookup nmap nuclei sqlmap ffuf nikto; do command -v "$t" >/dev/null && echo "FOUND $t"; done'
```

Saida esperada: nenhuma linha `FOUND`.

## Falhas comuns e como ler

### `GET /jobs/{uuid} 404 Not Found` no Kali

Significa que alguem consultou um job que o runner nao conhece. Hoje o runner persiste jobs em `/workspace/.runner_jobs`, entao isso deve acontecer apenas para IDs realmente antigos/inexistentes.

No backend, dois 404 consecutivos viram:

```text
dispatch_error=runner_lost_job:<uuid>
```

O scan nao deve ficar em polling infinito.

### Ferramenta em vermelho no Phase Monitor

Verifique:

1. `tools_failed`: ferramenta executou e falhou.
2. `last_error`: erro persistido em `ExecutedToolRun`.
3. `evidence_path`: path no Kali com `stdout.txt` e `stderr.txt`.
4. `tools_missing_unused`: pronta no Kali, mas nao tentada pelo agente.
5. `tools_missing_uninstalled`: esperada, mas sem profile/binario no Kali.
6. `requires_env`: profile pode ter virado `skipped` por falta de variavel.

### Runner online, mas ferramenta falha

Investigue:

```bash
docker compose --profile dev logs --tail 200 kali_runner
docker compose --profile dev exec kali_runner which nuclei
docker compose --profile dev exec kali_runner sh -lc 'ls -la /workspace/.runner_jobs | tail'
```

Depois consulte o `workdir` retornado pelo job.

### Worker aparece stale/offline

Verifique:

```bash
docker compose --profile dev ps
docker compose --profile dev logs --tail 200 worker_recon
curl -H "Authorization: Bearer <JWT>" \
  http://localhost:${BACKEND_HOST_PORT:-8000}/api/worker-manager/health
```

Se houver scan `running` sem task ativa, use a reconciliacao/orphan requeue pelo endpoint administrativo ou pela tela de workers/settings.

## Estrutura relevante do repositorio

```text
backend/
  app/api/routes_scans.py          # scans, status, logs, reports, phase-monitor
  app/api/routes_management.py     # users, settings, workers, kali health/profiles/tools/catalog
  app/graph/workflow.py            # LangGraph supervisor e nodes
  app/graph/mission.py             # 9 mission items + 22 fases tecnicas
  app/graph/kill_chain.py          # mapeamento Cyber Kill Chain para UI
  app/services/kali_executor.py    # cliente HTTP do Kali Runner
  app/services/kali_catalog.py     # catalogo vivo Kali -> profile -> worker -> skill
  app/services/worker_dispatcher.py# unica rota de execucao: Kali
  app/services/phase_monitor.py    # cruzamento state_data + runs + findings
  app/services/tool_catalog.py     # catalogo narrativo usado pelos agentes
  app/workers/tasks.py             # execucao Celery do scan
  app/workers/worker_groups.py     # grupos, filas, ferramentas e prioridades

kali-runner/
  Dockerfile
  runner.py                        # API FastAPI que executa CLI no Kali
  profiles/*.yaml                  # profiles de ferramentas

frontend/src/
  components/Navbar.jsx            # badge de saude do Kali
  components/Sidebar.jsx           # navegacao
  pages/DashboardPage.jsx
  pages/ScansPage.jsx
  pages/PhaseMonitorPage.jsx
  pages/WorkersPage.jsx
  pages/JobsRegistryPage.jsx
  pages/VulnerabilitiesPage.jsx
  pages/AttackEvolutionPage.jsx
  pages/ReportsPage.jsx
```

## Comandos de verificacao

```bash
# Sintaxe Python dos pontos centrais
python3 -m py_compile \
  backend/app/services/kali_executor.py \
  backend/app/services/kali_catalog.py \
  backend/app/services/worker_dispatcher.py \
  backend/app/services/phase_monitor.py \
  backend/app/graph/workflow.py \
  kali-runner/runner.py

# Config final do compose
docker compose --profile dev config --services

# Saude runtime
docker compose --profile dev ps
curl -fsS http://localhost:${KALI_RUNNER_HOST_PORT:-8088}/healthz | jq
```

## Documentacao complementar

- `docs/RUNBOOK.md`: rotinas de operacao e troubleshooting.
- `docs/SENIOR_ANALYST_FRAMEWORK.md`: contrato do analista senior e evidencia.
- `docs/CYBER_AUTOAGENT_ALIGNMENT.md`: alinhamento com modelo Cyber AutoAgent.
- `docs/KALI_EXECUTOR_PROPOSAL.md`: contexto da migracao para executor Kali.

## Status atual da plataforma

Validado em scan **#34** contra `http://juice-shop:3000` (OWASP Juice Shop):

| Metrica | Valor |
| --- | --- |
| Containers ativos | 16/16 healthy |
| Kali runner | reachable - 4 077 tools detected - 48 profiles |
| Backend image | 4.06 GB (sem qualquer ferramenta de pentest) |
| Workers (9) | 0 ferramentas de pentest cada |
| Tools executadas no scan | 43 (25 success - 18 fail por DNS/timeout esperado) |
| Findings persistidos | 20 (11 medium - 7 low - 2 info) |
| Capabilities concluidas | 8/8 |
| Cyber Kill Chain | 9/9 fases visitadas |
| Evidencia arquivada | `/workspace/34/{tool}/{job_id}/` no volume `kali_workspace` |

### Como provar que a refatoracao Kali-only esta ativa

```bash
# Backend NAO tem tools de pentest:
docker exec pentest_backend bash -c \
  'for t in subfinder nuclei nmap hydra sqlmap; do printf "%-12s " $t; command -v $t >/dev/null && echo INSTALLED || echo MISSING; done'
# subfinder    MISSING
# nuclei       MISSING
# nmap         MISSING
# hydra        MISSING
# sqlmap       MISSING

# Workers NAO tem tools de pentest:
docker exec pentest_worker_recon bash -c 'command -v subfinder || echo MISSING'
# MISSING

# Kali runner tem TUDO:
curl -fsS http://localhost:8088/healthz | jq
# { "status": "ok", "profiles_loaded": 48, "kali_tools_detected": 4077, ... }

docker exec pentest_kali_runner bash -c \
  'for t in subfinder nuclei nmap hydra sqlmap nikto httpx katana paramspider; do printf "%-12s " $t; command -v $t >/dev/null && echo INSTALLED || echo MISSING; done'
# subfinder    INSTALLED
# nuclei       INSTALLED
# nmap         INSTALLED
# ... (10/10)
```
