# Plano de Ação — Validação de Findings CANDIDATE e Melhoria da Eficácia dos Testes

Data: 2026-11-07
Origem: retest pós-refatoração (scans #3/#4/#5, alvo www.example.com). Baseline do problema: scan #5 terminou com 44 findings, dos quais **24 ficaram em `candidate`** sem adjudicação completa (só 34 de 44 findings foram adjudicados; 10 nem entraram no gate).

## 1. Diagnóstico — por que candidates sobram

Conjunto real de candidates do scan #5 (por ferramenta): nmap 6, zap-baseline 5, httpx 3, katana/theharvester/gospider/masscan/nikto/curl-headers/nuclei-misconfiguration/whatweb/wafw00f 1 cada.

Causas identificadas (com evidência desta rodada):

| Causa | Evidência | Onde atuar |
|---|---|---|
| Contrato de evidência exige semântica de exploração (proof pack, baseline_vs_exploit) de achados **passivos** | portas abertas, headers, tecnologia detectada viram inconclusive/blocked | `evidence_contract_service` + `deterministic_verdict` |
| Fams sem validator automático caem em `needs_human_review` sem tentativa | wire_not_materializable (scan #2: 19/22) — mitigado, mas sem validador ainda sobra | `poc_validator._select_validation_tool` + catálogo de validators |
| Sweep de adjudicação não cobre 100% dos findings | scan #5: 10/44 findings nunca adjudicados | loop de revalidação pós-scan |
| OSINT de terceiros (shodan/theharvester) entra como candidate sem confirmação cruzada | "6 e-mails corporativos" no example.com (FP suspeito no scan #2) | validador de corroboração multi-fonte |
| Sem política de "reprodução passiva": re-executar a mesma probe e comparar | um re-scan do nmap/httpx confirmaria porta/header de forma barata | novo validator `passive_reprobe` |

Princípio central: **achado passivo com evidência reproduzível não precisa de semântica de exploit para sair de candidate** — precisa de (a) re-execução da probe e (b) concordância do resultado. Exploit só é exigido de achados ativos (injection, auth bypass, etc.).

## 2. Linhas de ação

### LA-1 — Contrato de evidência por classe (passivo vs ativo)
- Estender `evidence_contract_service` com classe `passive_observation`: requirements = [`positive_reproduction`], onde a reprodução = re-execução da mesma ferramenta/probe com mesmo resultado (mesma porta aberta, mesmo header ausente, mesmo banner).
- `deterministic_verdict`: findings de classe passiva com tool output como artifact e re-probe concordante → `confirmed` (confiança 0.9); re-probe discordante → `refuted` (o serviço mudou/é volátil).
- Achados ativos (famílias injection/authz/rce...) **mantêm** o contrato atual (proof pack, baseline_vs_exploit) — sem relaxamento.
- **Entrega**: severidade de esforço média; arquivo: `evidence_contract_service.py`, `finding_adjudication.py`.

### LA-2 — Validadores por família (fechar o mapa de families → tool)
- Tabela declarativa `FAMILY_VALIDATORS` (novo módulo ou extensão de `poc_validator`): família → validator + expected_signals.
  - `exposed_service` (portas nmap/naabu/masscan) → `passive_reprobe` (re-executa a probe de porta; concordância confirma)
  - `security_headers` → nuclei-headers (✅ já funciona — scan #5 confirmou)
  - `tech_fingerprint` (whatweb/httpx/wafw00f) → `passive_reprobe` + concordância entre duas fontes (whatweb × httpx)
  - `osint_exposure` (shodan/theharvester) → corroboração: segunda fonte independente confirma; fonte única com dado improvável (domínio IANA, e-mail sem MX) → `refuted` com reason `uncorroborated_osint`
  - `exposed_files`/`secrets` → nuclei-exposure/gitleaks (existente)
- **Entrega**: alta; elimina a maioria dos `needs_human_review`.

### LA-3 — Validator `passive_reprobe` (novo)
- Work item P21 (contexto internal, read-only) que re-executa a probe original (comando gravado em `details.execution.command`) e compara o sinal essencial (porta/header/banner).
- Concordância → wire `completed`/positivo; discordância → `refuted` com `ephemeral_service` ou `header_changed`.
- Barato: probes de segundos, sem payload; respeita guardrails SEC-004/005 e budget de wires.
- **Entrega**: média; arquivo: `poc_validator.py` + perfil kali (reuso de nmap/httpx/curl existentes).

### LA-4 — Sweep pós-scan de candidatos órfãos
- Job agendado (celery beat, pós-terminal do scan): adjudica **todo** finding `candidate`/`hypothesis` que não tem adjudicação no ciclo corrente (fecha o gap dos 10/44).
- Reusa `adjudicate_finding(force=False)` + `retry_blocked_post_scan_wire` (já existe, pouco acionado).
- **Entrega**: baixa; arquivo: `workers/tasks.py` (novo task `sweep_orphan_candidates`).

### LA-5 — JEV como priorizador do backlog (shadow primeiro)
- Integração real do jev-local via `decision_port` no ponto de maior valor: **ordenar quais candidates validar primeiro** quando o budget de wires é limitado (`MAX_WIRES_PER_FINDING`/fila P21).
- `Score` 1-10 de prioridade de validação (impacto × confiabilidade da fonte × facilidade de reprodução); `Noul` por candidato "a evidência disponível justifica gastar wire?".
- Modo shadow: JEV pontua, regra decide; calibrar com os vereditos já produzidos (rótulos reais do scan #5).
- **Entrega**: média-alta; depende do `decision_port.py` (ainda não existe). É o primeiro consumidor real do JEV no fluxo de scan.

### LA-6 — Métricas de eficácia (fecha o ciclo)
- Por scan: taxa candidate→confirmed, candidate→refuted, % FP refutados, tempo até veredito, wires por finding, custo (tempo de tool) por confirmação.
- Rastrear grade do quality gate scan a scan; meta: candidate residual < 20% e zero candidates sem adjudicação.
- Fonte: `finding_adjudications` + `pentest_outcome_learning` (já gravam outcomes por dimensão).

## 3. Ordem de execução sugerida

| Fase | Itens | Por quê | Critério de pronto |
|---|---|---|---|
| 1 (quick wins) | LA-4 + LA-1 | Fecha o buraco imediato (órfãos + semântica passiva) sem nova infra | Sweep zera órfãos; porta aberta com re-probe vira confirmed/refuted em vez de inconclusive |
| 2 | LA-2 + LA-3 | Expande o que é validável automaticamente | Tabela de families cobre 100% dos candidates do scan #5; `needs_human_review` só para zona cinzenta real |
| 3 | LA-5 | JEV entra em produção (shadow→ativo) | Concordância JEV × regra ≥ 80% na calibração; latência por decisão < 2s |
| 4 | LA-6 contínuo | Medição permanente | Dashboard/métricas por scan; regressão bloqueia merge |

## 4. Riscos e cuidados

- **Não relaxar o gate de achados ativos**: confirmar SQLi/XSS sem exploit real destruiria a credibilidade do relatório. A distinção passivo/ativo é a fronteira crítica do LA-1.
- **Re-probe de OSINT** não deve re-consultar APIs externas em volume (rate limit/custo) — limitar a corroboração por segunda fonte já coletada (ex.: httpx × whatweb), não nova chamada Shodan.
- **JEV continua advisory**: propõe prioridade; limiar e execução ficam no código (regra dura do projeto: JEV propõe, código dispõe).
- Voltar a rodar o teste do alvo www.example.com (mesmo protocolo do retest) como benchmark de regressão após cada fase.

## 5. Pendências conhecidas que este plano não cobre

- `report_v2`/`executive_summary` não persistidos no scan #5 (P22 não gravou) — investigar separadamente.
- Rótulo `current_step` defasado do lote real — cosmético, baixa prioridade.
- 3 blocked + 12 inconclusive residuais do scan #5: após LA-1/LA-2, reavaliar quanto é piso real de evidência vs. contrato mal calibrado.
