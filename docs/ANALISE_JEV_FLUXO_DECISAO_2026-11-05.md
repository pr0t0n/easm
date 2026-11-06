# Análise — Onde o Jev pode substituir a tomada de decisão do LLM (LangGraph + MCP + RAG)

Data: 2026-11-05
Pergunta: **podemos** usar o Jev (TypeSafe) em pontos do fluxo onde hoje o LLM (Ollama) toma decisão? Onde sim, onde não, e com que cuidados.
Status do Jev na plataforma: **não existe** — esta é uma análise de viabilidade.

---

## 1. O que o Jev é (e o que não é)

Fontes: artigos de terceiros (besthub, wavect, infinisynapse). Nenhuma documentação oficial da TypeSafe foi lida — **validar com a API reference antes de codar**.

| Aspecto | O que se sabe |
| --- | --- |
| Natureza | Modelo de decisão "System One": recebe `state` + perguntas fechadas e devolve **respostas tipadas**, não texto |
| Primitivas | `Choice` (uma entre opções declaradas + probabilidade por opção), `Score` (nível numa escala declarada), `Noul` (sim/não com P(sim)) |
| Chamada | HTTP `POST api.typesafe.ai/v1/systemone` com `{model, state, questions}`; várias perguntas por chamada, avaliadas em paralelo e independentes |
| Limites | ~64k de contexto, 32k para state + maior pergunta, só texto (segundo resumo de terceiros) |
| Latência | 70–500 ms (vendor); teste de terceiro: mediana ~0,7 s com rede |
| Custo | US$ 0,042 / M tokens de entrada, saída grátis (vendor) |
| Deploy | **Só cloud**. Sem on-prem citado. ZDR (zero retention) para enterprise (vendor) |
| Determinismo | **Não é determinístico**: a interface é tipada, o julgamento é probabilístico. Confiança calibrada é objetivo do treino, não garantia |
| Ruim para | Gerar texto, raciocínio longo, planejamento multi-etapa, aritmética/comparação exata, **permissão/autorização** ("confiança não é autorização") |
| Idioma | Melhor em inglês; outros idiomas não comprovados |
| Prompt injection | Saída em enum **reduz** o estrago, mas não neutraliza: conteúdo no `state` pode enviesar a resposta |

**Regra de arquitetura que sai disso** (consenso das fontes):

```
código   → escopo, guardrail, permissão, orçamento, aritmética, efeitos colaterais
Jev      → julgamento semântico fechado: "isto é X?", "qual destas opções?", "quanto?"
LLM      → texto para humano e raciocínio aberto
humano   → zona cinzenta e alto impacto
```

---

## 2. Onde está o LLM hoje no fluxo

```
                ┌───────────────── LangGraph ─────────────────┐
 scan ──► supervisor (roteamento: CÓDIGO) ──► skill_pipeline ──┼──► MCP (CÓDIGO) ──► Kali
                │                               │ [3] decide_next_technique (LLM)
                │                               ▼
                │                        skill_execution_engine [8] (LLM)
                └──────────────────────────────────────────────┘
 operator (motor vivo) ── fila P01–P22 (CÓDIGO)
        ├─ [1/2] raciocínio entre fases (LLM)   ├─ [4] metodologia (LLM)
        ├─ [5] ranking de táticas (LLM)          └─ [6] llm_operator (LLM)
 RAG (kali-rag lexical / pgvector): CÓDIGO + embeddings
 pós-scan: [10] adjudicação advisory · [7] recomendações · [9] grader LLM-alvo · [11] narrativa
 offline:  [12] triagem/síntese do corpus H1 (~10k)
```

Todos os pontos LLM rodam no mesmo `llama3.2:3b` em CPU (`core/config.py:78-89`), `OLLAMA_NUM_PARALLEL=1` → **uma fila serial**, ~60 s por chamada segundo o comentário em `supervisor_runtime.py:370`. A "confiança" que o 3B devolve é um número inventado, não calibrado.

---

## 3. Veredito por ponto de decisão

Legenda: **JEV** = bom encaixe · **JEV após código** = o código monta candidatos, o Jev julga · **CÓDIGO** = é regra, nem Jev nem LLM · **LLM** = continua generativo.

| # | Ponto (arquivo) | Decisão real | Encaixe | Pergunta(s) Jev | Dado sai do ambiente? |
| --- | --- | --- | --- | --- | --- |
| 12 | Triagem H1 (`vulnerability_learning_service.py:1917`) | Família, aceitar/rejeitar, duplicado, confiança | **JEV — melhor caso** | `Choice` família (catálogo de skills) · `Noul` "seguro para aceite automático?" · `Noul` "duplica learning X?" · `Score` qualidade 1–5 | Não: reports públicos |
| 9 | Grader de LLM-alvo (`llm_risk_service.py:132`) | pass/fail de jailbreak/vazamento | **JEV após código** | Código: canário + regex de segredo. Jev: `Noul` "a resposta cumpriu a instrução proibida?" · `Score` severidade | Sim: resposta do alvo |
| 8 | Plano de skill (`skill_execution_engine.py:418`) | Quais endpoints × qual template | **JEV após código** | Para cada par (endpoint, template): `Noul` "endpoint é relevante para a técnica?"; código pega top-k ≤ 10 por P(sim) | Sim: URLs do alvo |
| 10 | Adjudicação advisory (`finding_adjudication.py:446`) | Veredito proposto, próxima ação, evidências | **JEV** (continua advisory) | `Choice` veredito (`ALLOWED_PROPOSED_VERDICTS`) · `Choice` próxima ação (`ALLOWED_ACTIONS`) · `Noul` por evidência "sustenta o achado?" | Sim: dossiê |
| 3 | Técnica do supervisor (`supervisor_runtime.py:357`, `skill_pipeline.py:724`) | Escolher técnica, bloquear/seguir | **CÓDIGO** hoje; **JEV** se houver >1 técnica | `Choice` técnica entre as do playbook. Escopo/risco **ficam no código** | Sim: contexto do alvo |
| 1/2 | Raciocínio entre fases (`offensive_operator_runner.py:1452`, `scan_intelligence.py:1207`) | Ferramentas extras para fases futuras | **JEV após código** (depois de corrigir, ver §4) | Código: matriz tech→ferramentas candidatas. Jev: `Noul` por candidata "a evidência justifica rodar X em PYY?" | Sim |
| 6 | `llm_operator` (`llm_operator.py:340`) | Propor (ferramenta, alvo, fase) | **JEV após código** | Código enumera candidatos do allowlist × alvos conhecidos; Jev `Score` prioridade 1–10 de cada | Sim |
| 5 | Ranking de táticas (`pentest_strategy_service.py:348`) | Ordenar ≤12 táticas | **CÓDIGO** (ou Jev `Score` como desempate) | `Score` relevância por tática; ordenação no código | Sim |
| 4 | Metodologia P01–P22 (`methodology_planner.py:107`) | Skills/tools por fase (JSON de 22 fases) | **JEV após código** | Quebrar em perguntas independentes em lote: `Noul` "skill S aplica ao alvo?" só para skills condicionais; resto sempre entra (perfil agressivo) | Sim |
| — | Aplicabilidade de fase no LangGraph (decisão §0.4 do `LANGGRAPH_BRAIN_PLAN.md`) | "Fase PXX entra?" com justificativa | **JEV — encaixe novo** | `Noul` "evidência justifica PXX?" com P(sim) gravado no trace como justificativa; limiar no código | Sim |
| 7 | Recomendações (`ai_recommendation_service.py:118`) | Texto de mitigação + prioridade | **LLM/catálogo** (texto). Prioridade = **CÓDIGO** (severidade/CVSS) | — | — |
| 11 | Narrativa / resumo CISO (`attack_narrative.py:143`, `reporting.py:117`) | Prosa executiva | **LLM** | — | — |
| — | Escopo, guardrail, budget, CVSS, veredito final (`deterministic_verdict`), MCP, RAG | — | **CÓDIGO, não mexer** | Jev nunca autoriza | — |

### Por que estes encaixam

O padrão comum aos bons candidatos: **o código já valida a saída do LLM contra uma lista fechada** (allowlist de tools, enum de veredito, índice de endpoint, catálogo de família). Ou seja, a decisão já é um `Choice`/`Noul`, só que pedida em JSON livre a um 3B e depois filtrada. O Jev pergunta exatamente isso, com tipo garantido e probabilidade, sem parser de JSON e sem fallback por "JSON inválido".

### Por que estes não encaixam

- **Escopo/risco/permissão**: o próprio fornecedor diz que confiança não é autorização. O `authorized_scope` já é calculado por `is_host_in_scope` (SEC-005) e deve continuar sendo gate duro.
- **Metodologia como JSON de 22 fases**: planejamento multi-etapa. Só funciona se quebrado em perguntas pequenas e independentes.
- **Texto** (narrativa, recomendação): o Jev não gera texto.

---

## 4. Pré-requisito encontrado no fluxo (antes de qualquer Jev)

O raciocínio entre fases do operator (`_append_llm_reasoning_decision`, `offensive_operator_runner.py:1626`) é chamado em 3 caminhos (`:2431`, `:4447`, `:6897`), **sempre** chama o Ollama (ignora `LLM_REASONING_ENABLED=false` do compose) e o resultado `llm_injected_tools` é gravado em `:1695` e **nunca lido** por ninguém. Trocar isso por Jev deixaria a chamada mais rápida, mas continuaria inútil. A ordem certa:

1. Desligar/remover a chamada atual.
2. Decidir se "injetar ferramentas por evidência" é desejado; se sim, criar o **consumidor** na fila de work items.
3. Só então colocar o Jev como juiz dos candidatos.

Da mesma forma, no ponto [3] o LLM recebe uma lista com **uma** técnica (`skill_pipeline.py:765`): não há escolha para o Jev fazer. Primeiro o planner precisa enviar as N técnicas do playbook.

---

## 5. Restrições que decidem o "podemos?"

| Restrição | Impacto | Mitigação |
| --- | --- | --- |
| **Jev é só cloud** e a plataforma foi desenhada local (decisão §0.3 do plano: Ollama local, sem licença externa) | Pontos que enviam **dados de cliente** (hostnames, endpoints, respostas, findings) passam a sair do ambiente | Contrato com ZDR; aprovação do cliente/escopo; redação (`redact`) antes do envio; começar pelos pontos **sem dado de cliente** (H1) |
| Conteúdo ofensivo (payloads, PoCs) no `state` | Possível recusa/política de uso do fornecedor | Validar na fase de piloto; enviar descrição, não payload |
| **Não determinístico** | Hoje o operador espera reprodutibilidade (`llm_determinism.py`, temperature 0 + seed) | Gravar `(question_hash, answer, probability)` no trace; decisão final por limiar no código; cache por hash da pergunta dentro do scan |
| Melhor em inglês | Prompts atuais em PT-BR | Escrever `instructions`/`criteria` em inglês; texto do alvo vai como está |
| Prompt injection no `state` | Banner/endpoint/resposta do alvo podem enviesar | Manter `wrap_untrusted`/`normalize_adversarial_text`; Jev só **propõe**, código aplica allowlist e escopo; testes adversariais |
| Dependência externa no caminho quente | Scan não pode parar se a API cair | Interface única com fallback: `jev → regra determinística` (nunca bloqueia) |
| Calibração não comprovada | P(sim)=0,8 pode não significar 80% | Calibrar por tipo de pergunta com rótulos reais (ver §6.3) antes de enforcement |

**Resposta direta: sim, podemos** — em 7 dos 12 pontos, desde que (a) o Jev só **proponha** e o código decida por limiar, (b) o piloto comece onde não há dado de cliente, e (c) exista fallback determinístico.

---

## 6. Como encaixar

### 6.1 Uma porta de decisão única

Hoje cada serviço tem seu próprio `_call_llm`/`_call_ollama` (7 implementações). Proposta: `backend/app/services/decision_port.py`

```python
answer = decide(
    question_id="skill_endpoint_relevance",      # tipo de pergunta (para calibração/limiar)
    kind="noul",                                  # noul | choice | score
    state=wrap_untrusted(...),                    # contexto do alvo, quarentenado
    instructions="Is this endpoint relevant to the technique?",
    options=None,                                 # para choice
    threshold=0.7,                                # por question_id, em config
    fallback=lambda: rule_based_relevance(...),   # determinístico, sempre disponível
)
# answer = {value, probability, source: "jev"|"rule", below_threshold: bool}
```

Backends plugáveis: `rule` (default), `jev`, `ollama`. Modo `shadow`: roda Jev em paralelo, **usa** a regra, grava os dois para comparar. Abaixo do limiar → `needs_review` / regra, nunca palpite.

### 6.2 Piloto em ordem

| Ordem | Ponto | Por quê primeiro | Critério de sucesso |
| --- | --- | --- | --- |
| 1 | **Triagem H1 (~10k)** | Dados públicos (sem problema de egress), offline (latência irrelevante), destrava o corpus travado em `pending_review` (§3.2 do plano). Custo estimado (preço vendor): ~10k × ~3k tokens ≈ 30 M tokens ≈ **US$ 1–2** | Concordância com amostra de 200 revisada por humano; zona cinzenta (P entre limiares) vai para revisão |
| 2 | Grader de LLM-alvo [9] (shadow) | Julgamento semântico puro, onde o heurístico atual erra (recusa contendo "ignore" vira `fail`) | Recusas → pass; canário vazado → fail; zero falso fail em conjunto de teste |
| 3 | Relevância endpoint×template [8] (shadow) | Muitas perguntas pequenas e independentes, Jev em lote | Mesmos achados que o plano LLM, com latência < 2 s |
| 4 | Aplicabilidade de fase no LangGraph (shadow) | Implementa a §0.4 do plano com justificativa mensurável no trace | Divergência Jev × regra revisada; nenhuma fase obrigatória pulada |
| 5 | Adjudicação advisory [10] | Já é advisory e validada fail-closed; troca direta | `proposed_verdict` concorda com `final_verdict` ≥ taxa atual |

Itens 1, 2 e 3 se encaixam sem depender do motor LangGraph estar em produção.

### 6.3 Calibração com rótulos que já existem

A plataforma já produz verdade de referência: `final_verdict` da adjudicação determinística, revisões humanas de learnings (`update_learning_review`) e resultados de re-teste (`/mcp/retest`). Usar esses rótulos para medir se P(sim) do Jev é calibrada por `question_id` antes de deixar qualquer limiar decidir sozinho.

### 6.4 O que muda em performance (estimativa)

| | Hoje (Ollama 3B CPU, fila serial) | Com Jev |
| --- | --- | --- |
| Latência por decisão | ~60 s (comentário no código) | 0,07–0,5 s vendor; ~0,7 s medido por terceiro |
| Paralelismo | 1 (`OLLAMA_NUM_PARALLEL=1`) | perguntas em lote por chamada |
| Falha de parse | frequente (fallbacks por JSON inválido em todos os call sites) | não existe (saída tipada) |
| Confiança | número gerado pelo modelo | probabilidade calibrável |
| RAM da VM | Ollama disputa memória (histórico de OOM) | sai do host |

O Ollama continua para o que é texto (narrativa, recomendação), fora do caminho quente.

---

## 7. Pendências antes de decidir

1. Ler a documentação oficial da TypeSafe (formato real da API, limites, política de conteúdo ofensivo, ZDR, região dos dados). As fontes desta análise são de terceiros e divergem no formato do SDK.
2. Confirmar com o jurídico/contrato se dados de alvo de cliente podem ir para API externa.
3. Remover a chamada morta do operator (§4) — independe do Jev.
4. Montar o conjunto rotulado de H1 (200 itens) para o piloto 1.

### Fontes sobre o Jev

- [JEV Explained: The Millisecond Decision Engine for AI Agents](https://www.besthub.dev/articles/jev-explained-the-millisecond-decision-engine-for-ai-agents-eea13a0db554)
- [Jev: Separating Semantic Judgment from Generation in LLM Applications](https://www.besthub.dev/articles/jev-separating-semantic-judgment-from-generation-in-llm-applications-24e9caab2097)
- [jev ai decision model review (wavect)](https://wavect.io/blog/jev-ai-decision-model-review/)
- [Jev vs LLM: Which Model Should Your Agent Use? (infinisynapse)](https://infinisynapse.com/en/blog/jev-vs-llm)
