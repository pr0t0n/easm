# Aprendizado HackerOne — formato, divisão pelas 22 skills, RAG e MCP

Como a plataforma **ScriptKidd.o** (pentest automatizado) transforma relatórios
públicos do HackerOne em conhecimento operacional, organiza esse conhecimento
pelas **22 fases técnicas (P01–P22)**, e como ele é **recuperado (RAG)** e
**executado (MCP → Kali)**.

> Nota de arquitetura (importante): o RAG **não vive mais no MCP**. O
> conhecimento migrou para o backend em **pgvector**; o `mcp_server` hoje é
> apenas a **ponte de execução** para o Kali. Os dois papéis estão detalhados
> nas seções "Como vira RAG" e "Relação com o MCP".

---

## 1. Visão geral do fluxo

```
URL HackerOne ──► ingestão (/reports/{id}.json) ──► extrai 3 blocos
   (Steps to reproduce · Impact · Remediation)
        │
        ▼
 LLM local (Ollama) sintetiza ──► learned_mission + learned_prompt + técnicas
        │
        ▼
 VulnerabilityLearning (status=pending_review)  ──►  ACEITE HUMANO
        │                                              (pending_review → accepted)
        ▼
 Indexação no RAG (pgvector, bge-small 384-dim)  ─── por fase P01–P22 + skill + worker
        │
        ▼
 Supervisor consulta o RAG ao decidir a próxima técnica (skill_memory)
        │
        ▼
 Execução via MCP ──► Kali runner ──► finding enriquecido com learning_match
```

---

## 2. Formato do aprendizado HackerOne (ingestão)

Origem: `backend/app/services/vulnerability_learning_service.py`.

- A tela **Aprendizado** aceita uma ou várias URLs públicas (separadas por `;`,
  quebra de linha ou espaço).
- Para reports do HackerOne, a plataforma tenta primeiro o **endpoint JSON
  público**: `https://hackerone.com/reports/{id}` → `…/reports/{id}.json`
  (`_hackerone_json_candidate`). O HTML da página é **fallback**.
- Do report são extraídos **três blocos canônicos**:
  - **Steps to reproduce** → como reproduzir/explorar (de forma defensiva);
  - **Impact** → impacto original, preservado para o relatório;
  - **Remediation / Suggested Mitigation** → orientação de correção.
- A busca tem **guardrails contra SSRF** (não é um fetch arbitrário).
- Em seguida, o conjunto vai para a **LLM local (Ollama)**, que sintetiza:
  **missão**, **prompt** e **técnicas operacionais**.

Também há **ensino manual** (operador escolhe classe de ataque/skill, fase
P01–P22, descreve a técnica) e a ação **"Antecipar catálogo"**, que cria
aprendizados pendentes para famílias conhecidas (XSS, SQLi, SSRF, IDOR, XXE,
CSRF, etc.) sem depender de download externo.

---

## 3. Modelo de dados

Tabela `VulnerabilityLearning` (`backend/app/models/models.py`):

| Campo | Função |
| --- | --- |
| `status` | `pending_review` (default) → `accepted` / `rejected` |
| `source_kind` | `hackerone_report` (default), `manual`, `bug_bounty_repository`… |
| `steps_to_reproduce` | playbook de reprodução/exploração defensiva |
| `impact` | impacto preservado para o relatório |
| `remediation` | correção preservada para o relatório |
| `learned_mission` | como a missão deve se adaptar |
| `learned_prompt` | trecho proposto para orientar os agentes |
| `accepted_by_id` / `accepted_at` | trilha de auditoria do aceite humano |

**Regra de ouro:** somente registros com `status = accepted` entram no prompt do
supervisor (bloco `ACCEPTED VULNERABILITY LEARNING`). Pendentes/rejeitados ficam
armazenados para auditoria, mas **não alteram o comportamento dos agentes**.

---

## 4. Divisão pelas 22 skills/fases (P01–P22)

Cada aprendizado é classificado por **fase técnica** da Cyber Kill Chain. As 22
fases (`backend/app/graph/mission.py`) mapeiam para as 9 capabilities executivas
e para os workers responsáveis. Resumo das famílias por fase:

| Fase | Tema | Exemplos de aprendizado |
| --- | --- | --- |
| P01 | Subdomain Enumeration | enum de subdomínios, fontes paralelas |
| P02 | Port & Service Scan | varredura de portas/serviços |
| P03 | Web Crawling & JS | extração de endpoints/segredos em JS |
| P04 | Parameter & GET Fuzzing | descoberta de parâmetros, XSS refletido |
| P05 | HTTP Headers / OWASP A05 | misconfig de headers, CSP, HSTS |
| P06 | WAF Detection & Evasion | fingerprint e perfil de evasão |
| P07 | OSINT & Leak Intel | dorks, segredos expostos, breaches |
| P08 | Email Security | SPF/DMARC |
| P09 | Subdomain Takeover | takeover de CNAME órfão |
| P10 | Cloud Asset Exposure | S3/Firebase/Azure expostos |
| P11 | CVE & Misconfiguration | nuclei/CVE, Jenkins, pipelines |
| P12 | Web Injection | SQLi, XSS, CRLF, Host Header, SSTI, cache poisoning |
| P13 | SSRF & Open Redirect | SSRF, open redirect (OOB) |
| P14 | Auth Bypass & Brute Force | JWT, OAuth, 2FA/MFA bypass, account takeover |
| P15 | Directory & File Enum | fuzzing de diretórios/arquivos, LFI/RFI |
| P16 | API Security & POST Fuzzing | mass assignment, business logic, CSRF |
| P17 | Upload & WebShell Bypass | bypass de upload |
| P18 | SSL/TLS & Cert Audit | protocolos/ciphers fracos |
| P19 | IDOR & Access Control | IDOR, controle de acesso |
| P20 | CMS-Specific | WordPress e afins |
| P21 | Secret & Credential Exposure | segredos em código/repos |
| P22 | Dependency & Supply Chain | dependências vulneráveis |

A página **Aprendizado** mostra o índice em **duas visões**:

1. **Por ataque/skill** — agrupa famílias (XSS, CSRF, SQLi, IDOR, SSRF, XXE…).
2. **Por fase P01–P22** — mostra, para cada etapa: conhecimento separado,
   workers responsáveis, ferramentas Kali, aprendizados aceitos/pendentes e
   técnicas disponíveis.

Assim, um report do HackerOne sobre, por exemplo, **IDOR** é catalogado em
**P19**, fica visível na skill "IDOR & Access Control", e passa a informar os
workers daquela fase quando aceito.

---

## 5. Aceite humano (human-in-the-loop)

Antes de aceitar, o operador vê: resumo, nº de técnicas, fases/skills/ferramentas
sugeridas, `steps_to_reproduce`, `impact`, `remediation`, `learned_mission`,
`learned_prompt` e a lista de técnicas com sinais de evidência e passos seguros.

- Aceite individual **ou em lote** (`POST /api/learning/vulnerabilities/bulk-review`).
- **Base pré-carregada de bug bounty** (repos públicos KingOfBugBountyTips e
  AllAboutBugBounty) entra já com `status=accepted` e
  `source_kind=bug_bounty_repository` — influencia o supervisor sem revisão,
  porque já é conhecimento curado.

---

## 6. Como vira RAG (recuperação semântica)

Após o aceite, o conhecimento é **indexado no RAG**, que hoje vive **no backend
sobre pgvector** — não no MCP.

- **Indexador:** `backend/app/services/skill_rag_indexer.py`
  (`index_skills_to_knowledge_store`) carrega skills/aprendizados e faz upsert na
  tabela `rag_knowledge_store`.
- **Embeddings:** `backend/app/services/embedding_service.py` —
  modelo `BAAI/bge-small-en-v1.5` (**384 dimensões**, ONNX/fastembed, roda em CPU).
- **Busca híbrida:** semântica (cosseno via `vector_cosine_ops`, índice IVFFlat
  no pgvector) **+** lexical (overlap de tokens), combinadas — ver
  `backend/app/services/rag_repository.py`.
- **Consumo na decisão:** o supervisor recebe o conhecimento recuperado em
  `skill_memory` (`knowledge_items`, `recommended_tools`, `retrieval_query`) ao
  chamar `decide_next_technique(...)`
  (`backend/app/agents/supervisor_runtime.py`). Ou seja: ao decidir a próxima
  técnica do pentest, o agente já "lembra" dos aprendizados aceitos relevantes
  para a fase/alvo atual.

Quando um agente identifica uma possível vulnerabilidade, os aprendizados
aceitos são **correlacionados** com o finding (por tipo, título, ferramenta,
fase, skill e evidência). Havendo match, o finding recebe em `details`:
`learning_match`, `reproduction_playbook`, `learned_steps_to_reproduce`,
`learned_impact`, `learned_remediation`, `repro_steps`,
`technical_evidence_expected`, `proof_pack_required=true`.

---

## 7. Relação com o MCP (execução)

Historicamente o `mcp_server` também respondia a consultas de conhecimento. Isso
**mudou**: o RAG migrou para o backend (pgvector) e o `mcp_server` ficou
**Kali-only**.

Papéis hoje:

| Componente | Papel | Onde |
| --- | --- | --- |
| **RAG (pgvector)** | guarda e recupera o conhecimento aprendido | backend (`rag_repository`, `embedding_service`) |
| **MCP server** | ponte de execução: resolve profile/alias, aplica guardrail, faz proxy do job para o Kali | `mcp-server/mcp_server.py` |
| **Kali runner** | executa de fato a ferramenta | `kali-runner/` |

Fluxo conjunto: o **RAG** informa *o que* tentar (técnica/ferramenta aprendida
para aquela fase); o **MCP** leva essa decisão até o **Kali**, que executa; o
resultado vira finding, e o finding é **enriquecido** de volta com o aprendizado
correspondente (`learning_match`). O aprendizado fecha o ciclo: orienta a
decisão **antes** da execução e enriquece a evidência **depois**.

---

## 8. Ponta a ponta (resumo)

1. **Ingestão** — URL HackerOne → `/reports/{id}.json` → Steps/Impact/Remediation.
2. **Síntese** — Ollama gera missão, prompt e técnicas.
3. **Aceite humano** — `pending_review` → `accepted` (só aceitos influenciam agentes).
4. **Classificação** — atribuído a uma das 22 fases (P01–P22) + skill + worker.
5. **Indexação RAG** — embeddings bge-small em pgvector (`rag_knowledge_store`).
6. **Recuperação** — supervisor consulta o RAG (`skill_memory`) ao decidir a técnica.
7. **Execução** — decisão vai via **MCP → Kali**.
8. **Enriquecimento** — finding recebe `learning_match` + `reproduction_playbook`.

---

### Arquivos relevantes

```
backend/app/services/vulnerability_learning_service.py  # ingestão HackerOne + síntese + enriquecimento
backend/app/models/models.py                            # VulnerabilityLearning (status, blocos, aceite)
backend/app/services/rag_repository.py                  # RAG híbrido (pgvector)
backend/app/services/skill_rag_indexer.py               # indexação skills/aprendizados → rag_knowledge_store
backend/app/services/embedding_service.py               # bge-small 384-dim (fastembed/CPU)
backend/app/agents/supervisor_runtime.py                # decide_next_technique consome skill_memory (RAG)
backend/app/graph/mission.py                            # 22 fases P01–P22
mcp-server/mcp_server.py                                # ponte de execução Kali-only
```
