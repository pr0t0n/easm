# EASM — Plataforma Enterprise de Gestão de Superfície de Ataque Externo

**EASM** é uma plataforma de **External Attack Surface Management** de nível enterprise, voltada para escanear, inventariar, quantificar e monitorar continuamente a superfície externa de organizações. Centraliza descoberta de ativos, triagem de vulnerabilidades, priorização financeira (em USD), rastreamento temporal com alertas baseados em desvios de postura, auditoria completa e dashboards executivos.

## Aviso de Segurança

Este projeto foi estruturado para **uso defensivo e autorizado exclusivamente**. Toda execução depende de autorização válida por escopo e de policy/allowlist ativa. Não use para varredura não autorizada.

---

## Estado Atual da Plataforma

### ✅ Features Implementadas

**Núcleo EASM (7-Node LangGraph Pipeline):**
- ✅ **Descoberta de Ativos**: varrição de domínios, enumeração de IPs, portas abertas
- ✅ **Avaliação de Risco**: fórmula **FAIR+AGE** com quantificação em USD
- ✅ **Inteligência de Ameaças**: correlação CVE, CVSS, EPSS, KEV (Known Exploited Vulnerabilities)
- ✅ **Governança de Remediação**: rastreamento de SLA, ciclo de vida de vulnerabilidades
- ✅ **Análise Executiva**: narrativas automáticas em português, recomendações para C-level
- ✅ **Rastreamento Temporal**: snapshots de risco, velocidade de remediação, desvios de postura
- ✅ **Alertas Inteligentes**: 6 tipos de eventos (rating_drop, crown_jewel_age, critical_spike, etc) com webhook

**Backend e Orquestração:**
- ✅ FastAPI com JWT + controle de acesso por owner_id
- ✅ PostgreSQL com **5 novas tabelas EASM**: assets, vulnerabilities, asset_rating_history, easm_alerts, easm_alert_rules
- ✅ Alembic migration 0002_easm_infrastructure (88 colunas, 12 índices)
- ✅ Celery + Redis para execução assíncrona (filas por grupo)
- ✅ LangGraph 0.2.62 com 7 nodos + PostgreSQL checkpointer

**Normalização de Ferramentas (8 Parsers):**
- ✅ **Subfinder** (JSON): domínios → IPs
- ✅ **Nmap** (JSON): hosts → portas abertas + detecção de serviço
- ✅ **Shodan** (JSON): fingerprinting + CVE extraction
- ✅ **h8mail** (JSON): breach data + OSINT exposure
- ✅ **Nuclei** (JSON-lines): template findings com severity/CVE
- ✅ **Nikto** (JSON): vulnerabilidades HTTP por URI
- ✅ **SQLMap** (JSON): SQL injection detection
- ✅ **Nessus** (XML): agregação de vulnerabilidades com plugin data
- ✅ Factory pattern + deduplicação de findings

**Dashboard EASM (6 Cards):**
- ✅ EASM Rating (A-F grade com score 0-100)
- ✅ FAIR Pillars (3 decomposição: perimeter_resilience, patching_hygiene, osint_exposure)
- ✅ Temporal Curves (remediation velocity, deviation 24h, 30-day forecast)
- ✅ Executive Summary (narrativa em prosa para stakeholders)
- ✅ Alerts (top 5 com severity colors)
- ✅ Asset List (top 10 ranked by risk)

**Quantificação Financeira:**
- ✅ Potencial loss em USD por setor (Healthcare $610/record, Financial $250/record, etc)
- ✅ Threat Event Frequency (TEF): probabilidade anual de exploração
- ✅ Expected Annual Loss (EAL) com multiplicadores de age, criticality
- ✅ Prompt engineering para narrativas financeiras

**Alertas e Webhooks:**
- ✅ 6 tipos de alertas: rating_drop, crown_jewel_age, critical_spike, zero_remediation, velocity_degradation, pillar_threshold
- ✅ Webhook dispatcher com retry async
- ✅ Integração Slack com payload colorido

**Relatórios:**
- ✅ Custom HTML/PDF com FAIR decomposition, executive summary, findings counts
- ✅ Print-friendly Tailwind CSS
- ✅ Endpoint `/api/scans/{scan_id}/easm-report`

**Auditoria e Compliance:**
- ✅ Trilha de autorização por escopo
- ✅ Logs em tempo real via WebSocket
- ✅ Allowlist com validação de ownership
- ✅ Policy enforcement pré-execução

### Tecnologia

```
Backend:          FastAPI 0.110.0 + SQLAlchemy + Alembic
Database:         PostgreSQL 17 (23 tabelas, 5 EASM-specific)
Async:            Celery + Redis
State Machine:    LangGraph 0.2.62 + PostgreSQL checkpointer
AI:               Ollama llama3 via httpx
Search:           ChromaDB (deduplicação vetorial)
Frontend:         React 18 + Tailwind CSS + Vite
Logging:          stdlib + WebSocket real-time
```

---

## Arquitetura Operacional

### Diagrama de Stack

```
┌─────────────────────────────────────────────────────────────┐
│              Frontend: React + Tailwind CSS                 │
│    Dashboard (6 EASM cards) + Custom Report + Admin Panel   │
└──────────────────────────┬──────────────────────────────────┘
                           │ HTTP/REST + WebSocket
        ┌──────────────────┴──────────────────┐
        │                                      │
   ┌────▼──────────┐                  ┌──────▼─────────┐
   │   FastAPI     │                  │  WebSocket     │
   │ Auth + Routes │                  │  Real-time Logs│
   └────┬──────────┘                  └────────────────┘
        │ orchestration
        │
   ┌────▼────────────────────────────────────────┐
   │         LangGraph v0.2.62 (StateGraph)      │
   │                                              │
   │  1. asset_discovery (nmap, subfinder, etc)  │
   │  2. risk_assessment (FAIR+AGE calculation)  │
   │  3. threat_intel (CVE correlation)          │
   │  4. governance (remediation tracking)       │
   │  5. executive_analyst (LLM narratives)      │
   │  6. temporal_tracking (history snapshot)    │
   │  7. alert_check (webhook triggers)          │
   │                                              │
   │  Checkpointer: PostgreSQL                   │
   └────┬────────────────────────────────────────┘
        │
     ┌──┴─────┬────────────┬──────────────┐
     │         │            │              │
┌────▼──┐ ┌───▼───┐ ┌─────▼──┐ ┌────────▼──┐
│Celery │ │ Redis │ │ Postgres │ │  ChromaDB │
│Workers│ │ Queue │ │ Storage  │ │  Vectors  │
│(7 Q)  │ │ Cache │ │(23 TB)   │ │(dup check)│
└───────┘ └───────┘ └──────────┘ └───────────┘
```

### Pipeline de Execução (Fluxo Ponta-a-Ponta)

```
1. User/Admin: Criar scan via POST /api/scans {target, tools}
                ↓
2. Backend: Validar authorization_code + policy/allowlist
                ↓
3. Enqueue: Tarefa para Celery (fila scan.unit)
                ↓
4. Worker: Inicializar LangGraph StateGraph
                ↓
5. Asset Discovery Node: Executar Subfinder, Nmap, Shodan
   Resultado: {domain, ip, port, service, fingerprint}
                ↓
6. Risk Assessment Node: Computar FAIR+AGE por asset
   Resultado: {easm_rating 0-100, grade A-F, pillar_scores}
                ↓
7. Threat Intel Node: Correlacionar CVE, CVSS, EPSS, KEV
   Resultado: {vulnerability[], cve_id, threat_frequency}
                ↓
8. Governance Node: Rastrear SLA, velocidade de remedição
   Resultado: {remediation_velocity %, trend, days_to_zero}
                ↓
9. Executive Analyst Node: Gerar narrativas com LLM
   Resultado: {narrative_text, financial_summary, recommendations}
                ↓
10. Temporal Tracking Node: Persistir asset_rating_history
    Resultado: Snapshots históricos para dashboard + forecast
                ↓
11. Alert Check Node: Avaliar regras, disparar webhooks
    Resultado: EASMAlert[] criados, webhooks POST sincronizados
                ↓
12. Persistir: Encontrado em findings + audit_trail
    Dashboard, Reports e APIs consomem dados persistidos
```

---

## Conceitos-Chave

### 1. FAIR + AGE Rating

Fórmula de risco quantitativo estendida:

```
EASM_Rating = (Asset_Impact × CVSS_Score) × Age_Factor

Age_Factor = 1 + log₁₀(days_open + 1)

Asset_Impact = (0.40 × perimeter_resilience) 
             + (0.30 × patching_hygiene) 
             + (0.30 × osint_exposure)

Perimeter_Resilience:  [Subfinder, Nmap] → descoberta de portas/serviços
Patching_Hygiene:      [Nuclei, Nikto, SQLMap] → vulnerabilidades conhecidas
OSINT_Exposure:        [h8mail, Shodan] → dados públicos, breaches

Grade: A (90-100), B (75-89), C (60-74), D (45-59), F (<45)
```

**Exemplo:**
- Asset: database.megacorp.com (CVSS 8.5)
- Age: 15 dias aberto
- Pillar scores: perimeter 85%, patching 60%, osint 40%
- Asset Impact = 0.40×85 + 0.30×60 + 0.30×40 = 34 + 18 + 12 = **64%**
- Age Factor = 1 + log₁₀(16) = 1 + 1.20 = **2.20**
- EASM Rating = 64 × 8.5 × 2.20 = **1,193** (capped at 100) → capped and normalized → **Grade B** (rating 87)

### 2. Temporal Curves (Séries Temporais)

Acompanhamento contínuo de 3 dimensões com snapshots diários:

**Remediation Velocity** (%/semana):
- Velocidade de fechamento de vulnerabilidades no período
- Trend: improving (>10%/sem), stable (5-10%), degrading (<5%)
- Projeção: dias até critical_count = 0

**Posture Deviation** (pontos em 24h):
- Mudança de rating EASM em 24 horas
- **Alert crítico** se deviation > 10 pontos
- Causa raiz: age_factor (aging), new_findings, remediation, stable

**30-Day Forecast**:
- Projeção do rating com AGE decay, novas descobertas, remediação esperada
- Confiança: alta/média/baixa
- Drivers: lista de fatores impactando mudança

**Asset Rating History** (tabela persistida):
```sql
asset_rating_history {
  asset_id,
  recorded_at (timestamp),
  easm_rating (0-100),
  easm_grade (A-F),
  open_critical, open_high, open_medium, open_low (counts),
  remediated_this_period (int),
  velocity_score (float % per week),
  pillar_scores (JSONB: {perimeter_resilience, patching_hygiene, osint_exposure}),
  remediation_notes (text)
}
```

### 3. Quantificação Financeira

**Setor-Specific Breach Costs:**
```python
SECTOR_BREACH_COSTS = {
    'healthcare': {'cost_per_record': 610, 'avg_records': 50000, ...},
    'financial': {'cost_per_record': 250, 'avg_records': 100000, ...},
    'retail': {'cost_per_record': 140, 'avg_records': 200000, ...},
    'technology': {'cost_per_record': 180, ...},
    'government': {'cost_per_record': 210, ...},
}
```

**Potential Loss** = avg_records × cost_per_record × severity_multiplier × age_multiplier × asset_type_mult × crown_jewel_mult

**Expected Annual Loss (EAL)** = Potential_Loss × Threat_Event_Frequency

**Threat Event Frequency (TEF)**:
- Severity probability: critical 0.70, high 0.40, medium 0.15, low 0.05
- Age boost: 1 + (age_days / 100)
- Threat intel multiplier: public_poc 1.8, exploit_kits 2.5, cisa_kev 2.0

---

## Database Schema (EASM-Specific)

### Novas Tabelas (5 registradas em migration 0002)

**assets** (inventário de host/porta/serviço):
```sql
CREATE TABLE assets (
  id SERIAL PRIMARY KEY,
  owner_id INT NOT NULL,
  domain_or_ip VARCHAR(255) NOT NULL INDEXED,
  port INT,
  protocol VARCHAR(20) DEFAULT 'http',
  asset_type VARCHAR(50) DEFAULT 'web',
  criticality_score FLOAT DEFAULT 50,
  status VARCHAR(20) DEFAULT 'active' INDEXED,
  first_seen TIMESTAMP NOT NULL,
  last_seen TIMESTAMP NOT NULL,
  scan_count INT DEFAULT 0,
  metadata JSONB,
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW(),
  FOREIGN KEY (owner_id) REFERENCES owner(id),
  UNIQUE (owner_id, domain_or_ip, port, protocol)
);
```

**vulnerabilities** (descobertas persistidas):
```sql
CREATE TABLE vulnerabilities (
  id SERIAL PRIMARY KEY,
  asset_id INT NOT NULL INDEXED,
  finding_id INT,
  tool_source VARCHAR(50) INDEXED,     -- 'nmap', 'nuclei', 'shodan', etc
  cve_id VARCHAR(20) INDEXED,
  severity VARCHAR(20),               -- 'critical', 'high', 'medium', 'low'
  cvss_score FLOAT,
  title VARCHAR(500),
  description TEXT,
  first_detected TIMESTAMP DEFAULT NOW(),
  last_detected TIMESTAMP,
  remediated_at TIMESTAMP INDEXED,
  age_factor FLOAT DEFAULT 1.0,
  ra_score FLOAT DEFAULT 0.0,
  fair_pillar VARCHAR(50) INDEXED,    -- 'perimeter_resilience', 'patching_hygiene', 'osint_exposure'
  detection_count INT DEFAULT 1,
  remediation_notes TEXT,
  metadata JSONB,
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW(),
  FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE CASCADE
);
```

**asset_rating_history** (série temporal):
```sql
CREATE TABLE asset_rating_history (
  id SERIAL PRIMARY KEY,
  asset_id INT NOT NULL INDEXED,
  scan_id INT,
  easm_rating FLOAT,
  easm_grade VARCHAR(1),              -- 'A', 'B', 'C', 'D', 'F'
  open_critical INT DEFAULT 0,
  open_high INT DEFAULT 0,
  open_medium INT DEFAULT 0,
  open_low INT DEFAULT 0,
  remediated_this_period INT DEFAULT 0,
  velocity_score FLOAT DEFAULT 0.0,   -- % per week
  pillar_scores JSONB,                -- {perimeter_resilience, patching_hygiene, osint_exposure}
  recorded_at TIMESTAMP DEFAULT NOW() INDEXED,
  FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE CASCADE
);
```

**easm_alerts** (eventos disparados):
```sql
CREATE TABLE easm_alerts (
  id SERIAL PRIMARY KEY,
  owner_id INT NOT NULL,
  asset_id INT,
  alert_type VARCHAR(50),             -- 'rating_drop', 'crown_jewel_age', etc
  severity VARCHAR(20),               -- 'CRITICAL', 'HIGH', 'MEDIUM'
  title VARCHAR(500),
  description TEXT,
  trigger_value FLOAT,
  threshold_value FLOAT,
  is_resolved BOOLEAN DEFAULT FALSE,
  resolved_at TIMESTAMP,
  resolved_notes TEXT,
  webhook_payload JSONB,
  created_at TIMESTAMP DEFAULT NOW() INDEXED,
  FOREIGN KEY (owner_id) REFERENCES owner(id),
  FOREIGN KEY (asset_id) REFERENCES assets(id)
);
```

**easm_alert_rules** (regras para trigger):
```sql
CREATE TABLE easm_alert_rules (
  id SERIAL PRIMARY KEY,
  owner_id INT NOT NULL,
  name VARCHAR(255),
  rule_type VARCHAR(50),              -- 'rating_drop', 'crown_jewel_age', etc
  enabled BOOLEAN DEFAULT TRUE,
  condition JSONB,                    -- {threshold: 10, period_hours: 24, ...}
  webhook_url VARCHAR(500),
  notify_channels JSONB,              -- ["email", "slack"]
  asset_filter JSONB,                 -- {min_criticality: 80, types: ["web"]}
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW(),
  FOREIGN KEY (owner_id) REFERENCES owner(id)
);
```

---

## Endpoints Principais

### Novos Endpoints EASM (7 rotas)

**Dashboard & Analytics:**
- `GET /api/dashboard/assets` — Query: status, min_criticality, sort_by; Returns: assets com ratings
- `GET /api/dashboard/vulnerabilities` — Query: open_only, severity, asset_id; Returns: vulns persistidas
- `GET /api/dashboard/trends/{asset_id}` — Query: days (7-365); Returns: histórico + velocity + deviation + forecast

**Scans & Reports:**
- `GET /api/scans/{scan_id}/easm-report` — Returns: FAIR decomp + executive summary + findings
- `GET /api/easm/alerts` — Query: unresolved_only, severity; Returns: alerts recentes

**Alert Management:**
- `POST /api/easm/alerts/{alert_id}/resolve` — Body: notes; Returns: confirmation

### Endpoints Legados (Backward Compatible)

Todos os endpoints anteriores mantidos:
- Autenticação: `/api/auth/*`
- Scans: `/api/scans`, `/api/scans/{id}/status`, `/api/scans/{id}/logs`
- Findings: `/api/findings`, `/api/findings/page`
- Compliance: `/api/compliance/authorizations/*`
- Workers: `/api/worker-manager/*`
- Config: `/api/config/*`, `/api/policy/allowlist`
- Schedules: `/api/schedules/*`

---

## Setup & Deployment

### 1. Ambiente de Desenvolvimento

```bash
# Clone e setup
git clone https://github.com/pr0t0n/easm.git && cd easm
cp .env.example .env

# Subir stack com Docker Compose
docker compose --profile dev up --build

# Endpoints:
# Frontend: http://localhost:5173
# Backend:  http://localhost:8000
# Docs:     http://localhost:8000/docs
```

### 2. Migração de Database (CRÍTICO)

```bash
# Dentro do container backend ou venv local:
cd backend
alembic upgrade head

# Isso cria as 5 novas tabelas EASM (0002_easm_infrastructure)
# Verificar com: \dt em psql → deve listar assets, vulnerabilities, etc
```

### 3. Testar Endpoints EASM

```bash
# Login primeiro
curl -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@example.com","password":"password"}'

# Copiar token JWT da resposta

# Listar assets
curl -X GET http://localhost:8000/api/dashboard/assets \
  -H "Authorization: Bearer <JWT_TOKEN>"

# Listar alertas
curl -X GET http://localhost:8000/api/easm/alerts \
  -H "Authorization: Bearer <JWT_TOKEN>"

# Custom report (após executar scan)
curl -X GET http://localhost:8000/api/scans/1/easm-report \
  -H "Authorization: Bearer <JWT_TOKEN>"
```

### 4. Configurar Webhooks (Opcional)

```bash
# Criar rule para alertar via webhook
curl -X POST http://localhost:8000/api/easm/alert-rules \
  -H "Authorization: Bearer <JWT_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Rating Drop Alert",
    "rule_type": "rating_drop",
    "enabled": true,
    "condition": {"threshold": 10, "period_hours": 24},
    "webhook_url": "https://your-slack-webhook-url",
    "notify_channels": ["slack"]
  }'
```

---

## Validação e Testes

### E2E Flow Validation

```bash
python scripts/validate_e2e_flow.py
```

Testa:
1. User registration + login
2. Authorization request + approval
3. Scan creation + execution
4. LangGraph pipeline execution
5. Data persistence em DB
6. Endpoint responses

### Unit Tests (Backend)

```bash
cd backend
python -m pytest tests/ -v
```

Cobertura: risk_service.py (FAIR+AGE), normalizers.py (8 parsers), alert_service.py

### Dashboard Validation

Acessar http://localhost:5173/dashboard e verificar:
- EASM Rating card renderizando
- FAIR Pillars bar chart
- Temporal Curves com gráficos
- Alerts list populated
- Asset list com dados

---

## Documentação Complementar

- **[RUNBOOK.md](docs/RUNBOOK.md)** — Operações diárias, troubleshooting, SOP
- **[backend/alembic/versions/](backend/alembic/versions/)** — Histórico de migrations
- **[backend/app/services/](backend/app/services/)** — Código de risco, parsers, alertas
- **[frontend/easm-report.html](frontend/easm-report.html)** — Template custom report
- **[backend/app/graph/workflow.py](backend/app/graph/workflow.py)** — LangGraph definition

---

## Estrutura de Arquivos (EASM-Relevant)

```
easm/
├── backend/
│   ├── alembic/
│   │   └── versions/
│   │       └── 0002_easm_infrastructure.py     ← NEW: Schema EASM
│   ├── app/
│   │   ├── models/models.py                    ← EXTENDED: 5 EASM classes
│   │   ├── services/
│   │   │   ├── risk_service.py                 ← EXTENDED: temporal curves
│   │   │   ├── normalizers.py                  ← NEW: 8 tool parsers
│   │   │   ├── prompt_engineering.py           ← NEW: financial models
│   │   │   ├── orchestrator.py                 ← NEW: workflow broker
│   │   │   └── alert_service.py                ← NEW: webhook dispatcher
│   │   └── api/
│   │       └── routes_scans.py                 ← EXTENDED: 7 EASM endpoints
│   └── requirements.txt                        ← ALL deps included
│
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   │   └── EASMDashboard.jsx               ← NEW: 6 EASM cards
│   │   └── pages/
│   │       └── DashboardPage.jsx               ← EXTENDED: EASM integration
│   └── easm-report.html                        ← NEW: Custom report template
│
└── docs/
    └── RUNBOOK.md
```

---

## Roadmap e Próximas Etapas

### Fase 1 — Production Ready (v1.0) ✅
- [x] FAIR+AGE motor
- [x] 5-node EASM pipeline
- [x] 8 tool normalizers
- [x] Asset inventory persistence
- [x] Temporal tracking + forecasting
- [x] Alert webhooks + Slack integration
- [x] EASM dashboard + custom report
- [x] Financial quantification
- [x] Compliance & auditoria

### Fase 2 — Intelligence & Automation (v2.0)
- [ ] Threat intelligence feeds (CISA KEV, Exploit-DB daily)
- [ ] SOAR playbooks para auto-remediation
- [ ] Integração com SIEM (Splunk, ELK)
- [ ] Scheduler automático (Celery Beat)
- [ ] Multi-tenant com tenant_id global
- [ ] Prometheus metrics export
- [ ] Cost optimization recommendations

### Fase 3 — Enterprise Scale (v3.0)
- [ ] Sharded PostgreSQL para 10K+ assets
- [ ] Grafana dashboards + alerting
- [ ] API rate limiting + quota management
- [ ] LDAP/SAML SSO
- [ ] Audit log archival (S3/WORM)
- [ ] PCI-DSS, SOC2 compliance mappings

---

## Suporte e Contribuições

**Issues**: Use a GitHub issue tracker com tags: `bug`, `enhancement`, `documentation`

**Contributing**: Contribuições bem-vindas. Favor seguir:
1. Feature branch: `git checkout -b feature/xyz`
2. Commit message: `feat(module): description`
3. Pull request com tests (pytest coverage >80%)

---

**Last Updated**: Março 2026  
**Maintainer**: Security Platform Team  
**License**: Proprietary
