# Teste de Nodes e Steps LangGraph

Este diretório contém scripts para validar a execução do **LangGraph workflow** e os **passos da missão** (MISSION_ITEMS).

## Arquitetura do LangGraph

O workflow do Pentest.io segue este fluxo:

```
[START]
  ↓
[asset_discovery]  ← Reconhecimento (Amass, MassDns, Sublist3r, Nmap)
  ↓
├─→ [threat_intel]       ← OSINT (Shodan.io) [PARALELO]
└─→ [risk_assessment]    ← Vulnerabilidades (Burp, Nmap Vulscan, Nikto) [PARALELO]
  ↓
[governance]       ← Rating FAIR+AGE (Python puro)
  ↓
[executive_analyst] ← Narrativa LLM (Ollama)
  ↓
[END]
```

## Nós Esperados

| Node | Responsabilidade | Ferramentas |
|------|------------------|-------------|
| `asset_discovery` | Descoberta de ativos e superfície | Amass, MassDns, Sublist3r, Nmap |
| `threat_intel` | Inteligência de ameaças | Shodan.io |
| `risk_assessment` | Análise de vulnerabilidades | Burp, Nmap Vulscan, Nikto |
| `governance` | Cálculo de risco (FAIR+AGE) | - |
| `executive_analyst` | Narrativa executiva | Ollama LLM |

## Passos da Missão (MISSION_ITEMS)

Cada nó executa um ou mais passos:

**Phase 1: RECONNAISSANCE** (asset_discovery)
1. Amass Subdomain Recon
2. Sublist3r Subdomain Expansion
3. MassDns DNS Validation
4. Nmap Port Scanning
5. Nmap Service Detection

**Phase 2a: OSINT** (threat_intel) [PARALELO]
6. Shodan Intelligence Gathering
7. Shodan Fingerprint Analysis

**Phase 2b: VULNERABILITY ANALYSIS** (risk_assessment) [PARALELO]
8. Burp Suite Scanning
9. Nmap Vulscan Script Analysis
10. Nikto Web Server Scan

**Phase 3: CONSOLIDATION & LLM** (governance + executive_analyst)
11. Consolidar Dados (Recon + OSINT + Vuln)
12. Validate Risk via LLM
13. Gerar Recomendações de Correção
14. Relatorio Final JsonL

## Scripts de Teste

### 1. `test_langgraph_nodes.sh` — Teste Completo do LangGraph

Dispara um scan real e monitora a execução através de todos os nós.

**Uso:**
```bash
./scripts/test_langgraph_nodes.sh [target_domain] [mode]
```

**Exemplos:**
```bash
# Teste básico
./scripts/test_langgraph_nodes.sh www.example.com single

# Modo agendado
./scripts/test_langgraph_nodes.sh monitoring.example.com scheduled

# Com target padrão
./scripts/test_langgraph_nodes.sh
```

**O que valida:**
- ✅ Backend API respondendo
- ✅ Autenticação JWT funcionando
- ✅ Target adicionado à allowlist
- ✅ Scan criado com sucesso
- ✅ Progresso em tempo real
- ✅ Nós visitados (asset_discovery, threat_intel, risk_assessment, governance, executive_analyst)
- ✅ Passos da missão executados (1-14)
- ✅ Estado final do scan

**Saída esperada:**
```
══════════════════════════════════════════════════════
  PENTEST.IO — Teste LangGraph Nodes & Mission Steps
══════════════════════════════════════════════════════
ℹ️  INFO Target: www.example.com
ℹ️  INFO Mode: single
ℹ️  INFO Backend: http://localhost:8000

┌─ 1. Backend Health Check 
✅ PASS Backend API respondendo em http://localhost:8000

┌─ 2. Authentication
✅ PASS JWT token obtido: eyJhbGciOiJIUzI1NiIsIn...

┌─ 3. Adicionar target à allowlist
✅ PASS Target adicionado à allowlist (ID: 23)

┌─ 4. Criar scan
✅ PASS Scan criado: ID 103

┌─ 5. Monitorar progresso do scan (5 min)
[  5s] Status: queued     | Node: ?                  | Step: 1. Amass Subdomain Recon | Progress: 7%
[ 10s] Status: running    | Node: asset_discovery    | Step: 1. Amass Subdomain Recon | Progress: 7%
[ 15s] Status: running    | Node: asset_discovery    | Step: 4. Nmap Port Scanning    | Progress: 28%
[ 20s] Status: running    | Node: threat_intel       | Step: 6. Shodan Intelligence   | Progress: 42%
[ 25s] Status: running    | Node: risk_assessment    | Step: 8. Burp Suite Scanning   | Progress: 50%
[ 35s] Status: running    | Node: governance         | Step: 12. Validate Risk via LLM | Progress: 85%
[ 45s] Status: completed  | Node: executive_analyst  | Step: 14. Relatorio Final JsonL| Progress: 100%
✅ PASS Scan completado!

┌─ 6. Validar nós do LangGraph visitados
✅ PASS Nó executado: asset_discovery
✅ PASS Nó executado: threat_intel
✅ PASS Nó executado: risk_assessment
✅ PASS Nó executado: governance
✅ PASS Nó executado: executive_analyst

┌─ 7. Validar passos da missão
✅ PASS Passo 1: Amass Subdomain Recon
✅ PASS Passo 2: Sublist3r Subdomain Expansion
✅ PASS Passo 3: MassDns DNS Validation
✅ PASS Passo 4: Nmap Port Scanning
✅ PASS Passo 5: Nmap Service Detection
✅ PASS Passo 6: Shodan Intelligence Gathering
✅ PASS Passo 7: Shodan Fingerprint Analysis
✅ PASS Passo 8: Burp Suite Scanning
✅ PASS Passo 9: Nmap Vulscan Script Analysis
✅ PASS Passo 10: Nikto Web Server Scan
✅ PASS Passo 11: Consolidar Dados (Recon + OSINT + Vuln)
✅ PASS Passo 12: Validate Risk via LLM
✅ PASS Passo 13: Gerar Recomendações de Correção
✅ PASS Passo 14: Relatorio Final JsonL

┌─ 8. Resumo da Execução
Scan ID: 103
Status Final: COMPLETED
Nós visitados: asset_discovery threat_intel risk_assessment governance executive_analyst
Falhas: 0

✅ Teste concluído com sucesso!
```

### 2. `test_worker_recon.sh` — Teste do Worker RECON

Valida que o worker RECON está vivo e pode processar tarefas.

**Uso:**
```bash
./scripts/test_worker_recon.sh [--docker] [--redis-url URL]
```

**Exemplos:**
```bash
# Teste com Docker (recomendado)
./scripts/test_worker_recon.sh --docker

# Teste local
./scripts/test_worker_recon.sh
```

**O que valida:**
- ✅ Conectividade com Redis
- ✅ Worker respondendo a ping Celery
- ✅ Filas registradas no Redis
- ✅ Binários das ferramentas (Amass, MassDns, Sublist3r, Nmap)
- ✅ Task de diagnóstico pode ser enviada
- ✅ Heartbeat do worker no banco de dados

### 3. `test_worker_osint.sh` e `test_worker_vuln.sh`

Scripts similares para validar os workers OSINT e VULN.

## Executando Testes End-to-End

```bash
# 1. Subir a stack
docker compose --profile dev up --build

# 2. Aguardar inicialização (30-60s)
sleep 45

# 3. Teste dos workers
bash scripts/test_worker_recon.sh --docker
bash scripts/test_worker_osint.sh --docker
bash scripts/test_worker_vuln.sh --docker

# 4. Teste completo do LangGraph
bash scripts/test_langgraph_nodes.sh www.example.com single

# 5. Monitorar resultado final
curl -s http://localhost:8000/api/scans/103 \
  -H "Authorization: Bearer $TOKEN" | jq '.status, .mission_progress'
```

## Variáveis de Ambiente

```bash
# Backend
BACKEND_URL=http://localhost:8000

# Credenciais admin
ADMIN_EMAIL=admin@example.com
ADMIN_PASSWORD=admin123

# Redis (para workers)
REDIS_URL=redis://localhost:6379/0

# Database (para heartbeats)
DATABASE_URL=postgresql://easm:easm@localhost:5432/easm
```

## Troubleshooting

| Problema | Solução |
|----------|---------|
| "Backend não respondendo" | Aguarde 30-60s e tente novamente; verifique `docker logs pentest_backend` |
| "Token inválido" | Verifique `ADMIN_EMAIL` e `ADMIN_PASSWORD` em .env |
| "Nó não visitado" | Pode estar sendo executado em paralelo; aguarde mais polling |
| "Timeout de 5min" | O scan está ainda em execução; use `curl` para monitorar status manualmente |
| "Redis não respondendo" | Verifique `docker compose ps` e `docker logs pentest_redis` |

## Interpretando Nós Paralelos

Os nós `threat_intel` e `risk_assessment` são executados **em paralelo** após `asset_discovery`. Portanto:
- Podem ser visitados em qualquer ordem
- Podem não aparecer no monitor se forem muito rápidos
- Ambos devem ser concluídos antes de `governance` iniciar

## Próximas Iterações

- [ ] Adicionar validação de findings gerados
- [ ] Validar descoberta de CVEs
- [ ] Testar escalada entre workers (Unit vs Scheduled)
- [ ] Medir tempo de execução por nó
- [ ] Capturar logs de Cellery para debugging
