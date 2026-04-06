# RUNBOOK Operacional - Pentest.io v2 (Simplificado)

## Objetivo

Guia rápido de operação para a **nova arquitetura com 3 workers** (RECON, OSINT, VULN).

## Arquitetura

```
┌─────────────────────────────────────────────────────────────┐
│                  Frontend (Vite)                             │
├─────────────────────────────────────────────────────────────┤
│    Backend (FastAPI)  |  PostgreSQL  |  Redis  |  Ollama    │
├─────────────────────────────────────────────────────────────┤
│  Worker RECON  │  Worker OSINT  │  Worker VULN              │
│ (4 ferramentas)│ (1 ferramenta) │ (3 ferramentas)           │
└─────────────────────────────────────────────────────────────┘
```

## Subida da Stack

### Desenvolvimento (perfil `dev`)
```bash
docker compose --profile dev up --build
```

Serviços iniciados:
- `pentest_postgres` — PostgreSQL 16
- `pentest_redis` — Redis 7
- `pentest_ollama` — Ollama LLM
- `pentest_backend` — API FastAPI (porta 8000)
- `pentest_worker_recon` — Worker de Reconhecimento
- `pentest_worker_osint` — Worker de OSINT
- `pentest_worker_vuln` — Worker de Vulnerabilidades
- `pentest_frontend` — Frontend Vite (porta 5173)

### Produção (perfil `prod`)
```bash
cp .env.example .env
docker compose --profile prod up --build -d
```

## Health Check Rápido

```bash
# Backend pronto
curl -s http://localhost:8000/docs | grep fastapi && echo "✅ Backend OK"

# Workers em execução
docker compose ps | grep "pentest_worker"

# Logs de um worker
docker compose logs -f pentest_worker_recon
```

## Configuração de Ambiente (.env)

```bash
# Banco de dados
POSTGRES_HOST_PORT=5432
REDIS_HOST_PORT=6379

# Backend
BACKEND_HOST_PORT=8000
APP_NAME=Pentest.io
ADMIN_EMAIL=admin@example.com
ADMIN_PASSWORD=admin123

# Frontend
FRONTEND_HOST_PORT=5173
VITE_API_URL=http://localhost:8000
```

## Executar um Scan Manual

```bash
TOKEN=$(curl -s -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@example.com","password":"admin123"}' \
  | jq -r '.access_token')

# 1. Adicionar domínio à allowlist
curl -s -X POST http://localhost:8000/api/policy/allowlist \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"target_pattern":"exemplo.com"}'

# 2. Criar scan
curl -s -X POST http://localhost:8000/api/scans \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"target_query":"exemplo.com","mode":"single"}'

# 3. Monitorar progresso
curl -s http://localhost:8000/api/scans/1/status \
  -H "Authorization: Bearer $TOKEN" | jq '.status, .current_step, .mission_progress'
```

## Parar e Limpar

```bash
# Parar containers (mantém dados)
docker compose down

# Remover volumes (CUIDADO: perdemos dados)
docker compose down -v
```

## Troubleshooting

| Problema | Solução |
|----------|---------|
| `podman: command not found` | Use `docker` em vez de `podman` |
| Worker não processa tarefas | Verifique `docker compose logs pentest_redis` |
| Backend recusa conexão | Aguarde `postgres_data` inicializar (15s) |
| Ollama muito lento | Reduza `OLLAMA_NUM_PARALLEL` em docker-compose.yml |
2. Verificar logs dos containers:
```bash
docker compose logs --tail=200 worker_unit_recon worker_unit_vuln worker_unit_osint
```
3. Reiniciar worker afetado:
```bash
docker compose restart worker_unit_recon
# ou
docker compose restart worker_unit_vuln
# ou
docker compose restart worker_unit_osint
```
4. Executar dry-run de órfãos.
5. Se houver órfãos, executar requeue efetivo.

### Cenário B: Scans travados em `running`
1. Rodar endpoint de reconciliacao em dry-run.
2. Revisar lista `orphans` retornada.
3. Executar requeue efetivo.
4. Acompanhar status em `/api/scans/{id}/status`.

### Cenário C: Falha do backend
1. Checar health:
```bash
curl -s http://localhost:8000/health
```
2. Ver logs:
```bash
docker compose logs --tail=300 backend
```
3. Reiniciar backend:
```bash
docker compose restart backend
```
4. Validar conectividade com DB/Redis.

## Restart Seguro (sem perda de contexto)

1. Pausar novas execucoes (operacional): evitar acionar novos scans.
2. Verificar scans ativos (`running`).
3. Reiniciar na ordem:
```bash
docker compose restart backend
docker compose restart worker_unit_recon
docker compose restart worker_unit_vuln
docker compose restart worker_unit_osint
```
4. Verificar health da API e workers.
5. Rodar dry-run de órfãos para confirmar consistencia.

## Bootstrap em Cloud

1. Criar .env a partir de [/.env.example](.env.example) antes da primeira subida.
2. Ajustar FRONTEND_ORIGIN, FRONTEND_ORIGINS e VITE_API_URL para as URLs publicas.
3. Definir BURP_LICENSE_KEY se o serviço [burp_rest](docker-compose.yml#L44) estiver habilitado.
4. Subir a stack:
```bash
docker compose --profile prod up --build -d
```
5. Validar:
```bash
curl -s http://localhost:8000/health
docker compose --profile prod ps
```

## Rollback

### Rollback rapido por imagem/tag anterior
1. Ajustar imagem/tag no compose (ou no pipeline).
2. Recriar containers com a versao anterior:
```bash
docker compose down
docker compose --profile prod up -d
```
3. Executar validacoes:
- `/health`
- `/api/worker-manager/health`
- dry-run de órfãos

### Rollback de dados
- Nao executar rollback destrutivo sem snapshot.
- Restaurar backup do PostgreSQL apenas com janela de manutencao aprovada.

## Checklist Pos-Incidente
1. Auditoria: revisar eventos em `/api/audit/events`.
2. Confirmar que `offline_workers = 0`.
3. Confirmar `orphans = []` no dry-run.
4. Registrar causa raiz e acao corretiva.

## Observacoes
- Heartbeat de worker e atualizado automaticamente durante execucao de scan.
- O reconciliador depende de `celery inspect`; se indisponivel, retorna 503 para evitar requeue indevido.
