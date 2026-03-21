# RUNBOOK Operacional - vASM

## Objetivo
Guia de operacao para incidentes, restart seguro, requeue de scans orfaos e rollback da stack.

## Perfis de execucao

### Desenvolvimento
```bash
docker compose --profile dev up --build
```

### Producao
```bash
docker compose --profile prod up --build -d
```

## Comandos de Diagnostico Rapido

### 1. Saude geral API
```bash
curl -s http://localhost:8000/health
```

### 2. Saude de workers
```bash
curl -s -H "Authorization: Bearer <ADMIN_TOKEN>" \
  http://localhost:8000/api/worker-manager/health
```

### 3. Overview de operacao
```bash
curl -s -H "Authorization: Bearer <ADMIN_TOKEN>" \
  http://localhost:8000/api/worker-manager/overview
```

## Reconciliacao de Scans Orfaos

### Dry-run (nao altera estado)
```bash
curl -s -X POST \
  -H "Authorization: Bearer <ADMIN_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"older_than_seconds": 300, "limit": 100, "dry_run": true}' \
  http://localhost:8000/api/worker-manager/requeue-orphans
```

### Requeue efetivo
```bash
curl -s -X POST \
  -H "Authorization: Bearer <ADMIN_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"older_than_seconds": 300, "limit": 100, "dry_run": false}' \
  http://localhost:8000/api/worker-manager/requeue-orphans
```

## Procedimento de Incidente

### Cenário A: Worker offline
1. Confirmar no endpoint `/api/worker-manager/health` quais workers ficaram offline.
2. Verificar logs dos containers:
```bash
docker compose logs --tail=200 worker_unit worker_scheduled
```
3. Reiniciar worker afetado:
```bash
docker compose restart worker_unit
# ou
docker compose restart worker_scheduled
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
docker compose restart worker_unit
docker compose restart worker_scheduled
```
4. Verificar health da API e workers.
5. Rodar dry-run de órfãos para confirmar consistencia.

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
