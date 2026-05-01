# Sistema de Orquestração de Agentes com Celery

## 📋 Visão Geral

O sistema implementa orquestração completa de agentes autônomos via Celery com:
- Fila de prioridades para agentes
- Supervisor que coordena fases de pentesting
- Validação automática de completude
- Retry com backoff exponencial
- Integração com LangGraph workflow
- API REST para monitoramento

## 🏗️ Arquitetura

```
┌─────────────────────────────────────────────────────────────┐
│                    LangGraph Workflow                        │
│                                                              │
│  [Supervisor Node] ──┐                                      │
│                      │                                      │
│                      ↓                                      │
│    [Agent Orchestrator Node] ◄─── dispatch_agents_for_mission
│                                                              │
└─────────────────────────────────────────────────────────────┘
                        │
                        │
                        ↓
┌─────────────────────────────────────────────────────────────┐
│                   Agent Supervisor                           │
│  (app/workers/agent_supervisor.py)                          │
│                                                              │
│  • Cria plano de fases                                      │
│  • Submete agentes ao Celery                                │
│  • Monitora progresso                                       │
│  • Controla retries                                         │
└─────────────────────────────────────────────────────────────┘
                        │
                        │
                        ↓
┌─────────────────────────────────────────────────────────────┐
│              Celery Task Queue                               │
│                                                              │
│  ┌──────────────────────────────────────────┐              │
│  │  execute_agent_phase (P01, P02, ...)     │ Priority: 8  │
│  └──────────────────────────────────────────┘              │
│                        │                                    │
│  ┌──────────────────────────────────────────┐              │
│  │  dispatch_from_queue                     │ Priority: 7  │
│  └──────────────────────────────────────────┘              │
│                        │                                    │
│  ┌──────────────────────────────────────────┐              │
│  │  record_tool_execution                   │ Priority: 6  │
│  └──────────────────────────────────────────┘              │
│                        │                                    │
│  ┌──────────────────────────────────────────┐              │
│  │  validate_phase_completion                │ Priority: 8  │
│  └──────────────────────────────────────────┘              │
└─────────────────────────────────────────────────────────────┘
                        │
                        ↓
┌─────────────────────────────────────────────────────────────┐
│              Agent Dispatcher                                │
│  (app/workers/agent_dispatcher.py)                          │
│                                                              │
│  AgentQueue:                                                │
│    • Fila de agentes com prioridades                        │
│    • Rastreamento de tarefas                                │
│    • Status de execução                                     │
└─────────────────────────────────────────────────────────────┘
                        │
                        ↓
┌─────────────────────────────────────────────────────────────┐
│            Agent Registry & Orchestrator                     │
│  (app/agents/agent_registry.py, orchestrator.py)            │
│                                                              │
│  • 19 agentes especializados                                │
│  • Validação de pré-requisitos                              │
│  • Rastreamento de execução                                 │
│  • Detecção de gaps                                         │
└─────────────────────────────────────────────────────────────┘
                        │
                        ↓
┌─────────────────────────────────────────────────────────────┐
│              Banco de Dados (PostgreSQL)                     │
│                                                              │
│  Tables:                                                    │
│    • executed_tool_runs - Rastreamento de ferramentas       │
│    • scan_jobs - Estado de scans                            │
│    • scan_audit_logs - Auditoria de agentes                 │
│    • findings - Achados de vulnerabilidades                 │
└─────────────────────────────────────────────────────────────┘
```

## 🔄 Fluxo de Execução

### 1. Submissão de Scan

```python
# Via API ou workflow
task_id = submit_scan_orchestration(scan_id)
```

### 2. Supervisor Cria Plano

```
AgentSupervisor.create_execution_plan()
  ↓
Retorna: [P01, P02, P05, P11, P12, ...]  # Fases críticas
```

### 3. Fases Executadas Sequencialmente

```
Para cada fase (P01, P02, ...):
  1. execute_agent_phase(scan_id, phase_id)
     └─ Cria AgentOrchestrator
     └─ Enfileira todos os agentes da fase
     └─ Prioriza agentes por valor de negócio
  
  2. dispatch_from_queue()
     └─ Remove agente de maior prioridade
     └─ Marca como "running"
  
  3. Agente Executa Ferramentas
     └─ Para cada ferramenta:
        └─ record_tool_execution(tool_name, target, status)
  
  4. validate_phase_completion(scan_id, phase_id)
     └─ Valida se 66% de ferramentas obrigatórias executaram
     └─ Se sim → proxima fase
     └─ Se não → retry_phase() com backoff
```

### 4. Monitoramento

```python
# Via API ou polling
status = get_agent_execution_status(scan_id)
# Retorna:
# {
#   "phases_completed": 3,
#   "phases_incomplete": ["P07", "P10"],
#   "queue_status": {
#     "pending": 5,
#     "running": 2,
#     "completed": 15
#   }
# }
```

## 📁 Arquivos Criados

### `agent_dispatcher.py`
Gerencia fila de tarefas e execução de agentes:
- `AgentExecutionTask` - Tarefa individual de agente
- `AgentQueue` - Fila com prioridades
- `execute_agent_phase()` - Task Celery: executa agentes para uma fase
- `record_tool_execution()` - Task Celery: registra execução de ferramenta
- `validate_phase_completion()` - Task Celery: valida completude

### `agent_supervisor.py`
Supervisiona orquestração completa:
- `AgentSupervisor` - Classe que coordena fases e retries
- `orchestrate_scan()` - Task Celery: executão completa
- `check_phase_progress()` - Task Celery: monitora fase

### `agent_workflow_integration.py`
Integra com LangGraph workflow:
- `dispatch_agents_for_mission()` - Despacha agentes
- `check_agent_progress()` - Verifica progresso
- `integrate_agents_with_workflow()` - Adiciona nó ao grafo

### `routes_agents.py`
Endpoints REST para monitoring:
- `POST /api/agents/submit/{scan_id}` - Submete execução
- `GET /api/agents/status/{scan_id}` - Status de execução
- `GET /api/agents/queue/status/{scan_id}` - Status da fila
- `POST /api/agents/retry/{scan_id}/{phase_id}` - Retenta fase
- `GET /api/agents/phases/plan/{scan_id}` - Plano de fases
- `GET /api/agents/agents/{phase_id}` - Lista agentes

## 🔧 Configuração

### Celery Settings (em `celery_app.py`)

```python
celery.conf.update(
    task_track_started=True,                    # Rastreia início
    worker_prefetch_multiplier=1,               # Prefetch=1 (serial)
    task_soft_time_limit=1800,                  # 30 min soft limit
    task_time_limit=2100,                       # 35 min hard limit
    task_acks_late=True,                        # Reconhece após sucesso
    broker_transport_options={
        "visibility_timeout": 3600,             # 1 hora de timeout
    },
)
```

### Queue Configuration

```
Filas:
  • worker.unit.reconhecimento   - Recon agents (priority: 9)
  • worker.unit.analise_vulnerabilidade - Vuln agents (priority: 9)
  • worker.unit.osint - OSINT agents (priority: 8)
  • worker.unit.exploit - Exploit agents (priority: 7)
  • worker.unit.code - Code analysis agents (priority: 6)
```

## 📊 Exemplo de Uso

### Via API

```bash
# 1. Submeter execução
curl -X POST "http://localhost:8001/api/agents/submit/1" \
  -H "Authorization: Bearer $TOKEN"
# Retorna: {"task_id": "...", "status": "submitted"}

# 2. Verificar status
curl -X GET "http://localhost:8001/api/agents/status/1" \
  -H "Authorization: Bearer $TOKEN"
# Retorna: {
#   "phases_completed": 3,
#   "phases_incomplete": ["P07"],
#   "queue_status": {"pending": 2, "running": 1, "completed": 12}
# }

# 3. Retenta fase incompleta
curl -X POST "http://localhost:8001/api/agents/retry/1/P07" \
  -H "Authorization: Bearer $TOKEN"
# Retorna: {"status": "retrying", "task_id": "..."}
```

### Via Python/Celery

```python
from app.workers.agent_supervisor import submit_scan_orchestration

# Submete
task_id = submit_scan_orchestration(scan_id=1)

# Monitora (em loop)
from app.workers.agent_supervisor import AgentSupervisor
from app.db.session import SessionLocal

db = SessionLocal()
supervisor = AgentSupervisor(scan_id=1, db=db)
summary = supervisor.get_execution_summary()
print(summary)
# {
#   'phases_completed': 3,
#   'incomplete_phases': ['P07', 'P10'],
#   'phase_results': {...}
# }
```

## ⚡ Validações e Garantias

### Validação de Completude

Cada fase é validada com critérios estritos:
- ✅ 66% de ferramentas obrigatórias DEVEM executar
- ✅ Ferramentas com sucesso (status="success") são contabilizadas
- ✅ Falhas são rastreadas para retry automático
- ✅ Máximo 2 retries por fase

### Idempotência

```python
# ExecutedToolRun usa constraints:
UniqueConstraint("scan_job_id", "tool_name", "target")

# Resultado: mesma ferramenta no mesmo alvo não executa 2x
# (atualiza registro existente)
```

### Retry Logic

```
Retry após falha:
  1. Contador incrementa
  2. Se < max_retries (2):
     → Requeue com backoff (60s)
     → Retry com prioridade reduzida
  3. Se >= max_retries:
     → Mark as "failed"
     → Log e continua próxima fase
```

## 🔐 Segurança

### Autenticação
- Todos os endpoints requerem Bearer token
- Verificação de ownership (user_id) antes de retornar dados

### Autorização
- Usuários veem apenas seus próprios scans
- Admins podem ver todos

### Isolamento
- Cada scan tem seu próprio supervisor
- Tarefas Celery isoladas por scan_id

## 📈 Escalabilidade

### Horizontal Scaling
```bash
# Iniciar múltiplos workers
celery -A app.workers.celery_app worker \
  -Q worker.unit.reconhecimento -c 4 -l INFO

celery -A app.workers.celery_app worker \
  -Q worker.unit.analise_vulnerabilidade -c 8 -l INFO

celery -A app.workers.celery_app worker \
  -Q worker.unit.osint -c 2 -l INFO
```

### Monitoramento
```bash
# Flower (web UI)
celery -A app.workers.celery_app flower

# CLI
celery -A app.workers.celery_app inspect active
celery -A app.workers.celery_app inspect stats
```

## 🐛 Troubleshooting

### Tarefas Não Executam
```python
# Check broker connection
from app.workers.celery_app import celery
celery.broker_connection().connect()

# Check tasks registered
celery.inspect().registered_tasks()

# Check queue
celery.inspect().active_queues()
```

### Fila Presa
```python
# Purge queue (DANGER!)
celery.control.purge()

# Revoke task
celery.control.revoke(task_id, terminate=True)
```

### Debug Logging
```python
# Enable debug
import logging
logging.basicConfig(level=logging.DEBUG)

# Check agent dispatch
from app.workers.agent_dispatcher import _agent_queue
print(_agent_queue.get_status_summary(scan_id=1))
```

---

## 📝 Próximas Melhorias

1. **Event-Driven**: Usar Celery Events para callback real-time
2. **Distributed Lock**: Redis lock para evitar race conditions
3. **Metrics**: Prometheus para monitoramento
4. **Dead Letter Queue**: Rastrear falhas permanentes
5. **Dynamic Routing**: Redirecionar agentes por carga de CPU/memória
