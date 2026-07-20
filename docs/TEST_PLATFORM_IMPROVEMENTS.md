# Melhorias de performance, profundidade e visibilidade de testes

Implementação concluída em 20/07/2026. O trabalho exclui, conforme solicitado, execução recorrente ou análise dos laboratórios Juice Shop, DVWA e IDOR.

## Performance

- `scan_work_items` é a fonte canônica de tentativas, sucessos, falhas, skips, progresso, espera, throughput, paralelismo e ETA. Ledgers de ferramentas não são mais misturados no denominador.
- Ledgers `submitted/running` são reconciliados com o work item terminal ao concluir o scan.
- Katana e Nikto passaram a aceitar lotes de alvos; os perfis exigem `target_type: targets_file`, evitando o alvo sentinela `__batch__`.
- O ajuste AIMD usa primeiro a pressão de memória do cgroup/container. Memória global do host só é fallback, evitando reduzir a concorrência por causa do baseline do Docker Desktop.
- Ativos ofensivos são normalizados por host/origem; paths ficam em endpoints. Serviços HTTP/HTTPS são persistidos a partir dos endpoints.
- O endpoint de relatório não chama mais Ollama/LLM em leitura. Recomendações de IA são geradas pelo worker e persistidas; a leitura usa fallback determinístico.
- Cockpit e relatório têm paginação. O estado interno completo do scan e seções duplicadas não são mais enviados ao browser.
- A paginação de findings do Cockpit ocorre no PostgreSQL, antes do enriquecimento EPSS/MITRE. Quatro índices compostos sustentam os filtros e ordenações de findings, work items, hipóteses e execuções de ferramentas.
- O Dashboard usa um BFF (`/api/dashboard/control-plane`) para consolidar Cockpit, scans, verificação, crown jewels, OSINT e alertas, reduzindo round-trips e mantendo um contrato único de leitura.
- Rotas React usam carregamento sob demanda. O bundle inicial minificado caiu de 529 kB para 239 kB; as páginas viraram chunks independentes.

## Profundidade e qualidade

- Quality Gate exige score mínimo de 70 e ausência de gaps altos. “Não há nova remediação automática” agora resulta em `completed_with_gaps`, não em aprovação falsa.
- Falha interna no gate também conclui com gaps visíveis, nunca por `error_bypass` aprovado.
- Qualidade ganhou componente de profundidade: hipóteses resolvidas, identidades, sessões válidas, endpoints com requisito de autenticação classificado, contratos de API, parâmetros e serviços.
- Hipóteses testadas deixam a fila aberta (`tested_candidate`, `validated`, `refuted` ou bloqueio explícito), evitando que o mesmo lote cause starvation das hipóteses seguintes.
- Validadores seguros drenam lotes nas fases aplicáveis até não haver hipóteses abertas. Bloqueios diferenciam falta de autenticação, falta de validador e pré-condição.
- Achados high/critical sem validação/evidência e matrizes de autorização sem duas identidades são blockers explícitos.
- O compositor de scan suporta duas identidades auditáveis (bearer, cookie, basic ou header) e mantém compatibilidade com autenticação legada de identidade única.
- Retestes são deduplicados enquanto estão em fila/em execução e atualizam um `RetestRun` real e o estado final do finding.
- LFI, SSTI, path traversal, XSS e SQLi usam validação diferencial segura (baseline, canário e controle negativo); RCE sem autorização explícita é bloqueado e auditado.
- Gates históricos que apareciam como aprovados abaixo de 70 são exibidos como `historical_mismatch`.

## Relatórios e dashboards

- Cockpit retorna `quality`, `execution_metrics`, gaps e paginação de findings.
- Dashboard mostra score/grade, estado do gate, progresso, sucesso, paralelismo e quantidade de gaps.
- SLIs de fila p95, sucesso de execução e score de qualidade são persistidos no scan; desvios criam alertas deduplicados, e a recuperação do indicador resolve o alerta correspondente.
- Relatório principal mostra completude do teste, fases saudáveis, achados verificados, p95 de espera e ETA.
- Plano de ação inclui prioridade, responsável sugerido, SLA e esforço, além de evidência.
- `completed_with_gaps` é terminal e aparece explicitamente nas telas, filtros, comparações e APIs.
- O contrato unificado `/api/pentest/scans/{id}/report-contract` permanece a fonte de readiness, autorização, autenticação, execução, evidência, ferramentas, findings e qualidade.
- Login por e-mail/senha na query string do relatório legado foi removido; somente token/refresh token da sessão é aceito.
- A rota visual legada agora redireciona para o relatório principal; formatos técnico/CSV continuam como exportações do mesmo scan.

## Automação e critérios de aceitação

- Backend: 356 testes passaram em 6,58 s. Chamadas reais de LLM foram desativadas no ambiente de teste.
- Frontend: 5 testes de contrato passaram e o build de produção concluiu; ambos fazem parte do CI.
- CI agora executa backend, frontend e migrations. Não adiciona execução de laboratórios vulneráveis.
- Budgets automatizados cobrem agregação de 10 mil work items e contratos HTTP de Dashboard, relatório e qualidade.
- Na validação implantada final, o Dashboard/BFF respondeu em 0,713 s (168.398 bytes), o relatório em 0,805 s (1.822.225 bytes) e qualidade em 0,024 s (16.120 bytes).

## Saneamento histórico e reversibilidade

- O backfill criou seis tabelas de backup com sufixo `20260720` antes de alterar dados.
- Foram consolidados 9.963 ativos duplicados por path, inferidos 239 serviços e reconciliadas 3.203 execuções de ferramentas obsoletas.
- O scan histórico foi reavaliado como `completed_with_gaps`, preservando os blockers reais em vez de uma aprovação inconsistente.
- Uma segunda execução resultou em zero merges, criações ou reconciliações, comprovando a idempotência do saneamento.
- O banco foi atualizado até a revisão Alembic `0022`; os quatro índices novos e os três alertas SLI históricos foram conferidos diretamente no PostgreSQL.

Metas operacionais recomendadas para acompanhamento no próprio Cockpit:

- p95 de espera em fila menor que 5 minutos;
- sucesso de execução maior ou igual a 75%, com skips separados;
- Quality Score maior ou igual a 70 e nenhum blocker alto;
- 100% dos high/critical com evidence pack e validação;
- 100% dos endpoints relevantes com `auth_required` classificado;
- duas ou mais identidades válidas quando o escopo autenticado exigir autorização horizontal/vertical.
