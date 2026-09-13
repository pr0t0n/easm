# Plano de refatoração do control plane de execução

## Objetivo

Garantir que nenhuma tentativa seja contada ou encerrada sem execução confirmada, que falhas sejam classificadas antes de reagir, que recuperação gere uma nova execução verificável e que qualidade só permita progressão após evidência.

## Contrato de estado

Cada work item terá tentativas persistentes com identidade própria. Estados de item: `queued`, `claimed`, `dispatched`, `worker_accepted`, `execution_started`, `mcp_accepted`, `runner_started`, `completed`, `failed`, `blocked`. Estados de tentativa nunca serão inferidos apenas por lease.

## Sequência de implementação

1. Criar entidade persistente de tentativa com `attempt_id`, timestamps, worker, MCP request, runner job, estado, erro classificado e confirmação de execução.
2. Alterar dispatcher para criar `claimed` e só incrementar tentativa após `execution_started` confirmado.
3. Alterar worker/MCP/runner para emitir acknowledgements idempotentes e correlacionados.
4. Refatorar watchdog para consultar a última confirmação antes de renovar lease, reencaminhar ou falhar.
5. Centralizar diagnóstico semântico no supervisor usando timeline completa e evidências.
6. Implementar política de capacidade no supervisor: prioridade, saturação, classe de recurso, troca de capacidade e backoff.
7. Implementar recuperação: reidratação, nova coleta, troca de ferramenta, novo plano e novo work item vinculado à intenção original.
8. Implementar verificação pós-recuperação comparando a nova evidência com a causa diagnosticada.
9. Alterar gates de fase para considerar apenas execução confirmada e qualidade mínima.
10. Recalcular qualidade após estado terminal; snapshots intermediários serão marcados como provisórios.
11. Atualizar comparação de scans para findings, riscos, evidência, cobertura, qualidade e falhas operacionais.
12. Testar cada transição, falha de transporte, expiração de lease, saturação, retry, replanejamento e progressão.

## Critérios de aceitação

- Item queued que nunca foi aceito pelo worker não pode consumir tentativa.
- Lease expirada sem confirmação não pode virar falha técnica.
- MCP indisponível gera diagnóstico de transporte e recuperação verificável.
- Runner ativo não pode ser encerrado pelo watchdog.
- Retry cria tentativa correlacionada; recovery estrutural cria novo work item.
- Gate não avança com itens apenas terminais administrativamente.
- Relatório não apresenta snapshot provisório como qualidade final.
- Scan 38 reproduzido contra o mesmo alvo deve demonstrar execução confirmada, recuperação e progressão sem loop.
