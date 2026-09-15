# Plano de refatoração do control plane de execução

## Objetivo

Garantir que nenhuma tentativa seja contada ou encerrada sem execução confirmada, que falhas sejam classificadas antes de reagir, que recuperação gere uma nova execução verificável e que qualidade só permita progressão após evidência.

## Contrato de estado

Cada work item terá tentativas persistentes com identidade própria. Estados de item: `queued`, `claimed`, `dispatched`, `worker_accepted`, `execution_started`, `mcp_accepted`, `runner_started`, `completed`, `failed`, `blocked`. Estados de tentativa nunca serão inferidos apenas por lease.

Cada item também terá um contrato versionado com intenção, alvo lógico, alvo executável, capacidade, perfil canônico e linhagem. Itens derivados preservam `parent_work_item_id`, `lineage_root_work_item_id`, `derivation_kind`, `derivation_depth` e `validation_depth`. Uma recuperação cria outra geração; uma validação não pode gerar validações recursivas.

O contrato de requisição é independente da capacidade que o executa. Método, URL, localização do parâmetro, corpo, tipo de conteúdo, identidade e origem da evidência são resolvidos primeiro. A capacidade compatível é descoberta no catálogo vivo pelos campos que aceita. O envelope entregue ao bridge é materializado somente depois dessa resolução.

## Causas estruturais identificadas

1. Produtores criavam itens diretamente e gravavam combinações diferentes de perfil, alvo e metadados.
2. O alvo lógico usado para idempotência era confundido com o alvo executável.
3. Contexto derivado tinha precedência prática sobre requisições observadas, mesmo quando a observação era mais autoritativa.
4. Dados de requisição resolvidos não eram colocados no campo de argumentos que o bridge efetivamente transporta.
5. Rotas de execução escolhiam capacidades compatíveis por condicionais locais, criando silos e comportamento diferente entre execução principal, suplementar e recuperação.
6. O supervisor registrava um replanejamento mesmo quando o scan fechado tornava o sucessor inexequível.
7. O watchdog apagava itens pendentes de scans terminais, destruindo a trilha que deveria provar por que uma recuperação não executou.
8. Serviços consumidores iniciavam após o processo de suas dependências existir, antes de sua prontidão funcional.
9. A suíte declarava uma dependência assíncrona, mas a configuração desativava seu plugin e escondia um teste como `skipped`.

## Responsabilidades do control plane

### 1. Observação

- Consolidar eventos de agente, logs, tentativas, acknowledgements, jobs, evidências, bindings, wires e decisões em uma timeline correlacionada.
- Preservar itens terminais e suas tentativas. Nenhum guardião pode apagar o histórico para limpar fila.
- Registrar origem e autoridade de cada campo reidratado.

### 2. Diagnóstico semântico

- Classificar `data_missing`, `data_contradictory`, `contract_degraded`, `capacity_unavailable`, `transient_error`, `inconclusive_result` e `impossible_state`.
- Separar ausência de evidência, incompatibilidade de capacidade, falha de transporte e ausência de resultado.
- Basear a decisão na timeline e no contrato resolvido, sem inferir falha a partir de lease ou flag isolada.

### 3. Reestruturação

- Reidratar o contexto a partir de artefato, requisição observada, endpoint e parâmetro persistidos, nessa ordem de autoridade aplicável.
- Corrigir bindings derivados quando uma observação exata os contradiz.
- Invalidar derivações recursivas e criar uma nova geração ligada à intenção original.
- Impedir criação de sucessor inexequível em scan terminal; usar apenas o canal explícito de revalidação pós-scan.

### 4. Correção em voo

- Descobrir uma capacidade compatível no catálogo vivo a partir do contrato requerido.
- Materializar método, corpo, conteúdo e parâmetro no envelope transportado.
- Criar um novo item para mudança estrutural; usar uma nova tentativa para repetição transitória confirmada.
- Aplicar orçamento de gerações. Ao esgotar alternativas verificáveis, abrir broken glass com causa e evidência.

### 5. Verificação e progressão

- Exigir a sequência `falha → diagnóstico → coleta/replanejamento → novo work item/tentativa → execução confirmada → evidência terminal → decisão`.
- Marcar recuperação como `verified` somente quando o novo resultado responde à causa diagnosticada.
- Manter resultado inconclusivo como inconclusivo; `skipped`, timeout ou encerramento administrativo não constituem prova negativa.
- Recalcular qualidade e progressão após a verificação causal.

## Matriz de reação

| Diagnóstico | Ação | Novo estado verificável | Condição de saída |
|---|---|---|---|
| Dado ausente | Coletar evidência autoritativa | binding/artefato persistido e item `retry` | contrato resolvido ou broken glass |
| Dado contraditório | Reidratar e invalidar derivação | correção com fonte e nova geração | binding coincide com evidência |
| Contrato degradado | Descobrir capacidade compatível | perfil e envelope adaptados | bridge aceita o contrato |
| Capacidade indisponível | Trocar capacidade/classe | item sucessor correlacionado | execução confirmada |
| Erro transitório | Redispatch com tentativa nova | attempt com acknowledgements | terminal confirmado ou orçamento esgotado |
| Resultado inconclusivo | Validador alternativo | item sucessor e evidência independente | confirmação, refutação ou broken glass |
| Estado impossível | Broken glass | bloqueio explícito com timeline | intervenção ou nova evidência |

## Invariantes

- `attempts` só aumenta depois de `execution_started`.
- Todo item ativo tem perfil canônico não vazio e `execution_target` limpo.
- Todo acknowledgement carrega IDs correlacionáveis entre item, tentativa, bridge e runner.
- Uma requisição mutável nunca é executada sem corpo observado.
- Um contrato mutável resolvido nunca é enviado por uma capacidade incapaz de receber corpo.
- `env_vars` de execução ficam em `arguments.env_vars`, que é o contrato transportado pelo bridge.
- `validation_depth` nunca excede um.
- Um scan final não recebe recovery comum; revalidação pós-scan exige wire, finding e adjudicação explícitos.
- Um item terminal não pode manter tentativa ativa.
- Watchdog terminaliza inconsistências e preserva a trilha; nunca as apaga.
- `blocked` e `paused` são estados operacionais válidos e não são tratados como corrupção.
- Consumers iniciam somente depois da saúde funcional das dependências.

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
- A suíte integral deve executar o teste assíncrono, sem marca desconhecida e sem skip causado por plugin desativado.
- `docker compose config` deve validar os perfis dev, prod e pentest-lab.
- Todos os ambientes Python devem passar `pip check` e a migração deve estar em `head`.
- A revalidação do caso real deve persistir o contrato resolvido, a adaptação, a tentativa, os acknowledgements e o resultado terminal.
