# Incidente de escopo — scan #6 (`valid.com`)

## Estado final

O scan #6 foi interrompido e permanece `stopped`, sem work items ativos. Ele foi marcado como não retomável. Os domínios externos, achados e vulnerabilidades derivados do incidente não aparecem mais no inventário nem nos dashboards.

## Causa raiz

Os alvos enviados pelo backend e gravados em `batch_targets` pertenciam a `valid.com`. A fuga ocorreu dentro do processo `httpx`:

- `-tls-probe` transformou SANs encontrados em certificados em novos alvos ativos;
- `-follow-redirects` permitiu que redirects atravessassem para outro host;
- a persistência confiava na saída estruturada sem repetir a validação de escopo.

Assim, a validação antes da fila estava correta, mas não enxergava alvos criados internamente pela ferramenta.

## Contenção e quarentena

Antes da limpeza, os registros foram copiados para tabelas recuperáveis com o prefixo `scope_incident_scan6_20260720_`.

| Registro fora do escopo | Quantidade |
|---|---:|
| Domínios em achados | 311 |
| Achados | 1.094 |
| Ativos | 4 |
| Vulnerabilidades | 4 |
| Vínculos de cobertura | 311 |

Após a transação de limpeza, restaram zero achados e zero ativos fora de `valid.com` associados ao scan #6.

## Correções

- `httpx` não usa mais expansão de SAN nem redirect automático;
- `curl` não usa mais `-L` nos perfis de inspeção e validação;
- Katana, Hakrawler e Gospider não seguem redirects automaticamente; o inventário de crawler descarta URLs externas antes do upsert;
- cada `Location` é resolvido e validado; apenas destinos dentro do `authorized_scope` viram um novo probe, com profundidade limitada;
- destinos externos de redirect são mantidos como evidência bloqueada, sem requisição;
- a saída JSONL do `httpx` é filtrada antes de ser salva e consumida;
- achados, ativos, vulnerabilidades, inventário ofensivo e ledgers repetem o gate de escopo antes de persistir;
- o Kali runner rejeita jobs sem `authorized_scope` explícito;
- fallbacks que contornavam a persistência central passaram a falhar fechados.

## Validação

- backend: 393 testes aprovados;
- frontend: 5 testes aprovados e build de produção concluído;
- tabletop: 43/43 contratos, zero tráfego e zero escrita;
- regressão específica: fan-out por SAN bloqueado, redirect interno permitido de forma controlada e redirect externo bloqueado.
