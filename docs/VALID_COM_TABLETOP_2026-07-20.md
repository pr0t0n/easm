# Smoke/tabletop do fluxo de pentest — `valid.com`

Validação concluída em 20/07/2026. O cenário percorre o fluxo completo desde a autorização até relatório e Dashboard, mas não envia tráfego ao `valid.com`, não cria scan, não grava no banco e não inicia jobs no Kali runner. Juice Shop, DVWA e o laboratório IDOR não fazem parte desta validação.

## Resultado executivo

| Controle | Resultado |
|---|---:|
| Contratos tabletop | 43/43 aprovados |
| Fases | P01–P22 |
| Ferramentas únicas nas fases | 83/83 catalogadas |
| Perfis carregados no runner | 118 |
| Executáveis detectados | 951 |
| Endpoints descobertos adicionados | 49 únicos |
| Endpoints sintéticos totais | 59 |
| Rotas canônicas | 58 |
| Testes aplicáveis planejados | 55 |
| Hipóteses priorizadas | 55 |
| Requisições ao alvo | 0 |
| Jobs criados pelo tabletop | 0; ativos 0 |
| Escritas no banco | 0 |
| Fluxos de business logic | 10 |
| Invariantes de negócio | 165 |
| Endpoints BL bloqueados por pré-condição | 30 |
| Backend | 393 testes aprovados em 6,92 s |
| Frontend | 5 testes aprovados; build de produção concluído |

Status final: **aprovado**.

## Como o fluxo se comportaria

1. A entrada `valid.com` é normalizada como host público.
2. Sem atestado explícito de autorização, a plataforma bloqueia o teste antes da fila. Com atestado, o gate permite continuar.
3. O escopo aceita `valid.com` e subdomínios como `api.valid.com`, mas rejeita confusões de prefixo/sufixo como `notvalid.com` e `valid.com.attacker.invalid`.
   A mesma decisão é repetida após a execução: linhas produzidas internamente pela ferramenta para outro domínio são descartadas antes de achados e inventário.
   Redirect não é seguido pela ferramenta. O `Location` é capturado, resolvido e somente gera um probe separado quando seu host pertence ao escopo autorizado; destinos externos ficam registrados como bloqueados sem receber tráfego.
4. O perfil `full` percorre os contratos P01–P22. Cada fase tem ferramentas, evidência mínima e critério de saída.
5. A descoberta sintética representa home, autenticação, APIs com IDs de objeto, administração, inputs, fetch/proxy, arquivos, XML/SOAP, upload/import, operações sensíveis, tokens/MFA, OpenAPI, `www.valid.com/search?search=tabletop`, execução sensível e JavaScript estático.
6. URLs `/api/orders/42` e `/api/orders/43` convergem para a mesma rota canônica `/api/orders/{id}`; os exemplos concretos continuam disponíveis para auditoria.
7. Um query string sozinho não agenda SQLMap ou Dalfox. A matriz nasce da semântica do endpoint e cobre autenticação, autorização de objeto, contrato de API, upload, parâmetros e mudança de estado.
   No caso `search`, a plataforma cria baseline e hipótese diferencial `xss_sqli` em modo seguro, exigindo comparação payload/baseline e controle negativo antes de qualquer escalada específica.
8. Testes horizontais exigem duas identidades. A simulação usa `user_a` e `user_b`; se a matriz estiver incompleta, a hipótese é bloqueada com causa explícita.
9. O planner ordena as hipóteses por impacto, confiança, fronteira de autenticação, joia da coroa, prontidão do validador, custo e histórico. No cenário, BFLA no host administrativo vem primeiro; RCE só avança com evidência de autorização do operador.
10. Exit code zero sem prova fica como candidato. Sinal positivo específico pode confirmar, mas achado crítico sem proof pack não é promovido.
11. A correlação de ataque só marca uma cadeia como provada quando os passos têm evidência e o objetivo é alcançável.
12. O gate encerra o scan apenas com qualidade saudável. Gaps altos e remediações concretas produzem `completed_with_gaps`.
13. Dashboard, inteligência, relatório e qualidade consomem os contratos persistidos e foram verificados com autenticação real na API interna.
14. Cada endpoint relevante recebe um contrato de business logic com invariantes, identidades, fixtures, evidências e política de execução. O executor só aceita URLs observadas; descoberta por wordlist, IDs vizinhos, brute force de cupom, SQLi durante login e mutação automática foram removidos do caminho padrão.

## Lote ampliado de endpoints

Foram incorporados 49 paths únicos após remover repetições e normalizar `redirect` como `/redirect`. A análise usa `endpoint-intelligence-v5` e separa descoberta de superfície de hipótese executável:

| Categoria | Exemplos | Decisão antes de conhecer parâmetros/método |
|---|---|---|
| Entrada/reflexão | `/search`, `/comments`, `/feedback`, `/support`, `/messages`, `/test` | descobrir parâmetros, métodos e content types; não presumir XSS/SQLi |
| Fetch/SSRF | `/fetch`, `/proxy`, `/preview`, `/webhook`, `/integrations`, `/image` | descobrir parâmetro URL/callback; não presumir SSRF |
| Redirect | `/redirect`, `/callback`, `/continue` | descobrir parâmetro de destino; não presumir open redirect |
| Arquivo/template | `/download`, `/export`, `/file`, `/view`, `/template`, `/logs`, `/backup`, `/invoice` | exigir autorização anônimo × usuário A × usuário B |
| Dados estruturados | `/xml`, `/soap`, `/import` | descobrir método e content type aceito; não presumir XXE |
| Upload/import | `/upload`, `/import`, `/file` | descobrir contrato de upload; hipótese ativa somente com método de escrita observado |
| Operação sensível | `/profile/update`, `/password/change`, `/email/change`, `/users/create`, `/payment`, `/transfer` | descobrir método real antes de afirmar mudança de estado |
| Autenticação/token | `/saml`, `/login`, `/logout`, `/register`, `/password/reset`, `/otp`, `/mfa`, `/token`, `/refresh` | classificar fronteira de autenticação; tokens exigem evidência de emissão, rotação e replay |
| Objeto | `/api/users/{id}`, `/accounts/{id}`, `/orders/{id}`, `/invoices/{id}`, `/documents/{id}`, `/transactions/{id}` | exigir duas identidades, mesmo objeto e controle negativo |

`/logout` é a exceção semântica: mesmo quando descoberto como GET, é tratado como término de sessão. O contrato exige sessão antes, chamada de logout e sessão depois; ele não é confundido com mass assignment.

## Inteligência de business logic

O tabletop agora valida dez famílias de fluxo: ownership de objeto, movimentação financeira, arquivo/exportação, autenticação, mudança de conta, fetch server-side, redirect, ingestão estruturada, conteúdo de usuário e transição de estado. No cenário, esses fluxos produziram 165 invariantes verificáveis.

- `/payment` e `/transfer`: valor positivo, conservação de saldo, commit único/idempotência e destinatário autorizado;
- rotas `{id}`: duas identidades, o mesmo objeto controlado, consistência lista/detalhe e controle negativo;
- logout/token/refresh/MFA: transição de estado, invalidação server-side, rotação, replay do token antigo e impossibilidade de pular MFA;
- arquivos/exports: escopo do proprietário e seleção de path controlada pelo servidor;
- fetch/redirect: nenhum teste ativo até observar o parâmetro de destino;
- escrita/importação: fixture descartável, read-back e rollback obrigatórios.

Um template `{id}` não é tratado como objeto executável: o plano fica bloqueado até existir um ID concreto pertencente à fixture. Ausência de pré-condição reduz a profundidade no Quality Gate e aparece como gap no relatório/Dashboard; nunca vira sucesso artificial.

## Lacunas encontradas e corrigidas

O tabletop detectou cinco aliases usados pelas fases sem entrada no catálogo/perfil executável:

- `nuclei-js-secrets`;
- `nuclei-js-analysis`;
- `nuclei-misconfiguration`;
- `nuclei-file-upload`;
- `nuclei-swagger`.

Os cinco foram adicionados ao catálogo, às classes de carga/família de vulnerabilidade e aos perfis Nuclei do runner. O runner passou de 113 para 118 perfis carregados.

A auditoria do caminho de despacho encontrou ainda 30 nomes de ferramenta presentes nas fases e no catálogo, mas ausentes em `TOOL_TO_PROFILE`. Na prática, o supervisor podia descartá-los e o worker retornava `no_profile_mapping`. Todos os aliases foram ligados aos respectivos perfis e o tabletop passou a exigir igualdade entre contrato, catálogo e mapa de despacho. A entrada genérica `amass` foi mantida no perfil passivo `amass_enum`; brute force permanece no alias explícito `amass-brute`.

O verificador também detectou que o inventário de ferramentas omitia executáveis-base (`python3` e `bash`) e caminhos absolutos, embora estivessem instalados. `/profiles` agora informa `command_executable_available` e o caminho resolvido pelo próprio runner, eliminando falsos negativos sem executar a ferramenta.

O antigo `phase_tool_smoke_test.py` iniciava ferramentas ativas por padrão. Agora:

- o modo padrão executa apenas o tabletop determinístico;
- `--execute` é obrigatório para iniciar jobs reais;
- `--authorization-attested` também é obrigatório;
- sem ambos, a execução ativa é bloqueada antes do primeiro job.

## Evidência de integração

Com a stack implantada, os endpoints internos responderam dentro dos budgets:

| Contrato | Latência | Payload | HTTP |
|---|---:|---:|---:|
| Dashboard/control-plane | 0,419 s | 169.269 bytes | 200 |
| Avaliação de inteligência | 0,009 s | 1.476 bytes | 200 |
| Relatório unificado | 0,719 s | 1.823.312 bytes | 200 |
| Qualidade | 0,022 s | 16.273 bytes | 200 |

## Como repetir com segurança

Tabletop com contratos ao vivo do runner e zero tráfego ao alvo:

```bash
docker exec -w /app scriptkiddo_backend \
  /opt/venv/bin/python -m scripts.tabletop_valid_com valid.com
```

Tabletop totalmente offline:

```bash
docker exec -w /app scriptkiddo_backend \
  /opt/venv/bin/python -m scripts.tabletop_valid_com valid.com --offline
```

O smoke ativo existe somente para um alvo que o operador esteja autorizado a testar:

```bash
python3 -m scripts.phase_tool_smoke_test alvo-autorizado.example \
  --execute --authorization-attested
```

Esse último comando é deliberadamente destravado apenas por duas opções explícitas e não foi executado contra `valid.com` nesta validação.
