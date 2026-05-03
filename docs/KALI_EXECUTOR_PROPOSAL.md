# Proposta: Kali Linux como "Tool Executor" remoto

> Status: **proposta**, não implementada. Avaliação técnica para crescimento.

## Contexto

Hoje cada `worker_*` (`recon`, `osint`, `vuln`, `exploit`, `code`) é uma cópia da
imagem `easm-backend` com ~58 tools instaladas via Dockerfile. Isso funciona
mas tem três limitações:

1. **Build lento (~6–10 min)** porque o `Dockerfile` precisa instalar Go, Rust,
   gems, npm, pip, e várias tools de fonte (massdns, jwt_tool, paramspider,
   theHarvester, sublist3r, etc.).
2. **Imagem inflada (~6 GB cada)** — 5 imagens × 6 GB = 30 GB locais.
3. **Toolset estagnado** — para adicionar uma ferramenta nova a equipe precisa
   editar Dockerfile, rebuildar, repushar e recriar todos os 5 workers.

Já mitigamos isso parcialmente com **auto-install on-demand** (padrão
xalgorix) em [tool_catalog.py:_TOOL_INSTALL_RECIPES](../backend/app/services/tool_catalog.py).
A próxima evolução natural é mover **toda a execução de tools para um único
container Kali Linux** centralizado, e fazer os workers Python apenas
**despacharem comandos** para esse executor.

## Arquitetura proposta

```
┌──────────────┐   tool dispatch   ┌─────────────────────┐
│ worker_recon │ ────────────────► │   Kali Executor     │
│ worker_vuln  │ ◄──────────────── │   (single container)│
│ worker_osint │   stdout+stderr   │                     │
│ worker_…     │                   │ • 600+ tools nativas│
└──────────────┘                   │ • SSH ou docker exec│
                                   │ • workdir por scan  │
                                   └─────────────────────┘
```

### Stack

- Imagem base: `kalilinux/kali-rolling` + `kali-linux-headless` metapackage
- Acesso: `docker exec` direto (workers e Kali no mesmo `docker-compose`)
  ou SSH (`paramiko`) se Kali ficar em host externo
- Workdir isolado: `/scans/{scan_id}/{tool}/{run_id}/` (volume montado)
- Resultado: cada execução escreve `stdout.txt`, `stderr.txt`, `exit_code.txt`
  no workdir; worker lê e persiste no DB exatamente como hoje

### Mudança no código

```python
# backend/app/services/worker_dispatcher.py
def execute_tool_with_workers(tool: str, target: str, scan_mode: str):
    if settings.use_kali_executor:
        return _execute_via_kali(tool, target, scan_mode)
    return _execute_local(tool, target, scan_mode)  # comportamento atual

def _execute_via_kali(tool, target, scan_mode):
    cmd = TOOL_COMMAND_TEMPLATES[tool].format(target=target)
    workdir = f"/scans/{scan_id}/{tool}/{uuid4()}"
    result = subprocess.run([
        "docker", "exec", "pentest_kali",
        "bash", "-lc",
        f"mkdir -p {workdir} && cd {workdir} && {cmd}",
    ], capture_output=True, text=True, timeout=tool_timeout(tool))
    return {
        "command": cmd,
        "return_code": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "status": "executed" if result.returncode == 0 else "failed",
    }
```

### docker-compose

```yaml
kali:
  image: kalilinux/kali-rolling
  container_name: pentest_kali
  command: >
    bash -lc "
      apt-get update -qq &&
      apt-get install -y --no-install-recommends kali-linux-headless openssh-server &&
      service ssh start &&
      tail -f /dev/null
    "
  volumes:
    - kali_scans:/scans
  profiles: ["dev", "prod"]
  cap_add: [NET_RAW, NET_ADMIN]   # masscan, hping precisam
```

## Trade-offs

| Aspecto                      | Hoje (per-worker tools)             | Kali Executor                      |
|------------------------------|-------------------------------------|------------------------------------|
| Disk                         | 30 GB (5 × 6 GB)                    | ~10 GB (1 Kali + 5 workers leves)  |
| Build time                   | 6–10 min                            | ~2 min (workers leves)             |
| Tool count                   | 58 manualmente curadas              | 600+ do metapackage                |
| Latência por tool            | nativa (subprocess)                 | +50–200 ms (docker exec)           |
| Atualização de tools         | rebuild + recreate                  | `apt-get upgrade kali-linux-…`     |
| Isolamento de scans          | implícito (worker per-fork)         | precisa workdir explícito          |
| CAP_NET_RAW (raw sockets)    | já configurado                      | precisa configurar uma vez         |
| Auditoria forense            | logs distribuídos                   | tudo em /scans/ — fácil tar+SIEM   |

## Quando vale a pena migrar

Recomendado quando uma das condições for verdadeira:

- **>100 tools** no catálogo (hoje temos 58)
- **>3 ferramentas/mês** sendo adicionadas pelo time
- **Storage >50 GB** consumido por imagens easm-*
- **>5 workers** rodando em paralelo (hoje 5)
- **Precisa kali-meta** (ex.: tools como `responder`, `bloodhound`,
  `crackmapexec` que dependem de toolchain Kali completa)

Hoje (58 tools, 5 workers, 30 GB) o ROI é marginal. A
[auto-install on-demand](../backend/app/services/tool_catalog.py#L504) cobre o
caso de tool faltante sem precisar rebuild. Manter a opção de Kali como
plano B.

## Caminho incremental sem big-bang

Se decidirmos seguir, dá para migrar gradualmente:

1. Subir o container Kali com SSH/exec habilitado
2. Adicionar `settings.use_kali_executor` (default `False`)
3. Implementar `_execute_via_kali` em paralelo ao `_execute_local`
4. Habilitar para 1 ferramenta de cada vez (ex.: `nuclei` primeiro), comparar
   resultados em `executed_tool_runs.error_message` para validar paridade
5. Quando 100% das tools tiverem comportamento idêntico, flippar o flag para
   `True` e magrar o Dockerfile dos workers (remove `go install ...` etc.)

## Referências

- `usestrix/strix` — usa **um sandbox Docker isolado por agente**, parecido em
  espírito mas a granularidade é por agente (não por tool).
- `xalgord/xalgorix` — usa **subprocess local com auto-install** (já
  adotamos esse padrão).
- Kali metapackages: <https://www.kali.org/docs/general-use/metapackages/>
