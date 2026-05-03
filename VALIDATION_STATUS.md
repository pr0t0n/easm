# Status de Validacao - Fluxo Kali Runner

## Estado Atual

- O backend e os workers ficaram sem instalacao de ferramentas ofensivas.
- O `kali_runner` e a unica origem de execucao de ferramentas.
- Os workers foram organizados por Cyber Kill Chain: scope, reconnaissance, weaponization, delivery, exploitation, installation, command_control, actions_on_objectives e reporting.
- O catalogo vivo fica em `GET /api/kali-runner/catalog`.
- O Phase Monitor interpreta disponibilidade como profile/binario pronto no Kali, nao como binario instalado no backend.

## Validacoes

```bash
python3 scripts/validate_kali_toolflow.py
python3 scripts/validate_agent_contract_and_flow.py
python3 scripts/validate_timeouts.py
```

Com a stack no ar:

```bash
python3 scripts/validate_kali_toolflow.py --live --runner-url http://localhost:8088
bash scripts/test_worker_recon.sh --live
bash scripts/test_worker_osint.sh --live
bash scripts/test_worker_vuln.sh --live
```

## Contrato

1. Worker escolhe ferramenta pelo grafo LangGraph e skill/phase da missao.
2. Backend traduz `tool -> profile` em `backend/app/services/kali_executor.py`.
3. Worker envia `POST /jobs` para o `kali_runner`.
4. Kali executa o profile YAML e persiste evidencias em `/workspace/{scan_id}/{tool}/{job_id}`.
5. Backend coleta `GET /jobs/{id}/result`, normaliza stdout/stderr/parsed e alimenta findings, logs, phase monitor e relatorio.

Qualquer ferramenta nova deve entrar primeiro em `kali-runner/profiles/*.yaml`, depois no mapa `TOOL_TO_PROFILE`, no grupo de worker e na skill/fase correspondente.
