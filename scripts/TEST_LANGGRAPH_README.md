# Validacao LangGraph e Kali Runner

Os scripts deste diretorio validam o fluxo atual da plataforma:

```text
LangGraph node -> worker Cyber Kill Chain -> Kali Runner profile -> evidence/result -> findings/report
```

## Validacao Rapida

```bash
python3 scripts/validate_kali_toolflow.py
python3 scripts/validate_agent_contract_and_flow.py
python3 scripts/validate_timeouts.py
```

## Validacao Com Docker

Suba a stack:

```bash
docker compose --profile dev up --build
```

Valide o runner:

```bash
python3 scripts/validate_kali_toolflow.py --live --runner-url http://localhost:8088
```

Valide grupos principais:

```bash
bash scripts/test_worker_recon.sh --live
bash scripts/test_worker_osint.sh --live
bash scripts/test_worker_vuln.sh --live
```

## Teste E2E

```bash
python3 scripts/validate_e2e_flow.py --base-url http://localhost:8000 --target example.com --timeout 300
```

O backend nao deve ter ferramentas ofensivas instaladas. Se um profile falhar,
o ajuste deve ser feito no Kali runner: Dockerfile, profile YAML ou variaveis
de ambiente exigidas pelo profile.
