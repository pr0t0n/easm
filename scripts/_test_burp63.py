"""Test burp-cli on scan 63 target."""
import time
from app.services.tool_adapters import run_tool_execution
from app.graph.workflow import _extract_burp_cli_findings

target = "http://lojinha.flashapp.com.br"
print(f"=== Executando burp-cli em {target} ===")
t0 = time.time()
res = run_tool_execution("burp-cli", target)
elapsed = time.time() - t0
print(f"elapsed={elapsed:.0f}s")
print(f"status={res.get('status')}")
print(f"return_code={res.get('return_code')}")
out = str(res.get("raw_output") or res.get("stdout") or "")
err = str(res.get("stderr") or "")
print(f"stdout_len={len(out)}")
print(f"stderr_len={len(err)}")

findings = _extract_burp_cli_findings(out, "RiskAssessment", "lojinha.flashapp.com.br")
print(f"findings_count={len(findings)}")
for f in findings[:10]:
    print(f"  [{f.get('severity')}] {f.get('title','')[:100]}  tool={f.get('details',{}).get('tool')}")

if not findings and out:
    print(f"stdout_preview={out[:2000]}")
if err:
    print(f"stderr_preview={err[:1000]}")
print("=== DONE ===")
