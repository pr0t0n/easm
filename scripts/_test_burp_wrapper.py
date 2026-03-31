"""Test Burp wrapper with stale detection - runs directly via subprocess like tool_adapters.py"""
import subprocess, sys, time

print(f"[{time.strftime('%H:%M:%S')}] Iniciando teste burp-cli wrapper via subprocess...", flush=True)

cmd = [
    "/app/scripts/burp_cli_wrapper.sh", "scan",
    "--url", "http://lojinha.flashapp.com.br",
    "--format", "json", "-a"
]

env = {
    "PATH": "/usr/local/bin:/usr/bin:/bin",
    "BURP_API_HOST": "burp_rest",
    "BURP_API_PORT": "1337",
    "BURP_API_KEY": "",
    "BURP_SCAN_TIMEOUT": "1500",
    "BURP_STALE_TIMEOUT": "120",  # 2min stale para teste mais rapido
    "BURP_PAUSE_MAX_RETRIES": "3",
    "BURP_REAL_CLI": "/usr/local/bin/burp-api-cli",
    "BURP_START_SCRIPT": "/usr/local/bin/start-burp-rest",
    "HOME": "/root",
}

start = time.time()
try:
    result = subprocess.run(
        cmd, capture_output=True, text=True, timeout=600, env=env
    )
    elapsed = time.time() - start
    print(f"\n[{time.strftime('%H:%M:%S')}] Concluido em {elapsed:.0f}s (exit code: {result.returncode})", flush=True)
    print(f"\n--- STDERR ---\n{result.stderr[-2000:]}", flush=True)
    stdout = result.stdout.strip()
    if stdout:
        # Tentar parsear JSON
        import json
        try:
            data = json.loads(stdout)
            issues = data.get("issue_events", [])
            print(f"\n--- RESULTADO ---", flush=True)
            print(f"Issues encontradas: {len(issues)}", flush=True)
            for iss in issues[:10]:
                i = iss.get("issue", {})
                print(f"  - [{i.get('severity','?')}] {i.get('name','?')} @ {i.get('path','?')}", flush=True)
        except json.JSONDecodeError:
            print(f"\n--- STDOUT (not JSON, first 500 chars) ---\n{stdout[:500]}", flush=True)
    else:
        print("\n--- STDOUT vazio ---", flush=True)
except subprocess.TimeoutExpired:
    elapsed = time.time() - start
    print(f"\n[{time.strftime('%H:%M:%S')}] TIMEOUT apos {elapsed:.0f}s", flush=True)
except Exception as e:
    print(f"\n[{time.strftime('%H:%M:%S')}] ERRO: {e}", flush=True)
