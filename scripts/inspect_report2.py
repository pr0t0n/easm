import json
import urllib.request

b = 'http://localhost:8000'

def post_json(url, payload):
    data = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data, headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(req, timeout=20) as r:
        return json.loads(r.read().decode())

def get_json(url, token):
    req = urllib.request.Request(url, headers={'Authorization': 'Bearer ' + token})
    with urllib.request.urlopen(req, timeout=20) as r:
        return json.loads(r.read().decode())

token = post_json(b + '/api/auth/login', {'email': 'admin@example.com', 'password': 'admin123'})['access_token']
r1 = get_json(b + '/api/scans/1/report?prioritized_limit=20&prioritized_offset=0', token)

state = r1.get('state_data') or {}
report_v2 = state.get('report_v2') or {}

# Full assets list
print('=== LISTA_ATIVOS (ALL) ===')
ativos = state.get('lista_ativos', []) or []
print(f'Total: {len(ativos)}')
print(ativos)
print()

# WAF summary
print('=== WAF_SUMMARY (top-level in report_v2) ===')
waf = report_v2.get('waf_summary') or {}
print(json.dumps(waf, indent=2, ensure_ascii=False))
print()

# vulnerability_table
vt = report_v2.get('vulnerability_table') or []
print(f'=== VULNERABILITY_TABLE (total: {len(vt)}) ===')
for v in vt[:5]:
    print(json.dumps(v, indent=2, ensure_ascii=False))
    print('---')

# recon_findings
rf = report_v2.get('recon_findings') or []
print(f'=== RECON_FINDINGS (total: {len(rf)}) ===')
for f in rf[:3]:
    print(json.dumps(f, indent=2, ensure_ascii=False))
    print('---')

# findings top-level
findings = r1.get('findings') or []
print(f'=== FINDINGS TOP-LEVEL (total: {len(findings)}) ===')
for f in findings[:3]:
    print(json.dumps(f, indent=2, ensure_ascii=False))
    print('---')

# osint_findings
osint = report_v2.get('osint_findings') or []
print(f'=== OSINT_FINDINGS (total: {len(osint)}) ===')
for f in osint[:3]:
    print(json.dumps(f, indent=2, ensure_ascii=False))
    print('---')

# coverage_summary
coverage = report_v2.get('coverage_summary') or {}
print('=== COVERAGE_SUMMARY ===')
print(json.dumps(coverage, indent=2, ensure_ascii=False))
