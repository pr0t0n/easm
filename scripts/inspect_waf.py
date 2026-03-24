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
r1 = get_json(b + '/api/scans/1/report?prioritized_limit=10&prioritized_offset=0', token)

state = r1.get('state_data') or {}
v2 = state.get('report_v2') or {}

# WAF summary
waf = v2.get('waf_summary')
print('WAF_SUMMARY raw type:', type(waf), 'value:', waf)

# Vulnerability table stats
vt = v2.get('vulnerability_table') or []
print(f'Vulnerability table count: {len(vt)}')
tools_in_vt = sorted(set(r.get('tool') for r in vt))
print('Tools in vulnerability_table:', tools_in_vt)
waf_rows = [r for r in vt if str(r.get('tool') or '').lower() == 'wafw00f']
print(f'wafw00f rows in vulnerability_table: {len(waf_rows)}')
for r in waf_rows:
    print('  ->',r.get('target'), r.get('name'), r.get('severity'))

# Recon findings
rf = v2.get('recon_findings') or []
print(f'Recon findings count: {len(rf)}')
waf_recon = [r for r in rf if str(r.get('tool') or '').lower() == 'wafw00f']
print(f'wafw00f rows in recon_findings: {len(waf_recon)}')

# lista_ativos from state_data
ativos = state.get('lista_ativos', []) or []
print(f'\nlista_ativos count: {len(ativos)}')
print('Assets:', ativos)
