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
r1 = get_json(b + '/api/scans/1/report?prioritized_limit=5&prioritized_offset=0', token)

print('=== TOP KEYS ===')
print(list(r1.keys()))
print('TARGET:', r1.get('target'))
print()

state = r1.get('state_data') or {}
print('=== STATE_DATA KEYS ===')
print(list(state.keys()))
print()

print('=== ASSETS ===')
print('lista_ativos:', state.get('lista_ativos', [])[:15])
print('discovered_assets:', state.get('discovered_assets', [])[:15])
print('hosts:', state.get('hosts', [])[:15])
print()

report_v2 = state.get('report_v2') or {}
print('=== REPORT_V2 KEYS ===')
print(list(report_v2.keys()))
print()

sec = report_v2.get('security_posture') or {}
print('=== SECURITY_POSTURE KEYS ===')
print(list(sec.keys()))
print()

waf = sec.get('waf_summary') or {}
print('=== WAF SUMMARY ===')
print(json.dumps(waf, indent=2, ensure_ascii=False))
print()

# Check technologies
tech = report_v2.get('technologies') or {}
print('=== TECHNOLOGIES ===')
print(json.dumps(dict(list(tech.items())[:20]), indent=2, ensure_ascii=False))
print()

# Check prioritized findings structure
pf = r1.get('prioritized_findings') or []
print('=== PRIORITIZED FINDINGS (first 3) ===')
for f in pf[:3]:
    print(json.dumps(f, indent=2, ensure_ascii=False))
    print('---')
print()

# Check findings by subdomain
print('=== UNIQUE TARGETS IN PRIORITIZED_FINDINGS ===')
targets = set(f.get('target') for f in pf)
print(sorted(targets)[:20])
