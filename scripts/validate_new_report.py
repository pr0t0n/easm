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

print('REPORT_V2 KEYS:', list(v2.keys()))
print()

assets = v2.get('assets_summary') or {}
print('ASSETS_SUMMARY:', json.dumps(assets, indent=2, ensure_ascii=False))
print()

fbs = v2.get('findings_by_subdomain') or {}
print(f'FINDINGS_BY_SUBDOMAIN: {len(fbs)} subdomains with findings')
for sub, rows in list(fbs.items())[:5]:
    print(f'  {sub}: {len(rows)} findings')
