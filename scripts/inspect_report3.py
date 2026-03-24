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
r1 = get_json(b + '/api/scans/1/report?prioritized_limit=200&prioritized_offset=0', token)

state = r1.get('state_data') or {}
report_v2 = state.get('report_v2') or {}

# vulnerability_table - check all entries
vt = report_v2.get('vulnerability_table') or []
print(f'=== VULNERABILITY_TABLE (total: {len(vt)}) ===')
print(json.dumps(vt[:3], indent=2, ensure_ascii=False))
print()

# recon_findings - all
rf = report_v2.get('recon_findings') or []
print(f'=== RECON_FINDINGS (total: {len(rf)}) ===')
print(json.dumps(rf[:3], indent=2, ensure_ascii=False))
print()

# waf from report_v2
waf = report_v2.get('waf_summary') or {}
print('=== WAF_SUMMARY ===')
print(json.dumps(waf, indent=2, ensure_ascii=False))
print()

# security_headers_summary
shs = report_v2.get('security_headers_summary') or {}
print('=== SECURITY_HEADERS_SUMMARY ===')
print(json.dumps(shs, indent=2, ensure_ascii=False))
print()

# Look for WAF mentions in all findings
findings = r1.get('findings') or []
print(f'=== FINDINGS total: {len(findings)} ===')

waf_findings = []
for f in findings:
    details = f.get('details') or {}
    title = str(f.get('title') or '').lower()
    evidence = str(details.get('evidence') or '').lower()
    tool  = str(details.get('tool') or '').lower()
    if any(kw in title + evidence + tool for kw in ['waf', 'akamai', 'mod_security', 'modsecurity', 'cloudflare']):
        waf_findings.append(f)
    # Also check vulnerabilities_encontradas
print(f'WAF-related findings: {len(waf_findings)}')
for f in waf_findings[:5]:
    print(json.dumps({'id': f.get('id'), 'title': f.get('title'), 'details_tool': (f.get('details') or {}).get('tool'), 'details_evidence': str((f.get('details') or {}).get('evidence'))[:200]}, indent=2, ensure_ascii=False))
    print('---')

# Also check vulnerabilidades_encontradas in state_data
vulns = state.get('vulnerabilidades_encontradas') or []
print(f'=== VULNERABILIDADES_ENCONTRADAS (total: {len(vulns)}) ===')
waf_vulns = [v for v in vulns if any(kw in str(v).lower() for kw in ['waf', 'akamai', 'mod_security', 'modsecurity'])]
print(f'WAF-related in vulns: {len(waf_vulns)}')
for v in waf_vulns[:5]:
    print(json.dumps(v, indent=2, ensure_ascii=False)[:500])
    print('---')

# Check unique targets in findings
targets = sorted(set(str(f.get('details', {}).get('asset') or f.get('details', {}).get('target') or '') for f in findings))
print(f'\n=== UNIQUE ASSET TARGETS IN FINDINGS ({len(targets)}) ===')
print(targets[:30])
