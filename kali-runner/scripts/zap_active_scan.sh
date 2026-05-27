#!/bin/bash
# zap_active_scan.sh — ZAP active scan via Automation Framework
#
# Full OWASP Top 10 active scan with spider + passive + active rules.
# WARNING: This sends active probes to the target — only use on authorized targets!
# Finds: SQLi, XSS, RCE, path traversal, SSRF, authentication bypass, etc.
#
# Usage: zap_active_scan.sh <target_url>
# Example: zap_active_scan.sh https://api.example.com

set -euo pipefail

TARGET="${1:?Usage: zap_active_scan.sh <target_url>}"

UNIQUE_ID="active-$$-$(date +%s)"
ZAP_HOME="/workspace/zap/${UNIQUE_ID}"
ZAP_PLAN="/tmp/zap_plan_${UNIQUE_ID}.yaml"
ZAP_REPORT="/tmp/zap_report_${UNIQUE_ID}.json"

mkdir -p "$ZAP_HOME"

cat > "$ZAP_PLAN" << YAML
env:
  contexts:
    - name: "default"
      urls:
        - "${TARGET}"
      includePaths:
        - "${TARGET}.*"
      excludePaths:
        - ".*logout.*"
        - ".*signout.*"
        - ".*delete.*"
  parameters:
    failOnError: false
    failOnWarning: false
    progressToStdout: true

jobs:
  - type: spider
    name: "spider"
    parameters:
      maxDuration: 3
      maxDepth: 4
      acceptCookies: true
    urls:
      - "${TARGET}"

  - type: passiveScan-wait
    name: "passiveScan-wait"
    parameters:
      maxDuration: 30

  - type: activeScan
    name: "activeScan"
    parameters:
      maxRuleDurationInMins: 2
      maxScanDurationInMins: 10
      addQueryParam: true
      defaultPolicy: "Default Policy"
      scanHeadersAllRequests: true
      threadPerHost: 3

  - type: report
    name: "report"
    parameters:
      template: "traditional-json-plus"
      reportDir: "/tmp"
      reportFile: "$(basename $ZAP_REPORT)"
      reportTitle: "ZAP Active Scan"
      reportDescription: "Active scan results for ${TARGET}"
YAML

echo "[ZAP-ACTIVE] Starting active scan: $TARGET"

timeout 900 zaproxy \
    -cmd \
    -dir "$ZAP_HOME" \
    -autorun "$ZAP_PLAN" \
    2>&1 | grep -v "^$" || true

if [ -f "$ZAP_REPORT" ]; then
    echo "[ZAP-REPORT-START]"
    ZAP_REPORT_FILE="$ZAP_REPORT" python3 - << 'PYEOF'
import json, sys, os

report_file = os.environ.get('ZAP_REPORT_FILE', '')
if not report_file or not os.path.exists(report_file):
    import glob
    reports = glob.glob('/tmp/zap_report_*.json')
    if reports:
        report_file = sorted(reports)[-1]

if not report_file or not os.path.exists(report_file):
    print('{"alerts": [], "error": "no report file found"}')
    sys.exit(0)

try:
    with open(report_file) as f:
        data = json.load(f)

    alerts = []
    sites = data.get('site', []) if isinstance(data, dict) else []
    if isinstance(sites, dict):
        sites = [sites]

    for site in sites:
        for alert in site.get('alerts', []):
            risk = alert.get('riskdesc', 'Informational')
            risk_level = risk.split(' ')[0].lower()
            severity_map = {'high': 'high', 'medium': 'medium', 'low': 'low', 'informational': 'info'}
            severity = severity_map.get(risk_level, 'low')

            instances = alert.get('instances', [])
            evidence = instances[0].get('evidence', '') if instances else ''
            uri = instances[0].get('uri', '') if instances else ''

            alerts.append({
                'title': alert.get('name', ''),
                'severity': severity,
                'risk': risk,
                'confidence': alert.get('confidence', 'Medium'),
                'description': alert.get('desc', ''),
                'solution': alert.get('solution', ''),
                'reference': alert.get('reference', ''),
                'cwe': alert.get('cweid', ''),
                'evidence': evidence,
                'uri': uri,
                'count': alert.get('count', 1),
                'tool': 'zap_active_scan',
            })

    print(json.dumps({'alerts': alerts, 'total': len(alerts)}, indent=2))

except Exception as e:
    print(json.dumps({'alerts': [], 'error': str(e)}))
PYEOF
    echo "[ZAP-REPORT-END]"
fi

rm -f "$ZAP_PLAN" "$ZAP_REPORT" 2>/dev/null || true
rm -rf "$ZAP_HOME" 2>/dev/null || true

echo "[ZAP-ACTIVE] Scan complete for $TARGET"
