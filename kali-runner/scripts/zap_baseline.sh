#!/bin/bash
# zap_baseline.sh — ZAP passive scan via Automation Framework
#
# Runs a ZAP passive scan on the target URL using the Automation Framework YAML.
# Passive scan only — no active probing, safe for production targets.
# Generates findings: missing security headers, CSP issues, cookie flags,
# information disclosure, SSL/TLS issues, and external JS without SRI.
#
# Usage: zap_baseline.sh <target_url>
# Example: zap_baseline.sh https://example.com

set -euo pipefail

TARGET="${1:?Usage: zap_baseline.sh <target_url>}"

# Sanitize target for use in filenames
SAFE_TARGET=$(echo "$TARGET" | sed 's|[^a-zA-Z0-9._-]|_|g' | cut -c1-80)
UNIQUE_ID="baseline-$$-$(date +%s)"
ZAP_HOME="/workspace/zap/${UNIQUE_ID}"
ZAP_PLAN="/tmp/zap_plan_${UNIQUE_ID}.yaml"
ZAP_REPORT="/tmp/zap_report_${UNIQUE_ID}.json"

mkdir -p "$ZAP_HOME"

# Write ZAP Automation Framework plan
cat > "$ZAP_PLAN" << YAML
env:
  contexts:
    - name: "default"
      urls:
        - "${TARGET}"
      includePaths: []
      excludePaths: []
  parameters:
    failOnError: false
    failOnWarning: false
    progressToStdout: true

jobs:
  - type: spider
    name: "spider"
    parameters:
      maxDuration: 2
      maxDepth: 3
      acceptCookies: true
      handleParameters: USE_ALL
    urls:
      - "${TARGET}"

  - type: passiveScan-wait
    name: "passiveScan-wait"
    parameters:
      maxDuration: 60

  - type: report
    name: "report"
    parameters:
      template: "traditional-json-plus"
      reportDir: "/tmp"
      reportFile: "$(basename $ZAP_REPORT)"
      reportTitle: "ZAP Baseline Scan"
      reportDescription: "Passive scan results for ${TARGET}"
YAML

echo "[ZAP-BASELINE] Starting passive scan: $TARGET"
echo "[ZAP-BASELINE] Home: $ZAP_HOME"

# Run ZAP with automation framework
timeout 300 zaproxy \
    -cmd \
    -dir "$ZAP_HOME" \
    -autorun "$ZAP_PLAN" \
    2>&1 | grep -v "^$" | grep -v "InsecureRequestWarning" || true

# Parse JSON report if it exists
if [ -f "$ZAP_REPORT" ]; then
    echo "[ZAP-REPORT-START]"
    python3 - << 'PYEOF'
import json, sys, os

report_file = os.environ.get('ZAP_REPORT_FILE', '')
if not report_file:
    # Try to find the report
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
                'wasc': alert.get('wascid', ''),
                'evidence': evidence,
                'uri': uri,
                'count': alert.get('count', 1),
                'tool': 'zap_baseline',
            })

    print(json.dumps({'alerts': alerts, 'total': len(alerts)}, indent=2))

except Exception as e:
    print(json.dumps({'alerts': [], 'error': str(e)}))
PYEOF
    echo "[ZAP-REPORT-END]"
else
    echo "[ZAP-BASELINE] No JSON report generated — outputting raw results"
fi

# Cleanup
rm -f "$ZAP_PLAN" "$ZAP_REPORT" 2>/dev/null || true
rm -rf "$ZAP_HOME" 2>/dev/null || true

echo "[ZAP-BASELINE] Scan complete for $TARGET"
