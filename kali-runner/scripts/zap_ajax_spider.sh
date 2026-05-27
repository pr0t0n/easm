#!/bin/bash
# zap_ajax_spider.sh — ZAP AJAX spider for Single Page Applications (SPAs)
#
# Uses ZAP's AJAX spider with headless browser to crawl React/Angular/Vue apps
# that rely on JavaScript to render content. Combined with passive scan.
#
# Usage: zap_ajax_spider.sh <target_url>
# Example: zap_ajax_spider.sh https://app.example.com

set -euo pipefail

TARGET="${1:?Usage: zap_ajax_spider.sh <target_url>}"

UNIQUE_ID="ajax-$$-$(date +%s)"
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
    urls:
      - "${TARGET}"

  - type: spiderAjax
    name: "spiderAjax"
    parameters:
      maxDuration: 3
      maxCrawlStates: 10
      browserid: firefox-headless
      clickDefaultElems: true
      clickElemsOnce: true
      randomInputs: true
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
      reportTitle: "ZAP AJAX Spider Scan"
      reportDescription: "AJAX spider results for ${TARGET}"
YAML

echo "[ZAP-AJAX] Starting AJAX spider scan: $TARGET"

timeout 600 zaproxy \
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
                'cwe': alert.get('cweid', ''),
                'evidence': evidence,
                'uri': uri,
                'count': alert.get('count', 1),
                'tool': 'zap_ajax_spider',
            })

    print(json.dumps({'alerts': alerts, 'total': len(alerts)}, indent=2))

except Exception as e:
    print(json.dumps({'alerts': [], 'error': str(e)}))
PYEOF
    echo "[ZAP-REPORT-END]"
fi

rm -f "$ZAP_PLAN" "$ZAP_REPORT" 2>/dev/null || true
rm -rf "$ZAP_HOME" 2>/dev/null || true

echo "[ZAP-AJAX] Scan complete for $TARGET"
