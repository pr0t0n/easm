#!/bin/bash
# interactsh OOB probe — registers callback payloads and captures them.
#
# interactsh-client is a long-lived listener: it registers an out-of-band
# callback domain and polls forever. For a profile run we only need it to
# register the payload(s) and emit the callback URL(s) that downstream SSRF/
# RCE tests inject into the target. We run it briefly, capture the registered
# URLs, then exit 0 so the runner records a successful job.
#
# Usage: interactsh_probe.sh [count]
COUNT="${1:-3}"
OUT=$(timeout 20 interactsh-client -v -json -n "$COUNT" -pi 5 2>&1 || true)
echo "$OUT"
# Always succeed — a timeout-kill of the listener is the expected lifecycle.
exit 0
