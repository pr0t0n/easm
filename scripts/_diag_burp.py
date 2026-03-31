import sys, json, urllib.request

# Check all scan IDs 1-15 and dump full structure for the latest
for sid in range(1, 16):
    url = f"http://127.0.0.1:1337/v0.1/scan/{sid}"
    try:
        with urllib.request.urlopen(url, timeout=5) as resp:
            d = json.loads(resp.read())
        m = d.get("scan_metrics", {})
        status = m.get("scan_status", d.get("scan_status", "???"))
        crawl = m.get("crawl_requests_made", 0)
        audit = m.get("audit_requests_made", 0)
        queue = m.get("audit_queue_items_waiting", 0)
        issues = len(d.get("issue_events", []))
        print(f"scan={sid} status={status} crawl={crawl} audit={audit} queue={queue} issues={issues}")
    except Exception as e:
        print(f"scan={sid} ERROR: {e}")

# Dump full structure of scan 12 (latest)
print("\n=== FULL SCAN 12 STRUCTURE ===")
try:
    with urllib.request.urlopen("http://127.0.0.1:1337/v0.1/scan/12", timeout=5) as resp:
        d = json.loads(resp.read())
    # Print all top-level keys and their types
    for k, v in d.items():
        if k == "issue_events":
            print(f"  {k}: list[{len(v)}]")
        elif isinstance(v, dict):
            print(f"  {k}: {json.dumps(v)[:200]}")
        else:
            print(f"  {k}: {v}")
except Exception as e:
    print(f"ERROR: {e}")
