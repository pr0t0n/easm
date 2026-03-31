import urllib.request, json
for sid in range(1, 20):
    try:
        r = urllib.request.urlopen(f'http://127.0.0.1:1337/v0.1/scan/{sid}', timeout=3)
        d = json.loads(r.read())
        m = d.get('scan_metrics', {})
        ss = d.get('scan_status', '?')
        print(f'scan={sid} status={ss} crawl={m.get("crawl_requests_made",0)} audit={m.get("audit_requests_made",0)} queue={m.get("audit_queue_items_waiting",0)} issues={len(d.get("issue_events",[]))}')
    except urllib.error.HTTPError:
        break
    except Exception as e:
        print(f'scan={sid} err={e}')
