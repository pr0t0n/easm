#!/usr/bin/env python3
"""Captura via CDP (Chrome DevTools Protocol) — para ANÁLISE de business logic.
Abre a app no chromium, navega, e captura: requisições (método+url+postData),
cookies e localStorage/sessionStorage. Saída JSON. NÃO é hardcoded por alvo."""
import asyncio, json, subprocess, time, urllib.request, sys, os, signal
import websockets

URL = sys.argv[1] if len(sys.argv) > 1 else "http://juice-shop:3000"
WAIT = int(sys.argv[2]) if len(sys.argv) > 2 else 12
# token de sessão (do generic_auth) p/ capturar estado AUTENTICADO. Genérico:
# injeta em chaves de localStorage comuns a SPAs (token/jwt/access_token).
TOKEN = sys.argv[3] if len(sys.argv) > 3 else ""

udir = f"/tmp/cdp-{os.getpid()}"
proc = subprocess.Popen(
    ["chromium", "--headless=new", "--no-sandbox", "--disable-gpu", "--disable-dev-shm-usage",
     f"--user-data-dir={udir}", "--remote-debugging-port=9223", "about:blank"],
    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def ws_url():
    for _ in range(15):
        try:
            data = json.load(urllib.request.urlopen("http://localhost:9223/json", timeout=2))
            for t in data:
                if t.get("type") == "page":
                    return t["webSocketDebuggerUrl"]
        except Exception:
            time.sleep(1)
    return None

async def main():
    wsu = ws_url()
    if not wsu:
        print(json.dumps({"error": "no CDP target"})); return
    reqs = []
    _id = 0
    pending = {}
    async with websockets.connect(wsu, max_size=None) as ws:
        async def send(method, params=None):
            nonlocal _id; _id += 1
            await ws.send(json.dumps({"id": _id, "method": method, "params": params or {}}))
            return _id
        for m in ("Network.enable", "Page.enable", "Runtime.enable"):
            await send(m)
        await send("Page.navigate", {"url": URL})
        if TOKEN:
            # estabelece a origin, injeta o token nas chaves comuns, recarrega
            await asyncio.sleep(3)
            keys = ["token", "jwt", "access_token", "authentication", "auth_token", "id_token"]
            expr = ";".join([f"localStorage.setItem('{k}', {json.dumps(TOKEN)})" for k in keys])
            await send("Runtime.evaluate", {"expression": expr})
            await send("Page.navigate", {"url": URL})
        end = time.time() + WAIT
        while time.time() < end:
            try:
                msg = json.loads(await asyncio.wait_for(ws.recv(), timeout=2))
            except asyncio.TimeoutError:
                continue
            except Exception:
                break
            if msg.get("method") == "Network.requestWillBeSent":
                r = msg["params"]["request"]
                reqs.append({"method": r.get("method"), "url": r.get("url"),
                             "postData": r.get("postData", "")})
        # storage + cookies (eval + CDP)
        ls_id = await send("Runtime.evaluate", {"expression": "JSON.stringify(Object.entries(localStorage))", "returnByValue": True})
        ss_id = await send("Runtime.evaluate", {"expression": "JSON.stringify(Object.entries(sessionStorage))", "returnByValue": True})
        ck_id = await send("Network.getAllCookies")
        storage = {"localStorage": "", "sessionStorage": "", "cookies": []}
        deadline = time.time() + 5
        got = set()
        while time.time() < deadline and len(got) < 3:
            try:
                msg = json.loads(await asyncio.wait_for(ws.recv(), timeout=2))
            except Exception:
                break
            if msg.get("id") == ls_id:
                storage["localStorage"] = (msg.get("result", {}).get("result", {}) or {}).get("value", ""); got.add("ls")
            elif msg.get("id") == ss_id:
                storage["sessionStorage"] = (msg.get("result", {}).get("result", {}) or {}).get("value", ""); got.add("ss")
            elif msg.get("id") == ck_id:
                storage["cookies"] = [c.get("name") for c in msg.get("result", {}).get("cookies", [])]; got.add("ck")
    # dedup requests por (method, path)
    seen, api = set(), []
    import re
    for r in reqs:
        if re.search(r"/(rest|api|v\d|graphql)/", r["url"] or ""):
            k = (r["method"], r["url"].split("?")[0])
            if k not in seen:
                seen.add(k); api.append(r)
    print(json.dumps({"storage": storage, "api_count": len(api), "api_requests": api[:25]}, indent=2))

try:
    asyncio.run(main())
finally:
    proc.kill()
