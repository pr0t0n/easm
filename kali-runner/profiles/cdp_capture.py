#!/usr/bin/env python3
"""Captura via CDP (Chrome DevTools Protocol) — para ANÁLISE de business logic.
Abre a app no chromium, navega, e captura: requisições (método+url+postData),
cookies e localStorage/sessionStorage. Saída JSON. NÃO é hardcoded por alvo.

Modos (genéricos, via argv — todos opcionais):
  argv[1] URL        alvo
  argv[2] WAIT       segundos do pump principal (default 10)
  argv[3] TOKEN      injeta token em chaves comuns de localStorage (carrega autenticado)
  argv[4] USER       login REAL via form (o app grava o que quiser → storage genuíno)
  argv[5] PASS       senha do login por form
  argv[6] ROUTES     rotas a visitar (csv) p/ disparar XHRs autenticadas (basket/{id}…)

Precedência: se USER+PASS → login por form (preferível, comportamento real do app);
senão se TOKEN → injeta token. Depois navega ROUTES p/ expandir a superfície."""
import asyncio, json, subprocess, time, urllib.request, sys, os, re
import websockets

URL = sys.argv[1] if len(sys.argv) > 1 else "http://juice-shop:3000"
WAIT = int(sys.argv[2]) if len(sys.argv) > 2 else 10
TOKEN = sys.argv[3] if len(sys.argv) > 3 else ""
USER = sys.argv[4] if len(sys.argv) > 4 else ""
PASS = sys.argv[5] if len(sys.argv) > 5 else ""
ROUTES = [r for r in (sys.argv[6].split(",") if len(sys.argv) > 6 and sys.argv[6] else []) if r.strip()]

udir = f"/tmp/cdp-{os.getpid()}"
proc = subprocess.Popen(
    ["chromium", "--headless=new", "--no-sandbox", "--disable-gpu", "--disable-dev-shm-usage",
     f"--user-data-dir={udir}", "--remote-debugging-port=9223", "about:blank"],
    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

# JS genérico de login por form: acha input[type=password], o campo de usuário
# imediatamente anterior (text/email/tel), preenche de forma compatível com
# frameworks (native setter + eventos input/change) e submete. Sem seletor por alvo.
LOGIN_JS = """
(function(u,p){
  function setVal(el,v){
    var proto = el.tagName==='TEXTAREA'?window.HTMLTextAreaElement.prototype:window.HTMLInputElement.prototype;
    var setter = Object.getOwnPropertyDescriptor(proto,'value').set;
    setter.call(el,v);
    el.dispatchEvent(new Event('input',{bubbles:true}));
    el.dispatchEvent(new Event('change',{bubbles:true}));
  }
  var pw=document.querySelector('input[type=password]');
  if(!pw) return 'no-pw';
  var inputs=[].slice.call(document.querySelectorAll('input'));
  var idx=inputs.indexOf(pw), user=null;
  for(var i=idx-1;i>=0;i--){var t=(inputs[i].type||'text').toLowerCase(); if(['text','email','tel'].indexOf(t)>=0){user=inputs[i];break;}}
  if(!user){user=inputs.filter(function(x){return ['text','email'].indexOf((x.type||'text').toLowerCase())>=0;})[0];}
  if(user) setVal(user,u);
  setVal(pw,p);
  var btn=document.querySelector('button[type=submit],input[type=submit],#loginButton,button#loginButton');
  if(!btn && pw.form) btn=pw.form.querySelector('button');
  if(btn){btn.click(); return 'clicked';}
  if(pw.form){ if(pw.form.requestSubmit) pw.form.requestSubmit(); else pw.form.submit(); return 'submitted';}
  return 'no-submit';
})(%s,%s)
"""


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
    login_status = "not-attempted"
    async with websockets.connect(wsu, max_size=None) as ws:
        async def send(method, params=None):
            nonlocal _id; _id += 1
            await ws.send(json.dumps({"id": _id, "method": method, "params": params or {}}))
            return _id

        async def pump(seconds, want_id=None):
            """Drena mensagens por N s, coletando requestWillBeSent; se want_id,
            retorna o valor daquele Runtime.evaluate assim que chegar."""
            result = None
            end = time.time() + seconds
            while time.time() < end:
                try:
                    msg = json.loads(await asyncio.wait_for(ws.recv(), timeout=1.5))
                except asyncio.TimeoutError:
                    continue
                except Exception:
                    break
                if msg.get("method") == "Network.requestWillBeSent":
                    r = msg["params"]["request"]
                    reqs.append({"method": r.get("method"), "url": r.get("url"),
                                 "postData": r.get("postData", "")})
                elif want_id is not None and msg.get("id") == want_id:
                    result = (msg.get("result", {}).get("result", {}) or {}).get("value")
                    return result   # resultado chegou → não desperdiça o budget restante
            return result

        async def navigate(u):
            await send("Page.navigate", {"url": u})

        async def evaluate(expr, budget=4):
            i = await send("Runtime.evaluate", {"expression": expr, "returnByValue": True})
            return await pump(budget, want_id=i)

        for m in ("Network.enable", "Page.enable", "Runtime.enable"):
            await send(m)
        await navigate(URL)
        await pump(3)

        if USER and PASS:
            # login REAL via form — tenta a página atual e rotas de login comuns
            base = URL.rstrip("/")
            # rotas de login comuns PRIMEIRO (a home raramente tem o form)
            login_routes = [URL + "/#/login", base + "/login", base + "/login.php",
                            base + "/signin", URL]
            js = LOGIN_JS % (json.dumps(USER), json.dumps(PASS))
            login_status = "no-login-form"
            for lr in login_routes:
                await navigate(lr); await pump(2)
                res = await evaluate(js, budget=3)
                if res in ("clicked", "submitted"):
                    login_status = f"form:{res}"
                    await pump(4)   # deixa o app autenticar e gravar storage
                    break
            if login_status == "no-login-form" and TOKEN:
                # fallback: form não encontrado → injeta token p/ manter superfície autenticada
                keys = ["token", "jwt", "access_token", "authentication", "auth_token", "id_token"]
                expr = ";".join([f"localStorage.setItem('{k}', {json.dumps(TOKEN)})" for k in keys])
                await evaluate(expr, budget=2)
                await navigate(URL); await pump(2)
                login_status = "token-injected-fallback"
        elif TOKEN:
            keys = ["token", "jwt", "access_token", "authentication", "auth_token", "id_token"]
            expr = ";".join([f"localStorage.setItem('{k}', {json.dumps(TOKEN)})" for k in keys])
            await evaluate(expr, budget=2)
            await navigate(URL); await pump(2)
            login_status = "token-injected"

        # navega rotas de negócio p/ disparar XHRs autenticadas (basket/{id}, cupom…)
        for route in ROUTES[:8]:
            await navigate(URL.rstrip("/") + ("" if route.startswith("/") else "/") + route)
            await pump(2.5)

        # pump principal final + leitura de storage
        await pump(WAIT)
        ls = await evaluate("JSON.stringify(Object.entries(localStorage))", budget=4) or ""
        ss = await evaluate("JSON.stringify(Object.entries(sessionStorage))", budget=4) or ""
        ck_id = await send("Network.getAllCookies")
        cookies = []
        end = time.time() + 4
        while time.time() < end:
            try:
                msg = json.loads(await asyncio.wait_for(ws.recv(), timeout=1.5))
            except Exception:
                break
            if msg.get("id") == ck_id:
                cookies = [{"name": c.get("name"), "httpOnly": c.get("httpOnly"),
                            "secure": c.get("secure")} for c in msg.get("result", {}).get("cookies", [])]
                break
            if msg.get("method") == "Network.requestWillBeSent":
                r = msg["params"]["request"]
                reqs.append({"method": r.get("method"), "url": r.get("url"), "postData": r.get("postData", "")})
        storage = {"localStorage": ls, "sessionStorage": ss, "cookies": cookies}

    # dedup requests por (method, path)
    seen, api = set(), []
    for r in reqs:
        if re.search(r"/(rest|api|v\d|graphql)/", r["url"] or ""):
            k = (r["method"], r["url"].split("?")[0])
            if k not in seen:
                seen.add(k); api.append(r)
    print(json.dumps({"login_status": login_status, "storage": storage,
                      "api_count": len(api), "api_requests": api[:40]}, indent=2))


try:
    asyncio.run(main())
finally:
    proc.kill()
