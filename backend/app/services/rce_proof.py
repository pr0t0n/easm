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

def _detect(text: str) -> tuple[str, str] | None:
    """Retorna (comando, trecho) se alguma assinatura de execução casar."""
    for cmd, pat in _SIGNATURES:
        m = pat.search(text or "")
        if m:
            start = max(0, m.start() - 20)
            return cmd, text[start:m.end() + 60]
    return None


def verify_rce(
    target_url: str,
    proof_cmd: str = "id",
    os_hint: str = "linux",
    *,
    observed_parameter: str | None = None,
) -> dict:
    """Tenta provar RCE no alvo com um comando de prova seguro. Bounded.

    Retorna: confirmed(bool), vector, command, evidence, attempts, note.
    """
    proof_cmd = proof_cmd if is_safe_proof_command(proof_cmd) else "id"
    win_cmd = "ver"
    result = {
        "target": target_url, "confirmed": False, "vector": None,
        "command": proof_cmd, "evidence": None, "attempts": 0,
        "note": None, "safe_proof": True, "negative_control_passed": False,
    }
    base = target_url if str(target_url).startswith("http") else f"https://{target_url}"
    base = base.rstrip("/")

    if not observed_parameter or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,63}", observed_parameter):
        result["note"] = "RCE inconclusivo: nenhum parâmetro/sink observado foi fornecido; nenhuma rota foi adivinhada."
        result["inconclusive"] = True
        return result

    try:
        with httpx.Client(timeout=_TIMEOUT, follow_redirects=False, verify=False,
                          headers={"User-Agent": "Mozilla/5.0 (easm-rce-proof)"}) as c:
            # Negative control prevents static page text from being mistaken
            # for command output. Only the exact observed sink is exercised.
            try:
                control = c.get(base, params={observed_parameter: "easm-rce-negative-control"})
                control_hit = _detect(control.text)
            except Exception:
                control_hit = None
            for cmd in (proof_cmd, win_cmd):
                if not is_safe_proof_command(cmd):
                    continue
                result["attempts"] += 1
                try:
                    response = c.get(base, params={observed_parameter: cmd})
                    hit = _detect(response.text)
                    if hit and not control_hit:
                        result.update({
                            "confirmed": True,
                            "vector": f"observed-cmd-param:{observed_parameter}",
                            "command": hit[0],
                            "evidence": hit[1][:300],
                            "negative_control_passed": True,
                        })
                        return result
                except Exception:
                    pass
    except Exception as exc:
        result["note"] = f"erro de conexão: {type(exc).__name__}"
        return result

    result["note"] = ("Nenhum comando foi comprovado em %d tentativas no sink observado; "
                      "resultado inconclusivo, não refutado." % result["attempts"])
    result["inconclusive"] = True
    return result
