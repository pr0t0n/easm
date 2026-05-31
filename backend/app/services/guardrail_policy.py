"""Guardrail de segurança ofensiva — fonte única da verdade (SSOT).

A plataforma é um pentest AUTOMATIZADO. Por princípio, ataques que causariam
IMPACTO real no alvo são PERMANENTEMENTE DESATIVADOS: só informamos a
possibilidade de execução, nunca executamos o efeito destrutivo.

Política (resumo):
  - DoS / DDoS .................. nunca executado (sem flood/exaustão).
  - SQLi — extração de dados .... só MAPEAMOS estrutura (dbs/tabelas/colunas);
                                  nunca extraímos/dumpamos conteúdo.
  - Defacement / modificação .... nunca escrevemos/alteramos o alvo.
  - Exfiltração de dados ........ nunca lemos/baixamos arquivos ou segredos.
  - RCE / shell ................. confirmamos a POSSIBILIDADE (ex.: callback OOB);
                                  nunca abrimos shell nem rodamos comando no alvo.
  - Brute-force destrutivo ...... sem credential-stuffing em massa / lockout.

Este módulo define (a) o catálogo exibido na página de Guardrails e
(b) os padrões de flags proibidas usados para SANITIZAR os argumentos de
qualquer ferramenta antes de despachar. O MCP (gateway antes do kali) tem um
espelho desta deny-list — mantenha os dois em sincronia.
"""

from __future__ import annotations

import re

# ---------------------------------------------------------------------------
# Deny-list de flags por ferramenta. Cada padrão é um regex aplicado a CADA
# argumento. Se casar, o argumento é REMOVIDO (e o bloqueio é registrado).
# As flags de MAPEAMENTO (estrutura) ficam DE FORA — são permitidas.
# ---------------------------------------------------------------------------

# sqlmap: permitir enumeração de ESTRUTURA, bloquear extração de CONTEÚDO,
# escrita em arquivo, shell de SO/SQL e execução de comandos.
_SQLMAP_FORBIDDEN = [
    r"^--dump(?:-all)?$",        # dump de conteúdo de tabelas
    r"^--dump-all$",
    r"^-D?$",                    # nota: -D/-T/-C sozinhos são p/ escopo de dump
    r"^--passwords$",            # hashes de senha = dado sensível
    r"^--sql-query.*$",          # query arbitrária pode extrair dados
    r"^--sql-shell$",
    r"^--os-shell$",
    r"^--os-pwn$",
    r"^--os-cmd.*$",
    r"^--os-smbrelay$",
    r"^--file-read.*$",          # exfiltração de arquivos
    r"^--file-write.*$",         # escrita no alvo (defacement)
    r"^--file-dest.*$",
    r"^--reg-read$",
    r"^--reg-add$",
    r"^--reg-del$",
    r"^--eval.*$",
    r"^--priv-esc$",
]
# -D/-T/-C são usados tanto para mapear quanto para escopar dump; só são
# perigosos quando acompanham --dump (que já é bloqueado acima). Removo o
# padrão genérico de -D para não quebrar mapeamento legítimo.
_SQLMAP_FORBIDDEN = [p for p in _SQLMAP_FORBIDDEN if p != r"^-D?$"]

# ghauri (alternativa ao sqlmap): mesmos princípios.
_GHAURI_FORBIDDEN = [
    r"^--dump(?:-all)?$",
    r"^--os-shell$",
    r"^--sql-shell$",
    r"^--file-read.*$",
    r"^--file-write.*$",
]

# nuclei: bloquear templates/tags de DoS e fuzzing destrutivo.
_NUCLEI_FORBIDDEN = [
    r"(?i)^-?-?tags?$",          # tratado em par no sanitizador (ver _PAIRED)
]

# hydra / medusa: sem brute-force massivo (DoS de auth / account lockout).
# Threads altas são reduzidas no sanitizador (ver _THREAD_CAPS).

# Padrões GLOBAIS proibidos para QUALQUER ferramenta (defesa em profundidade):
_GLOBAL_FORBIDDEN = [
    r"(?i)^--dump(?:-all)?$",
    r"(?i)^--os-shell$",
    r"(?i)^--file-write.*$",
    r"(?i)^--exfil.*$",
]

FORBIDDEN_ARG_PATTERNS: dict[str, list[str]] = {
    "sqlmap": _SQLMAP_FORBIDDEN,
    "ghauri": _GHAURI_FORBIDDEN,
}

# Valores de tag de nuclei que jamais devem rodar (DoS / fuzz destrutivo).
_NUCLEI_FORBIDDEN_TAGS = {"dos", "fuzzing-dos", "intrusive"}

# Teto de threads por ferramenta de brute-force (evita DoS de auth/lockout).
_THREAD_CAPS = {"hydra": 8, "medusa": 8}

_compiled: dict[str, list[re.Pattern]] = {
    tool: [re.compile(p) for p in pats] for tool, pats in FORBIDDEN_ARG_PATTERNS.items()
}
_compiled_global = [re.compile(p) for p in _GLOBAL_FORBIDDEN]


def sanitize_tool_args(tool: str, args: list[str] | None) -> tuple[list[str], list[str]]:
    """Remove flags proibidas de ``args`` para ``tool``.

    Retorna ``(args_limpos, removidos)``. ``removidos`` lista cada token
    bloqueado (para auditoria/log). Nunca levanta exceção — falha fechando
    (remove em caso de dúvida).
    """
    if not args:
        return [], []
    tool_l = str(tool or "").strip().lower()
    pats = _compiled.get(tool_l, []) + _compiled_global
    clean: list[str] = []
    removed: list[str] = []

    skip_next = False
    for i, raw in enumerate(args):
        if skip_next:
            skip_next = False
            removed.append(str(raw))
            continue
        a = str(raw)

        # nuclei: bloquear tag de DoS (par "-tags dos" ou "-tags=dos").
        if tool_l == "nuclei" and re.match(r"(?i)^-?-?tags?(=.*)?$", a):
            val = ""
            if "=" in a:
                val = a.split("=", 1)[1]
            elif i + 1 < len(args):
                val = str(args[i + 1])
                # se o próximo token for o valor da tag e contiver DoS, pular ambos
                if any(t in val.lower() for t in _NUCLEI_FORBIDDEN_TAGS):
                    removed.append(a)
                    skip_next = True
                    continue
            if any(t in val.lower() for t in _NUCLEI_FORBIDDEN_TAGS):
                removed.append(a)
                continue

        if any(p.match(a) for p in pats):
            removed.append(a)
            continue
        clean.append(a)

    # Teto de threads para brute-force.
    cap = _THREAD_CAPS.get(tool_l)
    if cap:
        clean = _cap_threads(clean, cap, removed)

    return clean, removed


def _cap_threads(args: list[str], cap: int, removed: list[str]) -> list[str]:
    out: list[str] = []
    i = 0
    while i < len(args):
        a = args[i]
        m = re.match(r"^(-t|-T|--threads?)(=)?(\d+)?$", a)
        if m and m.group(3) and int(m.group(3)) > cap:
            # forma "-t=64"
            removed.append(a)
            out.append(f"{m.group(1)}{'=' if m.group(2) else ''}{cap}")
            i += 1
            continue
        if m and not m.group(3) and i + 1 < len(args) and str(args[i + 1]).isdigit():
            if int(args[i + 1]) > cap:
                removed.append(f"{a} {args[i+1]}")
                out.append(a)
                out.append(str(cap))
                i += 2
                continue
        out.append(a)
        i += 1
    return out


# ---------------------------------------------------------------------------
# Catálogo exibido na página de Guardrails. Cada item descreve um ataque de
# IMPACTO e seu estado (desativado / restrito), o que FAZEMOS e o que NUNCA
# fazemos, e como o bloqueio é tecnicamente aplicado.
# ---------------------------------------------------------------------------

DISABLED_ATTACKS: list[dict] = [
    {
        "id": "dos_ddos",
        "name": "Negação de Serviço (DoS / DDoS)",
        "category": "Disponibilidade",
        "status": "disabled",
        "impact_if_executed": "Indisponibilidade do serviço, prejuízo operacional.",
        "what_we_do": "Identificamos ausência de rate-limit, endpoints custosos e "
                      "superfície amplificável — apenas como observação.",
        "what_we_never_do": "Nunca geramos flood, exaustão de recursos ou tráfego "
                            "volumétrico contra o alvo.",
        "enforcement": "Sem ferramenta de flood habilitada; tags 'dos' do nuclei "
                       "bloqueadas; rate-limits das ferramentas fixados em valores "
                       "educados.",
        "tools": ["nuclei (tags dos bloqueadas)"],
    },
    {
        "id": "sqli_extraction",
        "name": "SQL Injection — Extração de Dados",
        "category": "Injeção",
        "status": "restricted",
        "impact_if_executed": "Vazamento de dados sensíveis (PII, credenciais).",
        "what_we_do": "Detectamos a injeção e MAPEAMOS a estrutura: bancos, "
                      "tabelas, colunas e schema.",
        "what_we_never_do": "Nunca extraímos/dumpamos o conteúdo das tabelas nem "
                            "hashes de senha.",
        "enforcement": "sqlmap roda com --answers=exploit=N; flags --dump, "
                       "--dump-all, --passwords, --sql-query/shell, --file-read "
                       "removidas antes da execução.",
        "tools": ["sqlmap", "ghauri"],
    },
    {
        "id": "data_exfiltration",
        "name": "Exfiltração / Extração de Dados",
        "category": "Confidencialidade",
        "status": "disabled",
        "impact_if_executed": "Cópia não autorizada de arquivos, segredos ou dados.",
        "what_we_do": "Apontamos onde dados sensíveis estão expostos e o caminho "
                      "que um atacante usaria.",
        "what_we_never_do": "Nunca lemos, baixamos ou copiamos arquivos/segredos "
                            "do alvo.",
        "enforcement": "Flags de leitura/escrita de arquivo (--file-read, "
                       "--file-write, --file-dest) removidas globalmente.",
        "tools": ["sqlmap", "ghauri"],
    },
    {
        "id": "defacement",
        "name": "Defacement / Modificação de Conteúdo",
        "category": "Integridade",
        "status": "disabled",
        "impact_if_executed": "Alteração visível do site, dano à reputação.",
        "what_we_do": "Identificamos uploads inseguros e endpoints graváveis "
                      "como vulnerabilidade.",
        "what_we_never_do": "Nunca escrevemos, alteramos ou apagamos conteúdo no "
                            "alvo.",
        "enforcement": "Escrita em arquivo e os-shell bloqueados; nenhum profile "
                       "executa PUT/upload de payload.",
        "tools": ["sqlmap", "ghauri"],
    },
    {
        "id": "rce_shell",
        "name": "Execução Remota de Código (Shell)",
        "category": "Execução",
        "status": "restricted",
        "impact_if_executed": "Controle total do servidor (comprometimento).",
        "what_we_do": "Confirmamos a POSSIBILIDADE de RCE de forma segura "
                      "(ex.: callback out-of-band via interactsh).",
        "what_we_never_do": "Nunca abrimos shell interativo nem executamos "
                            "comandos de SO no alvo.",
        "enforcement": "Flags --os-shell, --os-cmd, --os-pwn, --os-smbrelay "
                       "removidas; sem framework de C2/payload de shell.",
        "tools": ["sqlmap", "interactsh (somente prova)"],
    },
    {
        "id": "bruteforce_destructive",
        "name": "Brute-force Destrutivo / Account Lockout",
        "category": "Autenticação",
        "status": "restricted",
        "impact_if_executed": "Bloqueio de contas legítimas, DoS de autenticação.",
        "what_we_do": "Testamos credenciais fracas com baixa intensidade e "
                      "credenciais fornecidas pelo operador.",
        "what_we_never_do": "Nunca rodamos credential-stuffing em massa nem "
                            "ataques que causem lockout.",
        "enforcement": "Teto de threads (≤8) em hydra/medusa; sem dicionários "
                       "massivos automáticos.",
        "tools": ["hydra", "medusa"],
    },
]


def guardrail_policy_payload() -> dict:
    """Payload consumido pela página de Guardrails."""
    return {
        "principle": "A plataforma é um pentest automatizado. Ataques de impacto "
                     "real são permanentemente desativados: informamos a "
                     "possibilidade de execução, nunca o efeito destrutivo.",
        "attacks": DISABLED_ATTACKS,
        "summary": {
            "total": len(DISABLED_ATTACKS),
            "disabled": sum(1 for a in DISABLED_ATTACKS if a["status"] == "disabled"),
            "restricted": sum(1 for a in DISABLED_ATTACKS if a["status"] == "restricted"),
        },
    }
