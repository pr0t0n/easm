"""Recusa explícita do GUARDRAIL — a plataforma PODE atacar, mas RECUSA classes
destrutivas e registra o porquê. Segurança como feature auditável.

Mapeia categorias de ataque proibidas (DoS, extração de dados, defacement/escrita
destrutiva) e produz um registro de RECUSA por capacidade — em vez de executar.
Ver [[feedback_destructive_db]] / guardrail_policy.

No contexto JuiceShop, isto explica POR QUE estes desafios NÃO são resolvidos
pela plataforma (e não por incapacidade): seria violar o guardrail.
"""

from __future__ import annotations

# capacidade tecnicamente possível -> motivo da recusa (categoria proibida)
REFUSED_CAPABILITIES = [
    {"capability": "sqli_data_extraction", "category": "EXTRAÇÃO DE DADOS",
     "reason": "Dumpar linhas (emails/senhas/PII) via UNION/blind é extração de dados — proibido. "
               "Mapear esquema é permitido; extrair conteúdo não.",
     "blocks_examples": ["User Credentials", "NoSQL Exfiltration", "Email Leak", "GDPR Data Theft"]},
    {"capability": "denial_of_service", "category": "DoS/DDoS",
     "reason": "Sleep/loop/expansão para travar o servidor é DoS — proibido em qualquer hipótese.",
     "blocks_examples": ["NoSQL DoS", "XXE DoS", "Blocked RCE DoS", "Successful RCE DoS", "Memory Bomb"]},
    {"capability": "destructive_write", "category": "DEFACEMENT/ESCRITA DESTRUTIVA",
     "reason": "Sobrescrever/apagar conteúdo do alvo é defacement/destruição — proibido.",
     "blocks_examples": ["Arbitrary File Write"]},
]

# desafios JuiceShop bloqueados POR DESIGN (guardrail), não por incapacidade
GUARDRAIL_BLOCKED_CHALLENGES = {
    "User Credentials": "EXTRAÇÃO DE DADOS",
    "NoSQL Exfiltration": "EXTRAÇÃO DE DADOS",
    "Email Leak": "EXTRAÇÃO DE DADOS",
    "GDPR Data Theft": "EXTRAÇÃO DE DADOS",
    "NoSQL DoS": "DoS",
    "XXE DoS": "DoS",
    "Blocked RCE DoS": "DoS",
    "Successful RCE DoS": "DoS",
    "Memory Bomb": "DoS",
    "Arbitrary File Write": "DEFACEMENT/ESCRITA DESTRUTIVA",
}


def guardrail_refusals() -> dict:
    """Registro de recusas — para o relatório e a página de guardrail."""
    return {
        "refused_capabilities": REFUSED_CAPABILITIES,
        "blocked_challenges": GUARDRAIL_BLOCKED_CHALLENGES,
        "summary": (f"{len(GUARDRAIL_BLOCKED_CHALLENGES)} desafios NÃO são resolvidos por DECISÃO "
                    f"de guardrail (DoS/extração/destruição), não por incapacidade técnica."),
    }
