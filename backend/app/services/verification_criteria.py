"""Critério de VERIFICAÇÃO por família (inspirado na seção 'Verification' dos
skills de pentest). Pentest PROVA, não só detecta.

Para cada classe de vulnerabilidade define: qual SINAL confirma a vuln, qual
ferramenta/abordagem confirma, e o método de prova SEGURO (sem ação destrutiva
— respeita o guardrail). Usado para: (a) anotar cada finding com seu padrão de
prova, (b) deixar explícito por que um achado é 'candidate' vs 'confirmed'.
"""

from __future__ import annotations

VERIFICATION: dict[str, dict] = {
    "xss": {
        "signal": "Execução de script refletido/armazenado no contexto do navegador (callback/alert canário).",
        "confirming_tools": ["dalfox", "nuclei-xss"],
        "method": "Injetar payload inócuo (canário) e confirmar reflexão executável — sem roubo de sessão real.",
    },
    "sqli": {
        "signal": "Resposta condicional booleana/baseada em tempo, ou erro SQL reproduzível.",
        "confirming_tools": ["sqlmap", "nuclei-sqli"],
        "method": "Confirmar injeção e MAPEAR estrutura (dbs/tabelas/colunas) — NUNCA extrair conteúdo.",
    },
    "rce": {
        "signal": "Callback out-of-band (interactsh) a partir do alvo, comprovando execução.",
        "confirming_tools": ["nuclei-rce", "interactsh-client"],
        "method": "Prova via OOB (DNS/HTTP) — sem abrir shell nem executar comando arbitrário.",
    },
    "ssrf": {
        "signal": "Interação out-of-band do servidor com host controlado / acesso a metadados internos.",
        "confirming_tools": ["nuclei-ssrf", "interactsh-client"],
        "method": "Confirmar fetch interno via OOB — sem exfiltrar dados internos.",
    },
    "idor": {
        "signal": "Acesso a objeto de outro usuário (id incrementado) retorna 200 com dado de terceiro.",
        "confirming_tools": ["nuclei-idor", "curl"],
        "method": "Comparar resposta autenticada vs objeto alheio — sem alterar o dado.",
    },
    "broken_access_control": {
        "signal": "Endpoint privilegiado acessível sem autorização adequada (200 onde deveria 401/403).",
        "confirming_tools": ["nuclei-idor", "ffuf", "curl"],
        "method": "Acessar recurso restrito sem credencial válida — leitura apenas.",
    },
    "auth_bypass": {
        "signal": "Acesso a área protegida sem credencial válida ou com credencial padrão.",
        "confirming_tools": ["nuclei-auth", "hydra"],
        "method": "Confirmar bypass/credencial fraca — sem persistir acesso nem brute massivo.",
    },
    "jwt_oauth": {
        "signal": "Token forjado aceito (alg:none, key confusion, segredo fraco).",
        "confirming_tools": ["jwt_tool"],
        "method": "Forjar token de teste e confirmar aceitação — sem usar para ação real.",
    },
    "ssti": {
        "signal": "Avaliação de expressão do template (ex.: {{7*7}}=49) na resposta.",
        "confirming_tools": ["nuclei-ssti", "wapiti"],
        "method": "Payload aritmético inócuo — sem execução de código no servidor.",
    },
    "xxe": {
        "signal": "Resolução de entidade externa via callback OOB ou leitura de arquivo de teste.",
        "confirming_tools": ["nuclei-xxe", "interactsh-client"],
        "method": "Prova via OOB — sem ler arquivos sensíveis.",
    },
    "open_redirect": {
        "signal": "Redirecionamento 30x para domínio externo controlado.",
        "confirming_tools": ["nuclei-redirect"],
        "method": "Confirmar redirect para host externo arbitrário.",
    },
    "cors": {
        "signal": "ACAO refletindo Origin arbitrária com ACAC:true.",
        "confirming_tools": ["nuclei-cors", "curl"],
        "method": "Requisição cross-origin de teste confirma leitura de resposta autenticada.",
    },
    "subdomain_takeover": {
        "signal": "CNAME pendente apontando para serviço não reivindicado (fingerprint).",
        "confirming_tools": ["subjack", "nuclei-takeover"],
        "method": "Confirmar fingerprint de takeover — sem reivindicar o recurso.",
    },
    "secrets": {
        "signal": "Segredo de alta entropia / padrão conhecido (AKIA, AIza, JWT, private key) em resposta.",
        "confirming_tools": ["page_analyzer", "gitleaks", "nuclei-exposure"],
        "method": "Regex de segredo no corpo — sem usar a credencial.",
    },
    "file_upload": {
        "signal": "Upload de arquivo com extensão/tipo perigoso aceito e acessível.",
        "confirming_tools": ["nuclei-exposure"],
        "method": "Confirmar aceitação de upload inócuo — sem webshell.",
    },
    "vulnerable_dependency": {
        "signal": "Versão detectada casa com CVE conhecido (faixa afetada).",
        "confirming_tools": ["nuclei", "trivy", "wpscan"],
        "method": "Confirmar versão via banner/template do CVE específico.",
    },
    "tls_ssl": {
        "signal": "Handshake confirma protocolo/cipher fraco ou cert inválido.",
        "confirming_tools": ["testssl", "sslscan"],
        "method": "Handshake real confirma a fraqueza.",
    },
    "security_headers": {
        "signal": "Ausência de header de segurança na resposta HTTP.",
        "confirming_tools": ["nuclei-headers", "curl-headers"],
        "method": "Inspeção direta dos headers da resposta.",
    },
}

# Default para famílias sem critério específico.
_DEFAULT = {
    "signal": "Evidência reproduzível da condição (request/response, payload, saída de ferramenta).",
    "confirming_tools": ["nuclei", "curl"],
    "method": "Confirmar com prova reproduzível — sem ação destrutiva.",
}


def verification_for(family_id: str | None) -> dict:
    """Critério de verificação de uma família (sempre retorna algo)."""
    return VERIFICATION.get(str(family_id or ""), _DEFAULT)
