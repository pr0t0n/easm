import json

import httpx

from app.core.config import settings


def _call_ollama(model: str, prompt: str) -> str:
    try:
        with httpx.Client(timeout=20.0) as client:
            resp = client.post(
                f"{settings.ollama_base_url}/api/generate",
                json={
                    "model": model,
                    "prompt": prompt,
                    "stream": False,
                },
            )
        if resp.status_code != 200:
            return ""
        payload = resp.json()
        return (payload.get("response") or "").strip()
    except Exception:
        return ""


def generate_portuguese_recommendations(finding: dict, known_patterns: list[str] | None = None) -> dict:
    title = str(finding.get("title", "Achado de seguranca"))
    severity = str(finding.get("severity", "medium"))
    details = finding.get("details") if isinstance(finding.get("details"), dict) else finding
    known_list = known_patterns or []

    base_prompt = (
        "Voce e um analista senior de ciberseguranca. "
        "Responda SOMENTE em portugues do Brasil e em JSON valido. "
        "Objetivo: recomendar mitigacoes praticas para vulnerabilidades encontradas no EASM. "
        "Formato JSON obrigatorio: "
        '{"resumo":"...","impacto":"...","mitigacoes":["..."],"prioridade":"baixa|media|alta|critica","validacoes":["..."]}. '
        "Contexto do achado: "
        f"titulo={title}; severidade={severity}; detalhes={json.dumps(details, ensure_ascii=True)}. "
        f"Padroes conhecidos no banco para autoaprendizado: {json.dumps(known_list[:25], ensure_ascii=True)}."
    )

    qwen_text = _call_ollama(settings.ollama_qwen_model, base_prompt)
    cloudcode_text = _call_ollama(settings.ollama_cloudcode_model, base_prompt)

    if not qwen_text:
        qwen_text = json.dumps(
            {
                "resumo": f"Risco identificado: {title}",
                "impacto": "Possivel exposicao de superficie externa e aumento do risco operacional.",
                "mitigacoes": [
                    "Aplicar correcao de configuracao ou patch no servico afetado.",
                    "Restringir exposicao externa via firewall/WAF e segmentacao.",
                    "Monitorar eventos correlatos no SIEM com alerta priorizado.",
                ],
                "prioridade": "media",
                "validacoes": [
                    "Executar reteste apos mitigacao.",
                    "Confirmar ausencia de regressao em scan subsequente.",
                ],
            },
            ensure_ascii=True,
        )

    if not cloudcode_text:
        cloudcode_text = qwen_text

    return {
        "qwen_recomendacao_pt": qwen_text,
        "cloudcode_recomendacao_pt": cloudcode_text,
    }
