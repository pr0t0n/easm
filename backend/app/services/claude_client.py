"""Claude API client — tarefas auxiliares com suporte a prompt caching.

O supervisor principal (decide_next_technique) continua em Ollama/qwen.
Este cliente é para uso pontual: geração de relatórios de qualidade, análises
de achados, síntese de evidências — tarefas que se beneficiam de raciocínio
mais profundo mas não estão no caminho crítico do scan.

Prompt caching:
  Contextos grandes e estáveis (ex: corpo de um relatório parcial, catálogo de
  10k learnings HackerOne) são marcados com cache_control="ephemeral" na
  primeira posição do array de conteúdo. O cache tem TTL de 5 minutos na API
  da Anthropic, reduzindo ~90% do custo em tokens de entrada para chamadas
  repetidas dentro desse janela.

Uso:
    client = ClaudeClient()
    if client.available:
        result = client.complete(system="...", user="...", cache_system=True)
"""
from __future__ import annotations

import logging
from typing import Any

from app.core.config import settings

logger = logging.getLogger(__name__)


class ClaudeClient:
    """Wrapper mínimo sobre o SDK Anthropic com suporte a prompt caching."""

    def __init__(self) -> None:
        self._client = None
        self._available: bool | None = None

    @property
    def available(self) -> bool:
        if self._available is None:
            self._available = bool(str(settings.anthropic_api_key or "").strip())
            if not self._available:
                logger.debug("ClaudeClient: ANTHROPIC_API_KEY não definida — claude_client desabilitado")
        return self._available

    def _get_client(self):
        if self._client is not None:
            return self._client
        if not self.available:
            return None
        try:
            import anthropic
            self._client = anthropic.Anthropic(api_key=settings.anthropic_api_key)
            return self._client
        except Exception as exc:
            logger.error("ClaudeClient: falha ao criar cliente Anthropic: %s", exc)
            self._available = False
            return None

    def complete(
        self,
        *,
        system: str,
        user: str,
        model: str | None = None,
        max_tokens: int = 2048,
        cache_system: bool = False,
        temperature: float = 0.1,
    ) -> str | None:
        """Chama Claude e retorna o texto da resposta.

        Args:
            system: Prompt de sistema (pode ser grande e estável).
            user: Prompt do usuário (específico por chamada).
            model: Modelo Claude. Padrão = settings.anthropic_model.
            max_tokens: Limite de tokens de saída.
            cache_system: Se True, marca o system prompt para prompt caching.
                         Use quando o mesmo system prompt será reutilizado em
                         múltiplas chamadas dentro de 5 minutos.
            temperature: Temperatura (0.1 para saídas determinísticas).
        """
        client = self._get_client()
        if client is None:
            return None

        use_model = model or settings.anthropic_model
        try:
            if cache_system:
                # Prompt caching: marca o system prompt como candidato a cache.
                # Reduz ~90% do custo em input tokens para chamadas repetidas
                # dentro do TTL de 5 minutos.
                system_content: Any = [
                    {
                        "type": "text",
                        "text": system,
                        "cache_control": {"type": "ephemeral"},
                    }
                ]
            else:
                system_content = system

            response = client.messages.create(
                model=use_model,
                max_tokens=max_tokens,
                temperature=temperature,
                system=system_content,
                messages=[{"role": "user", "content": user}],
                betas=["prompt-caching-2024-07-31"] if cache_system else [],
            )
            return str(response.content[0].text or "").strip()
        except Exception as exc:
            logger.error("ClaudeClient.complete failed (model=%s): %s", use_model, exc)
            return None

    def complete_with_context(
        self,
        *,
        system: str,
        stable_context: str,
        user: str,
        model: str | None = None,
        max_tokens: int = 2048,
    ) -> str | None:
        """Chamada com contexto estável cacheável separado do prompt do usuário.

        Útil quando há um bloco grande de contexto reutilizável (ex: catálogo de
        learnings, relatório parcial) que precede o prompt específico da chamada.

        Args:
            stable_context: Texto grande e estável — vai para cache.
            user: Pergunta ou instrução específica desta chamada — não vai para cache.
        """
        client = self._get_client()
        if client is None:
            return None

        use_model = model or settings.anthropic_model
        try:
            response = client.messages.create(
                model=use_model,
                max_tokens=max_tokens,
                system=system,
                messages=[
                    {
                        "role": "user",
                        "content": [
                            {
                                "type": "text",
                                "text": stable_context,
                                "cache_control": {"type": "ephemeral"},
                            },
                            {
                                "type": "text",
                                "text": user,
                            },
                        ],
                    }
                ],
                betas=["prompt-caching-2024-07-31"],
            )
            return str(response.content[0].text or "").strip()
        except Exception as exc:
            logger.error("ClaudeClient.complete_with_context failed: %s", exc)
            return None


# Singleton — criado lazy (sem falha se SDK não instalado ou key ausente)
claude_client = ClaudeClient()
