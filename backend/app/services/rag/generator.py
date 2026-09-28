"""LLM response generator with graceful fallback when unconfigured."""

import logging
from typing import List, Optional

import httpx

from app.config import settings
from app.models.rag import RetrievalResultItem
from app.services.rag.context_builder import ContextBuilder

logger = logging.getLogger(__name__)


class RAGGenerator:
    """Generates answers based on trusted context or returns graceful fallback."""

    def __init__(
        self,
        context_builder: Optional[ContextBuilder] = None,
        provider: Optional[str] = None,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        base_url: Optional[str] = None,
    ):
        self.context_builder = context_builder or ContextBuilder()
        self.provider = provider if provider is not None else settings.llm_provider
        self.api_key = api_key if api_key is not None else settings.llm_api_key
        self.model = model or settings.llm_model
        self.base_url = base_url or settings.llm_base_url or "https://api.openai.com/v1"

    def is_configured(self) -> bool:
        """Check if an active LLM provider and API key are configured."""
        if not self.api_key or not self.api_key.strip():
            return False
        if not self.provider or self.provider.strip().lower() in ("", "none", "disabled"):
            return False
        return True

    def generate(
        self,
        query: str,
        retrieval_items: List[RetrievalResultItem],
        context: Optional[str] = None,
    ) -> str:
        """Generate answer using LLM when available or return graceful fallback."""
        if context is None:
            context = self.context_builder.build_context(retrieval_items)

        # 1. Fallback when LLM is not configured
        if not self.is_configured():
            return self._build_unconfigured_fallback(query, retrieval_items)

        # 2. Invoke configured LLM
        try:
            return self._call_llm(query, context)
        except Exception as exc:
            logger.warning("LLM generation call failed: %s. Using graceful fallback.", exc)
            fallback_msg = (
                f"LLM generation encountered an error ({type(exc).__name__}). "
                f"Here are the trusted retrieved sources:\n\n"
            )
            return fallback_msg + self._format_source_summary(retrieval_items)

    def _build_unconfigured_fallback(
        self, query: str, items: List[RetrievalResultItem]
    ) -> str:
        """Build clear, structured fallback when no LLM is configured."""
        if not items:
            return (
                "LLM is not configured, and no trusted documents were found relevant to your query."
            )

        header = "LLM is not configured. Here are the trusted retrieved sources:\n\n"
        return header + self._format_source_summary(items)

    def _format_source_summary(self, items: List[RetrievalResultItem]) -> str:
        """Summarize retrieved items cleanly for fallback display."""
        if not items:
            return "No trusted sources available."

        parts = []
        for idx, item in enumerate(items, start=1):
            parts.append(
                f"[{idx}] {item.title} (Source: {item.source})\n"
                f"{item.content.strip()}"
            )
        return "\n\n".join(parts)

    def _call_llm(self, query: str, context: str) -> str:
        """Execute chat completion call to OpenAI-compatible endpoint."""
        endpoint = f"{self.base_url.rstrip('/')}/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": self.context_builder.build_system_prompt()},
                {"role": "user", "content": self.context_builder.build_user_prompt(query, context)},
            ],
            "temperature": 0.0,
        }

        with httpx.Client(timeout=30.0) as client:
            resp = client.post(endpoint, json=payload, headers=headers)
            resp.raise_for_status()
            data = resp.json()
            return data["choices"][0]["message"]["content"].strip()
