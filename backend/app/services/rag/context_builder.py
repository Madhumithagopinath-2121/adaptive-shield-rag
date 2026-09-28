"""Context and prompt builder for RAG query pipeline."""

from typing import List
from app.models.rag import RetrievalResultItem


class ContextBuilder:
    """Formats retrieved trusted documents into structured context for generation."""

    def build_context(self, items: List[RetrievalResultItem]) -> str:
        """Format a list of retrieved trusted items into readable context."""
        if not items:
            return ""

        chunks = []
        for idx, item in enumerate(items, start=1):
            chunk = (
                f"[Document {idx}]\n"
                f"Title: {item.title}\n"
                f"Source: {item.source} ({item.source_type})\n"
                f"Content: {item.content.strip()}"
            )
            chunks.append(chunk)

        return "\n\n".join(chunks)

    def build_system_prompt(self) -> str:
        """System instructions for the LLM."""
        return (
            "You are a helpful and security-conscious assistant. "
            "Answer the user's question using ONLY the provided trusted context. "
            "If the provided context does not contain enough information to answer the question, "
            "clearly state that the trusted knowledge base does not contain the answer. "
            "Do not hallucinate or use external unverified information."
        )

    def build_user_prompt(self, query: str, context: str) -> str:
        """User prompt combining question and context."""
        if not context.strip():
            return f"Question: {query}\n\nNo trusted reference context is available."

        return (
            f"Context from trusted knowledge base:\n"
            f"{context}\n\n"
            f"Question: {query}\n\n"
            f"Answer:"
        )
