"""Local embedding service using Sentence Transformers.

Generates dense vector representations for documents using the configured
local embedding model without relying on external third-party APIs.
"""

from typing import List, Optional

from app.config import settings


class EmbeddingService:
    """Service for computing dense text embeddings locally."""

    def __init__(self, model_name: Optional[str] = None):
        self.model_name = model_name or settings.embedding_model_name
        self._model = None

    @property
    def model(self):
        """Lazy load the SentenceTransformer model on first invocation."""
        if self._model is None:
            from sentence_transformers import SentenceTransformer

            self._model = SentenceTransformer(self.model_name)
        return self._model

    def embed_text(self, text: str) -> List[float]:
        """Compute embedding vector for a single text string."""
        if not text or not text.strip():
            # Return zero vector fallback if empty or whitespace
            return [0.0] * 384
        embedding = self.model.encode(text, convert_to_numpy=True)
        return embedding.tolist()

    def embed_documents(self, texts: List[str]) -> List[List[float]]:
        """Compute embedding vectors for a batch of documents."""
        if not texts:
            return []
        embeddings = self.model.encode(texts, convert_to_numpy=True)
        return embeddings.tolist()
