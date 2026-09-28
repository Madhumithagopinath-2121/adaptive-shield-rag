"""API endpoints and routing package."""

from app.api.documents import router as documents_router
from app.api.knowledge import router as knowledge_router
from app.api.rag import router as rag_router
from app.api.security import router as security_router
from app.api.simulation import router as simulation_router

__all__ = [
    "documents_router",
    "knowledge_router",
    "rag_router",
    "security_router",
    "simulation_router",
]
