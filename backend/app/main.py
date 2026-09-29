"""AdaptiveShield RAG - Backend Entrypoint."""

from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.documents import router as documents_router
from app.api.knowledge import router as knowledge_router
from app.api.rag import router as rag_router
from app.api.security import router as security_router
from app.api.simulation import router as simulation_router
from app.config import settings
from app.database import init_db


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan context: initialize database schema on startup."""
    init_db()
    yield


app = FastAPI(
    title=settings.app_name,
    description="Adaptive security layer foundation for continuously updating RAG knowledge streams (Initial Prototype).",
    version="0.1.0",
    lifespan=lifespan,
)

# Allow CORS requests from frontend development server
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount API routers
app.include_router(documents_router, prefix="/api/v1")
app.include_router(security_router, prefix="/api/v1")
app.include_router(knowledge_router, prefix="/api/v1")
app.include_router(rag_router, prefix="/api/v1")
app.include_router(simulation_router, prefix="/api/v1")


@app.get("/", tags=["General"])
def read_root():
    """Root endpoint identifying the API and current prototype status."""
    return {
        "service": settings.app_name,
        "version": "0.1.0",
        "status": "prototype_foundation",
        "description": "Backend foundation initialized with document ingestion, security analysis, and gated knowledge storage.",
    }


@app.get("/health", tags=["Health"])
def health_check():
    """Health check endpoint to verify backend service availability."""
    return {
        "status": "ok",
        "service": settings.app_name,
    }
