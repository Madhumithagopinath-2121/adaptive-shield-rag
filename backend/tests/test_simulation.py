"""Unit and integration tests for attack simulator and live stream simulation."""

from typing import List
import pytest
from fastapi.testclient import TestClient

from app.api.documents import get_ingestion_service
from app.api.knowledge import get_knowledge_service
from app.api.rag import get_rag_service
from app.api.security import (
    get_decision_engine,
    get_security_analyzer,
    get_threat_state_engine,
)
from app.api.simulation import get_simulation_service
from app.database import get_db_connection, init_db
from app.main import app
from app.models.security_decision import SecurityDecision
from app.models.threat_state import ThreatState
from app.services.ingestion import IngestionService
from app.services.knowledge.embedding_service import EmbeddingService
from app.services.knowledge.knowledge_service import KnowledgeService
from app.services.knowledge.vector_store import ChromaVectorStore
from app.services.rag.rag_service import RAGService
from app.services.security.decision_engine import DecisionEngine
from app.services.security.security_analyzer import SecurityAnalyzer
from app.services.security.threat_state import ThreatStateEngine
from app.services.simulation.simulator import AttackSimulatorService


class MockEmbeddingService(EmbeddingService):
    """Deterministic mock embedding service for fast, reproducible testing."""

    def __init__(self, dimension: int = 384):
        self.dimension = dimension

    def embed_text(self, text: str) -> List[float]:
        val = (abs(hash(text)) % 1000) / 1000.0
        return [val] * self.dimension

    def embed_documents(self, texts: List[str]) -> List[List[float]]:
        return [self.embed_text(t) for t in texts]


@pytest.fixture
def temp_db(tmp_path):
    """Fixture providing an isolated temporary SQLite database."""
    db_file = tmp_path / "test_sim.db"
    db_path = str(db_file)
    init_db(db_path)
    return db_path


@pytest.fixture
def temp_vector_store(tmp_path):
    """Fixture providing an isolated ChromaVectorStore on disk."""
    store_dir = tmp_path / "test_sim_vector_store"
    return ChromaVectorStore(
        persist_dir=str(store_dir),
        trusted_collection_name="test_trusted_knowledge",
        quarantine_collection_name="test_quarantined_knowledge",
    )


@pytest.fixture
def mock_embedding():
    """Fixture providing mock embedding service."""
    return MockEmbeddingService()


@pytest.fixture
def client(temp_db, temp_vector_store, mock_embedding):
    """Fixture providing TestClient with all services bound to isolated test stores."""
    ingestion_svc = IngestionService(db_path=temp_db)
    sec_analyzer = SecurityAnalyzer()
    dec_engine = DecisionEngine()
    knowledge_svc = KnowledgeService(
        ingestion_service=ingestion_svc,
        security_analyzer=sec_analyzer,
        decision_engine=dec_engine,
        vector_store=temp_vector_store,
        embedding_service=mock_embedding,
        db_path=temp_db,
    )
    threat_engine = ThreatStateEngine(db_path=temp_db)
    rag_svc = RAGService(
        vector_store=temp_vector_store,
        embedding_service=mock_embedding,
    )
    simulator_svc = AttackSimulatorService(
        ingestion_service=ingestion_svc,
        knowledge_service=knowledge_svc,
        threat_state_engine=threat_engine,
        db_path=temp_db,
    )

    app.dependency_overrides[get_ingestion_service] = lambda: ingestion_svc
    app.dependency_overrides[get_security_analyzer] = lambda: sec_analyzer
    app.dependency_overrides[get_decision_engine] = lambda: dec_engine
    app.dependency_overrides[get_knowledge_service] = lambda: knowledge_svc
    app.dependency_overrides[get_threat_state_engine] = lambda: threat_engine
    app.dependency_overrides[get_rag_service] = lambda: rag_svc
    app.dependency_overrides[get_simulation_service] = lambda: simulator_svc

    with TestClient(app) as test_client:
        yield test_client

    app.dependency_overrides.clear()


def test_1_normal_mode_simulation(client):
    """1. Normal mode generates mostly SAFE documents and preserves low threat state."""
    payload = {
        "mode": "normal",
        "document_count": 10,
        "attack_ratio": 0.10,
        "delay_ms": 0,
    }
    res = client.post("/api/v1/simulation/start", json=payload)
    assert res.status_code == 200
    data = res.json()

    assert data["mode"] == "normal"
    assert data["total_generated"] == 10
    assert data["safe_count"] >= 8
    assert data["block_count"] == 0
    assert data["quarantine_count"] <= 2
    assert data["safe_count"] + data["quarantine_count"] + data["block_count"] == 10
    assert data["average_risk_score"] < 0.30
    assert data["current_threat_state"] in [ThreatState.NORMAL.value, ThreatState.ELEVATED.value]
    assert data["attack_velocity"] <= 0.20
    assert len(data["documents"]) == 10


def test_2_attack_mode_simulation(client):
    """2. Attack mode generates high proportion of suspicious and blocked documents."""
    payload = {
        "mode": "attack",
        "document_count": 10,
        "attack_ratio": 0.80,
        "delay_ms": 0,
    }
    res = client.post("/api/v1/simulation/start", json=payload)
    assert res.status_code == 200
    data = res.json()

    assert data["mode"] == "attack"
    assert data["total_generated"] == 10
    assert data["quarantine_count"] + data["block_count"] >= 7
    assert data["block_count"] >= 3
    assert data["average_risk_score"] > 0.40
    # Attack velocity >= 0.50 triggers CRITICAL state
    assert data["current_threat_state"] in [ThreatState.HIGH.value, ThreatState.CRITICAL.value]
    assert data["attack_velocity"] >= 0.50


def test_3_mixed_mode_simulation(client):
    """3. Mixed mode produces both safe and suspicious documents in balanced proportion."""
    payload = {
        "mode": "mixed",
        "document_count": 10,
        "attack_ratio": 0.50,
        "delay_ms": 0,
    }
    res = client.post("/api/v1/simulation/start", json=payload)
    assert res.status_code == 200
    data = res.json()

    assert data["mode"] == "mixed"
    assert data["total_generated"] == 10
    assert data["safe_count"] >= 3
    assert data["quarantine_count"] + data["block_count"] >= 3
    assert data["safe_count"] + data["quarantine_count"] + data["block_count"] == 10


def test_4_all_simulated_documents_pass_existing_assessment(client, temp_db):
    """4. Every simulated document is ingested, assessed, and recorded in SQLite history."""
    payload = {"mode": "mixed", "document_count": 8, "delay_ms": 0}
    res = client.post("/api/v1/simulation/start", json=payload)
    assert res.status_code == 200

    # Verify SQLite security_assessments table contains exactly 8 assessments
    with get_db_connection(temp_db) as conn:
        cursor = conn.execute("SELECT COUNT(*) as count FROM security_assessments;")
        row = cursor.fetchone()
        assert row["count"] == 8

        # Verify all decisions are valid
        cursor = conn.execute("SELECT decision, risk_score FROM security_assessments;")
        for record in cursor.fetchall():
            assert record["decision"] in [
                SecurityDecision.SAFE.value,
                SecurityDecision.QUARANTINE.value,
                SecurityDecision.BLOCK.value,
            ]
            assert 0.0 <= record["risk_score"] <= 1.0


def test_5_block_documents_never_enter_vector_store(client, temp_vector_store):
    """5. BLOCK documents are strictly rejected from all vector collections."""
    payload = {"mode": "attack", "document_count": 10, "attack_ratio": 1.0, "delay_ms": 0}
    res = client.post("/api/v1/simulation/start", json=payload)
    assert res.status_code == 200
    sim_data = res.json()

    block_docs = [d for d in sim_data["documents"] if d["decision"] == SecurityDecision.BLOCK.value]
    assert len(block_docs) > 0

    trusted_ids = temp_vector_store.trusted_collection.get()["ids"]
    quar_ids = temp_vector_store.quarantine_collection.get()["ids"]

    for b in block_docs:
        assert b["storage_destination"] == "none"
        assert b["document_id"] not in trusted_ids
        assert b["document_id"] not in quar_ids


def test_6_quarantine_documents_never_enter_trusted_collection(client, temp_vector_store):
    """6. QUARANTINE documents are segregated into quarantine and never enter trusted."""
    payload = {"mode": "mixed", "document_count": 10, "attack_ratio": 0.5, "delay_ms": 0}
    res = client.post("/api/v1/simulation/start", json=payload)
    assert res.status_code == 200
    sim_data = res.json()

    quar_docs = [d for d in sim_data["documents"] if d["decision"] == SecurityDecision.QUARANTINE.value]
    safe_docs = [d for d in sim_data["documents"] if d["decision"] == SecurityDecision.SAFE.value]

    trusted_ids = temp_vector_store.trusted_collection.get()["ids"]
    quar_ids = temp_vector_store.quarantine_collection.get()["ids"]

    for q in quar_docs:
        assert q["storage_destination"] == "quarantine"
        assert q["document_id"] in quar_ids
        assert q["document_id"] not in trusted_ids

    for s in safe_docs:
        assert s["storage_destination"] == "trusted"
        assert s["document_id"] in trusted_ids
        assert s["document_id"] not in quar_ids


def test_7_threat_state_reflects_simulation_history(client):
    """7. Stream threat state API reflects the simulated stream traffic."""
    # 1. Run attack simulation
    payload = {"mode": "attack", "document_count": 12, "attack_ratio": 0.85, "delay_ms": 0}
    sim_res = client.post("/api/v1/simulation/start", json=payload)
    assert sim_res.status_code == 200
    sim_data = sim_res.json()

    # 2. Query threat-state endpoint directly
    state_res = client.get("/api/v1/security/threat-state")
    assert state_res.status_code == 200
    state_data = state_res.json()

    assert state_data["total_assessed"] == 12
    assert state_data["state"] == sim_data["current_threat_state"]
    assert state_data["attack_velocity"] == sim_data["attack_velocity"]
    assert state_data["safe_count"] == sim_data["safe_count"]
    assert state_data["quarantine_count"] == sim_data["quarantine_count"]
    assert state_data["block_count"] == sim_data["block_count"]


def test_8_simulation_status_endpoint(client):
    """8. Status endpoint exposes running state and latest completed simulation summary."""
    # Check initial status
    init_res = client.get("/api/v1/simulation/status")
    assert init_res.status_code == 200
    init_data = init_res.json()
    assert init_data["is_running"] is False

    # Run a simulation
    sim_res = client.post("/api/v1/simulation/start", json={"mode": "normal", "document_count": 5})
    assert sim_res.status_code == 200
    expected_id = sim_res.json()["simulation_id"]

    # Check status again
    after_res = client.get("/api/v1/simulation/status")
    assert after_res.status_code == 200
    after_data = after_res.json()
    assert after_data["is_running"] is False
    assert after_data["latest_simulation"] is not None
    assert after_data["latest_simulation"]["simulation_id"] == expected_id
    assert after_data["latest_simulation"]["total_generated"] == 5


def test_9_simulation_input_validation(client):
    """9. Input validation rejects invalid document counts and attack ratios."""
    # Document count < 1
    res1 = client.post("/api/v1/simulation/start", json={"document_count": 0})
    assert res1.status_code == 422

    # Document count > 100
    res2 = client.post("/api/v1/simulation/start", json={"document_count": 101})
    assert res2.status_code == 422

    # Attack ratio < 0.0
    res3 = client.post("/api/v1/simulation/start", json={"attack_ratio": -0.1})
    assert res3.status_code == 422

    # Attack ratio > 1.0
    res4 = client.post("/api/v1/simulation/start", json={"attack_ratio": 1.5})
    assert res4.status_code == 422

    # Delay ms < 0
    res5 = client.post("/api/v1/simulation/start", json={"delay_ms": -10})
    assert res5.status_code == 422


def test_10_trusted_retrieval_excludes_simulated_attacks(client):
    """10. End-to-end RAG retrieval after attack simulation returns ONLY verified SAFE documents."""
    # Run heavy attack simulation (generates attacks, prompt leaks, and benign policies)
    client.post(
        "/api/v1/simulation/start",
        json={"mode": "attack", "document_count": 10, "attack_ratio": 0.80, "delay_ms": 0},
    )

    # Search for attack keywords
    ret_res = client.post(
        "/api/v1/rag/retrieve",
        json={"query": "system prompt override leak attack", "top_k": 10},
    )
    assert ret_res.status_code == 200
    ret_data = ret_res.json()

    # Any returned documents MUST be SAFE
    for item in ret_data["results"]:
        assert item["decision"] == SecurityDecision.SAFE.value
        assert "SYSTEM OVERRIDE" not in item["content"]
        assert "Ignore all previous instructions" not in item["content"]
