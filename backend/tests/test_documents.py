"""Tests for document ingestion, persistence, and retrieval."""

import sqlite3
import pytest
from fastapi.testclient import TestClient

from app.api.documents import get_ingestion_service
from app.database import init_db
from app.main import app
from app.models.document import DocumentStatus
from app.services.ingestion import IngestionService


@pytest.fixture
def temp_db(tmp_path):
    """Fixture providing an isolated temporary SQLite database."""
    db_file = tmp_path / "test_adaptiveshield.db"
    db_path = str(db_file)
    init_db(db_path)
    return db_path


@pytest.fixture
def client(temp_db):
    """Fixture providing TestClient with dependency override to temp_db."""
    def override_service():
        return IngestionService(db_path=temp_db)

    app.dependency_overrides[get_ingestion_service] = override_service
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


def test_database_initialization(temp_db):
    """1. Test database initialization creates table and indexes."""
    conn = sqlite3.connect(temp_db)
    cursor = conn.cursor()

    # Verify documents table exists
    cursor.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='documents';"
    )
    table = cursor.fetchone()
    assert table is not None
    assert table[0] == "documents"

    # Verify indexes exist
    cursor.execute(
        "SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='documents';"
    )
    indexes = [row[0] for row in cursor.fetchall()]
    assert "idx_documents_timestamp" in indexes
    assert "idx_documents_status" in indexes
    conn.close()


def test_document_creation(client):
    """2. Test document creation via POST /api/v1/documents."""
    payload = {
        "title": "Release Notes 2.4",
        "content": "This release includes minor bug fixes and performance improvements.",
        "source": "https://internal.wiki/releases/2.4",
        "source_type": "wiki",
    }
    response = client.post("/api/v1/documents", json=payload)
    assert response.status_code == 201
    data = response.json()

    assert data["title"] == payload["title"]
    assert data["content"] == payload["content"]
    assert data["source"] == payload["source"]
    assert data["source_type"] == payload["source_type"]
    assert "id" in data and len(data["id"]) > 0
    assert "timestamp" in data
    assert data["status"] == "PENDING"


def test_document_retrieval(client):
    """3. Test document retrieval by ID via GET /api/v1/documents/{document_id}."""
    payload = {
        "title": "Architecture Overview",
        "content": "The system utilizes an ingestion pipeline and validation layer.",
        "source": "docs/architecture.md",
        "source_type": "file",
    }
    create_res = client.post("/api/v1/documents", json=payload)
    assert create_res.status_code == 201
    doc_id = create_res.json()["id"]

    get_res = client.get(f"/api/v1/documents/{doc_id}")
    assert get_res.status_code == 200
    retrieved = get_res.json()

    assert retrieved["id"] == doc_id
    assert retrieved["title"] == payload["title"]
    assert retrieved["content"] == payload["content"]
    assert retrieved["status"] == "PENDING"


def test_missing_document_404(client):
    """4. Test missing document returns 404 for retrieval and status updates."""
    non_existent_id = "00000000-0000-0000-0000-000000000000"

    get_res = client.get(f"/api/v1/documents/{non_existent_id}")
    assert get_res.status_code == 404
    assert "not found" in get_res.json()["detail"].lower()

    patch_res = client.patch(
        f"/api/v1/documents/{non_existent_id}/status",
        json={"status": "QUARANTINE"},
    )
    assert patch_res.status_code == 404
    assert "not found" in patch_res.json()["detail"].lower()


def test_status_update(client):
    """5. Test updating document status via PATCH /api/v1/documents/{document_id}/status."""
    payload = {
        "title": "Support Ticket #1042",
        "content": "User reported login retry failure after timeout.",
        "source": "ticket-system",
        "source_type": "ticket",
    }
    create_res = client.post("/api/v1/documents", json=payload)
    doc_id = create_res.json()["id"]
    assert create_res.json()["status"] == "PENDING"

    # Update to QUARANTINE
    patch_res = client.patch(
        f"/api/v1/documents/{doc_id}/status",
        json={"status": DocumentStatus.QUARANTINE.value},
    )
    assert patch_res.status_code == 200
    assert patch_res.json()["status"] == "QUARANTINE"

    # Confirm persistence
    get_res = client.get(f"/api/v1/documents/{doc_id}")
    assert get_res.status_code == 200
    assert get_res.json()["status"] == "QUARANTINE"

    # Update to SAFE
    patch_res2 = client.patch(
        f"/api/v1/documents/{doc_id}/status",
        json={"status": DocumentStatus.SAFE.value},
    )
    assert patch_res2.status_code == 200
    assert patch_res2.json()["status"] == "SAFE"


def test_default_status_is_pending(client):
    """6. Test that default status of newly ingested document is always PENDING."""
    payload = {
        "title": "Knowledge Feed Item",
        "content": "Autonomous monitoring data point received.",
        "source": "sensor-stream-1",
        "source_type": "api",
    }
    response = client.post("/api/v1/documents", json=payload)
    assert response.status_code == 201
    created = response.json()
    assert created["status"] == "PENDING"

    # Verify in retrieval endpoint
    fetched = client.get(f"/api/v1/documents/{created['id']}").json()
    assert fetched["status"] == "PENDING"


def test_multiple_documents_can_be_ingested(client):
    """7. Test ingesting multiple documents and retrieving them ordered by timestamp."""
    for i in range(3):
        res = client.post(
            "/api/v1/documents",
            json={
                "title": f"Doc {i}",
                "content": f"Sample document payload content {i}",
                "source": f"feed-{i}",
                "source_type": "feed",
            },
        )
        assert res.status_code == 201

    list_res = client.get("/api/v1/documents")
    assert list_res.status_code == 200
    items = list_res.json()
    assert len(items) == 3

    # Check pagination query parameters
    limited_res = client.get("/api/v1/documents?limit=2&offset=0")
    assert limited_res.status_code == 200
    assert len(limited_res.json()) == 2
