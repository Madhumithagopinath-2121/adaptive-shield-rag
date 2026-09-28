"""Tests for backend foundation endpoints."""

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_health_endpoint():
    """Verify GET /health returns expected status and service name."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["service"] == "AdaptiveShield RAG"


def test_root_endpoint():
    """Verify GET / returns API identification and prototype status."""
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["service"] == "AdaptiveShield RAG"
    assert data["status"] == "prototype_foundation"
    assert "version" in data
