"""Phase 2 Verification Test: FastAPI Backend & Security Middleware."""
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_health_endpoint():
    """Verify the /api/health endpoint returns 200 and expected schema."""
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "WinSecAudit" in data["service"]
    assert data["version"] == "1.0.0"
    assert "timestamp" in data
