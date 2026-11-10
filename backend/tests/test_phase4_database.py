"""Phase 4 Verification Tests: SQLite database models, persistence, and REST API endpoints."""
from fastapi.testclient import TestClient
from sqlalchemy import inspect

from app.database import engine, init_db
from app.main import app


def test_sqlite_tables_created():
    """Verify SQLite creates audit_sessions, audit_findings, category_scores, and report_metadata."""
    init_db()
    inspector = inspect(engine)
    tables = set(inspector.get_table_names())
    print(f"\n[SQLite] Created Tables: {sorted(tables)}")
    assert "audit_sessions" in tables
    assert "audit_findings" in tables
    assert "category_scores" in tables
    assert "report_metadata" in tables


def test_audit_lifecycle_and_database_persistence():
    """Test running an audit via API, storing in SQLite, and querying status, results, modules, and history."""
    with TestClient(app) as client:
        # 1. System info endpoint
        sys_res = client.get("/api/system/info")
        assert sys_res.status_code == 200
        sys_data = sys_res.json()
        assert sys_data["hostname"] != ""

        # 2. Start a full audit and persist in SQLite
        start_res = client.post("/api/audit/start")
        assert start_res.status_code == 200
        audit_data = start_res.json()
        audit_id = audit_data["audit_id"]
        print(f"\n[API /audit/start] Persisted Audit ID: {audit_id} | Score: {audit_data['score']['overall_score']}/100")

        # 3. Check audit status endpoint
        status_res = client.get(f"/api/audit/status/{audit_id}")
        assert status_res.status_code == 200
        assert status_res.json()["status"] == "COMPLETED"

        # 4. Retrieve audit results by ID and latest
        by_id_res = client.get(f"/api/audit/results/{audit_id}")
        assert by_id_res.status_code == 200
        assert by_id_res.json()["audit_id"] == audit_id

        latest_res = client.get("/api/audit/results/latest")
        assert latest_res.status_code == 200
        assert latest_res.json()["audit_id"] == audit_id

        # 5. Verify all 5 individual module endpoints read from the stored session
        for endpoint in (
            "/api/audit/users",
            "/api/audit/updates",
            "/api/audit/permissions",
            "/api/audit/services",
            "/api/audit/security",
        ):
            mod_res = client.get(endpoint)
            assert mod_res.status_code == 200
            assert "checks" in mod_res.json()

        # 6. Verify audit history endpoint
        hist_res = client.get("/api/history")
        assert hist_res.status_code == 200
        items = hist_res.json()["items"]
        assert len(items) >= 1
        assert items[0]["audit_id"] == audit_id
        assert len(items[0]["categories"]) == 5
        print(f"[API /history] Stored sessions count: {len(items)}")
