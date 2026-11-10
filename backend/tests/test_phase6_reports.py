"""Phase 6 Verification Tests: PDF Report Generation (ReportLab) and JSON Export."""
from fastapi.testclient import TestClient

from app.main import app


def test_generate_and_download_pdf_and_json_reports():
    """Verify PDF and JSON report generation, SQLite metadata tracking, and file download."""
    with TestClient(app) as client:
        # 1. Get latest audit session (or run one if DB is empty)
        latest_res = client.get("/api/audit/results/latest")
        if latest_res.status_code == 404:
            latest_res = client.post("/api/audit/start")
        assert latest_res.status_code == 200
        audit_id = latest_res.json()["audit_id"]

        # 2. Generate PDF Report
        pdf_gen = client.post(f"/api/reports/{audit_id}/generate?format=pdf")
        assert pdf_gen.status_code == 200
        pdf_meta = pdf_gen.json()
        print(f"\n[PDF Report] Generated: {pdf_meta['file_name']} ({pdf_meta['file_size_bytes']} bytes)")
        assert pdf_meta["report_type"] == "PDF"
        assert pdf_meta["file_size_bytes"] > 2000

        # Download PDF and check %PDF header
        pdf_dl = client.get(f"/api/reports/{pdf_meta['report_id']}/download")
        assert pdf_dl.status_code == 200
        assert pdf_dl.headers["content-type"] == "application/pdf"
        assert pdf_dl.content.startswith(b"%PDF-")

        # 3. Generate JSON Report
        json_gen = client.post(f"/api/reports/{audit_id}/generate?format=json")
        assert json_gen.status_code == 200
        json_meta = json_gen.json()
        print(f"[JSON Report] Generated: {json_meta['file_name']} ({json_meta['file_size_bytes']} bytes)")
        assert json_meta["report_type"] == "JSON"
        assert json_meta["file_size_bytes"] > 1000

        # Download JSON and verify keys
        json_dl = client.get(f"/api/reports/{json_meta['report_id']}/download")
        assert json_dl.status_code == 200
        exported_data = json_dl.json()
        assert "report_metadata" in exported_data
        assert "executive_assessment" in exported_data
        assert "identified_vulnerabilities_and_weaknesses" in exported_data
        assert "full_audit_data" in exported_data

        # 4. List reports endpoint
        list_res = client.get("/api/reports")
        assert list_res.status_code == 200
        items = list_res.json()["items"]
        assert len(items) >= 2
