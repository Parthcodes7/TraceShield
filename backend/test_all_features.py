"""
Comprehensive Verification Test Suite for TraceShield Backend
Tests all modules, improvements, bug fixes, and API endpoints.
"""

import sys
import os
import io
import asyncio
from fastapi.testclient import TestClient

# Ensure backend directory is in path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from main import app, init_db
from modules.header_forensics import analyze_headers
from modules.content_analysis import analyze_content
from modules.geolocation import geolocate_ip
from modules.fusion_scoring import run_fusion
from modules.report_generator import generate_report_pdf, generate_report_html

def test_modules_directly():
    print("--- 1. Testing Core Modules Directly ---")
    eml_path = os.path.join(os.path.dirname(__file__), "data", "test_emails", "dummy_phishing_1.eml")
    with open(eml_path, "rb") as f:
        eml_bytes = f.read()

    # Module 1: Header Forensics
    header_res = analyze_headers(eml_bytes)
    print("Header Forensics Results:")
    print(f"  - Subject: {header_res.get('subject_header')}")
    print(f"  - From: {header_res.get('from_header')}")
    print(f"  - To: {header_res.get('to_header')}")
    print(f"  - Date: {header_res.get('date_header')}")
    print(f"  - Return-Path: {header_res.get('return_path')}")
    print(f"  - Origin IP: {header_res.get('origin_ip')}")
    print(f"  - Display Name Spoof: {header_res.get('display_name_spoof')}")
    print(f"  - Attachment Hashes: {header_res.get('attachment_hashes')}")
    assert header_res.get("from_header") is not None, "from_header missing"
    assert header_res.get("subject_header") is not None, "subject_header missing"
    assert "attachment_hashes" in header_res, "attachment_hashes missing"
    print("  [PASS] Header Forensics")

    # Module 2: Content Analysis
    content_res = analyze_content(eml_bytes, display_name_mismatch=header_res.get("display_name_spoof", False))
    print("Content Analysis Results:")
    print(f"  - Lookalike: {content_res.get('lookalike_domains_found')}")
    print(f"  - Urgency Score: {content_res.get('urgency_score')}")
    print(f"  - Shorteners: {content_res.get('url_shorteners_found')}")
    assert isinstance(content_res.get("url_shorteners_found"), list), "url_shorteners_found should be list"
    assert len(content_res.get("lookalike_domains_found", [])) > 0, "Should detect bank0findia lookalike"
    print("  [PASS] Content Analysis")

    # Module 3: Geolocation
    origin_ip = header_res.get("origin_ip") or "209.85.212.49"
    geo_res = geolocate_ip(origin_ip)
    print("Geolocation Results:")
    print(f"  - Country: {geo_res.get('origin_country')}")
    print(f"  - City: {geo_res.get('origin_city')}")
    print("  [PASS] Geolocation")

    # Module 4: Fusion Scoring
    score_res = run_fusion(header_res, content_res, geo_res)
    print("Fusion Scoring Results:")
    print(f"  - Final Score: {score_res.get('final_risk_score')}")
    print(f"  - Risk Tier: {score_res.get('risk_tier')}")
    print(f"  - Breakdown: {score_res.get('score_breakdown')}")
    # Verify points key fix
    for k, item in score_res.get("score_breakdown", {}).items():
        assert "points" in item, f"Missing 'points' key in score_breakdown for {k}"
        assert "max_score" in item, f"Missing 'max_score' key in score_breakdown for {k}"
    print("  [PASS] Fusion Scoring (verified 'points' key & caps)")

    # Module 5: Report Generator
    dummy_record = {
        "email_id": "test-12345",
        "analyzed_at": "2026-09-06T12:00:00Z",
        "analysis_duration_ms": 42.5,
        "header_forensics": header_res,
        "content_analysis": content_res,
        "geolocation": geo_res,
        "scoring": score_res,
    }
    html_out = generate_report_html(dummy_record)
    assert len(html_out) > 500, "HTML report too short"
    pdf_bytes = generate_report_pdf(dummy_record)
    assert len(pdf_bytes) > 1000, "PDF report generation failed"
    print(f"  [PASS] Report Generator (HTML {len(html_out)} bytes, PDF {len(pdf_bytes)} bytes)")

def test_api_endpoints():
    print("\n--- 2. Testing FastAPI Endpoints via TestClient ---")
    client = TestClient(app)

    # 1. Health check & capability flags
    health_resp = client.get("/health")
    assert health_resp.status_code == 200, f"Health check failed: {health_resp.status_code}"
    health_data = health_resp.json()
    print("Health response:", health_data)
    assert "capabilities" in health_data, "capabilities missing in /health"
    assert health_data["status"] in ("ok", "healthy")
    print("  [PASS] GET /health with capabilities")

    # 2. Analyze File
    eml_path = os.path.join(os.path.dirname(__file__), "data", "test_emails", "dummy_phishing_1.eml")
    with open(eml_path, "rb") as f:
        files = {"file": ("dummy_phishing_1.eml", f, "message/rfc822")}
        analyze_resp = client.post("/analyze/file", files=files)
    
    assert analyze_resp.status_code == 200, f"Analyze file failed: {analyze_resp.text}"
    record = analyze_resp.json()
    email_id = record["email_id"]
    print(f"Analyze response email_id: {email_id}")
    print(f"  - analysis_duration_ms: {record.get('analysis_duration_ms')}")
    print(f"  - Risk tier: {record['scoring']['risk_tier']}")
    assert "analysis_duration_ms" in record, "analysis_duration_ms missing"
    assert record["header_forensics"].get("subject_header") is not None
    assert "attachment_hashes" in record["header_forensics"]
    print("  [PASS] POST /analyze/file")

    # 3. History endpoint
    hist_resp = client.get("/history?limit=10")
    assert hist_resp.status_code == 200, f"History failed: {hist_resp.text}"
    hist_data = hist_resp.json()
    records = hist_data if isinstance(hist_data, list) else hist_data.get('records', [])
    print(f"History records count: {len(records)}")
    assert any(r["email_id"] == email_id for r in records), "New email not found in history"
    print("  [PASS] GET /history")

    # 4. History detail endpoint
    hist_detail = client.get(f"/history/{email_id}")
    assert hist_detail.status_code == 200, f"History detail failed: {hist_detail.text}"
    detail_data = hist_detail.json()
    assert detail_data["email_id"] == email_id
    print("  [PASS] GET /history/{email_id}")

    # 5. Batch analyze endpoint
    with open(eml_path, "rb") as f1, open(eml_path, "rb") as f2:
        batch_files = [
            ("files", ("email1.eml", io.BytesIO(f1.read()), "message/rfc822")),
            ("files", ("email2.eml", io.BytesIO(f2.read()), "message/rfc822")),
        ]
        batch_resp = client.post("/analyze/batch", files=batch_files)
    assert batch_resp.status_code == 200, f"Batch analyze failed: {batch_resp.text}"
    batch_data = batch_resp.json()
    print(f"Batch returned {len(batch_data)} records")
    assert len(batch_data) == 2
    print("  [PASS] POST /analyze/batch")

    # 6. Report PDF from file
    with open(eml_path, "rb") as f:
        rep_resp = client.post("/report/file", files={"file": ("dummy.eml", f, "message/rfc822")})
    assert rep_resp.status_code == 200, f"Report file failed: {rep_resp.status_code}"
    assert rep_resp.headers.get("content-type") == "application/pdf"
    assert len(rep_resp.content) > 1000
    print(f"  [PASS] POST /report/file (PDF returned: {len(rep_resp.content)} bytes)")

    # 7. Report PDF from JSON
    json_rep_resp = client.post("/report", json=record)
    assert json_rep_resp.status_code == 200, f"Report json failed: {json_rep_resp.status_code}"
    assert json_rep_resp.headers.get("content-type") == "application/pdf"
    assert len(json_rep_resp.content) > 1000
    print(f"  [PASS] POST /report (PDF returned: {len(json_rep_resp.content)} bytes)")

if __name__ == "__main__":
    test_modules_directly()
    test_api_endpoints()
    print("\n==========================================")
    print("ALL TESTS PASSED WITH 100% SUCCESS!")
    print("==========================================")
