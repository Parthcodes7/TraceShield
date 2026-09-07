"""
TraceShield — FastAPI Backend
SIH26106 | AI-Powered Email Threat Detection, GeoLocation & Forensic Intelligence Platform

Endpoints:
  GET  /              — Service info
  GET  /health        — System health + capability flags
  POST /analyze       — Auto-detect: .eml file or JSON {raw_email}
  POST /analyze/file  — Multipart .eml upload
  POST /analyze/text  — JSON {raw_email}
  POST /analyze/batch — Batch: ZIP or multiple files
  GET  /history       — List past analysis records (SQLite, last 100)
  GET  /history/{id}  — Retrieve a specific record by email_id
  POST /report        — Generate PDF from EmailAnalysisRecord or RawEmailInput
  POST /report/file   — One-click: .eml → PDF
"""

import io
import os
import json
import time
import uuid
import hashlib
import asyncio
import zipfile
import logging
import logging.config
import aiosqlite

from datetime import datetime, timezone
from typing import List, Optional, Union

from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Response, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel, Field

# Internal forensic intelligence modules
from modules.header_forensics import analyze_headers
from modules.content_analysis import analyze_content, PYZBAR_AVAILABLE, is_classifier_available
from modules.geolocation import geolocate_ip, CITY_DB_PATH, ASN_DB_PATH
from modules.fusion_scoring import compute_risk_score, run_fusion
from modules.report_generator import generate_report_pdf
from modules.adversarial_test import generate_adversarial_sample, run_self_test

# ---------------------------------------------------------------------------
# Logging Configuration — Structured logging for all modules
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger("traceshield.main")

# ---------------------------------------------------------------------------
# SQLite History — Feature F1
# ---------------------------------------------------------------------------

DB_PATH = os.path.join(os.path.dirname(__file__), "data", "history.db")

# Maximum allowable email upload size — prevents DoS via large file bombs
MAX_EMAIL_SIZE_BYTES = 10 * 1024 * 1024  # 10 MB


_db_initialized = False

async def ensure_db():
    global _db_initialized
    if not _db_initialized:
        await init_db()
        _db_initialized = True


async def init_db():
    """Create the history table if it does not exist."""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("""
            CREATE TABLE IF NOT EXISTS analysis_history (
                email_id    TEXT PRIMARY KEY,
                analyzed_at TEXT NOT NULL,
                risk_tier   TEXT,
                risk_score  INTEGER,
                origin_ip   TEXT,
                record_json TEXT NOT NULL
            )
        """)
        await db.commit()


async def save_to_history(record: "EmailAnalysisRecord"):
    """Persist an EmailAnalysisRecord to SQLite."""
    try:
        await ensure_db()
        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute(
                """
                INSERT OR REPLACE INTO analysis_history
                    (email_id, analyzed_at, risk_tier, risk_score, origin_ip, record_json)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    record.email_id,
                    record.analyzed_at.isoformat(),
                    record.scoring.risk_tier if record.scoring else None,
                    record.scoring.final_risk_score if record.scoring else None,
                    record.geolocation.origin_ip if record.geolocation else None,
                    record.model_dump_json(),
                ),
            )
            await db.commit()
    except Exception as e:
        logger.warning("Failed to save analysis to history: %s", e)


# ---------------------------------------------------------------------------
# FastAPI App
# ---------------------------------------------------------------------------

app = FastAPI(
    title="TraceShield API",
    description="AI-Powered Email Threat Detection, GeoLocation & Forensic Intelligence Platform (SIH26106)",
    version="2.0.0",
)

# Enable CORS for React Frontend (Vite) and Chrome Extension
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
async def startup_event():
    """Initialise the SQLite history database on server start."""
    await init_db()
    logger.info("TraceShield started. History database initialised at %s", DB_PATH)


# ---------------------------------------------------------------------------
# Shared Data Contract — Pydantic Models
# ---------------------------------------------------------------------------

class RelayHop(BaseModel):
    hop: int
    from_host: str
    by_host: str
    timestamp: str


class AttachmentHash(BaseModel):
    filename: str
    sha256: str
    size_bytes: int
    is_dangerous: bool


class HeaderForensics(BaseModel):
    spf_result: str = Field(..., description="pass | fail | softfail | none | error")
    dmarc_result: str = Field(..., description="pass | fail | none | error")
    dkim_result: str = Field(..., description="pass | fail | none | error")
    relay_chain: List[RelayHop] = []
    origin_ip: Optional[str] = None
    reply_to_mismatch: bool = False
    display_name_spoof: bool = False
    suspicious_attachments: List[str] = []
    attachment_hashes: List[AttachmentHash] = []   # Feature F5
    anomaly_flags: List[str] = []
    # Feature F2 — Email metadata surfaced in PDF report
    from_header: Optional[str] = None
    to_header: Optional[str] = None
    subject_header: Optional[str] = None
    date_header: Optional[str] = None
    return_path: Optional[str] = None
    message_id: Optional[str] = None
    is_extension_scrape: bool = False


class HomoglyphDomain(BaseModel):
    visible_domain: str
    decoded_ascii: str
    suspicious: bool


class QRCode(BaseModel):
    decoded_url: str
    lookalike_check: bool
    reputation_flag: bool


class ContentAnalysis(BaseModel):
    urgency_score: float = Field(0.0, ge=0.0, le=1.0)
    impersonation_score: float = Field(0.0, ge=0.0, le=1.0)
    display_name_mismatch: bool = False
    lookalike_domains_found: List[str] = []
    homoglyph_domains_found: List[HomoglyphDomain] = []
    qr_codes_found: List[QRCode] = []
    url_shorteners_found: List[str] = []
    credential_harvesting_detected: bool = False


class Geolocation(BaseModel):
    origin_ip: str
    origin_country: str
    origin_city: str = "Unknown"
    origin_isp: str
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    is_known_vpn_or_hosting: bool = False


class Scoring(BaseModel):
    final_risk_score: int = Field(0, ge=0, le=100)
    risk_tier: str = Field(..., description="Low | Medium | High")
    confidence_level: str = Field(..., description="High Confidence | Moderate Confidence")
    confidence_reason: str
    llm_summary: str
    score_breakdown: Optional[dict] = None
    triggered_reasons: List[str] = []
    verified_authentications: List[str] = []
    recommendations: List[str] = []


class AdversarialTest(BaseModel):
    tested: bool = False
    generated_sample_caught: bool = False
    notes: str = ""


class EmailAnalysisRecord(BaseModel):
    email_id: str
    raw_email_hash: str
    analyzed_at: datetime
    analysis_duration_ms: Optional[int] = None   # Feature F3
    header_forensics: Optional[HeaderForensics] = None
    content_analysis: Optional[ContentAnalysis] = None
    geolocation: Optional[Geolocation] = None
    scoring: Optional[Scoring] = None
    adversarial_test: Optional[AdversarialTest] = None


class RawEmailInput(BaseModel):
    raw_email: str = Field(..., description="Full raw RFC 2822 email content or MIME text")


class AdversarialRunRequest(BaseModel):
    strategy: str = Field("business_routine", description="business_routine | it_compliance | quishing_statement")
    custom_email: Optional[str] = Field(None, description="Optional raw email string to test directly")
    custom_prompt: Optional[str] = Field(None, description="Optional custom prompt for LLM generation")


# ---------------------------------------------------------------------------
# Core Pipeline Orchestrator — runs in threadpool (not async) to avoid blocking
# ---------------------------------------------------------------------------

def analyze_raw_email(raw_bytes: bytes) -> EmailAnalysisRecord:
    """
    Executes the complete TraceShield forensic pipeline synchronously.
    Called via run_in_threadpool() from async endpoint handlers.

      1. SHA-256 hash for chain of custody.
      2. Module 1: DKIM, SPF/DMARC (envelope domain), relay chain, origin IP,
                   metadata extraction, attachment hashes.
      3. Module 2: NLP urgency/impersonation, homoglyphs, QR decoding, lookalikes.
      4. Module 3: Offline MaxMind GeoLite2 geolocation & datacenter attribution.
      5. Module 4: Multi-dimensional fusion scoring & calibrated confidence.
    """
    t_start = time.perf_counter()

    raw_hash = hashlib.sha256(raw_bytes).hexdigest()
    email_id = str(uuid.uuid4())

    # Module 1: Header Forensics
    hf_dict = analyze_headers(raw_bytes)

    # Module 2: Content Analysis
    ca_dict = analyze_content(
        raw_bytes,
        display_name_mismatch=hf_dict.get("display_name_spoof", False),
    )

    # Module 3: Geolocation of Origin IP extracted by Module 1
    origin_ip = hf_dict.get("origin_ip") or ""
    geo_dict = geolocate_ip(origin_ip)

    # Module 4: Fusion Scoring & Calibration
    scoring_dict = run_fusion(hf_dict, ca_dict, geo_dict)

    # Strict conformance to Pydantic shared data contract
    hf_data = {k: v for k, v in hf_dict.items() if k in HeaderForensics.model_fields}
    ca_data = {k: v for k, v in ca_dict.items() if k in ContentAnalysis.model_fields}
    geo_data = {k: v for k, v in geo_dict.items() if k in Geolocation.model_fields}
    scoring_data = {k: v for k, v in scoring_dict.items() if k in Scoring.model_fields}

    duration_ms = int((time.perf_counter() - t_start) * 1000)

    return EmailAnalysisRecord(
        email_id=email_id,
        raw_email_hash=raw_hash,
        analyzed_at=datetime.now(timezone.utc),
        analysis_duration_ms=duration_ms,
        header_forensics=HeaderForensics(**hf_data),
        content_analysis=ContentAnalysis(**ca_data),
        geolocation=Geolocation(**geo_data),
        scoring=Scoring(**scoring_data),
        adversarial_test=AdversarialTest(tested=False, generated_sample_caught=False, notes=""),
    )


# ---------------------------------------------------------------------------
# HTTP Endpoints
# ---------------------------------------------------------------------------

@app.get("/")
def read_root():
    return {
        "status": "online",
        "service": "TraceShield AI Threat Detection & Forensic Intelligence Platform",
        "specification": "SIH26106",
        "version": "2.0.0",
        "endpoints": {
            "health": "GET /health",
            "analyze_auto": "POST /analyze",
            "analyze_file": "POST /analyze/file",
            "analyze_text": "POST /analyze/text",
            "analyze_batch": "POST /analyze/batch",
            "history_list": "GET /history",
            "history_detail": "GET /history/{email_id}",
            "generate_report": "POST /report",
            "generate_report_file": "POST /report/file",
        },
    }


@app.get("/health")
def health_check():
    """Health check with capability flag reporting (Feature F8)."""
    city_db = os.path.exists(CITY_DB_PATH)
    asn_db = os.path.exists(ASN_DB_PATH)
    classifier_ready = is_classifier_available()
    return {
        "status": "healthy",
        "version": "2.0.0",
        "databases": {
            "GeoLite2-City.mmdb": "loaded" if city_db else "missing",
            "GeoLite2-ASN.mmdb": "loaded" if asn_db else "missing",
        },
        "modules": {
            "module_1_header_forensics": "ready",
            "module_2_content_analysis": "ready",
            "module_3_geolocation": "ready",
            "module_4_fusion_scoring": "ready",
            "module_5_report_generator": "ready",
        },
        # Capability flags — operators can see exactly what is enabled
        "capabilities": {
            "qr_decoding": "enabled" if PYZBAR_AVAILABLE else "disabled — run: brew install zbar",
            "nlp_classification": (
                "enabled (DistilBERT zero-shot)" if classifier_ready
                else "fallback heuristics only — transformers/torch not loaded"
            ),
            "geolocation": "enabled" if city_db and asn_db else "degraded — .mmdb files missing",
            "history_persistence": "enabled (SQLite)",
        },
    }


@app.post("/analyze", response_model=EmailAnalysisRecord)
async def analyze_email_auto(
    request: Request,
    file: Optional[UploadFile] = File(None),
):
    """
    Flexible analyze endpoint:
      - Multipart .eml file → analyze file
      - JSON {raw_email: ...} → analyze text
      - text/plain body → analyze raw text
    Uses run_in_threadpool() so the synchronous pipeline never blocks the event loop.
    """
    raw_bytes = None

    if file:
        raw_bytes = await file.read()
    else:
        content_type = request.headers.get("content-type", "")
        if "application/json" in content_type:
            body = await request.json()
            raw_text = body.get("raw_email") or body.get("email_text") or body.get("body", "")
            if raw_text:
                raw_bytes = raw_text.encode("utf-8", errors="replace")
        elif "text/plain" in content_type:
            raw_bytes = await request.body()

    if not raw_bytes:
        raise HTTPException(
            status_code=400,
            detail="No email content provided. Upload a .eml file or send JSON {raw_email}.",
        )

    if len(raw_bytes) > MAX_EMAIL_SIZE_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"Email payload too large ({len(raw_bytes):,} bytes). Maximum allowed size is 10 MB.",
        )

    try:
        record = await run_in_threadpool(analyze_raw_email, raw_bytes)
        await save_to_history(record)
        return record
    except Exception as e:
        logger.exception("Forensic analysis failed")
        raise HTTPException(status_code=500, detail=f"Forensic analysis failed: {e}")


@app.post("/analyze/file", response_model=EmailAnalysisRecord)
async def analyze_email_file(file: UploadFile = File(...)):
    """Accepts raw .eml file upload and runs the full analysis pipeline."""
    try:
        raw_bytes = await file.read()
        if not raw_bytes:
            raise HTTPException(status_code=400, detail="Uploaded file is empty.")
        if len(raw_bytes) > MAX_EMAIL_SIZE_BYTES:
            raise HTTPException(
                status_code=413,
                detail=f"File too large ({len(raw_bytes):,} bytes). Maximum allowed size is 10 MB.",
            )
        record = await run_in_threadpool(analyze_raw_email, raw_bytes)
        await save_to_history(record)
        return record
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("File analysis failed")
        raise HTTPException(status_code=500, detail=f"File analysis failed: {e}")


@app.post("/analyze/text", response_model=EmailAnalysisRecord)
async def analyze_email_text(input_data: RawEmailInput):
    """Accepts raw email string via JSON and runs the full analysis pipeline."""
    try:
        raw_bytes = input_data.raw_email.encode("utf-8", errors="replace")
        record = await run_in_threadpool(analyze_raw_email, raw_bytes)
        await save_to_history(record)
        return record
    except Exception as e:
        logger.exception("Text analysis failed")
        raise HTTPException(status_code=500, detail=f"Text analysis failed: {e}")


@app.post("/analyze/batch", response_model=List[EmailAnalysisRecord])
async def analyze_email_batch(
    files: List[UploadFile] = File(None),
    zip_file: Optional[UploadFile] = File(None),
):
    """
    Feature F6: Batch Analysis Endpoint.
    Accepts either:
      - Multiple .eml files via multipart form (files=[...])
      - A single ZIP archive containing .eml files (zip_file=...)
    Returns a list of EmailAnalysisRecord objects (one per email).
    Essential for SOC analysts triaging large volumes of suspected emails.
    """
    email_payloads: List[bytes] = []

    # Unpack ZIP if provided
    if zip_file:
        try:
            zip_bytes = await zip_file.read()
            with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
                for name in zf.namelist():
                    if name.lower().endswith(".eml"):
                        email_payloads.append(zf.read(name))
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Could not read ZIP archive: {e}")

    # Add individual uploaded files
    if files:
        for f in files:
            data = await f.read()
            if data:
                email_payloads.append(data)

    if not email_payloads:
        raise HTTPException(
            status_code=400,
            detail="No .eml files provided. Send 'files' (multiple .eml) or 'zip_file' (.zip).",
        )

    if len(email_payloads) > 50:
        raise HTTPException(
            status_code=400,
            detail="Batch limit is 50 emails per request.",
        )

    results = []
    for raw_bytes in email_payloads:
        try:
            record = await run_in_threadpool(analyze_raw_email, raw_bytes)
            await save_to_history(record)
            results.append(record)
        except Exception as e:
            logger.warning("Batch: skipped one email due to error: %s", e)
            # Continue processing remaining emails rather than aborting the batch

    return results


# ---------------------------------------------------------------------------
# History Endpoints — Feature F1
# ---------------------------------------------------------------------------

@app.get("/history")
async def list_history(limit: int = 100):
    """
    Feature F1: Returns the last N analysis records from the SQLite database.
    Shows email_id, analyzed_at, risk_tier, risk_score, origin_ip for quick triage.
    """
    try:
        await ensure_db()
        async with aiosqlite.connect(DB_PATH) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(
                """
                SELECT email_id, analyzed_at, risk_tier, risk_score, origin_ip
                FROM analysis_history
                ORDER BY analyzed_at DESC
                LIMIT ?
                """,
                (min(limit, 500),),
            )
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]
    except Exception as e:
        logger.exception("Failed to retrieve history")
        raise HTTPException(status_code=500, detail=f"History retrieval failed: {e}")


@app.get("/history/{email_id}", response_model=EmailAnalysisRecord)
async def get_history_record(email_id: str):
    """Feature F1: Retrieves a full EmailAnalysisRecord by its email_id."""
    try:
        await ensure_db()
        async with aiosqlite.connect(DB_PATH) as db:
            cursor = await db.execute(
                "SELECT record_json FROM analysis_history WHERE email_id = ?",
                (email_id,),
            )
            row = await cursor.fetchone()
            if row is None:
                raise HTTPException(status_code=404, detail=f"No record found for email_id: {email_id}")
            return EmailAnalysisRecord.model_validate_json(row[0])
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Failed to retrieve history record")
        raise HTTPException(status_code=500, detail=f"History retrieval failed: {e}")


# ---------------------------------------------------------------------------
# PDF Report Endpoints
# ---------------------------------------------------------------------------

@app.post("/report")
async def generate_report_endpoint(record_or_email: Union[EmailAnalysisRecord, RawEmailInput]):
    """
    Generates a structured forensic PDF report.
    Accepts an existing EmailAnalysisRecord JSON or a RawEmailInput.
    Returns downloadable PDF stream.
    """
    try:
        if isinstance(record_or_email, RawEmailInput):
            raw_bytes = record_or_email.raw_email.encode("utf-8", errors="replace")
            record = await run_in_threadpool(analyze_raw_email, raw_bytes)
            await save_to_history(record)
        else:
            record = record_or_email

        pdf_bytes = await run_in_threadpool(generate_report_pdf, record)
        filename = f"TraceShield_Report_{record.email_id[:8]}.pdf"

        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )
    except Exception as e:
        logger.exception("PDF generation failed")
        raise HTTPException(status_code=500, detail=f"PDF generation failed: {e}")


@app.post("/report/file")
async def generate_report_from_file(file: UploadFile = File(...)):
    """
    One-click forensic report: accepts raw .eml file, runs full pipeline,
    returns compiled forensic PDF directly.
    """
    try:
        raw_bytes = await file.read()
        if not raw_bytes:
            raise HTTPException(status_code=400, detail="Uploaded file is empty.")
        record = await run_in_threadpool(analyze_raw_email, raw_bytes)
        await save_to_history(record)
        pdf_bytes = await run_in_threadpool(generate_report_pdf, record)
        filename = f"TraceShield_Report_{record.email_id[:8]}.pdf"

        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Report generation from file failed")
        raise HTTPException(status_code=500, detail=f"Report generation from file failed: {e}")


# ---------------------------------------------------------------------------
# Module 7: Adversarial Self-Red-Teaming Endpoint
# ---------------------------------------------------------------------------

@app.post("/adversarial/run")
async def run_adversarial_test_endpoint(req: AdversarialRunRequest = AdversarialRunRequest()):
    """
    Module 7: Adversarial Self-Red-Teaming Endpoint.
    Generates an AI-crafted phishing email designed to evade detection filters,
    or tests custom adversarial input against the complete TraceShield pipeline.
    Returns the full EmailAnalysisRecord with adversarial notes and verdict.
    """
    try:
        if req.custom_email:
            sample_email = req.custom_email
        else:
            sample_email = await run_in_threadpool(
                generate_adversarial_sample,
                strategy=req.strategy,
                custom_prompt=req.custom_prompt,
            )

        test_result = await run_in_threadpool(
            run_self_test,
            sample_email=sample_email,
            pipeline_func=analyze_raw_email,
            strategy_name=req.strategy,
        )

        record = test_result["record"]
        await save_to_history(record)

        return {
            "tested": test_result["tested"],
            "strategy": test_result["strategy"],
            "generated_sample_caught": test_result["generated_sample_caught"],
            "final_risk_score": test_result["final_risk_score"],
            "risk_tier": test_result["risk_tier"],
            "confidence_level": test_result["confidence_level"],
            "detected_layers": test_result["detected_layers"],
            "notes": test_result["notes"],
            "record": record,
        }
    except Exception as e:
        logger.exception("Adversarial self-test failed")
        raise HTTPException(status_code=500, detail=f"Adversarial self-test failed: {e}")
