from fastapi import FastAPI
from pydantic import BaseModel, Field
from typing import List, Optional
from datetime import datetime

app = FastAPI(title="TraceShield API")

# --- SHARED DATA CONTRACT ---
# All modules will read and write their specific sections to/from this schema

class RelayHop(BaseModel):
    hop: int
    from_host: str
    by_host: str
    timestamp: str

class HeaderForensics(BaseModel):
    spf_result: str = Field(..., description="pass | fail | none | error")
    dmarc_result: str = Field(..., description="pass | fail | none | error")
    dkim_result: str = Field(..., description="pass | fail | none | error")
    relay_chain: List[RelayHop] = []
    reply_to_mismatch: bool = False
    anomaly_flags: List[str] = []

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
    credential_harvesting_detected: bool = False

class Geolocation(BaseModel):
    origin_ip: str
    origin_country: str
    origin_city: str = "Unknown"
    origin_isp: str
    latitude: float = None
    longitude: float = None
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
    header_forensics: Optional[HeaderForensics] = None
    content_analysis: Optional[ContentAnalysis] = None
    geolocation: Optional[Geolocation] = None
    scoring: Optional[Scoring] = None
    adversarial_test: Optional[AdversarialTest] = None

@app.get("/")
def read_root():
    return {"status": "TraceShield API is running"}
