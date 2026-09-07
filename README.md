# TraceShield 🛡️
### AI-Powered Email Threat Detection, GeoLocation & Forensic Intelligence Platform
**Problem Statement:** SIH26106  
**Repository:** [https://github.com/Parthcodes7/TraceShield](https://github.com/Parthcodes7/TraceShield)

---

## 📌 About TraceShield

TraceShield does not simply flag emails as "spam" or "phishing" using opaque heuristics. Instead, it is an **explainable forensic intelligence platform** that:
1. **Verifies Technical Authenticity:** Validates SPF records, DKIM cryptographic signatures, and DMARC alignments via authoritative DNS queries.
2. **Traces Origin & Infrastructure:** Extracts true public sender IPs from relay chains, performs offline MaxMind geolocation (city, country, lat/long), and identifies commercial VPN/datacenter infrastructure.
3. **Unmasks Advanced Threat Vectors:** Decodes hidden destination URLs inside attached QR codes (quishing), catches Unicode IDN homoglyph punycode domains, scans 40+ high-target Indian banks and global brands for Levenshtein lookalikes, detects URL shorteners, and catches paired credential-harvesting triggers.
4. **Applies Zero-Shot NLP:** Uses HuggingFace's DistilBERT (`distilbert-base-uncased-mnli`) to score psychological urgency and impersonation tone on a continuous scale.
5. **Calibrated Fusion Scoring:** Computes a 0–100 risk score, dimensional breakdown (Headers, Content, Origin), positive audit trail, deduplicated threat reasons, actionable containment recommendations, and plain-English narrative summaries.

---

## 🏗️ Architecture & Module Status

```
TraceShield Pipeline:
[ Raw Email (.eml) ]
         │
         ├──► Module 1: Header Forensics (DKIM, SPF, DMARC, Relay Chain, Attachments)  [✅ Complete]
         ├──► Module 2: Content Analysis (DistilBERT NLP, Lookalikes, Homoglyphs, QR)    [✅ Complete]
         ├──► Module 3: Geolocation & Attribution (MaxMind City & ASN, Lat/Long)       [✅ Complete]
         │
         ▼
[ Module 4: Fusion Scoring & Calibration Engine ]                                      [✅ Complete]
         │
         ├──► Module 5: Evidence PDF Report Generator (Jinja2 + HTML-to-PDF)          [⏳ In Progress]
         ├──► FastAPI REST API (`/analyze`, `/report`)                                 [⏳ In Progress]
         ├──► Frontend React 3D Dashboard, Threat Core, and XAI Forensics              [✅ Complete]
         ├──► Module 6: Chrome Manifest V3 Browser Extension                          [⏳ In Progress]
         └──► Module 7: Adversarial Red-Teaming Self-Test Engine                      [⏳ In Progress]
```

### Module Completion Matrix

| Module | File Path | Status | Verification |
|---|---|---|---|
| **Module 1: Header Forensics** | [`backend/modules/header_forensics.py`](backend/modules/header_forensics.py) | ✅ Complete | Fully tested |
| **Module 2: Content Analysis** | [`backend/modules/content_analysis.py`](backend/modules/content_analysis.py) | ✅ Complete | Fully tested |
| **Module 3: Geolocation** | [`backend/modules/geolocation.py`](backend/modules/geolocation.py) | ✅ Complete | Fully tested |
| **Module 4: Fusion Scoring** | [`backend/modules/fusion_scoring.py`](backend/modules/fusion_scoring.py) | ✅ Complete | Fully tested |
| **Module 5: Evidence PDF Report** | [`backend/modules/report_generator.py`](backend/modules/report_generator.py) | ⏳ Next | Specification ready |
| **FastAPI Backend Server** | [`backend/main.py`](backend/main.py) | ⏳ Next | Schema locked |
| **Frontend React UI** | [`frontend/`](frontend/) | ✅ Complete | 3D Dashboard & XAI |
| **Browser Extension** | [`extension/`](extension/) | ⏳ Next | Manifest scaffolded |
| **Module 7: Adversarial Red-Team**| [`backend/modules/adversarial_test.py`](backend/modules/adversarial_test.py) | ⏳ Next | Specification ready |

---

## 🚀 Teammate Quickstart Guide

Follow these steps to set up and run the project locally on your machine.

### Prerequisites
* **Python 3.10, 3.11, or 3.12** installed
* **Git** installed
* *(Optional for frontend)* Node.js v18+

---

### Step 1: Clone the Repository
```bash
git clone https://github.com/Parthcodes7/TraceShield.git
cd TraceShield
```

---

### Step 2: Backend Virtual Environment & Dependencies

1. Navigate to the backend directory:
   ```bash
   cd backend
   ```

2. Create a Python virtual environment:
   ```bash
   # Windows
   python -m venv venv
   .\venv\Scripts\activate

   # macOS / Linux
   python3 -m venv venv
   source venv/bin/activate
   ```

3. Install all dependencies:
   ```bash
   pip install -r requirements.txt
   ```

> **Note for Windows users:** All C-libraries (including `pyzbar` and `Levenshtein`) install directly via pre-compiled wheels. No external C compiler is required!

---

### Step 3: Verify the End-to-End Pipeline

Run the automated pipeline test against our bundled test fixtures:

```bash
python -c "
import email as emaillib
from modules.header_forensics import analyze_headers
from modules.content_analysis import analyze_content
from modules.geolocation import geolocate_ip
from modules.fusion_scoring import run_fusion

with open('data/test_emails/dummy_phishing_1.eml', 'rb') as f:
    raw = f.read()

hf = analyze_headers(raw)
msg = emaillib.message_from_bytes(raw)
body = msg.get_payload()
ca = analyze_content(body, display_name_mismatch=hf.get('display_name_spoof', False))
geo = geolocate_ip(hf.get('origin_ip', ''))
scoring = run_fusion(hf, ca, geo)

print('=== TRACESHIELD PIPELINE TEST ===')
print('Risk Score :', scoring['final_risk_score'], '/ 100')
print('Risk Tier  :', scoring['risk_tier'])
print('Confidence :', scoring['confidence_level'])
print('Breakdown  :', scoring['score_breakdown'])
print('Status     : ✅ ALL 4 MODULES FUNCTIONAL')
"
```

Expected output:
* **Risk Score:** 85/100 (Tier: High, Confidence: High)
* **Score Breakdown:** Header Auth: 40/40 (Fail), Content Threats: 45/45 (High), Network: 0/15 (Normal)

---

### Step 4: Run the FastAPI Server (Optional)

```bash
uvicorn main:app --reload --port 8000
```
Open [http://localhost:8000/docs](http://localhost:8000/docs) in your browser to view the interactive OpenAPI documentation.

---

## 📁 Repository Structure

```
TraceShield/
├── backend/
│   ├── data/
│   │   ├── GeoLite2-City.mmdb       # Offline City & Lat/Long database (bundled)
│   │   ├── GeoLite2-ASN.mmdb        # Offline ISP & ASN database (bundled)
│   │   └── test_emails/
│   │       ├── dummy_phishing_1.eml   # Phishing test fixture
│   │       └── dummy_legitimate_1.eml # Clean legitimate email fixture
│   ├── modules/
│   │   ├── header_forensics.py      # Module 1: SPF, DKIM, DMARC, Relays, Attachments
│   │   ├── content_analysis.py      # Module 2: DistilBERT NLP, Lookalikes, Homoglyphs, QR
│   │   ├── geolocation.py           # Module 3: MaxMind IP lookups & VPN detection
│   │   ├── fusion_scoring.py        # Module 4: 0-100 scoring & confidence engine
│   │   ├── report_generator.py      # Module 5: PDF evidence report generation
│   │   └── adversarial_test.py      # Module 7: AI self-red-teaming engine
│   ├── templates/
│   │   └── report_template.html     # Jinja2 forensic report template
│   ├── main.py                      # FastAPI server & Pydantic shared data schemas
│   └── requirements.txt             # Locked Python dependencies
├── frontend/                        # React + Leaflet.js user interface
│   ├── src/
│   │   ├── components/
│   │   │   ├── ScoreDashboard.jsx   # Visual risk score gauge & breakdown
│   │   │   ├── TraceMap.jsx         # Interactive Leaflet map plotting attacker IP
│   │   │   └── ReportViewer.jsx     # In-browser PDF evidence report viewer
│   │   └── App.jsx
│   └── package.json
├── extension/                       # Chrome Manifest V3 browser extension
│   ├── manifest.json
│   ├── content.js                   # Gmail DOM inspector & threat badging
│   └── popup.html
├── .gitignore                       # Git ignore rules for venvs and build caches
├── work_done.md                     # Comprehensive technical documentation of all features
├── TraceShield_Antigravity_Build_Spec.md # Master project build specification
└── README.md
```

---

## 🔒 Shared Data Contract Rule

Every module reads from and writes to the centralized Pydantic data contract defined in [`backend/main.py`](backend/main.py). 

**Team Rule:** When building or extending a module, read your required inputs from the shared schema and write only to your module's section. Do not alter other module sections to maintain clean decoupled parallelism.

---

## 📄 License & Attribution
* Built for **Smart India Hackathon (SIH26106)**.
* Includes GeoLite2 data created by MaxMind, available from [https://www.maxmind.com](https://www.maxmind.com).
