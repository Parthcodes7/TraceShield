# TraceShield — Complete Build Specification for Antigravity
## SIH26106 | AI-Powered Email Threat Detection, GeoLocation & Forensic Intelligence Platform
### Verified technical reference — every library/dataset claim below was checked before writing

---

## 0. How to Use This File

This document is written to be fed directly to an AI coding assistant (Antigravity) as the master spec. It contains the project structure, exact module logic, verified library names/install steps, dataset sources, and a JSON data contract every module must conform to. Where something could not be fully verified (rare, flagged explicitly), it is marked **⚠️ VERIFY DURING BUILD** rather than stated as fact.

---

## 1. Project Overview

**Problem Statement:** SIH26106 — AI-Powered Email Threat Detection, GeoLocation & Forensic Intelligence Platform

**One-line pitch:** A platform that doesn't just flag phishing emails — it forensically explains why an email is suspicious, traces its true origin, catches threats hidden in QR codes and lookalike Unicode domains, tests itself against AI-generated attacks, lives inside the user's actual inbox, and generates a legally-structured evidence report in one click.

**Core components:**
1. Header & Protocol Forensics (Module 1)
2. NLP Content Analysis + QR Detection + Homoglyph Detection (Module 2)
3. Geolocation & Attribution (Module 3)
4. Fusion Scoring + Confidence Calibration + LLM Summary (Module 4)
5. Evidence Report Generator (Module 5)
6. Browser Extension (Module 6)
7. Adversarial Self-Red-Teaming (Module 7)

---

## 2. Shared Data Contract (Lock This First — All Modules Read/Write This Shape)

```json
{
  "email_id": "string (UUID)",
  "raw_email_hash": "string (SHA-256 hex digest of raw email bytes)",
  "analyzed_at": "string (ISO 8601 timestamp)",

  "header_forensics": {
    "spf_result": "pass | fail | none | error",
    "dmarc_result": "pass | fail | none | error",
    "dkim_result": "pass | fail | none | error",
    "relay_chain": [
      {"hop": "int", "from_host": "string", "by_host": "string", "timestamp": "string"}
    ],
    "reply_to_mismatch": "boolean",
    "anomaly_flags": ["array of strings"]
  },

  "content_analysis": {
    "urgency_score": "float 0-1",
    "impersonation_score": "float 0-1",
    "display_name_mismatch": "boolean",
    "lookalike_domains_found": ["array of strings"],
    "homoglyph_domains_found": [
      {"visible_domain": "string", "decoded_ascii": "string", "suspicious": "boolean"}
    ],
    "qr_codes_found": [
      {"decoded_url": "string", "lookalike_check": "boolean", "reputation_flag": "boolean"}
    ],
    "credential_harvesting_detected": "boolean"
  },

  "geolocation": {
    "origin_ip": "string",
    "origin_country": "string",
    "origin_isp": "string",
    "is_known_vpn_or_hosting": "boolean"
  },

  "scoring": {
    "final_risk_score": "int 0-100",
    "risk_tier": "Low | Medium | High",
    "confidence_level": "High Confidence | Moderate Confidence",
    "confidence_reason": "string (e.g. 'protocol-verified: SPF/DKIM fail' or 'pattern-based only, recommend human review')",
    "llm_summary": "string (plain-English forensic summary)"
  },

  "adversarial_test": {
    "tested": "boolean",
    "generated_sample_caught": "boolean",
    "notes": "string"
  }
}
```

**Rule for the team:** Every module reads its inputs from this shape and writes only to its own section. Nobody edits another module's section. This is what allows 6 people to build in parallel against mock JSON before real data exists.

---

## 3. Module 1 — Header & Protocol Forensics

### Purpose
Determine whether the email's technical origin matches its claimed identity.

### Input
Raw `.eml` file or raw email string (bytes or `str`).

### Verified Libraries
| Library | Install | What it does |
|---|---|---|
| `email` | stdlib, no install | Parses raw email into a Message object |
| `dkimpy` | `pip install dkimpy` | Verifies DKIM cryptographic signatures — **use this for DKIM specifically** |
| `checkdmarc` | `pip install checkdmarc` | Validates and parses **SPF and DMARC DNS records** (does not do DKIM signature verification — that's `dkimpy`'s job). Actively maintained, current version 5.x as of 2026. |
| `dnspython` | `pip install dnspython` | Low-level DNS TXT record lookups if you need custom SPF parsing beyond checkdmarc |

**⚠️ Correction to earlier assumption:** `checkdmarc` covers SPF + DMARC, **not DKIM**. You need `dkimpy` separately for DKIM signature verification. Don't assume one library does all three checks.

### Logic
```python
import email
import dkim  # from dkimpy
import checkdmarc
import hashlib

def parse_email(raw_bytes: bytes) -> email.message.Message:
    return email.message_from_bytes(raw_bytes)

def compute_hash(raw_bytes: bytes) -> str:
    return hashlib.sha256(raw_bytes).hexdigest()

def verify_dkim(raw_bytes: bytes) -> str:
    try:
        result = dkim.verify(raw_bytes)
        return "pass" if result else "fail"
    except Exception:
        return "error"

def check_spf_dmarc(domain: str) -> dict:
    try:
        result = checkdmarc.check_domains([domain])
        return {
            "spf_result": "pass" if result[0].get("spf", {}).get("valid") else "fail",
            "dmarc_result": "pass" if result[0].get("dmarc", {}).get("valid") else "fail"
        }
    except Exception:
        return {"spf_result": "error", "dmarc_result": "error"}

def parse_relay_chain(msg: email.message.Message) -> list:
    received_headers = msg.get_all("Received", [])
    # Parse each header for hop, from, by, timestamp
    # Received headers are in REVERSE chronological order (last hop first)
    chain = []
    for i, header in enumerate(received_headers):
        chain.append({"hop": i, "raw": header})  # parse further with regex for from/by/date
    return chain

def check_reply_to_mismatch(msg: email.message.Message) -> bool:
    from_addr = email.utils.parseaddr(msg.get("From", ""))[1]
    reply_to_addr = email.utils.parseaddr(msg.get("Reply-To", ""))[1]
    if not reply_to_addr:
        return False
    from_domain = from_addr.split("@")[-1] if "@" in from_addr else ""
    reply_domain = reply_to_addr.split("@")[-1] if "@" in reply_to_addr else ""
    return from_domain.lower() != reply_domain.lower()
```

### Output
Populate `header_forensics` section of the shared contract.

---

## 4. Module 2 — NLP Content Analysis + QR + Homoglyph Detection

### Purpose
Detect linguistic, structural, and encoded-threat patterns in the email body and attachments.

### Verified Libraries
| Library | Install | What it does |
|---|---|---|
| `beautifulsoup4` | `pip install beautifulsoup4` | Strips HTML, extracts plain text and links from HTML email bodies |
| `python-Levenshtein` | `pip install python-Levenshtein` | Fast edit-distance calculation for lookalike domain detection |
| `transformers` (HuggingFace) | `pip install transformers` | Pretrained text classification, OR use Claude API for zero-shot classification |
| `pyzbar` | `pip install pyzbar` **+ system dependency** | Decodes QR codes from images |
| `Pillow` | `pip install Pillow` | Required by pyzbar to open images before decoding |

**⚠️ Critical system dependency for pyzbar — do not skip this:**
`pyzbar` is a Python wrapper around the `zbar` C library and will **not work from pip alone**. You must install the system library first:
- Linux (Debian/Ubuntu, which Antigravity's container likely uses): `sudo apt-get install libzbar0`
- macOS: `brew install zbar`
- Windows: zbar DLLs are bundled with the pip wheel, no extra step needed

If you skip the system install on Linux, `from pyzbar.pyzbar import decode` will throw an import error, not a silent failure — test this on Day 1.

### Sub-feature: QR "Quishing" Detection
```python
from pyzbar.pyzbar import decode
from PIL import Image
import io

def extract_qr_urls(image_bytes: bytes) -> list:
    image = Image.open(io.BytesIO(image_bytes))
    decoded_objects = decode(image)
    urls = [obj.data.decode("utf-8") for obj in decoded_objects if obj.type == "QRCODE"]
    return urls

# Feed each decoded URL through the SAME lookalike-domain check used for visible links
```

### Sub-feature: Unicode Homoglyph / IDN Homograph Detection
```python
import idna  # pip install idna — handles punycode encode/decode for internationalized domains

def check_homoglyph(domain: str) -> dict:
    try:
        # If domain contains non-ASCII, this reveals the actual punycode form
        ascii_form = idna.encode(domain).decode("ascii")
        is_punycode = ascii_form.startswith("xn--")
        return {
            "visible_domain": domain,
            "decoded_ascii": ascii_form,
            "suspicious": is_punycode  # xn-- prefix means non-Latin characters were used
        }
    except idna.IDNAError:
        return {"visible_domain": domain, "decoded_ascii": domain, "suspicious": False}
```
**Note:** `idna` (`pip install idna`) is the correct library for punycode/IDN encoding — this is what reveals whether a visually-normal-looking domain actually contains non-Latin Unicode characters underneath.

### Sub-feature: Lookalike Domain Detection (Edit Distance)
```python
import Levenshtein

KNOWN_LEGITIMATE_DOMAINS = ["bankofindia.co.in", "sbi.co.in", "gmail.com"]  # expand this list

def check_lookalike(domain: str) -> list:
    matches = []
    for legit in KNOWN_LEGITIMATE_DOMAINS:
        distance = Levenshtein.distance(domain, legit)
        if 0 < distance <= 2:
            matches.append(legit)
    return matches
```

### Output
Populate `content_analysis` section of the shared contract.

---

## 5. Module 3 — Geolocation & Attribution

### Purpose
Determine the true geographic/infrastructure origin of the email.

### Verified Libraries & Setup
| Library | Install | Notes |
|---|---|---|
| `geoip2` | `pip install geoip2` | Official MaxMind Python library to read `.mmdb` database files |

**⚠️ Important, verified access process — this is NOT a simple direct download anymore:**
As of MaxMind's 2019 policy change (still in effect), you **cannot anonymously download** the GeoLite2 database file. The correct process is:
1. Create a free MaxMind account at `https://www.maxmind.com/en/geolite2/signup`
2. Generate a free license key from your account dashboard
3. Download `GeoLite2-City.mmdb` using your account credentials (via their `geoipupdate` tool, or a direct authenticated download link from your account page)
4. Do this on **Day 1**, not the night before — account approval/access has occasionally had delays reported by users

```python
import geoip2.database

reader = geoip2.database.Reader("GeoLite2-City.mmdb")

def geolocate_ip(ip: str) -> dict:
    try:
        response = reader.city(ip)
        return {
            "origin_country": response.country.name,
            "origin_isp": "N/A - City DB does not include ISP, use GeoLite2-ASN for that"
        }
    except geoip2.errors.AddressNotFoundError:
        return {"origin_country": "Unknown", "origin_isp": "Unknown"}
```

**⚠️ Correction:** The `GeoLite2-City` database gives country/city/lat-long, but **not ISP/organization name**. For ISP/hosting-provider identification (needed for your VPN/hosting detection), you need the separate **`GeoLite2-ASN`** database (also free, same account) or the paid `GeoIP2-ISP` database for more accuracy. Download both `GeoLite2-City.mmdb` and `GeoLite2-ASN.mmdb`.

### VPN/Hosting Detection
Maintain a small static list of known hosting/VPN provider ASN numbers (e.g., DigitalOcean, AWS, OVH, M247) and cross-reference the ASN returned by `GeoLite2-ASN` lookup. **⚠️ VERIFY DURING BUILD:** compile this ASN list from a current public source at build time, since specific ASN-to-provider mappings can shift.

### Output
Populate `geolocation` section of the shared contract.

---

## 6. Module 4 — Fusion Scoring + Confidence Calibration + LLM Summary

### Purpose
Combine all signals into one interpretable score, an honest confidence label, and a plain-English explanation.

### Scoring Logic (tune weights during testing — these are starting points, not fixed truth)
```python
def compute_risk_score(data: dict) -> dict:
    score = 0
    hf = data["header_forensics"]
    ca = data["content_analysis"]
    geo = data["geolocation"]

    protocol_signals = 0  # tracks how many HIGH-CONFIDENCE (protocol-based) signals fired
    if hf["spf_result"] == "fail":
        score += 20; protocol_signals += 1
    if hf["dkim_result"] == "fail":
        score += 20; protocol_signals += 1
    if hf["dmarc_result"] == "fail":
        score += 15; protocol_signals += 1
    if hf["reply_to_mismatch"]:
        score += 15; protocol_signals += 1

    score += ca["urgency_score"] * 15
    score += ca["impersonation_score"] * 20
    if ca["lookalike_domains_found"]:
        score += 20
    if any(h["suspicious"] for h in ca.get("homoglyph_domains_found", [])):
        score += 20; protocol_signals += 1  # homoglyph detection is a technical/objective signal
    if ca.get("qr_codes_found") and any(q["reputation_flag"] for q in ca["qr_codes_found"]):
        score += 15

    if geo["is_known_vpn_or_hosting"]:
        score += 15

    score = min(int(score), 100)
    tier = "High" if score >= 61 else "Medium" if score >= 31 else "Low"

    # Confidence calibration: protocol-based signals (SPF/DKIM/DMARC/homoglyph) are
    # objectively verifiable. NLP-pattern-only signals (urgency, impersonation tone)
    # are probabilistic and should lower confidence if they're the ONLY signals firing.
    confidence = "High Confidence" if protocol_signals >= 1 else "Moderate Confidence"
    confidence_reason = (
        "Protocol-verified (SPF/DKIM/DMARC/domain authentication failure detected)"
        if confidence == "High Confidence"
        else "Based on language/pattern analysis only — recommend human review"
    )

    return {
        "final_risk_score": score,
        "risk_tier": tier,
        "confidence_level": confidence,
        "confidence_reason": confidence_reason
    }
```

### LLM Summary Generation
Use Claude API (or any LLM API) with a prompt template:
```
Given these forensic findings: {json_data}
Write a 3-4 sentence plain-English summary for a non-technical reader,
explaining what was found and why it is or isn't suspicious.
```

### Output
Populate `scoring` section of the shared contract.

---

## 7. Module 5 — Evidence Report Generator

### Purpose
Convert all findings into a structured, downloadable, filing-ready PDF.

### Verified Libraries
| Library | Install | Notes |
|---|---|---|
| `Jinja2` | `pip install Jinja2` | HTML templating |
| `WeasyPrint` | `pip install weasyprint` | Converts HTML+CSS to PDF. **⚠️ Has its own system dependencies (Pango, Cairo, GDK-PixBuf) on Linux** — if you hit install errors, run `apt-get install libpango-1.0-0 libpangocairo-1.0-0` first |

### Logic
```python
from jinja2 import Template
from weasyprint import HTML

def generate_report(data: dict, template_path: str, output_path: str):
    with open(template_path) as f:
        template = Template(f.read())
    filled_html = template.render(**data)
    HTML(string=filled_html).write_pdf(output_path)
```

### Report Contents (map directly from the shared data contract)
- Report ID, timestamp, SHA-256 hash (`raw_email_hash`) — chain of custody
- Executive summary (`scoring.llm_summary`)
- Technical findings table (`header_forensics`)
- Geolocation section (`geolocation`)
- Content analysis findings including QR/homoglyph detections (`content_analysis`)
- Final risk score + confidence label + recommendation (`scoring`)

**Framing note for the report and your pitch:** This is a document *structured the way* an investigator-usable forensic report would be — not a claim of official CERT-In certification.

---

## 8. Module 6 — Browser Extension

### Purpose
Live, in-inbox detection.

### Verified Approach
- **Manifest V3** Chrome Extension (current standard; Manifest V2 is deprecated by Google)
- `content.js` injected into `mail.google.com`
- Two implementation options:
  1. **DOM scraping** (faster to build, more fragile): read visible email content from Gmail's rendered HTML via `document.querySelector`. **Limitation:** full raw headers are NOT available in Gmail's web UI DOM — you'll only get sender, subject, visible body text.
  2. **Gmail API + OAuth2** (more robust, more setup time): use `gmail.readonly` scope, fetch messages with `format=RAW` to get the complete raw RFC 2822 message including all headers — this is required if you want real SPF/DKIM/DMARC data from a live Gmail message, not just the visible parts.

**⚠️ Recommendation given hackathon time constraints:** Start Gmail API OAuth consent screen setup on **Day 1, hour 1** if you choose option 2 — OAuth app verification/consent screens can take time to configure correctly, and you don't want to discover a blocker on the final day. If time is short, fall back to option 1 (DOM scraping) for the demo, and state Gmail API integration as the "production version" in your pitch.

```javascript
// manifest.json (Manifest V3)
{
  "manifest_version": 3,
  "name": "TraceShield",
  "version": "1.0",
  "permissions": ["activeTab", "scripting"],
  "host_permissions": ["https://mail.google.com/*"],
  "content_scripts": [{
    "matches": ["https://mail.google.com/*"],
    "js": ["content.js"]
  }]
}
```

```javascript
// content.js (simplified DOM-scraping version)
function extractVisibleEmail() {
  const sender = document.querySelector('.gD')?.getAttribute('email');
  const subject = document.querySelector('.hP')?.textContent;
  const body = document.querySelector('.a3s')?.textContent;
  return { sender, subject, body };
}

async function analyzeEmail(emailData) {
  const response = await fetch('http://localhost:8000/analyze', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(emailData)
  });
  return response.json();
}

// Inject a badge showing the result next to the email
```

---

## 9. Module 7 — Adversarial Self-Red-Teaming

### Purpose
Your standout demo feature — generate novel AI-crafted phishing emails designed to evade Module 2, then run them through your own detector live.

### Logic
```python
def generate_adversarial_sample(llm_client) -> str:
    prompt = """
    Write a realistic phishing email that would try to avoid detection by:
    - Not using urgent/threatening language
    - Not using an obviously fake domain
    - Sounding like routine business correspondence
    This is for authorized security testing of our own detection system.
    """
    response = llm_client.generate(prompt)
    return response

def run_self_test(generated_email: str, pipeline_func) -> dict:
    result = pipeline_func(generated_email)
    return {
        "tested": True,
        "generated_sample_caught": result["scoring"]["risk_tier"] in ["Medium", "High"],
        "notes": f"Adversarial sample scored {result['scoring']['final_risk_score']}/100"
    }
```

**Demo framing:** Whether it catches the sample or not, both outcomes make a strong point — catching it proves robustness; missing it justifies your Confidence-Calibrated Verdicts feature ("this is exactly why we flag moderate-confidence results for human review instead of claiming perfect detection").

---

## 10. Datasets

| Dataset | Use | Access |
|---|---|---|
| **Nazario Phishing Corpus** | Real phishing email samples for testing Module 2 | Publicly referenced in academic phishing-detection research; search for current mirror/host, as distribution links can move over time — **⚠️ VERIFY DURING BUILD** that whichever mirror you find is still active |
| **SpamAssassin Public Corpus** | Mix of spam/phishing and legitimate ("ham") emails for balanced testing | Widely mirrored; verify current download link at build time |
| **Self-generated legitimate emails** | 20-30 emails you write yourselves, varying sender/style/topic | No access issue — you create these directly, and they're essential for proving your model doesn't just flag everything as suspicious |
| **Self-crafted demo emails** | 4-5 emails specifically engineered to trigger each detection layer (SPF-fail, lookalike domain, QR+homoglyph combo, urgency+VPN routing) | You create these — this is your actual demo-day test set, more important than the public corpora |

---

## 11. Full Tech Stack Summary

| Layer | Technology |
|---|---|
| Backend | Python 3.11, FastAPI |
| Email parsing | `email` (stdlib), `mailparser` |
| DKIM | `dkimpy` |
| SPF/DMARC | `checkdmarc` |
| DNS | `dnspython` |
| HTML parsing | `beautifulsoup4` |
| Edit distance | `python-Levenshtein` |
| QR decoding | `pyzbar` + system `libzbar0` |
| Homoglyph/IDN | `idna` |
| NLP/LLM | `transformers` or Claude API |
| Geolocation | `geoip2` + MaxMind `GeoLite2-City.mmdb` + `GeoLite2-ASN.mmdb` (account + license key required) |
| PDF generation | `Jinja2` + `WeasyPrint` (+ system Pango/Cairo deps) |
| Frontend | React + Leaflet.js |
| Browser extension | Chrome Manifest V3 + optional Gmail API/OAuth2 |
| Database | SQLite (fastest to set up) or PostgreSQL |

---

## 12. Folder Structure

```
traceshield/
├── backend/
│   ├── main.py
│   ├── modules/
│   │   ├── header_forensics.py
│   │   ├── content_analysis.py       # includes QR + homoglyph sub-functions
│   │   ├── geolocation.py
│   │   ├── fusion_scoring.py
│   │   ├── report_generator.py
│   │   └── adversarial_test.py
│   ├── data/
│   │   ├── GeoLite2-City.mmdb
│   │   ├── GeoLite2-ASN.mmdb
│   │   └── test_emails/
│   ├── templates/
│   │   └── report_template.html
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── App.jsx
│   │   └── components/
│   │       ├── ScoreDashboard.jsx
│   │       ├── TraceMap.jsx
│   │       └── ReportViewer.jsx
│   └── package.json
├── extension/
│   ├── manifest.json
│   ├── content.js
│   └── popup.html
└── README.md
```

---

## 13. Build Order (Matches Team Role Split)

1. Lock shared JSON contract (all 6, hour 0-1)
2. Module 1 (Header Forensics) — no ML dependency, unblocks everyone
3. Module 3 (Geolocation) — get MaxMind account/keys running in parallel with Module 1
4. Module 2 (Content + QR + Homoglyph) — build against mock header data
5. Module 4 (Fusion + Confidence) — FastAPI `/analyze` endpoint stitching 1+2+3
6. Module 5 (Evidence Report) — build against dummy JSON from hour 1, swap in real data later
7. Module 7 (Adversarial Testing) — needs Module 2+4 working first
8. Module 6 (Browser Extension) — start OAuth setup Day 1 if using Gmail API, wire to `/analyze` last

---

## 14. Things Explicitly Flagged for Early Testing (Don't Discover These Late)

- **pyzbar's system dependency (`libzbar0`)** — test the import on your actual build environment Day 1
- **MaxMind account/license key signup** — do this immediately, not the night before
- **WeasyPrint's system dependencies** (Pango/Cairo/GDK-PixBuf on Linux) — test a minimal PDF generation script before building the full template
- **Gmail API OAuth consent screen** (if used) — start configuration Day 1
- **Public dataset mirror links** (Nazario, SpamAssassin) — confirm current working links before relying on them; have your self-crafted demo emails as a fallback regardless

---

## 15. Locked Scope — Do Not Add Further Features

This project is intentionally locked at: 5-module core + Browser Extension + Evidence Report + Confidence Calibration + QR Detection + Homoglyph Detection + Adversarial Self-Red-Teaming. Every addition beyond the original core reuses an existing module's logic — none require new infrastructure. No further features should be added; remaining time goes to integration testing, bug fixing, and demo rehearsal.
