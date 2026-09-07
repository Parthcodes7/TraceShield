# TraceShield - Project Features & Detailed Specifications

## Project Overview
**TraceShield** (SIH26106) is an AI-Powered Email Threat Detection, GeoLocation & Forensic Intelligence Platform. It goes beyond simple phishing detection by providing forensic explanations, tracing actual email origins, identifying hidden threats like QR codes and homoglyphs, integrating directly into the inbox via browser extensions, and providing legally structured evidence reports.

---

## 1. Core Modules & Detailed Features

### Module 1: Header & Protocol Forensics
*   **Purpose**: Validates the technical origin and claimed identity of an email.
*   **Features**:
    *   **SPF, DKIM, & DMARC Validation**: Cryptographically verifies DKIM signatures and checks SPF/DMARC policies.
    *   **Envelope Domain Checking**: Resolves the true SMTP `Return-Path` envelope domain for accurate SPF validation, falling back to the `From` domain if missing.
    *   **Relay Chain Analysis & IP Extraction**: Parses `Received` headers to trace server hops. Automatically extracts both IPv4 and IPv6 addresses.
    *   **Private-Subnet Filtering**: Utilizes `ipaddress` to ignore internal, loopback, and RFC 1918 private network hops to find the true public origin IP.
    *   **Reply-To Mismatch Detection**: Flags inconsistencies between the `From` address domain and the `Reply-To` domain.
    *   **Display Name Spoofing Detection**: Uses `tldextract` to verify if a trusted brand name in the display name (e.g., "SBI Bank") matches the actual Second-Level Domain (SLD) of the sender, preventing false negatives from subdomain spoofing.
    *   **Attachment Forensics & Hashing**: Scans MIME parts for dangerous extensions (including modern vectors like `.iso`, `.img`, `.hta`, and Office macros). Computes a **SHA-256 hash** for *every* attachment for threat intel cross-referencing.
    *   **Anomaly Flag Generation**: Detects suspicious structural headers, such as:
        *   Unusually short relay chains (< 2 hops).
        *   High-risk `X-Mailer` signatures (e.g., Sendblaster, Massmailer).
        *   Missing `Message-ID` headers.
        *   All-caps urgency triggers in the Subject line.
    *   **Metadata Extraction**: Gathers core investigative data (From, To, Subject, Date, Return-Path, Message-ID) for the final report.

### Module 2: NLP Content Analysis, QR & Homoglyph Detection
*   **Purpose**: Detects linguistic manipulation, structural anomalies, and encoded threats.
*   **Features**:
    *   **Urgency & Impersonation Scoring (NLP)**: Uses a HuggingFace Zero-Shot classifier (`typeform/distilbert-base-uncased-mnli`) with thread-safe lazy loading to prevent OOM errors. Expands the context window to the first 3072 and last 1024 characters to catch buried Call-To-Actions.
    *   **Credential Harvesting Detection**: Uses contextual regex to find combinations of action verbs (e.g., "verify", "enter") and credential targets (e.g., "password", "OTP") within an 80-character window.
    *   **URL Shortener Detection**: Identifies and flags common URL obfuscation services (bit.ly, tinyurl, etc.).
    *   **Lookalike Domain Detection (SLD-Level)**: Uses Levenshtein edit distance specifically on the extracted Second-Level Domain. This correctly catches TLD swaps (e.g., `hdfcbank.com` vs `hdfcbank.co.in`) and suffix injections.
    *   **Unicode Homoglyph / IDN Detection**: Decodes Punycode (`xn--`) via the `idna` library to reveal hidden non-Latin characters used to spoof legitimate domains.
    *   **QR Code "Quishing" Detection**: Uses `pyzbar` to extract embedded QR codes. Crucially, it scans both standard attachments AND **inline base64 encoded images** (`data:image/png;base64`) hidden in HTML bodies. Decoded URLs undergo lookalike and homoglyph checks.

### Module 3: Geolocation & Attribution
*   **Purpose**: Uncovers the true geographic and infrastructure origin of the email.
*   **Features**:
    *   **IP Geolocation**: Uses MaxMind GeoLite2 databases to map the origin IP to a Country and specific City.
    *   **ISP / ASN Tracking**: Identifies the specific Autonomous System Number (ASN) routing the traffic.
    *   **VPN & Commercial Hosting Detection**: Cross-references ASNs against known commercial hosting providers (AWS, DigitalOcean, OVH) and VPNs to detect bad actors masking their physical origin.

### Module 4: Fusion Scoring, Confidence Calibration & LLM Summary
*   **Purpose**: Aggregates all signals into a single standardized verdict with a natural language explanation.
*   **Features**:
    *   **Dimensional Score Breakdown**: Splits risk into three distinct categories: Header Authentication (max 40 pts), Content Threats (max 45 pts), and Network Infrastructure (max 15 pts).
    *   **Mitigating Discounts (False Positive Capping)**: If an email is strongly authenticated (passes SPF/DKIM with no spoofing) and lacks "hard threats," the total score is capped at 20 (Low Risk) to prevent aggressive NLP from flagging legitimate marketing emails.
    *   **NLP Hard Threat Override**: If NLP confidence for *both* Urgency and Impersonation exceeds 75%, it bypasses mitigating discounts (catches compromised legitimate accounts).
    *   **Confidence Calibration**: Labels findings as "High Confidence" (objective protocol failures like DKIM fail or Homoglyphs) or "Moderate Confidence" (probabilistic pattern failures like linguistic urgency).
    *   **Context-Aware Incident Recommendations**: Generates specific security actions (e.g., "Quarantine message", "Initiate password reset", "Blacklist QR destination") based on the exact triggers hit.
    *   **Verified Authentications & Triggered Reasons**: Deduplicates and lists exactly *why* a score was given, alongside a positive audit trail of what *passed*.
    *   **Forensic Executive Summary**: Generates a dynamic, plain-English summary designed for non-technical users to understand the threat vector.

### Module 5: Evidence Report Generator
*   **Purpose**: Produces structured, filing-ready forensic documents.
*   **Features**:
    *   **Automated PDF Generation**: Converts all findings (Chain of Custody, Hash, Header Forensics, Content Analysis, Geolocation, Verdict, Score Breakdown) into a downloadable PDF report using Jinja2 and WeasyPrint.

### Module 6: Browser Extension
*   **Purpose**: Provides live, in-inbox detection and warnings.
*   **Features**:
    *   **Manifest V3 Extension**: Integrates seamlessly with Chrome.
    *   **Gmail Integration**: Uses DOM scraping or Gmail API (OAuth2) to extract email contents and headers for real-time analysis against the backend.

### Module 7: Adversarial Self-Red-Teaming
*   **Purpose**: Proves platform robustness by generating and catching AI-crafted attacks.
*   **Features**:
    *   **AI Phishing Generation**: Crafts evasive, non-urgent, routine-sounding phishing emails to bypass standard NLP detection.
    *   **Live Self-Testing**: Feeds these generated samples back into the detection pipeline to demonstrate system efficacy and justify the confidence calibration logic.

---

## 2. Scores, Labels & Parameters

The system relies on a standardized JSON data contract across all modules.

### Risk Labels (Tiers)
Based on the final calculated score (0-100), the email is classified into:
*   **Low**: 0 - 30
*   **Medium**: 31 - 60
*   **High**: 61 - 100

### Scoring Weights & Parameters
*   **Header Authentication (Max 40 pts):**
    *   SPF Fail: `+20` | SPF Softfail: `+10`
    *   DKIM Fail: `+20`
    *   DMARC Fail: `+15` (or `+8` if SPF/DKIM passed, penalizing policy misalignment)
    *   Reply-To Mismatch: `+15`
    *   Display Name Spoofing: `+15`
    *   Dangerous Attachments: `+20`
    *   Header Anomalies: `+5` each (capped at `10`)
*   **Content Threats (Max 45 pts):**
    *   Urgency Score (>0.4): `(urgency * 15)`
    *   Impersonation Score (>0.4): `(impersonation * 20)`
    *   Lookalike Domain Found: `+20`
    *   Homoglyph Domain Found: `+20`
    *   Malicious QR Code Found: `+20`
    *   Credential Harvesting Language: `+15`
    *   URL Shorteners: `+5`
*   **Network Infrastructure (Max 15 pts):**
    *   Known VPN or Hosting IP Origin: `+15`

---

## 3. Standardized Data Contract (JSON)
Every analysis produces a unified structure covering these parameters:

```json
{
  "email_id": "UUID",
  "raw_email_hash": "SHA-256 hex digest",
  "analyzed_at": "ISO 8601 timestamp",
  "header_forensics": {
    "spf_result": "pass | fail | softfail | none | error",
    "dmarc_result": "pass | fail | none | error",
    "dkim_result": "pass | fail | none | error",
    "relay_chain": [ {"hop": 0, "from_host": "...", "by_host": "...", "ip_address": "...", "timestamp": "..."} ],
    "origin_ip": "...",
    "reply_to_mismatch": true,
    "display_name_spoof": false,
    "suspicious_attachments": [],
    "attachment_hashes": [ {"filename": "...", "sha256": "...", "size_bytes": 0, "is_dangerous": true} ],
    "anomaly_flags": [],
    "from_header": "...",
    "to_header": "...",
    "subject_header": "...",
    "date_header": "...",
    "return_path": "...",
    "message_id": "..."
  },
  "content_analysis": {
    "urgency_score": 0.85,
    "impersonation_score": 0.90,
    "display_name_mismatch": true,
    "lookalike_domains_found": [],
    "homoglyph_domains_found": [ {"visible_domain": "...", "decoded_ascii": "...", "suspicious": true} ],
    "qr_codes_found": [ {"decoded_url": "...", "lookalike_check": true, "reputation_flag": true} ],
    "url_shorteners_found": [],
    "credential_harvesting_detected": false
  },
  "geolocation": {
    "origin_ip": "...",
    "origin_country": "...",
    "origin_city": "...",
    "origin_isp": "...",
    "is_known_vpn_or_hosting": true
  },
  "scoring": {
    "final_risk_score": 85,
    "risk_tier": "High",
    "confidence_level": "High Confidence",
    "confidence_reason": "Protocol-verified threat...",
    "score_breakdown": {
        "header_authentication": {"points": 35, "max_score": 40, "status": "Fail"},
        "content_threats": {"points": 35, "max_score": 45, "status": "High"},
        "network_infrastructure": {"points": 15, "max_score": 15, "status": "Suspicious"}
    },
    "triggered_reasons": ["SPF record check FAILED...", "Dangerous attachment(s) identified..."],
    "verified_authentications": ["Attachments: No high-risk executable..."],
    "recommendations": ["Quarantine this message immediately..."],
    "llm_summary": "Plain-English summary of the attack vector."
  },
  "adversarial_test": {
    "tested": true,
    "generated_sample_caught": true,
    "notes": "..."
  }
}
```

---

## 4. Technical Stack

*   **Backend Application:** Python 3.11, FastAPI
*   **Domain & Signature Verification:** `dkimpy` (DKIM), `checkdmarc` (SPF/DMARC), `dnspython` (DNS lookups), `tldextract` (SLD extraction)
*   **Content / HTML Parsing:** `beautifulsoup4`
*   **Lookalike / Text Analysis:** `python-Levenshtein` (Edit distance), `idna` (Homoglyphs)
*   **Machine Learning / NLP:** `transformers` (HuggingFace `distilbert-base-uncased-mnli`)
*   **QR Decoding:** `pyzbar` + `Pillow` (Requires `libzbar0` system dependency)
*   **Geolocation:** `geoip2` with MaxMind GeoLite2 Databases (City + ASN)
*   **Evidence PDF Generation:** `Jinja2` (Templating) + `WeasyPrint` (HTML to PDF)
*   **Frontend:** React, Leaflet.js (for Geolocation maps)
*   **Browser Extension:** Chrome Manifest V3 (JavaScript, HTML, CSS)
*   **Database:** SQLite / PostgreSQL
