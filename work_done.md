# TraceShield — Comprehensive Work Done & Feature Audit
## SIH26106 | AI-Powered Email Threat Detection, GeoLocation & Forensic Intelligence Platform
**Generated at:** September 6, 2026  
**Status:** Core Detection & Intelligence Engine (Modules 1–4) Complete & Validated

---

## 📌 Executive Summary

TraceShield has completed the build, refinement, and end-to-end validation of its **Core Forensic Detection Engine (Modules 1 through 4)**. The platform combines deterministic cryptographic protocol checks, zero-shot natural language understanding, computer vision QR decoding, homoglyph punycode analysis, offline IP geolocation, and calibrated fusion scoring into an interpretable threat intelligence pipeline.

Every module conforms strictly to the shared Pydantic data contract defined in [`backend/main.py`](file:///c:/Users/Asus/OneDrive/Desktop/Traceshield/backend/main.py). All ML models and geographic databases run **100% locally and offline**, requiring zero API subscriptions and zero recurring costs.

---

## 🧱 Architecture & Data Contract Status

### Shared Data Contract ([`backend/main.py`](file:///c:/Users/Asus/OneDrive/Desktop/Traceshield/backend/main.py))
A centralized Pydantic v2 schema enforces inter-module consistency. Every component reads from and writes to its dedicated namespace:

* `RelayHop`: Parses relay hop index, `from_host`, `by_host`, timestamp, and hop IP address.
* `HeaderForensics`: Standardizes cryptographic validation results (`spf_result`, `dkim_result`, `dmarc_result`), relay chains, origin IP, Reply-To discrepancies, display name spoofing, attachment inspection, and anomaly flags.
* `HomoglyphDomain`: Structured container for visible Unicode domains, ASCII punycode equivalents, and suspicion flags.
* `QRCode`: Container for decoded URLs, lookalike checks, and reputation flags.
* `ContentAnalysis`: Aggregates urgency NLP score, impersonation NLP score, display name mismatch, lookalike domains, homoglyphs, QR quishing results, URL shorteners, and credential harvesting flags.
* `Geolocation`: Stores origin IP, country, city, ISP/ASN organization, latitude, longitude, and VPN/hosting infrastructure classification.
* `Scoring`: Standardizes 0–100 risk score, risk tier (`Low` | `Medium` | `High`), confidence calibration (`High Confidence` | `Moderate Confidence`), confidence rationale, multi-dimensional score breakdown, deduplicated threat reasons, verified authentications, actionable incident recommendations, and executive summary.
* `EmailAnalysisRecord`: Top-level container linking the raw email SHA-256 hash, unique UUID, analysis timestamp, and all module outputs for strict chain-of-custody tracking.

---

## 🔬 Detailed Module-by-Module Feature Breakdown

### 1. Module 1: Header & Protocol Forensics ([`backend/modules/header_forensics.py`](file:///c:/Users/Asus/OneDrive/Desktop/Traceshield/backend/modules/header_forensics.py))

Determines whether an email's technical origin matches its claimed sender identity through cryptographic and RFC-compliant protocol verification.

#### Features Implemented:
* **RFC 2822 / MIME Parsing:** Parses raw email bytes into structured Python email messages using standard library utilities.
* **Cryptographic DKIM Signature Verification:**
  * Uses `dkimpy` to mathematically verify RSA/Ed25519 digital signatures in email headers.
  * **RFC-Compliant State Machine:** Correctly returns `"none"` when no `DKIM-Signature` header exists, `"pass"` when valid, and `"fail"` when signatures are broken or headers/body were altered in transit.
* **DNS-Based SPF & DMARC Validation:**
  * Utilizes `checkdmarc` and `dnspython` to query and validate SPF TXT records and DMARC policy alignments directly from authoritative DNS servers.
* **Reverse Relay Chain Analysis:**
  * Traverses `Received:` headers in chronological order (from final hop back to original sending mail transfer agent).
  * Extracts sending hostnames, receiving MTAs, protocols (e.g., ESMTPS TLS 1.3), and timestamps.
* **Origin IP Extraction:**
  * Regex-extracts IPv4 addresses from bracketed relay hops (e.g., `[209.85.212.49]`).
  * Automatically filters out internal loopback/private subnets (`127.0.0.1`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) to isolate the true public origin IP for geolocation.
* **Reply-To Domain Mismatch Detection:**
  * Compares domain in `Reply-To:` against domain in `From:`.
  * Catches redirection attacks where replies bypass the victim’s inbox and route directly to an attacker mailbox.
* **Display Name Spoofing Scanner:**
  * Inspects `From:` header display text against a built-in dictionary of high-target brands (e.g., SBI, HDFC, ICICI, Bank of Baroda, IRCTC, UIDAI/Aadhaar, Income Tax, Google, Microsoft, Apple, PayPal).
  * Triggers an anomaly if a brand name appears in display text while the actual sending domain is unrelated (e.g., `"SBI Support" <attacker@phish-portal.com>`).
* **Weaponized Attachment Inspection:**
  * Recursively walks multipart email payloads and extracts attachment filenames.
  * Detects 13 dangerous executable, script, and archive extensions: `.exe`, `.bat`, `.cmd`, `.vbs`, `.js`, `.jar`, `.ps1`, `.msi`, `.scr`, `.pif`, `.hta`, `.zip`, `.rar`.
* **Header Anomaly Engine:**
  * Identifies unusually short relay chains (< 2 hops).
  * Detects mass-mailer tools via `X-Mailer` signatures (`sendblaster`, `mailchimp`, `phpmailer`, `massmailer`, `bulk`).
  * Flags missing `Message-ID` headers.
  * Flags subject line uppercase urgency triggers (`URGENT`, `ALERT`, `SUSPENDED`, `IMMEDIATE`, `WARNING`).

---

### 2. Module 2: Content Analysis, QR & Homoglyphs ([`backend/modules/content_analysis.py`](file:///c:/Users/Asus/OneDrive/Desktop/Traceshield/backend/modules/content_analysis.py))

Identifies linguistic manipulation, deceptive typography, disguised URLs, credential harvesting, and visual barcode attack vectors inside email bodies.

#### Features Implemented:
* **Dual Text & HTML Parsing:**
  * Extracts plain text and hyperlink attributes (`<a href="...">`) from HTML payloads via `BeautifulSoup4`.
  * Extracts raw URLs from plain-text email bodies using RFC-compliant regular expressions.
* **Zero-Shot NLP Threat Classifier (HuggingFace DistilBERT):**
  * Employs `typeform/distilbert-base-uncased-mnli` to evaluate psychological urgency and impersonation risk on a continuous 0.0 to 1.0 probability scale.
  * Evaluates against semantic labels: `"urgent threat"` vs. `"normal message"` and `"identity theft or phishing attempt"` vs. `"normal conversation"`.
  * **Zero-Downtime Fallback:** Includes a robust keyword heuristic baseline that operates instantly if model loading is delayed.
* **Levenshtein Typosquatting / Lookalike Domain Detection:**
  * Computes character edit distances using `python-Levenshtein`.
  * Scans every extracted domain against a curated directory of 40+ legitimate institutions:
    * **Major Indian Banks:** SBI (`sbi.co.in`, `onlinesbi.sbi`), Bank of India, Bank of Baroda, HDFC, ICICI, Axis Bank, PNB, Kotak, Canara, Union Bank, Federal Bank, IDFC First.
    * **Indian Government Entities:** IRCTC, Income Tax Department, UIDAI, EPFO, India.gov.in, MCA, NSDL, CIBIL, Passport India.
    * **Payment Gateways & Wallets:** Paytm, PhonePe, Google Pay, BHIM UPI, Razorpay.
    * **Global Tech:** Google, Microsoft, Apple, Amazon, PayPal, LinkedIn, Twitter/X, Yahoo.
  * Catches subtle substitutions (e.g., `bank0findia.co.in` vs. `bankofindia.co.in`).
* **Unicode IDN Homoglyph / Punycode Scanner:**
  * Uses the `idna` library to expose Internationalized Domain Name (IDN) homograph attacks.
  * Converts international character sets to ASCII Punycode (detecting `xn--` prefixes).
  * Unmasks spoofed Cyrillic or Greek characters that look visually identical to Latin alphabet characters (e.g., Cyrillic `а` vs Latin `a`).
* **QR Code "Quishing" Decoder:**
  * Uses `Pillow` and `pyzbar` (wrapper over `zbar`) to scan and decode QR code matrices embedded in attached images.
  * Extracts destination URLs hidden inside images and automatically routes them through the Lookalike Domain and Homoglyph scanning engines.
* **Multi-Keyword Credential Harvesting Detection:**
  * Detects combinations of high-risk credential-theft phrases (`password`, `otp`, `pin`, `cvv`, `card number`, `verify now`, `account details`, `login`, `authenticate`).
  * Requires a minimum threshold of ≥ 2 paired keywords to eliminate false positives on routine transactional receipts.
* **URL Shortener Cloaking Detection:**
  * Unmasks links routed through 12 common redirection services used to hide malicious endpoints: `bit.ly`, `tinyurl.com`, `t.co`, `goo.gl`, `ow.ly`, `short.link`, `buff.ly`, `rebrand.ly`, `cutt.ly`, `is.gd`, `v.gd`, `shorturl.at`.

---

### 3. Module 3: Geolocation & Attribution ([`backend/modules/geolocation.py`](file:///c:/Users/Asus/OneDrive/Desktop/Traceshield/backend/modules/geolocation.py))

Establishes physical and infrastructural origin tracking using offline MaxMind GeoLite2 databases.

#### Features Implemented:
* **MaxMind GeoLite2-City Database Integration:**
  * Resolves public IP addresses to Origin Country and Origin City offline.
  * Resolves exact **Latitude & Longitude coordinates** (`latitude: 37.751`, `longitude: -97.822`), providing coordinates directly formatted for Leaflet.js mapping.
* **MaxMind GeoLite2-ASN Database Integration:**
  * Queries Autonomous System Numbers (ASN) to identify the registered Internet Service Provider (ISP) or network organization (`Google LLC`, `Amazon.com`, `DigitalOcean`, etc.).
* **Commercial Datacenter & VPN Infrastructure Attribution:**
  * Cross-references network names against a blacklist of commercial cloud hosting, proxy, and VPN providers: `DigitalOcean`, `AWS / Amazon`, `OVH`, `M247`, `Choopa`, `Hetzner`, `Linode`, `Vultr`, `Alibaba`, `Tencent`, `Google Cloud`, `Microsoft Azure`.
  * Flags when an email claiming to be from a consumer or financial institution originates from cloud server infrastructure.
* **Resilient Error Handling:**
  * Handles private IPs, unallocated blocks, and `AddressNotFoundError` exceptions gracefully, returning sanitized `"Unknown"` fallbacks instead of crashing.

---

### 4. Module 4: Fusion Scoring, Calibration & Explainability ([`backend/modules/fusion_scoring.py`](file:///c:/Users/Asus/OneDrive/Desktop/Traceshield/backend/modules/fusion_scoring.py))

Acts as the central decision engine that fuses signals from Modules 1, 2, and 3 into an interpretable verdict.

#### Features Implemented:
* **Multi-Factor Weighted Scoring Algorithm (0–100 Scale):**
  * Evaluates threat indicators with bounded weight caps:
    * SPF Fail / Softfail: +20 / +10 pts
    * DKIM Fail: +20 pts
    * DMARC Fail: +15 pts
    * Reply-To Mismatch: +15 pts
    * Display Name Spoof: +15 pts
    * Dangerous Attachments: +20 pts
    * Lookalike / Typosquatted Domain: +20 pts
    * Unicode IDN Homoglyph: +20 pts
    * QR Quishing Attack: +20 pts
    * Credential Harvesting Language: +15 pts
    * Urgency & Impersonation NLP: Up to +35 pts combined
    * Hosting / VPN Infrastructure IP: +15 pts
    * URL Shorteners: +5 pts
    * Unhandled Header Anomalies: Up to +10 pts
* **Cryptographic Mitigating Discount:**
  * Protects authentic emails: if an email is strongly authenticated (passing SPF + DKIM + DMARC) with no domain spoofing or weaponized payloads, score is discounted to prevent false-positive alarms on urgent business phrasing.
* **Calibrated Confidence Engine:**
  * **Clean Emails:** If risk is low and SPF/DKIM authentication passed, accurately outputs **`High Confidence`** (*"Cryptographically verified authentic — SPF/DKIM/DMARC authentication passed with no domain spoofing or deceptive structural anomalies"*).
  * **Unverified Emails:** If risk is low but headers lack SPF/DKIM, outputs **`Moderate Confidence`** (*"Low risk based on content and heuristics, but domain authentication headers are unverified"*).
  * **Verified Threats:** When cryptographic or technical signals fail (SPF/DKIM/homoglyph/lookalike), outputs **`High Confidence`** (*"Protocol-verified threat — Cryptographic or DNS failure detected. Technical signals cannot be faked"*).
  * **Heuristic Threats:** When only linguistic/NLP signals fire without technical failure, outputs **`Moderate Confidence`** (*"Pattern-based threat — Flagged by linguistic NLP sentiment; recommend manual analyst verification"*).
* **Multi-Dimensional Score Breakdown:**
  * Separates the total score into dimensional sub-scores for frontend visualization and PDF reporting:
    * `header_authentication`: 0–40 pts (`Pass` | `Warning` | `Fail`)
    * `content_threats`: 0–45 pts (`Low` | `Medium` | `High`)
    * `network_infrastructure`: 0–15 pts (`Normal` | `Suspicious`)
* **Signal Deduplication Engine:**
  * Eliminates duplicate reason reporting between standalone protocol checks and raw header anomaly lists.
* **Positive Security Audit Trail (`verified_authentications`):**
  * Logs verified positive trust indicators (`SPF: Sender IP authorized`, `DKIM: Digital signature verified`, `Attachments: Clean`), providing a balanced forensic audit report.
* **Context-Aware Security Incident Recommendations (`recommendations`):**
  * Generates actionable remediation steps:
    * Immediate quarantine and gateway IP/domain blocking.
    * Emergency credential revocation and active session invalidation.
    * Attachment sandbox isolation and binary analysis.
    * Firewall perimeter blocking for decoded QR URLs.
    * Registrar takedown reporting for typosquatted domains.
* **Dynamic Executive Summary Generator (`llm_summary`):**
  * Generates coherent, non-contradictory plain-English narrative paragraphs tailored across Safe, Moderate, and Critical findings without requiring external API keys.

---

## 🧪 Test Fixtures & Validation Results

Two complete test fixtures were built in [`backend/data/test_emails/`](file:///c:/Users/Asus/OneDrive/Desktop/Traceshield/backend/data/test_emails/) and validated through the full end-to-end pipeline:

### 1. Phishing Attack Sample: [`dummy_phishing_1.eml`](file:///c:/Users/Asus/OneDrive/Desktop/Traceshield/backend/data/test_emails/dummy_phishing_1.eml)
* **Attack Vectors Simulated:** Spoofed Bank of India brand, failed SPF/DKIM/DMARC, mismatched Reply-To, lookalike URL (`bank0findia.co.in`), urgency triggers, credential harvesting language.
* **Pipeline Results:**
  * **Final Risk Score:** **85 / 100** (Risk Tier: **High**)
  * **Confidence Level:** **High Confidence** (Protocol-verified threat)
  * **Score Breakdown:** Header Auth: 40/40 (`Fail`), Content Threats: 45/45 (`High`), Network: 0/15 (`Normal`)
  * **Threat Reasons Identified:** 9 unique indicators (zero duplicates)
  * **Recommendations:** 4 immediate containment actions
  * **Pydantic Validation:** ✅ Passed

### 2. Legitimate Email Sample: [`dummy_legitimate_1.eml`](file:///c:/Users/Asus/OneDrive/Desktop/Traceshield/backend/data/test_emails/dummy_legitimate_1.eml)
* **Vectors Simulated:** Standard Google Calendar invitation with legitimate relay headers and no deceptive payloads.
* **Pipeline Results:**
  * **Final Risk Score:** **23 / 100** (Risk Tier: **Low**)
  * **Confidence Level:** **High Confidence** (Authentic origin)
  * **Score Breakdown:** Header Auth: 5/40 (`Pass`), Content Threats: 18/45 (`Medium`), Network: 0/15 (`Normal`)
  * **Verified Authentications:** 3 passing cryptographic indicators
  * **Recommendations:** Standard email hygiene
  * **Pydantic Validation:** ✅ Passed

---

## 🗂️ Installed Libraries & Local Datasets

| Component | Asset / Library | Status | Details |
|---|---|---|---|
| **MaxMind City DB** | `GeoLite2-City.mmdb` | ✅ Installed | 62.3 MB in `backend/data/` |
| **MaxMind ASN DB** | `GeoLite2-ASN.mmdb` | ✅ Installed | 11.5 MB in `backend/data/` |
| **NLP Transformer** | `typeform/distilbert-base-uncased-mnli` | ✅ Cached | Cached in `~/.cache/huggingface/` |
| **QR Decoder** | `pyzbar` + `Pillow` | ✅ Functional | Windows wheel includes bundled C DLLs |
| **Punycode / IDN** | `idna` | ✅ Functional | Handles internationalized Unicode conversions |
| **Edit Distance** | `python-Levenshtein` | ✅ Functional | Edit-distance calculation for lookalikes |
| **Crypto & DNS** | `dkimpy`, `checkdmarc`, `dnspython` | ✅ Functional | Full cryptographic header verification |
| **Data Models** | `pydantic` | ✅ Functional | Pydantic v2 data models |
| **Web Server** | `fastapi`, `uvicorn` | ✅ Functional | API framework |

---

## 🚀 Remaining Roadmap to 100% Complete Prototype

```
[██████████████░░░░░░░░░░] ~55-60% Complete Overall
```

1. **FastAPI Endpoints ([`backend/main.py`](file:///c:/Users/Asus/OneDrive/Desktop/Traceshield/backend/main.py)):** Expose `/analyze` endpoint to accept `.eml` uploads and raw text over HTTP.
2. **Module 5 — Evidence Report Generator ([`backend/modules/report_generator.py`](file:///c:/Users/Asus/OneDrive/Desktop/Traceshield/backend/modules/report_generator.py)):** Generate downloadable, court/filing-ready forensic PDF reports using Jinja2 + `xhtml2pdf`.
3. **Frontend Dashboard & TraceMap ([`frontend/src/`](file:///c:/Users/Asus/OneDrive/Desktop/Traceshield/frontend/src/)):** React interface with Leaflet.js map, risk gauge, score breakdown bars, and PDF download button.
4. **Module 6 — Chrome Browser Extension ([`extension/`](file:///c:/Users/Asus/OneDrive/Desktop/Traceshield/extension/)):** Manifest V3 in-inbox scanner badging Gmail messages.
5. **Module 7 — Adversarial Self-Red-Teaming ([`backend/modules/adversarial_test.py`](file:///c:/Users/Asus/OneDrive/Desktop/Traceshield/backend/modules/adversarial_test.py)):** Live demo feature testing AI-generated evasion emails against TraceShield.
