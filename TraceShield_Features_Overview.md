# 🛡️ TraceShield (SIH26106) — Complete Feature & Architectural Guide

---

## 1. The Core Problem Statement (SIH26106)

### The Problem
Traditional email gateways and spam filters (like standard Bayesian filters or static blacklists) suffer from critical limitations:
1. **Black-box verdicts**: They label an email as "Spam" or "Phishing" with no technical explanation or audit trail.
2. **Blindness to modern evasion vectors**: They struggle with **Unicode IDN homoglyphs** (e.g., Cyrillic characters that look identical to Latin letters), **quishing** (hiding malicious URLs inside QR codes in attachments or inline HTML), and **display-name brand spoofing**.
3. **Lack of infrastructure origin tracing**: Attackers easily forge the `From` header. Victims cannot see where the email *actually* came from geographically or whether it originated from a commercial VPN/datacenter node.
4. **No chain-of-custody evidence**: Law enforcement and enterprise SOC analysts cannot take a standard spam flag to court or an incident report; they need cryptographic proof, hashes, relay hops, and formal forensic documentation.

### TraceShield's Solution
**TraceShield** is an **Explainable Forensic Intelligence Platform**. Instead of giving a simple "safe/unsafe" flag, it performs multi-layered forensic inspection, traces physical and network origins, runs local offline Zero-Shot NLP, decodes hidden barcodes, calibrates risk transparently, and generates court-grade PDF dossiers.

---

## 2. Comprehensive Breakdown of All 7 Core Modules

```
                        [ Raw Email (.eml / MIME text) ]
                                      │
        ┌─────────────────────────────┼─────────────────────────────┐
        ▼                             ▼                             ▼
   [ Module 1 ]                  [ Module 2 ]                  [ Module 3 ]
Header Forensics              Content & QR Engine            Geolocation & ASN
- SPF / DKIM / DMARC          - Zero-Shot NLP (DistilBERT)   - Offline MaxMind DB
- Reverse Relay Chain         - QR Quishing Scanner          - Public Origin IP
- Display Name Spoofing       - Unicode Homoglyphs           - VPN / VPS ASN Flag
- Attachment SHA-256          - 40+ Bank Lookalike Domains   - Lat / Long Mapping
        │                             │                             │
        └─────────────────────────────┼─────────────────────────────┘
                                      ▼
                                [ Module 4 ]
                    Threat Fusion Scoring Engine (0-100)
                    - Dimensional Breakdown (Headers, Content, Origin)
                    - False-Positive Capping & Mitigating Discounts
                    - High / Moderate Confidence Calibration
                    - Dynamic AI Executive Briefing
                                      │
         ┌────────────────────────────┼────────────────────────────┐
         ▼                            ▼                            ▼
   [ Module 5 ]                  [ Module 6 ]                 [ Module 7 ]
Evidence PDF Dossier          Chrome Extension (MV3)       Adversarial Lab
- Chain of Custody            - Real-time Gmail overlay    - AI Evasion Simulator
- RFC Header Audit            - In-inbox threat badges     - Zero-Shot Stress Test
- WeasyPrint + Jinja2         - Direct triage actions      - Defense Verification
```

---

### 🔍 Module 1: Header & Protocol Forensics
*File: `backend/modules/header_forensics.py`*

1. **Cryptographic DKIM Verification (`dkimpy`)**:
   - Computes mathematical RSA/Ed25519 signature checks on headers and email body.
   - Detects whether headers or contents were tampered with in transit.
2. **Authoritative DNS SPF & DMARC Validation (`checkdmarc`, `dnspython`)**:
   - Resolves the true SMTP `Return-Path` envelope domain and checks SPF TXT records.
   - Evaluates DMARC alignment (`pass`, `fail`, `softfail`, or `none`).
3. **Reverse Relay Chain Reconstruction**:
   - Parses chronological `Received:` headers from the final destination back to the initial injection MTA.
   - Extracts server hostnames, timestamps, and routing protocols (e.g., ESMTPS TLS 1.3).
4. **Public Origin IP Extraction**:
   - Strips internal loopback and RFC 1918 private subnets (`127.0.0.1`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) to isolate the genuine public sender IP.
5. **Reply-To Mismatch Detection**:
   - Detects when the `Reply-To:` domain diverges from the `From:` domain, revealing attacker shadow inboxes.
6. **Display Name Brand Spoofing**:
   - Cross-references display names against major institutions (SBI, HDFC, ICICI, Aadhaar/UIDAI, PayPal, Microsoft, Google, etc.). Flags attacks where display text reads "HDFC Security" but the sender domain is `@random-server.com`.
7. **Attachment Forensics & SHA-256 Hashing**:
   - Recursively traverses MIME parts to detect 13 high-risk executable, script, and macro extensions (`.exe`, `.bat`, `.vbs`, `.js`, `.hta`, `.iso`, `.scr`, etc.).
   - Computes a cryptographic **SHA-256 hash** for every attachment for threat intel cross-referencing.
8. **Structural Anomaly Engine**:
   - Flags suspicious technical indicators: missing `Message-ID`, short relay hops (< 2 servers), known bulk mailers (`X-Mailer: sendblaster, massmailer`), and uppercase urgency triggers.

---

### 🧠 Module 2: NLP Content Analysis, QR & Homoglyphs
*File: `backend/modules/content_analysis.py`*

1. **Zero-Shot NLP Threat Classification (`transformers`)**:
   - Employs HuggingFace's `typeform/distilbert-base-uncased-mnli` running **100% locally and offline**.
   - Scores **Psychological Urgency** (panic induction) and **Authority Impersonation** on a continuous 0.0 to 1.0 scale.
   - Utilizes dual-window scanning (first 3072 + last 1024 characters) to catch calls-to-action buried at the bottom of long emails.
2. **QR Code "Quishing" Extraction (`pyzbar` + `Pillow`)**:
   - Detects embedded QR codes in image attachments *and* inline base64 HTML images (`data:image/png;base64`).
   - Decodes target URLs and sends them through lookalike and homoglyph checks.
3. **Unicode IDN Homoglyph Attack Detection (`idna`)**:
   - Decodes Internationalized Domain Names (Punycode `xn--`) to reveal lookalike non-Latin substitutions (e.g., replacing Latin `'a'` with Cyrillic `'а'`).
4. **Second-Level Domain (SLD) Lookalike Engine (`python-Levenshtein`)**:
   - Calculates Levenshtein edit distance on the exact second-level domain against 40+ high-target Indian banks, government portals, and global brands.
   - Catches subtle typosquatting (e.g., `sbi-verify.com` vs `sbi.co.in`).
5. **Credential Harvesting Detection**:
   - Scans for proximity patterns pairing sensitive targets (`password`, `OTP`, `PIN`, `bank account`, `KYC`) with action triggers (`verify`, `login`, `update immediately`).
6. **URL Shortener Obfuscation**:
   - Flags URL masking services (bit.ly, tinyurl, t.co, is.gd, etc.).

---

### 🌍 Module 3: Geolocation & Infrastructure Attribution
*File: `backend/modules/geolocation.py`*

1. **Offline MaxMind GeoLite2 City Database**:
   - Maps extracted origin IPs to exact Country, Region, City, and geographic coordinates (latitude & longitude).
2. **Autonomous System Number (ASN) & ISP Tracking**:
   - Queries MaxMind GeoLite2 ASN database to identify the network provider routing the message.
3. **Commercial VPN & Cloud Datacenter Detection**:
   - Detects origin IPs belonging to cloud VPS providers (DigitalOcean, AWS, OVH, Linode, Hetzner) and proxy/VPN networks, alerting analysts when a corporate email originated from an unauthenticated cloud server.

---

### ⚖️ Module 4: Fusion Scoring, Confidence Calibration & XAI
*File: `backend/modules/fusion_scoring.py`*

1. **Deterministic 0–100 Risk Score**:
   - Categorized into three tiers: **Low Risk (0–30)**, **Medium Risk (31–60)**, and **High Risk (61–100)**.
2. **Dimensional Points Breakdown**:
   - **Header Authentication**: Max 40 points (SPF, DKIM, DMARC, Reply-To, spoofing).
   - **Content Threats**: Max 45 points (NLP urgency/impersonation, homoglyphs, QR, lookalikes).
   - **Network Infrastructure**: Max 15 points (VPN/datacenter IP).
3. **Mitigating Discounts (False-Positive Capping)**:
   - If an email has valid SPF/DKIM authentication and zero hard threats (no homoglyphs, no quishing, no lookalikes), the score is capped at 20 (Low Risk) even if promotional marketing text triggered high NLP urgency.
4. **Hard Threat Override**:
   - If both NLP Urgency and Impersonation exceed 75%, mitigating discounts are bypassed to catch hijacked legitimate email accounts.
5. **Confidence Level Calibration**:
   - Labels verdicts as **"High Confidence"** (backed by objective cryptographic/DNS failures) or **"Moderate Confidence"** (driven by probabilistic heuristics).
6. **Positive Security Audit Trail**:
   - Provides a list of *passed* security controls alongside triggered threat indicators.
7. **Plain-English Executive Briefing**:
   - Synthesizes all findings into a plain-English, executive summary explaining what happened without requiring deep technical knowledge.

---

### 📄 Module 5: Court-Grade Evidence PDF Dossier
*File: `backend/modules/report_generator.py`*

1. **Chain of Custody & Evidence Headers**:
   - Records Analysis Timestamp, Investigator ID, Unique UUID, and raw email SHA-256 hash.
2. **Comprehensive Visual Report**:
   - Built using **Jinja2** HTML templating and rendered via **WeasyPrint**.
   - Includes executive summary, risk gauge, protocol verification grid, reverse relay hops table, decoded QR findings, and targeted incident containment steps.
3. **One-Click Export**:
   - Direct download from the web interface or via the `/report` API endpoint.

---

### 🧩 Module 6: Chrome Browser Extension (Manifest V3)
*Directory: `extension/`*

1. **In-Inbox Gmail Integration**:
   - Automatically injects security warning badges directly into the Gmail email reading pane.
2. **Real-Time Header & Content Parsing**:
   - Inspects active emails and sends telemetry to the local FastAPI backend.
3. **Interactive Extension Popup**:
   - Displays real-time risk gauges, origin country, authentication status, and one-click actions: "View Full Forensic Dossier", "Quarantine Message", and "Download Evidence PDF".

---

### ⚡ Module 7: Adversarial Red-Team Simulator
*File: `backend/modules/adversarial_test.py`*

1. **Simulated AI Attack Strategies**:
   - **Business Routine Reconciliation**: Low-urgency, polite invoice request designed to bypass NLP urgency filters (caught by SPF failure and lookalike domains).
   - **IT Certificate Maintenance**: Routine notification designed to evade alarm filters (caught by Cyrillic homoglyphs).
   - **EPFO HR Benefits Quishing**: Urgent barcode payload (caught by QR quishing detection).
   - **Executive Whaling Impersonation**: Calm CEO correspondence (caught by Reply-To mismatch).
2. **Live Defense Validation**:
   - Feeds generated evasive payloads through TraceShield to demonstrate how multi-layered detection catches attacks that bypass single-signal filters.

---

## 3. The Web Application & Dashboard Experience

1. **Landing Screen (`IntroPage.jsx`)**:
   - Clean, modern landing interface presenting the 6 core forensic pillars and a single-click entry into the dashboard.
2. **Threat Assessment Core (`ScoreDashboard.jsx`)**:
   - SVG radial risk gauge (0–100), dimensional breakdown progress bars, plain-English executive briefing, and interactive **Threat Explanation tooltips**.
3. **3D Interactive Earth Globe (`TraceMap.jsx`)**:
   - WebGL 3D rotating globe rendering the email's physical origin with latitude/longitude markers and datacenter ISP badges.
4. **3D Threat Topology Graph (`ReportViewer.jsx`)**:
   - Interactive 3D node-link graph visualizing relationships between Sender, Mail Relays, Target, and Detected Threats.
5. **One-Click Attack Demos**:
   - Instant testing with pre-loaded real-world scenarios: Bank of India Spoof, Google Calendar Invite, Cyrillic Homoglyph Attack, and Cloud VPS Origin.
6. **Upload & Batch Processing (`UploadModal.jsx`)**:
   - Supports `.eml` file drag-and-drop, raw RFC 822 text paste, and batch multi-email queues.
7. **SQLite Investigation History (`HistoryDrawer.jsx`)**:
   - Persists all past investigations locally with risk-tier filters and instant retrieval.

---

## 4. Key Advantages for Presentations & Evaluations

| Capability | Standard Gateway / Spam Filter | TraceShield Platform |
|---|---|---|
| **Protocol Authentication** | Binary Pass/Fail flag | Cryptographic DKIM + Envelope SPF + DMARC alignment audit |
| **Origin Attribution** | Often masked or ignored | Public IP reverse relay extraction + MaxMind City & ASN mapping |
| **Advanced Vectors** | Misses QR codes & Homoglyphs | Automatic inline QR decoding + Punycode IDN homoglyph detection |
| **Lookalike Detection** | Static keyword lists | Levenshtein edit distance on Second-Level Domains (40+ brands) |
| **NLP Context** | Generic keyword matching | Local Zero-Shot DistilBERT scoring urgency & impersonation |
| **Explainability** | Opaque black-box | Full dimensional point breakdown, positive audit trail, and briefing |
| **Offline Privacy** | Requires cloud API calls | **100% offline & local**, zero external data leakage |
| **Evidence Output** | Basic UI alert | Downloadable, court-grade PDF evidence dossier with SHA-256 hash |
