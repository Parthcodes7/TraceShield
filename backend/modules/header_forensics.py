"""
Module 1 — Header Forensics & Protocol Authentication
SIH26106 | AI-Powered Email Threat Detection, GeoLocation & Forensic Intelligence Platform

Performs:
  - DKIM cryptographic verification (dkimpy)
  - SPF / DMARC DNS policy checks (checkdmarc) against envelope Return-Path domain
  - Full relay chain parsing with IPv4 + IPv6 extraction
  - Private-subnet filtered origin IP extraction (stdlib ipaddress)
  - Reply-To / Display-name spoofing detection
  - Dangerous attachment detection + SHA-256 hashing per attachment
  - Key metadata extraction (From, To, Subject, Date, Return-Path)
"""

import email
import email.utils
import dkim          # from dkimpy
import checkdmarc
import hashlib
import logging
import re
import os
import ipaddress

try:
    import tldextract
    _TLDEXTRACT_AVAILABLE = True
except ImportError:
    _TLDEXTRACT_AVAILABLE = False

logger = logging.getLogger("traceshield.header_forensics")

# High-risk X-Mailer signatures — dedicated spam/malware-sending tools
# NOTE: mailchimp, sendinblue, sendgrid etc. send legitimate transactional mail
# and must NOT be flagged as suspicious (high false-positive rate).
SUSPICIOUS_MAILERS_HIGH = [
    "sendblaster", "massmailer", "bulk mailer", "group mail",
    "atomic mail", "advanced direct remailer",
]
# Informational only — mass-send platforms. Not scored, just logged.
SUSPICIOUS_MAILERS_INFO = [
    "phpmailer", "mailchimp", "sendinblue", "sendgrid",
    "constant contact", "brevo",
]

# Attachment extensions commonly used for malware delivery
# Updated 2026: added disk images (.iso/.img), Office macro formats (.docm/.xlsm)
# Windows shortcut (.lnk), and HTML application (.hta) threat vectors.
DANGEROUS_EXTENSIONS = [
    # Executables & scripts
    ".exe", ".bat", ".cmd", ".vbs", ".js", ".jar",
    ".ps1", ".msi", ".scr", ".pif", ".hta", ".com",
    # Archives (commonly used to bypass attachment scanners)
    ".zip", ".rar", ".7z", ".tar", ".gz",
    # Disk images (modern malware delivery vector)
    ".iso", ".img", ".vhd", ".vhdx",
    # Office macro-enabled formats
    ".docm", ".xlsm", ".pptm", ".xltm",
    # Windows shortcuts & compiled HTML
    ".lnk", ".chm",
]


# ---------------------------------------------------------------------------
# Core Parsing
# ---------------------------------------------------------------------------

def parse_email(raw_bytes: bytes) -> email.message.Message:
    return email.message_from_bytes(raw_bytes)


def compute_hash(raw_bytes: bytes) -> str:
    return hashlib.sha256(raw_bytes).hexdigest()


# ---------------------------------------------------------------------------
# DKIM — Bug fix: scan only header slice, never call .lower() on full bytes
# ---------------------------------------------------------------------------

def verify_dkim(raw_bytes: bytes) -> str:
    """
    Verifies the DKIM-Signature header cryptographically.
    Scans only the first 8KB of the message for the header presence to avoid
    allocating a full copy of large binary email payloads.
    """
    try:
        header_slice = raw_bytes[:8192]
        if not re.search(rb'(?im)^dkim-signature\s*:', header_slice):
            return "none"
        result = dkim.verify(raw_bytes)
        return "pass" if result else "fail"
    except Exception as e:
        logger.warning("DKIM verification error: %s", e)
        return "error"


# ---------------------------------------------------------------------------
# SPF / DMARC — Check against envelope Return-Path domain (not From domain)
# ---------------------------------------------------------------------------

def get_envelope_domain(msg: email.message.Message) -> str:
    """
    Returns the envelope sender domain for SPF checking.
    Prefers Return-Path (true SMTP MAIL FROM envelope), falls back to From.
    """
    # Return-Path is the authoritative envelope sender for SPF
    return_path_raw = msg.get("Return-Path", "")
    if return_path_raw:
        rp_addr = email.utils.parseaddr(return_path_raw)[1]
        if rp_addr and "@" in rp_addr:
            return rp_addr.split("@")[-1].lower().strip()

    # Fallback: From header domain
    from_addr = email.utils.parseaddr(msg.get("From", ""))[1]
    if from_addr and "@" in from_addr:
        return from_addr.split("@")[-1].lower().strip()

    return ""


def check_spf_dmarc(domain: str) -> dict:
    try:
        results = checkdmarc.check_domains([domain])
        spf_valid = False
        dmarc_valid = False

        if "spf" in results and "valid" in results["spf"]:
            spf_valid = results["spf"]["valid"]

        if "dmarc" in results and "valid" in results["dmarc"]:
            dmarc_valid = results["dmarc"]["valid"]

        return {
            "spf_result": "pass" if spf_valid else "fail",
            "dmarc_result": "pass" if dmarc_valid else "fail",
        }
    except Exception as e:
        logger.warning("SPF/DMARC check error for domain '%s': %s", domain, e)
        return {"spf_result": "error", "dmarc_result": "error"}


# ---------------------------------------------------------------------------
# Relay Chain — IPv4 + IPv6 extraction
# ---------------------------------------------------------------------------

def parse_relay_chain(msg: email.message.Message) -> list:
    received_headers = msg.get_all("Received", [])
    chain = []
    for i, header in enumerate(received_headers):
        header_flat = header.replace("\n", " ").replace("\r", " ")

        from_host = "unknown"
        by_host = "unknown"
        timestamp = "unknown"
        ip_address = None

        from_match = re.search(r"from\s+(\S+)", header_flat, re.IGNORECASE)
        if from_match:
            from_host = from_match.group(1)

        by_match = re.search(r"by\s+(\S+)", header_flat, re.IGNORECASE)
        if by_match:
            by_host = by_match.group(1)

        # Extract IPv4 from brackets e.g. [209.85.212.49]
        ipv4_match = re.search(r"\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]", header_flat)
        if ipv4_match:
            ip_address = ipv4_match.group(1)

        # Extract IPv6 from brackets e.g. [2001:db8::1] (only if no IPv4 found)
        if not ip_address:
            ipv6_match = re.search(r"\[([0-9a-fA-F:]{7,39})\]", header_flat)
            if ipv6_match:
                candidate = ipv6_match.group(1)
                # Validate it's actually a parseable IPv6 address
                try:
                    ipaddress.IPv6Address(candidate)
                    ip_address = candidate
                except ValueError:
                    pass

        date_parts = header_flat.split(";")
        if len(date_parts) > 1:
            timestamp = date_parts[-1].strip()

        chain.append({
            "hop": i,
            "from_host": from_host,
            "by_host": by_host,
            "timestamp": timestamp,
            "ip_address": ip_address,
        })
    return chain


def _is_private_ip(ip: str) -> bool:
    """
    Uses stdlib ipaddress for accurate RFC 1918 / loopback / link-local detection.
    Replaces the fragile prefix-string approach that incorrectly flagged 172.1-15.x.x.
    """
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def extract_origin_ip(relay_chain: list) -> str:
    """
    Picks the most likely origin IP from the relay chain.
    The LAST entry in the parsed chain is the FIRST hop (earliest sender).
    We skip private/loopback IPs as they are internal relay hops.
    """
    for hop in reversed(relay_chain):
        ip = hop.get("ip_address")
        if ip and not _is_private_ip(ip):
            return ip
    return ""


# ---------------------------------------------------------------------------
# Spoofing Detection
# ---------------------------------------------------------------------------

def check_reply_to_mismatch(msg: email.message.Message) -> bool:
    from_addr = email.utils.parseaddr(msg.get("From", ""))[1]
    reply_to_addr = email.utils.parseaddr(msg.get("Reply-To", ""))[1]

    if not reply_to_addr:
        return False

    from_domain = from_addr.split("@")[-1] if "@" in from_addr else ""
    reply_domain = reply_to_addr.split("@")[-1] if "@" in reply_to_addr else ""

    return from_domain.lower() != reply_domain.lower()


def check_display_name_spoofing(msg: email.message.Message) -> bool:
    """
    Detects if the display name in 'From' contains a known brand name
    but the actual sending address domain does not match it.
    e.g. "SBI Bank" <hacker@phish.com> — display says SBI but domain is phish.com.

    Uses tldextract (when available) to compare only the registered domain (SLD+TLD)
    rather than the full hostname, preventing both false positives from subdomains
    and false negatives from suffix-appended lookalike domains
    (e.g., 'sbi-secure-login.com' correctly fails — 'sbi' is not the SLD).
    """
    KNOWN_BRANDS = [
        "sbi", "hdfc", "icici", "axis", "bank of india", "pnb", "kotak",
        "paypal", "microsoft", "apple", "amazon", "google", "irctc", "uidai",
        "aadhar", "income tax", "epfo", "nps", "lic", "phonepe", "paytm",
    ]
    raw_from = msg.get("From", "")
    display_name, addr = email.utils.parseaddr(raw_from)
    display_name_lower = display_name.lower()
    addr_domain = addr.split("@")[-1].lower() if "@" in addr else ""

    # Extract only the registrable domain (SLD, no subdomain, no TLD)
    # e.g. 'mail.sbi.co.in' -> 'sbi', 'sbi-secure-login.com' -> 'sbi-secure-login'
    if _TLDEXTRACT_AVAILABLE and addr_domain:
        ext = tldextract.extract(addr_domain)
        # registered_domain = sld + tld, e.g. 'sbi.co.in'
        # domain = sld only, e.g. 'sbi'
        addr_sld = ext.domain.lower()  # Just the SLD for brand matching
    else:
        # Fallback: strip common TLDs manually
        addr_sld = addr_domain.split(".")[0] if addr_domain else ""

    for brand in KNOWN_BRANDS:
        if brand in display_name_lower:
            # Normalize brand to a single token (e.g., "bank of india" -> "bankofindia")
            brand_token = brand.replace(" ", "")
            # A legitimate brand email's SLD should be exactly the brand token
            # 'sbi.co.in' -> sld='sbi' -> matches 'sbi' brand ✓
            # 'sbi-secure-login.com' -> sld='sbi-secure-login' -> 'sbi' NOT == sld → spoof ✓
            if brand_token != addr_sld and brand_token not in addr_sld.replace("-", "").replace("_", ""):
                return True
    return False


def detect_anomaly_flags(msg: email.message.Message, relay_chain: list) -> list:
    """
    Generates a list of human-readable anomaly flags from header analysis.
    """
    flags = []

    # Flag 1: Suspiciously few relay hops (legit emails have at least 2-3)
    if len(relay_chain) < 2:
        flags.append("Unusually short relay chain — may indicate spoofed headers")

    # Flag 2: Suspicious X-Mailer header (dedicated spam-sending tools only)
    # Only flag HIGH-risk mailers to avoid false positives from legitimate marketing tools.
    x_mailer = msg.get("X-Mailer", "").lower()
    if x_mailer and any(sm in x_mailer for sm in SUSPICIOUS_MAILERS_HIGH):
        flags.append(
            f"High-risk bulk mailer detected: '{x_mailer}' — associated with spam campaigns"
        )
    elif x_mailer and any(sm in x_mailer for sm in SUSPICIOUS_MAILERS_INFO):
        logger.debug("Informational: Mass-send platform detected in X-Mailer: %s", x_mailer)

    # Flag 3: Display name spoofing
    if check_display_name_spoofing(msg):
        flags.append(
            "Display name spoofing detected — brand name in 'From' display does not match sending domain"
        )

    # Flag 4: Reply-To domain mismatch
    if check_reply_to_mismatch(msg):
        flags.append(
            "Reply-To domain does not match From domain — replies will be redirected to a different address"
        )

    # Flag 5: Missing Message-ID (legit emails always have one)
    if not msg.get("Message-ID"):
        flags.append("Missing Message-ID header — unusual for legitimate email")

    # Flag 6: Subject contains all-caps urgency words
    subject = msg.get("Subject", "")
    if re.search(r"\b(URGENT|ALERT|SUSPENDED|IMMEDIATE|WARNING)\b", subject):
        flags.append(f"Subject line contains urgency trigger word: '{subject}'")

    return flags


# ---------------------------------------------------------------------------
# Attachment Inspection — Feature F5: SHA-256 hash per attachment
# ---------------------------------------------------------------------------

def check_suspicious_attachments(msg: email.message.Message) -> list:
    """
    Walks all MIME parts and flags attachments with dangerous file extensions.
    """
    suspicious = []
    for part in msg.walk():
        filename = part.get_filename()
        if filename:
            _, ext = os.path.splitext(filename.lower())
            if ext in DANGEROUS_EXTENSIONS:
                suspicious.append(filename)
    return suspicious


def extract_attachment_hashes(msg: email.message.Message) -> list:
    """
    Feature F5: For every attachment (dangerous or benign), compute SHA-256.
    Returns a list of dicts: {filename, sha256, size_bytes, is_dangerous}.
    Gives incident responders hashes to cross-reference with threat intel feeds.
    """
    hashes = []
    for part in msg.walk():
        filename = part.get_filename()
        if filename:
            try:
                payload = part.get_payload(decode=True)
                if payload:
                    _, ext = os.path.splitext(filename.lower())
                    hashes.append({
                        "filename": filename,
                        "sha256": hashlib.sha256(payload).hexdigest(),
                        "size_bytes": len(payload),
                        "is_dangerous": ext in DANGEROUS_EXTENSIONS,
                    })
            except Exception as e:
                logger.warning("Could not hash attachment '%s': %s", filename, e)
    return hashes


# ---------------------------------------------------------------------------
# Metadata Extraction — Feature F2: Subject, From, To, Date, Return-Path
# ---------------------------------------------------------------------------

def extract_email_metadata(msg: email.message.Message) -> dict:
    """
    Extracts key investigative metadata fields from the parsed message object.
    These are surfaced in the forensic PDF report header section.
    """
    return {
        "from_header": msg.get("From", ""),
        "to_header": msg.get("To", ""),
        "subject_header": msg.get("Subject", ""),
        "date_header": msg.get("Date", ""),
        "return_path": msg.get("Return-Path", ""),
        "message_id": msg.get("Message-ID", ""),
    }


# ---------------------------------------------------------------------------
# Module 1 Orchestrator
# ---------------------------------------------------------------------------

def analyze_headers(raw_email_bytes: bytes) -> dict:
    msg = parse_email(raw_email_bytes)

    # Extract envelope domain for correct SPF checking
    envelope_domain = get_envelope_domain(msg)
    spf_dmarc = (
        check_spf_dmarc(envelope_domain)
        if envelope_domain
        else {"spf_result": "error", "dmarc_result": "error"}
    )

    relay_chain = parse_relay_chain(msg)
    origin_ip = extract_origin_ip(relay_chain)

    suspicious_attachments = check_suspicious_attachments(msg)
    attachment_hashes = extract_attachment_hashes(msg)
    metadata = extract_email_metadata(msg)

    anomaly_flags_list = detect_anomaly_flags(msg, relay_chain)
    if suspicious_attachments:
        anomaly_flags_list.append(
            f"Dangerous attachment(s) detected: {', '.join(suspicious_attachments)}"
        )

    return {
        # Protocol authentication
        "spf_result": spf_dmarc["spf_result"],
        "dmarc_result": spf_dmarc["dmarc_result"],
        "dkim_result": verify_dkim(raw_email_bytes),
        # Routing analysis
        "relay_chain": relay_chain,
        "origin_ip": origin_ip,
        # Spoofing signals
        "reply_to_mismatch": check_reply_to_mismatch(msg),
        "display_name_spoof": check_display_name_spoofing(msg),
        # Attachment forensics
        "suspicious_attachments": suspicious_attachments,
        "attachment_hashes": attachment_hashes,
        # Anomaly flags
        "anomaly_flags": anomaly_flags_list,
        # Metadata (F2)
        **metadata,
    }
