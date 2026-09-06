import email
import email.utils
import dkim  # from dkimpy
import checkdmarc
import hashlib
import re
import os

# Mass-mailer X-Mailer signatures — legitimate transactional email rarely uses these
SUSPICIOUS_MAILERS = ["sendblaster", "mailchimp", "phpmailer", "massmailer", "sendinblue", "bulk"]

# Attachment extensions that are commonly used for malware delivery
DANGEROUS_EXTENSIONS = [".exe", ".bat", ".cmd", ".vbs", ".js", ".jar",
                         ".ps1", ".msi", ".scr", ".pif", ".hta", ".zip", ".rar"]

def parse_email(raw_bytes: bytes) -> email.message.Message:
    return email.message_from_bytes(raw_bytes)

def compute_hash(raw_bytes: bytes) -> str:
    return hashlib.sha256(raw_bytes).hexdigest()

def verify_dkim(raw_bytes: bytes) -> str:
    try:
        # If no DKIM-Signature header exists, result is 'none', not 'fail'
        if b"dkim-signature:" not in raw_bytes.lower():
            return "none"
        result = dkim.verify(raw_bytes)
        return "pass" if result else "fail"
    except Exception as e:
        print(f"DKIM verification error: {e}")
        return "error"

def check_spf_dmarc(domain: str) -> dict:
    try:
        results = checkdmarc.check_domains([domain])
        spf_valid = False
        dmarc_valid = False

        if 'spf' in results and 'valid' in results['spf']:
            spf_valid = results['spf']['valid']

        if 'dmarc' in results and 'valid' in results['dmarc']:
            dmarc_valid = results['dmarc']['valid']

        return {
            "spf_result": "pass" if spf_valid else "fail",
            "dmarc_result": "pass" if dmarc_valid else "fail"
        }
    except Exception as e:
        print(f"SPF/DMARC check error for domain {domain}: {e}")
        return {"spf_result": "error", "dmarc_result": "error"}

def parse_relay_chain(msg: email.message.Message) -> list:
    received_headers = msg.get_all("Received", [])
    chain = []
    for i, header in enumerate(received_headers):
        header_flat = header.replace('\n', ' ').replace('\r', ' ')

        from_host = "unknown"
        by_host = "unknown"
        timestamp = "unknown"
        ip_address = None

        from_match = re.search(r'from\s+([^\s]+)', header_flat, re.IGNORECASE)
        if from_match:
            from_host = from_match.group(1)

        by_match = re.search(r'by\s+([^\s]+)', header_flat, re.IGNORECASE)
        if by_match:
            by_host = by_match.group(1)

        # Extract IP from brackets e.g. [209.85.212.49]
        ip_match = re.search(r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]', header_flat)
        if ip_match:
            ip_address = ip_match.group(1)

        date_parts = header_flat.split(';')
        if len(date_parts) > 1:
            timestamp = date_parts[-1].strip()

        chain.append({
            "hop": i,
            "from_host": from_host,
            "by_host": by_host,
            "timestamp": timestamp,
            "ip_address": ip_address  # Now we extract the raw IP for geolocation
        })
    return chain

def extract_origin_ip(relay_chain: list) -> str:
    """
    Picks the most likely origin IP from the relay chain.
    The LAST entry in the parsed chain is the FIRST hop (earliest sender).
    We skip private/loopback IPs as they are internal relay hops.
    """
    private_prefixes = ('10.', '192.168.', '172.', '127.')
    for hop in reversed(relay_chain):
        ip = hop.get("ip_address")
        if ip and not any(ip.startswith(p) for p in private_prefixes):
            return ip
    return ""

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
    e.g. "SBI Bank" <hacker@phish.com> — display says SBI but domain is phish.com
    """
    KNOWN_BRANDS = [
        "sbi", "hdfc", "icici", "axis bank", "bank of india", "pnb", "kotak",
        "paypal", "microsoft", "apple", "amazon", "google", "irctc", "uidai",
        "aadhar", "income tax", "epfo", "nps", "lic"
    ]
    raw_from = msg.get("From", "")
    display_name, addr = email.utils.parseaddr(raw_from)
    display_name_lower = display_name.lower()
    addr_domain = addr.split("@")[-1].lower() if "@" in addr else ""

    for brand in KNOWN_BRANDS:
        if brand in display_name_lower:
            # If the brand name appears in display but NOT in the actual domain, it's spoofing
            brand_word = brand.replace(" ", "").replace("bank", "")
            if brand_word and brand_word not in addr_domain:
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

    # Flag 2: Suspicious X-Mailer header (mass mailer tools)
    x_mailer = msg.get("X-Mailer", "").lower()
    if x_mailer and any(sm in x_mailer for sm in SUSPICIOUS_MAILERS):
        flags.append(f"Suspicious X-Mailer detected: '{x_mailer}' — associated with bulk senders")

    # Flag 3: Display name spoofing
    if check_display_name_spoofing(msg):
        flags.append("Display name spoofing detected — brand name in 'From' display does not match sending domain")

    # Flag 4: Reply-To domain mismatch
    if check_reply_to_mismatch(msg):
        flags.append("Reply-To domain does not match From domain — replies will be redirected to a different address")

    # Flag 5: Missing Message-ID (legit emails always have one)
    if not msg.get("Message-ID"):
        flags.append("Missing Message-ID header — unusual for legitimate email")

    # Flag 6: Subject contains all-caps urgency words
    subject = msg.get("Subject", "")
    if re.search(r'\b(URGENT|ALERT|SUSPENDED|IMMEDIATE|WARNING)\b', subject):
        flags.append(f"Subject line contains urgency trigger word: '{subject}'")

    return flags


def check_suspicious_attachments(msg: email.message.Message) -> list:
    """
    Walks all MIME parts of the email and flags any attachments
    with known dangerous file extensions.
    """
    suspicious = []
    for part in msg.walk():
        filename = part.get_filename()
        if filename:
            _, ext = os.path.splitext(filename.lower())
            if ext in DANGEROUS_EXTENSIONS:
                suspicious.append(filename)
    return suspicious


# --- Orchestrator for Module 1 ---
def analyze_headers(raw_email_bytes: bytes) -> dict:
    msg = parse_email(raw_email_bytes)

    # Extract domain from 'From' header
    from_addr = email.utils.parseaddr(msg.get("From", ""))[1]
    domain = from_addr.split("@")[-1] if "@" in from_addr else ""

    spf_dmarc = check_spf_dmarc(domain) if domain else {"spf_result": "error", "dmarc_result": "error"}
    relay_chain = parse_relay_chain(msg)

    suspicious_attachments = check_suspicious_attachments(msg)
    if suspicious_attachments:
        # Inline the attachment flag into anomaly_flags so it shows up in reports
        anomaly_flags_list = detect_anomaly_flags(msg, relay_chain)
        anomaly_flags_list.append(
            f"Dangerous attachment(s) detected: {', '.join(suspicious_attachments)}"
        )
    else:
        anomaly_flags_list = detect_anomaly_flags(msg, relay_chain)

    return {
        "spf_result": spf_dmarc["spf_result"],
        "dmarc_result": spf_dmarc["dmarc_result"],
        "dkim_result": verify_dkim(raw_email_bytes),
        "relay_chain": relay_chain,
        "origin_ip": extract_origin_ip(relay_chain),
        "reply_to_mismatch": check_reply_to_mismatch(msg),
        "display_name_spoof": check_display_name_spoofing(msg),
        "suspicious_attachments": suspicious_attachments,
        "anomaly_flags": anomaly_flags_list
    }
