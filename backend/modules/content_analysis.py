"""
Module 2 — Content & Linguistic Analysis
SIH26106 | AI-Powered Email Threat Detection, GeoLocation & Forensic Intelligence Platform

Performs:
  - HTML body parsing & URL extraction
  - Lookalike / typosquatting domain detection (Levenshtein distance)
  - Unicode homoglyph / IDN punycode detection
  - QR code quishing vector extraction (pyzbar)
  - NLP zero-shot urgency & impersonation scoring (DistilBERT fallback to keyword heuristics)
  - URL shortener detection
  - Credential harvesting language detection
"""

import io
import re
import idna
import email
import base64
import logging
import threading
import Levenshtein
from bs4 import BeautifulSoup

try:
    from pyzbar.pyzbar import decode
    PYZBAR_AVAILABLE = True
except (ImportError, Exception):
    decode = None
    PYZBAR_AVAILABLE = False

from PIL import Image

logger = logging.getLogger("traceshield.content_analysis")

# ---------------------------------------------------------------------------
# NLP Classifier — Thread-safe lazy loader
# ---------------------------------------------------------------------------

_classifier = None
_classifier_lock = threading.Lock()
_classifier_load_attempted = False   # Avoid retrying after a known failure


def _get_classifier():
    """
    Thread-safe lazy initialisation.
    The lock prevents multiple concurrent requests from each loading the 260 MB
    DistilBERT model simultaneously, which would cause OOM errors.
    """
    global _classifier, _classifier_load_attempted
    with _classifier_lock:
        if _classifier is None and not _classifier_load_attempted:
            _classifier_load_attempted = True
            try:
                from transformers import pipeline
                _classifier = pipeline(
                    "zero-shot-classification",
                    model="typeform/distilbert-base-uncased-mnli",
                )
                logger.info("NLP classifier loaded successfully.")
            except Exception as e:
                logger.warning("Failed to load transformers pipeline: %s", e)
    return _classifier


# Expose CLASSIFIER_AVAILABLE so health endpoint can report it
def is_classifier_available() -> bool:
    """Returns True if the NLP classifier loaded without error."""
    return _classifier is not None


# ---------------------------------------------------------------------------
# Known Domain Lists
# ---------------------------------------------------------------------------

# Common URL shorteners used to hide malicious destinations
URL_SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "short.link",
    "buff.ly", "rebrand.ly", "cutt.ly", "is.gd", "v.gd", "shorturl.at",
]

# Expanded domain list with major Indian banks, government portals, and global brands
KNOWN_LEGITIMATE_DOMAINS = [
    # Indian Banks
    "sbi.co.in", "onlinesbi.sbi", "bankofindia.co.in", "bankofbaroda.in",
    "hdfcbank.com", "icicibank.com", "axisbank.com", "pnbindia.in",
    "kotakbank.com", "unionbankofindia.co.in", "canarabank.com",
    "indianbank.in", "centralbankofindia.co.in", "idfcfirstbank.com",
    "yesbank.in", "indusind.com", "rblbank.com", "federalbank.co.in",
    # Indian Government
    "irctc.co.in", "incometax.gov.in", "uidai.gov.in", "epfindia.gov.in",
    "india.gov.in", "mca.gov.in", "nsdl.co.in", "cibil.com", "passportindia.gov.in",
    # Payment & Wallets
    "paytm.com", "phonepe.com", "gpay.in", "bhimupi.org.in", "razorpay.com",
    # Global
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com",
    "paypal.com", "microsoft.com", "apple.com", "amazon.com",
    "google.com", "linkedin.com", "facebook.com", "twitter.com",
]

# Credential harvesting keywords — any 2+ of these together is suspicious
HARVESTING_KEYWORDS = [
    "password", "otp", "pin", "cvv", "card number",
    "verify", "confirm", "update your", "enter your",
    "login", "sign in", "account details", "bank details",
    "click here to verify", "validate your", "authenticate",
]


# ---------------------------------------------------------------------------
# Domain Checks
# ---------------------------------------------------------------------------

def check_homoglyph(domain: str) -> dict:
    try:
        if "xn--" in domain.lower():
            return {
                "visible_domain": domain,
                "decoded_ascii": domain.lower(),
                "suspicious": True,
            }
        ascii_form = idna.encode(domain).decode("ascii")
        is_punycode = ascii_form.startswith("xn--")
        return {
            "visible_domain": domain,
            "decoded_ascii": ascii_form,
            "suspicious": is_punycode,
        }
    except idna.IDNAError:
        return {"visible_domain": domain, "decoded_ascii": domain, "suspicious": False}


def _extract_sld(domain: str) -> str:
    """
    Extracts the second-level domain (SLD) from a full domain/hostname for comparison.
    Uses a simple public suffix heuristic:
      - 'mail.hdfcbank.com'  -> 'hdfcbank'
      - 'hdfcbank.co.in'     -> 'hdfcbank'
      - 'hdfcbonk.com'       -> 'hdfcbonk'
    Falls back to first label if pattern is not matched.
    """
    try:
        import tldextract
        return tldextract.extract(domain).domain.lower()
    except ImportError:
        pass
    # Fallback: strip www, take second-to-last label if multi-part TLD
    labels = domain.lower().lstrip("www.").split(".")
    if len(labels) >= 2:
        # Handle two-part TLDs like co.in, com.au, org.uk
        if labels[-1] in ("in", "uk", "au", "br", "jp") and len(labels) >= 3:
            return labels[-3]
        return labels[-2]
    return labels[0] if labels else domain


def check_lookalike(domain: str) -> list:
    """
    Levenshtein-distance lookalike check using SLD-only comparison.
    This catches TLD swaps: hdfcbank.co.in vs hdfcbank.com (same SLD).
    Also catches suffix injection: hdfcbank-secure.com vs hdfcbank.com.
    Guard: domains shorter than 6 chars produce too many false positives.
    """
    matches = []
    base_domain = domain.lower()
    if base_domain.startswith("www."):
        base_domain = base_domain[4:]

    # Min-length guard — very short domains match everything
    if len(base_domain) < 6:
        return []

    sld_input = _extract_sld(base_domain)

    for legit in KNOWN_LEGITIMATE_DOMAINS:
        if base_domain == legit:
            continue  # Exact match is not a lookalike

        sld_legit = _extract_sld(legit)

        # 1. Levenshtein on SLD only (catches typos AND TLD swaps)
        if sld_input != sld_legit and 0 < Levenshtein.distance(sld_input, sld_legit) <= 2:
            matches.append(legit)
            continue

        # 2. Brand-as-substring check: if a known brand SLD is entirely contained
        #    within the input SLD (e.g. 'hdfcbank' in 'hdfcbank-secure'), it’s a lookalike.
        if (
            len(sld_legit) >= 5  # avoid short noise like 'sbi'
            and sld_legit in sld_input
            and sld_input != sld_legit
        ):
            matches.append(legit)

    return list(set(matches))


# ---------------------------------------------------------------------------
# QR Code Extraction
# ---------------------------------------------------------------------------

def extract_qr_urls(image_bytes: bytes) -> list:
    if not PYZBAR_AVAILABLE or decode is None:
        return []
    try:
        image = Image.open(io.BytesIO(image_bytes))
        decoded_objects = decode(image)
        urls = [
            obj.data.decode("utf-8")
            for obj in decoded_objects
            if obj.type == "QRCODE"
        ]
        return urls
    except Exception as e:
        logger.warning("Error decoding QR: %s", e)
        return []


# ---------------------------------------------------------------------------
# Text / URL Utilities
# ---------------------------------------------------------------------------

def extract_text_and_links(html_content: str) -> tuple:
    soup = BeautifulSoup(html_content, "html.parser")
    text = soup.get_text(separator=" ", strip=True)
    links = [a.get("href") for a in soup.find_all("a", href=True)]
    return text, links


def extract_urls_from_text(text: str) -> list:
    return re.findall(
        r"http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+",
        text,
    )


def detect_url_shorteners(links: list) -> list:
    """
    Returns deduplicated list of shortener domains found in links.
    Uses a set to avoid reporting the same shortener multiple times.
    """
    found = set()
    for link in links:
        try:
            domain = link.split("//")[-1].split("/")[0].split(":")[0].lower()
            if domain in URL_SHORTENERS:
                found.add(domain)
        except Exception:
            pass
    return list(found)


def detect_credential_harvesting(text: str) -> bool:
    """
    Detects credential-harvesting intent using REGEX PHRASE PAIRS that require
    a credential term AND an action term within the same sentence/clause.
    This avoids false positives like "You do NOT need to enter your password".

    Patterns: <action> ... <credential> within 80 chars of each other.
    Threshold: 2 or more distinct phrase patterns matched -> suspicious.
    """
    text_lower = text.lower()

    # Regex phrase patterns: must match action + credential in context
    HARVEST_PATTERNS = [
        r"(enter|provide|submit|type|input|share)\b.{0,80}\b(password|otp|pin|cvv|card number)",
        r"(verify|confirm|validate|authenticate)\b.{0,80}\b(account|identity|detail|credential)",
        r"(click|tap)\b.{0,80}\b(verify|confirm|login|sign.?in|authenticate)",
        r"(login|sign.?in)\b.{0,80}\b(to (access|continue|update|confirm))",
        r"(account|banking|card)\b.{0,80}\b(suspend|block|expi|terminat)",
        r"(update|re-?enter|re-?verify)\b.{0,80}\b(detail|info|credential|data)",
    ]

    matched = sum(
        1 for pattern in HARVEST_PATTERNS
        if re.search(pattern, text_lower, re.DOTALL)
    )
    return matched >= 2


# ---------------------------------------------------------------------------
# Email Payload Extraction
# ---------------------------------------------------------------------------

def extract_email_payloads(raw_or_msg):
    """
    Extracts plain text body, HTML body, and image bytes from an RFC 2822
    email message or raw bytes.

    Captures BOTH multipart attachments AND inline base64-encoded images
    embedded in HTML bodies (common in quishing attacks).
    """
    if isinstance(raw_or_msg, (bytes, bytearray)):
        msg = email.message_from_bytes(bytes(raw_or_msg))
    elif isinstance(raw_or_msg, email.message.Message):
        msg = raw_or_msg
    else:
        return str(raw_or_msg or ""), "", []

    body_text = ""
    html_body = ""
    attached_images = []

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition", ""))
            if content_type == "text/plain" and "attachment" not in content_disposition:
                payload = part.get_payload(decode=True)
                if payload:
                    charset = part.get_content_charset() or "utf-8"
                    body_text += payload.decode(charset, errors="replace") + "\n"
            elif content_type == "text/html" and "attachment" not in content_disposition:
                payload = part.get_payload(decode=True)
                if payload:
                    charset = part.get_content_charset() or "utf-8"
                    html_body += payload.decode(charset, errors="replace") + "\n"
            elif content_type.startswith("image/"):
                img_data = part.get_payload(decode=True)
                if img_data:
                    attached_images.append(img_data)
    else:
        content_type = msg.get_content_type()
        payload = msg.get_payload(decode=True)
        if payload:
            charset = msg.get_content_charset() or "utf-8"
            decoded = payload.decode(charset, errors="replace")
            if content_type == "text/html":
                html_body = decoded
            else:
                body_text = decoded

    # Extract inline base64 images from HTML body
    # Quishing attacks often embed QR codes as <img src="data:image/png;base64,...">
    # These are NOT multipart attachments and would be missed by the loop above.
    if html_body:
        soup = BeautifulSoup(html_body, "html.parser")
        for img_tag in soup.find_all("img", src=True):
            src = img_tag["src"]
            if src.startswith("data:image/") and ";base64," in src:
                try:
                    b64_data = src.split(";base64,", 1)[1]
                    img_bytes = base64.b64decode(b64_data)
                    if len(img_bytes) > 100:  # Skip trivially small images
                        attached_images.append(img_bytes)
                        logger.debug("Extracted inline base64 image (%d bytes) for QR scanning", len(img_bytes))
                except Exception as e:
                    logger.debug("Could not decode inline base64 image: %s", e)

    return body_text, html_body, attached_images


# ---------------------------------------------------------------------------
# Module 2 Orchestrator
# ---------------------------------------------------------------------------

def analyze_content(
    body_text,
    html_body: str = "",
    attached_images: list = None,
    display_name_mismatch: bool = False,
) -> dict:
    # If raw bytes or an email.message.Message is passed as the first parameter
    if isinstance(body_text, (bytes, bytearray, email.message.Message)):
        body_text, html_body, attached_images = extract_email_payloads(body_text)

    attached_images = attached_images or []

    # 1. HTML Parsing
    if html_body:
        html_text, links = extract_text_and_links(html_body)
        full_text = (body_text or "") + " " + html_text
        if body_text:
            links = list(set(links + extract_urls_from_text(body_text)))
    else:
        full_text = body_text or ""
        links = extract_urls_from_text(full_text)

    domains_to_check = set()
    for link in links:
        try:
            domain = link.split("//")[-1].split("/")[0].split(":")[0]
            if domain:
                domains_to_check.add(domain)
        except Exception:
            pass

    # 2. Check Domains for Lookalike + Homoglyph
    lookalikes_found = set()
    homoglyphs_found = []

    for domain in domains_to_check:
        for la in check_lookalike(domain):
            lookalikes_found.add(la)

        homoglyph_result = check_homoglyph(domain)
        if homoglyph_result["suspicious"]:
            homoglyphs_found.append(homoglyph_result)

    # 3. Check QR Codes
    qr_results = []
    for img_bytes in attached_images:
        qr_urls = extract_qr_urls(img_bytes)
        for url in qr_urls:
            try:
                qr_domain = url.split("//")[-1].split("/")[0].split(":")[0]
                is_lookalike = len(check_lookalike(qr_domain)) > 0
                is_homoglyph = check_homoglyph(qr_domain)["suspicious"]
                qr_results.append({
                    "decoded_url": url,
                    "lookalike_check": is_lookalike,
                    "reputation_flag": is_lookalike or is_homoglyph,
                })
            except Exception:
                pass

    # 4. NLP Analysis (Urgency and Impersonation)
    urgency_score = 0.0
    impersonation_score = 0.0

    # Keyword baseline fallback
    urgent_keywords = [
        "urgent", "immediate", "suspend", "closure", "verify now",
        "action required", "account blocked", "final warning", "last chance",
    ]
    impersonation_keywords = [
        "dear user", "dear customer", "account suspended",
        "security alert", "verify your account", "your account has been",
    ]

    if any(k in full_text.lower() for k in urgent_keywords):
        urgency_score = 0.5

    if any(k in full_text.lower() for k in impersonation_keywords):
        impersonation_score = 0.5

    classifier = _get_classifier()
    # Extend NLP window: first 3072 + last 1024 chars to catch buried phishing CTAs
    if classifier and full_text.strip():
        if len(full_text) > 4096:
            text_to_classify = full_text[:3072] + " " + full_text[-1024:]
        else:
            text_to_classify = full_text
        try:
            u_res = classifier(
                text_to_classify,
                candidate_labels=["urgent threat", "normal message"],
            )
            if u_res["labels"][0] == "urgent threat":
                urgency_score = max(urgency_score, u_res["scores"][0])

            i_res = classifier(
                text_to_classify,
                candidate_labels=["identity theft or phishing attempt", "normal conversation"],
            )
            if i_res["labels"][0] == "identity theft or phishing attempt":
                impersonation_score = max(impersonation_score, i_res["scores"][0])
        except Exception as e:
            logger.warning("Classification error: %s", e)

    shorteners_found = detect_url_shorteners(links)

    return {
        "urgency_score": round(urgency_score, 2),
        "impersonation_score": round(impersonation_score, 2),
        "display_name_mismatch": display_name_mismatch,
        "lookalike_domains_found": list(lookalikes_found),
        "homoglyph_domains_found": homoglyphs_found,
        "qr_codes_found": qr_results,
        "url_shorteners_found": shorteners_found,
        "credential_harvesting_detected": detect_credential_harvesting(full_text),
    }
