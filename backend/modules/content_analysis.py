import io
import re
import idna
import Levenshtein
from bs4 import BeautifulSoup
from pyzbar.pyzbar import decode
from PIL import Image

# Lazy load transformers to avoid blocking startup
classifier = None

# Common URL shorteners used to hide malicious destinations
URL_SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "short.link",
    "buff.ly", "rebrand.ly", "cutt.ly", "is.gd", "v.gd", "shorturl.at"
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

# Credential harvesting keywords — any combination of these is suspicious
HARVESTING_KEYWORDS = [
    "password", "otp", "pin", "cvv", "card number",
    "verify", "confirm", "update your", "enter your",
    "login", "sign in", "account details", "bank details",
    "click here to verify", "validate your", "authenticate"
]

def _init_classifier():
    global classifier
    if classifier is None:
        try:
            from transformers import pipeline
            classifier = pipeline("zero-shot-classification", model="typeform/distilbert-base-uncased-mnli")
        except Exception as e:
            print(f"Failed to load transformers pipeline: {e}")

def check_homoglyph(domain: str) -> dict:
    try:
        if "xn--" in domain.lower():
            return {
                "visible_domain": domain,
                "decoded_ascii": domain.lower(),
                "suspicious": True
            }
        ascii_form = idna.encode(domain).decode("ascii")
        is_punycode = ascii_form.startswith("xn--")
        return {
            "visible_domain": domain,
            "decoded_ascii": ascii_form,
            "suspicious": is_punycode
        }
    except idna.IDNAError:
        return {"visible_domain": domain, "decoded_ascii": domain, "suspicious": False}

def check_lookalike(domain: str) -> list:
    matches = []
    base_domain = domain.lower()
    if base_domain.startswith("www."):
        base_domain = base_domain[4:]

    for legit in KNOWN_LEGITIMATE_DOMAINS:
        if base_domain == legit:
            continue
        distance = Levenshtein.distance(base_domain, legit)
        if 0 < distance <= 2:
            matches.append(legit)
    return matches

def extract_qr_urls(image_bytes: bytes) -> list:
    try:
        image = Image.open(io.BytesIO(image_bytes))
        decoded_objects = decode(image)
        urls = [obj.data.decode("utf-8") for obj in decoded_objects if obj.type == "QRCODE"]
        return urls
    except Exception as e:
        print(f"Error decoding QR: {e}")
        return []

def extract_text_and_links(html_content: str) -> tuple:
    soup = BeautifulSoup(html_content, "html.parser")
    text = soup.get_text(separator=' ', strip=True)
    links = [a.get('href') for a in soup.find_all('a', href=True)]
    return text, links

def extract_urls_from_text(text: str) -> list:
    return re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', text)

def detect_url_shorteners(links: list) -> list:
    """Returns list of shortener domains found in links."""
    found = []
    for link in links:
        try:
            domain = link.split('//')[-1].split('/')[0].split(':')[0].lower()
            if domain in URL_SHORTENERS:
                found.append(domain)
        except:
            pass
    return found

def detect_credential_harvesting(text: str) -> bool:
    """
    Improved: checks for combinations of credential-harvesting keyword pairs,
    not just a single pair. More keyword combinations = higher confidence.
    """
    text_lower = text.lower()
    matches = sum(1 for kw in HARVESTING_KEYWORDS if kw in text_lower)
    # If 2 or more harvesting keywords appear together, it's suspicious
    return matches >= 2

def analyze_content(body_text: str, html_body: str = "", attached_images: list = [], display_name_mismatch: bool = False) -> dict:
    # 1. HTML Parsing
    if html_body:
        html_text, links = extract_text_and_links(html_body)
        full_text = body_text + " " + html_text
    else:
        full_text = body_text
        links = extract_urls_from_text(body_text)

    domains_to_check = set()
    for link in links:
        try:
            domain = link.split('//')[-1].split('/')[0].split(':')[0]
            if domain:
                domains_to_check.add(domain)
        except:
            pass

    # 2. Check Domains for Lookalike + Homoglyph
    lookalikes_found = set()
    homoglyphs_found = []

    for domain in domains_to_check:
        lookalikes = check_lookalike(domain)
        for la in lookalikes:
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
                qr_domain = url.split('//')[-1].split('/')[0].split(':')[0]
                is_lookalike = len(check_lookalike(qr_domain)) > 0
                is_homoglyph = check_homoglyph(qr_domain)["suspicious"]

                qr_results.append({
                    "decoded_url": url,
                    "lookalike_check": is_lookalike,
                    "reputation_flag": is_lookalike or is_homoglyph
                })
            except:
                pass

    # 4. NLP Analysis (Urgency and Impersonation)
    urgency_score = 0.0
    impersonation_score = 0.0

    # Keyword baseline fallback
    urgent_keywords = ["urgent", "immediate", "suspend", "closure", "verify now",
                       "action required", "account blocked", "final warning", "last chance"]
    impersonation_keywords = ["dear user", "dear customer", "account suspended",
                              "security alert", "verify your account", "your account has been"]

    if any(k in full_text.lower() for k in urgent_keywords):
        urgency_score = 0.5

    if any(k in full_text.lower() for k in impersonation_keywords):
        impersonation_score = 0.5

    _init_classifier()
    if classifier and full_text.strip():
        text_to_classify = full_text[:1000]
        try:
            u_res = classifier(text_to_classify, candidate_labels=["urgent threat", "normal message"])
            if u_res['labels'][0] == 'urgent threat':
                urgency_score = max(urgency_score, u_res['scores'][0])

            i_res = classifier(text_to_classify, candidate_labels=["identity theft or phishing attempt", "normal conversation"])
            if i_res['labels'][0] == 'identity theft or phishing attempt':
                impersonation_score = max(impersonation_score, i_res['scores'][0])
        except Exception as e:
            print(f"Classification error: {e}")

    shorteners_found = detect_url_shorteners(links)

    return {
        "urgency_score": round(urgency_score, 2),
        "impersonation_score": round(impersonation_score, 2),
        "display_name_mismatch": display_name_mismatch,  # Correctly passed in from Module 1
        "lookalike_domains_found": list(lookalikes_found),
        "homoglyph_domains_found": homoglyphs_found,
        "qr_codes_found": qr_results,
        "url_shorteners_found": shorteners_found,         # New: shortener detection
        "credential_harvesting_detected": detect_credential_harvesting(full_text)
    }
