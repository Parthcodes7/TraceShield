"""
TraceShield — Module 7: Adversarial Self-Red-Teaming
Evaluates TraceShield's detection engine against AI-crafted evasion attacks.

Simulates advanced persistent threat (APT) attacks that evade standard NLP
and keyword-based filters through:
  1. Low-urgency, calm corporate phrasing (evading urgency NLP).
  2. Typo-tolerant lookalike domains and IDN Homoglyph domains (bypassing visual review).
  3. Disguised routing (Reply-To manipulation, shortened URLs, or quishing).

Provides both zero-dependency offline evasion generation and optional live LLM
synthesis (Gemini / Claude / OpenAI) if environment credentials are present.
"""

import os
import re
import logging
from typing import Dict, Any, Callable, Optional, Union
from pydantic import BaseModel

logger = logging.getLogger("traceshield.adversarial")


class AdversarialTestModel(BaseModel):
    tested: bool = False
    generated_sample_caught: bool = False
    notes: str = ""

# ---------------------------------------------------------------------------
# Procedural Adversarial Evasion Templates (Offline / Zero-Dependency)
# ---------------------------------------------------------------------------

ADVERSARIAL_TEMPLATES = {
    "business_routine": """Received: from mail-relay.corporate-network.com (mail-relay.corporate-network.com. [198.51.100.24])
        by mx.recipient-domain.com with ESMTPS id b92si7101239qkc.44.2026.09.06.10.15.00
        for <finance-audit@company.org>;
        Sun, 06 Sep 2026 10:15:00 -0400
From: "Vendor Financial Accounts" <billing@hdfc-vendorportal.co.in>
To: finance-audit@company.org
Reply-To: remittance-drop@anonymous-mail.org
Subject: Q3 Supplier Statement & Remittance Advice Reconciliation
Date: Sun, 06 Sep 2026 10:14:45 -0400
Message-ID: <stmt-20260906-881923@corporate-network.com>
MIME-Version: 1.0
Content-Type: text/html; charset="utf-8"

<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
  <p>Good morning,</p>
  <p>Attached for your convenience is the routine reconciled statement for services rendered through the conclusion of August 2026.</p>
  <p>Please cross-reference the line-item balance against your general ledger records when convenient before the month-end closing cycle.</p>
  <p>You may view the updated digital ledger breakdown and payment clearing status at our corporate portal:</p>
  <p><a href="http://hdfcbank-corporate.co.in/invoices/view?id=992812">https://hdfcbank.com/reconciliation/q3-audit</a></p>
  <p>Kind regards,<br>
  <strong>Corporate Accounts Department</strong><br>
  Commercial Banking & Vendor Settlement Division</p>
</body>
</html>
""",
    "it_compliance": """Received: from sso-dispatch.cloud-corp.net (sso-dispatch.cloud-corp.net. [203.0.113.88])
        by mx.company.com with ESMTPS id c44si1028394qkc.12.2026.09.06.11.20.00
        for <all-staff@company.com>;
        Sun, 06 Sep 2026 11:20:00 -0400
From: "IT Operations & Cloud Identity" <no-reply@microsoft-sso-portal.com>
To: all-staff@company.com
Subject: Scheduled Cloud Identity Certificate Maintenance (Reference #IT-88410)
Date: Sun, 06 Sep 2026 11:19:30 -0400
Message-ID: <it-maintenance-88410@cloud-corp.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"

Hello Team,

In accordance with our quarterly IT infrastructure lifecycle maintenance, the unified sign-on security certificates for remote workplace applications will undergo standard rotation over the upcoming weekend.

Most users will experience uninterrupted access. However, if your workstation utilizes legacy desktop synchronization, please review the device certificate registry status at your earliest convenience:

http://micrоsoft.com/devices/cert-sync

This will ensure your local credentials remain aligned with standard enterprise directory policy.

Best regards,
Enterprise Identity & Access Management Team
Global Technical Support Services
""",
    "quishing_statement": """Received: from hr-portal.benefits-secure.net (hr-portal.benefits-secure.net. [198.51.100.99])
        by mx.company.com with ESMTPS id q81si9918231qkc.08.2026.09.06.09.45.00
        for <employee-records@company.com>;
        Sun, 06 Sep 2026 09:45:00 -0400
From: "Employee Provident Fund & HR Benefits" <epfo-services@epf0.gov.in>
To: employee-records@company.com
Subject: Annual Benefits Statement & Universal Account Number (UAN) Summary
Date: Sun, 06 Sep 2026 09:44:12 -0400
Message-ID: <uan-summary-20260906@benefits-secure.net>
MIME-Version: 1.0
Content-Type: text/html; charset="utf-8"

<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family: sans-serif; color: #222;">
  <p>Dear Colleague,</p>
  <p>Your updated annual Provident Fund balance and tax exemption credit summary for the financial year is now available for review.</p>
  <p>To access the confidential statement from a personal mobile device, please scan the encrypted access code below using your mobile camera:</p>
  <p><a href="http://epfindia-portal.co.in/uan/login">Access Employee Portal</a></p>
  <p>Thank you,<br>HR Compensation & Benefits Administration</p>
</body>
</html>
""",

    # Strategy 4: Executive whaling — calm CEO impersonation with plausible display name.
    # Detection vectors: display name spoof, Reply-To redirect, short relay chain.
    "executive_whaling": """Received: from webmail.corp-gateway.net (webmail.corp-gateway.net. [203.0.113.56])
        by mx.targetcompany.com with ESMTPS id w21si4401283qkc.01.2026.09.06.14.30.00
        for <cfo@targetcompany.com>;
        Sun, 06 Sep 2026 14:30:00 -0400
From: "Rajesh Mehta, CEO" <rajesh.mehta@targetcompany.com.ceo-office.net>
To: cfo@targetcompany.com
Reply-To: rajesh-secure@protonmail.com
Subject: Discreet Wire Transfer — Board-Approved Acquisition
Date: Sun, 06 Sep 2026 14:29:45 -0400
Message-ID: <boardm-20260906-0024@corp-gateway.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"

Hi,

I am currently in a board-level strategy session and require your discreet assistance with a time-sensitive matter.

We are finalising a confidential pre-IPO acquisition. The legal team has cleared a one-time wire transfer of INR 2.4 crore to an escrow account. The transfer must be initiated before market opening to avoid regulatory disclosure.

Please treat this as strictly confidential. Do not discuss with other staff. I will call you after the session to confirm receipt.

Reply to this email directly with confirmation of availability.

Regards,
Rajesh Mehta
Chief Executive Officer
""",

    # Strategy 5: Invoice fraud — realistic vendor payment with subtle lookalike domain.
    # Detection vectors: lookalike domain (hdfcbank.com vs hdfcbonk.com style), credential harvesting.
    "invoice_fraud": """Received: from mail.invoicepay-gateway.net (mail.invoicepay-gateway.net. [198.51.100.75])
        by mx.company.com with ESMTPS id p55si2201123qkc.07.2026.09.06.08.00.00
        for <accounts@company.com>;
        Sun, 06 Sep 2026 08:00:00 -0400
From: "HDFC Bank Corporate Payments" <noreply@hdfcbank-corp.in>
To: accounts@company.com
Subject: Payment Confirmation Required — Reference #INV-2026-08-9921
Date: Sun, 06 Sep 2026 07:59:30 -0400
Message-ID: <inv9921-20260906@invoicepay-gateway.net>
MIME-Version: 1.0
Content-Type: text/html; charset="utf-8"

<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family: Arial, sans-serif; color: #1a1a1a; line-height: 1.5;">
  <p>Dear Valued Customer,</p>
  <p>A payment of <strong>INR 8,40,000</strong> against Invoice #INV-2026-08-9921 requires your authorisation before processing.</p>
  <p>Please log in to your HDFC NetBanking portal to review and authorise this transaction:</p>
  <p><a href="http://hdfcbank-netbanking.co.in/auth/confirm?ref=INV9921">Authorise Payment &rarr;</a></p>
  <p>If you did not initiate this request, please contact your Relationship Manager immediately.</p>
  <p>Regards,<br>
  <strong>HDFC Bank Corporate Payments Team</strong></p>
</body>
</html>
""",
}


# ---------------------------------------------------------------------------
# LLM Generation (Optional Live API)
# ---------------------------------------------------------------------------

def _generate_with_llm(prompt: str) -> Optional[str]:
    """Attempts to synthesize an adversarial sample using any configured LLM API."""
    # 1. Google Gemini API
    gemini_key = os.environ.get("GEMINI_API_KEY")
    if gemini_key:
        try:
            from google import genai
            client = genai.Client(api_key=gemini_key)
            response = client.models.generate_content(
                model="gemini-2.5-flash",
                contents=prompt,
            )
            if response and response.text:
                logger.info("Generated adversarial sample via Gemini API")
                return response.text.strip()
        except Exception as e:
            logger.warning("Gemini generation failed, falling back: %s", e)

    # 2. Anthropic Claude API
    anthropic_key = os.environ.get("ANTHROPIC_API_KEY")
    if anthropic_key:
        try:
            import anthropic
            client = anthropic.Anthropic(api_key=anthropic_key)
            msg = client.messages.create(
                model="claude-3-5-sonnet-20241022",
                max_tokens=1000,
                messages=[{"role": "user", "content": prompt}],
            )
            if msg and msg.content:
                logger.info("Generated adversarial sample via Anthropic Claude")
                return msg.content[0].text.strip()
        except Exception as e:
            logger.warning("Anthropic generation failed, falling back: %s", e)

    # 3. OpenAI API
    openai_key = os.environ.get("OPENAI_API_KEY")
    if openai_key:
        try:
            from openai import OpenAI
            client = OpenAI(api_key=openai_key)
            completion = client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[{"role": "user", "content": prompt}],
                max_tokens=1000,
            )
            if completion.choices:
                logger.info("Generated adversarial sample via OpenAI API")
                return completion.choices[0].message.content.strip()
        except Exception as e:
            logger.warning("OpenAI generation failed, falling back: %s", e)

    return None


# ---------------------------------------------------------------------------
# Main Public Interface
# ---------------------------------------------------------------------------

def generate_adversarial_sample(
    strategy: str = "business_routine",
    custom_prompt: Optional[str] = None,
) -> str:
    """
    Generates an adversarial email sample engineered to evade standard NLP filters.
    
    Strategies:
      - 'business_routine': Routine invoice reconciliation with lookalike domain & reply-to mismatch.
      - 'it_compliance': Calm IT policy maintenance with Cyrillic IDN homoglyphs.
      - 'quishing_statement': Employee benefits portal using typosquatted government agency domain.
    """
    if custom_prompt or (os.environ.get("GEMINI_API_KEY") or os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("OPENAI_API_KEY")):
        system_prompt = (
            custom_prompt or
            """Write a realistic RFC 2822 email designed to test a forensic email security filter.
Requirements:
1. Avoid urgent or alarming words like 'URGENT', 'SUSPENDED', 'IMMEDIATE', 'ACT NOW'.
2. Tone must be calm, polite, and sound like routine business correspondence.
3. Include standard headers (Received, From, To, Subject, Date, Message-ID).
4. Embed a deceptive technical vector (e.g., a subtle lookalike domain or mismatched Reply-To).
Return ONLY the raw email text (headers + body) with no markdown fences.
"""
        )
        llm_sample = _generate_with_llm(system_prompt)
        if llm_sample:
            # Strip any accidental ``` markdown code blocks returned by LLMs
            cleaned = re.sub(r"^```[a-zA-Z]*\n", "", llm_sample)
            cleaned = re.sub(r"\n```$", "", cleaned)
            return cleaned.strip()

    # Fallback to high-fidelity built-in templates
    return ADVERSARIAL_TEMPLATES.get(strategy, ADVERSARIAL_TEMPLATES["business_routine"]).strip()


def run_self_test(
    sample_email: Union[str, bytes],
    pipeline_func: Callable[[bytes], Any],
    strategy_name: str = "custom",
) -> Dict[str, Any]:
    """
    Executes an adversarial email against TraceShield's complete forensic pipeline.
    
    Evaluates whether multi-layer defense mechanisms caught the attack even when
    linguistic/NLP urgency was intentionally minimized.
    """
    raw_bytes = sample_email.encode("utf-8", errors="replace") if isinstance(sample_email, str) else sample_email

    record = pipeline_func(raw_bytes)

    risk_score = record.scoring.final_risk_score if record.scoring else 0
    risk_tier = record.scoring.risk_tier if record.scoring else "Low"
    confidence_level = record.scoring.confidence_level if record.scoring else "Unknown"

    # Threat is considered caught if:
    #   a) Risk tier is Medium or High (broad heuristic threshold), OR
    #   b) Score >= 35 (numeric floor), OR
    #   c) Confidence is "High Confidence" AND score > 20 (protocol-verified finding
    #      — catches sophisticated phishing that passes auth but has hard technical signals)
    is_caught = (
        (risk_tier in ["Medium", "High"])
        or (risk_score >= 35)
        or (confidence_level == "High Confidence" and risk_score > 20)
    )

    # Compile plain-English forensic red-teaming notes
    detected_layers = []
    if record.header_forensics:
        if record.header_forensics.reply_to_mismatch:
            detected_layers.append("Reply-To Mismatch")
        if record.header_forensics.display_name_spoof:
            detected_layers.append("Display Name Spoof")
        if record.header_forensics.spf_result in ["fail", "softfail"]:
            detected_layers.append(f"SPF {record.header_forensics.spf_result.upper()}")
        if record.header_forensics.dkim_result == "fail":
            detected_layers.append("DKIM Signature Fail")

    if record.content_analysis:
        if record.content_analysis.lookalike_domains_found:
            detected_layers.append(f"Lookalike Domain ({', '.join(record.content_analysis.lookalike_domains_found)})")
        if any(h.suspicious for h in record.content_analysis.homoglyph_domains_found):
            detected_layers.append("Unicode IDN Homoglyph")
        if record.content_analysis.url_shorteners_found:
            detected_layers.append("Cloaked Shortener URL")

    if record.geolocation and record.geolocation.is_known_vpn_or_hosting:
        detected_layers.append("Hosting/VPN Infrastructure IP")

    if is_caught:
        if detected_layers:
            notes = (
                f"Adversarial evasion defeated: Language-level evasion was neutralized by technical "
                f"forensic layers: {', '.join(detected_layers)}. Scored {risk_score}/100 ({risk_tier} Risk, {confidence_level})."
            )
        else:
            notes = (
                f"Adversarial evasion caught: Scored {risk_score}/100 ({risk_tier} Risk) based on "
                f"aggregated heuristic and multi-factor scoring."
            )
    else:
        notes = (
            f"Adversarial evasion evaded high-tier flagging (Score {risk_score}/100, {risk_tier} Risk). "
            f"Demonstrates the importance of Calibrated Confidence: flagged with '{confidence_level}' "
            f"requiring human SOC analyst review rather than silent pass-through."
        )

    # Attach result back to record if model supports it
    if hasattr(record, "adversarial_test"):
        record.adversarial_test = AdversarialTestModel(
            tested=True,
            generated_sample_caught=is_caught,
            notes=notes,
        )

    logger.info("Adversarial self-test completed: strategy=%s, caught=%s, score=%d", strategy_name, is_caught, risk_score)

    return {
        "tested": True,
        "strategy": strategy_name,
        "generated_sample_caught": is_caught,
        "final_risk_score": risk_score,
        "risk_tier": risk_tier,
        "confidence_level": confidence_level,
        "detected_layers": detected_layers,
        "notes": notes,
        "record": record,
    }
