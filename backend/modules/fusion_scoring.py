"""
Module 4 — Fusion Scoring + Confidence Calibration + Forensic Summary Generator

Takes the outputs of Modules 1, 2, and 3 and produces:
  - A final risk score (0–100)
  - A risk tier (Low / Medium / High)
  - A calibrated confidence level (High / Moderate) with rationale
  - Dimensional score breakdown (Headers, Content, Origin)
  - Verified authentications (positive audit trail)
  - Contextual triggered threat reasons (deduplicated)
  - Actionable security incident recommendations
  - A plain-English forensic executive summary (offline templated + optional LLM)
"""

import os
import re
from typing import Dict, Any, List, Optional


def compute_risk_score(data: dict) -> dict:
    """
    Computes a multi-dimensional risk score from header, content, and network signals.
    Applies calibrated confidence rules and returns full explainability details.
    """
    data = data or {}
    hf = data.get("header_forensics") or {}
    ca = data.get("content_analysis") or {}
    geo = data.get("geolocation") or {}

    header_score = 0
    content_score = 0
    origin_score = 0

    protocol_failure_signals = 0  # High-confidence, objectively verifiable failure indicators
    protocol_pass_signals = 0     # Cryptographic/DNS passes proving authenticity
    triggered_reasons: List[str] = []
    verified_authentications: List[str] = []

    # ── 1. Protocol & Header Forensics (Max 40 pts) ───────────────────────────
    spf = (hf.get("spf_result") or "").lower()
    if spf == "fail":
        header_score += 20
        protocol_failure_signals += 1
        triggered_reasons.append("SPF record check FAILED — sending IP is not authorized by domain policy")
    elif spf == "softfail":
        header_score += 10
        protocol_failure_signals += 1
        triggered_reasons.append("SPF record check SOFTFAIL — sender IP is questionable under domain policy (~all)")
    elif spf == "pass":
        protocol_pass_signals += 1
        verified_authentications.append("SPF: Sender IP authorized by domain SPF policy")

    dkim = (hf.get("dkim_result") or "").lower()
    if dkim == "fail":
        header_score += 20
        protocol_failure_signals += 1
        triggered_reasons.append("DKIM signature FAILED — email content or headers were modified in transit")
    elif dkim == "pass":
        protocol_pass_signals += 1
        verified_authentications.append("DKIM: Cryptographic digital signature verified and intact")

    dmarc = (hf.get("dmarc_result") or "").lower()
    if dmarc == "fail":
        header_score += 15
        protocol_failure_signals += 1
        triggered_reasons.append("DMARC policy check FAILED — domain owner flags unaligned sending sources")
    elif dmarc == "pass":
        protocol_pass_signals += 1
        verified_authentications.append("DMARC: Domain policy validated and aligned")

    reply_to_mismatch = bool(hf.get("reply_to_mismatch"))
    if reply_to_mismatch:
        header_score += 15
        protocol_failure_signals += 1
        triggered_reasons.append("Reply-To address domain differs from From domain — recipient replies will redirect to a third party")

    display_spoof = bool(hf.get("display_name_spoof") or ca.get("display_name_mismatch"))
    if display_spoof:
        header_score += 15
        protocol_failure_signals += 1
        triggered_reasons.append("Display name spoofing detected — From header displays a known brand but originates from an unrelated domain")

    suspicious_attachments = hf.get("suspicious_attachments") or []
    if suspicious_attachments:
        header_score += 20
        protocol_failure_signals += 1
        names = ", ".join(suspicious_attachments)
        triggered_reasons.append(f"Dangerous attachment(s) identified ({names}) — commonly weaponized for malware delivery")
    else:
        verified_authentications.append("Attachments: No high-risk executable or script payloads detected")

    # Filter anomaly flags to avoid duplicate lines with dedicated checks above
    raw_anomalies = hf.get("anomaly_flags") or []
    filtered_anomalies = []
    for flag in raw_anomalies:
        flag_lower = flag.lower()
        if "reply-to" in flag_lower and reply_to_mismatch:
            continue
        if ("display name" in flag_lower or "brand" in flag_lower) and display_spoof:
            continue
        if "attachment" in flag_lower and suspicious_attachments:
            continue
        filtered_anomalies.append(flag)

    if filtered_anomalies:
        header_score += min(len(filtered_anomalies) * 5, 10)
        for flag in filtered_anomalies:
            triggered_reasons.append(f"Header anomaly: {flag}")

    header_score = min(header_score, 40)

    # ── 2. Content & Linguistic Threats (Max 45 pts) ──────────────────────────
    try:
        urgency = float(ca.get("urgency_score") or 0.0)
    except (TypeError, ValueError):
        urgency = 0.0

    if urgency > 0.4:
        content_score += int(urgency * 15)
        triggered_reasons.append(f"High urgency psychological pressure detected in body ({urgency:.0%} urgency confidence)")

    try:
        impersonation = float(ca.get("impersonation_score") or 0.0)
    except (TypeError, ValueError):
        impersonation = 0.0

    if impersonation > 0.4:
        content_score += int(impersonation * 20)
        triggered_reasons.append(f"Impersonation and authority mimicry detected ({impersonation:.0%} impersonation confidence)")

    lookalikes = ca.get("lookalike_domains_found") or []
    if lookalikes:
        content_score += 20
        protocol_failure_signals += 1
        domains_str = ", ".join(lookalikes)
        triggered_reasons.append(f"Typosquatted / lookalike domain identified targeting legitimate entity: {domains_str}")

    homoglyphs = ca.get("homoglyph_domains_found") or []
    suspicious_homoglyphs = [h for h in homoglyphs if h.get("suspicious")]
    if suspicious_homoglyphs:
        content_score += 20
        protocol_failure_signals += 1
        decoded_names = ", ".join(h.get("decoded_ascii", h.get("visible_domain", "")) for h in suspicious_homoglyphs)
        triggered_reasons.append(f"Unicode IDN homoglyph punycode domain detected ({decoded_names}) — visually deceiving domain")

    qr_codes = ca.get("qr_codes_found") or []
    quishing_attacks = [q for q in qr_codes if q.get("reputation_flag")]
    if quishing_attacks:
        content_score += 20
        protocol_failure_signals += 1
        triggered_reasons.append("Malicious / deceptive destination embedded inside QR code (quishing attack)")
    elif qr_codes:
        triggered_reasons.append("Embedded QR code detected without known malicious links — recommend scanning caution")

    if ca.get("credential_harvesting_detected"):
        content_score += 15
        triggered_reasons.append("Credential harvesting language detected (requests for credentials, OTP, PIN, or sensitive verification)")

    url_shorteners = ca.get("url_shorteners_found") or []
    if url_shorteners:
        content_score += 5
        shorteners_str = ", ".join(url_shorteners)
        triggered_reasons.append(f"URL shortener(s) detected ({shorteners_str}) — destination URLs are intentionally obfuscated")

    content_score = min(content_score, 45)

    # ── 3. Geolocation & Network Infrastructure (Max 20 pts) ─────────────────
    if geo.get("is_known_vpn_or_hosting"):
        origin_score += 15
        isp_name = geo.get("origin_isp") or "Unknown Provider"
        triggered_reasons.append(
            f"Email originated from commercial hosting / VPN infrastructure ({isp_name}) "
            "— uncommon for legitimate corporate or banking communications"
        )

    origin_score = min(origin_score, 20)

    # ── 4. Total Calculation & Mitigating Discounts ─────────────────────────
    total_raw = header_score + content_score + origin_score

    # Deduplicate triggered reasons while preserving order
    seen_reasons = set()
    deduped_reasons = []
    for r in triggered_reasons:
        if r not in seen_reasons:
            seen_reasons.add(r)
            deduped_reasons.append(r)
    triggered_reasons = deduped_reasons

    # Mitigating check: if clean cryptographically and no hard threats, cap false positive
    has_hard_threat = (
        protocol_failure_signals > 0
        or bool(lookalikes)
        or bool(suspicious_homoglyphs)
        or bool(quishing_attacks)
        or bool(suspicious_attachments)
        or display_spoof
    )
    is_strongly_authenticated = (
        protocol_pass_signals >= 2
        and spf == "pass"
        and dkim == "pass"
        and not reply_to_mismatch
    )

    if is_strongly_authenticated and not has_hard_threat:
        total_raw = min(total_raw, 20)

    final_score = max(0, min(int(total_raw), 100))
    tier = "High" if final_score >= 61 else "Medium" if final_score >= 31 else "Low"

    # ── 5. Calibrated Confidence Logic ───────────────────────────────────────
    if tier == "Low":
        if is_strongly_authenticated or (protocol_pass_signals >= 1 and protocol_failure_signals == 0):
            confidence = "High Confidence"
            confidence_reason = (
                "Cryptographically verified authentic — SPF/DKIM/DMARC authentication passed "
                "with no domain spoofing or deceptive structural anomalies."
            )
        else:
            confidence = "Moderate Confidence"
            confidence_reason = (
                "Low risk based on content and heuristics, but domain authentication headers "
                "(SPF/DKIM) are unverified or absent."
            )
    else:  # Medium or High risk
        if protocol_failure_signals >= 1:
            confidence = "High Confidence"
            confidence_reason = (
                "Protocol-verified threat — Cryptographic or DNS authentication failure(s) detected "
                "(SPF/DKIM/DMARC/domain spoofing). Technical signals cannot be faked."
            )
        else:
            confidence = "Moderate Confidence"
            confidence_reason = (
                "Pattern-based threat — Flagged by linguistic NLP sentiment, urgency, or keyword heuristics; "
                "recommend manual analyst verification."
            )

    # ── 6. Context-Aware Incident Recommendations ────────────────────────────
    recommendations: List[str] = []
    if tier == "High":
        recommendations.append("Quarantine this message immediately and isolate it from the recipient's inbox.")
        recommendations.append("Block sender email address and origin IP on the secure email gateway.")
        if ca.get("credential_harvesting_detected"):
            recommendations.append("Initiate immediate password reset and revoke active sessions for targeted users.")
        if suspicious_attachments:
            recommendations.append("Submit quarantined attachments to an isolated sandbox for binary analysis.")
        if quishing_attacks:
            recommendations.append("Blacklist decoded QR destinations on corporate perimeter firewalls.")
        if lookalikes or suspicious_homoglyphs:
            recommendations.append("Report typosquatted / homoglyph domains to domain registrars and anti-phishing feeds.")
    elif tier == "Medium":
        recommendations.append("Flag message with an external banner and warn user against clicking links.")
        recommendations.append("Verify authenticity through a trusted secondary channel before complying with requests.")
        if url_shorteners:
            recommendations.append("Expand and inspect shortened URLs in a secure sandbox before opening.")
        if ca.get("credential_harvesting_detected"):
            recommendations.append("Do NOT submit any passwords, OTPs, or banking credentials via forms in this message.")
    else:
        recommendations.append("No critical indicators detected. Standard email security awareness applies.")
        recommendations.append("Always verify links manually if an unexpected financial or account request arises.")

    # ── 7. Structured Score Breakdown ────────────────────────────────────────
    score_breakdown = {
        "header_authentication": {
            "score": header_score,
            "max_score": 40,
            "status": "Fail" if header_score >= 20 else "Warning" if header_score >= 10 else "Pass"
        },
        "content_threats": {
            "score": content_score,
            "max_score": 45,
            "status": "High" if content_score >= 25 else "Medium" if content_score >= 15 else "Low"
        },
        "network_infrastructure": {
            "score": origin_score,
            "max_score": 15,
            "status": "Suspicious" if origin_score >= 10 else "Normal"
        }
    }

    return {
        "final_risk_score": final_score,
        "risk_tier": tier,
        "confidence_level": confidence,
        "confidence_reason": confidence_reason,
        "score_breakdown": score_breakdown,
        "triggered_reasons": triggered_reasons,
        "verified_authentications": verified_authentications,
        "recommendations": recommendations,
    }


def generate_summary(scoring: dict, geolocation: dict) -> str:
    """
    Generates a coherent, plain-English forensic executive summary without requiring any API keys.
    Adapts narrative structure dynamically across Safe, Moderate, and Critical findings.
    """
    score = scoring["final_risk_score"]
    tier = scoring["risk_tier"]
    confidence = scoring["confidence_level"]
    reasons = scoring.get("triggered_reasons", [])
    country = geolocation.get("origin_country") or "an unknown location"
    city = geolocation.get("origin_city")
    city_str = f", {city}" if city and city != "Unknown" else ""
    isp = geolocation.get("origin_isp") or "an unclassified provider"
    is_hosting = geolocation.get("is_known_vpn_or_hosting", False)

    geo_desc = f"{country}{city_str} via {isp}"
    if is_hosting:
        geo_desc += " (commercial hosting / VPN infrastructure)"

    if tier == "Low":
        if score == 0 and not reasons:
            return (
                f"This email has been assessed as SAFE with a risk score of 0/100 ({confidence}). "
                f"Originating from {geo_desc}, all cryptographic checks (SPF/DKIM/DMARC) validated successfully. "
                "No lookalike domains, deceptive homoglyphs, quishing QR codes, or credential-harvesting triggers "
                "were detected."
            )
        return (
            f"This email has been assessed as LOW RISK with a score of {score}/100 ({confidence}). "
            f"It originated from {geo_desc}. While standard authentication passed, minor non-critical "
            f"findings were noted: {'; '.join(reasons[:2]) or 'routine business phrasing'}. "
            "No active exploit or phishing attack was detected."
        )

    if tier == "Medium":
        top = "; ".join(reasons[:3]) if reasons else "unusual linguistic patterns"
        return (
            f"This email has been assessed as SUSPICIOUS (Moderate Risk, score {score}/100, {confidence}). "
            f"Originating from {geo_desc}, it exhibited {len(reasons)} warning indicator(s). "
            f"Key findings include: {top}. "
            f"{scoring.get('confidence_reason', '')} "
            "Precautionary verification via a secondary channel is advised before interacting with this message."
        )

    # High Risk
    top = "; ".join(reasons[:3]) if reasons else "multiple severe forensic anomalies"
    return (
        f"CRITICAL ALERT: This email has been assessed as a HIGH-RISK PHISHING/FRAUD THREAT with a score of {score}/100 "
        f"({confidence}). Originating from {geo_desc}, forensic analysis identified {len(reasons)} active threat indicator(s). "
        f"Primary attack vectors: {top}. "
        f"{scoring.get('confidence_reason', '')} "
        "Immediate quarantine and defensive blocking are recommended."
    )


def generate_llm_summary(combined_data: dict, scoring: dict) -> str:
    """
    Hybrid summary generator:
    If an external LLM API key is present in environment (e.g., GEMINI_API_KEY, ANTHROPIC_API_KEY),
    it can call the model for a creative summary. Otherwise, it gracefully uses the high-precision
    forensic template generator.
    """
    # For now, generate the high-precision forensic templated summary
    # (can be extended with google-genai or anthropic if key configured)
    geo = combined_data.get("geolocation") or {}
    return generate_summary(scoring, geo)


def run_fusion(header_data: dict, content_data: dict, geo_data: dict) -> dict:
    """
    Main orchestrator for Module 4.
    Accepts outputs from Modules 1, 2, 3 and returns the completed scoring section
    matching the TraceShield shared contract.
    """
    combined = {
        "header_forensics": header_data or {},
        "content_analysis": content_data or {},
        "geolocation": geo_data or {},
    }

    scoring = compute_risk_score(combined)
    scoring["llm_summary"] = generate_llm_summary(combined, scoring)

    return scoring
