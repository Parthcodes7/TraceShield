/**
 * TraceShield — Chrome Browser Extension (Manifest V3)
 * Content Script for Gmail in-inbox threat analysis & forensic badging.
 * Conforms to SIH26106 Build Specification.
 */

(function () {
  'use strict';

  const BACKEND_URL = 'http://localhost:8000';
  const FRONTEND_URL = 'http://localhost:5173';
  const SCANNED_ATTR = 'data-traceshield-scanned';
  const analysisCache = new Map();

  console.log('[TraceShield] Gmail Content Script Loaded.');

  /**
   * Builds an RFC 822 email payload from extracted DOM components.
   */
  function buildMimePayload(senderName, senderEmail, subject, bodyText, bodyHtml) {
    const cleanSender = senderEmail || 'unknown@sender.com';
    const cleanName = senderName ? `"${senderName.replace(/"/g, '')}"` : cleanSender;
    const dateStr = new Date().toUTCString();

    const headers = [
      `From: ${cleanName} <${cleanSender}>`,
      `Subject: ${subject || 'No Subject'}`,
      `Date: ${dateStr}`,
      `MIME-Version: 1.0`,
      `Content-Type: text/html; charset=UTF-8`,
      `X-Mailer: TraceShield-Extension-V2`,
      '',
      bodyHtml || bodyText || 'Empty email body'
    ];

    return headers.join('\r\n');
  }

  /**
   * Extracts visible email data from a Gmail email message card container.
   */
  function extractEmailData(messageEl) {
    // 1. Sender
    const senderEl = messageEl.querySelector('.gD') || document.querySelector('.gD');
    const senderEmail = senderEl?.getAttribute('email') || senderEl?.innerText || '';
    const senderName = senderEl?.getAttribute('name') || senderEl?.innerText || '';

    // 2. Subject (thread-level subject)
    const subjectEl =
      document.querySelector('h2.hP') ||
      document.querySelector('.ha h2') ||
      messageEl.closest('.nH')?.querySelector('h2.hP');
    const subject = subjectEl?.innerText?.trim() || '';

    // 3. Body
    const bodyEl =
      messageEl.querySelector('.a3s.aiL') ||
      messageEl.querySelector('.ii.gt') ||
      messageEl.querySelector('.a3s');
    const bodyText = bodyEl?.innerText?.trim() || '';
    const bodyHtml = bodyEl?.innerHTML || '';

    return {
      senderName,
      senderEmail,
      subject,
      bodyText,
      bodyHtml,
      hasContent: Boolean(senderEmail || subject || bodyText),
    };
  }

  /**
   * Queries TraceShield FastAPI backend /analyze endpoint.
   */
  async function queryTraceShieldAnalysis(rawEmailMime) {
    const res = await fetch(`${BACKEND_URL}/analyze`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ raw_email: rawEmailMime }),
    });

    if (!res.ok) {
      throw new Error(`TraceShield API error: ${res.status} ${res.statusText}`);
    }

    return await res.json();
  }

  /**
   * Generates a 2-page forensic PDF dossier and downloads it directly.
   */
  async function downloadEvidencePdf(record) {
    try {
      const res = await fetch(`${BACKEND_URL}/report`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(record),
      });

      if (!res.ok) throw new Error('Failed to generate report PDF');

      const blob = await res.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `TraceShield_Evidence_${record.email_id.slice(0, 8)}.pdf`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(url);
    } catch (err) {
      console.error('[TraceShield] PDF download failed:', err);
      alert('Failed to download forensic PDF report. Ensure TraceShield backend is running.');
    }
  }

  /**
   * Injects the threat evaluation banner into the email DOM.
   */
  function injectThreatBanner(targetInsertionEl, analysisRecord, rawEmailMime) {
    // Remove any existing banner in this container
    const existing = targetInsertionEl.parentNode?.querySelector('.traceshield-banner');
    if (existing) existing.remove();

    const banner = document.createElement('div');
    const scoring = analysisRecord.scoring || {};
    const riskScore = scoring.final_risk_score ?? 0;
    const riskTier = (scoring.risk_tier || 'Low').toLowerCase();
    const confidenceLevel = scoring.confidence_level || 'Moderate Confidence';
    const confidenceReason = scoring.confidence_reason || '';
    const llmSummary = scoring.llm_summary || '';

    const header = analysisRecord.header_forensics || {};
    const content = analysisRecord.content_analysis || {};
    const geo = analysisRecord.geolocation || {};

    banner.className = `traceshield-banner tier-${riskTier}`;

    // Collect highlight badges
    const triggers = [];
    if (content.lookalike_domains_found?.length > 0) {
      triggers.push(`Lookalike Domain: ${content.lookalike_domains_found[0]}`);
    }
    if (content.homoglyph_domains_found?.some((h) => h.suspicious)) {
      triggers.push('Punycode / Homoglyph Detected');
    }
    if (content.qr_codes_found?.length > 0) {
      triggers.push('QR Quishing Attack Embedded');
    }
    if (content.credential_harvesting_detected) {
      triggers.push('Credential Harvesting Phrasing');
    }
    if (header.reply_to_mismatch) {
      triggers.push('Reply-To Domain Redirection Mismatch');
    }
    if (header.display_name_spoof) {
      triggers.push('High-Target Brand Display Spoofing');
    }
    if (geo.is_known_vpn_or_hosting) {
      triggers.push(`Cloud/VPN Infrastructure (${geo.origin_isp || 'Hosting'})`);
    }

    const tierTitle =
      riskTier === 'high'
        ? 'CRITICAL THREAT'
        : riskTier === 'medium'
        ? 'SUSPICIOUS'
        : 'AUTHENTIC';

    banner.innerHTML = `
      <div class="traceshield-header-row">
        <div class="traceshield-brand-wrap">
          <div class="traceshield-logo-badge">🛡️</div>
          <div class="traceshield-brand-title">
            TRACESHIELD RADAR
            <span class="traceshield-tag">SIH26106</span>
          </div>
        </div>
        <div class="traceshield-status-chip chip-${riskTier}">
          <span class="traceshield-radar-dot"></span>
          ${tierTitle} (${riskScore}/100)
        </div>
      </div>

      <div class="traceshield-metrics-row">
        <div class="traceshield-score-badge" style="color: ${
          riskTier === 'high' ? '#ef4444' : riskTier === 'medium' ? '#f59e0b' : '#10b981'
        }">
          ${riskScore} <span class="score-max">/ 100</span>
        </div>
        <div class="traceshield-confidence-label">
          <strong>${confidenceLevel}:</strong> ${confidenceReason}
        </div>
      </div>

      ${
        triggers.length > 0
          ? `<div class="traceshield-triggers-list">
              ${triggers.map((t) => `<span class="traceshield-trigger-tag">⚠️ ${t}</span>`).join('')}
             </div>`
          : `<div class="traceshield-triggers-list">
              <span class="traceshield-trigger-tag tag-safe">✓ Cryptographic checks passed & no malicious vectors found</span>
             </div>`
      }

      <div class="traceshield-actions-row">
        <a class="traceshield-btn traceshield-btn-primary" href="${FRONTEND_URL}" target="_blank" rel="noopener noreferrer">
          Open in TraceShield SOC ↗
        </a>
        <button class="traceshield-btn traceshield-btn-secondary traceshield-download-pdf-btn" type="button">
          Download Evidence PDF
        </button>
        <button class="traceshield-btn traceshield-btn-secondary traceshield-toggle-details-btn" type="button">
          Forensic Details ▾
        </button>
      </div>

      <div class="traceshield-details-pane" style="display: none;">
        <div class="traceshield-grid-2">
          <div>
            <div class="traceshield-field-label">Header Cryptography</div>
            <div class="traceshield-field-val">SPF: ${header.spf_result || 'N/A'} | DKIM: ${header.dkim_result || 'N/A'} | DMARC: ${header.dmarc_result || 'N/A'}</div>
          </div>
          <div>
            <div class="traceshield-field-label">Origin Attribution</div>
            <div class="traceshield-field-val">${geo.origin_country || 'Unknown'} (${geo.origin_ip || 'No Public IP'})</div>
          </div>
          <div>
            <div class="traceshield-field-label">Linguistic Urgency NLP</div>
            <div class="traceshield-field-val">${Math.round((content.urgency_score || 0) * 100)}% Urgency Probability</div>
          </div>
          <div>
            <div class="traceshield-field-label">Chain of Custody SHA-256</div>
            <div class="traceshield-field-val" title="${analysisRecord.raw_email_hash}">${(analysisRecord.raw_email_hash || '').slice(0, 16)}...</div>
          </div>
        </div>
      </div>
    `;

    // Wire up actions
    const downloadBtn = banner.querySelector('.traceshield-download-pdf-btn');
    downloadBtn.addEventListener('click', () => downloadEvidencePdf(analysisRecord));

    const toggleBtn = banner.querySelector('.traceshield-toggle-details-btn');
    const detailsPane = banner.querySelector('.traceshield-details-pane');
    toggleBtn.addEventListener('click', () => {
      const isHidden = detailsPane.style.display === 'none';
      detailsPane.style.display = isHidden ? 'block' : 'none';
      toggleBtn.innerText = isHidden ? 'Forensic Details ▴' : 'Forensic Details ▾';
    });

    // Insert before target
    targetInsertionEl.parentNode.insertBefore(banner, targetInsertionEl);
  }

  /**
   * Injects an offline / scanning placeholder banner.
   */
  function injectPlaceholderBanner(targetInsertionEl, statusText) {
    const existing = targetInsertionEl.parentNode?.querySelector('.traceshield-banner');
    if (existing) existing.remove();

    const banner = document.createElement('div');
    banner.className = 'traceshield-banner tier-low';
    banner.innerHTML = `
      <div class="traceshield-header-row">
        <div class="traceshield-brand-wrap">
          <div class="traceshield-logo-badge">🛡️</div>
          <div class="traceshield-brand-title">
            TRACESHIELD RADAR
            <span class="traceshield-tag">SIH26106</span>
          </div>
        </div>
        <div class="traceshield-status-chip chip-scanning">
          <span class="traceshield-radar-dot"></span>
          ${statusText}
        </div>
      </div>
    `;
    targetInsertionEl.parentNode.insertBefore(banner, targetInsertionEl);
    return banner;
  }

  /**
   * Scans a specific email message element in Gmail.
   */
  async function processEmailMessage(messageEl) {
    if (messageEl.hasAttribute(SCANNED_ATTR)) return;

    const emailData = extractEmailData(messageEl);
    if (!emailData.hasContent) return;

    // Mark as scanned to prevent loop
    messageEl.setAttribute(SCANNED_ATTR, 'pending');

    // Insertion target: above the email body
    const bodyTarget =
      messageEl.querySelector('.a3s.aiL') ||
      messageEl.querySelector('.ii.gt') ||
      messageEl.querySelector('.a3s') ||
      messageEl;

    const cacheKey = `${emailData.senderEmail}:${emailData.subject}:${emailData.bodyText.slice(0, 100)}`;

    if (analysisCache.has(cacheKey)) {
      messageEl.setAttribute(SCANNED_ATTR, 'done');
      injectThreatBanner(bodyTarget, analysisCache.get(cacheKey), '');
      return;
    }

    const placeholder = injectPlaceholderBanner(bodyTarget, 'Scanning Forensics & Protocols...');
    const rawMime = buildMimePayload(
      emailData.senderName,
      emailData.senderEmail,
      emailData.subject,
      emailData.bodyText,
      emailData.bodyHtml
    );

    try {
      const record = await queryTraceShieldAnalysis(rawMime);
      analysisCache.set(cacheKey, record);
      messageEl.setAttribute(SCANNED_ATTR, 'done');
      injectThreatBanner(bodyTarget, record, rawMime);
    } catch (err) {
      console.warn('[TraceShield] Backend connection failed:', err);
      placeholder.className = 'traceshield-banner tier-medium';
      placeholder.innerHTML = `
        <div class="traceshield-header-row">
          <div class="traceshield-brand-wrap">
            <div class="traceshield-logo-badge">🛡️</div>
            <div class="traceshield-brand-title">TRACESHIELD RADAR</div>
          </div>
          <div class="traceshield-status-chip chip-medium">BACKEND DISCONNECTED</div>
        </div>
        <div style="margin-top: 8px; font-size: 11px; color: #94a3b8;">
          Ensure local API server is running: <code style="color: #38bdf8;">python -m uvicorn main:app --reload</code> on port 8000.
        </div>
      `;
    }
  }

  /**
   * Observe DOM mutations to catch opened email threads dynamically.
   */
  function setupObserver() {
    const observer = new MutationObserver((mutations) => {
      // Find Gmail message bodies
      const messages = document.querySelectorAll('.adn.ads, .gA.gt, div[role="main"] .adn');
      messages.forEach((msg) => {
        if (!msg.hasAttribute(SCANNED_ATTR)) {
          processEmailMessage(msg);
        }
      });
    });

    observer.observe(document.body, {
      childList: true,
      subtree: true,
    });
  }

  // Listen for messages from popup
  chrome.runtime?.onMessage?.addListener((request, sender, sendResponse) => {
    if (request.action === 'PING') {
      sendResponse({ status: 'PONG', active: true });
    } else if (request.action === 'RESCAN') {
      // Reset scanned flags
      document.querySelectorAll(`[${SCANNED_ATTR}]`).forEach((el) => {
        el.removeAttribute(SCANNED_ATTR);
      });
      const messages = document.querySelectorAll('.adn.ads, .gA.gt, div[role="main"] .adn');
      messages.forEach(processEmailMessage);
      sendResponse({ status: 'RESCAN_TRIGGERED' });
    }
    return true;
  });

  // Initialize
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', setupObserver);
  } else {
    setupObserver();
  }
})();
