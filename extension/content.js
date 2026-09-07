/**
 * TraceShield — Chrome Browser Extension (Manifest V3)
 * Content Script for Gmail in-inbox threat analysis & forensic badging.
 * Self-contained: all analysis runs locally via analysis.js — no backend required.
 */

(function () {
  'use strict';

  const SCANNED_ATTR = 'data-traceshield-scanned';
  const analysisCache = new Map();

  console.log('[TraceShield] Gmail Content Script Loaded (Local Analysis Mode).');

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

    // 4. Reply-To (check for visible "Reply-To" indicator in Gmail)
    let replyTo = '';
    const headerArea = messageEl.querySelector('.ajy');
    if (headerArea) {
      const spans = headerArea.querySelectorAll('span');
      for (const span of spans) {
        if (span.textContent.toLowerCase().includes('reply-to:')) {
          const emailSpan = span.closest('tr')?.querySelector('span[email]');
          if (emailSpan) replyTo = emailSpan.getAttribute('email') || '';
        }
      }
    }

    // 5. Attachments (detect Gmail attachment chips)
    const attachmentNames = [];
    const attachmentEls = messageEl.querySelectorAll('.aZo .aV3, .aQH .aV3, [download_url]');
    attachmentEls.forEach(el => {
      const name = el.getAttribute('aria-label') || el.textContent?.trim() || '';
      if (name) attachmentNames.push(name);
    });
    // Also try download_url pattern
    messageEl.querySelectorAll('[download_url]').forEach(el => {
      const downloadUrl = el.getAttribute('download_url') || '';
      const parts = downloadUrl.split(':');
      if (parts.length > 1) {
        const fname = parts[0].split('/').pop();
        if (fname && !attachmentNames.includes(fname)) attachmentNames.push(fname);
      }
    });

    return {
      senderName,
      senderEmail,
      subject,
      bodyText,
      bodyHtml,
      replyTo,
      attachmentNames,
      hasContent: Boolean(senderEmail || subject || bodyText),
    };
  }

  /**
   * Injects the threat evaluation banner into the email DOM.
   */
  function injectThreatBanner(targetInsertionEl, analysisRecord) {
    // Remove any existing banner in this container
    const existing = targetInsertionEl.parentNode?.querySelector('.traceshield-banner');
    if (existing) existing.remove();

    const banner = document.createElement('div');
    const scoring = analysisRecord.scoring || {};
    const riskScore = scoring.final_risk_score ?? 0;
    const riskTier = (scoring.risk_tier || 'Low').toLowerCase();
    const confidenceLevel = scoring.confidence_level || 'Low Risk';
    const confidenceReason = scoring.confidence_reason || '';

    const sender = analysisRecord.senderIdentity || {};
    const domains = analysisRecord.domainAnalysis || {};
    const urls = analysisRecord.urlAnalysis || {};
    const language = analysisRecord.languageAnalysis || {};
    const allFlags = analysisRecord.allFlags || [];

    banner.className = `traceshield-banner tier-${riskTier}`;

    // Collect highlight badges
    const triggers = [];
    if (domains.lookalikeDomainsFound?.length > 0) {
      const first = domains.lookalikeDomainsFound[0];
      triggers.push(`Lookalike Domain: "${first.suspicious}" mimics ${first.brand}`);
    }
    if (domains.homoglyphDomainsFound?.some(h => h.suspicious)) {
      triggers.push('Punycode / Homoglyph Detected');
    }
    if (language.credentialHarvestingDetected) {
      triggers.push('Credential Harvesting Phrasing');
    }
    if (sender.replyToMismatch) {
      triggers.push('Reply-To Domain Mismatch');
    }
    if (sender.displayNameSpoof) {
      triggers.push(`Brand Spoofing: ${sender.spoofedBrand}`);
    }
    if (urls.displayHrefMismatches?.length > 0) {
      triggers.push('Deceptive Link Detected');
    }
    if (urls.urlShortenersFound?.length > 0) {
      triggers.push('URL Shortener Hiding Destination');
    }
    if (language.urgencyScore > 0.4) {
      triggers.push(`Urgency Score: ${Math.round(language.urgencyScore * 100)}%`);
    }

    const tierTitle =
      riskTier === 'high'
        ? 'CRITICAL THREAT'
        : riskTier === 'medium'
        ? 'SUSPICIOUS'
        : 'AUTHENTIC';

    const scoreColor = riskTier === 'high' ? '#dc2626' : riskTier === 'medium' ? '#d97706' : '#059669';

    banner.innerHTML = `
      <div class="traceshield-header-row">
        <div class="traceshield-brand-wrap">
          <div class="traceshield-logo-badge">🛡️</div>
          <div class="traceshield-brand-title">
            TRACESHIELD RADAR
            <span class="traceshield-tag">LOCAL</span>
          </div>
        </div>
        <div class="traceshield-status-chip chip-${riskTier}">
          <span class="traceshield-radar-dot"></span>
          ${tierTitle} (${riskScore}/100)
        </div>
      </div>

      <div class="traceshield-metrics-row">
        <div class="traceshield-score-badge" style="color: ${scoreColor}">
          ${riskScore} <span class="score-max">/ 100</span>
        </div>
        <div class="traceshield-confidence-label">
          <strong>${confidenceLevel}:</strong> ${confidenceReason}
        </div>
      </div>

      ${
        triggers.length > 0
          ? `<div class="traceshield-triggers-list">
              ${triggers.map(t => `<span class="traceshield-trigger-tag">⚠️ ${t}</span>`).join('')}
             </div>`
          : `<div class="traceshield-triggers-list">
              <span class="traceshield-trigger-tag tag-safe">✓ No deceptive patterns detected in visible content</span>
             </div>`
      }

      <div class="traceshield-actions-row">
        <button class="traceshield-btn traceshield-btn-secondary traceshield-toggle-details-btn" type="button">
          Forensic Details ▾
        </button>
      </div>

      <div class="traceshield-details-pane" style="display: none;">
        <div class="traceshield-grid-2">
          <div>
            <div class="traceshield-field-label">Analysis Mode</div>
            <div class="traceshield-field-val">Extension Local (No Backend)</div>
          </div>
          <div>
            <div class="traceshield-field-label">Sender Domain</div>
            <div class="traceshield-field-val">${sender.senderDomain || 'N/A'}</div>
          </div>
          <div>
            <div class="traceshield-field-label">Urgency Score</div>
            <div class="traceshield-field-val">${Math.round((language.urgencyScore || 0) * 100)}%</div>
          </div>
          <div>
            <div class="traceshield-field-label">Links Scanned</div>
            <div class="traceshield-field-val">${urls.totalLinks || 0} links analyzed</div>
          </div>
        </div>
        ${allFlags.length > 0 ? `
        <div style="margin-top: 10px; padding-top: 8px; border-top: 1px solid rgba(255,255,255,0.08);">
          <div class="traceshield-field-label" style="margin-bottom: 4px;">All Signals Detected</div>
          <ul style="margin: 0; padding-left: 16px; color: #94a3b8; font-size: 11px;">
            ${allFlags.map(f => `<li style="margin-bottom: 2px;">${f}</li>`).join('')}
          </ul>
        </div>` : ''}
      </div>
    `;

    // Wire up toggle
    const toggleBtn = banner.querySelector('.traceshield-toggle-details-btn');
    const detailsPane = banner.querySelector('.traceshield-details-pane');
    toggleBtn.addEventListener('click', () => {
      const isHidden = detailsPane.style.display === 'none';
      detailsPane.style.display = isHidden ? 'block' : 'none';
      toggleBtn.innerText = isHidden ? 'Forensic Details ▴' : 'Forensic Details ▾';
    });

    // Insert before target
    targetInsertionEl.parentNode.insertBefore(banner, targetInsertionEl);

    // Save to storage for popup history
    saveToHistory(analysisRecord);
  }

  /**
   * Injects a scanning placeholder banner.
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
            <span class="traceshield-tag">LOCAL</span>
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
   * Save analysis result to chrome.storage for popup history.
   */
  function saveToHistory(record) {
    try {
      chrome.storage?.local?.get(['scanHistory'], (result) => {
        const history = result.scanHistory || [];
        const entry = {
          timestamp: record.analyzedAt,
          sender: record.senderIdentity?.senderEmail || 'Unknown',
          subject: '',
          riskScore: record.scoring?.final_risk_score ?? 0,
          riskTier: record.scoring?.risk_tier || 'Low',
          triggerCount: record.allFlags?.length || 0,
        };
        history.unshift(entry);
        // Keep max 20 entries
        if (history.length > 20) history.length = 20;
        chrome.storage.local.set({ scanHistory: history });
      });
    } catch { /* chrome.storage not available in testing */ }
  }

  /**
   * Scans a specific email message element in Gmail.
   */
  function processEmailMessage(messageEl) {
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
      injectThreatBanner(bodyTarget, analysisCache.get(cacheKey));
      return;
    }

    injectPlaceholderBanner(bodyTarget, 'Analyzing Threat Signals...');

    // Run local analysis (synchronous — no network call)
    try {
      const record = TraceShieldAnalysis.analyze(emailData);
      analysisCache.set(cacheKey, record);
      messageEl.setAttribute(SCANNED_ATTR, 'done');
      injectThreatBanner(bodyTarget, record);
    } catch (err) {
      console.error('[TraceShield] Local analysis failed:', err);
      messageEl.setAttribute(SCANNED_ATTR, 'error');
    }
  }

  /**
   * Observe DOM mutations to catch opened email threads dynamically.
   */
  function setupObserver() {
    const observer = new MutationObserver(() => {
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
      analysisCache.clear();
      const messages = document.querySelectorAll('.adn.ads, .gA.gt, div[role="main"] .adn');
      messages.forEach(processEmailMessage);
      sendResponse({ status: 'RESCAN_TRIGGERED' });
    } else if (request.action === 'GET_CURRENT_ANALYSIS') {
      // Return the most recent analysis for the popup
      const lastKey = [...analysisCache.keys()].pop();
      const lastRecord = lastKey ? analysisCache.get(lastKey) : null;
      sendResponse({ record: lastRecord });
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
