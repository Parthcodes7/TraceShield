/**
 * TraceShield — Extension Popup Script
 * Self-contained: runs local analysis, shows scan history from chrome.storage.
 * No backend required.
 */

(function () {
  'use strict';

  // DOM Elements
  const statusPill = document.getElementById('extension-status-pill');
  const statusText = document.getElementById('extension-status-text');
  const btnScanTab = document.getElementById('btn-scan-tab');
  const scanFeedback = document.getElementById('tab-scan-feedback');
  const rawInput = document.getElementById('raw-input-textarea');
  const btnAnalyzeText = document.getElementById('btn-analyze-text');
  const resultCard = document.getElementById('quick-result-card');
  const resTierChip = document.getElementById('res-tier-chip');
  const resScore = document.getElementById('res-score');
  const resConfidence = document.getElementById('res-confidence');
  const resTriggers = document.getElementById('res-triggers');
  const historyList = document.getElementById('history-list');
  const btnClearHistory = document.getElementById('btn-clear-history');
  
  // SPOC Settings
  const spocEmailInput = document.getElementById('spoc-email-input');
  const btnSaveSpoc = document.getElementById('btn-save-spoc');
  const spocFeedback = document.getElementById('spoc-feedback');

  /**
   * Check if current tab is Gmail and content script is active.
   */
  async function checkExtensionStatus() {
    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (!tab || !tab.url || !tab.url.includes('mail.google.com')) {
        statusPill.className = 'status-pill offline';
        statusText.innerText = 'Not on Gmail';
        statusPill.title = 'Navigate to Gmail to enable scanning';
        return;
      }

      // Try pinging the content script
      chrome.tabs.sendMessage(tab.id, { action: 'PING' }, (response) => {
        if (chrome.runtime.lastError || !response) {
          statusPill.className = 'status-pill offline';
          statusText.innerText = 'Reload Gmail';
          statusPill.title = 'Refresh your Gmail tab to activate TraceShield';
        } else {
          statusPill.className = 'status-pill online';
          statusText.innerText = 'Active';
          statusPill.title = 'TraceShield is scanning emails in Gmail';
        }
      });
    } catch (e) {
      statusPill.className = 'status-pill offline';
      statusText.innerText = 'Error';
    }
  }

  /**
   * Trigger in-inbox rescan on current active Gmail tab.
   */
  async function triggerTabScan() {
    scanFeedback.className = 'feedback-msg';
    scanFeedback.innerText = 'Checking active tab...';

    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (!tab) {
        scanFeedback.className = 'feedback-msg error';
        scanFeedback.innerText = 'No active tab found.';
        return;
      }

      if (!tab.url || !tab.url.includes('mail.google.com')) {
        scanFeedback.className = 'feedback-msg error';
        scanFeedback.innerText = 'Switch to a Gmail tab first.';
        return;
      }

      chrome.tabs.sendMessage(tab.id, { action: 'RESCAN' }, (response) => {
        if (chrome.runtime.lastError) {
          scanFeedback.className = 'feedback-msg error';
          scanFeedback.innerText = 'Refresh Gmail and try again.';
        } else {
          scanFeedback.className = 'feedback-msg success';
          scanFeedback.innerText = '✓ Rescanning all visible emails in Gmail!';
          // Refresh history after a short delay
          setTimeout(loadHistory, 1500);
        }
      });
    } catch (err) {
      scanFeedback.className = 'feedback-msg error';
      scanFeedback.innerText = `Error: ${err.message}`;
    }
  }

  /**
   * Run local analysis on pasted text in popup.
   */
  function analyzeRawText() {
    const text = rawInput.value.trim();
    if (!text) {
      scanFeedback.className = 'feedback-msg error';
      scanFeedback.innerText = 'Paste email text to analyze.';
      return;
    }

    btnAnalyzeText.disabled = true;
    btnAnalyzeText.querySelector('span').innerText = 'Analyzing...';

    // Parse basic email structure from pasted text
    const emailData = parseRawText(text);

    try {
      const record = TraceShieldAnalysis.analyze(emailData);
      renderQuickResult(record);
    } catch (err) {
      console.error('[TraceShield] Analysis error:', err);
      scanFeedback.className = 'feedback-msg error';
      scanFeedback.innerText = `Analysis error: ${err.message}`;
    } finally {
      btnAnalyzeText.disabled = false;
      btnAnalyzeText.querySelector('span').innerText = 'Run Local Analysis';
    }
  }

  /**
   * Parse raw pasted text into email data structure.
   */
  function parseRawText(text) {
    const lines = text.split('\n');
    let senderEmail = '';
    let senderName = '';
    let subject = '';
    let replyTo = '';
    let bodyStart = 0;

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim();
      if (!line) {
        bodyStart = i + 1;
        break;
      }

      const fromMatch = line.match(/^From:\s*(?:"?([^"<]*)"?\s*)?<?([^>]+@[^>]+)>?/i);
      if (fromMatch) {
        senderName = (fromMatch[1] || '').trim();
        senderEmail = (fromMatch[2] || '').trim();
        continue;
      }

      const subjectMatch = line.match(/^Subject:\s*(.*)/i);
      if (subjectMatch) {
        subject = subjectMatch[1].trim();
        continue;
      }

      const replyMatch = line.match(/^Reply-To:\s*<?([^>]+@[^>]+)>?/i);
      if (replyMatch) {
        replyTo = replyMatch[1].trim();
        continue;
      }

      // If no header pattern matched and we haven't found a blank line, keep going
      if (!line.includes(':')) {
        bodyStart = i;
        break;
      }
    }

    const bodyText = lines.slice(bodyStart).join('\n').trim();

    return {
      senderEmail,
      senderName,
      subject,
      bodyText,
      bodyHtml: bodyText, // Treat as plaintext for popup analysis
      replyTo,
      attachmentNames: [],
    };
  }

  /**
   * Render analysis result card inside popup.
   */
  function renderQuickResult(record) {
    resultCard.style.display = 'block';
    const scoring = record.scoring || {};
    const riskTier = (scoring.risk_tier || 'Low').toLowerCase();
    const score = scoring.final_risk_score ?? 0;

    resTierChip.className = `tier-chip tier-${riskTier}`;
    resTierChip.innerText = scoring.risk_tier || 'Low';
    resScore.innerText = `${score} / 100`;
    resConfidence.innerText = `${scoring.confidence_level || ''}: ${scoring.confidence_reason || ''}`;

    // Threat triggers
    const allFlags = record.allFlags || [];
    if (allFlags.length === 0) {
      resTriggers.innerHTML =
        '<span class="trigger-badge" style="background:rgba(16,185,129,0.15); color:#6ee7b7; border-color:rgba(16,185,129,0.3);">✓ No deceptive patterns flagged</span>';
    } else {
      resTriggers.innerHTML = allFlags
        .slice(0, 5)
        .map(t => `<span class="trigger-badge">⚠️ ${t}</span>`)
        .join('');
    }
  }

  /**
   * Load scan history from chrome.storage.
   */
  function loadHistory() {
    chrome.storage?.local?.get(['scanHistory'], (result) => {
      const history = result.scanHistory || [];
      if (history.length === 0) {
        historyList.innerHTML =
          '<p class="card-desc" style="margin-bottom: 0;">No scans yet — open an email in Gmail to start.</p>';
        return;
      }

      historyList.innerHTML = history
        .slice(0, 8)
        .map(entry => {
          const tier = (entry.riskTier || 'Low').toLowerCase();
          const timeStr = formatTimeAgo(entry.timestamp);
          const senderShort = (entry.sender || 'Unknown').length > 28
            ? entry.sender.substring(0, 28) + '…'
            : entry.sender;

          return `
            <div class="history-item tier-${tier}">
              <div class="history-item-top">
                <span class="history-sender">${escapeHtml(senderShort)}</span>
                <span class="history-score tier-${tier}">${entry.riskScore}/100</span>
              </div>
              <div class="history-item-bottom">
                <span class="history-tier-badge tier-${tier}">${entry.riskTier}</span>
                <span class="history-time">${timeStr}</span>
              </div>
            </div>
          `;
        })
        .join('');
    });
  }

  /**
   * Clear scan history.
   */
  function clearHistory() {
    chrome.storage?.local?.set({ scanHistory: [] }, () => {
      loadHistory();
    });
  }

  /**
   * Load SPOC Email from storage.
   */
  function loadSpocEmail() {
    chrome.storage?.local?.get(['spocEmail'], (result) => {
      if (result.spocEmail) {
        spocEmailInput.value = result.spocEmail;
      }
    });
  }

  /**
   * Save SPOC Email to storage.
   */
  function saveSpocEmail() {
    const email = spocEmailInput.value.trim();
    chrome.storage?.local?.set({ spocEmail: email }, () => {
      spocFeedback.className = 'feedback-msg success';
      spocFeedback.innerText = 'SPOC email saved!';
      setTimeout(() => { spocFeedback.innerText = ''; }, 3000);
    });
  }

  /**
   * Format timestamp as relative time.
   */
  function formatTimeAgo(isoStr) {
    if (!isoStr) return '';
    const then = new Date(isoStr);
    const now = new Date();
    const diffMs = now - then;
    const diffMins = Math.floor(diffMs / 60000);
    const diffHrs = Math.floor(diffMs / 3600000);

    if (diffMins < 1) return 'just now';
    if (diffMins < 60) return `${diffMins}m ago`;
    if (diffHrs < 24) return `${diffHrs}h ago`;
    return then.toLocaleDateString();
  }

  /**
   * Escape HTML for safe rendering.
   */
  function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
  }

  // ─── Event Listeners ──────────────────────────────────────
  btnScanTab.addEventListener('click', triggerTabScan);
  btnAnalyzeText.addEventListener('click', analyzeRawText);
  btnClearHistory.addEventListener('click', clearHistory);
  btnSaveSpoc.addEventListener('click', saveSpocEmail);

  // ─── Initialize ───────────────────────────────────────────
  checkExtensionStatus();
  loadHistory();
  loadSpocEmail();
})();
