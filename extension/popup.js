/**
 * TraceShield — Extension Popup Script
 * Manages backend health check, tab communication, and ad-hoc analysis.
 */

(function () {
  'use strict';

  const BACKEND_URL = 'http://localhost:8000';
  let lastAnalysisRecord = null;

  // DOM Elements
  const statusPill = document.getElementById('backend-status-pill');
  const statusText = document.getElementById('backend-status-text');
  const btnScanTab = document.getElementById('btn-scan-tab');
  const scanFeedback = document.getElementById('tab-scan-feedback');
  const rawInput = document.getElementById('raw-input-textarea');
  const btnAnalyzeText = document.getElementById('btn-analyze-text');
  const resultCard = document.getElementById('quick-result-card');
  const resTierChip = document.getElementById('res-tier-chip');
  const resScore = document.getElementById('res-score');
  const resConfidence = document.getElementById('res-confidence');
  const resTriggers = document.getElementById('res-triggers');
  const btnDownloadPdf = document.getElementById('btn-download-quick-pdf');

  /**
   * Check health of TraceShield local FastAPI backend.
   */
  async function checkBackendHealth() {
    try {
      const res = await fetch(`${BACKEND_URL}/health`, { method: 'GET' });
      if (res.ok) {
        const data = await res.json();
        statusPill.className = 'status-pill online';
        statusText.innerText = 'API Online';
        statusPill.title = `Modules Ready: ${Object.keys(data.modules || {}).length}`;
      } else {
        throw new Error('API degraded');
      }
    } catch (e) {
      statusPill.className = 'status-pill offline';
      statusText.innerText = 'API Offline';
      statusPill.title = 'Start backend: python -m uvicorn main:app --reload in /backend';
    }
  }

  /**
   * Trigger in-inbox rescan on current active Gmail tab.
   */
  async function triggerTabScan() {
    scanFeedback.className = 'feedback-msg';
    scanFeedback.innerText = 'Checking active tab...';

    try {
      if (!chrome.tabs) {
        scanFeedback.innerText = 'Extension tab API unavailable.';
        return;
      }

      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (!tab) {
        scanFeedback.className = 'feedback-msg error';
        scanFeedback.innerText = 'No active tab found.';
        return;
      }

      if (!tab.url || !tab.url.includes('mail.google.com')) {
        scanFeedback.className = 'feedback-msg error';
        scanFeedback.innerText = 'Please switch to an active Gmail tab to scan.';
        return;
      }

      chrome.tabs.sendMessage(tab.id, { action: 'RESCAN' }, (response) => {
        if (chrome.runtime.lastError) {
          scanFeedback.className = 'feedback-msg error';
          scanFeedback.innerText = 'Could not contact Gmail tab (refresh Gmail and retry).';
        } else {
          scanFeedback.className = 'feedback-msg success';
          scanFeedback.innerText = '✓ In-inbox threat scanner triggered in Gmail!';
        }
      });
    } catch (err) {
      scanFeedback.className = 'feedback-msg error';
      scanFeedback.innerText = `Error: ${err.message}`;
    }
  }

  /**
   * Run ad-hoc analysis on pasted text / email in popup.
   */
  async function analyzeRawText() {
    const text = rawInput.value.trim();
    if (!text) {
      alert('Please paste email text, headers, or message body to analyze.');
      return;
    }

    btnAnalyzeText.disabled = true;
    btnAnalyzeText.innerText = 'Analyzing Threat Signals...';

    try {
      const res = await fetch(`${BACKEND_URL}/analyze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ raw_email: text }),
      });

      if (!res.ok) {
        throw new Error(`API error: ${res.status} ${res.statusText}`);
      }

      const record = await res.json();
      lastAnalysisRecord = record;
      renderQuickResult(record);
    } catch (err) {
      alert(`Analysis failed: ${err.message}. Ensure backend is running.`);
    } finally {
      btnAnalyzeText.disabled = false;
      btnAnalyzeText.innerText = 'Run Forensic Analysis';
    }
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
    const content = record.content_analysis || {};
    const header = record.header_forensics || {};
    const geo = record.geolocation || {};
    const triggers = [];

    if (content.lookalike_domains_found?.length > 0) {
      triggers.push(`Lookalike: ${content.lookalike_domains_found[0]}`);
    }
    if (content.homoglyph_domains_found?.some((h) => h.suspicious)) {
      triggers.push('Punycode / Homoglyph');
    }
    if (content.credential_harvesting_detected) {
      triggers.push('Credential Phishing Tone');
    }
    if (header.reply_to_mismatch) {
      triggers.push('Reply-To Mismatch');
    }
    if (geo.is_known_vpn_or_hosting) {
      triggers.push(`Cloud/VPN Origin (${geo.origin_isp || 'Hosting'})`);
    }

    if (triggers.length === 0) {
      resTriggers.innerHTML = '<span class="trigger-badge" style="background:rgba(16,185,129,0.15); color:#6ee7b7; border-color:rgba(16,185,129,0.3);">✓ No deceptive patterns flagged</span>';
    } else {
      resTriggers.innerHTML = triggers
        .slice(0, 3)
        .map((t) => `<span class="trigger-badge">⚠️ ${t}</span>`)
        .join('');
    }
  }

  /**
   * Download evidence PDF from popup.
   */
  async function downloadQuickPdf() {
    if (!lastAnalysisRecord) return;
    try {
      btnDownloadPdf.disabled = true;
      btnDownloadPdf.innerText = 'Compiling PDF Dossier...';

      const res = await fetch(`${BACKEND_URL}/report`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(lastAnalysisRecord),
      });

      if (!res.ok) throw new Error('PDF compilation failed');

      const blob = await res.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `TraceShield_Evidence_${lastAnalysisRecord.email_id.slice(0, 8)}.pdf`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(url);
    } catch (e) {
      alert(`PDF download failed: ${e.message}`);
    } finally {
      btnDownloadPdf.disabled = false;
      btnDownloadPdf.innerText = 'Download 2-Page Evidence PDF';
    }
  }

  // Event Listeners
  btnScanTab.addEventListener('click', triggerTabScan);
  btnAnalyzeText.addEventListener('click', analyzeRawText);
  btnDownloadPdf.addEventListener('click', downloadQuickPdf);

  // Initial health check
  checkBackendHealth();
})();
