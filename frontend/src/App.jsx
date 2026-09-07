import React, { useState, useEffect } from 'react';
import HeaderNav from './components/HeaderNav.jsx';
import ScoreDashboard from './components/ScoreDashboard.jsx';
import TraceMap from './components/TraceMap.jsx';
import ReportViewer from './components/ReportViewer.jsx';
import UploadModal from './components/UploadModal.jsx';
import HistoryDrawer from './components/HistoryDrawer.jsx';
import AdversarialLab from './components/AdversarialLab.jsx';
import IntroPage from './components/IntroPage.jsx';
import { Shield, Sparkles, RefreshCw, AlertCircle } from 'lucide-react';

// Built-in raw sample emails for one-click demo
const DEMO_EMAILS = {
  phishing_boi: {
    label: 'Bank of India Spoof',
    tier: 'High',
    raw: `Received: from mail.attacker-server.com (mail.attacker-server.com. [209.85.212.49])
        by mx.victim-domain.com with ESMTPS id a10si819283qkc.12.2023.10.15.08.30.00
        for <victim@example.com>;
        Sun, 15 Oct 2023 08:30:00 -0700
From: "Bank of India Support" <admin@bankofindia-secure.com>
To: victim@example.com
Reply-To: phisher-drop@anonymous-mail.org
Subject: URGENT: Your Account Has Been Suspended - Action Required
Date: Sun, 15 Oct 2023 08:30:00 -0700
Message-ID: <threat-20231015-881920@attacker-server.com>
MIME-Version: 1.0
Content-Type: text/html; charset="utf-8"

<!DOCTYPE html>
<html>
<body>
  <h2>Urgent Notification Regarding Your Account</h2>
  <p>Dear Valued Customer,</p>
  <p>Your access has been temporarily suspended due to security irregularities.</p>
  <p>Please update your credentials and verify your account details immediately by visiting:</p>
  <p><a href="http://bank0findia.co.in/login">http://bank0findia.co.in/login</a></p>
  <p>Enter your password and current OTP to authenticate your session.</p>
</body>
</html>`,
  },
  legitimate_cal: {
    label: 'Google Calendar Invite',
    tier: 'Low',
    raw: `Received: from mail-pj1-f51.google.com (mail-pj1-f51.google.com. [209.85.216.51])
        by mx.google.com with ESMTPS id d19si9918231qkc.08.2023.10.15.09.45.00
        for <recipient@example.com>;
        Sun, 15 Oct 2023 09:45:00 -0700
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=20230601;
        h=to:from:subject:date:message-id:mime-version;
        bh=FRtB1yF80bA1d7yP9E6d4x9K5p+7w0q4v3d1x0k2p4o=;
        b=d2FybmluZy1zaWduYXR1cmUtZHVtbXktYnl0ZXM=
From: "Google Calendar" <calendar-notification@google.com>
To: recipient@example.com
Subject: Invitation: Project Sync @ Mon Oct 16, 2023 10am - 11am (recipient@example.com)
Date: Sun, 15 Oct 2023 09:45:00 -0700
Message-ID: <calendar-invite-9921203@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"

Hi team,

You have been invited to Project Sync.
Time: Mon Oct 16, 2023 10am - 11am
Location: Google Meet video conference

Agenda:
- Sprint review
- Backlog groom
- Next steps

Looking forward to catching up.`,
  },
  homoglyph: {
    label: 'Cyrillic Homoglyph Attack',
    tier: 'High',
    raw: `Received: from sso.id-auth.net (sso.id-auth.net. [198.51.100.12])
        by mx.company.com with ESMTPS id h71si1029312qkc.14.2026.09.06.12.00.00
        for <user@company.com>;
        Sun, 06 Sep 2026 12:00:00 -0400
From: "PayPal Account Team" <security@paypаl.com>
To: user@company.com
Reply-To: security@paypаl.com
Subject: Security Alert: Unauthorized sign-in attempt detected
Date: Sun, 06 Sep 2026 11:59:00 -0400
Message-ID: <sec-alert-892102@paypаl.com>
MIME-Version: 1.0
Content-Type: text/html; charset="utf-8"

<!DOCTYPE html>
<html>
<body>
  <p>Dear Customer,</p>
  <p>We noticed a suspicious sign-in to your account from an unrecognized IP address in Moscow.</p>
  <p>If this was not you, please secure your account immediately:</p>
  <p><a href="http://paypаl.com/verify-identity">http://paypаl.com/verify-identity</a></p>
  <p>Thank you,<br>Account Protection Services</p>
</body>
</html>`,
  },
  vpn_cloud: {
    label: 'Cloud VPS / Datacenter Origin',
    tier: 'Medium',
    raw: `Received: from vps-node-881.digitalocean.com (vps-node-881.digitalocean.com. [167.99.160.1])
        by mx.corporate-mail.com with ESMTPS id d22si992812qkc.04.2026.09.06.14.00.00
        for <audit@corporate-mail.com>;
        Sun, 06 Sep 2026 14:00:00 -0400
From: "Customer Support" <support@vendor-portal.com>
To: audit@corporate-mail.com
Subject: Standard Vendor Status Report - Ticket #88410
Date: Sun, 06 Sep 2026 13:58:00 -0400
Message-ID: <ticket-88410-status@vendor-portal.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"

Hello Support,

This is a scheduled follow-up on ticket #88410 regarding the database migration.
Please review the attached report summary when convenient.

Kind regards,
Operations Team`,
  },
};

export default function App() {
  const [hasEntered, setHasEntered] = useState(false);
  const [record, setRecord] = useState(null);
  const [backendHealth, setBackendHealth] = useState(null);
  const [activeDemo, setActiveDemo] = useState('phishing_boi');
  const [loading, setLoading] = useState(false);
  const [isDownloadingPdf, setIsDownloadingPdf] = useState(false);

  // Modals
  const [uploadModalOpen, setUploadModalOpen] = useState(false);
  const [historyDrawerOpen, setHistoryDrawerOpen] = useState(false);
  const [adversarialModalOpen, setAdversarialModalOpen] = useState(false);

  // Fetch backend status & initial demo record
  useEffect(() => {
    checkHealth();
    loadDemo('phishing_boi');
  }, []);

  const checkHealth = async () => {
    try {
      const res = await fetch('/health');
      if (res.ok) {
        const data = await res.json();
        setBackendHealth(data);
      }
    } catch (e) {
      console.warn('Backend not yet reachable on /health:', e);
    }
  };

  const loadDemo = async (demoKey) => {
    const demo = DEMO_EMAILS[demoKey];
    if (!demo) return;
    setActiveDemo(demoKey);
    setLoading(true);

    try {
      const res = await fetch('/analyze/text', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ raw_email: demo.raw }),
      });

      if (res.ok) {
        const data = await res.json();
        setRecord(data);
      }
    } catch (e) {
      console.error('Failed to analyze demo email:', e);
    } finally {
      setLoading(false);
    }
  };

  const handleDownloadPdf = async () => {
    if (!record) return;
    setIsDownloadingPdf(true);
    try {
      const response = await fetch('/report', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(record),
      });

      if (!response.ok) {
        throw new Error(`Report generation failed: HTTP ${response.status}`);
      }

      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `TraceShield_Report_${record.email_id?.slice(0, 8) || 'evidence'}.pdf`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
    } catch (err) {
      alert('Error generating PDF report: ' + err.message);
    } finally {
      setIsDownloadingPdf(false);
    }
  };

  if (!hasEntered) {
    return <IntroPage onEnter={() => setHasEntered(true)} />;
  }

  return (
    <div className="app-container">
      {/* Top Navbar */}
      <HeaderNav
        backendHealth={backendHealth}
        onOpenUpload={() => setUploadModalOpen(true)}
        onOpenHistory={() => setHistoryDrawerOpen(true)}
        onOpenAdversarial={() => setAdversarialModalOpen(true)}
      />

      <main className="main-content">
        {/* Quick Demo Selector Chips */}
        <div className="demo-bar">
          <div className="demo-bar-label">
            <Sparkles size={16} style={{ color: 'var(--accent-blue)' }} />
            One-Click Attack Vectors:
          </div>

          <div className="demo-pills-list">
            {Object.entries(DEMO_EMAILS).map(([key, demo]) => (
              <button
                key={key}
                className={`demo-chip ${activeDemo === key ? 'active' : ''}`}
                onClick={() => loadDemo(key)}
              >
                <span
                  style={{
                    width: '8px',
                    height: '8px',
                    borderRadius: '50%',
                    background:
                      demo.tier === 'High'
                        ? 'var(--threat-high)'
                        : demo.tier === 'Medium'
                        ? 'var(--threat-med)'
                        : 'var(--threat-low)',
                  }}
                ></span>
                {demo.label}
              </button>
            ))}
          </div>

          {loading && (
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '0.8rem', color: 'var(--accent-cyan)' }}>
              <RefreshCw size={14} className="spin" />
              Inspecting message...
            </div>
          )}
        </div>

        {/* Dashboard Focus Layout */}
        <div className="dashboard-focus-layout">
          {/* Top Section: Threat Gauge & Score Breakdown */}
          <ScoreDashboard record={record} />

          {/* Geo Attribution & Map */}
          <TraceMap
            geolocation={record?.geolocation}
            relayChain={record?.header_forensics?.relay_chain}
          />
        </div>

        {/* Detailed Forensic Evidence Dossier */}
        <ReportViewer
          record={record}
          onDownloadPdf={handleDownloadPdf}
          isDownloadingPdf={isDownloadingPdf}
        />
      </main>

      {/* Modals & Drawers */}
      <UploadModal
        isOpen={uploadModalOpen}
        onClose={() => setUploadModalOpen(false)}
        onAnalysisComplete={(newRecord) => {
          setRecord(newRecord);
          setActiveDemo(null);
        }}
      />

      <HistoryDrawer
        isOpen={historyDrawerOpen}
        onClose={() => setHistoryDrawerOpen(false)}
        onSelectRecord={(historicRecord) => {
          setRecord(historicRecord);
          setActiveDemo(null);
        }}
      />

      <AdversarialLab
        isOpen={adversarialModalOpen}
        onClose={() => setAdversarialModalOpen(false)}
        onTestCompleted={(adversarialRecord) => {
          setRecord(adversarialRecord);
          setActiveDemo(null);
        }}
      />
    </div>
  );
}
