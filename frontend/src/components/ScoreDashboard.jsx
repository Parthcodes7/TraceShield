import React, { useState, useEffect } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  FileText,
  Info,
  Layers,
  CheckCircle2,
  XCircle,
  Sparkles,
  Bot
} from 'lucide-react';

function HighlightedText({ text }) {
  if (!text) return null;
  const regex = /(CRITICAL ALERT|HIGH-RISK|PHISHING|FRAUD|FAILED|quarantine|blocking|\bthreat\b|spoofing|Verified|Low Risk|intact|authorized|safe)/gi;
  const parts = text.split(regex);
  return (
    <span>
      {parts.map((part, idx) => {
        const lower = part.toLowerCase();
        if (['verified', 'low risk', 'intact', 'authorized', 'safe'].includes(lower)) {
          return (
            <span key={idx} style={{ color: 'var(--threat-low)', fontWeight: 600 }}>
              {part}
            </span>
          );
        }
        if (['critical alert', 'high-risk', 'phishing', 'fraud', 'failed', 'quarantine', 'blocking', 'threat', 'spoofing'].includes(lower)) {
          return (
            <span key={idx} style={{ color: 'var(--threat-high)', fontWeight: 600 }}>
              {part}
            </span>
          );
        }
        return part;
      })}
    </span>
  );
}

function ThreatIndicator({ reason }) {
  const [showTooltip, setShowTooltip] = useState(false);

  let explanation = "Suspicious anomaly deviating from secure communication protocols.";
  if (reason.includes("SPF")) {
    explanation = "The sender's IP address is not authorized by the domain owner. Highly indicative of an offshore server spoofing the brand.";
  } else if (reason.includes("DKIM")) {
    explanation = "Cryptographic signature validation failed, indicating the message body or headers were altered in transit.";
  } else if (reason.includes("DMARC")) {
    explanation = "The domain enforces strict anti-spoofing policies, but this email failed alignment, proving it is an unauthorized payload.";
  } else if (reason.includes("Reply-To")) {
    explanation = "The attacker is spoofing the 'From' address to look trusted, while secretly routing your replies to their own shadow inbox.";
  } else if (reason.includes("homoglyph")) {
    explanation = "Punycode/Cyrillic character substitution used to mimic a reputable domain name and deceive recipient visual checks.";
  } else if (reason.includes("QR") || reason.includes("quishing")) {
    explanation = "Malicious or disguised destination URL embedded within a QR image to bypass conventional email gateway filters.";
  } else if (reason.includes("attachment")) {
    explanation = "High-risk file extension identified (e.g. script, executable, or macro) frequently leveraged for malware delivery.";
  } else if (reason.includes("short relay")) {
    explanation = "Legitimate enterprise emails pass through multiple verifiable routing hops. This email was directly injected, bypassing origin tracking.";
  } else if (reason.includes("urgency trigger") || reason.includes("urgency")) {
    explanation = "Phishing attacks use psychological pressure ('URGENT', 'Action Required') to induce panic and bypass critical verification.";
  } else if (reason.includes("Credential") || reason.includes("OTP")) {
    explanation = "Message requests passwords, OTP codes, or banking verification, indicating an active credential harvesting campaign.";
  }

  return (
    <div 
      className="reason-tag threat" 
      style={{ position: 'relative', cursor: 'pointer' }}
      onMouseEnter={() => setShowTooltip(true)}
      onMouseLeave={() => setShowTooltip(false)}
    >
      <XCircle size={15} style={{ flexShrink: 0, marginTop: '2px' }} />
      <span>{reason}</span>
      <Info size={14} style={{ marginLeft: 'auto', color: 'var(--text-muted)', flexShrink: 0 }} />

      {showTooltip && (
        <div style={{
          position: 'absolute',
          bottom: 'calc(100% + 8px)',
          right: '0px',
          width: '300px',
          background: '#ffffff',
          border: '1px solid var(--border-light)',
          boxShadow: '0 10px 25px -5px rgba(0, 0, 0, 0.12), 0 8px 10px -6px rgba(0, 0, 0, 0.08)',
          padding: '12px 14px',
          borderRadius: '10px',
          zIndex: 9999,
          color: 'var(--text-primary)',
          fontSize: '0.8rem',
          lineHeight: '1.5',
          fontFamily: 'var(--font-main)',
          textTransform: 'none',
          pointerEvents: 'none',
          animation: 'fadeIn 0.15s ease-out',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '6px', color: 'var(--accent-blue)', fontWeight: 600 }}>
            <Info size={14} />
            Threat Explanation
          </div>
          <div style={{ color: 'var(--text-secondary)' }}>
            {explanation}
          </div>
          {/* Bottom pointer arrow */}
          <div style={{
            position: 'absolute',
            bottom: '-6px',
            right: '16px',
            width: 0,
            height: 0,
            borderLeft: '6px solid transparent',
            borderRight: '6px solid transparent',
            borderTop: '6px solid #ffffff',
          }} />
          <div style={{
            position: 'absolute',
            bottom: '-7px',
            right: '16px',
            width: 0,
            height: 0,
            borderLeft: '6px solid transparent',
            borderRight: '6px solid transparent',
            borderTop: '6px solid var(--border-light)',
            zIndex: -1,
          }} />
        </div>
      )}
    </div>
  );
}

export default function ScoreDashboard({ record }) {
  if (!record || !record.scoring) {
    return (
      <div className="card" style={{ textAlign: 'center', padding: '40px' }}>
        <p style={{ color: 'var(--text-muted)' }}>No analysis record loaded.</p>
      </div>
    );
  }

  const { scoring, header_forensics } = record;
  const score = scoring.final_risk_score ?? 0;
  const tier = (scoring.risk_tier || 'Low').toLowerCase();
  const confidence = scoring.confidence_level || 'Moderate Confidence';
  const breakdown = scoring.score_breakdown || {
    header_authentication: { points: 0, max_score: 40, status: 'Pass' },
    content_threats: { points: 0, max_score: 45, status: 'Low' },
    network_infrastructure: { points: 0, max_score: 15, status: 'Normal' },
  };

  // Radial SVG calculation
  const radius = 70;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (score / 100) * circumference;

  let strokeColor = 'var(--threat-low)';
  if (score >= 61) {
    strokeColor = 'var(--threat-high)';
  } else if (score >= 31) {
    strokeColor = 'var(--threat-med)';
  }

  return (
    <div className="card">
      <div className="card-header">
        <h2 className="card-title">
          <ShieldAlert size={20} style={{ color: strokeColor }} />
          Threat Assessment & Calibration
        </h2>
        <span className={`badge-tier ${tier}`}>
          {scoring.risk_tier || 'Low'} Risk
        </span>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '200px 1fr', gap: '24px', alignItems: 'center' }}>
        {/* SVG Radial Gauge */}
        <div>
          <div className="gauge-wrapper" style={{ width: '200px', height: '200px' }}>
            <svg className="gauge-svg" viewBox="0 0 160 160">
              <circle
                className="gauge-bg-circle"
                cx="80" cy="80" r={radius}
              />
              <circle
                className="gauge-progress-circle"
                cx="80" cy="80" r={radius}
                stroke={strokeColor}
                strokeDasharray={circumference}
                strokeDashoffset={strokeDashoffset}
              />
            </svg>
            <div className="gauge-center-text">
              <div className="gauge-score" style={{ color: strokeColor }}>
                {score}
              </div>
              <div className="gauge-score-sub">RISK INDEX</div>
            </div>
          </div>
        </div>

        {/* Executive Summary & Confidence */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', height: '100%', justifyContent: 'center' }}>
          
          <div style={{
            background: 'var(--bg-secondary)',
            border: '1px solid var(--border-light)',
            borderRadius: 'var(--radius-lg)',
            padding: '16px 20px',
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '12px' }}>
              <Bot size={18} style={{ color: 'var(--accent-blue)' }} />
              <h3 style={{ fontSize: '0.85rem', color: 'var(--text-primary)', textTransform: 'uppercase', fontFamily: 'var(--font-mono)', fontWeight: 600 }}>
                AI Executive Briefing
              </h3>
            </div>
            <div style={{ fontSize: '0.88rem', lineHeight: '1.6', color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)' }}>
              <HighlightedText text={scoring.llm_summary} />
            </div>
          </div>

          <div className="confidence-box" style={{ margin: 0, display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '12px 16px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <span className="confidence-label">Calibration Engine</span>
            </div>
            <span
              className={`confidence-badge ${
                confidence.includes('High') ? 'high' : 'moderate'
              }`}
            >
              {confidence}
            </span>
          </div>
        </div>
      </div>

      {/* Dimensional Breakdown Bars */}
      <div className="breakdown-list">
        {/* Headers */}
        <div className="breakdown-row">
          <div className="breakdown-labels">
            <span className="breakdown-title">
              Protocol & Header Authentication
            </span>
            <span className="breakdown-points">
              {breakdown.header_authentication?.points ?? 0} / 40 pts ({breakdown.header_authentication?.status || 'Pass'})
            </span>
          </div>
          <div className="progress-track">
            <div
              className="progress-fill"
              style={{
                width: `${Math.min(
                  ((breakdown.header_authentication?.points ?? 0) / 40) * 100,
                  100
                )}%`,
                background:
                  (breakdown.header_authentication?.points ?? 0) > 15
                    ? 'var(--threat-high)'
                    : 'var(--accent-blue)',
              }}
            ></div>
          </div>
        </div>

        {/* Content */}
        <div className="breakdown-row">
          <div className="breakdown-labels">
            <span className="breakdown-title">
              Linguistic & Content Attack Vectors
            </span>
            <span className="breakdown-points">
              {breakdown.content_threats?.points ?? 0} / 45 pts ({breakdown.content_threats?.status || 'Low'})
            </span>
          </div>
          <div className="progress-track">
            <div
              className="progress-fill"
              style={{
                width: `${Math.min(
                  ((breakdown.content_threats?.points ?? 0) / 45) * 100,
                  100
                )}%`,
                background:
                  (breakdown.content_threats?.points ?? 0) > 20
                    ? 'var(--threat-high)'
                    : 'var(--accent-blue)',
              }}
            ></div>
          </div>
        </div>

        {/* Network Infrastructure */}
        <div className="breakdown-row">
          <div className="breakdown-labels">
            <span className="breakdown-title">
              Network & Routing Infrastructure
            </span>
            <span className="breakdown-points">
              {breakdown.network_infrastructure?.points ?? 0} / 15 pts ({breakdown.network_infrastructure?.status || 'Normal'})
            </span>
          </div>
          <div className="progress-track">
            <div
              className="progress-fill"
              style={{
                width: `${Math.min(
                  ((breakdown.network_infrastructure?.points ?? 0) / 15) * 100,
                  100
                )}%`,
                background:
                  (breakdown.network_infrastructure?.points ?? 0) > 0
                    ? 'var(--threat-med)'
                    : 'var(--accent-blue)',
              }}
            ></div>
          </div>
        </div>
      </div>

      {/* Triggered Reasons & Verified Authentications */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px', marginTop: '20px' }}>
        {/* Threat Signals */}
        <div>
          <h3 style={{ fontSize: '0.82rem', fontFamily: 'var(--font-mono)', color: 'var(--threat-high)', textTransform: 'uppercase', marginBottom: '8px' }}>
            Detected Threat Indicators ({scoring.triggered_reasons?.length || 0})
          </h3>
          {scoring.triggered_reasons && scoring.triggered_reasons.length > 0 ? (
            scoring.triggered_reasons.map((reason, idx) => (
              <ThreatIndicator key={idx} reason={reason} />
            ))
          ) : (
            <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', fontStyle: 'italic' }}>
              No structural or cryptographic threat indicators detected.
            </div>
          )}
        </div>

        {/* Positive Authentications */}
        <div>
          <h3 style={{ fontSize: '0.82rem', fontFamily: 'var(--font-mono)', color: 'var(--threat-low)', textTransform: 'uppercase', marginBottom: '8px' }}>
            Positive Security Baseline ({scoring.verified_authentications?.length || 0})
          </h3>
          {scoring.verified_authentications && scoring.verified_authentications.length > 0 ? (
            scoring.verified_authentications.map((auth, idx) => (
              <div key={idx} className="reason-tag auth">
                <CheckCircle2 size={15} style={{ flexShrink: 0, marginTop: '2px' }} />
                <span>{auth}</span>
              </div>
            ))
          ) : (
            <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', fontStyle: 'italic' }}>
              No cryptographic passes verified in message headers.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
