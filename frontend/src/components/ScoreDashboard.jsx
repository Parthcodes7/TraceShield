import React from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  FileText,
  Info,
  Layers,
  CheckCircle2,
  XCircle,
} from 'lucide-react';

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

      <div style={{ display: 'grid', gridTemplateColumns: '220px 1fr', gap: '24px', alignItems: 'center' }}>
        {/* Radial SVG Gauge */}
        <div>
          <div className="gauge-wrapper">
            <svg className="gauge-svg" viewBox="0 0 160 160">
              <circle
                className="gauge-bg-circle"
                cx="80"
                cy="80"
                r={radius}
              />
              <circle
                className="gauge-progress-circle"
                cx="80"
                cy="80"
                r={radius}
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
        <div>
          <div style={{ fontSize: '0.92rem', lineHeight: '1.6', color: 'var(--text-primary)', marginBottom: '12px' }}>
            {scoring.llm_summary}
          </div>

          <div className="confidence-box">
            <div className="confidence-header">
              <span className="confidence-label">Calibration Engine</span>
              <span
                className={`confidence-badge ${
                  confidence.includes('High') ? 'high' : 'moderate'
                }`}
              >
                {confidence}
              </span>
            </div>
            <div className="confidence-reason">{scoring.confidence_reason}</div>
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
                    : 'var(--accent-cyan)',
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
                    : 'var(--accent-purple)',
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
              <div key={idx} className="reason-tag threat">
                <XCircle size={15} style={{ flexShrink: 0, marginTop: '2px' }} />
                <span>{reason}</span>
              </div>
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
