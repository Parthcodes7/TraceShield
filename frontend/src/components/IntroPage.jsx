import React from 'react';
import { Shield, Mail, Globe, FileText, Zap, BarChart3 } from 'lucide-react';

const features = [
  { icon: Mail, label: 'Header Forensics', desc: 'SPF, DKIM, DMARC validation' },
  { icon: BarChart3, label: 'NLP Content Analysis', desc: 'Urgency & phishing detection' },
  { icon: Globe, label: 'Geolocation & IP', desc: 'Origin tracking & mapping' },
  { icon: Shield, label: 'Threat Fusion Scoring', desc: 'Multi-signal risk calibration' },
  { icon: Zap, label: 'Adversarial Red-Team', desc: 'AI evasion simulation' },
  { icon: FileText, label: 'Evidence PDF Dossier', desc: 'Court-grade forensic reports' },
];

export default function IntroPage({ onEnter }) {
  return (
    <div style={{
      width: '100vw',
      height: '100vh',
      display: 'flex',
      flexDirection: 'column',
      alignItems: 'center',
      justifyContent: 'center',
      background: 'var(--bg-primary)',
      overflow: 'hidden',
      position: 'relative',
    }}>
      {/* Subtle gradient overlay */}
      <div style={{
        position: 'absolute',
        inset: 0,
        background: 'radial-gradient(ellipse at 50% 30%, rgba(59, 130, 246, 0.06) 0%, transparent 60%)',
        pointerEvents: 'none',
      }} />

      {/* Logo & Title */}
      <div style={{
        display: 'flex',
        alignItems: 'center',
        gap: '16px',
        marginBottom: '12px',
        zIndex: 1,
      }}>
        <div style={{
          width: '56px',
          height: '56px',
          borderRadius: '14px',
          background: 'var(--accent-blue)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          color: '#fff',
        }}>
          <Shield size={30} />
        </div>
        <div>
          <h1 style={{
            fontSize: '2.4rem',
            fontFamily: "var(--font-display)",
            fontWeight: 800,
            color: 'var(--text-white)',
            letterSpacing: '-0.02em',
            lineHeight: 1,
          }}>
            Trace<span style={{ color: 'var(--accent-blue)' }}>Shield</span>
          </h1>
        </div>
      </div>

      <p style={{
        fontSize: '1rem',
        color: 'var(--text-secondary)',
        marginBottom: '48px',
        fontFamily: 'var(--font-main)',
        letterSpacing: '0.02em',
        textAlign: 'center',
        zIndex: 1,
      }}>
        AI-Powered Email Threat Detection & Forensic Intelligence Platform
      </p>

      {/* Feature Grid */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(3, 1fr)',
        gap: '14px',
        maxWidth: '640px',
        width: '100%',
        padding: '0 24px',
        marginBottom: '48px',
        zIndex: 1,
      }}>
        {features.map((f, i) => {
          const Icon = f.icon;
          return (
            <div key={i} style={{
              background: 'var(--bg-card)',
              border: '1px solid var(--border-light)',
              boxShadow: 'var(--shadow-card)',
              borderRadius: 'var(--radius-md)',
              padding: '16px',
              display: 'flex',
              flexDirection: 'column',
              gap: '6px',
            }}>
              <Icon size={18} style={{ color: 'var(--accent-blue)', marginBottom: '2px' }} />
              <span style={{
                fontSize: '0.82rem',
                fontWeight: 600,
                color: 'var(--text-primary)',
              }}>{f.label}</span>
              <span style={{
                fontSize: '0.72rem',
                color: 'var(--text-muted)',
                lineHeight: 1.3,
              }}>{f.desc}</span>
            </div>
          );
        })}
      </div>

      {/* CTA Button */}
      <button
        onClick={onEnter}
        style={{
          background: 'var(--accent-blue)',
          color: '#fff',
          border: 'none',
          padding: '14px 40px',
          fontSize: '0.95rem',
          fontWeight: 700,
          fontFamily: "var(--font-main)",
          borderRadius: 'var(--radius-md)',
          cursor: 'pointer',
          transition: 'all 0.2s ease',
          zIndex: 1,
        }}
        onMouseOver={(e) => {
          e.currentTarget.style.transform = 'translateY(-2px)';
          e.currentTarget.style.boxShadow = '0 8px 24px rgba(59, 130, 246, 0.3)';
        }}
        onMouseOut={(e) => {
          e.currentTarget.style.transform = 'translateY(0)';
          e.currentTarget.style.boxShadow = 'none';
        }}
      >
        Open Dashboard
      </button>

      <p style={{
        marginTop: '16px',
        fontSize: '0.72rem',
        color: 'var(--text-muted)',
        fontFamily: 'var(--font-mono)',
        zIndex: 1,
      }}>
        SIH26106 • Forensic Intelligence Engine
      </p>
    </div>
  );
}
