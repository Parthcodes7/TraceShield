import React, { useRef, useState, useEffect } from 'react';
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
import { Canvas, useFrame } from '@react-three/fiber';
import { OrbitControls, MeshDistortMaterial, Float } from '@react-three/drei';
import * as THREE from 'three';

function HolographicCore({ score, color }) {
  const group = useRef();
  
  // Speed is higher if score is high
  const speed = score > 60 ? 4 : (score > 30 ? 2 : 1);
  const distort = score > 60 ? 0.6 : 0.2;

  useFrame((state, delta) => {
    if (group.current) {
      group.current.rotation.y += delta * (speed * 0.5);
      group.current.rotation.z += delta * (speed * 0.2);
    }
  });

  return (
    <group ref={group}>
      <Float speed={speed} rotationIntensity={0.5} floatIntensity={1}>
        <mesh>
          <sphereGeometry args={[1.5, 64, 64]} />
          <MeshDistortMaterial 
            color="#080c14"
            emissive={color}
            emissiveIntensity={1.5}
            roughness={0.2}
            metalness={0.8}
            distort={distort}
            speed={speed}
            wireframe={score > 60}
          />
        </mesh>
        
        {/* Outer containment rings */}
        <mesh rotation={[Math.PI / 2, 0, 0]}>
          <ringGeometry args={[1.8, 1.85, 64]} />
          <meshBasicMaterial color={color} transparent opacity={0.5} side={THREE.DoubleSide} />
        </mesh>
        <mesh rotation={[Math.PI / 2.5, Math.PI / 4, 0]}>
          <ringGeometry args={[2.2, 2.22, 64]} />
          <meshBasicMaterial color={color} transparent opacity={0.3} side={THREE.DoubleSide} />
        </mesh>
      </Float>
    </group>
  );
}

function TypewriterText({ text, speed = 10 }) {
  const [displayedText, setDisplayedText] = useState('');
  
  useEffect(() => {
    setDisplayedText('');
    let i = 0;
    const interval = setInterval(() => {
      setDisplayedText(text.slice(0, i));
      i++;
      if (i > text.length) clearInterval(interval);
    }, speed);
    return () => clearInterval(interval);
  }, [text, speed]);

  const highlightKeywords = (str) => {
    const keywords = ['CRITICAL ALERT', 'HIGH-RISK', 'PHISHING', 'FRAUD', 'FAILED', 'quarantine', 'blocking', 'threat', 'spoofing'];
    let result = str;
    keywords.forEach(kw => {
      const regex = new RegExp(`(${kw})`, 'gi');
      result = result.replace(regex, '<span style="color: #ff3344; font-weight: bold; text-shadow: 0 0 5px #ff3344;">$1</span>');
    });
    const passKeywords = ['Verified', 'Low Risk', 'intact', 'authorized', 'safe'];
    passKeywords.forEach(kw => {
      const regex = new RegExp(`(${kw})`, 'gi');
      result = result.replace(regex, '<span style="color: #00f0ff; font-weight: bold; text-shadow: 0 0 5px #00f0ff;">$1</span>');
    });
    return result;
  };

  return <span dangerouslySetInnerHTML={{ __html: highlightKeywords(displayedText) }} />;
}

function ThreatIndicator({ reason }) {
  const [showTooltip, setShowTooltip] = useState(false);
  
  let explanation = "Suspicious anomaly deviating from secure communication protocols.";
  if (reason.includes("SPF")) explanation = "The sender's IP address is not authorized by the domain owner. Highly indicative of an offshore server spoofing the brand.";
  if (reason.includes("DMARC")) explanation = "The domain enforces strict anti-spoofing policies, but this email failed alignment, proving it is a forged payload.";
  if (reason.includes("Reply-To")) explanation = "The attacker is spoofing the 'From' address to look trusted, while secretly routing your replies to their own shadow inbox.";
  if (reason.includes("short relay")) explanation = "Legitimate enterprise emails pass through multiple verifiable routing hops. This email was directly injected, bypassing origin tracking.";
  if (reason.includes("urgency trigger")) explanation = "Phishing attacks use urgency triggers ('URGENT', 'Action Required') to induce panic, bypassing the victim's critical thinking.";

  return (
    <div 
      className="reason-tag threat" 
      style={{ position: 'relative', cursor: 'help' }}
      onMouseEnter={() => setShowTooltip(true)}
      onMouseLeave={() => setShowTooltip(false)}
    >
      <XCircle size={15} style={{ flexShrink: 0, marginTop: '2px' }} />
      <span>{reason}</span>
      <Info size={14} style={{ marginLeft: 'auto', color: 'var(--text-muted)' }} />
      
      {showTooltip && (
        <div style={{
          position: 'absolute', bottom: '100%', left: '50%', transform: 'translateX(-50%)',
          width: '280px', background: 'var(--bg-secondary)', border: '1px solid var(--accent-purple)',
          boxShadow: '0 5px 15px rgba(0,0,0,0.5)', padding: '10px', borderRadius: '8px',
          zIndex: 100, marginBottom: '8px', color: 'var(--text-primary)', fontSize: '0.8rem',
          lineHeight: '1.4', fontFamily: 'var(--font-main)', textTransform: 'none'
        }}>
          <strong style={{ color: 'var(--accent-purple)', display: 'block', marginBottom: '4px' }}>
            <Sparkles size={12} style={{ marginRight: '4px', display: 'inline-block', verticalAlign: 'middle' }} />
            XAI Threat Translation
          </strong>
          {explanation}
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

      <div style={{ display: 'grid', gridTemplateColumns: '220px 1fr', gap: '24px', alignItems: 'center' }}>
        {/* 3D Holographic Threat Core */}
        <div>
          <div className="gauge-wrapper" style={{ width: '220px', height: '220px', position: 'relative' }}>
            <div style={{ position: 'absolute', top: 0, left: 0, width: '100%', height: '100%', zIndex: 1 }}>
              <Canvas camera={{ position: [0, 0, 5], fov: 45 }}>
                <React.Suspense fallback={null}>
                  <ambientLight intensity={0.5} />
                  <pointLight position={[10, 10, 10]} intensity={1} color={strokeColor} />
                  <HolographicCore score={score} color={strokeColor} />
                  <OrbitControls enableZoom={false} enablePan={false} autoRotate={false} />
                </React.Suspense>
              </Canvas>
            </div>
            <div className="gauge-center-text" style={{ zIndex: 2, pointerEvents: 'none' }}>
              <div className="gauge-score" style={{ color: strokeColor, textShadow: `0 0 10px ${strokeColor}` }}>
                {score}
              </div>
              <div className="gauge-score-sub" style={{ textShadow: '0 0 5px #000' }}>RISK INDEX</div>
            </div>
          </div>
        </div>

        {/* Executive Summary & Confidence */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', height: '100%', justifyContent: 'center' }}>
          
          <div style={{
            background: 'linear-gradient(145deg, rgba(16, 24, 39, 0.9) 0%, rgba(30, 20, 50, 0.9) 100%)',
            border: '1px solid rgba(139, 92, 246, 0.4)',
            borderRadius: 'var(--radius-lg)',
            padding: '16px 20px',
            boxShadow: '0 0 15px rgba(139, 92, 246, 0.1)',
            position: 'relative',
            overflow: 'hidden'
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '12px' }}>
              <Bot size={18} style={{ color: 'var(--accent-cyan)' }} />
              <h3 style={{ fontSize: '0.9rem', color: 'var(--accent-cyan)', textTransform: 'uppercase', fontFamily: 'var(--font-mono)' }}>
                AI Executive Briefing
              </h3>
            </div>
            <div style={{ fontSize: '0.92rem', lineHeight: '1.6', color: 'var(--text-primary)', minHeight: '80px', fontFamily: 'var(--font-mono)' }}>
              <TypewriterText text={scoring.llm_summary} speed={15} />
              <span className="cursor-blink" style={{ display: 'inline-block', width: '8px', height: '15px', background: 'var(--accent-cyan)', verticalAlign: 'middle', marginLeft: '4px', animation: 'blink 1s step-end infinite' }}></span>
            </div>
          </div>

          <div className="confidence-box" style={{ margin: 0, display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '12px 16px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <span className="confidence-label">Calibration Engine</span>
              <Sparkles size={14} style={{ color: 'var(--text-muted)' }} />
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
