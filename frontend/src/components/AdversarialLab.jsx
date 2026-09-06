import React, { useState } from 'react';
import { Zap, ShieldCheck, ShieldAlert, Play, RefreshCw, X, Crosshair } from 'lucide-react';

export default function AdversarialLab({ isOpen, onClose, onTestCompleted }) {
  const [strategy, setStrategy] = useState('business_routine');
  const [customPrompt, setCustomPrompt] = useState('');
  const [isRunning, setIsRunning] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  if (!isOpen) return null;

  const strategies = [
    {
      id: 'business_routine',
      name: 'Business Routine Reconciliation',
      desc: 'Evades urgency NLP via polite supplier statement; caught by SPF fail & lookalike domain',
    },
    {
      id: 'it_compliance',
      name: 'IT Certificate Maintenance',
      desc: 'Evades alarm filters using IT routine maintenance; caught by Cyrillic homoglyph',
    },
    {
      id: 'quishing_statement',
      name: 'EPFO HR Benefits Quishing',
      desc: 'Embeds payload in QR access code; caught by decoded barcode destination & lookalike',
    },
    {
      id: 'executive_whaling',
      name: 'Executive Whaling Impersonation',
      desc: 'Calm CEO correspondence; caught by display name spoof and Reply-To mismatch',
    },
  ];

  const handleRunTest = async () => {
    setIsRunning(true);
    setError(null);
    try {
      const response = await fetch('/adversarial/run', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          strategy: strategy,
          custom_prompt: customPrompt || undefined,
        }),
      });

      if (!response.ok) {
        throw new Error(`Server returned HTTP ${response.status}`);
      }

      const data = await response.json();
      setResult(data);
      if (onTestCompleted && data.record) {
        onTestCompleted(data.record);
      }
    } catch (err) {
      setError(err.message || 'Adversarial simulation failed');
    } finally {
      setIsRunning(false);
    }
  };

  return (
    <div className="modal-overlay">
      <div className="modal-card" style={{ maxWidth: '780px' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '20px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <div
              style={{
                width: '36px',
                height: '36px',
                borderRadius: '8px',
                background: 'rgba(168, 85, 247, 0.15)',
                color: '#c084fc',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
              }}
            >
              <Zap size={20} />
            </div>
            <div>
              <h2 style={{ fontSize: '1.2rem', fontFamily: 'var(--font-display)', color: '#fff' }}>
                Module 7: Adversarial Red-Team Simulator
              </h2>
              <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
                Test TraceShield's multi-layered forensic architecture against evasion attacks
              </p>
            </div>
          </div>

          <button
            onClick={onClose}
            style={{
              background: 'transparent',
              border: 'none',
              color: 'var(--text-muted)',
              cursor: 'pointer',
            }}
          >
            <X size={20} />
          </button>
        </div>

        {/* Strategy Picker */}
        <div style={{ marginBottom: '20px' }}>
          <label style={{ display: 'block', fontSize: '0.8rem', fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)', textTransform: 'uppercase', marginBottom: '10px' }}>
            Select AI Evasion Strategy
          </label>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px' }}>
            {strategies.map((strat) => (
              <div
                key={strat.id}
                onClick={() => setStrategy(strat.id)}
                style={{
                  padding: '12px',
                  borderRadius: 'var(--radius-md)',
                  background: strategy === strat.id ? 'rgba(168, 85, 247, 0.12)' : 'var(--bg-secondary)',
                  border: `1px solid ${strategy === strat.id ? '#c084fc' : 'var(--border-subtle)'}`,
                  cursor: 'pointer',
                  transition: 'all 0.2s ease',
                }}
              >
                <div style={{ fontWeight: '600', fontSize: '0.86rem', color: strategy === strat.id ? '#c084fc' : 'var(--text-primary)', marginBottom: '4px' }}>
                  {strat.name}
                </div>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', lineHeight: '1.3' }}>
                  {strat.desc}
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Launch Button */}
        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '12px', marginBottom: '20px' }}>
          <button className="btn btn-outline" onClick={onClose}>
            Close
          </button>
          <button
            className="btn btn-primary"
            style={{ background: 'linear-gradient(135deg, #a855f7 0%, #6366f1 100%)', color: '#fff' }}
            onClick={handleRunTest}
            disabled={isRunning}
          >
            {isRunning ? (
              <>
                <RefreshCw size={15} className="spin" />
                Synthesizing & Inspecting...
              </>
            ) : (
              <>
                <Crosshair size={15} />
                Launch Evasion Test
              </>
            )}
          </button>
        </div>

        {/* Error message */}
        {error && (
          <div style={{ padding: '12px', background: 'var(--threat-high-bg)', border: '1px solid var(--threat-high)', borderRadius: 'var(--radius-md)', color: 'var(--threat-high)', fontSize: '0.85rem', marginBottom: '16px' }}>
            {error}
          </div>
        )}

        {/* Test Result Display */}
        {result && (
          <div
            style={{
              background: 'var(--bg-secondary)',
              border: `1px solid ${result.generated_sample_caught ? 'var(--threat-high)' : 'var(--threat-med)'}`,
              borderRadius: 'var(--radius-md)',
              padding: '16px',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '10px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                {result.generated_sample_caught ? (
                  <ShieldAlert size={20} style={{ color: 'var(--threat-high)' }} />
                ) : (
                  <ShieldCheck size={20} style={{ color: 'var(--threat-med)' }} />
                )}
                <span style={{ fontWeight: 'bold', fontSize: '0.92rem', color: '#fff' }}>
                  {result.generated_sample_caught ? 'Evasion Neutralized (Sample Caught)' : 'Flagged for Human Review'}
                </span>
              </div>

              <span className={`badge-tier ${result.risk_tier?.toLowerCase() || 'high'}`}>
                Score: {result.final_risk_score} / 100 ({result.risk_tier})
              </span>
            </div>

            <div style={{ fontSize: '0.84rem', color: 'var(--text-secondary)', lineHeight: '1.5', marginBottom: '12px' }}>
              {result.notes}
            </div>

            {result.detected_layers && result.detected_layers.length > 0 && (
              <div>
                <div style={{ fontSize: '0.75rem', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '6px' }}>
                  Forensic Layers That Neutralized Evasion:
                </div>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
                  {result.detected_layers.map((layer, i) => (
                    <span
                      key={i}
                      style={{
                        padding: '3px 8px',
                        background: 'rgba(255, 255, 255, 0.05)',
                        border: '1px solid var(--border-light)',
                        borderRadius: 'var(--radius-sm)',
                        fontSize: '0.75rem',
                        fontFamily: 'var(--font-mono)',
                        color: 'var(--accent-cyan)',
                      }}
                    >
                      {layer}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
