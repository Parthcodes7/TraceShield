import React from 'react';
import { Shield, Activity, UploadCloud, History, Zap, Server } from 'lucide-react';

export default function HeaderNav({
  backendHealth,
  onOpenUpload,
  onOpenHistory,
  onOpenAdversarial,
  onOpenBatch,
}) {
  const isHealthy = backendHealth?.status === 'healthy';
  const caps = backendHealth?.capabilities || {};

  return (
    <header className="header-nav">
      <div className="nav-inner">
        <div className="logo-group">
          <div className="logo-shield">
            <Shield size={22} />
          </div>
          <div>
            <div className="logo-title">
              Trace<span>Shield</span>
            </div>
            <div className="logo-subtitle">SIH26106 • Forensic Intelligence Engine</div>
          </div>
        </div>

        {/* Action Buttons */}
        <div className="nav-actions">
          <button
            className="btn btn-outline btn-sm"
            onClick={onOpenHistory}
            title="View Past Investigations"
          >
            <History size={16} />
            History Log
          </button>

          <button
            className="btn btn-outline btn-sm"
            onClick={onOpenAdversarial}
            style={{ borderColor: 'var(--accent-purple)', color: '#c084fc' }}
            title="Module 7: Red-Team AI Evasion Simulator"
          >
            <Zap size={16} />
            Adversarial Lab
          </button>

          <button className="btn btn-primary btn-sm" onClick={onOpenUpload}>
            <UploadCloud size={16} />
            Inspect Email
          </button>
        </div>
      </div>
    </header>
  );
}
