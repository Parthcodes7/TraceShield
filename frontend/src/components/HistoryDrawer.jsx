import React, { useState, useEffect } from 'react';
import { History, X, RefreshCw, ChevronRight, ShieldAlert } from 'lucide-react';

export default function HistoryDrawer({ isOpen, onClose, onSelectRecord }) {
  const [records, setRecords] = useState([]);
  const [filter, setFilter] = useState('ALL');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    if (isOpen) {
      fetchHistory();
    }
  }, [isOpen]);

  const fetchHistory = async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await fetch('/history?limit=50');
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }
      const data = await response.json();
      setRecords(data);
    } catch (err) {
      setError(err.message || 'Failed to load history');
    } finally {
      setLoading(false);
    }
  };

  const handleSelect = async (emailId) => {
    setLoading(true);
    try {
      const response = await fetch(`/history/${emailId}`);
      if (!response.ok) throw new Error('Failed to load record details');
      const fullRecord = await response.json();
      onSelectRecord(fullRecord);
      onClose();
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  if (!isOpen) return null;

  const filtered = records.filter((r) => {
    if (filter === 'ALL') return true;
    return r.risk_tier?.toUpperCase() === filter;
  });

  return (
    <>
      <div className="drawer-backdrop" onClick={onClose} />
      <div className="drawer-panel">
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '20px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <History size={18} style={{ color: 'var(--accent-cyan)' }} />
            <h2 style={{ fontSize: '1.1rem', fontFamily: 'var(--font-display)', color: '#fff' }}>
              Forensic Investigation History
            </h2>
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
            <X size={18} />
          </button>
        </div>

        {/* Filter Pills */}
        <div style={{ display: 'flex', gap: '6px', marginBottom: '16px' }}>
          {['ALL', 'HIGH', 'MEDIUM', 'LOW'].map((f) => (
            <button
              key={f}
              onClick={() => setFilter(f)}
              style={{
                background: filter === f ? 'var(--bg-card-hover)' : 'transparent',
                border: `1px solid ${filter === f ? 'var(--accent-cyan)' : 'var(--border-subtle)'}`,
                color: filter === f ? 'var(--accent-cyan)' : 'var(--text-muted)',
                fontSize: '0.72rem',
                fontFamily: 'var(--font-mono)',
                fontWeight: '600',
                padding: '4px 10px',
                borderRadius: 'var(--radius-sm)',
                cursor: 'pointer',
              }}
            >
              {f}
            </button>
          ))}
        </div>

        {/* Records List */}
        <div style={{ flex: 1, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '8px' }}>
          {loading && records.length === 0 && (
            <div style={{ textAlign: 'center', padding: '40px', color: 'var(--text-muted)' }}>
              <RefreshCw size={20} className="spin" style={{ margin: '0 auto 10px' }} />
              Loading history records...
            </div>
          )}

          {error && (
            <div style={{ color: 'var(--threat-high)', fontSize: '0.85rem', padding: '10px' }}>
              {error}
            </div>
          )}

          {!loading && filtered.length === 0 && (
            <div style={{ textAlign: 'center', padding: '40px', color: 'var(--text-muted)', fontSize: '0.85rem' }}>
              No past records in this category.
            </div>
          )}

          {filtered.map((item) => (
            <div
              key={item.email_id}
              onClick={() => handleSelect(item.email_id)}
              style={{
                background: 'var(--bg-card)',
                border: '1px solid var(--border-subtle)',
                borderRadius: 'var(--radius-md)',
                padding: '12px',
                cursor: 'pointer',
                transition: 'all 0.2s ease',
              }}
              onMouseEnter={(e) => (e.currentTarget.style.borderColor = 'var(--accent-cyan)')}
              onMouseLeave={(e) => (e.currentTarget.style.borderColor = 'var(--border-subtle)')}
            >
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '6px' }}>
                <span className={`badge-tier ${item.risk_tier?.toLowerCase() || 'low'}`} style={{ fontSize: '0.7rem', padding: '2px 8px' }}>
                  Score: {item.risk_score ?? 0} • {item.risk_tier || 'Low'}
                </span>
                <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                  {item.analyzed_at ? new Date(item.analyzed_at).toLocaleDateString() : ''}
                </span>
              </div>

              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <div>
                  <div style={{ fontSize: '0.78rem', fontFamily: 'var(--font-mono)', color: 'var(--text-primary)' }}>
                    ID: {item.email_id.slice(0, 14)}...
                  </div>
                  <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                    IP: {item.origin_ip || 'Internal / N/A'}
                  </div>
                </div>
                <ChevronRight size={16} style={{ color: 'var(--text-muted)' }} />
              </div>
            </div>
          ))}
        </div>
      </div>
    </>
  );
}
