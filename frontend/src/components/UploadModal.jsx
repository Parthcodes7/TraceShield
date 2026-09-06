import React, { useState, useRef } from 'react';
import { UploadCloud, FileText, X, RefreshCw, FolderArchive } from 'lucide-react';

export default function UploadModal({ isOpen, onClose, onAnalysisComplete }) {
  const [tab, setTab] = useState('file'); // 'file' | 'text' | 'batch'
  const [rawText, setRawText] = useState('');
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [error, setError] = useState(null);
  const [dragActive, setDragActive] = useState(false);
  const fileInputRef = useRef(null);
  const batchInputRef = useRef(null);

  if (!isOpen) return null;

  const handleDrag = (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === 'dragenter' || e.type === 'dragover') {
      setDragActive(true);
    } else if (e.type === 'dragleave') {
      setDragActive(false);
    }
  };

  const handleDrop = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleFileUpload(e.dataTransfer.files[0]);
    }
  };

  const handleFileUpload = async (file) => {
    if (!file) return;
    setIsAnalyzing(true);
    setError(null);
    try {
      const formData = new FormData();
      formData.append('file', file);

      const response = await fetch('/analyze/file', {
        method: 'POST',
        body: formData,
      });

      if (!response.ok) {
        throw new Error(`Server returned HTTP ${response.status}`);
      }

      const record = await response.json();
      onAnalysisComplete(record);
      onClose();
    } catch (err) {
      setError(err.message || 'File analysis failed');
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handleTextSubmit = async () => {
    if (!rawText.trim()) {
      setError('Please paste raw email headers and body content.');
      return;
    }

    setIsAnalyzing(true);
    setError(null);
    try {
      const response = await fetch('/analyze/text', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ raw_email: rawText }),
      });

      if (!response.ok) {
        throw new Error(`Server returned HTTP ${response.status}`);
      }

      const record = await response.json();
      onAnalysisComplete(record);
      onClose();
    } catch (err) {
      setError(err.message || 'Text analysis failed');
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handleBatchUpload = async (e) => {
    const files = e.target.files;
    if (!files || files.length === 0) return;

    setIsAnalyzing(true);
    setError(null);
    try {
      const formData = new FormData();
      for (let i = 0; i < files.length; i++) {
        formData.append('files', files[i]);
      }

      const response = await fetch('/analyze/batch', {
        method: 'POST',
        body: formData,
      });

      if (!response.ok) {
        throw new Error(`Batch analysis failed: HTTP ${response.status}`);
      }

      const records = await response.json();
      if (records && records.length > 0) {
        onAnalysisComplete(records[0]); // Load the first one into dashboard
      }
      onClose();
    } catch (err) {
      setError(err.message || 'Batch analysis failed');
    } finally {
      setIsAnalyzing(false);
    }
  };

  return (
    <div className="modal-overlay">
      <div className="modal-card">
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '20px' }}>
          <h2 style={{ fontSize: '1.25rem', fontFamily: 'var(--font-display)', color: '#fff' }}>
            Submit Email For Forensic Intelligence Inspection
          </h2>
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

        {/* Tab Buttons */}
        <div className="evidence-tabs" style={{ marginBottom: '20px' }}>
          <button
            className={`evidence-tab-btn ${tab === 'file' ? 'active' : ''}`}
            onClick={() => setTab('file')}
          >
            <UploadCloud size={16} />
            Upload .EML File
          </button>

          <button
            className={`evidence-tab-btn ${tab === 'text' ? 'active' : ''}`}
            onClick={() => setTab('text')}
          >
            <FileText size={16} />
            Raw MIME / RFC 822 Text
          </button>

          <button
            className={`evidence-tab-btn ${tab === 'batch' ? 'active' : ''}`}
            onClick={() => setTab('batch')}
          >
            <FolderArchive size={16} />
            Batch Queue (Multi-EML)
          </button>
        </div>

        {/* Error notification */}
        {error && (
          <div style={{ padding: '12px', background: 'var(--threat-high-bg)', border: '1px solid var(--threat-high)', borderRadius: 'var(--radius-md)', color: 'var(--threat-high)', fontSize: '0.85rem', marginBottom: '16px' }}>
            {error}
          </div>
        )}

        {/* Tab Content: Single File */}
        {tab === 'file' && (
          <div>
            <div
              className={`dropzone ${dragActive ? 'active' : ''}`}
              onDragEnter={handleDrag}
              onDragLeave={handleDrag}
              onDragOver={handleDrag}
              onDrop={handleDrop}
              onClick={() => fileInputRef.current && fileInputRef.current.click()}
            >
              <input
                ref={fileInputRef}
                type="file"
                accept=".eml,.msg,message/rfc822"
                style={{ display: 'none' }}
                onChange={(e) => e.target.files && handleFileUpload(e.target.files[0])}
              />
              <UploadCloud size={42} style={{ color: 'var(--accent-cyan)', margin: '0 auto 12px' }} />
              <p style={{ fontWeight: '600', color: 'var(--text-primary)', marginBottom: '4px' }}>
                Click to browse or drag and drop raw .EML file
              </p>
              <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
                Supports standard RFC 2822 / 5322 MIME messages with attachments
              </p>
            </div>
          </div>
        )}

        {/* Tab Content: Raw Text */}
        {tab === 'text' && (
          <div>
            <textarea
              className="code-editor"
              placeholder="Paste raw email headers and body here, e.g.:&#10;Received: from mail.example.com ...&#10;From: attacker@spoofed.com&#10;Subject: Urgent Security Alert&#10;&#10;Please verify your credentials immediately..."
              value={rawText}
              onChange={(e) => setRawText(e.target.value)}
            />
            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px', marginTop: '16px' }}>
              <button className="btn btn-outline" onClick={onClose}>
                Cancel
              </button>
              <button
                className="btn btn-primary"
                onClick={handleTextSubmit}
                disabled={isAnalyzing || !rawText.trim()}
              >
                {isAnalyzing ? (
                  <>
                    <RefreshCw size={15} className="spin" />
                    Analyzing...
                  </>
                ) : (
                  'Run Forensic Inspection'
                )}
              </button>
            </div>
          </div>
        )}

        {/* Tab Content: Batch */}
        {tab === 'batch' && (
          <div>
            <div
              className="dropzone"
              onClick={() => batchInputRef.current && batchInputRef.current.click()}
            >
              <input
                ref={batchInputRef}
                type="file"
                multiple
                accept=".eml"
                style={{ display: 'none' }}
                onChange={handleBatchUpload}
              />
              <FolderArchive size={42} style={{ color: 'var(--accent-blue)', margin: '0 auto 12px' }} />
              <p style={{ fontWeight: '600', color: 'var(--text-primary)', marginBottom: '4px' }}>
                Select up to 50 .EML files for bulk triage
              </p>
              <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
                Processes queue concurrently using backend threadpool workers
              </p>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
