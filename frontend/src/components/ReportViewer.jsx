import React, { useState, useRef } from 'react';
import {
  FileText,
  Download,
  Terminal,
  QrCode,
  Paperclip,
  CheckSquare,
  Hash,
  AlertCircle,
  Copy,
  ExternalLink,
  Network,
  Sparkles,
} from 'lucide-react';
import { Canvas, useFrame } from '@react-three/fiber';
import { OrbitControls, Float, Text } from '@react-three/drei';
import * as THREE from 'three';

function TopologyNode({ position, label, status, delay = 0 }) {
  const mesh = useRef();
  
  useFrame((state) => {
    if (mesh.current) {
      mesh.current.position.y = position[1] + Math.sin(state.clock.elapsedTime + delay) * 0.2;
    }
  });

  let color = '#3b82f6'; // default blue
  let emissive = '#6366f1';
  if (status === 'fail') {
    color = '#ff3344';
    emissive = '#ff0000';
  } else if (status === 'pass') {
    color = '#00e599';
    emissive = '#00ff88';
  }

  return (
    <group position={position} ref={mesh}>
      <mesh>
        <sphereGeometry args={[0.4, 32, 32]} />
        <meshStandardMaterial 
          color={color} 
          emissive={emissive} 
          emissiveIntensity={status === 'fail' ? 1.5 : 0.8} 
          wireframe={status === 'fail'}
        />
      </mesh>
      {/* Node Label */}
      <Text position={[0, -0.7, 0]} fontSize={0.25} color="#ffffff" anchorX="center" anchorY="middle" outlineWidth={0.02} outlineColor="#080c14">
        {label}
      </Text>
    </group>
  );
}

function TopologyGraph({ record }) {
  const hasSpfFail = record?.header_forensics?.spf_result === 'fail';
  const hasDkimFail = record?.header_forensics?.dkim_result === 'fail';
  const headerStatus = (hasSpfFail || hasDkimFail) ? 'fail' : 'pass';
  
  const hasLookalike = record?.content_analysis?.lookalike_domains_found?.length > 0;
  const contentStatus = hasLookalike ? 'fail' : 'pass';
  
  const hasBadAttach = record?.header_forensics?.attachment_hashes?.some(a => a.is_dangerous);
  const attachStatus = hasBadAttach ? 'fail' : (record?.header_forensics?.attachment_hashes?.length > 0 ? 'pass' : 'neutral');
  
  return (
    <group>
      <TopologyNode position={[0, 0, 0]} label="Email Core Payload" status="neutral" delay={0} />
      <TopologyNode position={[-2, 1.5, -1]} label="Header & Auth" status={headerStatus} delay={1} />
      <TopologyNode position={[2, 1.5, -1]} label="Content Vectors" status={contentStatus} delay={2} />
      <TopologyNode position={[0, -2, 1]} label="MIME Attachments" status={attachStatus} delay={3} />
      <TopologyNode position={[0, 1, 2]} label="Origin Routing" status="pass" delay={1.5} />
      
      {/* Abstract connection lines (simple thin cylinders) */}
      <mesh position={[-1, 0.75, -0.5]} rotation={[0, -0.5, 0.8]}>
        <cylinderGeometry args={[0.02, 0.02, 2.5]} />
        <meshBasicMaterial color="#3b82f6" transparent opacity={0.3} />
      </mesh>
      <mesh position={[1, 0.75, -0.5]} rotation={[0, 0.5, -0.8]}>
        <cylinderGeometry args={[0.02, 0.02, 2.5]} />
        <meshBasicMaterial color="#3b82f6" transparent opacity={0.3} />
      </mesh>
      <mesh position={[0, -1, 0.5]} rotation={[0.5, 0, 0]}>
        <cylinderGeometry args={[0.02, 0.02, 2.5]} />
        <meshBasicMaterial color="#3b82f6" transparent opacity={0.3} />
      </mesh>
      <mesh position={[0, 0.5, 1]} rotation={[-1, 0, 0]}>
        <cylinderGeometry args={[0.02, 0.02, 2.2]} />
        <meshBasicMaterial color="#3b82f6" transparent opacity={0.3} />
      </mesh>
    </group>
  );
}

export default function ReportViewer({ record, onDownloadPdf, isDownloadingPdf }) {
  const [activeTab, setActiveTab] = useState('headers');
  const [copiedHash, setCopiedHash] = useState(false);

  if (!record) return null;

  const { header_forensics, content_analysis, scoring } = record;

  const handleCopyHash = () => {
    if (record.raw_email_hash) {
      navigator.clipboard.writeText(record.raw_email_hash);
      setCopiedHash(true);
      setTimeout(() => setCopiedHash(false), 2000);
    }
  };

  return (
    <div className="card" style={{ marginTop: '24px' }}>
      <div className="card-header">
        <h2 className="card-title">
          <FileText size={20} style={{ color: 'var(--accent-cyan)' }} />
          Forensic Evidence Dossier & Chain of Custody
        </h2>

        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <button
            className="btn btn-primary btn-sm"
            onClick={onDownloadPdf}
            disabled={isDownloadingPdf}
          >
            <Download size={15} />
            {isDownloadingPdf ? 'Compiling PDF...' : 'Download Forensic PDF Dossier'}
          </button>
        </div>
      </div>

      {/* Chain of Custody Bar */}
      <div
        style={{
          background: 'var(--bg-secondary)',
          border: '1px solid var(--border-subtle)',
          borderRadius: 'var(--radius-md)',
          padding: '12px 16px',
          marginBottom: '20px',
          display: 'flex',
          flexWrap: 'wrap',
          alignItems: 'center',
          justifyContent: 'space-between',
          gap: '12px',
          fontFamily: 'var(--font-mono)',
          fontSize: '0.78rem',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <Hash size={14} style={{ color: 'var(--accent-cyan)' }} />
          <span style={{ color: 'var(--text-muted)' }}>SHA-256 Digest:</span>
          <span style={{ color: 'var(--accent-cyan)' }}>
            {record.raw_email_hash
              ? `${record.raw_email_hash.slice(0, 16)}...${record.raw_email_hash.slice(-16)}`
              : 'N/A'}
          </span>
          <button
            onClick={handleCopyHash}
            style={{
              background: 'transparent',
              border: 'none',
              color: 'var(--text-muted)',
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
            }}
            title="Copy Full SHA-256 Hash"
          >
            <Copy size={13} />
          </button>
          {copiedHash && (
            <span style={{ color: 'var(--threat-low)', fontSize: '0.7rem' }}>
              Copied!
            </span>
          )}
        </div>

        <div style={{ color: 'var(--text-muted)' }}>
          Record ID: <span style={{ color: 'var(--text-primary)' }}>{record.email_id?.slice(0, 13)}</span>
          {' • '}
          Analysis Time:{' '}
          <span style={{ color: 'var(--text-primary)' }}>
            {record.analysis_duration_ms ? `${record.analysis_duration_ms} ms` : 'Instant'}
          </span>
        </div>
      </div>

      {/* Tabs */}
      <div className="evidence-tabs">
        <button
          className={`evidence-tab-btn ${activeTab === 'headers' ? 'active' : ''}`}
          onClick={() => setActiveTab('headers')}
        >
          <Terminal size={15} />
          Protocol & Headers
        </button>

        <button
          className={`evidence-tab-btn ${activeTab === 'vectors' ? 'active' : ''}`}
          onClick={() => setActiveTab('vectors')}
        >
          <QrCode size={15} />
          Content, Homoglyphs & QR
        </button>

        <button
          className={`evidence-tab-btn ${activeTab === 'attachments' ? 'active' : ''}`}
          onClick={() => setActiveTab('attachments')}
        >
          <Paperclip size={15} />
          Attachments ({header_forensics?.attachment_hashes?.length || 0})
        </button>

        <button
          className={`evidence-tab-btn ${activeTab === 'topology' ? 'active' : ''}`}
          onClick={() => setActiveTab('topology')}
        >
          <Network size={15} />
          3D Threat Topology
        </button>

        <button
          className={`evidence-tab-btn ${activeTab === 'remediation' ? 'active' : ''}`}
          onClick={() => setActiveTab('remediation')}
        >
          <CheckSquare size={15} />
          Remediation Actions ({scoring?.recommendations?.length || 0})
        </button>
      </div>

      {/* Tab 5: 3D Threat Topology */}
      {activeTab === 'topology' && (
        <div style={{ width: '100%', height: '400px', background: '#020408', borderRadius: '12px', overflow: 'hidden', position: 'relative' }}>
          <Canvas camera={{ position: [0, 2, 8], fov: 45 }}>
            <React.Suspense fallback={null}>
              <ambientLight intensity={0.5} />
              <pointLight position={[10, 10, 10]} intensity={1} color="#00f0ff" />
              <TopologyGraph record={record} />
              <OrbitControls enableZoom={true} autoRotate autoRotateSpeed={1} />
            </React.Suspense>
          </Canvas>
          <div style={{ position: 'absolute', top: '15px', left: '15px', color: 'rgba(255,255,255,0.7)', fontSize: '0.8rem', fontFamily: 'var(--font-mono)' }}>
            [INTERACTIVE: DRAG TO ROTATE]
          </div>
        </div>
      )}

      {/* Tab 1: Protocol & Headers */}
      {activeTab === 'headers' && (
        <div>
          {/* Core Protocol Status Badges */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '12px', marginBottom: '20px' }}>
            <div className="geo-meta-item">
              <div className="geo-meta-label">SPF Record Validation</div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span
                  className={`status-pill ${
                    header_forensics?.spf_result === 'pass'
                      ? 'pass'
                      : header_forensics?.spf_result === 'fail'
                      ? 'fail'
                      : 'warn'
                  }`}
                >
                  {header_forensics?.spf_result || 'None'}
                </span>
                <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                  RFC 7208 Alignment
                </span>
              </div>
            </div>

            <div className="geo-meta-item">
              <div className="geo-meta-label">DKIM Cryptographic Signature</div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span
                  className={`status-pill ${
                    header_forensics?.dkim_result === 'pass'
                      ? 'pass'
                      : header_forensics?.dkim_result === 'fail'
                      ? 'fail'
                      : 'warn'
                  }`}
                >
                  {header_forensics?.dkim_result || 'None'}
                </span>
                <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                  RSA/Ed25519 Key Check
                </span>
              </div>
            </div>

            <div className="geo-meta-item">
              <div className="geo-meta-label">DMARC Policy Enforcement</div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span
                  className={`status-pill ${
                    header_forensics?.dmarc_result === 'pass'
                      ? 'pass'
                      : header_forensics?.dmarc_result === 'fail'
                      ? 'fail'
                      : 'warn'
                  }`}
                >
                  {header_forensics?.dmarc_result || 'None'}
                </span>
                <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                  Authoritative DNS Query
                </span>
              </div>
            </div>
          </div>

          {/* XAI Insights Panel */}
          <div style={{
            background: 'linear-gradient(145deg, rgba(16, 24, 39, 0.9) 0%, rgba(30, 20, 50, 0.9) 100%)',
            border: '1px solid rgba(139, 92, 246, 0.4)',
            borderRadius: 'var(--radius-lg)',
            padding: '16px 20px',
            marginBottom: '24px',
            boxShadow: '0 0 15px rgba(139, 92, 246, 0.1)',
            position: 'relative',
            overflow: 'hidden'
          }}>
            <div style={{
              position: 'absolute', top: '-10px', left: '-10px', width: '40px', height: '40px', 
              background: 'var(--accent-purple)', filter: 'blur(30px)', opacity: 0.5
            }} />
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '12px' }}>
              <Sparkles size={16} style={{ color: 'var(--accent-purple)' }} />
              <h3 style={{ fontSize: '0.9rem', color: 'var(--accent-purple)', textTransform: 'uppercase', fontFamily: 'var(--font-mono)' }}>
                Explainable AI (XAI) Protocol Insight
              </h3>
            </div>
            <p style={{ fontSize: '0.9rem', color: 'var(--text-primary)', lineHeight: '1.6', margin: 0 }}>
              {header_forensics?.dmarc_result === 'fail' 
                ? "The sender's domain lacks DMARC enforcement policies. This critical vulnerability allows attackers to flawlessly spoof the brand's 'From' address, as receiving mail servers have no instructions to reject unauthorized senders."
                : header_forensics?.spf_result === 'fail' 
                ? "The origin IP address is not authorized to send emails on behalf of this domain (SPF failure). This is a strong indicator of an infrastructure-level spoofing attack."
                : "Cryptographic signatures (DKIM) and alignment policies (SPF/DMARC) are intact. The message payload originated from authorized infrastructure."}
            </p>
          </div>

          {/* Email Headers Meta Table */}
          <div className="forensic-table-wrap">
            <table className="forensic-table">
              <thead>
                <tr>
                  <th style={{ width: '180px' }}>RFC Header Parameter</th>
                  <th>Extracted Value</th>
                  <th style={{ width: '130px' }}>Integrity Check</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td>From Header</td>
                  <td style={{ fontFamily: 'var(--font-mono)' }}>
                    {header_forensics?.from_header || 'N/A'}
                    {header_forensics?.display_name_spoof && (
                        <div style={{ marginTop: '8px', padding: '8px', background: 'rgba(139, 92, 246, 0.1)', borderLeft: '3px solid var(--accent-purple)', borderRadius: '4px', fontSize: '0.8rem', color: 'var(--text-primary)', fontFamily: 'var(--font-main)' }}>
                          <strong style={{ color: 'var(--accent-purple)', display: 'flex', alignItems: 'center', gap: '4px', marginBottom: '4px' }}><Sparkles size={12}/> AI Verdict:</strong>
                          The display name was intentionally altered to impersonate a trusted brand, overriding the actual suspicious email address hidden behind it.
                        </div>
                    )}
                  </td>
                  <td>
                    {header_forensics?.display_name_spoof ? (
                      <span className="status-pill fail">Brand Spoof</span>
                    ) : (
                      <span className="status-pill pass">Verified</span>
                    )}
                  </td>
                </tr>

                <tr>
                  <td>Return-Path (Envelope)</td>
                  <td style={{ fontFamily: 'var(--font-mono)' }}>
                    {header_forensics?.return_path || 'N/A'}
                  </td>
                  <td>
                    <span className="status-pill pass">Parsed</span>
                  </td>
                </tr>

                <tr>
                  <td>Reply-To Alignment</td>
                  <td>
                    {header_forensics?.reply_to_mismatch ? (
                      <div>
                        <span style={{ color: 'var(--threat-high)' }}>
                          ⚠️ Discrepancy detected between sender and reply destination!
                        </span>
                        <div style={{ marginTop: '8px', padding: '8px', background: 'rgba(139, 92, 246, 0.1)', borderLeft: '3px solid var(--accent-purple)', borderRadius: '4px', fontSize: '0.8rem', color: 'var(--text-primary)' }}>
                          <strong style={{ color: 'var(--accent-purple)', display: 'flex', alignItems: 'center', gap: '4px', marginBottom: '4px' }}><Sparkles size={12}/> AI Verdict:</strong>
                          The attacker is spoofing a trusted entity in the 'From' header, but secretly routing your replies to their own controlled mailbox.
                        </div>
                      </div>
                    ) : (
                      <span style={{ color: 'var(--threat-low)' }}>
                        Aligned with sender mailbox
                      </span>
                    )}
                  </td>
                  <td>
                    {header_forensics?.reply_to_mismatch ? (
                      <span className="status-pill fail">Mismatch</span>
                    ) : (
                      <span className="status-pill pass">Aligned</span>
                    )}
                  </td>
                </tr>

                <tr>
                  <td>Subject Line</td>
                  <td>{header_forensics?.subject_header || 'No subject header'}</td>
                  <td>
                    <span className="status-pill pass">Inspected</span>
                  </td>
                </tr>

                <tr>
                  <td>Transmission Timestamp</td>
                  <td>{header_forensics?.date_header || 'N/A'}</td>
                  <td>
                    <span className="status-pill pass">Logged</span>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>

          {/* Relay Chain */}
          {header_forensics?.relay_chain && header_forensics.relay_chain.length > 0 && (
            <div style={{ marginTop: '20px' }}>
              <h3 style={{ fontSize: '0.85rem', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '10px' }}>
                Reverse Mail Relay Transmission Chain ({header_forensics.relay_chain.length} Hops)
              </h3>
              <div className="forensic-table-wrap">
                <table className="forensic-table">
                  <thead>
                    <tr>
                      <th style={{ width: '60px' }}>Hop</th>
                      <th>Origin Transfer Agent (From Host)</th>
                      <th>Receiving MTA (By Host)</th>
                      <th>Relay Timestamp</th>
                    </tr>
                  </thead>
                  <tbody>
                    {header_forensics.relay_chain.map((hop, i) => (
                      <tr key={i}>
                        <td style={{ fontFamily: 'var(--font-mono)', fontWeight: 'bold' }}>
                          #{hop.hop}
                        </td>
                        <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem' }}>
                          {hop.from_host}
                        </td>
                        <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem' }}>
                          {hop.by_host}
                        </td>
                        <td style={{ fontSize: '0.78rem', color: 'var(--text-secondary)' }}>
                          {hop.timestamp}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Tab 2: Content, Homoglyphs & QR */}
      {activeTab === 'vectors' && (
        <div>
          {/* Lookalike & Typosquatted Domains */}
          <div style={{ marginBottom: '20px' }}>
            <h3 style={{ fontSize: '0.85rem', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '8px' }}>
              Typosquatting & Lookalike Domain Analysis (Levenshtein Distance ≤ 2)
            </h3>
            {content_analysis?.lookalike_domains_found &&
            content_analysis.lookalike_domains_found.length > 0 ? (
              <div className="forensic-table-wrap">
                <table className="forensic-table">
                  <thead>
                    <tr>
                      <th>Targeted Legitimate Brand</th>
                      <th>Deception Vector</th>
                      <th>Threat Verdict</th>
                    </tr>
                  </thead>
                  <tbody>
                    {content_analysis.lookalike_domains_found.map((dom, i) => (
                      <tr key={i}>
                        <td style={{ fontWeight: 'bold', color: 'var(--accent-cyan)' }}>
                          {dom}
                        </td>
                        <td>Lookalike domain impersonating authentic banking / institutional portal</td>
                        <td>
                          <span className="status-pill fail">Deceptive Typosquat</span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <div style={{ fontSize: '0.85rem', color: 'var(--text-muted)', padding: '10px 0' }}>
                No lookalike or typosquatted brand domains identified.
              </div>
            )}
          </div>

          {/* Unicode IDN Homoglyph Table */}
          <div style={{ marginBottom: '20px' }}>
            <h3 style={{ fontSize: '0.85rem', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '8px' }}>
              Unicode IDN Homoglyph / Punycode Unmasking
            </h3>
            {content_analysis?.homoglyph_domains_found &&
            content_analysis.homoglyph_domains_found.length > 0 ? (
              <div className="forensic-table-wrap">
                <table className="forensic-table">
                  <thead>
                    <tr>
                      <th>Visible Displayed Domain</th>
                      <th>Punycode Decoded ASCII</th>
                      <th>Suspicion Status</th>
                    </tr>
                  </thead>
                  <tbody>
                    {content_analysis.homoglyph_domains_found.map((hg, i) => (
                      <tr key={i}>
                        <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.9rem' }}>
                          {hg.visible_domain}
                        </td>
                        <td style={{ fontFamily: 'var(--font-mono)', color: 'var(--threat-high)' }}>
                          {hg.decoded_ascii}
                        </td>
                        <td>
                          {hg.suspicious ? (
                            <span className="status-pill fail">Cyrillic / IDN Spoof</span>
                          ) : (
                            <span className="status-pill pass">Standard ASCII</span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <div style={{ fontSize: '0.85rem', color: 'var(--text-muted)', padding: '10px 0' }}>
                No non-Latin Unicode homoglyph characters unmasked.
              </div>
            )}
          </div>

          {/* QR Quishing Detections */}
          <div style={{ marginBottom: '20px' }}>
            <h3 style={{ fontSize: '0.85rem', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '8px' }}>
              Decoded QR Code "Quishing" Attack Vectors
            </h3>
            {content_analysis?.qr_codes_found &&
            content_analysis.qr_codes_found.length > 0 ? (
              <div className="forensic-table-wrap">
                <table className="forensic-table">
                  <thead>
                    <tr>
                      <th>Decoded Embedded QR Destination</th>
                      <th>Lookalike Check</th>
                      <th>Reputation Flag</th>
                    </tr>
                  </thead>
                  <tbody>
                    {content_analysis.qr_codes_found.map((qr, i) => (
                      <tr key={i}>
                        <td style={{ fontFamily: 'var(--font-mono)', color: 'var(--threat-high)' }}>
                          {qr.decoded_url}
                        </td>
                        <td>
                          {qr.lookalike_check ? (
                            <span className="status-pill fail">Typosquat Trigger</span>
                          ) : (
                            <span className="status-pill pass">Clean</span>
                          )}
                        </td>
                        <td>
                          {qr.reputation_flag ? (
                            <span className="status-pill fail">Malicious Barcode</span>
                          ) : (
                            <span className="status-pill pass">Normal</span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <div style={{ fontSize: '0.85rem', color: 'var(--text-muted)', padding: '10px 0' }}>
                No embedded QR barcodes decoded in message attachments.
              </div>
            )}
          </div>
        </div>
      )}

      {/* Tab 3: Attachment Chain of Custody */}
      {activeTab === 'attachments' && (
        <div>
          {header_forensics?.attachment_hashes &&
          header_forensics.attachment_hashes.length > 0 ? (
            <div className="forensic-table-wrap">
              <table className="forensic-table">
                <thead>
                  <tr>
                    <th>Attachment Filename</th>
                    <th>File Size</th>
                    <th>Cryptographic SHA-256 Evidence Digest</th>
                    <th>Weaponization Risk</th>
                  </tr>
                </thead>
                <tbody>
                  {header_forensics.attachment_hashes.map((att, i) => (
                    <tr key={i}>
                      <td style={{ fontWeight: '600' }}>{att.filename}</td>
                      <td>{(att.size_bytes / 1024).toFixed(1)} KB</td>
                      <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.78rem', color: 'var(--accent-cyan)' }}>
                        {att.sha256}
                      </td>
                      <td>
                        {att.is_dangerous ? (
                          <span className="status-pill fail">Executable / Script</span>
                        ) : (
                          <span className="status-pill pass">Safe MIME</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div style={{ textAlign: 'center', padding: '30px', color: 'var(--text-muted)' }}>
              No binary or document attachments present in message MIME payload.
            </div>
          )}
        </div>
      )}

      {/* Tab 4: Incident Remediation */}
      {activeTab === 'remediation' && (
        <div>
          <div style={{ marginBottom: '16px', fontSize: '0.88rem', color: 'var(--text-secondary)' }}>
            Automated defensive containment actions tailored to the verified threat indicators:
          </div>
          {scoring?.recommendations && scoring.recommendations.length > 0 ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
              {scoring.recommendations.map((rec, i) => (
                <div
                  key={i}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '12px',
                    padding: '12px 16px',
                    background: 'var(--bg-secondary)',
                    border: '1px solid var(--border-light)',
                    borderRadius: 'var(--radius-md)',
                  }}
                >
                  <span
                    style={{
                      width: '24px',
                      height: '24px',
                      borderRadius: '50%',
                      background: 'rgba(0, 240, 255, 0.1)',
                      color: 'var(--accent-cyan)',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      fontFamily: 'var(--font-mono)',
                      fontSize: '0.75rem',
                      fontWeight: 'bold',
                      flexShrink: 0,
                    }}
                  >
                    {i + 1}
                  </span>
                  <span style={{ fontSize: '0.88rem', color: 'var(--text-primary)' }}>
                    {rec}
                  </span>
                </div>
              ))}
            </div>
          ) : (
            <div style={{ color: 'var(--text-muted)', fontStyle: 'italic' }}>
              Standard hygiene recommendations. No critical emergency containment required.
            </div>
          )}
        </div>
      )}
    </div>
  );
}
