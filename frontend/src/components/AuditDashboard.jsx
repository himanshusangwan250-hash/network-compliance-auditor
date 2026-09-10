import React, { useState } from 'react';

const API_BASE = '/api';

// ---------------------------------------------------------------------------
// Status indicator
// ---------------------------------------------------------------------------

function StatusCell({ status }) {
  const dotClass = status === 'PASS' ? 'pass' : status === 'FAIL' ? 'fail' : 'unknown';
  return (
    <div className="status-cell">
      <span className={`status-dot ${dotClass}`} />
      <span className="status-label">{status.toLowerCase()}</span>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Circular Score Display — progress ring out of 100
// ---------------------------------------------------------------------------

function ScoreDisplay({ score, summary }) {
  const total = summary?.total ?? 0;
  const passCount = summary?.pass ?? 0;
  const failCount = summary?.fail ?? 0;
  const unknownCount = summary?.unknown ?? 0;

  // Calculate score percentage (0-100)
  const scoreValue = score ?? 0;
  const radius = 45;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (scoreValue / 100) * circumference;

  // Determine color based on score
  let scoreColor = '#1a7f5a'; // green (pass)
  if (scoreValue < 50) {
    scoreColor = '#c53030'; // red (fail)
  } else if (scoreValue < 70) {
    scoreColor = '#d69e2e'; // yellow (warning)
  }

  return (
    <div className="score-display">
      {/* Circular Progress Ring */}
      <div className="score-ring-container">
        <svg className="score-ring" viewBox="0 0 120 120">
          {/* Background circle */}
          <circle
            cx="60"
            cy="60"
            r={radius}
            fill="none"
            stroke="var(--color-border-light)"
            strokeWidth="8"
          />
          {/* Progress circle */}
          <circle
            cx="60"
            cy="60"
            r={radius}
            fill="none"
            stroke={scoreColor}
            strokeWidth="8"
            strokeDasharray={circumference}
            strokeDashoffset={strokeDashoffset}
            strokeLinecap="round"
            transform="rotate(-90 60 60)"
            className="score-ring-progress"
          />
        </svg>
        {/* Center text */}
        <div className="score-ring-text">
          <span className="score-ring-number">
            {score === null ? '—' : Math.round(scoreValue)}
          </span>
          <span className="score-ring-label">/ 100</span>
        </div>
      </div>

      {/* Summary Stats */}
      <div className="score-summary">
        <div className="score-summary-item">
          <span className="score-summary-label">Passed</span>
          <span className="score-summary-value pass">{passCount}</span>
        </div>
        <div className="score-divider" />
        <div className="score-summary-item">
          <span className="score-summary-label">Failed</span>
          <span className="score-summary-value fail">{failCount}</span>
        </div>
        {unknownCount > 0 && (
          <>
            <div className="score-divider" />
            <div className="score-summary-item">
              <span className="score-summary-label">Unknown</span>
              <span className="score-summary-value unknown">{unknownCount}</span>
            </div>
          </>
        )}
        <div className="score-divider" />
        <div className="score-summary-item">
          <span className="score-summary-label">Total</span>
          <span className="score-summary-value">{total}</span>
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Unsupported fields footnote
// ---------------------------------------------------------------------------

function UnsupportedFootnote({ fields }) {
  if (!fields || fields.length === 0) return null;
  return (
    <div className="unsupported-footnote">
      Unsupported fields — this vendor/format does not expose:{' '}
      {fields.map((f) => <code key={f}>{f}</code>).reduce((prev, curr) => [
        prev,
        ', ',
        curr,
      ])}
    </div>
  );
}

// ---------------------------------------------------------------------------
// AI panel — shows V6 primary, V4 fallback, and fusion when relevant
// ---------------------------------------------------------------------------

function AIPanel({ ai_analysis }) {
  if (!ai_analysis || ai_analysis.prediction === 'unavailable') {
    return (
      <div className="ai-panel">
        <div className="ai-label">AI Semantic Analysis</div>
        <div className="ai-value unavailable">Unavailable</div>
      </div>
    );
  }

  const { prediction, confidence, model_used, fallback_used, v6, v4, models_agree } = ai_analysis;
  const pct = ((confidence ?? 0) * 100).toFixed(1);

  // Single-model case (V6 only, high confidence)
  if (!fallback_used) {
    return (
      <div className="ai-panel">
        <div className="ai-label">AI Analysis</div>
        <div className={`ai-value ${prediction}`}>
          <span className="ai-prediction">
            {prediction.charAt(0).toUpperCase() + prediction.slice(1)}
          </span>
          <span className="ai-confidence">{pct}%</span>
        </div>
        <div className="ai-model-tag">{model_used} primary</div>
      </div>
    );
  }

  // Dual-model case (V6 + V4 fused)
  const v6Pred = v6?.prediction;
  const v6Conf = ((v6?.confidence ?? 0) * 100).toFixed(1);
  const v4Pred = v4?.prediction;
  const v4Conf = ((v4?.confidence ?? 0) * 100).toFixed(1);
  const disagree = !models_agree;

  return (
    <div className="ai-panel ai-panel--dual">
      <div className="ai-label">AI Analysis</div>

      <div className="ai-row">
        <span className="ai-model-label">V6 primary</span>
        <span className={`ai-prediction ${v6Pred}`}>
          {(v6Pred ?? '?').charAt(0).toUpperCase() + (v6Pred ?? '').slice(1)}
        </span>
        <span className="ai-confidence">{v6Conf}%</span>
      </div>

      <div className="ai-row">
        <span className="ai-model-label">V4 fallback</span>
        <span className={`ai-prediction ${v4Pred}`}>
          {(v4Pred ?? '?').charAt(0).toUpperCase() + (v4Pred ?? '').slice(1)}
        </span>
        <span className="ai-confidence">{v4Conf}%</span>
      </div>

      <div className="ai-divider" />

      <div className="ai-row ai-row--final">
        <span className="ai-model-label">Combined</span>
        <span className={`ai-prediction ${prediction}`}>
          {prediction.charAt(0).toUpperCase() + prediction.slice(1)}
        </span>
        <span className="ai-confidence">{pct}%</span>
      </div>

      {disagree && (
        <div className="ai-disagreement">⚠ Models disagree — review recommended</div>
      )}
      {!disagree && (
        <div className="ai-agreement">✓ Models agree</div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Findings table
// ---------------------------------------------------------------------------

function FindingsTable({ findings }) {
  if (!findings || findings.length === 0) {
    return <div className="no-findings">No compliance findings.</div>;
  }

  return (
    <table className="findings-table">
      <thead>
        <tr>
          <th>Rule</th>
          <th>Finding</th>
          <th>Severity</th>
          <th>Status</th>
          <th>Evidence</th>
          <th>Remediation</th>
          <th>AI Analysis</th>
        </tr>
      </thead>
      <tbody>
        {findings.map((f, i) => (
          <tr key={i}>
            <td><span className="rule-id mono">{f.rule_id}</span></td>
            <td><span className="finding-title">{f.title}</span></td>
            <td>
              <span className={`severity ${f.severity.toLowerCase()}`}>
                {f.severity}
              </span>
            </td>
            <td><StatusCell status={f.status} /></td>
            <td>
              <span className="evidence mono">{f.evidence}</span>
            </td>
            <td>
              {f.status === 'FAIL' ? (
                <span className="remediation">{f.remediation}</span>
              ) : null}
            </td>
            <td><AIPanel ai_analysis={f.ai_analysis} /></td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

// ---------------------------------------------------------------------------
// Result panel
// ---------------------------------------------------------------------------

function ResultPanel({ result, onNewAudit }) {
  const { vendor, format, hostname, score, summary, findings, unsupported_fields } = result;
  const passCount = summary?.pass ?? 0;
  const failCount = summary?.fail ?? 0;
  const unknownCount = summary?.unknown ?? 0;
  const totalCount = summary?.total ?? 0;

  return (
    <div className="results">
      {/* Device caption */}
      {(vendor || hostname || format) && (
        <div className="device-caption">
          {[vendor, format, hostname].filter(Boolean).join(' · ')}
        </div>
      )}

      {/* Score + Summary Cards */}
      {score !== undefined && (
        <>
          <ScoreDisplay score={score} summary={summary} />
          <div className="audit-summary">
            <div className="audit-summary-card">
              <div className="audit-summary-card-label">Vendor</div>
              <div className="audit-summary-card-value">{vendor || '—'}</div>
            </div>
            <div className="audit-summary-card">
              <div className="audit-summary-card-label">Format</div>
              <div className="audit-summary-card-value">{format || '—'}</div>
            </div>
            <div className="audit-summary-card">
              <div className="audit-summary-card-label">Hostname</div>
              <div className="audit-summary-card-value mono">{hostname || '—'}</div>
            </div>
            <div className="audit-summary-card">
              <div className="audit-summary-card-label">Passed</div>
              <div className="audit-summary-card-value pass">{passCount}</div>
            </div>
            <div className="audit-summary-card">
              <div className="audit-summary-card-label">Failed</div>
              <div className="audit-summary-card-value fail">{failCount}</div>
            </div>
            {unknownCount > 0 && (
              <div className="audit-summary-card">
                <div className="audit-summary-card-label">Unknown</div>
                <div className="audit-summary-card-value unknown">{unknownCount}</div>
              </div>
            )}
            <div className="audit-summary-card">
              <div className="audit-summary-card-label">Total Rules</div>
              <div className="audit-summary-card-value">{totalCount}</div>
            </div>
          </div>
        </>
      )}

      {/* Unsupported fields footnote */}
      <UnsupportedFootnote fields={unsupported_fields} />

      {/* Findings */}
      <div className="findings-section">
        <h2>Compliance Findings ({findings?.length ?? 0})</h2>
        <FindingsTable findings={findings} />
        <div className="legend">
          <span className="legend-item">
            <span className="legend-dot pass" /> Verified compliant
          </span>
          <span className="legend-item">
            <span className="legend-dot fail" /> Verified non-compliant
          </span>
          <span className="legend-item">
            <span className="legend-dot unknown" /> Insufficient evidence
          </span>
        </div>
      </div>

      {/* CTA */}
      <div style={{ marginTop: '32px', textAlign: 'right' }}>
        <button className="cta-link" onClick={onNewAudit}>
          Run another audit →
        </button>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Error panel
// ---------------------------------------------------------------------------

function ErrorPanel({ message, onNewAudit }) {
  return (
    <div>
      <div className="error-box">
        <strong>Audit failed</strong>
        <p>{message}</p>
      </div>
      <div style={{ textAlign: 'right' }}>
        <button className="cta-link" onClick={onNewAudit}>Try again →</button>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main dashboard
// ---------------------------------------------------------------------------

export default function AuditDashboard() {
  const [file, setFile] = useState(null);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(false);

  const handleFileChange = (e) => {
    const selected = e.target.files[0];
    setFile(selected || null);
    setResult(null);
    setError(null);
  };

  const handleRunAudit = async () => {
    if (!file) return;
    setLoading(true);
    setResult(null);
    setError(null);

    const formData = new FormData();
    formData.append('file', file);

    try {
      const resp = await fetch(`${API_BASE}/audit`, { method: 'POST', body: formData });
      if (!resp.ok) {
        const errData = await resp.json().catch(() => ({}));
        throw new Error(errData.detail || `Server returned ${resp.status}`);
      }
      const data = await resp.json();
      setResult(data);
    } catch (err) {
      if (err.message.includes('NetworkError') || err.message.includes('Failed to fetch')) {
        setError(
          'Unable to connect to the audit server. Make sure the FastAPI backend is running on port 8000.'
        );
      } else {
        setError(err.message);
      }
    } finally {
      setLoading(false);
    }
  };

  const handleNewAudit = () => {
    setFile(null);
    setResult(null);
    setError(null);
  };

  return (
    <>
      {/* Upload section */}
      <div className="upload-section">
        <h1 className="upload-heading">Drop a config.</h1>
        <p className="upload-subheading">
          Paste or upload a network device configuration to audit against CIS benchmarks.
        </p>

        <div className={`drop-zone ${file ? 'has-file' : ''}`}>
          <input
            type="file"
            accept=".txt,.cfg,.conf,.json,.xml,.config"
            onChange={handleFileChange}
            aria-label="Upload configuration file"
          />
          <p className="drop-zone-label">
            {file ? file.name : 'Drop to upload'}
          </p>
        </div>

        <div style={{ textAlign: 'right' }}>
          <button
            className="cta-link"
            onClick={handleRunAudit}
            disabled={!file || loading}
          >
            {loading ? 'Analyzing...' : 'Run Audit →'}
          </button>
        </div>
      </div>

      {/* Loading */}
      {loading && (
        <div className="loading">
          <span className="spinner" />
          <span>Parsing configuration and evaluating compliance rules…</span>
        </div>
      )}

      {/* Error */}
      {error && <ErrorPanel message={error} onNewAudit={handleNewAudit} />}

      {/* Results */}
      {result && !loading && <ResultPanel result={result} onNewAudit={handleNewAudit} />}

      {/* Empty state */}
      {!result && !error && !loading && (
        <div className="empty-state">
          <div className="empty-state-icon">⬡</div>
          <p>No audit results yet. Upload a configuration file to get started.</p>
        </div>
      )}
    </>
  );
}
