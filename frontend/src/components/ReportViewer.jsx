import React from 'react';

function ReportViewer({ report }) {
  if (!report) return null;

  return (
    <div style={{ marginTop: '20px' }}>
      <h2>Audit Report</h2>
      <p><strong>Vendor:</strong> {report.vendor}</p>
      <p><strong>Hostname:</strong> {report.normalized?.hostname || 'Unknown'}</p>

      <h3>Findings</h3>
      {report.findings?.length === 0 ? (
        <p>No compliance issues found.</p>
      ) : (
        <table border="1" cellPadding="5" style={{ width: '100%', borderCollapse: 'collapse' }}>
          <thead>
            <tr style={{ backgroundColor: '#f2f2f2' }}>
              <th>Rule ID</th>
              <th>Title</th>
              <th>Severity</th>
              <th>Status</th>
              <th>Evidence</th>
              <th>Remediation</th>
            </tr>
          </thead>
          <tbody>
            {report.findings.map((f, i) => (
              <tr key={i}>
                <td>{f.rule_id}</td>
                <td>{f.title}</td>
                <td>{f.severity}</td>
                <td>{f.status}</td>
                <td>{f.evidence}</td>
                <td>{f.remediation}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

export default ReportViewer;
