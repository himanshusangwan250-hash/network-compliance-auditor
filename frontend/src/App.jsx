import React, { useState } from 'react';
import AuditDashboard from './components/AuditDashboard';

function App() {
  return (
    <div className="app">
      <header className="header">
        <h1>Network Configuration Compliance Auditor</h1>
        <p>Upload a network device configuration to evaluate CIS-style security compliance rules.</p>
      </header>
      <AuditDashboard />
    </div>
  );
}

export default App;
