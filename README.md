# Network Configuration Compliance Auditor

A comprehensive tool for auditing network device configurations against CIS-style security compliance rules.

## What the System Does

Upload a network device configuration file and receive a deterministic compliance report showing:

- Detected vendor and configuration format
- Overall compliance score (percentage of evaluable rules that pass)
- Per-rule findings with PASS / FAIL / UNKNOWN status
- Evidence explaining each finding
- Remediation guidance for failures

## Supported Vendors

| Vendor | Format | Notes |
|--------|--------|-------|
| Cisco IOS | Text (running-config style) | Full parser with interfaces, users, NTP, syslog, SNMP |
| Juniper Junos | Text (hierarchical brace syntax) | Full parser with zones, interfaces, users, NTP, syslog, SNMP |
| Palo Alto PAN-OS | XML (API export) | Full parser with zones, addresses, services, security rules, SNMP, NTP |
| Palo Alto PAN-OS | Curly-brace (`show running-config`) | Full parser with same coverage as XML |

## Architecture

```
Configuration File (text, .txt/.cfg/.xml)
    ↓
Vendor Detection (pattern matching on raw text)
    ↓
Vendor-Specific Parser (Cisco / Juniper / Palo Alto)
    ↓
Normalization Layer (vendor-agnostic models + unsupported_fields tracking)
    ↓
Compliance Engine (CIS Rules → Findings)
    ↓
FastAPI Backend (/audit endpoint)
    ↓
React/Vite Frontend (dashboard UI)
```

## Compliance Status Semantics

| Status | Meaning |
|--------|---------|
| **PASS** | Evidence positively demonstrates compliance with the rule. |
| **FAIL** | Evidence positively demonstrates non-compliance. |
| **UNKNOWN** | Insufficient evidence to determine compliance — the parser does not extract this data for the given vendor/format. |

**Key principle:** Absence of parsed data is never treated as automatic PASS or FAIL. When the system cannot verify a control because the vendor/parser does not expose the relevant information, the finding is marked UNKNOWN with an explanatory evidence message.

## Compliance Score Calculation

The overall score is computed from evaluable findings only:

```
score = (pass_count / (pass_count + fail_count)) × 100
```

- UNKNOWN findings are excluded from the denominator — they do not penalize the score.
- When all findings are UNKNOWN (or there are no findings at all), the score is `null`.
- The response also includes a summary object with pass/fail/unknown/total counts.

## Installation

### Prerequisites

- Python 3.10+
- Node.js 18+
- npm

### Backend Setup

```bash
# Clone the repository
git clone https://github.com/<your-username>/network-compliance-auditor.git
cd network-compliance-auditor

# Setup Python virtual environment
python -m venv venv
# On Windows:
venv\Scripts\activate
# On Linux/macOS:
# source venv/bin/activate

pip install -r backend/requirements.txt
```

### Frontend Setup

```bash
cd frontend
npm install
```

## How to Run

Open two terminals.

**Terminal 1 — Backend:**

```bash
# In the root repository directory:
uvicorn backend.main:app --reload --port 8000
```

**Terminal 2 — Frontend:**

```bash
cd frontend
npm run dev
```

**Browser:** Open http://localhost:5173

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Health check |
| GET | `/vendors` | List supported vendors |
| GET | `/rules` | List compliance rule IDs |
| GET | `/rules/{rule_id}` | Get rule metadata |
| POST | `/audit` | Upload config for audit |

### Example: Audit a Configuration

```powershell
curl -X POST http://localhost:8000/audit `
  -F "file=@sample_configs/cisco_ios_sample.txt"
```

### Response Shape

```json
{
  "vendor": "cisco_ios",
  "format": null,
  "hostname": "TEST-RTR-01",
  "score": 40.0,
  "summary": { "pass": 2, "fail": 3, "unknown": 1, "total": 6 },
  "findings": [
    {
      "rule_id": "CIS-1.1",
      "title": "Avoid Default Credentials",
      "severity": "High",
      "status": "FAIL",
      "evidence": "Default usernames found: admin",
      "remediation": "Change all default usernames to unique accounts."
    }
  ],
  "unsupported_fields": ["domain", "zones", "security_rules", "routes"]
}
```

## Security Model

- **Stateless processing:** Configuration files are processed per audit request and are **not persisted** by the MVP. No database or file storage is used.
- **No secrets in responses:** Password hashes and plaintext credentials from parser output are not returned in API responses.
- **UTF-8 validation:** Non-UTF-8 uploads are rejected with a clear error.
- **Upload size limit:** Maximum upload size is 10 MB.
- **CORS:** Restricted to `http://localhost:5173` and `http://127.0.0.1:5173` in development.

## Known Limitations

- Only 6 CIS-style compliance rules implemented (expandable via `rules_engine.py`)
- Palo Alto curly-brace SNMP extraction may be empty for some config variants
- Cisco IOS and Juniper Junos parsers do not extract security zones (reported as UNKNOWN for CIS-4.1)
- Palo Alto parser does not extract user accounts (reported as UNKNOWN for CIS-1.1, CIS-1.2)
- The MVP is intentionally stateless — no history, no user accounts, no persistent storage
