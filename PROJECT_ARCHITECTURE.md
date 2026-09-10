# Network Configuration Compliance Auditor
## Complete Technical Architecture & Pipeline Documentation

**Last Updated:** 2026-09-11  
**Project Status:** Production Ready  
**Architecture:** Dual-Model AI Pipeline (V6 Primary + V4 Fallback)

---

## Table of Contents

1. [System Overview](#system-overview)
2. [Architecture Pipeline](#architecture-pipeline)
3. [Component Details](#component-details)
4. [AI Models](#ai-models)
5. [Compliance Rules](#compliance-rules)
6. [API Endpoints](#api-endpoints)
7. [Data Flow](#data-flow)
8. [Configuration](#configuration)
9. [Deployment](#deployment)

---

## System Overview

The Network Configuration Compliance Auditor is a **network device configuration compliance tool** that:

1. Accepts network device configurations (Cisco IOS, Juniper Junos, Palo Alto PAN-OS)
2. Parses and normalizes them into vendor-agnostic format
3. Extracts rule-specific evidence from normalized data
4. Runs AI compliance analysis using V6 (primary) and V4 (fallback) models
5. Fuses predictions when both models are used
6. Returns structured compliance findings with evidence and remediation guidance

**Key Principle:** The deterministic Rule Engine is preserved for rule metadata but is **NOT** used for compliance decisions. All PASS/FAIL/UNKNOWN determinations come from the AI pipeline.

---

## Architecture Pipeline

```
┌─────────────────────────────────────────────────────────────────────┐
│                    CONFIGURATION UPLOAD                             │
└─────────────────────────────────────────────────────────────────────┘
                                    ↓
┌─────────────────────────────────────────────────────────────────────┐
│  STEP 1: VENDOR DETECTION                                          │
│  - Pattern matching on raw config text                             │
│  - Identifies: cisco_ios, juniper_junos, paloalto_panos            │
└─────────────────────────────────────────────────────────────────────┘
                                    ↓
┌─────────────────────────────────────────────────────────────────────┐
│  STEP 2: VENDOR-SPECIFIC PARSING                                   │
│  - Cisco IOS parser → dict with hostname, interfaces, users, etc.  │
│  - Juniper Junos parser → dict with zones, users, NTP, syslog      │
│  - Palo Alto PAN-OS parser → dict with zones, security rules, etc. │
└─────────────────────────────────────────────────────────────────────┘
                                    ↓
┌─────────────────────────────────────────────────────────────────────┐
│  STEP 3: NORMALIZATION                                             │
│  - Converts vendor-specific output to common schema                │
│  - Produces NormalizedConfig object                                │
│  - Tracks unsupported_fields per vendor                            │
└─────────────────────────────────────────────────────────────────────┘
                                    ↓
┌─────────────────────────────────────────────────────────────────────┐
│  STEP 4: EVIDENCE EXTRACTION (per rule)                           │
│  - Extracts relevant config snippets for each CIS rule           │
│  - Formats as Cisco IOS-style text for model input               │
│  - Includes surrounding context lines                              │
└─────────────────────────────────────────────────────────────────────┘
                                    ↓
┌─────────────────────────────────────────────────────────────────────┐
│  STEP 5: V6 ANALYSIS (PRIMARY MODEL)                              │
│  - Run V6 SetFit model on (policy_text || evidence_text)         │
│  - Get prediction, confidence, probability                        │
│  - Check confidence against threshold (0.80)                       │
└─────────────────────────────────────────────────────────────────────┘
                                    ↓
                    ┌───────────────┴───────────────┐
                    ↓                               ↓
              CONFIDENT                      UNCERTAIN
           (confidence >= 0.80)         (confidence < 0.80)
                    ↓                               ↓
              RETURN V6                     RUN V4 FALLBACK
              RESULT ONLY                 (only if needed)
                                         ↓
                              ┌──────────┴──────────┐
                              ↓                     ↓
                        CONFIDENT              UNCERTAIN
                   (confidence >= 0.60)   (confidence < 0.60)
                              ↓                     ↓
                        USE V4 RESULT        USE V4 RESULT
                              ↓                     ↓
                    ┌───────────────────────────────────┐
                    ↓                                     ↓
            V6 + V4 FUSION                    FUSE RESULTS
            (weighted probability average)      (same)
                    ↓                                     ↓
                    └──────────────────┬──────────────────┘
                                       ↓
                    ┌──────────────────┴──────────────────┐
                    ↓                                     ↓
            MODELS AGREE                            MODELS DISAGREE
            (same prediction)                    (different predictions)
                    ↓                                     ↓
            USE FUSED CONFIDENCE                  USE FUSED CONFIDENCE
                                                   + surface disagreement
                    ↓                                     ↓
                    └──────────────────┬──────────────────┘
                                       ↓
                    ┌──────────────────┴──────────────────┐
                    ↓                                     ↓
            RETURN FINAL RESULT                    RETURN FINAL RESULT
            with ai_pipeline metadata             with ai_pipeline metadata
                                       ↓
                              ┌────────────────┐
                              ↓                ↓
                        BUILD FINDINGS    CALCULATE SCORE
                              ↓                ↓
                              └────────────────┘
                                       ↓
                              RETURN AUDIT RESPONSE
```

---

## Component Details

### 1. Vendor Detection (`backend/parser/vendor_detector.py`)

**Purpose:** Identify device vendor from raw configuration text

**Method:** Pattern matching on distinctive configuration syntax
- Cisco IOS: `hostname`, `interface GigabitEthernet`, `router ospf`
- Juniper Junos: `set system hostname`, `interfaces { interface`
- Palo Alto PAN-OS XML: `<config>` root element
- Palo Alto Curly: `configure` command, `set` prefixes

**Output:**
```python
{
    "vendor": "cisco_ios" | "juniper_junos" | "paloalto_panos",
    "confidence": 0.95,
    "details": {...}
}
```

---

### 2. Vendor Parsers (`backend/parser/*.py`)

#### Cisco IOS Parser (`cisco_ios.py`)
- Parses running-config format
- Extracts: hostname, version, interfaces (name/IP/mask/shutdown), users (name/privilege/encrypted), NTP servers, logging hosts, SNMP communities, banners
- Output: dict with all parsed fields

#### Juniper Junos Parser (`juniper_junos.py`)
- Parses hierarchical brace syntax
- Extracts: hostname, domain, interfaces (name/description/address), users (name/class/encrypted), NTP servers, syslog hosts, SNMP communities, security zones, routes
- Output: dict with all parsed fields

#### Palo Alto PAN-OS Parser (`paloalto_panos.py`)
- Parses XML API export format
- Extracts: hostname, domain, interfaces, addresses, services, security rules, zones, SNMP communities, NTP, users, logging
- Output: dict with all parsed fields

#### Palo Alto Curly Parser (`paloalto_curly.py`)
- Parses `show running-config` output
- Uses regex patterns to extract same fields as XML parser
- Output: dict with `format: "curly_brace"` indicator

---

### 3. Normalization Layer (`backend/compliance/models.py`)

**Purpose:** Convert vendor-specific parsed output into a common schema

**NormalizedSchema:**
```python
@dataclass
class NormalizedConfig:
    vendor: str
    format: Optional[str]
    hostname: Optional[str]
    domain: Optional[str]
    interfaces: List[NormalizedInterface]
    users: List[NormalizedUser]
    logging_hosts: List[str]
    ntp_servers: List[str]
    snmp_communities: List[NormalizedSnmpCommunity]
    zones: List[NormalizedZone]
    security_rules: List[NormalizedSecurityRule]
    routes: List[Dict[str, Any]]
    unsupported_fields: List[str]  # Fields not available for this vendor
    raw: Dict[str, Any]  # Original parser output preserved
```

**Vendor Adapters:**
- `normalize_cisco()`: Maps Cisco output to NormalizedConfig
- `normalize_juniper()`: Maps Juniper output to NormalizedConfig  
- `normalize_paloalto()`: Maps Palo Alto output to NormalizedConfig

**Key Design:** Unsupported fields are tracked separately so the compliance engine knows when data is missing vs. absent.

---

### 4. Evidence Extraction (`backend/ml/evidence_extractor.py`)

**Purpose:** Extract rule-specific configuration snippets for AI analysis

**Flow:**
```python
extract_rule_evidence(rule_id, normalized_config) → evidence_text
```

**For each CIS rule:**

| Rule | Evidence Extracted | Format |
|------|-------------------|--------|
| CIS-1.1 | User accounts with names and encryption status | Cisco IOS style |
| CIS-1.2 | Password encryption service + user details | Cisco IOS style |
| CIS-2.1 | Logging host configurations | Cisco IOS style |
| CIS-2.2 | NTP server configurations | Cisco IOS style |
| CIS-3.1 | SNMP community configurations | Cisco IOS style |
| CIS-4.1 | Security zone configurations | Cisco IOS style |

**Evidence Format:**
```
hostname DEVICE-NAME
! Evidence for rule X
username admin privilege 15 password 0 PLAINTEXT
interface GigabitEthernet0/0
 ip address 192.168.1.1 255.255.255.0
 no shutdown
```

Context lines are added around the evidence for better model performance.

---

### 5. AI Compliance Engine (`backend/ml/semantic_compliance.py`)

**Purpose:** Run dual-model inference with confidence gating and fusion

#### Model Loading

```python
MODEL_V6_DIR = ml_compliance/model/setfit_v6/
MODEL_V4_DIR = ml_compliance/model/setfit_v4/
```

Models are loaded once as singletons and reused across requests.

#### Confidence Thresholds

| Parameter | Default | Environment Variable | Description |
|-----------|---------|---------------------|-------------|
| `V6_CONFIDENCE_THRESHOLD` | 0.80 | `AI_V6_CONFIDENCE_THRESHOLD` | Below this, V4 is invoked |
| `V6_FUSION_WEIGHT` | 0.60 | `AI_V6_WEIGHT` | Weight for V6 in fusion |
| `V4_FUSION_WEIGHT` | 0.40 | `AI_V4_WEIGHT` | Weight for V4 in fusion |

#### Inference Flow (per rule)

**Step 1: Run V6 (Primary)**
```python
v6_result = _predict_with_model(v6_model, policy_text, evidence_text)
```

Returns:
```python
{
    "prediction": "compliant" | "non_compliant",
    "confidence": float (0.0 to 1.0),
    "probability": float (P(compliant))
}
```

**Step 2: Confidence Gate**
```python
if v6_result["probability"] >= 0.80 or v6_result["probability"] <= 0.20:
    return V6 result only (no V4 needed)
else:
    run V4 fallback
```

**Step 3: Run V4 (Fallback)**
```python
v4_result = _predict_with_model(v4_model, policy_text, evidence_text)
```

**Step 4: Fuse Results**
```python
p_fused = v6_prob * 0.60 + v4_prob * 0.40
prediction = "compliant" if p_fused >= 0.5 else "non_compliant"

if prediction == "compliant":
    confidence = p_fused
else:
    confidence = 1 - p_fused
```

**Step 5: Disagreement Handling**
```python
if models_disagree and 0.4 < p_fused < 0.6:
    prediction = "uncertain"
    confidence = abs(v6_prob - v4_prob)
```

#### Output Structure

**V6-Only Case:**
```json
{
    "prediction": "non_compliant",
    "confidence": 0.729,
    "probability": 0.271,
    "model_used": "V6",
    "fallback_used": false,
    "v6": {"prediction": "...", "confidence": 0.729, "probability": 0.271},
    "vendor": "cisco_ios"
}
```

**V6+V4 Fused Case:**
```json
{
    "prediction": "non_compliant",
    "confidence": 0.667,
    "probability": 0.333,
    "model_used": "V6+V4",
    "fallback_used": true,
    "v6": {"prediction": "...", "confidence": 0.729, "probability": 0.271},
    "v4": {"prediction": "...", "confidence": 0.574, "probability": 0.426},
    "models_agree": true,
    "vendor": "cisco_ios"
}
```

---

## AI Models

### V6 Model (Primary)

**Location:** `ml_compliance/model/setfit_v6/`

**Architecture:** SetFit fine-tuned sentence transformer
- Base: `sentence-transformers/all-MiniLM-L6-v2`
- Head: Logistic Regression (sklearn)
- Training: ~15,000 labeled compliance examples
- Evaluation: ~95% accuracy, ~95% F1 on test set

**Purpose:** Primary compliance classifier with highest benchmark accuracy

**Training Data:** Synthetic and real network configurations labeled as compliant/non-compliant for various CIS rules

---

### V4 Model (Fallback)

**Location:** `ml_compliance/model/setfit_v4/`

**Architecture:** SetFit fine-tuned sentence transformer (same base as V6)
- Base: `sentence-transformers/all-MiniLM-L6-v2`
- Head: Logistic Regression (sklearn)
- Training: Earlier iteration with different weighting
- Evaluation: ~76.7% match rate on real-world holdout

**Purpose:** Real-world robustness fallback when V6 is uncertain

**Why V4?** Despite lower benchmark accuracy, V4 showed stronger performance on unseen real-world configurations, making it valuable as a backup.

---

### Model Loading Strategy

```python
_model_v6 = None  # Singleton
_model_v4 = None  # Singleton

def get_v6_model():
    global _model_v6
    if _model_v6 is None:
        _model_v6 = SetFitModel.from_pretrained(MODEL_V6_DIR)
    return _model_v6
```

Models are loaded once per process and cached. No reloading between requests.

---

## Compliance Rules

### Rule Definitions (`backend/compliance/rules_engine.py`)

The rules engine is **preserved for metadata only**. It provides:
- Rule IDs and descriptions (used as policy text for AI)
- Severity levels
- Remediation guidance
- Title mappings

**Rule List:**

| Rule ID | Title | Severity | Policy Description |
|---------|-------|----------|-------------------|
| CIS-1.1 | Avoid Default Credentials | High | Default usernames like admin, root, or default should not be used |
| CIS-1.2 | Password Encryption Required | Medium | Passwords should be encrypted, not stored in plain text |
| CIS-2.1 | Syslog Configuration Required | Medium | Remote logging should be configured for audit trails |
| CIS-2.2 | NTP Configuration Required | Low | NTP should be configured for accurate timestamps |
| CIS-3.1 | Secure SNMP Configuration | High | Default SNMP communities like public/private indicate weak security |
| CIS-4.1 | Network Segmentation | Medium | Security zones should be configured to segment traffic |

**Note:** The deterministic rules engine functions (`evaluate_compliance()`) are **NOT CALLED** in production. They are preserved for reference and testing.

---

## API Endpoints

### Base URL: `http://localhost:8000/api`

#### GET `/health`
Health check endpoint.

**Response:**
```json
{"status": "ok"}
```

#### GET `/vendors`
List supported vendors.

**Response:**
```json
["cisco_ios", "juniper_junos", "paloalto_panos"]
```

#### GET `/rules`
List all compliance rule IDs.

**Response:**
```json
["CIS-1.1", "CIS-1.2", "CIS-2.1", "CIS-2.2", "CIS-3.1", "CIS-4.1"]
```

#### GET `/rules/{rule_id}`
Get rule metadata.

**Response:**
```json
{
    "rule_id": "CIS-1.1",
    "title": "Avoid Default Credentials",
    "severity": "High",
    "description": "Default usernames like admin, root, or default should not be used.",
    "remediation": "Change all default usernames to unique accounts."
}
```

#### POST `/audit`
Upload configuration for compliance audit.

**Request:**
```
multipart/form-data
file: <network_config.txt>
```

**Response:**
```json
{
    "vendor": "cisco_ios",
    "format": null,
    "hostname": "RTR-01",
    "score": 40.0,
    "summary": {
        "pass": 2,
        "fail": 3,
        "unknown": 1,
        "total": 6
    },
    "findings": [
        {
            "rule_id": "CIS-1.1",
            "title": "Avoid Default Credentials",
            "severity": "High",
            "status": "FAIL",
            "evidence": "AI analysis: non_compliant (confidence: 72.9%)",
            "remediation": "Change all default usernames to unique accounts.",
            "ai_analysis": {
                "prediction": "non_compliant",
                "confidence": 0.729,
                "probability": 0.271,
                "model_used": "V6",
                "fallback_used": false,
                "v6": {
                    "prediction": "non_compliant",
                    "confidence": 0.729,
                    "probability": 0.271
                }
            }
        }
    ],
    "unsupported_fields": ["zones", "security_rules"],
    "ai_pipeline": {
        "primary": "V6",
        "fallback": "V4",
        "v6_confidence_threshold": 0.80,
        "v6_weight": 0.60,
        "v4_weight": 0.40
    }
}
```

---

## Data Flow

### Example: Cisco Config Audit

```
1. User uploads cisco_ios_sample.txt
   ↓
2. detect_vendor() matches "hostname" and "interface" patterns
   → vendor = "cisco_ios"
   ↓
3. parse_cisco_ios() extracts:
   - hostname: "TEST-RTR-01"
   - interfaces: [{"name": "GigabitEthernet0/0", "ip": "192.168.1.1", ...}]
   - users: [{"name": "admin", "privilege": 15, "encrypted": false}, ...]
   - ntp: ["8.8.8.8"]
   - logging: [{"host": "192.168.1.100"}]
   - snmp: [{"community": "public", "permission": "ro"}]
   ↓
4. normalize_cisco() converts to NormalizedConfig:
   - vendor: "cisco_ios"
   - hostname: "TEST-RTR-01"
   - interfaces: [NormalizedInterface(...)]
   - users: [NormalizedUser(...)]
   - unsupported_fields: ["domain", "zones", "security_rules", "routes"]
   ↓
5. For each CIS rule:
   
   a) CIS-1.1 (Default Credentials):
      - evidence = extract_rule_evidence("CIS-1.1", config)
      - returns: "hostname TEST-RTR-01\nusername admin privilege 15 password 0 plaintext\n..."
      - V6 predicts: non_compliant with P(compliant)=0.271, confidence=0.729
      - 0.729 >= 0.80? NO, but 0.271 <= 0.20? NO
      - → Run V4 fallback
      - V4 predicts: non_compliant with P(compliant)=0.426, confidence=0.574
      - Fuse: p_fused = 0.271*0.6 + 0.426*0.4 = 0.333
      - prediction = non_compliant (0.333 < 0.5)
      - confidence = 1 - 0.333 = 0.667
      - models_agree = True
      - → Result: non_compliant 66.7%
      ↓
   
   b) CIS-2.1 (Syslog):
      - evidence = "hostname TEST-RTR-01\nlogging host 192.168.1.100\n..."
      - V6 predicts: compliant with P(compliant)=0.92, confidence=0.92
      - 0.92 >= 0.80? YES
      - → V6 ONLY (no V4)
      - → Result: compliant 92.0%
      ↓
   
   (Repeat for all 6 rules)
   ↓
6. Calculate scores:
   - pass = 2, fail = 3, unknown = 1
   - score = 2/6 * 100 = 33.3%
   ↓
7. Build response JSON with all findings
```

---

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `AI_V6_CONFIDENCE_THRESHOLD` | 0.80 | V6 confidence threshold for fallback |
| `AI_V6_WEIGHT` | 0.60 | Fusion weight for V6 |
| `AI_V4_WEIGHT` | 0.40 | Fusion weight for V4 |
| `KMP_DUPLICATE_LIB_OK` | TRUE | OpenMP compatibility flag (required on some systems) |

### Model Paths

Models are loaded from:
- V6: `ml_compliance/model/setfit_v6/`
- V4: `ml_compliance/model/setfit_v4/`

Each model directory contains:
- `config.json` - Model configuration
- `config_sentence_transformers.json` - Sentence transformer settings
- `config_setfit.json` - SetFit-specific settings
- `model.safetensors` - Model weights
- `model_head.pkl` - Classification head
- `tokenizer.json` - Tokenizer vocab
- `modules.json` - Module configuration
- `training_results_*.json` - Training metrics

---

## Deployment

### Backend

```bash
# Activate virtual environment
source venv/bin/activate  # Linux/Mac
# or
venv\Scripts\activate     # Windows

# Start FastAPI server
python -m uvicorn backend.main:app --reload --port 8000
```

### Frontend

```bash
cd frontend
npm install
npm run dev
```

### Full Stack

**Terminal 1 (Backend):**
```bash
uvicorn backend.main:app --reload --port 8000
```

**Terminal 2 (Frontend):**
```bash
cd frontend
npm run dev
```

**Browser:** http://localhost:5173

---

## Key Design Decisions

### 1. Why AI-Only Compliance?

The original hybrid system used deterministic rules + AI supplementary analysis. The new system:
- Uses AI for all PASS/FAIL/UNKNOWN decisions
- Preserves rule engine for metadata (descriptions, severity, remediation)
- Provides semantic understanding of configurations
- Enables better generalization to unseen configs

### 2. Why Dual-Model?

- **V6** provides high benchmark accuracy (~95%)
- **V4** provides better real-world robustness (~76.7% holdout)
- Fusion combines strengths of both models
- Confidence gating ensures V4 only runs when needed

### 3. Why Confidence Threshold?

Running V4 for every request would:
- Double inference time
- Double memory usage
- Not add value when V6 is already confident

Threshold of 0.80 means:
- V6 confident (>80% or <20% P(compliant)) → Use V6 only
- V6 uncertain (20% ≤ P ≤ 80%) → Run V4 for validation

### 4. Why Weighted Fusion?

- V6 has higher benchmark accuracy, so it gets 60% weight
- V4 has better real-world performance, so it gets 40% weight
- Weighted average produces more robust predictions than either model alone

### 5. Why Distance-from-Boundary Was Wrong

The old formula `confidence = |p_fused - 0.5| * 2` had issues:
- When both models agree on non-compliant (low P(compliant)), the fused P is also low
- Distance from 0.5 then gives LOW confidence, which is counterintuitive
- Example: Both models 90% non-compliant → fused P(compliant)=0.1 → confidence=0.8 ✓ (good)
- But: Both models 60% non-compliant → fused P(compliant)=0.4 → confidence=0.2 ✗ (bad!)

The fix uses P(predicted_class) directly:
- Both non-compliant 60% → P(non_compliant)=0.6 → confidence=0.6 ✓

---

## File Structure

```
network-compliance-auditor/
├── backend/
│   ├── main.py                          # FastAPI app entry point
│   ├── api/
│   │   └── routes.py                    # API endpoints
│   ├── compliance/
│   │   ├── models.py                    # NormalizedConfig dataclasses
│   │   └── rules_engine.py              # Rule definitions (metadata only)
│   ├── ml/
│   │   ├── semantic_compliance.py       # V6/V4 dual-model pipeline
│   │   └── evidence_extractor.py        # Rule-specific evidence extraction
│   ├── parser/
│   │   ├── vendor_detector.py           # Vendor identification
│   │   ├── cisco_ios.py                 # Cisco IOS parser
│   │   ├── juniper_junos.py             # Juniper Junos parser
│   │   ├── paloalto_panos.py            # Palo Alto XML parser
│   │   └── paloalto_curly.py            # Palo Alto curly-brace parser
│   └── tests/
│       ├── test_api.py                  # API endpoint tests
│       ├── test_ai_compliance.py        # AI pipeline tests
│       └── test_evidence_extractor.py   # Evidence extraction tests
├── frontend/
│   ├── src/
│   │   ├── App.jsx                      # Main app component
│   │   ├── index.css                    # Styles
│   │   └── components/
│   │       └── AuditDashboard.jsx       # Main dashboard UI
│   └── package.json
├── ml_compliance/
│   └── model/
│       ├── setfit_v6/                   # V6 model artifacts
│       └── setfit_v4/                   # V4 model artifacts
├── sample_configs/                      # Sample configs for testing
└── PROJECT_ARCHITECTURE.md              # This file
```

---

## Testing

### Run All Tests
```bash
pytest backend/tests/ -v
```

### Test Coverage
- **49 tests total**
- 19 AI compliance tests (dual-model pipeline)
- 13 API tests (endpoints and error handling)
- 17 evidence extractor tests (rule-specific extraction)

### Key Test Scenarios
1. V6-only path (high confidence)
2. V4 fallback path (low confidence)
3. V6+V4 fusion (both models agree)
4. Model disagreement handling
5. All three vendors (Cisco, Juniper, Palo Alto)
6. Failure handling (model unavailable)

---

## Known Limitations

1. **Only 6 CIS rules implemented** - Expandable by adding to rules_engine.py
2. **Palo Alto curly-brace SNMP** - May be empty for some config variants
3. **Cisco/Juniper zones** - Not extracted (reported as UNKNOWN for CIS-4.1)
4. **Palo Alto users** - Not extracted (reported as UNKNOWN for CIS-1.1, CIS-1.2)
5. **Stateless processing** - No persistent storage or history
6. **No auth required** - MVP does not implement authentication

---

## Security Considerations

- **No secrets in responses** - Password hashes and credentials are filtered
- **UTF-8 validation** - Non-UTF-8 uploads rejected
- **Upload size limit** - 10 MB maximum
- **Stateless processing** - Configs not persisted
- **CORS restricted** - Only localhost:5173 allowed

---

## Future Enhancements

1. Add more CIS rules (CIS-5.x, CIS-6.x)
2. Support additional vendors (FortiOS, Arista EOS)
3. Add config history and comparison
4. Implement user authentication
5. Add export to PDF/JSON reports
6. Support batch uploads
7. Add real-time monitoring integration

---

**Documentation Version:** 1.0  
**Last Updated:** 2026-09-11
