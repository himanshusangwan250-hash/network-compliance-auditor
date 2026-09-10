# Dual-Model AI Ensemble Architecture

**Date:** 2026-09-11  
**Status:** Active in production  
**Models:** V6 (primary) + V4 (fallback)

---

## Overview

The compliance AI pipeline uses a **dual-model ensemble** where V6 is the primary model and V4 serves as a confidence-aware fallback. The deterministic Rule Engine is completely separate and is NOT an input to the AI pipeline.

```
Configuration
    ↓
Vendor Detection → Parsing → Normalization → Evidence Extraction
    ↓
V6 Model (primary, ~95% F1)
    ↓
Confidence Gate
    ├── confident (≥ threshold) → Use V6 result directly
    └── uncertain (< threshold) → Run V4 → Fuse results
    ↓
Final AI Result (prediction + confidence)
```

---

## Models

| Model | Role | Performance | Location |
|-------|------|-------------|----------|
| **V6** | Primary | ~95% accuracy, ~95% F1 | `ml_compliance/model/setfit_v6/` |
| **V4** | Fallback | Strong real-world holdout performance | `ml_compliance/model/setfit_v4/` |

**Why V4 as fallback?**  
V4 was selected because it demonstrated stronger real-world holdout performance (~76.7% match rate on untouched test data), making it a robust backup when V6 is uncertain. V6 remains primary due to its superior benchmark accuracy and F1 score.

---

## Configuration

All parameters are configurable via environment variables with sensible defaults:

| Variable | Default | Description |
|----------|---------|-------------|
| `AI_V6_CONFIDENCE_THRESHOLD` | `0.80` | V6 confidence below this triggers V4 fallback |
| `AI_V6_WEIGHT` | `0.60` | Weight for V6 in probability fusion |
| `AI_V4_WEIGHT` | `0.40` | Weight for V4 in probability fusion |

---

## Pipeline Flow

### Step 1: V6 Inference (Primary)
- Run V6 model on the rule-specific evidence text
- Extract prediction, confidence, and probability

### Step 2: Confidence Gate
```python
if v6_confidence >= AI_V6_CONFIDENCE_THRESHOLD:
    return V6 result (V6_ONLY path)
else:
    trigger V4 fallback
```

### Step 3: V4 Fallback (Conditional)
- Only invoked when V6 confidence is below threshold
- Run V4 on the **same** evidence text as V6
- Preserve all original context (policy, vendor, rule_id)

### Step 4: Probability Fusion
```python
p_fused = v6_prob * V6_FUSION_WEIGHT + v4_prob * V4_FUSION_WEIGHT

if p_fused >= 0.5:
    final_prediction = "compliant"
else:
    final_prediction = "non_compliant"

final_confidence = abs(p_fused - 0.5) * 2
```

### Step 5: Disagreement Handling
If V6 and V4 predict different classes AND fused probability is near the boundary (0.4 < p < 0.6):
- Mark as `UNCERTAIN`
- Surface both predictions to the frontend
- Add "models disagree — review recommended" warning

---

## Output Structure

### High-Confidence Case (V6 Only)
```json
{
  "prediction": "compliant",
  "confidence": 0.95,
  "model_used": "V6",
  "fallback_used": false,
  "v6": {"prediction": "compliant", "confidence": 0.95, "probability": 0.95},
  "vendor": "cisco_ios"
}
```

### Fallback Case (V6 + V4 Fused)
```json
{
  "prediction": "compliant",
  "confidence": 0.78,
  "model_used": "V6+V4",
  "fallback_used": true,
  "v6": {"prediction": "compliant", "confidence": 0.62, "probability": 0.62},
  "v4": {"prediction": "compliant", "confidence": 0.83, "probability": 0.83},
  "models_agree": true,
  "vendor": "cisco_ios"
}
```

### Disagreement Case
```json
{
  "prediction": "uncertain",
  "confidence": 0.55,
  "model_used": "V6+V4",
  "fallback_used": true,
  "v6": {"prediction": "non_compliant", "confidence": 0.58, ...},
  "v4": {"prediction": "compliant", "confidence": 0.83, ...},
  "models_agree": false,
  "vendor": "cisco_ios"
}
```

---

## Key Design Decisions

1. **V6 is always primary** — V4 never runs unless V6 is uncertain
2. **No training at runtime** — models are loaded once and reused
3. **Deterministic fusion** — same inputs always produce same outputs
4. **Failure isolation** — if V4 fails, V6 result is returned with a note
5. **Disagreement visibility** — frontend surfaces model conflicts for review
6. **Rule Engine separate** — deterministic rules are preserved but not used for AI decisions

---

## Logging

Each inference produces structured logs:
```
[V6] CIS-1.1 prediction=COMPLIANT confidence=0.9500 prob=0.9500
[AI GATE] CIS-1.1 V6 confident (0.95 >= 0.80) → V6 ONLY

[V6] CIS-2.2 prediction=COMPLIANT confidence=0.5400 prob=0.5400
[AI GATE] CIS-2.2 V6 uncertain (0.54 < 0.80) → FALLBACK to V4
[V4] CIS-2.2 prediction=NON_COMPLIANT confidence=0.8300 prob=0.8300
[FUSION] CIS-2.2 v6=COMPLIANT(0.54) v4=NON_COMPLIANT(0.83) agree=false final=NON_COMPLIANT(0.68)
```

---

## Safety Guarantees

- ✅ No model retraining occurs
- ✅ Model weights are never modified
- ✅ No training datasets are touched
- ✅ No new model versions (V7, V8) are created
- ✅ Existing parsers unchanged
- ✅ Deterministic Rule Engine untouched (preserved for metadata only)
- ✅ Stateless inference — no persistence of configuration data

---

**End of Document**
