"""
Dual-Model AI Compliance Pipeline: V6 Primary + V4 Fallback.

PRIMARY: ml_compliance/model/setfit_v6/ (V6) — ~95% accuracy/F1
FALLBACK: ml_compliance/model/setfit_v4/ (V4) — stronger real-world holdout performance

Architecture:
  Config → Parser → Normalization → Evidence Extraction → V6 Analysis
                                          ↓
                              Confidence Gate (threshold)
                              ├── confident → use V6 directly
                              └── uncertain → run V4 → fuse results
                                          ↓
                                    Final AI Result

The deterministic rules engine is completely separate from this AI pipeline.
It is preserved for rule metadata only (get_rule_ids, get_rule_details).

Configuration (environment variables with sensible defaults):
  AI_V6_CONFIDENCE_THRESHOLD: 0.80 — below this, V4 is invoked
  AI_V6_WEIGHT: 0.60 — weight for V6 in probability fusion
  AI_V4_WEIGHT: 0.40 — weight for V4 in probability fusion
"""

import logging
import os
from pathlib import Path
from typing import Optional, Dict, Any

from setfit import SetFitModel

logger = logging.getLogger(__name__)

# ============================================================================
# Model paths
# ============================================================================

BASE_DIR = Path(__file__).parent.parent.parent
MODEL_V6_DIR = BASE_DIR / "ml_compliance" / "model" / "setfit_v6"
MODEL_V4_DIR = BASE_DIR / "ml_compliance" / "model" / "setfit_v4"

# ============================================================================
# Configurable parameters
# ============================================================================

def _env_float(key: str, default: float) -> float:
    """Read a float from environment, with a default."""
    raw = os.environ.get(key)
    if raw is None:
        return default
    try:
        return float(raw)
    except ValueError:
        logger.warning(f"Invalid value for {key}={raw!r}, using default {default}")
        return default


# Confidence threshold: V6 must be at least this confident before we trust it alone.
V6_CONFIDENCE_THRESHOLD = _env_float("AI_V6_CONFIDENCE_THRESHOLD", 0.80)

# Fusion weights — must sum to 1.0 after normalization.
_V6_WEIGHT = _env_float("AI_V6_WEIGHT", 0.60)
_V4_WEIGHT = _env_float("AI_V4_WEIGHT", 0.40)
_WEIGHT_SUM = _V6_WEIGHT + _V4_WEIGHT
if _WEIGHT_SUM > 0:
    V6_FUSION_WEIGHT = _V6_WEIGHT / _WEIGHT_SUM
    V4_FUSION_WEIGHT = _V4_WEIGHT / _WEIGHT_SUM
else:
    V6_FUSION_WEIGHT = 0.5
    V4_FUSION_WEIGHT = 0.5

logger.info(
    f"[config] V6_THRESHOLD={V6_CONFIDENCE_THRESHOLD}, "
    f"V6_FUSION_WEIGHT={V6_FUSION_WEIGHT:.2f}, V4_FUSION_WEIGHT={V4_FUSION_WEIGHT:.2f}"
)

# ============================================================================
# Singleton model instances
# ============================================================================

_model_v6: Optional[SetFitModel] = None
_model_v4: Optional[SetFitModel] = None


def _load_model(model_dir: Path, name: str) -> Optional[SetFitModel]:
    """Load a SetFit model with error handling."""
    try:
        logger.info(f"Loading {name} model from {model_dir}...")
        model = SetFitModel.from_pretrained(str(model_dir))
        logger.info(f"{name} model loaded successfully")
        return model
    except Exception as e:
        logger.error(f"Failed to load {name} model from {model_dir}: {e}")
        return None


def get_v6_model() -> Optional[SetFitModel]:
    """Get V6 model (primary)."""
    global _model_v6
    if _model_v6 is not None:
        return _model_v6
    _model_v6 = _load_model(MODEL_V6_DIR, "V6")
    return _model_v6


def get_v4_model() -> Optional[SetFitModel]:
    """Get V4 model (fallback)."""
    global _model_v4
    if _model_v4 is not None:
        return _model_v4
    _model_v4 = _load_model(MODEL_V4_DIR, "V4")
    return _model_v4


# ============================================================================
# Core inference
# ============================================================================

def _predict_with_model(model: SetFitModel, policy_text: str, config_text: str) -> Dict[str, Any]:
    """
    Run inference through a SetFit model.

    Returns dict with:
        prediction: "compliant" | "non_compliant"
        confidence: float (0.0 to 1.0) — distance from 0.5 decision boundary
        probability: float (0.0 to 1.0) — raw P(compliant) from the model
    """
    try:
        input_text = f"{policy_text} || {config_text}"
        probabilities = model.predict_proba([input_text])

        if hasattr(probabilities, "numpy"):
            probs = probabilities.numpy()
        elif hasattr(probabilities, "tolist"):
            probs = list(probabilities.tolist())
        else:
            probs = probabilities

        # Extract P(compliant) — second element of the binary probability vector
        if isinstance(probs, list):
            if len(probs) > 0 and isinstance(probs[0], list):
                prob_compliant = probs[0][1] if len(probs[0]) > 1 else probs[0][0]
            elif len(probs) > 0:
                prob_compliant = probs[0]
            else:
                prob_compliant = 0.5
        else:
            prob_compliant = float(probs[0][1]) if hasattr(probs[0], "__getitem__") and len(probs[0]) > 1 else 0.5

        # Prediction is whichever side of 0.5 the probability falls on;
        # confidence is the distance from the boundary (0.5).
        if prob_compliant >= 0.5:
            prediction = "compliant"
            confidence = prob_compliant
        else:
            prediction = "non_compliant"
            confidence = 1.0 - prob_compliant

        return {
            "prediction": prediction,
            "confidence": round(confidence, 4),
            "probability": round(prob_compliant, 4),
        }
    except Exception as e:
        logger.error(f"Model inference error: {e}")
        return {
            "prediction": "error",
            "confidence": 0.0,
            "probability": 0.5,
            "error": str(e),
        }


def _fuse_results(
    v6_result: Dict[str, Any],
    v4_result: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Fuse V6 and V4 predictions using weighted probability averaging.

    Both models output a P(compliant) in [0, 1].

    Fusion approach:
      1. Average P(compliant) using configured weights
      2. Determine prediction based on whether p_fused >= 0.5
      3. Calculate confidence as P(predicted_class) from the fused distribution

    This ensures consistency: if both models predict NON_COMPLIANT,
    the fused confidence reflects the probability of NON_COMPLIANT,
    not distance from the 0.5 boundary.

    Example: V6 non_compliant 72.9%, V4 non_compliant 57.4%
        V6: P(compliant)=0.271, P(non_compliant)=0.729
        V4: P(compliant)=0.426, P(non_compliant)=0.574
        p_fused(compliant) = 0.271*0.6 + 0.426*0.4 = 0.333
        p_fused(non_compliant) = 0.729*0.6 + 0.574*0.4 = 0.667
        prediction = "non_compliant" (since p_fused(compliant) < 0.5)
        confidence = 0.667 (66.7%) ✓
    """
    v6_prob = v6_result.get("probability", 0.5)
    v4_prob = v4_result.get("probability", 0.5)

    # Fuse P(compliant) with weights
    p_fused_compliant = v6_prob * V6_FUSION_WEIGHT + v4_prob * V4_FUSION_WEIGHT
    p_fused_compliant = round(p_fused_compliant, 4)

    # Determine prediction
    if p_fused_compliant >= 0.5:
        prediction = "compliant"
        confidence = round(p_fused_compliant, 4)
    else:
        prediction = "non_compliant"
        # Confidence is P(non_compliant) = 1 - P(compliant)
        confidence = round(1.0 - p_fused_compliant, 4)

    # If fused probability is close to the boundary and models disagree,
    # surface as UNCERTAIN so the operator knows to review.
    models_agree = v6_result.get("prediction") == v4_result.get("prediction")
    if not models_agree and 0.4 < p_fused_compliant < 0.6:
        prediction = "uncertain"
        # Use confidence gap as measure of disagreement
        confidence = round(abs(v6_prob - v4_prob), 4)

    return {
        "prediction": prediction,
        "confidence": confidence,
        "probability": p_fused_compliant,
    }


# ============================================================================
# Public API
# ============================================================================

def analyze_compliance(
    policy_text: str,
    config_text: str,
    vendor: str = "unknown",
    rule_id: str = "",
) -> Dict[str, Any]:
    """
    Analyze compliance using the V6→V4 dual-model pipeline.

    Flow:
      1. Run V6 (primary, high accuracy).
      2. If V6 confidence >= threshold → return V6 result directly.
      3. Else → run V4 (fallback, robust real-world performance).
      4. Fuse V6 + V4 probabilities with configured weights.
      5. If V4 unavailable, fall back to V6 result with a note.

    Args:
        policy_text: CIS rule description (e.g., "Default usernames like admin...")
        config_text: Rule-specific evidence text from extract_rule_evidence()
        vendor: Vendor name for logging (cisco_ios, juniper_junos, paloalto_panos)
        rule_id: Rule ID for logging (e.g., "CIS-1.1")

    Returns:
        Dict with keys:
            prediction: "compliant" | "non_compliant" | "uncertain"
            confidence: float 0..1
            probability: float 0..1 (P(compliant))
            model_used: "V6" | "V4" | "V6+V4" | "none"
            fallback_used: bool
            v6: {prediction, confidence, probability} or None
            v4: {prediction, confidence, probability} or None
            models_agree: bool (only present when both ran)
            vendor: str
    """
    v6_model = get_v6_model()
    if v6_model is None:
        logger.warning(f"[{rule_id}] V6 model not available")
        # Last resort: try V4 alone
        v4_model = get_v4_model()
        if v4_model is None:
            return {
                "prediction": "uncertain",
                "confidence": 0.0,
                "probability": 0.5,
                "model_used": "none",
                "fallback_used": False,
                "vendor": vendor,
                "error": "No ML models available",
            }
        v4_result = _predict_with_model(v4_model, policy_text, config_text)
        return {
            "prediction": v4_result["prediction"],
            "confidence": v4_result["confidence"],
            "probability": v4_result["probability"],
            "model_used": "V4",
            "fallback_used": True,
            "v4": v4_result,
            "vendor": vendor,
        }

    # ── Step 1: Run V6 (primary) ──────────────────────────────────────
    v6_result = _predict_with_model(v6_model, policy_text, config_text)
    v6_prob = v6_result["probability"]
    logger.info(f"[V6] {rule_id} prediction={v6_result['prediction']} confidence={v6_result['confidence']:.4f} prob={v6_prob:.4f}")

    # ── Step 2: Confidence gate ────────────────────────────────────────
    above_threshold = v6_prob >= V6_CONFIDENCE_THRESHOLD
    below_threshold = v6_prob <= (1.0 - V6_CONFIDENCE_THRESHOLD)

    if above_threshold or below_threshold:
        logger.info(f"[AI GATE] {rule_id} V6 confident ({v6_prob:.4f} >= {V6_CONFIDENCE_THRESHOLD}) → V6 ONLY")
        return {
            "prediction": v6_result["prediction"],
            "confidence": v6_result["confidence"],
            "probability": v6_prob,
            "model_used": "V6",
            "fallback_used": False,
            "v6": v6_result,
            "vendor": vendor,
        }

    # ── Step 3: V6 uncertain → run V4 fallback ────────────────────────
    logger.info(
        f"[AI GATE] {rule_id} V6 uncertain ({v6_prob:.4f} < {V6_CONFIDENCE_THRESHOLD}) → FALLBACK to V4"
    )

    v4_model = get_v4_model()
    if v4_model is None:
        logger.warning(f"[{rule_id}] V4 fallback not available, returning V6 result")
        return {
            "prediction": v6_result["prediction"],
            "confidence": v6_result["confidence"],
            "probability": v6_prob,
            "model_used": "V6",
            "fallback_used": True,
            "v6": v6_result,
            "v4_available": False,
            "vendor": vendor,
        }

    v4_result = _predict_with_model(v4_model, policy_text, config_text)
    v4_prob = v4_result["probability"]
    logger.info(f"[V4] {rule_id} prediction={v4_result['prediction']} confidence={v4_result['confidence']:.4f} prob={v4_prob:.4f}")

    # ── Step 4: Fuse V6 + V4 ──────────────────────────────────────────
    fused = _fuse_results(v6_result, v4_result)
    models_agree = v6_result["prediction"] == v4_result["prediction"]

    logger.info(
        f"[FUSION] {rule_id} v6={v6_result['prediction']}({v6_prob:.2f}) "
        f"v4={v4_result['prediction']}({v4_prob:.2f}) "
        f"agree={models_agree} final={fused['prediction']}({fused['confidence']:.4f})"
    )

    return {
        "prediction": fused["prediction"],
        "confidence": fused["confidence"],
        "probability": fused["probability"],
        "model_used": "V6+V4",
        "fallback_used": True,
        "v6": v6_result,
        "v4": v4_result,
        "models_agree": models_agree,
        "vendor": vendor,
    }


def analyze_compliance_batch(
    policy_text: str,
    config_text: str,
    vendor: str = "unknown",
    rule_id: str = "",
) -> list:
    """Legacy wrapper returning a list for backward compatibility."""
    return [analyze_compliance(policy_text, config_text, vendor, rule_id)]
