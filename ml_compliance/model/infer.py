#!/usr/bin/env python3
"""
Inference module for ML compliance layer.
Supports compliant, non_compliant, and uncertain predictions.
"""

import sys
import json
import torch
import numpy as np
from pathlib import Path
from setfit import SetFitModel

# Configuration
MODEL_DIR = Path(__file__).parent / "setfit"
CONFIDENCE_THRESHOLD = 0.6


def load_model():
    """Load the trained model."""
    print(f"Loading model from {MODEL_DIR}...")
    model = SetFitModel.from_pretrained(MODEL_DIR)

    # Move to CUDA if available
    if torch.cuda.is_available():
        model.model_body.to(torch.device("cuda"))
        print("Model moved to CUDA")

    return model


def predict(policy: str, config: str, vendor: str, model, threshold: float = CONFIDENCE_THRESHOLD) -> dict:
    """
    Predict compliance status.

    Args:
        policy: Security policy description
        config: Configuration text
        vendor: Vendor name (cisco, juniper, paloalto)
        model: Trained SetFit model
        threshold: Confidence threshold for uncertain predictions

    Returns:
        Dictionary with prediction, confidence, vendor, and rule_id
    """
    # Create input
    input_text = f"{policy} || {config}"

    # Get predictions
    predictions = model.predict([input_text])
    probs = model.predict_proba([input_text])

    if hasattr(predictions, 'tolist'):
        predictions = predictions.tolist()
    if hasattr(probs, 'tolist'):
        probs = probs.tolist()

    # Extract result
    pred = predictions[0]
    prob = probs[0][1]  # Probability of compliant class

    # Determine label and confidence
    if prob >= threshold:
        label = "compliant"
        confidence = prob
    elif prob <= (1 - threshold):
        label = "non_compliant"
        confidence = 1 - prob
    else:
        label = "uncertain"
        confidence = max(prob, 1 - prob)

    # Extract rule_id from policy (simplified)
    rule_id = extract_rule_id(policy)

    return {
        "prediction": label,
        "confidence": round(confidence, 4),
        "vendor": vendor,
        "rule_id": rule_id,
        "probability_compliant": round(prob, 4),
    }


def extract_rule_id(policy: str) -> str:
    """Extract rule ID from policy description."""
    policy_lower = policy.lower()

    if "default credential" in policy_lower or "default username" in policy_lower:
        return "CIS-1.1"
    elif "password encryption" in policy_lower or "encrypted" in policy_lower:
        return "CIS-1.2"
    elif "syslog" in policy_lower or "logging" in policy_lower:
        return "CIS-2.1"
    elif "ntp" in policy_lower:
        return "CIS-2.2"
    elif "snmp" in policy_lower:
        return "CIS-3.1"
    elif "zone" in policy_lower or "segmentation" in policy_lower:
        return "CIS-4.1"
    else:
        return "unknown"


def main():
    """CLI interface for inference."""
    import argparse

    parser = argparse.ArgumentParser(description="ML Compliance Inference")
    parser.add_argument("--policy", required=True, help="Security policy description")
    parser.add_argument("--config", required=True, help="Configuration text")
    parser.add_argument("--vendor", required=True, choices=["cisco", "juniper", "paloalto"],
                       help="Vendor name")
    parser.add_argument("--threshold", type=float, default=CONFIDENCE_THRESHOLD,
                       help=f"Confidence threshold (default: {CONFIDENCE_THRESHOLD})")

    args = parser.parse_args()

    # Update threshold (use local variable instead)
    threshold = args.threshold

    # Load model
    model = load_model()

    # Predict
    result = predict(args.policy, args.config, args.vendor, model)

    # Output
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
