#!/usr/bin/env python3
"""
Evaluate V4 model on real-world holdout configs.
Uses the 5 reserved holdout files from HOLDOUT_MANIFEST.md.
"""

import os
os.environ['KMP_DUPLICATE_LIB_OK'] = 'TRUE'

import sys
import numpy as np
import pandas as pd
from pathlib import Path
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from backend.parser.cisco_ios import parse_cisco_ios
from backend.compliance.models import NormalizedConfig, NormalizedUser
from backend.compliance.rules_engine import evaluate_compliance
from setfit import SetFitModel

# ============================================================================
# Configuration
# ============================================================================

MODEL_DIR = Path(__file__).parent.parent / "model" / "setfit_v4"
HOLDOUT_DIR = Path(__file__).parent.parent.parent / "real_configs"

# Holdout files (reserved for final evaluation)
HOLDOUT_FILES = {
    'basic-cisco-router-config.txt',
    'R1-base-config.txt',
    'SW1-base-config.txt',
    'R1-config.txt',
    'SW1-config.txt',
}

# Policy texts for each rule
POLICY_TEXTS = {
    "CIS-1.1": "Administrative accounts must not use vendor-default credentials",
    "CIS-1.2": "All user passwords must be encrypted using secure hashing algorithms",
    "CIS-2.1": "Network devices must forward security events to approved centralized logging",
    "CIS-2.2": "Network infrastructure must synchronize clock with approved time sources",
    "CIS-3.1": "SNMP must use secure community names and modern protocol versions",
    "CIS-4.1": "Security zones must be configured to enforce traffic segmentation",
}


def load_model():
    """Load V4 model."""
    print(f"Loading V4 model from: {MODEL_DIR}")
    model = SetFitModel.from_pretrained(str(MODEL_DIR))
    print("Model loaded successfully")
    return model


def load_holdout_configs():
    """Load holdout configuration files."""
    configs = {}
    for root, dirs, files in os.walk(HOLDOUT_DIR):
        for f in files:
            filepath = Path(root) / f
            # Match by checking if filename is in holdout list
            if f in HOLDOUT_FILES:
                try:
                    with open(filepath, 'r', encoding='utf-8', errors='ignore') as fh:
                        content = fh.read()
                        if len(content.strip()) > 100:
                            configs[f] = content
                except:
                    continue
    return configs


def evaluate_with_rules_engine(content):
    """Evaluate config with deterministic rules engine."""
    parsed = parse_cisco_ios(content)
    if not parsed:
        return []

    # Extract logging hosts correctly
    logging_hosts = [entry.get('host') for entry in parsed.get('logging', []) if entry.get('host')]

    norm = NormalizedConfig(
        vendor='cisco_ios',
        format='cli',
        hostname=parsed.get('hostname', 'device'),
        users=[NormalizedUser(name=u.get('name'), encrypted=u.get('encrypted'))
               for u in parsed.get('users', [])],
        ntp_servers=parsed.get('ntp', []),
        logging_hosts=logging_hosts,
        snmp_communities=[],
        zones=[],
    )

    findings = evaluate_compliance(norm)
    return findings


def evaluate_with_ml_model(model, policy_text, config_text):
    """Evaluate config with ML model."""
    input_text = f"{policy_text} || {config_text}"
    prediction = model.predict([input_text])[0]
    probabilities = model.predict_proba([input_text])

    if hasattr(probabilities, 'numpy'):
        probs = probabilities.numpy()
    elif hasattr(probabilities, 'tolist'):
        probs = np.array(probabilities.tolist())
    else:
        probs = np.array(probabilities)

    if probs.ndim == 2:
        prob_compliant = probs[0, 1]
    else:
        prob_compliant = probs[0] if len(probs) > 0 else 0.5

    return int(prediction), float(prob_compliant)


def main():
    """Run holdout evaluation."""
    print("=" * 80)
    print("REAL-WORLD HOLDOUT EVALUATION - MODEL V4")
    print("=" * 80)

    # Load model and configs
    model = load_model()
    configs = load_holdout_configs()
    print(f"\nLoaded {len(configs)} holdout configs")

    # Evaluate each config
    all_results = []

    for config_name, content in configs.items():
        print(f"\n{'='*60}")
        print(f"Config: {config_name}")
        print(f"{'='*60}")

        # Get rules engine findings
        findings = evaluate_with_rules_engine(content)

        # Evaluate each applicable rule
        for finding in findings:
            if finding.rule_id not in POLICY_TEXTS:
                continue

            policy_text = POLICY_TEXTS[finding.rule_id]

            # ML prediction
            ml_pred, ml_prob = evaluate_with_ml_model(model, policy_text, content)

            # Rules engine prediction
            rules_status = finding.status  # PASS/FAIL/UNKNOWN

            # Convert to labels
            rules_label = 1 if rules_status == 'PASS' else 0
            ml_label = ml_pred

            # Check if they match
            match = "MATCH" if ml_label == rules_label else "MISMATCH"

            print(f"\n{finding.rule_id}:")
            print(f"  Rules Engine: {rules_status} (label={rules_label})")
            print(f"  ML Model:     {ml_label} (prob={ml_prob:.4f})")
            print(f"  Result:       {match}")

            all_results.append({
                'config': config_name,
                'rule_id': finding.rule_id,
                'rules_label': rules_label,
                'ml_label': ml_label,
                'ml_prob': ml_prob,
                'match': ml_label == rules_label,
            })

    # Summary statistics
    print("\n" + "=" * 80)
    print("SUMMARY")
    print("=" * 80)

    df = pd.DataFrame(all_results)
    if len(df) > 0:
        total = len(df)
        matches = df['match'].sum()
        match_rate = matches / total * 100

        print(f"\nTotal evaluations: {total}")
        print(f"Matches: {matches} ({match_rate:.1f}%)")
        print(f"Mismatches: {total - matches} ({100 - match_rate:.1f}%)")

        # By rule
        print(f"\nMatch rate by rule:")
        for rule in sorted(df['rule_id'].unique()):
            rule_df = df[df['rule_id'] == rule]
            rule_matches = rule_df['match'].sum()
            rule_total = len(rule_df)
            rule_rate = rule_matches / rule_total * 100 if rule_total > 0 else 0
            print(f"  {rule}: {rule_matches}/{rule_total} ({rule_rate:.1f}%)")

        # By config
        print(f"\nMatch rate by config:")
        for config in sorted(df['config'].unique()):
            config_df = df[df['config'] == config]
            config_matches = config_df['match'].sum()
            config_total = len(config_df)
            config_rate = config_matches / config_total * 100 if config_total > 0 else 0
            print(f"  {config}: {config_matches}/{config_total} ({config_rate:.1f}%)")
    else:
        print("No results to summarize")

    print("\n" + "=" * 80)
    print("HOLDOUT EVALUATION COMPLETE")
    print("=" * 80)


if __name__ == "__main__":
    main()
