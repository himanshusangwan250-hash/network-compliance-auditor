#!/usr/bin/env python3
"""
Threshold Experiment for Model V4.
Test different confidence thresholds to find optimal precision-recall balance.
"""

import os
os.environ['KMP_DUPLICATE_LIB_OK'] = 'TRUE'

import sys
import numpy as np
import pandas as pd
from pathlib import Path
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from setfit import SetFitModel

# ============================================================================
# Configuration
# ============================================================================

MODEL_DIR = Path(__file__).parent / "setfit_v4"
DATA_DIR = Path(__file__).parent.parent / "data_v4"

# Thresholds to test
THRESHOLDS = [0.50, 0.55, 0.60, 0.65, 0.70, 0.75]


def load_model():
    """Load V4 model."""
    print(f"Loading V4 model from: {MODEL_DIR}")
    model = SetFitModel.from_pretrained(str(MODEL_DIR))
    print("Model loaded successfully")
    return model


def load_data():
    """Load test data."""
    test_df = pd.read_csv(DATA_DIR / "test.csv")
    test_df['label'] = test_df['label'].astype(int)
    print(f"Loaded test set: {len(test_df)} examples")
    return test_df


def format_text(row):
    """Format input text."""
    return f"{row['policy']} || {row['config']}"


def get_probabilities(model, texts):
    """Get prediction probabilities."""
    probs = model.predict_proba(texts)
    # Convert to numpy array if needed
    if hasattr(probs, 'numpy'):
        probs = probs.numpy()
    elif hasattr(probs, 'tolist'):
        probs = np.array(probs)
    else:
        probs = np.array(probs)

    # predict_proba returns [[prob_non_compliant, prob_compliant]]
    # We want prob_compliant (index 1)
    if probs.ndim == 2:
        return probs[:, 1]  # probability of being compliant (class 1)
    return probs


def evaluate_threshold(model, test_df, threshold):
    """Evaluate model with specific threshold."""
    texts = [format_text(row) for _, row in test_df.iterrows()]
    labels = test_df['label'].tolist()

    # Get probabilities
    probs = get_probabilities(model, texts)

    # Apply threshold
    predictions = (probs >= threshold).astype(int)

    # Calculate metrics
    accuracy = accuracy_score(labels, predictions)
    precision = precision_score(labels, predictions, zero_division=0)
    recall = recall_score(labels, predictions, zero_division=0)
    f1 = f1_score(labels, predictions, zero_division=0)

    return {
        'threshold': threshold,
        'accuracy': accuracy,
        'precision': precision,
        'recall': recall,
        'f1': f1,
        'predictions': predictions,
        'probabilities': probs,
    }


def main():
    """Run threshold experiment."""
    print("=" * 80)
    print("THRESHOLD EXPERIMENT - MODEL V4")
    print("=" * 80)

    # Load model and data
    model = load_model()
    test_df = load_data()

    print(f"\nTesting thresholds: {THRESHOLDS}")
    print()

    # Test each threshold
    results = []
    for threshold in THRESHOLDS:
        result = evaluate_threshold(model, test_df, threshold)
        results.append(result)

        print(f"Threshold {threshold:.2f}:")
        print(f"  Accuracy:  {result['accuracy']*100:.2f}%")
        print(f"  Precision: {result['precision']*100:.2f}%")
        print(f"  Recall:    {result['recall']*100:.2f}%")
        print(f"  F1-Score:  {result['f1']*100:.2f}%")
        print()

    # Find optimal threshold
    print("=" * 80)
    print("OPTIMAL THRESHOLD SELECTION")
    print("=" * 80)

    # Strategy 1: Maximize F1
    best_f1 = max(results, key=lambda x: x['f1'])
    print(f"\nBest F1 Score: {best_f1['f1']*100:.2f}% at threshold {best_f1['threshold']:.2f}")

    # Strategy 2: Best balance (maximize min(precision, recall))
    balanced = max(results, key=lambda x: min(x['precision'], x['recall']))
    print(f"Best Balanced: {balanced['f1']*100:.2f}% at threshold {balanced['threshold']:.2f}")
    print(f"  Precision: {balanced['precision']*100:.2f}%, Recall: {balanced['recall']*100:.2f}%")

    # Strategy 3: Default threshold (0.6)
    default = next((r for r in results if r['threshold'] == 0.6), None)
    if default:
        print(f"\nDefault Threshold (0.6):")
        print(f"  Accuracy:  {default['accuracy']*100:.2f}%")
        print(f"  Precision: {default['precision']*100:.2f}%")
        print(f"  Recall:    {default['recall']*100:.2f}%")
        print(f"  F1-Score:  {default['f1']*100:.2f}%")

    # Per-rule analysis at optimal threshold
    print("\n" + "=" * 80)
    print("PER-RULE ANALYSIS AT OPTIMAL THRESHOLD")
    print("=" * 80)

    optimal_threshold = best_f1['threshold']
    optimal_result = best_f1

    for rule in sorted(test_df['rule_id'].unique()):
        rule_mask = test_df['rule_id'] == rule
        rule_preds = optimal_result['predictions'][rule_mask.values]
        rule_labels = np.array(optimal_result['probabilities'])[rule_mask.values]

        # Apply threshold
        rule_preds = (rule_labels >= optimal_threshold).astype(int)
        true_labels = test_df.loc[rule_mask, 'label'].tolist()

        rule_acc = accuracy_score(true_labels, rule_preds)
        rule_f1 = f1_score(true_labels, rule_preds, zero_division=0)

        print(f"  {rule}: accuracy={rule_acc*100:.1f}%, f1={rule_f1*100:.1f}%, n={len(true_labels)}")

    print("\n" + "=" * 80)
    print("RECOMMENDATION")
    print("=" * 80)
    print(f"\nUse threshold: {optimal_threshold:.2f}")
    print(f"  Accuracy:  {optimal_result['accuracy']*100:.2f}%")
    print(f"  Precision: {optimal_result['precision']*100:.2f}%")
    print(f"  Recall:    {optimal_result['recall']*100:.2f}%")
    print(f"  F1-Score:  {optimal_result['f1']*100:.2f}%")


if __name__ == "__main__":
    main()
