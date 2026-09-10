#!/usr/bin/env python3
"""
Evaluate trained SetFit model and provide detailed error analysis.
Uses binary predictions for metrics, uncertainty handling only for inference.
"""

import json
import torch
import numpy as np
import pandas as pd
from pathlib import Path
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report
)
from setfit import SetFitModel

# Configuration
MODEL_DIR = Path(__file__).parent.parent / "model" / "setfit"
DATA_DIR = Path(__file__).parent.parent / "data"
RESULTS_FILE = MODEL_DIR / "training_results.json"
CONFIDENCE_THRESHOLD = 0.6


def load_model():
    """Load the trained model."""
    print("Loading trained model...")
    model = SetFitModel.from_pretrained(MODEL_DIR)

    # Move to CUDA if available
    if torch.cuda.is_available():
        model.model_body.to(torch.device("cuda"))
        print("Model moved to CUDA")

    return model


def load_test_data():
    """Load test dataset."""
    test_df = pd.read_csv(DATA_DIR / "test.csv")
    return test_df


def create_input(texts):
    """Create model input strings."""
    return [f"{row['policy']} || {row['config']}" for _, row in texts.iterrows()]


def predict_with_confidence(model, texts_df):
    """Predict with confidence scores.

    For evaluation, we use binary predictions.
    Uncertainty is only used for inference layer.
    """
    texts = create_input(texts_df)

    # Get predictions (binary: 0 or 1)
    predictions = model.predict(texts)
    if hasattr(predictions, 'tolist'):
        predictions = predictions.tolist()

    # For uncertainty reporting, get probabilities
    probs = model.predict_proba(texts)
    confidences = []
    uncertainty_flags = []

    for prob in probs:
        compliant_prob = prob[1]  # Probability of class 1 (compliant)
        confidence = max(compliant_prob, 1 - compliant_prob)
        confidences.append(confidence)

        # Mark uncertainty for inference layer (not used in metrics)
        if 1 - CONFIDENCE_THRESHOLD < compliant_prob < CONFIDENCE_THRESHOLD:
            uncertainty_flags.append(True)
        else:
            uncertainty_flags.append(False)

    return predictions, confidences, uncertainty_flags


def evaluate_model(model, test_df):
    """Evaluate model on test set using binary predictions only."""
    print("\n" + "=" * 80)
    print("MODEL EVALUATION")
    print("=" * 80)

    predictions, confidences, uncertainty_flags = predict_with_confidence(model, test_df)

    # Convert to numpy for sklearn
    true_labels = test_df['label'].astype(int).tolist()
    pred_labels = np.array(predictions)
    true_arr = np.array(true_labels)

    # Calculate metrics (using binary predictions only)
    accuracy = accuracy_score(true_arr, pred_labels)
    precision = precision_score(true_arr, pred_labels, average='binary', zero_division=0)
    recall = recall_score(true_arr, pred_labels, average='binary', zero_division=0)
    f1 = f1_score(true_arr, pred_labels, average='binary', zero_division=0)

    print(f"\nOverall Test Metrics:")
    print(f"  Accuracy:  {accuracy:.4f}")
    print(f"  Precision: {precision:.4f}")
    print(f"  Recall:    {recall:.4f}")
    print(f"  F1-Score:  {f1:.4f}")
    print(f"  Test examples: {len(true_labels)}")

    # Confusion matrix
    cm = confusion_matrix(true_arr, pred_labels)
    print(f"\nConfusion Matrix:")
    print(f"  [[TN, FP],")
    print(f"   [FN, TP]]")
    print(f"  {cm.tolist()}")

    # Classification report
    print(f"\nClassification Report:")
    print(classification_report(true_arr, pred_labels, target_names=['Non-compliant', 'Compliant']))

    # Per-rule metrics
    print(f"\nPer-Rule Metrics:")
    rule_results = {}
    for rule in sorted(test_df['rule_id'].unique()):
        rule_mask = test_df['rule_id'] == rule
        rule_preds = pred_labels[rule_mask]
        rule_true = true_arr[rule_mask]

        if len(rule_true) > 0:
            rule_acc = accuracy_score(rule_true, rule_preds)
            rule_f1 = f1_score(rule_true, rule_preds, average='binary', zero_division=0)
            rule_results[rule] = {'accuracy': rule_acc, 'f1': rule_f1, 'count': len(rule_true)}
            print(f"  {rule}: accuracy={rule_acc:.4f}, f1={rule_f1:.4f}, n={len(rule_true)}")

    # Per-vendor metrics
    print(f"\nPer-Vendor Metrics:")
    vendor_results = {}
    for vendor in sorted(test_df['vendor'].unique()):
        vendor_mask = test_df['vendor'] == vendor
        vendor_preds = pred_labels[vendor_mask]
        vendor_true = true_arr[vendor_mask]

        if len(vendor_true) > 0:
            vendor_acc = accuracy_score(vendor_true, vendor_preds)
            vendor_f1 = f1_score(vendor_true, vendor_preds, average='binary', zero_division=0)
            vendor_results[vendor] = {'accuracy': vendor_acc, 'f1': vendor_f1, 'count': len(vendor_true)}
            print(f"  {vendor}: accuracy={vendor_acc:.4f}, f1={vendor_f1:.4f}, n={len(vendor_true)}")

    return {
        'predictions': predictions,
        'confidences': confidences,
        'true_labels': true_labels,
        'accuracy': accuracy,
        'precision': precision,
        'recall': recall,
        'f1': f1,
        'confusion_matrix': cm.tolist(),
        'rule_results': rule_results,
        'vendor_results': vendor_results,
    }


def error_analysis(model, test_df, results):
    """Perform detailed error analysis."""
    print("\n" + "=" * 80)
    print("ERROR ANALYSIS")
    print("=" * 80)

    predictions = results['predictions']
    true_labels = results['true_labels']
    confidences = results['confidences']

    # Find incorrect predictions
    errors = []
    for i, (pred, true, conf) in enumerate(zip(predictions, true_labels, confidences)):
        if pred != true:
            errors.append({
                'index': i,
                'rule_id': test_df.iloc[i]['rule_id'],
                'vendor': test_df.iloc[i]['vendor'],
                'policy': test_df.iloc[i]['policy'],
                'config': test_df.iloc[i]['config'],
                'true_label': true,
                'predicted_label': pred,
                'confidence': conf,
            })

    print(f"\nTotal errors: {len(errors)} out of {len(test_df)} examples")
    print(f"Error rate: {len(errors)/len(test_df)*100:.1f}%")

    # Show at least 15 predictions (including errors and correct ones)
    print(f"\nSample Predictions (showing {min(15, len(test_df))} examples):")
    print("-" * 80)

    sample_indices = list(range(min(15, len(test_df))))
    for idx in sample_indices:
        ex = test_df.iloc[idx]
        pred = predictions[idx]
        true = true_labels[idx]
        conf = confidences[idx]

        pred_str = "COMPLIANT" if pred == 1 else "NON-COMPLIANT"
        true_str = "COMPLIANT" if true == 1 else "NON-COMPLIANT"
        marker = " <- ERROR" if pred != true else ""

        print(f"\nExample {idx+1}: {marker}")
        print(f"  Rule: {ex['rule_id']}")
        print(f"  Vendor: {ex['vendor']}")
        print(f"  Policy: {ex['policy']}")
        print(f"  Config: {ex['config'][:100]}{'...' if len(ex['config']) > 100 else ''}")
        print(f"  True: {true_str} | Predicted: {pred_str} | Confidence: {conf:.3f}")

    # Analyze error patterns
    if errors:
        print(f"\nError Pattern Analysis:")
        print(f"  By rule:")
        rule_errors = {}
        for err in errors:
            rule = err['rule_id']
            rule_errors[rule] = rule_errors.get(rule, 0) + 1
        for rule, count in sorted(rule_errors.items()):
            print(f"    {rule}: {count} errors")

        print(f"  By vendor:")
        vendor_errors = {}
        for err in errors:
            vendor = err['vendor']
            vendor_errors[vendor] = vendor_errors.get(vendor, 0) + 1
        for vendor, count in sorted(vendor_errors.items()):
            print(f"    {vendor}: {count} errors")

        # Analyze error types
        print(f"\nError Type Analysis:")
        false_positives = sum(1 for e in errors if e['true_label'] == 0 and e['predicted_label'] == 1)
        false_negatives = sum(1 for e in errors if e['true_label'] == 1 and e['predicted_label'] == 0)
        print(f"  False Positives (predicted compliant but non-compliant): {false_positives}")
        print(f"  False Negatives (predicted non-compliant but compliant): {false_negatives}")


def main():
    """Main evaluation pipeline."""
    print("=" * 80)
    print("ML COMPLIANCE MODEL EVALUATION")
    print("=" * 80)

    # Load model
    model = load_model()

    # Load test data
    test_df = load_test_data()

    # Evaluate
    results = evaluate_model(model, test_df)

    # Error analysis
    error_analysis(model, test_df, results)

    # Save detailed results
    output_file = MODEL_DIR / "evaluation_results.json"
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)
    print(f"\nDetailed results saved to: {output_file}")


if __name__ == "__main__":
    main()
