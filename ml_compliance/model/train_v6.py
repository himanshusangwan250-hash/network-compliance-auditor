#!/usr/bin/env python3
"""
Train Model V6 - Rule-Conditioned Evidence Classification.

Uses the same format as production inference:
  "Policy: <policy>\nRule: <rule_id>\nEvidence: <config>"

Architecture:
  Model input = Policy + Rule ID + Raw Config Evidence
  Model output = compliant / non_compliant
"""

import os
os.environ['KMP_DUPLICATE_LIB_OK'] = 'TRUE'
os.environ['PYTORCH_CUDA_ALLOC_CONF'] = 'expandable_segments:True'

import json
import sys
import time
import torch
import gc
import numpy as np
import pandas as pd
from pathlib import Path
from datasets import Dataset
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report
)
from setfit import SetFitModel, Trainer, TrainingArguments

# ============================================================================
# Configuration
# ============================================================================

MODEL_NAME = "all-MiniLM-L6-v2"
OUTPUT_DIR = Path(__file__).parent / "setfit_v6"
DATA_DIR = Path(__file__).parent.parent / "data_v6"
RANDOM_SEED = 42
CONFIDENCE_THRESHOLD = 0.70  # V5 threshold

# Training hyperparameters
EMBEDDING_EPOCHS = 2
CLASSIFIER_EPOCHS = 5
MAX_STEPS = 1000  # Same as V5
BATCH_SIZE = 16   # Increased from V5's 8 for speed
LEARNING_RATE = 2e-5
HEAD_LEARNING_RATE = 1e-2
MAX_LENGTH = 512  # Increased from 256 for longer rule-conditioned inputs


def setup_environment():
    """Print environment info and verify GPU."""
    print("=" * 80)
    print("MODEL V6 TRAINING ENVIRONMENT")
    print("=" * 80)
    print(f"Python version: {sys.version.split()[0]}")
    print(f"PyTorch version: {torch.__version__}")
    print(f"CUDA available: {torch.cuda.is_available()}")
    if torch.cuda.is_available():
        print(f"GPU: {torch.cuda.get_device_name(0)}")
        print(f"VRAM: {torch.cuda.get_device_properties(0).total_memory / (1024**3):.1f} GB")
        print(f"CUDA version: {torch.version.cuda}")
    else:
        print("WARNING: CUDA not available. Training on CPU.")
    print()


def load_data():
    """Load V6 dataset splits."""
    print(f"Loading data from: {DATA_DIR}")
    train_df = pd.read_csv(DATA_DIR / "train.csv")
    val_df = pd.read_csv(DATA_DIR / "validation.csv")
    test_df = pd.read_csv(DATA_DIR / "test.csv")

    train_df['label'] = train_df['label'].astype(int)
    val_df['label'] = val_df['label'].astype(int)
    test_df['label'] = test_df['label'].astype(int)

    print(f"  Train: {len(train_df)} examples")
    print(f"  Validation: {len(val_df)} examples")
    print(f"  Test: {len(test_df)} examples")
    return train_df, val_df, test_df


def create_datasets(df: pd.DataFrame):
    """Create HuggingFace Datasets."""
    return Dataset.from_dict({
        "text": df['input_text'].tolist(),
        "label": df['label'].astype(int).tolist(),
    })


def benchmark_throughput(model, texts):
    """Benchmark inference throughput."""
    import time
    n = min(10, len(texts))
    start = time.time()
    for _ in range(3):
        model.predict(texts[:n])
    elapsed = time.time() - start
    samples_per_sec = (n * 3) / elapsed
    print(f"\nBenchmark: {samples_per_sec:.1f} samples/sec")
    return samples_per_sec


def train_model():
    """Train the SetFit model on V6 data."""
    print("\n" + "=" * 80)
    print("TRAINING MODEL V6")
    print("=" * 80)

    train_df, val_df, test_df = load_data()

    train_ds = create_datasets(train_df)
    val_ds = create_datasets(val_df)

    # Verify label balance
    comp_train = sum(train_df['label'].tolist())
    non_comp_train = len(train_df) - comp_train
    print(f"\nTraining labels: {comp_train} compliant, {non_comp_train} non-compliant")

    # Initialize model
    print(f"\nLoading base model: {MODEL_NAME}")
    model = SetFitModel.from_pretrained(MODEL_NAME)

    # Move model to CUDA
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model.model_body.to(device)
    print(f"Model moved to: {device}")

    # Training arguments
    training_args = TrainingArguments(
        num_epochs=(EMBEDDING_EPOCHS, CLASSIFIER_EPOCHS),
        max_steps=MAX_STEPS,
        batch_size=BATCH_SIZE,
        body_learning_rate=LEARNING_RATE,
        head_learning_rate=HEAD_LEARNING_RATE,
        max_length=MAX_LENGTH,
        output_dir=str(OUTPUT_DIR),
        eval_strategy="epoch",
        save_strategy="epoch",
        logging_strategy="steps",
        logging_steps=50,
        report_to="none",
        seed=RANDOM_SEED,
    )

    # Print configuration
    print(f"\nTraining Configuration:")
    print(f"  Embedding epochs: {EMBEDDING_EPOCHS}")
    print(f"  Classifier epochs: {CLASSIFIER_EPOCHS}")
    print(f"  Max steps: {MAX_STEPS}")
    print(f"  Batch size: {BATCH_SIZE}")
    print(f"  Learning rate (body): {LEARNING_RATE}")
    print(f"  Learning rate (head): {HEAD_LEARNING_RATE}")
    print(f"  Max length: {MAX_LENGTH}")

    # Train
    start_time = time.time()
    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=train_ds,
        eval_dataset=val_ds,
    )

    print(f"\nStarting training on {device}...")
    trainer.train()
    training_time = time.time() - start_time

    throughput = len(train_df) / training_time
    print(f"\nTraining completed in {training_time:.1f} seconds ({training_time/60:.1f} minutes)")
    print(f"Throughput: {throughput:.1f} samples/sec")
    return model, train_df, val_df, test_df, training_time, throughput


def evaluate_model(model, test_df, split_name="test"):
    """Evaluate model on a split."""
    texts = test_df['input_text'].tolist()
    labels = test_df['label'].astype(int).tolist()

    predictions = model.predict(texts)
    if hasattr(predictions, 'tolist'):
        predictions = predictions.tolist()

    predictions = np.array(predictions)
    labels = np.array(labels)

    accuracy = accuracy_score(labels, predictions)
    precision = precision_score(labels, predictions, average='binary', zero_division=0)
    recall = recall_score(labels, predictions, average='binary', zero_division=0)
    f1 = f1_score(labels, predictions, average='binary', zero_division=0)

    print(f"\n{split_name.upper()} Metrics:")
    print(f"  Accuracy:  {accuracy:.4f}")
    print(f"  Precision: {precision:.4f}")
    print(f"  Recall:    {recall:.4f}")
    print(f"  F1-Score:  {f1:.4f}")
    print(f"  Examples:  {len(labels)}")

    cm = confusion_matrix(labels, predictions)
    print(f"\nConfusion Matrix:")
    print(f"  [[TN, FP],")
    print(f"   [FN, TP]]")
    print(f"  {cm.tolist()}")

    # Per-rule metrics
    print(f"\nPer-Rule Metrics:")
    rule_metrics = {}
    for rule in sorted(test_df['rule_id'].unique()):
        rule_mask = test_df['rule_id'] == rule
        rule_preds = predictions[rule_mask.values]
        rule_true = labels[rule_mask.values]

        if len(rule_true) > 0:
            rule_acc = accuracy_score(rule_true, rule_preds)
            rule_f1 = f1_score(rule_true, rule_preds, average='binary', zero_division=0)
            rule_metrics[rule] = {'accuracy': rule_acc, 'f1': rule_f1, 'count': len(rule_true)}
            flag = ' [SMALL]' if len(rule_true) < 20 else ''
            print(f"  {rule}: acc={rule_acc:.4f}, f1={rule_f1:.4f}, n={len(rule_true)}{flag}")

    # Per-vendor metrics
    print(f"\nPer-Vendor Metrics:")
    vendor_metrics = {}
    for vendor in sorted(test_df['vendor'].unique()):
        vendor_mask = test_df['vendor'] == vendor
        vendor_preds = predictions[vendor_mask.values]
        vendor_true = labels[vendor_mask.values]

        if len(vendor_true) > 0:
            vendor_acc = accuracy_score(vendor_true, vendor_preds)
            vendor_f1 = f1_score(vendor_true, vendor_preds, average='binary', zero_division=0)
            vendor_metrics[vendor] = {'accuracy': vendor_acc, 'f1': vendor_f1, 'count': len(vendor_true)}
            print(f"  {vendor}: acc={vendor_acc:.4f}, f1={vendor_f1:.4f}, n={len(vendor_true)}")

    return {
        'predictions': predictions.tolist(),
        'accuracy': accuracy,
        'precision': precision,
        'recall': recall,
        'f1': f1,
        'confusion_matrix': cm.tolist(),
        'rule_metrics': rule_metrics,
        'vendor_metrics': vendor_metrics,
    }


def evaluate_paloalto_holdout(model):
    """Evaluate on the real-world Palo Alto holdout config."""
    print("\n" + "=" * 80)
    print("PALO ALTO HOLDOVER EVALUATION")
    print("=" * 80)

    from backend.parser.vendor_detector import detect_vendor
    from backend.parser.paloalto_panos import parse_paloalto_panos
    from backend.compliance.models import normalize
    from backend.ml.evidence_extractor import extract_rule_evidence
    from backend.compliance.rules_engine import get_rule_ids, get_rule_details

    PA_CONFIG = '''<?xml version="1.0" encoding="UTF-8"?>
<config version="10.0" urldb="panupv2-all-contents-8625-7698">
  <mgt-config>
    <users>
      <entry name="admin">
        <phash>$1$abcd1234$XyZQeR9tKp7mNv3sLf0Hq1</phash>
        <permissions><role-based><superuser>yes</superuser></role-based></permissions>
      </entry>
      <entry name="svc-monitor">
        <password>Monitor@123</password>
        <permissions><role-based><superreader>yes</superreader></role-based></permissions>
      </entry>
    </users>
  </mgt-config>
  <log-settings>
    <syslog><entry name="syslog-primary"><server><entry name="server1"><ip-address>192.168.1.50</ip-address><port>514</port></entry></server></entry></syslog>
  </log-settings>
  <deviceconfig><system><hostname>TEST-PAFW-02</hostname><ntp-servers><primary>192.168.1.10</primary><secondary>192.168.1.11</secondary></ntp-servers></system></deviceconfig>
  <vsys><entry name="vsys1"><zone><entry name="trust"><network><member>ethernet1/1</member></network></entry><entry name="untrust"><network><member>ethernet1/2</member></network></entry></zone></entry></vsys>
  <snmp><community><entry name="secure-monitoring"><version>v3</version></entry></community></snmp>
</config>'''

    vendor = detect_vendor(PA_CONFIG)
    parsed = parse_paloalto_panos(PA_CONFIG)
    normalized = normalize(vendor['vendor'], parsed)

    from backend.ml.semantic_compliance import analyze_compliance

    print(f"Vendor: {vendor['vendor']} | Hostname: {normalized.hostname}")
    print()

    expected = {
        'CIS-1.1': 'FAIL',
        'CIS-1.2': 'FAIL',
        'CIS-2.1': 'PASS',
        'CIS-2.2': 'PASS',
        'CIS-3.1': 'PASS',
        'CIS-4.1': 'PASS',
    }

    correct = 0
    total = 0
    for rule_id in get_rule_ids():
        rule_info = get_rule_details(rule_id)
        policy_text = rule_info['description']
        evidence_text = extract_rule_evidence(rule_id, normalized)

        result = analyze_compliance(policy_text, evidence_text, vendor['vendor'], rule_id)
        prediction = result.get('prediction', 'uncertain')
        status = 'PASS' if prediction == 'compliant' else ('FAIL' if prediction == 'non_compliant' else 'UNKNOWN')

        match = "✓" if status == expected.get(rule_id) else "✗"
        if status == expected.get(rule_id):
            correct += 1
        total += 1

        print(f"{rule_id}: {status:7} | conf={result.get('confidence', 0):.2%} | model={result.get('model_used', '?')} | expected={expected[rule_id]} {match}")

    print(f"\nPalo Alto Holdout: {correct}/{total} correct")
    return correct, total


def save_results(model, val_results, test_results, training_time, throughput):
    """Save results to JSON."""
    print("\n" + "=" * 80)
    print("SAVING MODEL V6 ARTIFACTS")
    print("=" * 80)

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    model.save_pretrained(OUTPUT_DIR)

    results = {
        'model_version': 'v6',
        'training_config': {
            'model_name': MODEL_NAME,
            'embedding_epochs': EMBEDDING_EPOCHS,
            'classifier_epochs': CLASSIFIER_EPOCHS,
            'max_steps': MAX_STEPS,
            'batch_size': BATCH_SIZE,
            'learning_rate': LEARNING_RATE,
            'head_learning_rate': HEAD_LEARNING_RATE,
            'max_length': MAX_LENGTH,
            'random_seed': RANDOM_SEED,
            'confidence_threshold': CONFIDENCE_THRESHOLD,
            'training_time_seconds': training_time,
            'throughput_samples_per_sec': round(throughput, 1),
        },
        'hardware': {
            'device': 'cuda' if torch.cuda.is_available() else 'cpu',
            'gpu_name': torch.cuda.get_device_name(0) if torch.cuda.is_available() else 'N/A',
            'gpu_memory_gb': round(torch.cuda.get_device_properties(0).total_memory / (1024**3), 1) if torch.cuda.is_available() else 'N/A',
            'cuda_version': torch.version.cuda if torch.cuda.is_available() else 'N/A',
            'python_version': sys.version.split()[0],
            'pytorch_version': torch.__version__,
        },
        'validation_metrics': {
            'accuracy': val_results['accuracy'],
            'precision': val_results['precision'],
            'recall': val_results['recall'],
            'f1': val_results['f1'],
            'confusion_matrix': val_results['confusion_matrix'],
            'rule_metrics': val_results['rule_metrics'],
            'vendor_metrics': val_results['vendor_metrics'],
        },
        'test_metrics': {
            'accuracy': test_results['accuracy'],
            'precision': test_results['precision'],
            'recall': test_results['recall'],
            'f1': test_results['f1'],
            'confusion_matrix': test_results['confusion_matrix'],
            'rule_metrics': test_results['rule_metrics'],
            'vendor_metrics': test_results['vendor_metrics'],
        },
        'dependencies': {
            'pytorch': torch.__version__,
            'cuda': torch.version.cuda if torch.cuda.is_available() else 'N/A',
            'sentence_transformers': __import__('sentence_transformers').__version__,
            'setfit': __import__('setfit').__version__,
            'scikit_learn': __import__('sklearn').__version__,
        },
    }

    results_file = OUTPUT_DIR / "training_results_v6.json"
    with open(results_file, 'w') as f:
        json.dump(results, f, indent=2, default=str)

    print(f"Model saved to: {OUTPUT_DIR}")
    print(f"Results saved to: {results_file}")
    return results


def cleanup():
    """Clean up resources."""
    print("\nCleaning up resources...")
    if 'model' in locals():
        del model
    if 'trainer' in locals():
        del trainer
    gc.collect()
    if torch.cuda.is_available():
        torch.cuda.empty_cache()
    print("Cleanup complete")


def main():
    print("=" * 80)
    print("MODEL V6 TRAINING - Rule-Conditioned Evidence Classification")
    print("=" * 80)
    print(f"Data directory: {DATA_DIR}")
    print(f"Model output: {OUTPUT_DIR}")
    print()

    setup_environment()

    try:
        start_time = time.time()
        model, train_df, val_df, test_df, training_time, throughput = train_model()

        # Validate on validation set
        val_texts = val_df['input_text'].tolist()
        val_labels = val_df['label'].astype(int).tolist()
        val_results = evaluate_model(model, val_df, "Validation")

        # Test on test set
        test_results = evaluate_model(model, test_df, "Test")

        # Palo Alto holdout
        pa_correct, pa_total = evaluate_paloalto_holdout(model)

        # Save
        all_results = save_results(model, val_results, test_results, training_time, throughput)

        # Print summary
        print("\n" + "=" * 80)
        print("MODEL V6 TRAINING COMPLETE")
        print("=" * 80)
        print(f"\nTest Metrics:")
        print(f"  Accuracy:  {test_results['accuracy']:.4f}")
        print(f"  Precision: {test_results['precision']:.4f}")
        print(f"  Recall:    {test_results['recall']:.4f}")
        print(f"  F1-Score:  {test_results['f1']:.4f}")
        print(f"\nValidation Metrics:")
        print(f"  Accuracy:  {val_results['accuracy']:.4f}")
        print(f"  F1-Score:  {val_results['f1']:.4f}")
        print(f"\nPalo Alto Holdout: {pa_correct}/{pa_total} correct")
        print(f"\nTraining time: {training_time:.1f} seconds ({training_time/60:.1f} minutes)")
        print(f"Throughput: {throughput:.1f} samples/sec")
        print(f"Model saved to: {OUTPUT_DIR}")

        # Check target
        target_achieved = test_results['accuracy'] > 0.90 and test_results['f1'] > 0.85
        print(f"\nTARGET ACHIEVED: {'YES' if target_achieved else 'NO'} (acc={test_results['accuracy']:.4f}, f1={test_results['f1']:.4f})")

    finally:
        cleanup()


if __name__ == "__main__":
    main()
