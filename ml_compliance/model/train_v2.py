#!/usr/bin/env python3
"""
Model V2 Training Script.
Uses Dataset V2 (ml_compliance/data_v2/) and outputs to ml_compliance/model/setfit_v2/.
Keeps V1 model and dataset untouched.
"""

import os
os.environ['KMP_DUPLICATE_LIB_OK'] = 'TRUE'
os.environ['PYTORCH_CUDA_ALLOC_CONF'] = 'expandable_segments:True'

import json
import sys
import time
import torch
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
# Configuration — V2 paths (separate from V1)
# ============================================================================

MODEL_NAME = "all-MiniLM-L6-v2"
OUTPUT_DIR = Path(__file__).parent / "setfit_v2"          # V2 model output
DATA_DIR = Path(__file__).parent.parent / "data_v2"        # V2 dataset
RANDOM_SEED = 42
CONFIDENCE_THRESHOLD = 0.6

# Training hyperparameters (optimized for ~15-20 min on RTX 4050 6GB VRAM)
EMBEDDING_EPOCHS = 1           # Embedding fine-tuning epochs
CLASSIFIER_EPOCHS = 5          # Classification head training epochs
MAX_STEPS = 300                # Max training steps for embeddings
BATCH_SIZE = 4                 # Minimal batch size for 6GB VRAM
LEARNING_RATE = 2e-5           # Learning rate for body
HEAD_LEARNING_RATE = 1e-2      # Learning rate for head
MAX_LENGTH = 64                # Reduced to minimize memory usage


def setup_environment():
    """Print environment info and verify GPU."""
    print("=" * 80)
    print("MODEL V2 TRAINING ENVIRONMENT")
    print("=" * 80)
    print(f"Python version: {sys.version.split()[0]}")
    print(f"PyTorch version: {torch.__version__}")
    print(f"CUDA available: {torch.cuda.is_available()}")
    if torch.cuda.is_available():
        print(f"GPU: {torch.cuda.get_device_name(0)}")
        print(f"VRAM: {torch.cuda.get_device_properties(0).total_memory / (1024**3):.1f} GB")
        print(f"CUDA version: {torch.version.cuda}")
    else:
        print("ERROR: CUDA not available. Cannot train on GPU.")
        sys.exit(1)
    print()


def load_data():
    """Load V2 dataset splits."""
    print(f"Loading data from: {DATA_DIR}")
    train_df = pd.read_csv(DATA_DIR / "train.csv")
    val_df = pd.read_csv(DATA_DIR / "validation.csv")
    test_df = pd.read_csv(DATA_DIR / "test.csv")
    print(f"  Train: {len(train_df)} examples")
    print(f"  Validation: {len(val_df)} examples")
    print(f"  Test: {len(test_df)} examples")
    return train_df, val_df, test_df


def create_inputs(df):
    """Create policy || config input strings."""
    return [f"{row['policy']} || {row['config']}" for _, row in df.iterrows()]


def train_model():
    """Train the SetFit model on V2 data with CUDA."""
    print("\n" + "=" * 80)
    print("TRAINING MODEL V2")
    print("=" * 80)

    train_df, val_df, test_df = load_data()

    train_texts = create_inputs(train_df)
    train_labels = train_df['label'].astype(int).tolist()

    val_texts = create_inputs(val_df)
    val_labels = val_df['label'].astype(int).tolist()

    # Verify label balance
    comp_train = sum(train_labels)
    non_comp_train = len(train_labels) - comp_train
    print(f"\nTraining labels: {comp_train} compliant, {non_comp_train} non-compliant")

    # Initialize model
    print(f"\nLoading base model: {MODEL_NAME}")
    model = SetFitModel.from_pretrained(MODEL_NAME)

    # Move model to CUDA
    device = torch.device("cuda")
    model.model_body.to(device)
    print(f"Model moved to CUDA: {torch.cuda.get_device_name(0)}")

    # Training arguments - use max_steps to control training time
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

    # Print expected configuration
    print(f"\nTraining Configuration:")
    print(f"  Embedding epochs: {EMBEDDING_EPOCHS}")
    print(f"  Classifier epochs: {CLASSIFIER_EPOCHS}")
    print(f"  Max steps (embeddings): {MAX_STEPS}")
    print(f"  Batch size: {BATCH_SIZE}")
    print(f"  Learning rate (body): {LEARNING_RATE}")
    print(f"  Learning rate (head): {HEAD_LEARNING_RATE}")
    print(f"  Expected time: ~15-20 minutes on RTX 4050")

    # Train
    start_time = time.time()
    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=Dataset.from_dict({"text": train_texts, "label": train_labels}),
        eval_dataset=Dataset.from_dict({"text": val_texts, "label": val_labels}),
    )

    print(f"\nStarting training on CUDA...")
    trainer.train()
    training_time = time.time() - start_time

    print(f"\nTraining completed in {training_time:.1f} seconds ({training_time/60:.1f} minutes)")
    return model, train_df, val_df, test_df, training_time


def evaluate_model(model, test_df):
    """Evaluate model on test set."""
    print("\n" + "=" * 80)
    print("MODEL V2 TEST EVALUATION")
    print("=" * 80)

    test_texts = create_inputs(test_df)
    test_labels = test_df['label'].astype(int).tolist()

    predictions = model.predict(test_texts)
    if hasattr(predictions, 'tolist'):
        predictions = predictions.tolist()

    # Metrics
    accuracy = accuracy_score(test_labels, predictions)
    precision = precision_score(test_labels, predictions, average='binary', zero_division=0)
    recall = recall_score(test_labels, predictions, average='binary', zero_division=0)
    f1 = f1_score(test_labels, predictions, average='binary', zero_division=0)

    print(f"\nOverall Test Metrics:")
    print(f"  Accuracy:  {accuracy:.4f}")
    print(f"  Precision: {precision:.4f}")
    print(f"  Recall:    {recall:.4f}")
    print(f"  F1-Score:  {f1:.4f}")
    print(f"  Test examples: {len(test_labels)}")

    # Confusion matrix
    cm = confusion_matrix(test_labels, predictions)
    print(f"\nConfusion Matrix:")
    print(f"  [[TN, FP],")
    print(f"   [FN, TP]]")
    print(f"  {cm.tolist()}")

    # Classification report
    print(f"\nClassification Report:")
    print(classification_report(test_labels, predictions, target_names=['Non-compliant', 'Compliant']))

    # Per-rule metrics
    print(f"\nPer-Rule Metrics:")
    rule_metrics = {}
    predictions_arr = np.array(predictions)
    for rule in sorted(test_df['rule_id'].unique()):
        rule_mask = test_df['rule_id'] == rule
        rule_preds = predictions_arr[rule_mask.values]
        rule_true = np.array(test_labels)[rule_mask.values]

        if len(rule_true) > 0:
            rule_acc = accuracy_score(rule_true, rule_preds)
            rule_f1 = f1_score(rule_true, rule_preds, average='binary', zero_division=0)
            rule_metrics[rule] = {'accuracy': rule_acc, 'f1': rule_f1, 'count': len(rule_true)}
            print(f"  {rule}: accuracy={rule_acc:.4f}, f1={rule_f1:.4f}, n={len(rule_true)}")

    # Per-vendor metrics
    print(f"\nPer-Vendor Metrics:")
    vendor_metrics = {}
    for vendor in sorted(test_df['vendor'].unique()):
        vendor_mask = test_df['vendor'] == vendor
        vendor_preds = predictions_arr[vendor_mask.values]
        vendor_true = np.array(test_labels)[vendor_mask.values]

        if len(vendor_true) > 0:
            vendor_acc = accuracy_score(vendor_true, vendor_preds)
            vendor_f1 = f1_score(vendor_true, vendor_preds, average='binary', zero_division=0)
            vendor_metrics[vendor] = {'accuracy': vendor_acc, 'f1': vendor_f1, 'count': len(vendor_true)}
            print(f"  {vendor}: accuracy={vendor_acc:.4f}, f1={vendor_f1:.4f}, n={len(vendor_true)}")

    return {
        'predictions': predictions,
        'test_df': test_df,
        'accuracy': accuracy,
        'precision': precision,
        'recall': recall,
        'f1': f1,
        'confusion_matrix': cm.tolist(),
        'rule_metrics': rule_metrics,
        'vendor_metrics': vendor_metrics,
    }


def run_validation_evaluation(model, val_df):
    """Evaluate model on validation set."""
    print("\n" + "=" * 80)
    print("MODEL V2 VALIDATION EVALUATION")
    print("=" * 80)

    val_texts = create_inputs(val_df)
    val_labels = val_df['label'].astype(int).tolist()

    predictions = model.predict(val_texts)
    if hasattr(predictions, 'tolist'):
        predictions = predictions.tolist()

    accuracy = accuracy_score(val_labels, predictions)
    precision = precision_score(val_labels, predictions, average='binary', zero_division=0)
    recall = recall_score(val_labels, predictions, average='binary', zero_division=0)
    f1 = f1_score(val_labels, predictions, average='binary', zero_division=0)

    print(f"\nValidation Metrics:")
    print(f"  Accuracy:  {accuracy:.4f}")
    print(f"  Precision: {precision:.4f}")
    print(f"  Recall:    {recall:.4f}")
    print(f"  F1-Score:  {f1:.4f}")
    print(f"  Validation examples: {len(val_labels)}")

    cm = confusion_matrix(val_labels, predictions)
    print(f"\nConfusion Matrix:")
    print(f"  [[TN, FP],")
    print(f"   [FN, TP]]")
    print(f"  {cm.tolist()}")

    # Per-rule
    print(f"\nPer-Rule Validation Metrics:")
    for rule in sorted(val_df['rule_id'].unique()):
        sub = val_df[val_df['rule_id'] == rule]
        mask = val_df['rule_id'] == rule
        preds = np.array(predictions)[mask.values]
        true = np.array(val_labels)[mask.values]
        if len(true) > 0:
            acc = accuracy_score(true, preds)
            f1_r = f1_score(true, preds, average='binary', zero_division=0)
            print(f"  {rule}: accuracy={acc:.4f}, f1={f1_r:.4f}, n={len(true)}")

    return {
        'accuracy': accuracy,
        'precision': precision,
        'recall': recall,
        'f1': f1,
        'confusion_matrix': cm.tolist(),
    }


def save_results(model, test_results, val_results, training_time):
    """Save results to JSON."""
    print("\n" + "=" * 80)
    print("SAVING MODEL V2 ARTIFACTS")
    print("=" * 80)

    # Save model
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    model.save_pretrained(OUTPUT_DIR)

    # Prepare results
    results = {
        'model_version': 'v2',
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
        },
        'hardware': {
            'device': 'cuda',
            'gpu_name': torch.cuda.get_device_name(0),
            'gpu_memory_gb': round(torch.cuda.get_device_properties(0).total_memory / (1024**3), 1),
            'cuda_version': torch.version.cuda,
            'python_version': sys.version.split()[0],
            'pytorch_version': torch.__version__,
        },
        'validation_metrics': val_results,
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
            'cuda': torch.version.cuda,
            'sentence_transformers': __import__('sentence_transformers').__version__,
            'setfit': __import__('setfit').__version__,
            'scikit_learn': __import__('sklearn').__version__,
        },
    }

    # Save
    results_file = OUTPUT_DIR / "training_results_v2.json"
    with open(results_file, 'w') as f:
        json.dump(results, f, indent=2, default=str)

    print(f"Model saved to: {OUTPUT_DIR}")
    print(f"Results saved to: {results_file}")

    return results


def inference_test(model, test_df):
    """Run standalone inference test on test examples."""
    print("\n" + "=" * 80)
    print("INFERENCE COMPATIBILITY TEST (Model V2)")
    print("=" * 80)

    # Test a few examples
    sample_indices = [0, 5, 10, 15, 20]
    print("\nSample predictions:")
    for idx in sample_indices[:min(5, len(test_df))]:
        row = test_df.iloc[idx]
        text = f"{row['policy']} || {row['config']}"
        prediction = model.predict([text])[0]
        print(f"  Example {idx}: predicted={prediction}, actual={row['label']}, "
              f"vendor={row['vendor']}, rule={row['rule_id']}")

    print("\nInference test passed")


def main():
    """Main V2 training pipeline."""
    print("=" * 80)
    print("MODEL V2 TRAINING - Dataset V2 -> SetFit V2")
    print("=" * 80)
    print(f"Data directory: {DATA_DIR}")
    print(f"Model output: {OUTPUT_DIR}")
    print()

    # Verify CUDA
    if not torch.cuda.is_available():
        print("ERROR: CUDA not available. Cannot proceed.")
        sys.exit(1)

    # Setup
    setup_environment()

    # Train
    start_time = time.time()
    model, train_df, val_df, test_df, training_time = train_model()

    # Evaluate on validation
    val_results = run_validation_evaluation(model, val_df)

    # Evaluate on test
    test_results = evaluate_model(model, test_df)

    # Inference compatibility test
    inference_test(model, test_df)

    # Save results
    all_results = save_results(model, test_results, val_results, training_time)

    # Print summary
    print("\n" + "=" * 80)
    print("MODEL V2 TRAINING COMPLETE")
    print("=" * 80)
    print(f"\nTest Metrics:")
    print(f"  Accuracy:  {test_results['accuracy']:.4f}")
    print(f"  Precision: {test_results['precision']:.4f}")
    print(f"  Recall:    {test_results['recall']:.4f}")
    print(f"  F1-Score:  {test_results['f1']:.4f}")
    print(f"\nValidation Metrics:")
    print(f"  Accuracy:  {val_results['accuracy']:.4f}")
    print(f"  F1-Score:  {val_results['f1']:.4f}")
    print(f"\nTraining time: {training_time:.1f} seconds ({training_time/60:.1f} minutes)")
    print(f"Model saved to: {OUTPUT_DIR}")
    print(f"Results saved to: {OUTPUT_DIR / 'training_results_v2.json'}")


if __name__ == "__main__":
    main()
