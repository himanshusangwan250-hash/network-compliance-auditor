#!/usr/bin/env python3
"""
Complete training and run final evaluation.
Uses the existing checkpoint and continues training.
"""

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

# Configuration
MODEL_NAME = "all-MiniLM-L6-v2"
OUTPUT_DIR = Path(__file__).parent.parent / "model" / "setfit"
DATA_DIR = Path(__file__).parent.parent / "data"
CHECKPOINT_DIR = OUTPUT_DIR / "checkpoint-151"
RANDOM_SEED = 42
CONFIDENCE_THRESHOLD = 0.6

# Resume training hyperparameters
NUM_EPOCHS = 5  # Already completed 1 epoch
BATCH_SIZE = 8
LEARNING_RATE = 2e-5
MAX_LENGTH = 256


def load_data():
    """Load dataset splits."""
    train_df = pd.read_csv(DATA_DIR / "train.csv")
    val_df = pd.read_csv(DATA_DIR / "validation.csv")
    test_df = pd.read_csv(DATA_DIR / "test.csv")
    return train_df, val_df, test_df


def create_inputs(df):
    """Create policy || config input strings."""
    return [f"{row['policy']} || {row['config']}" for _, row in df.iterrows()]


def setup_environment():
    """Print environment info."""
    print("=" * 80)
    print("TRAINING ENVIRONMENT")
    print("=" * 80)
    print(f"Python version: {sys.version.split()[0]}")
    print(f"PyTorch version: {torch.__version__}")
    print(f"CUDA available: {torch.cuda.is_available()}")
    if torch.cuda.is_available():
        print(f"GPU: {torch.cuda.get_device_name(0)}")
        print(f"VRAM: {torch.cuda.get_device_properties(0).total_mem / (1024**3):.1f} GB")
    else:
        print("Using CPU (no GPU available)")
    print()


def load_model_and_resume():
    """Load model from checkpoint and resume training."""
    print("Loading model from checkpoint...")
    model = SetFitModel.from_pretrained(CHECKPOINT_DIR)

    train_df, val_df, test_df = load_data()

    train_texts = create_inputs(train_df)
    train_labels = train_df['label'].astype(int).tolist()

    val_texts = create_inputs(val_df)
    val_labels = val_df['label'].astype(int).tolist()

    # Update training args to resume
    training_args = TrainingArguments(
        num_epochs=NUM_EPOCHS,
        batch_size=BATCH_SIZE,
        body_learning_rate=LEARNING_RATE,
        max_length=MAX_LENGTH,
        output_dir=str(OUTPUT_DIR),
        eval_strategy="epoch",
        save_strategy="epoch",
        logging_strategy="epoch",
        report_to="none",
        seed=RANDOM_SEED,
        resume_from_checkpoint=str(CHECKPOINT_DIR),
    )

    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=Dataset.from_dict({"text": train_texts, "label": train_labels}),
        eval_dataset=Dataset.from_dict({"text": val_texts, "label": val_labels}),
    )

    return trainer, train_df, val_df, test_df, model


def evaluate_on_test(model, test_df):
    """Evaluate model on test set."""
    print("\n" + "=" * 80)
    print("FINAL TEST EVALUATION")
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
    for rule in sorted(test_df['rule_id'].unique()):
        rule_mask = test_df['rule_id'] == rule
        rule_preds = predictions[rule_mask]
        rule_true = np.array(test_labels)[rule_mask]

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
        vendor_preds = predictions[vendor_mask]
        vendor_true = np.array(test_labels)[vendor_mask]

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


def run_cross_vendor_evaluation(model):
    """Run cross-vendor experiments."""
    print("\n" + "=" * 80)
    print("CROSS-VENDOR EVALUATION")
    print("=" * 80)

    cv_dir = DATA_DIR / "cross_vendor"
    cv_results = []

    for train_file in sorted(cv_dir.glob("train_*.csv")):
        test_file = train_file.parent / f"test_{train_file.name.replace('train_', '')}"

        if not test_file.exists():
            continue

        train_df = pd.read_csv(train_file)
        test_df = pd.read_csv(test_file)

        if len(test_df) == 0:
            continue

        train_texts = create_inputs(train_df)
        train_labels = train_df['label'].astype(int).tolist()

        test_texts = create_inputs(test_df)
        test_labels = test_df['label'].astype(int).tolist()

        # Train fresh model for cross-vendor experiment
        cv_model = SetFitModel.from_pretrained(MODEL_NAME)

        training_args = TrainingArguments(
            num_epochs=3,
            batch_size=BATCH_SIZE,
            body_learning_rate=LEARNING_RATE,
            max_length=MAX_LENGTH,
            output_dir=str(OUTPUT_DIR / "cross_vendor"),
            eval_strategy="epoch",
            logging_strategy="epoch",
            report_to="none",
            seed=RANDOM_SEED,
        )

        cv_trainer = Trainer(
            model=cv_model,
            args=training_args,
            train_dataset=Dataset.from_dict({"text": train_texts, "label": train_labels}),
        )

        cv_trainer.train()

        predictions = cv_model.predict(test_texts)
        if hasattr(predictions, 'tolist'):
            predictions = predictions.tolist()

        accuracy = accuracy_score(test_labels, predictions)
        precision = precision_score(test_labels, predictions, average='binary', zero_division=0)
        recall = recall_score(test_labels, predictions, average='binary', zero_division=0)
        f1 = f1_score(test_labels, predictions, average='binary', zero_division=0)

        cv_results.append({
            'experiment': train_file.stem,
            'train_vendors': list(set(train_df['vendor'].unique())),
            'test_vendor': list(set(test_df['vendor'].unique())),
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'f1': f1,
            'train_size': len(train_df),
            'test_size': len(test_df),
        })

        print(f"{train_file.stem}:")
        print(f"  {set(train_df['vendor'].unique())} -> {set(test_df['vendor'].unique())}")
        print(f"  Accuracy: {accuracy:.4f}, F1: {f1:.4f}")

    return cv_results


def save_results(model, test_results, cv_results, training_time):
    """Save all results."""
    print("\n" + "=" * 80)
    print("SAVING RESULTS")
    print("=" * 80)

    # Save final model
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    model.save_pretrained(OUTPUT_DIR)

    # Prepare results
    results = {
        'training_config': {
            'model_name': MODEL_NAME,
            'num_epochs': NUM_EPOCHS,
            'batch_size': BATCH_SIZE,
            'learning_rate': LEARNING_RATE,
            'max_length': MAX_LENGTH,
            'random_seed': RANDOM_SEED,
            'confidence_threshold': CONFIDENCE_THRESHOLD,
            'training_time_seconds': training_time,
            'checkpoint_resume': str(CHECKPOINT_DIR),
        },
        'hardware': {
            'device': 'cuda' if torch.cuda.is_available() else 'cpu',
            'gpu_name': torch.cuda.get_device_name(0) if torch.cuda.is_available() else 'N/A',
            'gpu_memory_gb': round(torch.cuda.get_device_properties(0).total_mem / (1024**3), 1) if torch.cuda.is_available() else 'N/A',
            'cuda_version': torch.version.cuda if torch.cuda.is_available() else 'N/A',
            'python_version': sys.version.split()[0],
            'pytorch_version': torch.__version__,
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
        'cross_vendor_metrics': cv_results,
        'dependencies': {
            'pytorch': torch.__version__,
            'cuda': torch.version.cuda if torch.cuda.is_available() else 'N/A',
            'sentence_transformers': __import__('sentence_transformers').__version__,
            'setfit': __import__('setfit').__version__,
            'scikit_learn': __import__('sklearn').__version__,
        },
    }

    # Save
    results_file = OUTPUT_DIR / "training_results.json"
    with open(results_file, 'w') as f:
        json.dump(results, f, indent=2, default=str)

    print(f"Model saved to: {OUTPUT_DIR}")
    print(f"Results saved to: {results_file}")

    return results


def main():
    """Main pipeline."""
    print("=" * 80)
    print("ML COMPLIANCE MODEL - COMPLETING TRAINING")
    print("=" * 80)

    # Setup
    setup_environment()

    # Load and resume training
    start_time = time.time()
    trainer, train_df, val_df, test_df, model = load_model_and_resume()

    # Complete training
    print("\nResuming training from checkpoint...")
    trainer.train()

    training_time = time.time() - start_time

    # Evaluate on test set
    test_results = evaluate_on_test(model, test_df)

    # Cross-vendor evaluation
    cv_results = run_cross_vendor_evaluation(model)

    # Save results
    all_results = save_results(model, test_results, cv_results, training_time)

    # Print summary
    print("\n" + "=" * 80)
    print("TRAINING COMPLETE")
    print("=" * 80)
    print(f"\nFinal Test Metrics:")
    print(f"  Accuracy:  {test_results['accuracy']:.4f}")
    print(f"  Precision: {test_results['precision']:.4f}")
    print(f"  Recall:    {test_results['recall']:.4f}")
    print(f"  F1-Score:  {test_results['f1']:.4f}")
    print(f"\nCross-vendor experiments: {len(cv_results)}")
    print(f"Total training time: {training_time:.1f} seconds")
    print(f"\nModel saved to: {OUTPUT_DIR}")
    print(f"Results saved to: {OUTPUT_DIR / 'training_results.json'}")


if __name__ == "__main__":
    main()
