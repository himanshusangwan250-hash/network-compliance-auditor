#!/usr/bin/env python3
"""
Generate V6 Dataset: Rule-Conditioned Evidence from V5.

Transforms V5 dataset to add rule-specific context while preserving the
original config (which the model was trained on).

Input format: "Policy: <policy>\nRule: <rule_id>\nEvidence: <original_config>"
"""

import os
os.environ['KMP_DUPLICATE_LIB_OK'] = 'TRUE'

import sys
import pandas as pd
from pathlib import Path

BASE_DIR = Path(__file__).parent.parent
sys.path.insert(0, str(BASE_DIR))

DATA_V5 = BASE_DIR / "data_v5"
DATA_V6 = BASE_DIR / "data_v6"
DATA_V6.mkdir(parents=True, exist_ok=True)


def build_input_text(row: pd.Series) -> str:
    """Build rule-conditioned input from a V5 row."""
    policy = row['policy']
    rule_id = row['rule_id']
    config = row['config']
    return f"Policy: {policy}\nRule: {rule_id}\nEvidence: {config}"


def main():
    print("=" * 70)
    print("V6 DATASET GENERATION: Rule-Conditioned Evidence")
    print("=" * 70)

    train_df = pd.read_csv(DATA_V5 / "train.csv")
    val_df = pd.read_csv(DATA_V5 / "validation.csv")
    test_df = pd.read_csv(DATA_V5 / "test.csv")

    print(f"\nLoaded V5 dataset:")
    print(f"  Train: {len(train_df)}")
    print(f"  Validation: {len(val_df)}")
    print(f"  Test: {len(test_df)}")

    # Build new columns
    train_df = train_df.copy()
    val_df = val_df.copy()
    test_df = test_df.copy()

    train_df['input_text'] = train_df.apply(build_input_text, axis=1)
    val_df['input_text'] = val_df.apply(build_input_text, axis=1)
    test_df['input_text'] = test_df.apply(build_input_text, axis=1)

    # Save
    train_df.to_csv(DATA_V6 / "train.csv", index=False)
    val_df.to_csv(DATA_V6 / "validation.csv", index=False)
    test_df.to_csv(DATA_V6 / "test.csv", index=False)

    print(f"\nSaved to: {DATA_V6}")

    # Report
    print("\n" + "=" * 70)
    print("V6 DATASET REPORT")
    print("=" * 70)

    for split_name, split_df in [("Train", train_df), ("Validation", val_df), ("Test", test_df)]:
        print(f"\n--- {split_name} ({len(split_df)} examples) ---")

        print("\nRule distribution:")
        for rule in sorted(split_df['rule_id'].unique()):
            subset = split_df[split_df['rule_id'] == rule]
            comp = len(subset[subset['label'] == 1])
            noncomp = len(subset[subset['label'] == 0])
            print(f"  {rule}: compliant={comp}, non_compliant={noncomp}, total={len(subset)}")

        print("\nVendor distribution:")
        for vendor in sorted(split_df['vendor'].unique()):
            count = len(split_df[split_df['vendor'] == vendor])
            print(f"  {vendor}: {count}")

        lengths = split_df['config'].str.len()
        print(f"\nConfig length stats (preserved from V5):")
        print(f"  Mean: {lengths.mean():.0f} chars")
        print(f"  Median: {lengths.median():.0f} chars")
        print(f"  Min: {lengths.min()} chars")
        print(f"  Max: {lengths.max()} chars")

        inp_lengths = split_df['input_text'].str.len()
        over_256 = len(inp_lengths[inp_lengths > 256])
        over_512 = len(inp_lengths[inp_lengths > 512])
        print(f"\nInput text length stats:")
        print(f"  Mean: {inp_lengths.mean():.0f} chars")
        print(f"  >256 chars: {over_256}")
        print(f"  >512 chars: {over_512}")

    # Show sample
    print("\n" + "=" * 70)
    print("SAMPLE INPUT (CIS-1.2)")
    print("=" * 70)
    sample = train_df[train_df['rule_id'] == 'CIS-1.2'].iloc[0]
    print(f"\n{sample['input_text'][:500]}...")
    print(f"\nLabel: {sample['label']}")
    print(f"Source: {sample['source']}")

    print("\nV6 dataset generation complete.")


if __name__ == "__main__":
    main()
