#!/usr/bin/env python3
"""
Validate the generated dataset for quality and consistency.
Checks for malformed examples, duplicates, leakage, and balance.
"""

import csv
import sys
from pathlib import Path
from collections import defaultdict


def load_csv(filepath: str) -> list[dict]:
    """Load CSV file and return list of dictionaries."""
    with open(filepath, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        return list(reader)


def validate_examples(examples: list[dict], source_name: str) -> list[str]:
    """Validate a list of examples and return list of issues."""
    issues = []

    for i, ex in enumerate(examples):
        # Check for empty fields
        for field in ['rule_id', 'policy', 'security_intent', 'config', 'vendor', 'label']:
            if not ex.get(field, '').strip():
                issues.append(f"{source_name}[{i}]: Empty field '{field}'")

        # Check for valid rule_id
        valid_rules = ['CIS-1.1', 'CIS-1.2', 'CIS-2.1', 'CIS-2.2', 'CIS-3.1', 'CIS-4.1']
        if ex.get('rule_id') not in valid_rules:
            issues.append(f"{source_name}[{i}]: Invalid rule_id '{ex.get('rule_id')}'")

        # Check for valid vendor
        valid_vendors = ['cisco', 'juniper', 'paloalto']
        if ex.get('vendor') not in valid_vendors:
            issues.append(f"{source_name}[{i}]: Invalid vendor '{ex.get('vendor')}'")

        # Check for valid label
        if ex.get('label') not in ['0', '1']:
            issues.append(f"{source_name}[{i}]: Invalid label '{ex.get('label')}' (should be 0 or 1)")

        # Check for malformed config
        config = ex.get('config', '').strip()
        if len(config) < 5:
            issues.append(f"{source_name}[{i}]: Config too short ({len(config)} chars)")

        # Check for CIS-4.1 Cisco examples (should not exist)
        if ex.get('rule_id') == 'CIS-4.1' and ex.get('vendor') == 'cisco':
            issues.append(f"{source_name}[{i}]: CIS-4.1 should not have Cisco examples")

    return issues


def check_duplicates(examples: list[dict], source_name: str) -> list[str]:
    """Check for duplicate examples."""
    issues = []
    configs = defaultdict(list)

    for i, ex in enumerate(examples):
        config_hash = hash(ex.get('config', ''))
        configs[config_hash].append(i)

    for config_hash, indices in configs.items():
        if len(indices) > 1:
            issues.append(f"{source_name}: Duplicate config found at indices {indices}")

    return issues


def check_leakage(train: list[dict], test: list[dict], source_name: str) -> list[str]:
    """Check for data leakage between train and test sets."""
    issues = []

    train_configs = set(hash(ex.get('config', '')) for ex in train)
    test_configs = set(hash(ex.get('config', '')) for ex in test)

    overlap = train_configs & test_configs
    if overlap:
        issues.append(f"{source_name}: {len(overlap)} configs appear in both train and test")

    return issues


def print_report(all_examples: dict, issues: list[str]):
    """Print comprehensive dataset report."""

    print("\n" + "=" * 70)
    print("DATASET VALIDATION REPORT")
    print("=" * 70)

    # Summary
    total = sum(len(exs) for exs in all_examples.values())
    compliant = sum(1 for exs in all_examples.values() for ex in exs if ex.get('label') == '1')
    non_compliant = sum(1 for exs in all_examples.values() for ex in exs if ex.get('label') == '0')

    print(f"\nTotal examples: {total}")
    print(f"  Compliant: {compliant}")
    print(f"  Non-compliant: {non_compliant}")
    print(f"  Balance ratio: {compliant/non_compliant:.2f}" if non_compliant > 0 else "  Balance ratio: N/A")

    # By rule
    print(f"\nBy rule:")
    rule_counts = defaultdict(int)
    for exs in all_examples.values():
        for ex in exs:
            rule_counts[ex.get('rule_id')] += 1

    for rule in sorted(rule_counts.keys()):
        print(f"  {rule}: {rule_counts[rule]}")

    # By vendor
    print(f"\nBy vendor:")
    vendor_counts = defaultdict(int)
    for exs in all_examples.values():
        for ex in exs:
            vendor_counts[ex.get('vendor')] += 1

    for vendor in sorted(vendor_counts.keys()):
        print(f"  {vendor}: {vendor_counts[vendor]}")

    # By split
    print(f"\nBy split:")
    for split_name, exs in all_examples.items():
        print(f"  {split_name}: {len(exs)}")

    # Issues
    print(f"\nValidation Issues:")
    if issues:
        for issue in issues:
            print(f"  - {issue}")
    else:
        print("  None - Dataset is valid!")

    print("\n" + "=" * 70)


def main():
    """Main validation entry point."""
    data_dir = Path(__file__).parent / "data"

    all_examples = {}
    all_issues = []

    # Load and validate main splits
    for split_name in ['train', 'validation', 'test']:
        filepath = data_dir / f"{split_name}.csv"
        if filepath.exists():
            examples = load_csv(str(filepath))
            all_examples[split_name] = examples

            issues = validate_examples(examples, split_name)
            issues += check_duplicates(examples, split_name)
            all_issues.extend(issues)

    # Load and validate cross-vendor splits
    cv_dir = data_dir / "cross_vendor"
    if cv_dir.exists():
        for train_file in cv_dir.glob("train_*.csv"):
            test_file = cv_dir / f"test_{train_file.name.replace('train_', '')}"

            if test_file.exists():
                train_examples = load_csv(str(train_file))
                test_examples = load_csv(str(test_file))

                split_key = f"cross_vendor_{train_file.stem}"
                all_examples[split_key] = train_examples + test_examples

                issues = validate_examples(train_examples, split_key + "_train")
                issues += validate_examples(test_examples, split_key + "_test")
                issues += check_leakage(train_examples, test_examples, split_key)
                all_issues.extend(issues)

    # Print report
    print_report(all_examples, all_issues)

    # Show sample
    if all_examples.get('train'):
        print("\n" + "=" * 70)
        print("SAMPLE EXAMPLES (random 20)")
        print("=" * 70)

        import random
        random.seed(42)
        sample = random.sample(all_examples['train'], min(20, len(all_examples['train'])))

        for i, ex in enumerate(sample, 1):
            label = "COMPLIANT" if ex['label'] == '1' else "NON-COMPLIANT"
            print(f"\n{i}. [{ex['rule_id']}] {ex['vendor'].upper()} - {label}")
            print(f"   Config: {ex['config'][:100]}{'...' if len(ex['config']) > 100 else ''}")
            print(f"   Difficulty: {ex.get('difficulty', 'N/A')}")

    # Exit with error if issues found
    if all_issues:
        print(f"\n❌ Validation failed with {len(all_issues)} issues!")
        sys.exit(1)
    else:
        print("\n✅ Dataset validation passed!")
        sys.exit(0)


if __name__ == "__main__":
    main()
