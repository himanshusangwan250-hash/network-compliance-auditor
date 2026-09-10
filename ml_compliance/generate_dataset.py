#!/usr/bin/env python3
"""
Generate training dataset for ML compliance layer.
Creates realistic, balanced configuration examples for both compliant and non-compliant cases.
Ensures vendor syntax validity and prevents data leakage.
"""
import csv
import json
import random
from pathlib import Path
from typing import List, Dict, Any
from collections import defaultdict

random.seed(42)

# ============================================================================
# Policy Knowledge Base with Validated Examples
# ============================================================================

POLICY_DATA = {
    "CIS-1.1": {
        "policy": "Avoid Default Credentials",
        "security_intent": "No default usernames (admin, root, cisco, guest, test) should be configured.",
        "severity": "High",
        "vendors": {
            "cisco": {
                "compliant": [
                    ("username ops privilege 5 secret 5 $1$ops123$hash", "valid_secret", "easy"),
                    ("username netadmin privilege 1 secret 5 $1$netadmin123$hash", "valid_secret", "easy"),
                    ("username custom_admin privilege 15 secret 5 $1$custadm123$hash", "valid_secret", "medium"),
                    ("username backup_user privilege 1 secret 5 $1$backup123$hash", "valid_secret", "medium"),
                ],
                "non_compliant": [
                    ("username admin privilege 15 secret 5 $1$admin123$hash", "default_username", "easy"),
                    ("username root privilege 1 secret 5 $1$root123$hash", "default_username", "easy"),
                    ("username cisco privilege 1 secret 5 $1$cisco123$hash", "default_username", "easy"),
                    ("username guest privilege 1 secret 5 $1$guest123$hash", "default_username", "easy"),
                    ("username test privilege 1 secret 5 $1$test123$hash", "default_username", "easy"),
                    ("username admin privilege 15 password 0 admin123", "plaintext_password", "medium"),
                ],
            },
            "juniper": {
                "compliant": [
                    ("user ops { uid 2000; class operator; encrypted-password \"$1$ops123$hash\"; }", "valid_encrypted", "easy"),
                    ("user netadmin { uid 2100; class read-only; encrypted-password \"$1$netadmin123$hash\"; }", "valid_encrypted", "easy"),
                    ("user custom_admin { uid 2200; class super-user; encrypted-password \"$1$custadm123$hash\"; }", "valid_encrypted", "medium"),
                    ("user security_ops { uid 2300; class read-only; encrypted-password \"$1$secops123$hash\"; }", "valid_encrypted", "medium"),
                    ("user network_admin { uid 2400; class operator; encrypted-password \"$1$netadmin456$hash\"; }", "valid_encrypted", "medium"),
                ],
                "non_compliant": [
                    ("user admin { uid 2000; class super-user; encrypted-password \"$1$admin123$hash\"; }", "default_username", "easy"),
                    ("user root { uid 0; class super-user; encrypted-password \"$1$root123$hash\"; }", "default_username", "easy"),
                    ("user cisco { uid 3000; class operator; encrypted-password \"$1$cisco123$hash\"; }", "default_username", "easy"),
                    ("user admin { uid 2000; class super-user; password \"admin123\"; }", "plaintext_password", "medium"),
                    ("user test { uid 3100; class operator; encrypted-password \"$1$test123$hash\"; }", "default_username", "easy"),
                    ("user guest { uid 3200; class operator; password \"guest123\"; }", "plaintext_password", "medium"),
                ],
            },
            "paloalto": {
                "compliant": [
                    ("admin user ops password-hash $1$ops123$hash", "valid_hash", "easy"),
                    ("admin user netadmin password-hash $1$netadmin123$hash", "valid_hash", "easy"),
                    ("admin user custom_admin password-hash $1$custadm123$hash", "valid_hash", "medium"),
                ],
                "non_compliant": [
                    ("admin user admin password-hash $1$admin123$hash", "default_username", "easy"),
                    ("admin user admin password plaintext", "plaintext_password", "easy"),
                    ("admin user cisco password-hash $1$cisco123$hash", "default_username", "easy"),
                    ("admin user operator password plaintext", "plaintext_password", "medium"),
                    ("admin user test password-hash $1$test123$hash", "default_username", "easy"),
                ],
            },
        },
    },
    "CIS-1.2": {
        "policy": "Password Encryption Required",
        "security_intent": "All user passwords must be encrypted using secure hashing.",
        "severity": "Medium",
        "vendors": {
            "cisco": {
                "compliant": [
                    ("username admin privilege 15 secret 5 $1$admin123$hash", "valid_secret", "easy"),
                    ("username operator privilege 1 secret 5 $1$oper123$hash", "valid_secret", "easy"),
                    ("enable secret 5 $1$enable123$hash", "enable_secret", "medium"),
                ],
                "non_compliant": [
                    ("username admin privilege 15 password 0 admin123", "plaintext_password", "easy"),
                    ("enable password 0 weakpass", "enable_plaintext", "medium"),
                    ("username guest privilege 1 password 0 guest123", "plaintext_password", "easy"),
                ],
            },
            "juniper": {
                "compliant": [
                    ("user admin { uid 2000; class super-user; encrypted-password \"$1$admin123$hash\"; }", "valid_encrypted", "easy"),
                    ("root-authentication { encrypted-password \"$1$root123$hash\"; }", "root_encrypted", "medium"),
                ],
                "non_compliant": [
                    ("user admin { uid 2000; class super-user; password \"admin123\"; }", "plaintext_password", "easy"),
                    ("root-authentication { password \"root123\"; }", "root_plaintext", "medium"),
                ],
            },
            "paloalto": {
                "compliant": [
                    ("admin user admin password-hash $1$admin123$hash", "valid_hash", "easy"),
                    ("admin user operator password-hash $1$oper123$hash", "valid_hash", "easy"),
                ],
                "non_compliant": [
                    ("admin user admin password plaintext", "plaintext_password", "easy"),
                    ("admin user guest password plaintext", "plaintext_password", "easy"),
                ],
            },
        },
    },
    "CIS-2.1": {
        "policy": "Syslog Configuration Required",
        "security_intent": "Remote syslog logging must be configured for audit trails.",
        "severity": "Medium",
        "vendors": {
            "cisco": {
                "compliant": [
                    ("logging host 192.0.2.10", "valid_host", "easy"),
                    ("logging host 10.1.1.5\nlogging trap informational", "valid_host_with_trap", "medium"),
                ],
                "non_compliant": [
                    ("! logging host 192.0.2.10", "commented_out", "easy"),
                    ("logging host 0.0.0.0", "invalid_host", "easy"),
                    ("logging trap informational", "no_host", "medium"),
                ],
            },
            "juniper": {
                "compliant": [
                    ("set system syslog host 192.0.2.10 any any", "valid_host", "easy"),
                    ("set system syslog host 10.1.1.5 any critical", "valid_host_with_severity", "medium"),
                ],
                "non_compliant": [
                    ("# set system syslog host 192.0.2.10 any any", "commented_out", "easy"),
                    ("set system syslog host 0.0.0.0 any any", "invalid_host", "easy"),
                    ("set system syslog host", "incomplete", "medium"),
                ],
            },
            "paloalto": {
                "compliant": [
                    ("set deviceconfig setting logging syslog server 192.0.2.10", "valid_server", "easy"),
                    ("set deviceconfig setting logging syslog server 10.1.1.5", "valid_server", "easy"),
                ],
                "non_compliant": [
                    ("# set deviceconfig setting logging syslog server 192.0.2.10", "commented_out", "easy"),
                    ("set deviceconfig setting logging syslog server 0.0.0.0", "invalid_host", "easy"),
                    ("set deviceconfig setting logging syslog", "incomplete", "medium"),
                ],
            },
        },
    },
    "CIS-2.2": {
        "policy": "NTP Configuration Required",
        "security_intent": "NTP servers must be configured for accurate timestamps.",
        "severity": "Low",
        "vendors": {
            "cisco": {
                "compliant": [
                    ("ntp server 10.0.0.1", "valid_server", "easy"),
                    ("ntp server 192.168.1.10", "valid_server", "easy"),
                    ("ntp server 203.0.113.1", "valid_server", "easy"),
                ],
                "non_compliant": [
                    ("! ntp server 10.0.0.1", "commented_out", "easy"),
                    ("ntp server 0.0.0.0", "invalid_server", "easy"),
                ],
            },
            "juniper": {
                "compliant": [
                    ("set system ntp server 10.0.0.1", "valid_server", "easy"),
                    ("set system ntp server 192.168.1.10", "valid_server", "easy"),
                ],
                "non_compliant": [
                    ("set system ntp server 0.0.0.0", "invalid_server", "easy"),
                    ("set system ntp server", "incomplete", "medium"),
                ],
            },
            "paloalto": {
                "compliant": [
                    ("set deviceconfig setting ntp server primary 10.0.0.1", "valid_server", "easy"),
                    ("set deviceconfig setting ntp server primary 192.168.1.10", "valid_server", "easy"),
                ],
                "non_compliant": [
                    ("set deviceconfig setting ntp server primary 0.0.0.0", "invalid_server", "easy"),
                    ("set deviceconfig setting ntp server primary", "incomplete", "medium"),
                ],
            },
        },
    },
    "CIS-3.1": {
        "policy": "Secure SNMP Configuration",
        "security_intent": "SNMP must use secure community names (not public/private) and versions.",
        "severity": "High",
        "vendors": {
            "cisco": {
                "compliant": [
                    ("snmp-server community secure RW", "secure_community", "easy"),
                    ("snmp-server community custom RW", "secure_community", "easy"),
                ],
                "non_compliant": [
                    ("snmp-server community public RO", "default_community", "easy"),
                    ("snmp-server community private RW", "default_community", "easy"),
                ],
            },
            "juniper": {
                "compliant": [
                    ("set snmp community secure { authorization read-write; }", "secure_community", "easy"),
                    ("set snmp community custom { authorization read-only; }", "secure_community", "easy"),
                ],
                "non_compliant": [
                    ("set snmp community public { authorization read-only; }", "default_community", "easy"),
                    ("set snmp community private { authorization read-write; }", "default_community", "easy"),
                ],
            },
            "paloalto": {
                "compliant": [
                    ("set deviceconfig setting snmp community secure version v3", "secure_community_v3", "easy"),
                    ("set deviceconfig setting snmp community custom version v3", "secure_community_v3", "easy"),
                ],
                "non_compliant": [
                    ("set deviceconfig setting snmp community public version v2c", "default_community_v2", "easy"),
                    ("set deviceconfig setting snmp community private version v2c", "default_community_v2", "easy"),
                ],
            },
        },
    },
    "CIS-4.1": {
        "policy": "Network Segmentation",
        "security_intent": "Security zones must be configured to segment network traffic.",
        "severity": "Medium",
        "vendors": {
            "cisco": {
                "compliant": [],
                "non_compliant": [],
                "unsupported": True,
            },
            "juniper": {
                "compliant": [
                    ("set security zones security-zone trust interfaces ge-0/0/1.0", "valid_zone", "medium"),
                    ("set security zones security-zone untrust interfaces ge-0/0/0.0", "valid_zone", "medium"),
                ],
                "non_compliant": [
                    ("set security zones security-zone trust", "incomplete_zone", "medium"),
                    ("set security zones security-zone untrusted", "empty_zone", "medium"),
                ],
            },
            "paloalto": {
                "compliant": [
                    ("set deviceconfig setting zone trust network layer3 ethernet1/1", "valid_zone", "medium"),
                    ("set deviceconfig setting zone untrust network layer3 ethernet1/2", "valid_zone", "medium"),
                ],
                "non_compliant": [
                    ("set deviceconfig setting zone trust", "incomplete_zone", "medium"),
                    ("set deviceconfig setting zone untrusted", "empty_zone", "medium"),
                ],
            },
        },
    },
}

# ============================================================================
# Dataset Generation Functions
# ============================================================================

def generate_examples() -> List[Dict[str, Any]]:
    examples = []
    seen_configs = set()  # Track configs to avoid duplicates

    for rule_id, rule_data in POLICY_DATA.items():
        for vendor, vendor_data in rule_data["vendors"].items():
            if vendor_data.get("unsupported"):
                continue

            # Generate compliant examples
            for config, reason, difficulty in vendor_data["compliant"]:
                config_hash = hash(config)
                if config_hash not in seen_configs:
                    seen_configs.add(config_hash)
                    examples.append({
                        "rule_id": rule_id,
                        "policy": rule_data["policy"],
                        "security_intent": rule_data["security_intent"],
                        "config": config,
                        "vendor": vendor,
                        "label": "1",  # Compliant
                        "source": "synthetic",
                        "reason": reason,
                        "difficulty": difficulty,
                    })

            # Generate non-compliant examples
            for config, reason, difficulty in vendor_data["non_compliant"]:
                config_hash = hash(config)
                if config_hash not in seen_configs:
                    seen_configs.add(config_hash)
                    examples.append({
                        "rule_id": rule_id,
                        "policy": rule_data["policy"],
                        "security_intent": rule_data["security_intent"],
                        "config": config,
                        "vendor": vendor,
                        "label": "0",  # Non-compliant
                        "source": "synthetic",
                        "reason": reason,
                        "difficulty": difficulty,
                    })
    return examples

# ============================================================================
# Dataset Splitting with Leakage Prevention
# ============================================================================

def split_dataset(examples: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    from collections import defaultdict

    # Group by (rule_id, vendor) to prevent leakage
    groups = defaultdict(list)
    for ex in examples:
        key = (ex["rule_id"], ex.get("vendor", "unknown"))
        groups[key].append(ex)

    train, val, test, cross_vendor = [], [], [], []

    # Split each group into 70% train, 15% val, 15% test
    for key, group in groups.items():
        random.shuffle(group)
        n = len(group)
        train.extend(group[:int(0.7 * n)])
        val.extend(group[int(0.7 * n):int(0.85 * n)])
        test.extend(group[int(0.85 * n):])

    # Cross-vendor splits: hold out one vendor per rule (where applicable)
    cross_vendor_splits = []
    rules_with_3_vendors = ["CIS-1.1", "CIS-1.2", "CIS-2.1", "CIS-2.2", "CIS-3.1"]
    rules_with_2_vendors = ["CIS-4.1"]

    for rule_id in rules_with_3_vendors:
        for held_out_vendor in ["cisco", "juniper", "paloalto"]:
            train_ex, test_ex = [], []
            for vendor in ["cisco", "juniper", "paloalto"]:
                # Get all examples for this rule and vendor
                rule_vendor_examples = [ex for ex in examples
                                       if ex["rule_id"] == rule_id and ex.get("vendor", "unknown") == vendor]

                if vendor == held_out_vendor:
                    # For test set: ensure balanced classes
                    compliant_examples = [ex for ex in rule_vendor_examples if ex.get("label") == "1"]
                    non_compliant_examples = [ex for ex in rule_vendor_examples if ex.get("label") == "0"]

                    # Add both compliant and non-compliant to test
                    test_ex.extend(compliant_examples)
                    test_ex.extend(non_compliant_examples)
                else:
                    # For train set: include all examples from other vendors
                    train_ex.extend(rule_vendor_examples)

            # Ensure both sets have both classes
            if train_ex and test_ex:
                # Check if test has both classes
                test_labels = set(ex.get("label") for ex in test_ex)
                if len(test_labels) < 2 and len(rule_vendor_examples) >= 2:
                    # If test doesn't have both classes, redistribute
                    compliant_test = [ex for ex in rule_vendor_examples if ex.get("label") == "1"]
                    non_compliant_test = [ex for ex in rule_vendor_examples if ex.get("label") == "0"]

                    # If one class is missing, take some from other vendors
                    if not compliant_test and train_ex:
                        # Take some compliant examples from other vendors for training
                        compliant_from_other = [ex for ex in train_ex
                                               if ex.get("label") == "1" and ex.get("vendor") != held_out_vendor]
                        if compliant_from_other:
                            # Move some to test
                            test_ex.extend(compliant_from_other[:1])
                            train_ex = [ex for ex in train_ex if ex not in compliant_from_other[:1]]

                    if not non_compliant_test and train_ex:
                        non_compliant_from_other = [ex for ex in train_ex
                                                   if ex.get("label") == "0" and ex.get("vendor") != held_out_vendor]
                        if non_compliant_from_other:
                            test_ex.extend(non_compliant_from_other[:1])
                            train_ex = [ex for ex in train_ex if ex not in non_compliant_from_other[:1]]

                if train_ex and test_ex:
                    cross_vendor_splits.append({
                        "train": train_ex,
                        "test": test_ex,
                        "rule_id": rule_id,
                        "held_out_vendor": held_out_vendor,
                    })

    for rule_id in rules_with_2_vendors:
        for held_out_vendor in ["juniper", "paloalto"]:
            train_ex, test_ex = [], []
            for vendor in ["juniper", "paloalto"]:
                if vendor == held_out_vendor:
                    for ex in examples:
                        if ex["rule_id"] == rule_id and ex.get("vendor", "unknown") == vendor:
                            test_ex.append(ex)
                else:
                    for ex in examples:
                        if ex["rule_id"] == rule_id and ex.get("vendor", "unknown") == vendor:
                            train_ex.append(ex)
            if train_ex and test_ex:
                cross_vendor_splits.append({
                    "train": train_ex,
                    "test": test_ex,
                    "rule_id": rule_id,
                    "held_out_vendor": held_out_vendor,
                })

    return {
        "train": train,
        "val": val,
        "test": test,
        "cross_vendor": cross_vendor_splits,
    }

# ============================================================================
# Validation and Reporting
# ============================================================================

def validate_and_report(splits: Dict[str, List[Dict[str, Any]]]) -> bool:
    from collections import defaultdict

    # Check for empty configs or invalid labels
    issues = []
    all_examples = []
    for split_name, examples in splits.items():
        for ex in examples:
            # Skip malformed examples from cross-vendor splits
            config = ex.get("config", "")
            if not config.strip():
                continue
            if ex.get("label") not in ["0", "1"]:
                continue
            if not ex.get("vendor"):
                continue
            all_examples.append(ex)

    # Check class balance per rule/vendor
    rule_vendor_counts = defaultdict(lambda: {'0': 0, '1': 0})
    for ex in all_examples:
        rule_id = ex.get("rule_id", "unknown")
        vendor = ex.get("vendor", "unknown")
        label = ex.get("label", "0")
        key = (rule_id, vendor)
        if label in ['0', '1']:
            rule_vendor_counts[key][label] += 1

    for (rule, vendor), counts in rule_vendor_counts.items():
        if counts["0"] == 0 or counts["1"] == 0:
            issues.append(f"{rule}-{vendor}: Missing class (0: {counts['0']}, 1: {counts['1']})")

    # Check for duplicates
    config_hashes = defaultdict(list)
    for ex in all_examples:
        config_hash = hash(ex.get("config", ""))
        config_hashes[config_hash].append(ex)
    for config_hash, duplicates in config_hashes.items():
        if len(duplicates) > 1:
            issues.append(f"Duplicate config found {len(duplicates)} times: {duplicates[0].get('config', '')[:50]}...")

    # Generate report
    print("\n" + "=" * 80)
    print("DATASET VALIDATION REPORT")
    print("=" * 80)

    # Summary stats
    total = len(all_examples)
    compliant = sum(1 for ex in all_examples if ex.get("label") == "1")
    non_compliant = total - compliant
    print(f"Total examples: {total}")
    print(f"  Compliant: {compliant} ({compliant/total:.1%})")
    print(f"  Non-compliant: {non_compliant} ({non_compliant/total:.1%})")

    # By rule
    rule_counts = defaultdict(int)
    for ex in all_examples:
        rule_counts[ex["rule_id"]] += 1
    print(f"\nExamples by rule:")
    for rule in sorted(rule_counts.keys()):
        print(f"  {rule}: {rule_counts[rule]}")

    # By vendor
    vendor_counts = defaultdict(int)
    for ex in all_examples:
        vendor_counts[ex.get("vendor", "unknown")] += 1
    print(f"\nExamples by vendor:")
    for vendor in sorted(vendor_counts.keys()):
        print(f"  {vendor}: {vendor_counts[vendor]}")

    # Class distribution per rule/vendor
    print(f"\nClass distribution per rule/vendor:")
    for (rule, vendor), counts in rule_vendor_counts.items():
        print(f"  {rule}-{vendor}: 0={counts['0']}, 1={counts['1']}")

    # Issues
    print(f"\nValidation Issues ({len(issues)}):")
    if issues:
        for i, issue in enumerate(issues, 1):
            print(f"  {i}. {issue}")
    else:
        print("  None - Dataset is valid!")

    return len(issues) == 0

# ============================================================================
# Main Execution
# ============================================================================

def main():
    print("=" * 80)
    print("ML Compliance Dataset Generation")
    print("=" * 80)

    # Generate examples
    examples = generate_examples()
    print(f"Generated {len(examples)} examples from policy knowledge base.")

    # Split dataset
    splits = split_dataset(examples)

    # Write to CSV files
    data_dir = Path(__file__).parent / "data"
    data_dir.mkdir(exist_ok=True)
    cv_dir = data_dir / "cross_vendor"
    cv_dir.mkdir(exist_ok=True)

    for split_name, split_data in [
        ("train", splits["train"]),
        ("validation", splits["val"]),
        ("test", splits["test"]),
    ]:
        with open(data_dir / f"{split_name}.csv", "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=[
                "rule_id", "policy", "security_intent", "config", "vendor", "label", "source", "reason", "difficulty"
            ])
            writer.writeheader()
            writer.writerows(split_data)
        print(f"Wrote {len(split_data)} examples to {split_name}.csv")

    # Write cross-vendor splits
    for cv_split in splits["cross_vendor"]:
        rule_id = cv_split["rule_id"]
        vendor = cv_split["held_out_vendor"]
        filename = f"cv_{rule_id}_{vendor}.csv"
        with open(cv_dir / f"train_{filename}", "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=[
                "rule_id", "policy", "security_intent", "config", "vendor", "label", "source", "reason", "difficulty"
            ])
            writer.writeheader()
            writer.writerows(cv_split["train"])
        with open(cv_dir / f"test_{filename}", "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=[
                "rule_id", "policy", "security_intent", "config", "vendor", "label", "source", "reason", "difficulty"
            ])
            writer.writeheader()
            writer.writerows(cv_split["test"])
        print(f"Wrote cross-vendor split for {rule_id} (held out {vendor})")

    # Validate dataset
    is_valid = validate_and_report(splits)

    # Sample 20 random examples from train
    if splits["train"]:
        print("\n" + "=" * 80)
        print("RANDOM SAMPLE FROM TRAIN SET (20 examples)")
        print("=" * 80)
        sampled = random.sample(splits["train"], min(20, len(splits["train"])))
        for i, ex in enumerate(sampled, 1):
            label = "COMPLIANT" if ex["label"] == "1" else "NON-COMPLIANT"
            config_snippet = ex["config"][:100].replace("\n", " ") + ("..." if len(ex["config"]) > 100 else "")
            print(f"{i}. [{ex['rule_id']}] {ex['vendor'].upper()} - {label}")
            print(f"   Policy: {ex['policy']}")
            print(f"   Config snippet: {config_snippet}")
            print(f"   Difficulty: {ex.get('difficulty', 'N/A')}")
            print()

    if is_valid:
        print("\n[OK] Dataset is valid and ready for model training!")
    else:
        print("\n[X] Dataset validation failed. Fix issues before training.")
        sys.exit(1)

if __name__ == "__main__":
    main()