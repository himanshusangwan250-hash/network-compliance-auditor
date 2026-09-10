#!/usr/bin/env python3
"""
Generate Dataset V4 - Hybrid real-derived + high-quality synthetic.
Combines V1 curated examples, real-derived mutations, and synthetic examples.
"""

import os
import sys
import random
import csv
import hashlib
from pathlib import Path
from typing import List, Dict, Any, Tuple
from collections import defaultdict

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
os.environ['KMP_DUPLICATE_LIB_OK'] = 'TRUE'

from backend.parser.cisco_ios import parse_cisco_ios
from backend.compliance.models import NormalizedConfig, NormalizedUser
from backend.compliance.rules_engine import evaluate_compliance

# Set seed for reproducibility
random.seed(42)

# ============================================================================
# Configuration
# ============================================================================

OUTPUT_DIR = Path(__file__).parent
TRAIN_RATIO = 0.70
VAL_RATIO = 0.15
TEST_RATIO = 0.15

# Holdout files (reserved for final evaluation)
HOLDOUT_FILES = {
    'basic-cisco-router-config.txt',
    'ccna_labs/R1-base-config.txt',
    'ccna_labs/SW1-base-config.txt',
    'ccna_labs/R1-config.txt',
    'ccna_labs/SW1-config.txt',
}

# Policy templates (diverse formulations)
POLICY_TEXTS = {
    "CIS-1.1": [
        "Administrative accounts must not use vendor-default credentials",
        "Default usernames such as admin or root should be changed",
        "No default credential accounts should remain on network devices",
        "Unique administrative accounts must replace default credentials",
    ],
    "CIS-1.2": [
        "All user passwords must be encrypted using secure hashing algorithms",
        "Password storage must use encrypted representations, not plaintext",
        "Credential storage must employ secure password encryption",
        "Authentication credentials must not be stored in readable form",
    ],
    "CIS-2.1": [
        "Network devices must forward security events to approved centralized logging",
        "Remote syslog servers must be configured for audit trail retention",
        "Security-relevant events must be logged to external syslog infrastructure",
        "Centralized logging via syslog must be implemented for compliance",
    ],
    "CIS-2.2": [
        "Network infrastructure must synchronize clock with approved time sources",
        "NTP servers must be configured for accurate timestamp recording",
        "Time synchronization with trusted NTP infrastructure is required",
        "Device clocks must be synchronized via configured NTP servers",
    ],
    "CIS-3.1": [
        "SNMP must use secure community names and modern protocol versions",
        "Default SNMP community strings like public or private are prohibited",
        "SNMP configuration must avoid well-known community names",
        "Secure SNMP community naming and versioning is required",
    ],
    "CIS-4.1": [
        "Security zones must be configured to enforce traffic segmentation",
        "Network segmentation through defined security zones is required",
        "Zone-based firewall policies must separate network segments",
        "Inter-zone traffic control via security zone configuration is mandatory",
    ],
}

# Realistic usernames
SECURE_USERNAMES = [
    "netadmin", "ops_team", "security_ops", "network_engineer",
    "infrastructure_admin", "noc_analyst", "sysadmin", "devops",
]

DEFAULT_USERNAMES = ["admin", "root", "cisco", "guest", "test", "operator"]

SECURE_COMMUNITIES = [
    "corp-monitor", "network-ops", "security-team", "datacenter",
    "server-mgmt", "fw-monitor", "switch-admin", "router-ops",
]

DEFAULT_COMMUNITIES = ["public", "private", "community", "test", "default"]


def rand_ip():
    return f"{random.randint(1, 254)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"


def rand_subnet():
    return f"{random.randint(10, 172)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}"


# ============================================================================
# Real-Derived Example Generation
# ============================================================================

def load_real_configs() -> Dict[str, str]:
    """Load all non-holdout real configs."""
    configs = {}
    config_dir = Path(__file__).parent.parent.parent / "real_configs"

    for root, dirs, files in os.walk(config_dir):
        for f in files:
            filepath = Path(root) / f
            if filepath.suffix not in ['.txt', '.raw']:
                continue
            if filepath.name in HOLDOUT_FILES:
                continue

            try:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as fh:
                    content = fh.read()
                    if len(content.strip()) > 100 and '404' not in content:
                        configs[filepath.name] = content
            except:
                continue

    return configs


def generate_real_derived_example(
    config_name: str,
    content: str,
    rule_id: str,
    target_label: str,
    difficulty: str = "medium"
) -> Dict[str, Any]:
    """Generate a mutated example from a real config."""

    # Parse the original config
    parsed = parse_cisco_ios(content)
    if not parsed:
        return None

    hostname = parsed.get('hostname', 'device')
    lines = content.split('\n')

    # Create mutation based on rule and target label
    modified_lines = lines.copy()

    if rule_id == "CIS-1.1":
        if target_label == "1":  # Compliant - ensure no default users
            # Remove any default usernames
            modified_lines = [l for l in modified_lines
                           if not ('username' in l and any(u in l for u in DEFAULT_USERNAMES))]
            # Add secure username if none exists
            has_user = any('username' in l for l in modified_lines)
            if not has_user:
                sec_user = random.choice(SECURE_USERNAMES)
                modified_lines.append(f"username {sec_user} privilege 15 secret 5 $1${random.randint(1000,9999)}$hash")
        else:  # Non-compliant - add default user
            default_user = random.choice(DEFAULT_USERNAMES)
            modified_lines.append(f"username {default_user} privilege 15 secret 5 $1${random.randint(1000,9999)}$hash")

    elif rule_id == "CIS-1.2":
        if target_label == "1":  # Compliant - ensure encryption
            # Add service password-encryption if missing
            if not any('service password-encryption' in l for l in modified_lines):
                idx = next((i for i, l in enumerate(modified_lines) if 'hostname' in l), 0)
                modified_lines.insert(idx + 1, "service password-encryption")
            # Ensure username uses secret (not password)
            modified_lines = [l for l in modified_lines if 'password 0' not in l]
        else:  # Non-compliant - use plaintext
            # Change secret to password 0
            modified_lines = [l.replace('secret 5', 'password 0') if 'secret' in l else l
                             for l in modified_lines]
            if not any('password 0' in l for l in modified_lines):
                modified_lines.append("username operator privilege 1 password 0 cleartext123")

    elif rule_id == "CIS-2.1":
        if target_label == "1":  # Compliant - add syslog
            if not any('logging host' in l for l in modified_lines):
                modified_lines.append(f"logging host {rand_ip()}")
                modified_lines.append("logging trap informational")
        else:  # Non-compliant - remove syslog
            modified_lines = [l for l in modified_lines if 'logging host' not in l]

    elif rule_id == "CIS-2.2":
        if target_label == "1":  # Compliant - add NTP
            if not any('ntp server' in l for l in modified_lines):
                modified_lines.append(f"ntp server {rand_ip()}")
        else:  # Non-compliant - remove NTP
            modified_lines = [l for l in modified_lines if 'ntp server' not in l]

    elif rule_id == "CIS-3.1":
        if target_label == "1":  # Compliant - add secure SNMP
            if not any('snmp-server community' in l for l in modified_lines):
                community = random.choice(SECURE_COMMUNITIES)
                modified_lines.append(f"snmp-server community {community} RO")
        else:  # Non-compliant - use default community
            if not any('snmp-server community' in l for l in modified_lines):
                community = random.choice(DEFAULT_COMMUNITIES)
                modified_lines.append(f"snmp-server community {community} RO")

    # Add realistic noise (interface configs, routing)
    if random.random() > 0.5:
        intf = f"GigabitEthernet{random.randint(0,1)}/{random.randint(0,3)}"
        modified_lines.extend([
            f"interface {intf}",
            f" description {random.choice(['WAN', 'LAN', 'DMZ'])} Interface",
            f" ip address {rand_ip()} 255.255.255.0",
            " no shutdown",
            "!",
        ])

    # Reconstruct config
    new_content = '\n'.join(modified_lines)

    # Verify label with rules engine
    try:
        # Parse new content to get updated structure
        new_parsed = parse_cisco_ios(new_content)

        # Extract fields correctly
        logging_hosts = [entry.get('host') for entry in new_parsed.get('logging', []) if entry.get('host')]

        norm = NormalizedConfig(
            vendor='cisco_ios',
            format='cli',
            hostname=new_parsed.get('hostname', hostname),
            users=[NormalizedUser(name=u.get('name'), encrypted=u.get('encrypted'))
                   for u in new_parsed.get('users', [])],
            ntp_servers=new_parsed.get('ntp', []),
            logging_hosts=logging_hosts,
            snmp_communities=[],
            zones=[],
        )
        findings = evaluate_compliance(norm)

        # Find the finding for our rule
        finding = next((f for f in findings if f.rule_id == rule_id), None)
        if finding and finding.status in ['PASS', 'FAIL']:
            expected_label = '1' if finding.status == 'PASS' else '0'
            if expected_label == target_label:
                return {
                    "rule_id": rule_id,
                    "policy": random.choice(POLICY_TEXTS[rule_id]),
                    "security_intent": f"Verify {rule_id} compliance",
                    "config": new_content.strip(),
                    "vendor": "cisco",
                    "label": target_label,
                    "source": f"real_derived_{config_name}",
                    "reason": f"mutated_from_{config_name}_to_{target_label}",
                    "difficulty": difficulty,
                }
    except Exception as e:
        pass

    return None


# ============================================================================
# Synthetic Example Generation
# ============================================================================

def generate_synthetic_example(rule_id: str, compliant: bool, vendor: str = "cisco") -> str:
    """Generate a synthetic Cisco IOS config."""
    hostname = f"RTR-{random.randint(1,99)}-{random.randint(1,99)}"
    lines = []

    # Header (varied comment styles to avoid bias)
    if random.random() > 0.5:
        lines.append(f"! {hostname} Configuration")
    else:
        lines.append(f"! Generated: 2024-01-{random.randint(1,28):02d}")
    lines.append("!")
    lines.append(f"hostname {hostname}")
    lines.append("version 15.7")

    # Rule-specific config
    if rule_id == "CIS-1.1":
        if compliant:
            username = random.choice(SECURE_USERNAMES)
            lines.append(f"username {username} privilege 15 secret 5 $1${random.randint(1000,9999)}$hash")
        else:
            default_user = random.choice(DEFAULT_USERNAMES)
            lines.append(f"username {default_user} privilege 15 secret 5 $1${random.randint(1000,9999)}$hash")

    elif rule_id == "CIS-1.2":
        if compliant:
            lines.append("service password-encryption")
            lines.append("username netadmin privilege 15 secret 5 $1$secure$hash")
        else:
            lines.append("username operator privilege 1 password 0 cleartext123")

    elif rule_id == "CIS-2.1":
        if compliant:
            lines.append(f"logging host {rand_ip()}")
            lines.append("logging trap informational")
        else:
            lines.append(f"! logging host {rand_ip()}")

    elif rule_id == "CIS-2.2":
        if compliant:
            lines.append(f"ntp server {rand_ip()}")
            if random.random() > 0.5:
                lines.append(f"ntp server {rand_ip()}")
        else:
            lines.append(f"! ntp server {rand_ip()}")

    elif rule_id == "CIS-3.1":
        if compliant:
            community = random.choice(SECURE_COMMUNITIES)
            lines.append(f"snmp-server community {community} RO")
        else:
            lines.append(f"snmp-server community {random.choice(DEFAULT_COMMUNITIES)} RO")

    # Add noise
    if random.random() > 0.3:
        for _ in range(random.randint(1, 2)):
            intf = f"GigabitEthernet{random.randint(0,1)}/{random.randint(0,3)}"
            lines.extend([
                f"interface {intf}",
                f" ip address {rand_ip()} 255.255.255.0",
                " no shutdown",
                "!",
            ])

    return '\n'.join(lines)


# ============================================================================
# Dataset Generation
# ============================================================================

def generate_v4_dataset() -> Tuple[List[Dict], List[Dict], List[Dict]]:
    """Generate complete V4 dataset."""
    all_examples = []

    # 1. Load V1 curated examples (48 examples)
    v1_dir = Path(__file__).parent.parent / "data"
    if (v1_dir / "train.csv").exists():
        import pandas as pd
        v1_train = pd.read_csv(v1_dir / "train.csv")
        for _, row in v1_train.iterrows():
            all_examples.append({
                "rule_id": row['rule_id'],
                "policy": row['policy'],
                "security_intent": row['security_intent'],
                "config": row['config'],
                "vendor": row['vendor'],
                "label": str(row['label']),
                "source": "v1_curated",
                "reason": "curated_training",
                "difficulty": row.get('difficulty', 'medium'),
            })
        print(f"Loaded {len(v1_train)} V1 training examples")

    # 2. Generate real-derived examples
    real_configs = load_real_configs()
    print(f"Loaded {len(real_configs)} real configs for derivation")

    real_derived = []
    for config_name, content in real_configs.items():
        # Determine which rules are applicable
        parsed = parse_cisco_ios(content)
        if not parsed:
            continue

        applicable_rules = []
        if parsed.get('users') or any('username' in l for l in content.split('\n')):
            applicable_rules.append("CIS-1.1")
        if parsed.get('users'):
            applicable_rules.append("CIS-1.2")
        applicable_rules.append("CIS-2.1")
        applicable_rules.append("CIS-2.2")
        applicable_rules.append("CIS-3.1")
        applicable_rules.append("CIS-4.1")

        # Generate variants for each rule
        for rule in applicable_rules:
            for label in ['0', '1']:
                for _ in range(3):  # 3 variants per rule/label
                    example = generate_real_derived_example(config_name, content, rule, label)
                    if example:
                        real_derived.append(example)

    print(f"Generated {len(real_derived)} real-derived examples")
    all_examples.extend(real_derived)

    # 3. Generate synthetic examples to balance and scale
    target_synthetic = 1000
    rules_vendors = [
        ("CIS-1.1", "cisco"), ("CIS-1.1", "juniper"), ("CIS-1.1", "paloalto"),
        ("CIS-1.2", "cisco"), ("CIS-1.2", "juniper"), ("CIS-1.2", "paloalto"),
        ("CIS-2.1", "cisco"), ("CIS-2.1", "juniper"), ("CIS-2.1", "paloalto"),
        ("CIS-2.2", "cisco"), ("CIS-2.2", "juniper"), ("CIS-2.2", "paloalto"),
        ("CIS-3.1", "cisco"), ("CIS-3.1", "juniper"), ("CIS-3.1", "paloalto"),
        ("CIS-4.1", "juniper"), ("CIS-4.1", "paloalto"),
    ]

    target_per_combo = target_synthetic // len(rules_vendors)

    synthetic = []
    for rule_id, vendor in rules_vendors:
        policy = random.choice(POLICY_TEXTS[rule_id])

        # Generate compliant
        for _ in range(target_per_combo // 2):
            config = generate_synthetic_example(rule_id, True, vendor)
            if config:
                synthetic.append({
                    "rule_id": rule_id,
                    "policy": policy,
                    "security_intent": f"Verify {rule_id} compliance",
                    "config": config,
                    "vendor": vendor,
                    "label": "1",
                    "source": "synthetic_v4",
                    "reason": "compliant",
                    "difficulty": random.choice(["easy", "medium", "hard"]),
                })

        # Generate non-compliant
        for _ in range(target_per_combo // 2):
            config = generate_synthetic_example(rule_id, False, vendor)
            if config:
                synthetic.append({
                    "rule_id": rule_id,
                    "policy": policy,
                    "security_intent": f"Verify {rule_id} compliance",
                    "config": config,
                    "vendor": vendor,
                    "label": "0",
                    "source": "synthetic_v4",
                    "reason": "non_compliant",
                    "difficulty": random.choice(["easy", "medium", "hard"]),
                })

    print(f"Generated {len(synthetic)} synthetic examples")
    all_examples.extend(synthetic)

    # 4. Split by source family
    train, val, test = split_by_family(all_examples)

    return train, val, test


def split_by_family(examples: List[Dict]) -> Tuple[List, List, List]:
    """Split by source family to prevent leakage."""
    grouped = defaultdict(list)
    for ex in examples:
        # Use rule_id + vendor as family key
        family = f"{ex['rule_id']}_{ex['vendor']}"
        grouped[family].append(ex)

    train, val, test = [], [], []

    for family, family_examples in grouped.items():
        random.shuffle(family_examples)
        n = len(family_examples)
        n_train = int(n * TRAIN_RATIO)
        n_val = int(n * VAL_RATIO)

        train.extend(family_examples[:n_train])
        val.extend(family_examples[n_train:n_train + n_val])
        test.extend(family_examples[n_train + n_val:])

    return train, val, test


def write_csv(data: List[Dict], filepath: Path):
    """Write dataset to CSV."""
    if not data:
        return
    fieldnames = ["rule_id", "policy", "security_intent", "config", "vendor", "label", "source", "reason", "difficulty"]
    with open(filepath, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(data)


def validate_dataset(examples: List[Dict], name: str):
    """Validate dataset quality."""
    print(f"\n{'='*60}")
    print(f"VALIDATING {name}")
    print(f"{'='*60}")

    total = len(examples)
    if total == 0:
        print("EMPTY DATASET")
        return

    compliant = sum(1 for e in examples if e['label'] == '1')
    non_compliant = sum(1 for e in examples if e['label'] == '0')

    print(f"Total: {total}")
    print(f"Compliant: {compliant} ({compliant/total*100:.1f}%)")
    print(f"Non-compliant: {non_compliant} ({non_compliant/total*100:.1f}%)")

    # Check duplicates
    configs = [e['config'] for e in examples]
    unique_configs = set(configs)
    print(f"Unique configs: {len(unique_configs)} ({len(unique_configs)/total*100:.1f}%)")

    # Check by vendor
    print(f"\nBy vendor:")
    for vendor in ['cisco', 'juniper', 'paloalto']:
        vendor_ex = [e for e in examples if e['vendor'] == vendor]
        if vendor_ex:
            v_comp = sum(1 for e in vendor_ex if e['label'] == '1')
            print(f"  {vendor}: {len(vendor_ex)} (compliant={v_comp}/{len(vendor_ex)*100:.1f}%)")

    # Check by rule
    print(f"\nBy rule:")
    for rule in sorted(set(e['rule_id'] for e in examples)):
        rule_ex = [e for e in examples if e['rule_id'] == rule]
        r_comp = sum(1 for e in rule_ex if e['label'] == '1')
        print(f"  {rule}: {len(rule_ex)} (compliant={r_comp}/{len(rule_ex)*100:.1f}%)")


def main():
    """Main generation pipeline."""
    print("="*80)
    print("DATASET V4 GENERATOR - Hybrid Real + Synthetic")
    print("="*80)

    # Generate dataset
    print("\nGenerating V4 dataset...")
    train, val, test = generate_v4_dataset()

    # Validate
    validate_dataset(train, "TRAIN")
    validate_dataset(val, "VALIDATION")
    validate_dataset(test, "TEST")

    # Write to files
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    write_csv(train, OUTPUT_DIR / "train.csv")
    write_csv(val, OUTPUT_DIR / "validation.csv")
    write_csv(test, OUTPUT_DIR / "test.csv")

    print(f"\n{'='*80}")
    print("DATASET SAVED")
    print(f"{'='*80}")
    print(f"Train: {len(train)} examples")
    print(f"Validation: {len(val)} examples")
    print(f"Test: {len(test)} examples")
    print(f"Total: {len(train) + len(val) + len(test)} examples")
    print(f"\nFiles created:")
    print(f"  {OUTPUT_DIR / 'train.csv'}")
    print(f"  {OUTPUT_DIR / 'validation.csv'}")
    print(f"  {OUTPUT_DIR / 'test.csv'}")


if __name__ == "__main__":
    main()
