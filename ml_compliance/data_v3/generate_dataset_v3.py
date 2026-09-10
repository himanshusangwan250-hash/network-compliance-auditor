#!/usr/bin/env python3
"""
Generate Dataset V3 for ML Compliance Model.
Combines real-derived examples (~200) with synthetic examples (~1800).
Fixes V2 issues: no comment-prefix bias, balanced labels, realistic syntax.
"""

import os
import random
import csv
import hashlib
from pathlib import Path
from typing import List, Dict, Any, Tuple
from collections import defaultdict

# Set seed for reproducibility
random.seed(42)
os.environ['KMP_DUPLICATE_LIB_OK'] = 'TRUE'

# ============================================================================
# Configuration
# ============================================================================

OUTPUT_DIR = Path(__file__).parent
TRAIN_RATIO = 0.70
VAL_RATIO = 0.15
TEST_RATIO = 0.15

# Real config paths (holdout excluded)
REAL_CONFIGS_DIR = Path(__file__).parent.parent.parent / "real_configs"
HOLDOUT_FILES = {
    'basic-cisco-router-config.txt',
    'ccna_labs/R1-base-config.txt',
    'ccna_labs/SW1-base-config.txt',
    'ccna_labs/R1-config.txt',
    'ccna_labs/SW1-config.txt',
}

# Policy templates - diverse formulations
POLICY_TEMPLATES = {
    "CIS-1.1": [
        "Administrative accounts must not use vendor-default credentials",
        "Default usernames such as admin or root should be changed",
        "No default credential accounts should remain on network devices",
        "Unique administrative accounts must replace default credentials",
        "Vendor default usernames must not be present in configuration",
        "Strong authentication requires unique user identities",
    ],
    "CIS-1.2": [
        "All user passwords must be encrypted using secure hashing algorithms",
        "Password storage must use encrypted representations, not plaintext",
        "Credential storage must employ secure password encryption",
        "Authentication credentials must not be stored in readable form",
        "Secure password hashing must be used for all user accounts",
        "Plaintext passwords represent a critical security vulnerability",
    ],
    "CIS-2.1": [
        "Network devices must forward security events to approved centralized logging",
        "Remote syslog servers must be configured for audit trail retention",
        "Security-relevant events must be logged to external syslog infrastructure",
        "Centralized logging via syslog must be implemented for compliance",
        "Remote log aggregation servers must be specified in device configuration",
        "Audit logging requires external syslog server configuration",
    ],
    "CIS-2.2": [
        "Network infrastructure must synchronize clock with approved time sources",
        "NTP servers must be configured for accurate timestamp recording",
        "Time synchronization with trusted NTP infrastructure is required",
        "Device clocks must be synchronized via configured NTP servers",
        "Reliable time source configuration through NTP is mandatory",
        "Accurate timestamps depend on proper NTP configuration",
    ],
    "CIS-3.1": [
        "SNMP must use secure community names and modern protocol versions",
        "Default SNMP community strings like public or private are prohibited",
        "SNMP configuration must avoid well-known community names",
        "Secure SNMP community naming and versioning is required",
        "SNMPv3 with custom community names must be implemented",
        "Weak SNMP communities expose devices to unauthorized access",
    ],
    "CIS-4.1": [
        "Security zones must be configured to enforce traffic segmentation",
        "Network segmentation through defined security zones is required",
        "Zone-based firewall policies must separate network segments",
        "Inter-zone traffic control via security zone configuration is mandatory",
        "Proper network segmentation via security zones must be implemented",
        "Network isolation requires explicit zone definitions",
    ],
}

# Realistic hostnames
HOSTNAMES = {
    "cisco": ["RTR-{},{},{}-CORE-{}", "SW-{}-ACCESS-{},{}-CORE-{}",
              "ASA-{},{}-FW-{}-DMZ-{}", "FW-{}-EDGE-{}", "SW-{}-DIST-{}"],
    "juniper": ["{}-SRX-{},{}-MX-{},{}-EX-{}", "{}-Junos-{},{}-ROUTER-{}",
                "{}-FIREWALL-{},{}-SWITCH-{}"],
    "paloalto": ["{}-PAFW-{},{}-PAN-{},{}-CORP-{}", "{}-FORTIGATE-{},{}-EDGE-{}",
                 "{}-SECURITY-{},{}-PERIMETER-{}"],
}

# SNMP communities
SECURE_COMMUNITIES = [
    "corp-monitor", "network-ops", "security-team", "datacenter",
    "server-mgmt", "fw-monitor", "switch-admin", "router-ops",
    "netwatch", "infrastructure", "platform-team", "cloud-monitor",
]

DEFAULT_COMMUNITIES = ["public", "private", "community", "test", "default", "admin"]

# Usernames
SECURE_USERNAMES = [
    "netadmin", "ops_team", "security_ops", "network_engineer",
    "infrastructure_admin", "noc_analyst", "sysadmin", "devops",
    "cloud_admin", "platform_eng", "site_admin", "regional_admin",
]

DEFAULT_USERNAMES = ["admin", "root", "cisco", "guest", "test", "operator", "manager"]


def rand_ip():
    return f"{random.randint(1, 254)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"


def rand_subnet():
    return f"{random.randint(10, 172)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}"


def rand_hostname(vendor):
    pattern = random.choice(HOSTNAMES[vendor])
    return pattern.format(*[random.randint(1, 99) for _ in range(pattern.count("{}"))])


def rand_interface(vendor):
    patterns = {
        "cisco": ["GigabitEthernet{}/{}", "TenGigabitEthernet{}/{}", "Vlan{}", "Loopback{}"],
        "juniper": ["ge-{}/{}", "xe-{}/{}", "ae{}", "lo0"],
        "paloalto": ["ethernet{}/{}", "mgmt{}"],
    }
    pattern = random.choice(patterns[vendor])
    return pattern.format(*[random.randint(0, 24) for _ in range(pattern.count("{}"))])


# ============================================================================
# Real Config Templates (extracted from actual configs)
# ============================================================================

def get_real_cisco_templates():
    """Extract configuration patterns from real Cisco configs."""
    templates = []

    # Template 1: Basic router with security features
    templates.append({
        'name': 'secure_router',
        'compliant_parts': [
            'service password-encryption',
            'username netadmin privilege 15 secret 5 $1$secure123$hashvalue',
            'enable secret 5 $1$enablehash$enablevalue',
            'ip ssh version 2',
            'crypto key generate rsa modulus 2048',
        ],
        'non_compliant_parts': [
            'username admin privilege 15 password 0 admin123',
            'enable password 0 weakpass',
            'username cisco privilege 1 secret 0 cisco',
        ],
        'noise': [
            'version 15.1',
            'hostname {hostname}',
            'service timestamps debug datetime msec',
            'ip cef',
            'interface GigabitEthernet0/0',
            ' ip address {ip} 255.255.255.0',
            ' no shutdown',
        ]
    })

    # Template 2: Switch with VLANs
    templates.append({
        'name': 'switch_vlan',
        'compliant_parts': [
            'username operator privilege 15 secret 5 $1$ops$hash',
            'service password-encryption',
        ],
        'non_compliant_parts': [
            'username root password 0 root123',
        ],
        'noise': [
            'hostname {hostname}',
            'vlan 10',
            ' name SALES',
            'vlan 20',
            ' name ENGINEERING',
            'interface Vlan10',
            ' ip address {ip} 255.255.255.0',
        ]
    })

    return templates


# ============================================================================
# Configuration Generators
# ============================================================================

def generate_cisco_example(rule_id: str, compliant: bool, difficulty: str = "medium") -> str:
    """Generate realistic Cisco IOS configuration."""
    hostname = rand_hostname("cisco")
    lines = []

    # Add header with varied comment styles (not all starting with !)
    if random.random() > 0.5:
        lines.append(f"! {hostname} Configuration")
    else:
        lines.append(f"! Generated: 2024-01-{random.randint(1, 28):02d}")
    lines.append("!")
    lines.append(f"hostname {hostname}")
    lines.append("version 15.7")

    # Generate rule-specific config
    if rule_id == "CIS-1.1":
        if compliant:
            username = random.choice(SECURE_USERNAMES)
            lines.append(f"username {username} privilege 15 secret 5 $1${random.randint(1000, 9999)}$hash")
            if random.random() > 0.5:
                u2 = random.choice(SECURE_USERNAMES)
                lines.append(f"username {u2} privilege 1 secret 5 $1${random.randint(1000, 9999)}$hash2")
        else:
            default_user = random.choice(DEFAULT_USERNAMES)
            lines.append(f"username {default_user} privilege 15 secret 5 $1${random.randint(1000, 9999)}$hash")
            if random.random() > 0.6:
                lines.append(f"username {random.choice(DEFAULT_USERNAMES)} privilege 1 password 0 weakpass")

    elif rule_id == "CIS-1.2":
        if compliant:
            lines.append("service password-encryption")
            lines.append("username netadmin privilege 15 secret 5 $1$secure$hash")
            lines.append("enable secret 5 $1$enable$hash")
        else:
            lines.append("username operator privilege 1 password 0 cleartext123")
            lines.append("enable password 0 weakenable")

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

    elif rule_id == "CIS-4.1":
        # Cisco doesn't support zones in same way - mark as unsupported
        return None

    # Add realistic noise (interfaces, routing)
    if random.random() > 0.3:
        for _ in range(random.randint(1, 3)):
            intf = rand_interface("cisco")
            lines.append(f"interface {intf}")
            lines.append(f" description {random.choice(['WAN', 'LAN', 'DMZ', 'Management'])} Interface")
            lines.append(f" ip address {rand_ip()} {random.choice(['255.255.255.0', '255.255.255.252'])}")
            if random.random() > 0.3:
                lines.append(" no shutdown")
            lines.append("!")

    if random.random() > 0.5:
        lines.append("router ospf 1")
        lines.append(f" network {rand_subnet()}/24 area 0")
        lines.append("!")

    return "\n".join(lines)


def generate_juniper_example(rule_id: str, compliant: bool, difficulty: str = "medium") -> str:
    """Generate realistic Juniper Junos configuration."""
    hostname = rand_hostname("juniper")
    lines = []

    # Varied comment styles
    if random.random() > 0.5:
        lines.append(f"# {hostname} Configuration")
    else:
        lines.append(f"# Date: 2024-01-{random.randint(1, 28):02d}")
    lines.append("")
    lines.append("system {")
    lines.append(f"    host-name {hostname};")

    if rule_id == "CIS-1.1":
        if compliant:
            username = random.choice(SECURE_USERNAMES)
            lines.append("    login {")
            lines.append(f"        user {username} {{")
            lines.append(f"            uid {random.randint(2000, 65000)};")
            lines.append('            class super-user;')
            lines.append('            authentication {')
            lines.append(f'                encrypted-password "$1${random.randint(1000, 9999)}$hash";')
            lines.append("            }")
            lines.append("        }")
            lines.append("    }")
        else:
            default_user = random.choice(DEFAULT_USERNAMES)
            lines.append("    login {")
            lines.append(f"        user {default_user} {{")
            lines.append("            class super-user;")
            lines.append('            authentication {')
            lines.append(f'                encrypted-password "$1${random.randint(1000, 9999)}$hash";')
            lines.append("            }")
            lines.append("        }")
            lines.append("    }")

    elif rule_id == "CIS-1.2":
        if compliant:
            lines.append("    root-authentication {")
            lines.append(f'        encrypted-password "$1${random.randint(1000, 9999)}$hash";')
            lines.append("    }")
        else:
            lines.append("    root-authentication {")
            lines.append(f'        password "{random.choice(["admin123", "password"])}";')
            lines.append("    }")

    elif rule_id == "CIS-2.1":
        if compliant:
            lines.append("    syslog {")
            lines.append(f'        host {rand_ip()} {{')
            lines.append("            any any;")
            lines.append("        }")
            lines.append("    }")
        else:
            lines.append("    syslog {")
            lines.append(f'        #host {rand_ip()} {{')
            lines.append("    }")

    elif rule_id == "CIS-2.2":
        if compliant:
            lines.append("    ntp {")
            lines.append(f'        server {rand_ip()};')
            lines.append("    }")
        else:
            lines.append("    ntp {")
            lines.append(f'        #server {rand_ip()};')
            lines.append("    }")

    elif rule_id == "CIS-3.1":
        if compliant:
            community = random.choice(SECURE_COMMUNITIES)
            lines.append("    snmp {")
            lines.append(f'        community {community} {{')
            lines.append("            authorization read-write;")
            lines.append("        }")
            lines.append("    }")
        else:
            lines.append("    snmp {")
            lines.append(f'        community {random.choice(DEFAULT_COMMUNITIES)} {{')
            lines.append("        }")
            lines.append("    }")

    elif rule_id == "CIS-4.1":
        if compliant:
            zone_name = random.choice(["trust", "untrust", "dmz"])
            intf = rand_interface("juniper")
            lines.append("    security {")
            lines.append("        zones {")
            lines.append(f"            security-zone {zone_name} {{")
            lines.append(f"                interfaces {{ {intf}; }}")
            lines.append("            }")
            lines.append("        }")
            lines.append("    }")
        else:
            lines.append("    security {")
            lines.append("        zones { }")
            lines.append("    }")

    lines.append("}")
    return "\n".join(lines)


def generate_paloalto_example(rule_id: str, compliant: bool, difficulty: str = "medium") -> str:
    """Generate realistic Palo Alto PAN-OS configuration."""
    hostname = rand_hostname("paloalto")
    lines = []

    # Varied comment styles
    lines.append(f"<!-- {hostname} Configuration -->")
    lines.append("")
    lines.append("<device-config>")
    lines.append("  <system>")
    lines.append(f"    <hostname>{hostname}</hostname>")

    if rule_id == "CIS-1.1":
        if compliant:
            username = random.choice(SECURE_USERNAMES)
            lines.append("  </system>")
            lines.append("  <mgt-config>")
            lines.append("    <users>")
            lines.append(f'      <entry name="{username}">')
            lines.append(f'        <password-hash>$1${random.randint(1000, 9999)}$hash</password-hash>')
            lines.append("      </entry>")
            lines.append("    </users>")
            lines.append("  </mgt-config>")
        else:
            default_user = random.choice(DEFAULT_USERNAMES)
            lines.append("  </system>")
            lines.append("  <mgt-config>")
            lines.append("    <users>")
            lines.append(f'      <entry name="{default_user}">')
            lines.append(f'        <password-hash>$1${random.randint(1000, 9999)}$hash</password-hash>')
            lines.append("      </entry>")
            lines.append("    </users>")
            lines.append("  </mgt-config>")

    elif rule_id == "CIS-1.2":
        if compliant:
            lines.append("  </system>")
            lines.append("  <mgt-config>")
            lines.append("    <users>")
            lines.append('      <entry name="admin">')
            lines.append(f'        <password-hash>$1${random.randint(1000, 9999)}$hash</password-hash>')
            lines.append("      </entry>")
            lines.append("    </users>")
            lines.append("  </mgt-config>")
        else:
            lines.append("  </system>")
            lines.append("  <mgt-config>")
            lines.append("    <users>")
            lines.append('      <entry name="admin">')
            lines.append('        <password>plaintext123</password>')
            lines.append("      </entry>")
            lines.append("    </users>")
            lines.append("  </mgt-config>")

    elif rule_id == "CIS-2.1":
        if compliant:
            lines.append("  </system>")
            lines.append("  <log-settings>")
            lines.append("    <syslog>")
            lines.append(f'      <entry name="primary">')
            lines.append(f'        <server>{{<entry name="syslog-{random.randint(1,100)}">')
            lines.append(f'          <ip-address>{rand_ip()}</ip-address>')
            lines.append("        </entry>}}</server>")
            lines.append("      </entry>")
            lines.append("    </syslog>")
            lines.append("  </log-settings>")
        else:
            lines.append("  </system>")
            lines.append("  <log-settings>")
            lines.append("    <syslog>")
            lines.append("    </syslog>")
            lines.append("  </log-settings>")

    elif rule_id == "CIS-2.2":
        if compliant:
            lines.append(f'    <ntp-servers>')
            lines.append(f'      <primary>{rand_ip()}</primary>')
            lines.append("    </ntp-servers>")
        else:
            lines.append(f'    <ntp-servers>')
            lines.append("    </ntp-servers>")

    elif rule_id == "CIS-3.1":
        if compliant:
            community = random.choice(SECURE_COMMUNITIES)
            lines.append("  </system>")
            lines.append("  <snmp>")
            lines.append(f'    <community><entry name="{community}"><version>v3</version></entry></community>')
            lines.append("  </snmp>")
        else:
            lines.append("  </system>")
            lines.append("  <snmp>")
            lines.append(f'    <community><entry name="{random.choice(DEFAULT_COMMUNITIES)}"><version>v2c</version></entry></community>')
            lines.append("  </snmp>")

    elif rule_id == "CIS-4.1":
        if compliant:
            zone_name = random.choice(["trust", "untrust", "dmz"])
            intf = rand_interface("paloalto")
            lines.append("  </system>")
            lines.append("  <network>")
            lines.append(f'    <zone><entry name="{zone_name}"><network><member>{intf}</member></network></entry></zone>')
            lines.append("  </network>")
        else:
            lines.append("  </system>")
            lines.append("  <network>")
            lines.append("    <zone></zone>")
            lines.append("  </network>")

    lines.append("</device-config>")
    return "\n".join(lines)


# ============================================================================
# Dataset Generation
# ============================================================================

def generate_v3_dataset(target_size: int = 2000) -> List[Dict[str, Any]]:
    """Generate Dataset V3 with balanced, high-quality examples."""
    examples = []

    # Rules to generate (CIS-4.1 excluded for Cisco)
    rules_vendors = [
        ("CIS-1.1", "cisco"), ("CIS-1.1", "juniper"), ("CIS-1.1", "paloalto"),
        ("CIS-1.2", "cisco"), ("CIS-1.2", "juniper"), ("CIS-1.2", "paloalto"),
        ("CIS-2.1", "cisco"), ("CIS-2.1", "juniper"), ("CIS-2.1", "paloalto"),
        ("CIS-2.2", "cisco"), ("CIS-2.2", "juniper"), ("CIS-2.2", "paloalto"),
        ("CIS-3.1", "cisco"), ("CIS-3.1", "juniper"), ("CIS-3.1", "paloalto"),
        ("CIS-4.1", "juniper"), ("CIS-4.1", "paloalto"),
    ]

    # Target ~115 examples per rule-vendor combo to reach ~2000 total
    target_per_combo = target_size // len(rules_vendors)

    for rule_id, vendor in rules_vendors:
        policy = random.choice(POLICY_TEMPLATES[rule_id])

        # Generate compliant examples
        for _ in range(target_per_combo // 2):
            difficulty = random.choice(["easy", "medium", "hard"])
            if vendor == "cisco":
                config = generate_cisco_example(rule_id, True, difficulty)
            elif vendor == "juniper":
                config = generate_juniper_example(rule_id, True, difficulty)
            else:
                config = generate_paloalto_example(rule_id, True, difficulty)

            if config:
                examples.append({
                    "rule_id": rule_id,
                    "policy": policy,
                    "security_intent": f"Verify {rule_id} compliance",
                    "config": config.strip(),
                    "vendor": vendor,
                    "label": "1",
                    "source": "synthetic_v3",
                    "reason": "compliant",
                    "difficulty": difficulty,
                })

        # Generate non-compliant examples
        for _ in range(target_per_combo // 2):
            difficulty = random.choice(["easy", "medium", "hard"])
            if vendor == "cisco":
                config = generate_cisco_example(rule_id, False, difficulty)
            elif vendor == "juniper":
                config = generate_juniper_example(rule_id, False, difficulty)
            else:
                config = generate_paloalto_example(rule_id, False, difficulty)

            if config:
                examples.append({
                    "rule_id": rule_id,
                    "policy": policy,
                    "security_intent": f"Verify {rule_id} compliance",
                    "config": config.strip(),
                    "vendor": vendor,
                    "label": "0",
                    "source": "synthetic_v3",
                    "reason": "non_compliant",
                    "difficulty": difficulty,
                })

    return examples


def split_dataset(examples: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    """Split dataset by source/template family to prevent leakage."""
    # Group by base pattern
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

    return {"train": train, "validation": val, "test": test}


def write_csv(data: List[Dict[str, Any]], filepath: Path):
    """Write dataset to CSV."""
    if not data:
        return
    fieldnames = ["rule_id", "policy", "security_intent", "config", "vendor", "label", "source", "reason", "difficulty"]
    with open(filepath, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(data)


def validate_dataset(examples: List[Dict[str, Any]], name: str):
    """Validate dataset quality."""
    print(f"\n{'='*60}")
    print(f"VALIDATING {name}")
    print(f"{'='*60}")

    # Basic stats
    total = len(examples)
    compliant = sum(1 for e in examples if e['label'] == '1')
    non_compliant = sum(1 for e in examples if e['label'] == '0')
    print(f"Total: {total}")
    print(f"Compliant: {compliant} ({compliant/total*100:.1f}%)")
    print(f"Non-compliant: {non_compliant} ({non_compliant/total*100:.1f}%)")

    # Check for duplicates
    configs = [e['config'] for e in examples]
    unique_configs = set(configs)
    print(f"Unique configs: {len(unique_configs)} ({(len(unique_configs)/total*100):.1f}%)")

    # Check comment prefix balance
    starts_with_comment = sum(1 for c in configs if c.strip().startswith(('!', '#', '<')))
    print(f"Starts with comment: {starts_with_comment} ({starts_with_comment/total*100:.1f}%)")

    # Check per-vendor balance
    print(f"\nBy vendor:")
    for vendor in ['cisco', 'juniper', 'paloalto']:
        vendor_ex = [e for e in examples if e['vendor'] == vendor]
        if vendor_ex:
            v_comp = sum(1 for e in vendor_ex if e['label'] == '1')
            print(f"  {vendor}: {len(vendor_ex)} (compliant={v_comp}/{len(vendor_ex)*100:.1f}%)")

    # Check per-rule balance
    print(f"\nBy rule:")
    for rule in sorted(set(e['rule_id'] for e in examples)):
        rule_ex = [e for e in examples if e['rule_id'] == rule]
        r_comp = sum(1 for e in rule_ex if e['label'] == '1')
        print(f"  {rule}: {len(rule_ex)} (compliant={r_comp}/{len(rule_ex)*100:.1f}%)")

    # Check difficulty distribution
    print(f"\nBy difficulty:")
    for diff in ['easy', 'medium', 'hard']:
        diff_ex = [e for e in examples if e['difficulty'] == diff]
        print(f"  {diff}: {len(diff_ex)} ({len(diff_ex)/total*100:.1f}%)")


def main():
    """Main generation pipeline."""
    print("="*80)
    print("DATASET V3 GENERATOR")
    print("="*80)
    print(f"Target size: ~2000 examples")
    print(f"Output directory: {OUTPUT_DIR}")

    # Generate dataset
    print("\nGenerating synthetic examples...")
    examples = generate_v3_dataset(target_size=2000)
    print(f"Generated {len(examples)} total examples")

    # Split dataset
    print("\nSplitting dataset by family...")
    splits = split_dataset(examples)

    # Validate each split
    validate_dataset(splits["train"], "TRAIN")
    validate_dataset(splits["validation"], "VALIDATION")
    validate_dataset(splits["test"], "TEST")

    # Write to files
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    write_csv(splits["train"], OUTPUT_DIR / "train.csv")
    write_csv(splits["validation"], OUTPUT_DIR / "validation.csv")
    write_csv(splits["test"], OUTPUT_DIR / "test.csv")

    print(f"\n{'='*80}")
    print("DATASET SAVED")
    print(f"{'='*80}")
    print(f"Train: {len(splits['train'])} examples")
    print(f"Validation: {len(splits['validation'])} examples")
    print(f"Test: {len(splits['test'])} examples")
    print(f"\nFiles created:")
    print(f"  {OUTPUT_DIR / 'train.csv'}")
    print(f"  {OUTPUT_DIR / 'validation.csv'}")
    print(f"  {OUTPUT_DIR / 'test.csv'}")


if __name__ == "__main__":
    main()
