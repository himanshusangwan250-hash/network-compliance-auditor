#!/usr/bin/env python3
"""
Generate Dataset V5 - Targeted improvements based on V4 forensic analysis.
Fixes:
1. CIS-2.2 (NTP) - Add contrastive pairs, handle comments properly
2. CIS-4.1 (Zones) - Generate REAL zone configurations for Juniper/PA
3. CIS-2.1 (Syslog) - Add contrastive pairs, handle comments properly
4. Preserve strong rules (CIS-1.1, CIS-1.2, CIS-3.1)
5. Increase Cisco representation
"""

import os
import sys
import random
import csv
from pathlib import Path
from typing import List, Dict, Any, Tuple
from collections import defaultdict
import pandas as pd

sys.path.insert(0, str(Path(__file__).parent.parent.parent))
os.environ['KMP_DUPLICATE_LIB_OK'] = 'TRUE'

# Set seed for reproducibility
random.seed(42)

# ============================================================================
# Configuration
# ============================================================================

OUTPUT_DIR = Path(__file__).parent
TRAIN_RATIO = 0.70
VAL_RATIO = 0.15
TEST_RATIO = 0.15

# ============================================================================
# Helper Functions
# ============================================================================

def rand_ip():
    return f"{random.randint(1, 254)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

def rand_subnet():
    return f"{random.randint(10, 172)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}"

def rand_mac():
    return ':'.join(f'{random.randint(0,255):02x}' for _ in range(6))

# ============================================================================
# Policy Texts (Diverse formulations)
# ============================================================================

POLICIES = {
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

# ============================================================================
# Username/Community Lists
# ============================================================================

SECURE_USERNAMES = [
    "netadmin", "ops_team", "security_ops", "network_engineer",
    "infrastructure_admin", "noc_analyst", "sysadmin", "devops",
    "platform_eng", "site_admin", "neteng", "security_admin",
]

DEFAULT_USERNAMES = ["admin", "root", "cisco", "guest", "test", "operator", "user", "default"]

SECURE_COMMUNITIES = [
    "corp-monitor", "network-ops", "security-team", "datacenter",
    "server-mgmt", "fw-monitor", "switch-admin", "router-ops",
    "monitoring-team", "noc-alerts", "security-audit",
]

DEFAULT_COMMUNITIES = ["public", "private", "community", "test", "default", "read-only", "write-only"]

# ============================================================================
# CIS-1.1 Examples (Preserve strong patterns)
# ============================================================================

def generate_cis11_example(compliant: bool, vendor: str = "cisco") -> str:
    """Generate CIS-1.1 example - default credential detection."""
    hostname = f"RTR-{random.randint(1,99)}-{random.randint(1,99)}"
    lines = [f"! {hostname} Configuration", "!", f"hostname {hostname}", "version 15.7"]

    if compliant:
        # Secure username
        username = random.choice(SECURE_USERNAMES)
        lines.append(f"username {username} privilege 15 secret 5 $1${random.randint(1000,9999)}$hash")
    else:
        # Default username
        username = random.choice(DEFAULT_USERNAMES)
        lines.append(f"username {username} privilege 15 secret 5 $1${random.randint(1000,9999)}$hash")

    # Add noise
    for _ in range(random.randint(1, 3)):
        intf = f"GigabitEthernet{random.randint(0,1)}/{random.randint(0,3)}"
        lines.extend([
            f"interface {intf}",
            f" ip address {rand_ip()} 255.255.255.0",
            " no shutdown",
            "!",
        ])

    return '\n'.join(lines)

# ============================================================================
# CIS-1.2 Examples (Preserve strong patterns)
# ============================================================================

def generate_cis12_example(compliant: bool, vendor: str = "cisco") -> str:
    """Generate CIS-1.2 example - password encryption."""
    hostname = f"SW-{random.randint(1,99)}-{random.randint(1,99)}"
    lines = [f"! {hostname} Configuration", "!", f"hostname {hostname}"]

    if compliant:
        lines.append("service password-encryption")
        username = random.choice(SECURE_USERNAMES)
        lines.append(f"username {username} privilege 15 secret 5 $1${random.randint(1000,9999)}$hash")
    else:
        # Plaintext password
        username = random.choice(DEFAULT_USERNAMES)
        lines.append(f"username {username} privilege 1 password 0 {random.choice(['pass123', 'admin123', 'cisco123'])}")

    # Add noise
    for _ in range(random.randint(1, 2)):
        lines.extend([
            f"interface Vlan{random.randint(1,10)}",
            f" ip address {rand_ip()} 255.255.255.0",
            " no shutdown",
            "!",
        ])

    return '\n'.join(lines)

# ============================================================================
# CIS-2.1 Examples (FIXED - Syslog with proper comment handling)
# ============================================================================

def generate_cis21_example(compliant: bool, vendor: str = "cisco") -> str:
    """Generate CIS-2.1 example - syslog configuration."""
    hostname = f"FW-{random.randint(1,99)}-{random.randint(1,99)}"
    lines = [f"! {hostname} Configuration", "!", f"hostname {hostname}"]

    if compliant:
        # Active logging
        lines.append(f"logging host {rand_ip()}")
        lines.append("logging trap informational")
    else:
        # Either no logging OR commented-out logging
        if random.random() > 0.5:
            # No logging at all
            pass
        else:
            # Commented-out logging (non-compliant)
            lines.append(f"! logging host {rand_ip()}")

    # Add realistic noise
    for _ in range(random.randint(2, 4)):
        intf = f"GigabitEthernet{random.randint(0,1)}/{random.randint(0,3)}"
        lines.extend([
            f"interface {intf}",
            f" description {random.choice(['WAN', 'LAN', 'DMZ', 'Server'])} Interface",
            f" ip address {rand_ip()} 255.255.255.0",
            " no shutdown",
            "!",
        ])

    return '\n'.join(lines)

# ============================================================================
# CIS-2.2 Examples (FIXED - NTP with proper comment handling)
# ============================================================================

def generate_cis22_example(compliant: bool, vendor: str = "cisco") -> str:
    """Generate CIS-2.2 example - NTP configuration."""
    hostname = f"RTR-{random.randint(1,99)}-{random.randint(1,99)}"
    lines = [f"! {hostname} Configuration", "!", f"hostname {hostname}"]

    if compliant:
        # Active NTP server(s)
        num_servers = random.randint(1, 3)
        for _ in range(num_servers):
            lines.append(f"ntp server {rand_ip()}")
    else:
        # Either no NTP OR commented-out NTP
        if random.random() > 0.5:
            # No NTP at all
            pass
        else:
            # Commented-out NTP (non-compliant)
            lines.append(f"! ntp server {rand_ip()}")

    # Add realistic noise - interfaces, routing, etc.
    for _ in range(random.randint(2, 4)):
        intf = f"GigabitEthernet{random.randint(0,1)}/{random.randint(0,3)}"
        lines.extend([
            f"interface {intf}",
            f" description {random.choice(['WAN', 'LAN', 'DMZ', 'Uplink'])} Interface",
            f" ip address {rand_ip()} 255.255.255.0",
            " no shutdown",
            "!",
        ])

    # Add routing noise
    if random.random() > 0.5:
        lines.extend([
            "ip routing",
            f"ip route 0.0.0.0 0.0.0.0 {rand_ip()}",
        ])

    return '\n'.join(lines)

# ============================================================================
# CIS-3.1 Examples (Preserve strong patterns)
# ============================================================================

def generate_cis31_example(compliant: bool, vendor: str = "cisco") -> str:
    """Generate CIS-3.1 example - SNMP community names."""
    hostname = f"SW-{random.randint(1,99)}-{random.randint(1,99)}"
    lines = [f"! {hostname} Configuration", "!", f"hostname {hostname}"]

    if compliant:
        # Secure community
        community = random.choice(SECURE_COMMUNITIES)
        lines.append(f"snmp-server community {community} RO")
    else:
        # Default/insecure community
        community = random.choice(DEFAULT_COMMUNITIES)
        lines.append(f"snmp-server community {community} RO")

    # Add noise
    for _ in range(random.randint(1, 3)):
        lines.extend([
            f"interface Vlan{random.randint(1,10)}",
            f" ip address {rand_ip()} 255.255.255.0",
            " no shutdown",
            "!",
        ])

    return '\n'.join(lines)

# ============================================================================
# CIS-4.1 Examples (FIXED - REAL zone configurations)
# ============================================================================

def generate_cis41_juniper(compliant: bool) -> str:
    """Generate CIS-4.1 example for Juniper Junos - REAL zone config."""
    hostname = f"SRX-{random.randint(1,99)}"
    lines = [
        f"## {hostname} Configuration",
        f"## Generated: 2024-01-{random.randint(1,28):02d}",
        "##",
        f"set system hostname {hostname}",
    ]

    if compliant:
        # REAL Juniper zone configuration
        lines.extend([
            "",
            "### Security Zones",
            "set security zones security-zone UNTRUSTED interface eth0.0",
            "set security zones security-zone TRUSTED interface eth1.0",
            "set security zones security-zone DMZ interface eth2.0",
            "",
            "### Zone Policies",
            "set security policies from-zone UNTRUSTED to-zone TRUSTED policy deny-all match source-address any",
            "set security policies from-zone UNTRUSTED to-zone TRUSTED policy deny-all match destination-address any",
            "set security policies from-zone UNTRUSTED to-zone TRUSTED policy deny-all then deny",
            "",
            "set security policies from-zone TRUSTED to-zone UNTRUSTED policy allow-internet match source-address trusted-net",
            "set security policies from-zone TRUSTED to-zone UNTRUSTED policy allow-internet match destination-address any",
            "set security policies from-zone TRUSTED to-zone UNTRUSTED policy allow-internet then permit",
        ])
    else:
        # No zones or incomplete zones (non-compliant)
        lines.extend([
            "",
            "### Incomplete zone configuration",
            "set security zones security-zone MGMT interface xe0.0",
            # Missing other zones and policies
        ])

    # Add base configuration
    lines.extend([
        "",
        "### Interface Configuration",
        "set interfaces eth0 unit 0 family inet address 192.168.1.1/24",
        "set interfaces eth1 unit 0 family inet address 10.0.0.1/24",
        "",
        "### Routing",
        "set routing-options static route 0.0.0.0/0 next-hop 192.168.1.254",
    ])

    return '\n'.join(lines)

def generate_cis41_paloalto(compliant: bool) -> str:
    """Generate CIS-4.1 example for Palo Alto PAN-OS - REAL zone config."""
    hostname = f"PA-{random.randint(1,99)}"
    lines = [
        f"<!-- {hostname} Configuration -->",
        f"<!-- Generated: 2024-01-{random.randint(1,28):02d} -->",
        "<deviceconfig>",
        f"  <hostname>{hostname}</hostname>",
        "</deviceconfig>",
    ]

    if compliant:
        # REAL Palo Alto zone configuration
        lines.extend([
            "",
            "<network>",
            "  <interface>",
            "    <ethernet>",
            "      <name>eth1/1</name>",
            "      <layer3>",
            "        <ip>192.168.1.1/24</ip>",
            "      </layer3>",
            "    </ethernet>",
            "    <ethernet>",
            "      <name>eth1/2</name>",
            "      <layer3>",
            "        <ip>10.0.0.1/24</ip>",
            "      </layer3>",
            "    </ethernet>",
            "  </interface>",
            "</network>",
            "",
            "<zones>",
            "  <network>",
            "    <layer3>",
            "      <entry name='UNTRUSTED'>",
            "        <network>eth1/1</network>",
            "      </entry>",
            "      <entry name='TRUSTED'>",
            "        <network>eth1/2</network>",
            "      </entry>",
            "    </layer3>",
            "  </network>",
            "</zones>",
            "",
            "<vsys>",
            "  <entry name='vsys1'>",
            "    <zone>",
            "      <entry name='UNTRUSTED'>",
            "        <type>layer3</type>",
            "      </entry>",
            "      <entry name='TRUSTED'>",
            "        <type>layer3</type>",
            "      </entry>",
            "    </zone>",
            "  </entry>",
            "</vsys>",
        ])
    else:
        # No zones or single zone (non-compliant)
        lines.extend([
            "",
            "<network>",
            "  <interface>",
            "    <ethernet>",
            "      <name>eth1/1</name>",
            "      <layer3>",
            "        <ip>192.168.1.1/24</ip>",
            "      </layer3>",
            "    </ethernet>",
            "  </interface>",
            "</network>",
            # No zones defined
        ])

    return '\n'.join(lines)

def generate_cis41_cisco(compliant: bool) -> str:
    """Generate CIS-4.1 example for Cisco IOS - zone-based firewall."""
    hostname = f"FWSM-{random.randint(1,99)}"
    lines = [
        f"! {hostname} Configuration",
        f"! Generated: 2024-01-{random.randint(1,28):02d}",
        "!",
        f"hostname {hostname}",
    ]

    if compliant:
        # REAL Cisco zone-based firewall configuration
        lines.extend([
            "",
            "### Zone Definition",
            "zone security UNTRUSTED",
            "zone security TRUSTED",
            "zone security DMZ",
            "",
            "### Zone Membership",
            "interface GigabitEthernet0/0",
            " zone-membership untrusted",
            "interface GigabitEthernet0/1",
            " zone-membership trusted",
            "interface GigabitEthernet0/2",
            " zone-membership dmz",
            "",
            "### Zone-Based Firewall Policy",
            "policy-map type inspect FIRST_POLICY",
            " class type inspect INSPECT_UNTRUSTED_TO_TRUSTED",
            "  inspect INSIDE-OUTSIDE-FLOW",
            "class-map type inspect MATCH_UNTRUSTED_TO_TRUSTED",
            " match access-group name UNTRUSTED_TO_TRUSTED_ACL",
            "zone-pair security UNTRUSTED to TRUSTED",
            " service-policy type inspect FIRST_POLICY",
        ])
    else:
        # No zones or incomplete zones
        lines.extend([
            "",
            "### No zone-based firewall configured",
            "interface GigabitEthernet0/0",
            " ip address 192.168.1.1 255.255.255.0",
            " no shutdown",
            "interface GigabitEthernet0/1",
            " ip address 10.0.0.1 255.255.255.0",
            " no shutdown",
        ])

    return '\n'.join(lines)

# ============================================================================
# Contrastive Pair Generation
# ============================================================================

def generate_contrastive_ntp_pairs(count: int = 100) -> List[Dict]:
    """Generate contrastive pairs for NTP - same config with/without NTP."""
    examples = []

    for i in range(count):
        # Base config template
        hostname = f"RTR-{random.randint(1,99)}-{random.randint(1,99)}"
        base_lines = [
            f"! {hostname} Configuration",
            f"!",
            f"hostname {hostname}",
            "version 15.7",
        ]

        # Add realistic noise
        for _ in range(random.randint(2, 4)):
            intf = f"GigabitEthernet{random.randint(0,1)}/{random.randint(0,3)}"
            base_lines.extend([
                f"interface {intf}",
                f" description {random.choice(['WAN', 'LAN', 'DMZ'])} Interface",
                f" ip address {rand_ip()} 255.255.255.0",
                " no shutdown",
                "!",
            ])

        # Add routing
        base_lines.extend([
            "ip routing",
            f"ip route 0.0.0.0 0.0.0.0 {rand_ip()}",
        ])

        # COMPLIANT: Add NTP
        compliant_config = '\n'.join(base_lines + [f"ntp server {rand_ip()}"])

        # NON-COMPLIANT: No NTP or commented NTP
        if random.random() > 0.5:
            noncompliant_config = '\n'.join(base_lines)
        else:
            # Commented out NTP
            noncompliant_config = '\n'.join(base_lines + [f"! ntp server {rand_ip()}"])

        policy = random.choice(POLICIES["CIS-2.2"])

        examples.append({
            "rule_id": "CIS-2.2",
            "policy": policy,
            "security_intent": "Verify NTP synchronization",
            "config": compliant_config,
            "vendor": random.choice(["cisco", "juniper", "paloalto"]),
            "label": "1",
            "source": "contrastive_ntp_compliant",
            "reason": "ntp_present",
            "difficulty": "medium",
        })

        examples.append({
            "rule_id": "CIS-2.2",
            "policy": policy,
            "security_intent": "Verify NTP synchronization",
            "config": noncompliant_config,
            "vendor": random.choice(["cisco", "juniper", "paloalto"]),
            "label": "0",
            "source": "contrastive_ntp_noncompliant",
            "reason": "ntp_absent_or_commented",
            "difficulty": "medium",
        })

    return examples

def generate_contrastive_syslog_pairs(count: int = 80) -> List[Dict]:
    """Generate contrastive pairs for syslog - same config with/without logging."""
    examples = []

    for i in range(count):
        # Base config template
        hostname = f"FW-{random.randint(1,99)}-{random.randint(1,99)}"
        base_lines = [
            f"! {hostname} Configuration",
            f"!",
            f"hostname {hostname}",
            "version 15.7",
        ]

        # Add realistic noise
        for _ in range(random.randint(2, 4)):
            intf = f"GigabitEthernet{random.randint(0,1)}/{random.randint(0,3)}"
            base_lines.extend([
                f"interface {intf}",
                f" description {random.choice(['WAN', 'LAN', 'DMZ'])} Interface",
                f" ip address {rand_ip()} 255.255.255.0",
                " no shutdown",
                "!",
            ])

        # COMPLIANT: Add syslog
        compliant_config = '\n'.join(base_lines + [
            f"logging host {rand_ip()}",
            "logging trap informational",
        ])

        # NON-COMPLIANT: No logging or commented logging
        if random.random() > 0.5:
            noncompliant_config = '\n'.join(base_lines)
        else:
            noncompliant_config = '\n'.join(base_lines + [f"! logging host {rand_ip()}"])

        policy = random.choice(POLICIES["CIS-2.1"])

        examples.append({
            "rule_id": "CIS-2.1",
            "policy": policy,
            "security_intent": "Verify syslog configuration",
            "config": compliant_config,
            "vendor": random.choice(["cisco", "juniper", "paloalto"]),
            "label": "1",
            "source": "contrastive_syslog_compliant",
            "reason": "syslog_present",
            "difficulty": "medium",
        })

        examples.append({
            "rule_id": "CIS-2.1",
            "policy": policy,
            "security_intent": "Verify syslog configuration",
            "config": noncompliant_config,
            "vendor": random.choice(["cisco", "juniper", "paloalto"]),
            "label": "0",
            "source": "contrastive_syslog_noncompliant",
            "reason": "syslog_absent_or_commented",
            "difficulty": "medium",
        })

    return examples

# ============================================================================
# Dataset Generation
# ============================================================================

def generate_v5_dataset() -> Tuple[List[Dict], List[Dict], List[Dict]]:
    """Generate complete V5 dataset with targeted improvements."""
    all_examples = []

    # 1. Load V4 test set as frozen evaluation baseline
    v4_test = pd.read_csv(Path(__file__).parent.parent / "data_v4" / "test.csv")
    for _, row in v4_test.iterrows():
        all_examples.append({
            "rule_id": row['rule_id'],
            "policy": row['policy'],
            "security_intent": row['security_intent'],
            "config": row['config'],
            "vendor": row['vendor'],
            "label": str(row['label']),
            "source": "v4_test_frozen",
            "reason": "frozen_evaluation_baseline",
            "difficulty": row.get('difficulty', 'medium'),
        })

    # 2. Load V4 train/val for strong rule preservation
    v4_train = pd.read_csv(Path(__file__).parent.parent / "data_v4" / "train.csv")
    for _, row in v4_train.iterrows():
        # Only preserve strong rules (CIS-1.1, CIS-1.2, CIS-3.1)
        if row['rule_id'] in ['CIS-1.1', 'CIS-1.2', 'CIS-3.1']:
            all_examples.append({
                "rule_id": row['rule_id'],
                "policy": row['policy'],
                "security_intent": row['security_intent'],
                "config": row['config'],
                "vendor": row['vendor'],
                "label": str(row['label']),
                "source": "v4_preserved_strong",
                "reason": "preserve_strong_patterns",
                "difficulty": row.get('difficulty', 'medium'),
            })

    print(f"Loaded {len(all_examples)} preserved examples from V4")

    # 3. Generate NEW CIS-2.2 contrastive pairs (FIX NTP)
    ntp_pairs = generate_contrastive_ntp_pairs(120)
    all_examples.extend(ntp_pairs)
    print(f"Generated {len(ntp_pairs)} NTP contrastive pairs")

    # 4. Generate NEW CIS-2.1 contrastive pairs (FIX syslog)
    syslog_pairs = generate_contrastive_syslog_pairs(100)
    all_examples.extend(syslog_pairs)
    print(f"Generated {len(syslog_pairs)} syslog contrastive pairs")

    # 5. Generate NEW CIS-4.1 examples (FIX zones with REAL configs)
    zone_examples = []
    # Juniper zones
    for _ in range(80):
        compliant = random.random() > 0.3
        config = generate_cis41_juniper(compliant)
        zone_examples.append({
            "rule_id": "CIS-4.1",
            "policy": random.choice(POLICIES["CIS-4.1"]),
            "security_intent": "Verify security zone configuration",
            "config": config,
            "vendor": "juniper",
            "label": "1" if compliant else "0",
            "source": "synthetic_v5_zone_juniper",
            "reason": "real_zone_config",
            "difficulty": "hard" if compliant else "medium",
        })

    # Palo Alto zones
    for _ in range(80):
        compliant = random.random() > 0.3
        config = generate_cis41_paloalto(compliant)
        zone_examples.append({
            "rule_id": "CIS-4.1",
            "policy": random.choice(POLICIES["CIS-4.1"]),
            "security_intent": "Verify security zone configuration",
            "config": config,
            "vendor": "paloalto",
            "label": "1" if compliant else "0",
            "source": "synthetic_v5_zone_paloalto",
            "reason": "real_zone_config",
            "difficulty": "hard" if compliant else "medium",
        })

    # Cisco zones (zone-based firewall)
    for _ in range(60):
        compliant = random.random() > 0.3
        config = generate_cis41_cisco(compliant)
        zone_examples.append({
            "rule_id": "CIS-4.1",
            "policy": random.choice(POLICIES["CIS-4.1"]),
            "security_intent": "Verify security zone configuration",
            "config": config,
            "vendor": "cisco",
            "label": "1" if compliant else "0",
            "source": "synthetic_v5_zone_cisco",
            "reason": "real_zone_config",
            "difficulty": "hard" if compliant else "medium",
        })

    all_examples.extend(zone_examples)
    print(f"Generated {len(zone_examples)} zone configuration examples")

    # 6. Generate additional CIS-1.1, CIS-1.2, CIS-3.1 to reinforce strong rules
    for rule in ['CIS-1.1', 'CIS-1.2', 'CIS-3.1']:
        generator = {
            'CIS-1.1': generate_cis11_example,
            'CIS-1.2': generate_cis12_example,
            'CIS-3.1': generate_cis31_example,
        }[rule]

        for _ in range(60):
            compliant = random.random() > 0.5
            vendor = random.choice(["cisco", "cisco", "cisco", "juniper", "paloalto"])  # 60% Cisco
            config = generator(compliant, vendor)
            all_examples.append({
                "rule_id": rule,
                "policy": random.choice(POLICIES[rule]),
                "security_intent": f"Verify {rule} compliance",
                "config": config,
                "vendor": vendor,
                "label": "1" if compliant else "0",
                "source": f"synthetic_v5_{rule.lower()}",
                "reason": "reinforce_strong_rule",
                "difficulty": random.choice(["easy", "medium"]),
            })

    print(f"Generated additional strong rule examples")

    # 7. Split by source family to prevent leakage
    train, val, test = split_by_family(all_examples)

    return train, val, test

def split_by_family(examples: List[Dict]) -> Tuple[List, List, List]:
    """Split by source family to prevent leakage."""
    grouped = defaultdict(list)
    for ex in examples:
        # Use rule_id + vendor + source as family key
        family = f"{ex['rule_id']}_{ex['vendor']}_{ex['source']}"
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
    print("DATASET V5 GENERATOR - Targeted Forensic Improvements")
    print("="*80)

    # Generate dataset
    print("\nGenerating V5 dataset...")
    train, val, test = generate_v5_dataset()

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
