#!/usr/bin/env python3
"""
Generate Dataset V2 for ML Compliance Model.
Creates ~600 high-quality synthetic examples with realistic variations.
"""

import random
import csv
from pathlib import Path
from typing import List, Dict, Any
from collections import defaultdict

random.seed(42)

# ============================================================================
# Configuration
# ============================================================================

OUTPUT_DIR = Path(__file__).parent
TARGET_SIZE = 600
TARGET_PER_VENDOR = 200
TRAIN_RATIO = 0.70
VAL_RATIO = 0.15
TEST_RATIO = 0.15

# Policy templates with natural language variations
POLICY_TEMPLATES = {
    "CIS-1.1": [
        "Administrative accounts must not use vendor-default credentials",
        "Default usernames such as admin or root should be changed",
        "No default credential accounts should remain on network devices",
        "Unique administrative accounts must replace default credentials",
        "Vendor default usernames must not be present in configuration",
    ],
    "CIS-1.2": [
        "All user passwords must be encrypted using secure hashing algorithms",
        "Password storage must use encrypted representations, not plaintext",
        "Credential storage must employ secure password encryption",
        "Authentication credentials must not be stored in readable form",
        "Secure password hashing must be used for all user accounts",
    ],
    "CIS-2.1": [
        "Network devices must forward security events to approved centralized logging",
        "Remote syslog servers must be configured for audit trail retention",
        "Security-relevant events must be logged to external syslog infrastructure",
        "Centralized logging via syslog must be implemented for compliance",
        "Remote log aggregation servers must be specified in device configuration",
    ],
    "CIS-2.2": [
        "Network infrastructure must synchronize clock with approved time sources",
        "NTP servers must be configured for accurate timestamp recording",
        "Time synchronization with trusted NTP infrastructure is required",
        "Device clocks must be synchronized via configured NTP servers",
        "Reliable time source configuration through NTP is mandatory",
    ],
    "CIS-3.1": [
        "SNMP must use secure community names and modern protocol versions",
        "Default SNMP community strings like public or private are prohibited",
        "SNMP configuration must avoid well-known community names",
        "Secure SNMP community naming and versioning is required",
        "SNMPv3 with custom community names must be implemented",
    ],
    "CIS-4.1": [
        "Security zones must be configured to enforce traffic segmentation",
        "Network segmentation through defined security zones is required",
        "Zone-based firewall policies must separate network segments",
        "Inter-zone traffic control via security zone configuration is mandatory",
        "Proper network segmentation via security zones must be implemented",
    ],
}

# Realistic hostnames per vendor
HOSTNAMES = {
    "cisco": ["RTR-{},{},{}-CORE-{}",
              "SW-{}-ACCESS-{},{}-CORE-{}",
              "ASA-{},{}-FW-{}-DMZ-{}"],
    "juniper": ["{}-SRX-{},{}-MX-{},{}-EX-{}",
                "{}-Junos-{},{}-ROUTER-{}",
                "{}-FIREWALL-{},{}-SWITCH-{}"],
    "paloalto": ["{}-PAFW-{},{}-PAN-{},{}-CORP-{}",
                 "{}-FORTIGATE-{},{}-EDGE-{}",
                 "{}-SECURITY-{},{}-PERIMETER-{}"],
}

# Realistic subnet patterns
SUBNETS = [
    "10.0.{}.{}", "{}.16.{}", "{}.32.{}", "{}.48.{}", "{}.64.{}",
    "172.16.{}", "172.20.{}", "172.24.{}", "192.168.{}",
]

# Realistic interface names
INTERFACES = {
    "cisco": ["GigabitEthernet{}/{}", "TenGigabitEthernet{}/{}",
              "FastEthernet{}/{}", "Vlan{}", "Loopback{}", "Port-channel{}",
              "Management0"],
    "juniper": ["ge-{}/{}", "xe-{}/{}", "et-{}/{}",
                "ae{}", "lo0", "st0.{}", "vlan{}", "irb.{}"],
    "paloalto": ["ethernet{}/{}", "ethernet{}/{}",
                 "ethernet{}/{}", "mgmt{}"],
}

# Realistic usernames
USERNAMES = [
    "netadmin", "ops_team", "security_ops", "network_engineer",
    "infrastructure_admin", "noc_analyst", "sysadmin", "devops",
    "cloud_admin", "platform_eng", "site_admin", "regional_admin",
    "security_admin", "audit_user", "backup_admin", "monitoring",
    "netops", "infra_ops", "security_team", "network_team",
    "sysops", "platform_admin", "cloud_ops", "dev_team",
]

DEFAULT_USERNAMES = ["admin", "root", "cisco", "guest", "test", "operator", "manager"]

# Realistic SNMP communities
SNMP_COMMUNITIES = [
    "corp-monitor", "network-ops", "security-team", "datacenter",
    "server-mgmt", "fw-monitor", "switch-admin", "router-ops",
    "netwatch", "infrastructure", "platform-team", "cloud-monitor",
]

DEFAULT_COMMUNITIES = ["public", "private", "community", "test", "default"]


def rand_ip():
    return f"{random.randint(1, 254)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"


def rand_subnet():
    return random.choice(SUBNETS).format(random.randint(0, 255), random.randint(0, 255))


def rand_hostname(vendor):
    pattern = random.choice(HOSTNAMES[vendor])
    n_braces = pattern.count("{}")
    return pattern.format(*[random.randint(1, 99) for _ in range(n_braces)])


def rand_interface(vendor):
    pattern = random.choice(INTERFACES[vendor])
    n_braces = pattern.count("{}")
    return pattern.format(*[random.randint(0, 24) for _ in range(n_braces)])


def rand_username():
    return random.choice(USERNAMES)


def rand_snmp_community():
    return random.choice(SNMP_COMMUNITIES)


# ============================================================================
# Cisco IOS Example Generation
# ============================================================================

def generate_cisco_example(rule_id: str, compliant: bool) -> str:
    hostname = rand_hostname("cisco")
    lines = []

    lines.append(f"! {hostname} Configuration")
    lines.append(f"! Generated: 2024-01-{random.randint(1, 28):02d}")
    lines.append("!")
    lines.append(f"hostname {hostname}")
    lines.append("version 15.7")
    lines.append("service timestamps debug datetime msec")
    lines.append("service timestamps log datetime msec")
    lines.append("service password-encryption")
    lines.append("")

    if rule_id == "CIS-1.1":
        if compliant:
            username = rand_username()
            privilege = random.choice([1, 5, 15])
            lines.append(f"username {username} privilege {privilege} secret 5 $1${random.randint(1000, 9999)}$hashvalue")
            if random.random() > 0.5:
                u2 = rand_username()
                lines.append(f"username {u2} privilege 1 secret 5 $1${random.randint(1000, 9999)}$hashvalue2")
        else:
            default_user = random.choice(DEFAULT_USERNAMES)
            lines.append(f"username {default_user} privilege 15 secret 5 $1${random.randint(1000, 9999)}$hashvalue")
            if random.random() > 0.6:
                lines.append(f"username {random.choice(DEFAULT_USERNAMES)} privilege 1 password 0 weakpass")

    elif rule_id == "CIS-1.2":
        if compliant:
            lines.append("username netadmin privilege 15 secret 5 $1$secure123$hashvalue")
            lines.append("enable secret 5 $1$enablehash$enablevalue")
        else:
            lines.append("username operator privilege 1 password 0 cleartext123")
            lines.append("enable password 0 weakenable")

    elif rule_id == "CIS-2.1":
        if compliant:
            lines.append(f"logging host {rand_ip()}")
            lines.append("logging trap informational")
        else:
            lines.append(f"! logging host {rand_ip()}")
            lines.append("logging trap debugging")

    elif rule_id == "CIS-2.2":
        if compliant:
            lines.append(f"ntp server {rand_ip()}")
            if random.random() > 0.5:
                lines.append(f"ntp server {rand_ip()}")
        else:
            lines.append(f"! ntp server {rand_ip()}")

    elif rule_id == "CIS-3.1":
        if compliant:
            community = rand_snmp_community()
            lines.append(f"snmp-server community {community} RO")
        else:
            lines.append(f"snmp-server community {random.choice(DEFAULT_COMMUNITIES)} RO")

    elif rule_id == "CIS-4.1":
        return None

    if random.random() > 0.3:
        for _ in range(random.randint(1, 3)):
            intf = rand_interface("cisco")
            lines.append(f"interface {intf}")
            lines.append(f" description {random.choice(['WAN', 'LAN', 'DMZ', 'Management', 'Uplink'])} Interface")
            lines.append(f" ip address {rand_ip()} {random.choice(['255.255.255.0', '255.255.255.252', '255.255.252.0'])}")
            if random.random() > 0.3:
                lines.append(" no shutdown")
            lines.append("!")

    if random.random() > 0.5:
        lines.append("router ospf 1")
        lines.append(f" network {rand_subnet()}/24 area 0")
        lines.append("!")

    return "\n".join(lines)


# ============================================================================
# Juniper Junos Example Generation
# ============================================================================

def generate_juniper_example(rule_id: str, compliant: bool) -> str:
    hostname = rand_hostname("juniper")
    lines = []

    lines.append(f"# {hostname} Configuration")
    lines.append(f"# Date: 2024-01-{random.randint(1, 28):02d}")
    lines.append("")
    lines.append("system {")
    lines.append(f"    host-name {hostname};")
    lines.append(f"    domain-name example.corp.net;")

    if rule_id == "CIS-1.1":
        if compliant:
            username = rand_username()
            uid = random.randint(2000, 65000)
            class_type = random.choice(["super-user", "read-only", "operator", "network-admin"])
            lines.append("    login {")
            lines.append(f"        user {username} {{")
            lines.append(f"            uid {uid};")
            lines.append(f"            class {class_type};")
            lines.append('            authentication {')
            lines.append(f'                encrypted-password "$1${random.randint(1000, 9999)}$hashvalue";')
            lines.append("            }")
            lines.append("        }")
            lines.append("    }")
        else:
            default_user = random.choice(DEFAULT_USERNAMES)
            lines.append("    login {")
            lines.append(f"        user {default_user} {{")
            lines.append(f"            uid {random.randint(1000, 2000)};")
            lines.append("            class super-user;")
            lines.append('            authentication {')
            lines.append(f'                encrypted-password "$1${random.randint(1000, 9999)}$hashvalue";')
            lines.append("            }")
            lines.append("        }")
            lines.append("    }")

    elif rule_id == "CIS-1.2":
        if compliant:
            lines.append("    root-authentication {")
            lines.append(f'        encrypted-password "$1${random.randint(1000, 9999)}$hashvalue";')
            lines.append("    }")
        else:
            lines.append("    root-authentication {")
            lines.append(f'        password "{random.choice(["admin123", "password", "weakpass"])}";')
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
            lines.append("            any any;")
            lines.append("        }")
            lines.append("    }")

    elif rule_id == "CIS-2.2":
        if compliant:
            lines.append("    ntp {")
            lines.append(f'        server {rand_ip()};')
            if random.random() > 0.5:
                lines.append(f'        server {rand_ip()};')
            lines.append("    }")
        else:
            lines.append("    ntp {")
            lines.append(f'        #server {rand_ip()};')
            lines.append("    }")

    elif rule_id == "CIS-3.1":
        if compliant:
            community = rand_snmp_community()
            lines.append("    snmp {")
            lines.append(f'        community {community} {{')
            lines.append("            authorization read-write;")
            lines.append("        }")
            lines.append("    }")
        else:
            lines.append("    snmp {")
            lines.append(f'        community {random.choice(DEFAULT_COMMUNITIES)} {{')
            lines.append("            authorization read-only;")
            lines.append("        }")
            lines.append("    }")

    elif rule_id == "CIS-4.1":
        if compliant:
            zone_name = random.choice(["trust", "untrust", "dmz", "management", "guest"])
            intf = rand_interface("juniper")
            lines.append("    security {")
            lines.append("        zones {")
            lines.append(f"            security-zone {zone_name} {{")
            lines.append("                interfaces {")
            lines.append(f"                    {intf};")
            lines.append("                }")
            lines.append("            }")
            lines.append("        }")
            lines.append("    }")
        else:
            lines.append("    security {")
            lines.append("        zones {")
            lines.append("            #security-zone untrusted {")
            lines.append("                interfaces { }")
            lines.append("            }")
            lines.append("        }")
            lines.append("    }")

    lines.append("}")
    return "\n".join(lines)


# ============================================================================
# Palo Alto PAN-OS Example Generation
# ============================================================================

def generate_paloalto_example(rule_id: str, compliant: bool) -> str:
    hostname = rand_hostname("paloalto")
    lines = []

    lines.append(f"<!-- {hostname} Configuration -->")
    lines.append(f"<!-- Date: 2024-01-{random.randint(1, 28):02d} -->")
    lines.append("")
    lines.append("<device-config>")
    lines.append("  <system>")
    lines.append(f"    <hostname>{hostname}</hostname>")
    lines.append(f"    <domain>example.com</domain>")

    if rule_id == "CIS-1.1":
        if compliant:
            username = rand_username()
            lines.append("  </system>")
            lines.append("  <mgt-config>")
            lines.append("    <users>")
            lines.append(f'      <entry name="{username}">')
            lines.append(f'        <password-hash>$1${random.randint(1000, 9999)}$hashvalue</password-hash>')
            lines.append("      </entry>")
            lines.append("    </users>")
            lines.append("  </mgt-config>")
        else:
            lines.append("  </system>")
            lines.append("  <mgt-config>")
            lines.append("    <users>")
            default_user = random.choice(DEFAULT_USERNAMES)
            lines.append(f'      <entry name="{default_user}">')
            lines.append(f'        <password-hash>$1${random.randint(1000, 9999)}$hashvalue</password-hash>')
            lines.append("      </entry>")
            lines.append("    </users>")
            lines.append("  </mgt-config>")

    elif rule_id == "CIS-1.2":
        if compliant:
            lines.append("  </system>")
            lines.append("  <mgt-config>")
            lines.append("    <users>")
            lines.append('      <entry name="admin">')
            lines.append(f'        <password-hash>$1${random.randint(1000, 9999)}$encryptedhash</password-hash>')
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
            lines.append(f'        <server>')
            lines.append(f'          <entry name="syslog-{random.randint(1, 100)}">')
            lines.append(f'            <ip-address>{rand_ip()}</ip-address>')
            lines.append("          </entry>")
            lines.append("        </server>")
            lines.append("      </entry>")
            lines.append("    </syslog>")
            lines.append("  </log-settings>")
        else:
            lines.append("  </system>")
            lines.append("  <log-settings>")
            lines.append("    <syslog>")
            lines.append(f'      <!-- <entry name="primary"> -->')
            lines.append("    </syslog>")
            lines.append("  </log-settings>")

    elif rule_id == "CIS-2.2":
        if compliant:
            lines.append(f'    <ntp-servers>')
            lines.append(f'      <primary>{rand_ip()}</primary>')
            if random.random() > 0.5:
                lines.append(f'      <secondary>{rand_ip()}</secondary>')
            lines.append("    </ntp-servers>")
        else:
            lines.append(f'    <ntp-servers>')
            lines.append(f'      <!-- <primary>{rand_ip()}</primary> -->')
            lines.append("    </ntp-servers>")

    elif rule_id == "CIS-3.1":
        if compliant:
            community = rand_snmp_community()
            lines.append("  </system>")
            lines.append("  <snmp>")
            lines.append("    <community>")
            lines.append(f'      <entry name="{community}">')
            lines.append("        <version>v3</version>")
            lines.append("      </entry>")
            lines.append("    </community>")
            lines.append("  </snmp>")
        else:
            lines.append("  </system>")
            lines.append("  <snmp>")
            lines.append("    <community>")
            lines.append(f'      <entry name="{random.choice(DEFAULT_COMMUNITIES)}">')
            lines.append('        <version>v2c</version>')
            lines.append("      </entry>")
            lines.append("    </community>")
            lines.append("  </snmp>")

    elif rule_id == "CIS-4.1":
        if compliant:
            zone_name = random.choice(["trust", "untrust", "dmz", "external", "internal"])
            intf = rand_interface("paloalto")
            lines.append("  </system>")
            lines.append("  <network>")
            lines.append("    <zone>")
            lines.append(f'      <entry name="{zone_name}">')
            lines.append("        <network>")
            lines.append(f'          <member>{intf}</member>')
            lines.append("        </network>")
            lines.append("      </entry>")
            lines.append("    </zone>")
            lines.append("  </network>")
        else:
            lines.append("  </system>")
            lines.append("  <network>")
            lines.append("    <zone>")
            lines.append("      <!-- <entry name='untrusted'> -->")
            lines.append("    </zone>")
            lines.append("  </network>")

    lines.append("</device-config>")
    return "\n".join(lines)


# ============================================================================
# Dataset Generation
# ============================================================================

def generate_dataset_v2() -> List[Dict[str, Any]]:
    examples = []
    policies = POLICY_TEMPLATES

    rules_vendors = [
        ("CIS-1.1", "cisco"), ("CIS-1.1", "juniper"), ("CIS-1.1", "paloalto"),
        ("CIS-1.2", "cisco"), ("CIS-1.2", "juniper"), ("CIS-1.2", "paloalto"),
        ("CIS-2.1", "cisco"), ("CIS-2.1", "juniper"), ("CIS-2.1", "paloalto"),
        ("CIS-2.2", "cisco"), ("CIS-2.2", "juniper"), ("CIS-2.2", "paloalto"),
        ("CIS-3.1", "cisco"), ("CIS-3.1", "juniper"), ("CIS-3.1", "paloalto"),
        ("CIS-4.1", "juniper"), ("CIS-4.1", "paloalto"),
    ]

    target_per_combo = 35

    for rule_id, vendor in rules_vendors:
        policy = random.choice(policies[rule_id])

        for _ in range(target_per_combo // 2):
            gen_fn = {"cisco": generate_cisco_example,
                      "juniper": generate_juniper_example,
                      "paloalto": generate_paloalto_example}[vendor]
            config = gen_fn(rule_id, True)
            if config:
                examples.append({
                    "rule_id": rule_id,
                    "policy": policy,
                    "security_intent": f"Verify {rule_id.lower()} compliance",
                    "config": config.strip(),
                    "vendor": vendor,
                    "label": "1",
                    "source": "synthetic_v2",
                    "reason": "compliant_" + rule_id.lower().replace("-", "_"),
                    "difficulty": random.choice(["easy", "medium", "hard"]),
                })

        for _ in range(target_per_combo // 2):
            gen_fn = {"cisco": generate_cisco_example,
                      "juniper": generate_juniper_example,
                      "paloalto": generate_paloalto_example}[vendor]
            config = gen_fn(rule_id, False)
            if config:
                examples.append({
                    "rule_id": rule_id,
                    "policy": policy,
                    "security_intent": f"Verify {rule_id.lower()} compliance",
                    "config": config.strip(),
                    "vendor": vendor,
                    "label": "0",
                    "source": "synthetic_v2",
                    "reason": "non_compliant_" + rule_id.lower().replace("-", "_"),
                    "difficulty": random.choice(["easy", "medium", "hard"]),
                })

    return examples


def split_dataset(examples: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    random.shuffle(examples)
    n = len(examples)
    n_train = int(n * TRAIN_RATIO)
    n_val = int(n * VAL_RATIO)

    return {
        "train": examples[:n_train],
        "validation": examples[n_train:n_train + n_val],
        "test": examples[n_train + n_val:],
    }


def write_csv(data: List[Dict[str, Any]], filepath: Path):
    if not data:
        return
    fieldnames = ["rule_id", "policy", "security_intent", "config", "vendor", "label", "source", "reason", "difficulty"]
    with open(filepath, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(data)


def main():
    print("=" * 80)
    print("DATASET V2 GENERATION")
    print("=" * 80)

    print("\nGenerating synthetic examples...")
    examples = generate_dataset_v2()
    print(f"Generated {len(examples)} total examples")

    print("\nSplitting dataset...")
    splits = split_dataset(examples)

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    write_csv(splits["train"], OUTPUT_DIR / "train.csv")
    write_csv(splits["validation"], OUTPUT_DIR / "validation.csv")
    write_csv(splits["test"], OUTPUT_DIR / "test.csv")

    print(f"\nTrain: {len(splits['train'])} examples")
    print(f"Validation: {len(splits['validation'])} examples")
    print(f"Test: {len(splits['test'])} examples")

    print("\n" + "=" * 80)
    print("DATASET STATISTICS")
    print("=" * 80)

    compliant = sum(1 for e in examples if e['label'] == '1')
    non_compliant = sum(1 for e in examples if e['label'] == '0')
    print(f"\nOverall:")
    print(f"  Total: {len(examples)}")
    print(f"  Compliant: {compliant} ({compliant/len(examples)*100:.1f}%)")
    print(f"  Non-compliant: {non_compliant} ({non_compliant/len(examples)*100:.1f}%)")

    vendor_counts = defaultdict(int)
    for e in examples:
        vendor_counts[e['vendor']] += 1

    print(f"\nBy vendor:")
    for vendor in ['cisco', 'juniper', 'paloalto']:
        count = vendor_counts.get(vendor, 0)
        print(f"  {vendor}: {count}")

    rule_counts = defaultdict(int)
    for e in examples:
        rule_counts[e['rule_id']] += 1

    print(f"\nBy rule:")
    for rule in sorted(rule_counts.keys()):
        print(f"  {rule}: {rule_counts[rule]}")

    print(f"\nBy split:")
    for split_name, split_data in splits.items():
        comp = sum(1 for e in split_data if e['label'] == '1')
        non_comp = sum(1 for e in split_data if e['label'] == '0')
        print(f"  {split_name}: {len(split_data)} (compliant={comp}, non_compliant={non_comp})")

    print(f"\nDataset saved to: {OUTPUT_DIR}")
    print("=" * 80)


if __name__ == "__main__":
    main()
