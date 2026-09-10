#!/usr/bin/env python3
"""
Generate real-world evaluation corpus from config files.
Uses deterministic rules engine to establish ground truth labels.
"""

import sys
import os
import csv
from pathlib import Path
from typing import List, Dict, Any, Optional

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from backend.parser.cisco_ios import parse_cisco_ios
from backend.parser.juniper_junos import parse_juniper_junos
from backend.parser.paloalto_panos import parse_paloalto_panos, detect_paloalto_format
from backend.compliance.models import NormalizedConfig, NormalizedUser, NormalizedSnmpCommunity, NormalizedZone
from backend.compliance.rules_engine import evaluate_compliance, RULE_DETAILS

POLICY_TEXTS = {
    "CIS-1.1": "Administrative accounts must not use vendor-default credentials",
    "CIS-1.2": "All user passwords must be encrypted using secure hashing algorithms",
    "CIS-2.1": "Network devices must forward security events to approved centralized logging",
    "CIS-2.2": "Network infrastructure must synchronize clock with approved time sources",
    "CIS-3.1": "SNMP must use secure community names and modern protocol versions",
    "CIS-4.1": "Security zones must be configured to enforce traffic segmentation",
}


def detect_vendor(content: str) -> Optional[str]:
    """Detect vendor from config content with specific pattern matching."""
    stripped = content.strip()

    # Check Palo Alto first (XML or set format)
    if stripped.startswith('<?xml') or stripped.startswith('<config'):
        return "paloalto"
    if '<device-config>' in content or '<mgt-config>' in content:
        return "paloalto"

    # Check Juniper (hierarchical brace format with specific keywords)
    if 'system {' in content and 'host-name' in content:
        return "juniper"
    if 'security {' in content and 'zones {' in content:
        return "juniper"

    # Check Cisco IOS (line-based with ! comments)
    if '!' in content and ('hostname' in content or 'interface' in content):
        return "cisco"
    if 'version' in content and 'service timestamps' in content:
        return "cisco"

    return None


def parse_config(content: str, vendor: str) -> Optional[Dict[str, Any]]:
    """Parse config based on detected vendor."""
    try:
        if vendor == "cisco":
            return parse_cisco_ios(content)
        elif vendor == "juniper":
            return parse_juniper_junos(content)
        elif vendor == "paloalto":
            return parse_paloalto_panos(content)
    except Exception as e:
        print(f"    Parse error: {e}")
        return None
    return None


def normalize_config(parsed: Dict[str, Any], vendor: str) -> Optional[NormalizedConfig]:
    """Convert parsed config to NormalizedConfig."""
    try:
        users = []
        for u in parsed.get("users", []):
            if isinstance(u, dict):
                users.append(NormalizedUser(
                    name=u.get("username"),
                    privilege_or_class=u.get("privilege_level"),
                    encrypted=u.get("encrypted"),
                ))
            else:
                users.append(NormalizedUser(name=str(u)))

        snmp_communities = []
        for s in parsed.get("snmp_communities", []):
            if isinstance(s, dict):
                snmp_communities.append(NormalizedSnmpCommunity(
                    community_name=s.get("community_name"),
                    version=s.get("version"),
                    access_level=s.get("access_level"),
                ))

        zones = []
        for z in parsed.get("zones", []):
            if isinstance(z, dict):
                zones.append(NormalizedZone(
                    name=z.get("name"),
                    interfaces=z.get("interfaces", []),
                ))

        norm = NormalizedConfig(
            vendor=vendor,
            format=parsed.get("format", "unknown"),
            hostname=parsed.get("hostname"),
            domain=parsed.get("domain"),
            interfaces=parsed.get("interfaces", []),
            users=users,
            logging_hosts=parsed.get("logging_hosts", []),
            ntp_servers=parsed.get("ntp_servers", []),
            snmp_communities=snmp_communities,
            zones=zones,
            security_rules=parsed.get("security_rules", []),
            routes=parsed.get("routes", []),
            unsupported_fields=parsed.get("unsupported_fields", []),
            raw=parsed,
        )
        return norm
    except Exception as e:
        print(f"  ERROR normalizing: {e}")
        return None


def evaluate_and_extract_cases(
    filepath: str,
    content: str,
    vendor: str,
    parsed: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """Evaluate config against all rules and extract evaluation cases."""
    norm = normalize_config(parsed, vendor)
    if not norm:
        return []

    findings = evaluate_compliance(norm)
    cases = []

    for finding in findings:
        # Only include cases with definite labels (PASS or FAIL)
        if finding.status not in ["PASS", "FAIL"]:
            continue

        # Get relevant config section
        config_context = extract_relevant_context(content, finding.rule_id, vendor)

        cases.append({
            "source_config": filepath,
            "vendor": vendor,
            "rule_id": finding.rule_id,
            "policy": POLICY_TEXTS.get(finding.rule_id, ""),
            "configuration_context": config_context[:500] if config_context else "",
            "ground_truth_label": "compliant" if finding.status == "PASS" else "non_compliant",
            "evidence": finding.evidence[:300] if finding.evidence else "",
            "reasoning": finding.remediation[:300] if finding.remediation else "",
            "supported_by_rules_engine": True,
            "human_verified": False,
            "notes": f"Automated label from rules engine. Severity: {finding.severity}",
        })

    return cases


def extract_relevant_context(
    content: str,
    rule_id: str,
    vendor: str,
) -> str:
    """Extract relevant configuration section for a rule."""
    lines = content.split("\n")
    context_lines = []
    in_relevant_section = False
    line_count = 0

    for line in lines:
        stripped = line.strip()

        # Collect context based on rule and vendor patterns
        if rule_id == "CIS-1.1":
            if ("username" in stripped and "privilege" in stripped) or \
               ("user " in stripped and "uid" in stripped) or \
               ('<entry name="' in stripped):
                in_relevant_section = True
        elif rule_id == "CIS-1.2":
            if ("secret" in stripped and "password" not in stripped) or \
               "encrypted-password" in stripped or \
               "password-hash" in stripped or \
               "password 0" in stripped or \
               "<password>" in stripped:
                in_relevant_section = True
        elif rule_id == "CIS-2.1":
            if ("logging host" in stripped) or \
               ("host" in stripped and "syslog" in content.lower()) or \
               "<ip-address>" in stripped:
                in_relevant_section = True
        elif rule_id == "CIS-2.2":
            if "ntp server" in stripped or "ntp-servers" in content.lower():
                in_relevant_section = True
        elif rule_id == "CIS-3.1":
            if "snmp-server community" in stripped or "community" in stripped:
                in_relevant_section = True
        elif rule_id == "CIS-4.1":
            if "zone" in stripped.lower() or "security-zone" in stripped:
                in_relevant_section = True

        if in_relevant_section:
            context_lines.append(line)
            line_count += 1
            if line_count > 15:
                break

    return "\n".join(context_lines) if context_lines else content[:300]


def main():
    """Main generation pipeline."""
    print("="*80)
    print("REAL-WORLD EVALUATION CORPUS GENERATOR")
    print("="*80)

    config_dir = Path(__file__).parent.parent.parent / "real_configs"
    output_dir = Path(__file__).parent

    all_cases = []
    skipped_files = []
    files_by_vendor = {"cisco": [], "juniper": [], "paloalto": [], "unknown": []}

    print(f"\nScanning: {config_dir}")

    for root, dirs, files in os.walk(config_dir):
        for filename in sorted(files):
            filepath = Path(root) / filename

            # Skip non-config files
            if filepath.suffix not in ['.txt', '.raw', '.xml']:
                continue
            if filepath.stat().st_size < 100:
                skipped_files.append((filepath.name, 'too_small'))
                continue

            # Read content
            try:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
            except Exception as e:
                skipped_files.append((filepath.name, f'read_error: {e}'))
                continue

            # Skip 404 errors and placeholders
            if '404' in content and len(content.strip()) < 100:
                skipped_files.append((filepath.name, '404_error'))
                continue
            if content.strip() in ['404: Not Found', 'Not Found']:
                skipped_files.append((filepath.name, 'empty_placeholder'))
                continue

            display_name = filepath.name

            # Detect vendor
            vendor = detect_vendor(content)
            if not vendor:
                skipped_files.append((display_name, 'unknown_vendor'))
                files_by_vendor["unknown"].append(display_name)
                continue

            files_by_vendor[vendor].append(display_name)

            # Parse and evaluate
            print(f"\nProcessing: {display_name} (vendor={vendor}, {len(content)} chars)")

            try:
                parsed = parse_config(content, vendor)
                if not parsed:
                    print(f"  SKIP: Parse failed")
                    skipped_files.append((display_name, 'parse_failed'))
                    continue

                hostname = parsed.get('hostname', 'unknown')
                print(f"  Hostname: {hostname}")

                cases = evaluate_and_extract_cases(
                    display_name,
                    content,
                    vendor,
                    parsed,
                )

                if cases:
                    all_cases.extend(cases)
                    print(f"  Generated {len(cases)} evaluation cases")
                    for case in cases:
                        print(f"    {case['rule_id']}: {case['ground_truth_label']}")
                else:
                    print(f"  SKIP: No findings for evaluable rules")
                    skipped_files.append((display_name, 'no_findings'))

            except Exception as e:
                print(f"  ERROR: {e}")
                import traceback
                traceback.print_exc()
                skipped_files.append((display_name, f'error: {e}'))

    # Write CSV
    csv_path = output_dir / "real_world_cases.csv"
    fieldnames = [
        'source_config', 'vendor', 'rule_id', 'policy', 'configuration_context',
        'ground_truth_label', 'evidence', 'reasoning', 'supported_by_rules_engine',
        'human_verified', 'notes'
    ]

    with open(csv_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(all_cases)

    print(f"\n{'='*80}")
    print(f"RESULTS SUMMARY")
    print(f"{'='*80}")
    total_files = len(files_by_vendor['cisco']) + len(files_by_vendor['juniper']) + len(files_by_vendor['paloalto']) + len(files_by_vendor['unknown'])
    print(f"Total source files scanned: {total_files}")
    print(f"  Cisco IOS: {len(files_by_vendor['cisco'])}")
    print(f"  Juniper Junos: {len(files_by_vendor['juniper'])}")
    print(f"  Palo Alto PAN-OS: {len(files_by_vendor['paloalto'])}")
    print(f"  Unknown: {len(files_by_vendor['unknown'])}")
    print(f"\nTotal evaluation cases generated: {len(all_cases)}")
    print(f"Cases requiring human review: {sum(1 for c in all_cases if not c['supported_by_rules_engine'])}")

    # Stats by vendor
    print(f"\nCases by vendor:")
    for vendor in ['cisco', 'juniper', 'paloalto']:
        vendor_cases = [c for c in all_cases if c['vendor'] == vendor]
        compliant = sum(1 for c in vendor_cases if c['ground_truth_label'] == 'compliant')
        non_compliant = sum(1 for c in vendor_cases if c['ground_truth_label'] == 'non_compliant')
        print(f"  {vendor}: {len(vendor_cases)} (compliant={compliant}, non_compliant={non_compliant})")

    # Stats by rule
    print(f"\nCases by rule:")
    for rule in sorted(set(c['rule_id'] for c in all_cases)):
        rule_cases = [c for c in all_cases if c['rule_id'] == rule]
        compliant = sum(1 for c in rule_cases if c['ground_truth_label'] == 'compliant')
        non_compliant = sum(1 for c in rule_cases if c['ground_truth_label'] == 'non_compliant')
        print(f"  {rule}: {len(rule_cases)} (compliant={compliant}, non_compliant={non_compliant})")

    # Stats by label
    compliant_total = sum(1 for c in all_cases if c['ground_truth_label'] == 'compliant')
    non_compliant_total = sum(1 for c in all_cases if c['ground_truth_label'] == 'non_compliant')
    print(f"\nOverall label distribution:")
    print(f"  Compliant: {compliant_total}")
    print(f"  Non-compliant: {non_compliant_total}")

    # Write skipped files report
    if skipped_files:
        skipped_path = output_dir / "skipped_files.csv"
        with open(skipped_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['file', 'reason'])
            for file, reason in skipped_files:
                writer.writerow([file, reason])
        print(f"\nSkipped files report: {skipped_path}")

    print(f"\nEvaluation corpus saved to: {csv_path}")
    print("="*80)


if __name__ == "__main__":
    main()
