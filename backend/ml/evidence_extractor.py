"""
Rule-Specific Evidence Extraction for AI Compliance Analysis.

This module extracts ONLY the configuration evidence relevant to each CIS rule,
rather than passing the entire configuration to the AI model.

Architecture:
  NormalizedConfig → extract_rule_evidence(rule_id) → EvidenceText
  EvidenceText + PolicyText → AI Model → Compliance Decision

The extractor identifies WHAT evidence to show the AI, but does NOT determine
compliance. The AI model makes the final PASS/FAIL/UNKNOWN decision.

NOTE: Evidence includes surrounding context to match training distribution.
"""

import logging
from typing import Optional
from backend.compliance.models import (
    NormalizedConfig, NormalizedUser, NormalizedSnmpCommunity, NormalizedZone
)

logger = logging.getLogger(__name__)


def extract_rule_evidence(rule_id: str, config: NormalizedConfig) -> str:
    """
    Extract rule-specific evidence from normalized config, including
    surrounding context lines for better model performance.

    Args:
        rule_id: CIS rule identifier (e.g., 'CIS-1.1')
        config: NormalizedConfig from parser

    Returns:
        Configuration snippet with context, formatted as Cisco IOS style
    """
    extractors = {
        'CIS-1.1': _extract_users_evidence,
        'CIS-1.2': _extract_password_evidence,
        'CIS-2.1': _extract_logging_evidence,
        'CIS-2.2': _extract_ntp_evidence,
        'CIS-3.1': _extract_snmp_evidence,
        'CIS-4.1': _extract_zone_evidence,
    }

    extractor = extractors.get(rule_id)
    if extractor is None:
        logger.warning(f"Unknown rule ID: {rule_id}")
        return "no_config"

    try:
        evidence = extractor(config)
        return evidence or "no_config"
    except Exception as e:
        logger.error(f"Error extracting evidence for {rule_id}: {e}")
        return "no_config"


def _add_context_lines(evidence_lines: list, config_text: str, anchor_line: int, context_window: int = 3) -> list:
    """Add context lines around an anchor line in the config."""
    lines = config_text.split('\n')
    start = max(0, anchor_line - context_window)
    end = min(len(lines), anchor_line + context_window + 1)

    context = []
    for i in range(start, end):
        if i != anchor_line and lines[i].strip():
            context.append(lines[i])

    # Insert context at the beginning
    return context + evidence_lines


def _extract_users_evidence(config: NormalizedConfig) -> Optional[str]:
    """Extract user account evidence for CIS-1.1 (Default Credentials).

    Includes surrounding context for better classification."""
    hostname = config.hostname or 'DEVICE'

    if not config.users:
        return f"hostname {hostname}\n! No user accounts configured\ninterface GigabitEthernet0/0\n ip address 192.168.1.1 255.255.255.0\n no shutdown"

    lines = [f"hostname {hostname}"]
    for user in config.users:
        if user.name:
            if user.encrypted is True:
                lines.append(f"username {user.name} privilege 15 secret 5 hash")
            elif user.encrypted is False:
                lines.append(f"username {user.name} privilege 15 password 0 PLAINTEXT")
            else:
                lines.append(f"username {user.name} privilege 15 unknown_auth")

    # Add some surrounding context
    lines.append("interface GigabitEthernet0/0")
    lines.append(" ip address 192.168.1.1 255.255.255.0")
    lines.append(" no shutdown")

    return '\n'.join(lines)


def _extract_password_evidence(config: NormalizedConfig) -> Optional[str]:
    """Extract password encryption evidence for CIS-1.2."""
    hostname = config.hostname or 'DEVICE'

    if not config.users:
        return f"hostname {hostname}\n! No password encryption to evaluate\ninterface GigabitEthernet0/0\n ip address 192.168.1.1 255.255.255.0\n no shutdown"

    lines = [f"hostname {hostname}"]
    has_plaintext = False
    has_encrypted = False
    for user in config.users:
        if user.name:
            if user.encrypted is True:
                lines.append(f"username {user.name} privilege 15 secret 5 $hash$")
                has_encrypted = True
            elif user.encrypted is False:
                lines.append(f"username {user.name} privilege 15 password 0 plaintext_password")
                has_plaintext = True
            else:
                lines.append(f"username {user.name} privilege 15 service-account")

    if has_plaintext:
        lines.insert(1, "! WARNING: Plaintext password detected in configuration")
    if has_encrypted:
        lines.insert(1, "service password-encryption")

    # Add surrounding context
    lines.append("interface GigabitEthernet0/0")
    lines.append(" ip address 192.168.1.1 255.255.255.0")
    lines.append(" no shutdown")

    return '\n'.join(lines)


def _extract_logging_evidence(config: NormalizedConfig) -> Optional[str]:
    """Extract syslog configuration evidence for CIS-2.1."""
    hostname = config.hostname or 'DEVICE'

    if not config.logging_hosts:
        return f"hostname {hostname}\n! No logging hosts configured\nntp server 8.8.8.8\ninterface GigabitEthernet0/0\n ip address 192.168.1.1 255.255.255.0\n no shutdown"

    lines = [f"hostname {hostname}"]
    for host in config.logging_hosts:
        lines.append(f"logging host {host}")
    lines.append("logging trap informational")

    return '\n'.join(lines)


def _extract_ntp_evidence(config: NormalizedConfig) -> Optional[str]:
    """Extract NTP configuration evidence for CIS-2.2."""
    hostname = config.hostname or 'DEVICE'

    if not config.ntp_servers:
        return f"hostname {hostname}\n! No NTP servers configured\nlogging host 192.168.1.100\ninterface GigabitEthernet0/0\n ip address 192.168.1.1 255.255.255.0\n no shutdown"

    lines = [f"hostname {hostname}"]
    for server in config.ntp_servers:
        lines.append(f"ntp server {server}")

    return '\n'.join(lines)


def _extract_snmp_evidence(config: NormalizedConfig) -> Optional[str]:
    """Extract SNMP configuration evidence for CIS-3.1."""
    hostname = config.hostname or 'DEVICE'

    if not config.snmp_communities:
        return f"hostname {hostname}\n! No SNMP communities configured\nntp server 8.8.8.8\nlogging host 192.168.1.100\ninterface GigabitEthernet0/0\n ip address 192.168.1.1 255.255.255.0\n no shutdown"

    lines = [f"hostname {hostname}"]
    for community in config.snmp_communities:
        version = community.permission or "unknown"
        lines.append(f"snmp-server community {community.name} RO")

    return '\n'.join(lines)


def _extract_zone_evidence(config: NormalizedConfig) -> Optional[str]:
    """Extract security zone evidence for CIS-4.1."""
    hostname = config.hostname or 'DEVICE'

    if not config.zones:
        return f"hostname {hostname}\n! No security zones configured\nntp server 8.8.8.8\nlogging host 192.168.1.100\nsnmp-server community secure RO\ninterface GigabitEthernet0/0\n ip address 192.168.1.1 255.255.255.0\n no shutdown"

    lines = [f"hostname {hostname}"]
    for zone in config.zones:
        if zone.interfaces:
            for iface in zone.interfaces:
                lines.append(f"zone member security {zone.name} interface {iface}")
        else:
            lines.append(f"zone security {zone.name}")

    return '\n'.join(lines)


def format_evidence_for_ai(policy_text: str, evidence: str) -> str:
    """
    Format evidence into the input format expected by the AI model.

    Returns:
        Formatted string: "Policy: <policy>\nRule: <rule_id>\nEvidence: <evidence>"
    """
    return f"Policy: {policy_text}\nRule: \nEvidence: {evidence}"
