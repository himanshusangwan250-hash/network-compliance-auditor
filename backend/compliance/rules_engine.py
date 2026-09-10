"""
Rules Engine - ARCHIVED / LEGACY

This module is NO LONGER used for compliance decisions in the production system.

Current architecture:
  Config → Parser → Normalization → AI Compliance Analysis → Findings

The deterministic rules engine has been replaced by AI-only analysis
using V5 (primary) and V4 (fallback) models.

This module is preserved for reference and historical purposes only.
It may be removed in a future cleanup.

Rule definitions and policy text are still needed by the AI system
for model input, so they remain accessible via get_rule_details().
"""

from typing import List, Dict, Any
from dataclasses import dataclass
from backend.compliance.models import NormalizedConfig, NormalizedUser, NormalizedSnmpCommunity

# ============================================================================
# ComplianceFinding dataclass (preserved for backward compatibility)
# ============================================================================

@dataclass
class ComplianceFinding:
    rule_id: str
    title: str
    severity: str
    status: str
    evidence: str
    remediation: str


# ============================================================================
# Legacy compliance functions (NOT USED IN PRODUCTION)
# ============================================================================

def _field_supported(config: NormalizedConfig, field_name: str) -> bool:
    """Return True if the given normalized field is supported by the vendor's parser."""
    return field_name not in config.unsupported_fields


def _check_default_credentials(config: NormalizedConfig) -> List[ComplianceFinding]:
    """LEGACY: Rule CIS-1.1: Check for default usernames."""
    if not _field_supported(config, "users"):
        return [ComplianceFinding(
            rule_id='CIS-1.1',
            title='Avoid Default Credentials',
            severity='High',
            status='UNKNOWN',
            evidence='User account information is not available for this vendor format.',
            remediation='Manually verify that no default usernames are in use on this device.'
        )]

    default_users = ['admin', 'root', 'default', 'cisco', 'guest', 'test']
    found_defaults = [u for u in config.users if u.name and u.name.lower() in default_users]

    if found_defaults:
        names = ', '.join(u.name for u in found_defaults)
        return [ComplianceFinding(
            rule_id='CIS-1.1',
            title='Avoid Default Credentials',
            severity='High',
            status='FAIL',
            evidence=f'Default usernames found: {names}',
            remediation='Change all default usernames to unique accounts.'
        )]

    if not config.users:
        return [ComplianceFinding(
            rule_id='CIS-1.1',
            title='Avoid Default Credentials',
            severity='High',
            status='PASS',
            evidence='No user accounts are configured on this device.',
            remediation='Ensure no default credentials are in use.'
        )]

    return [ComplianceFinding(
        rule_id='CIS-1.1',
        title='Avoid Default Credentials',
        severity='High',
        status='PASS',
        evidence='No default usernames detected in configured accounts.',
        remediation='No action required.'
    )]


def _check_password_encryption(config: NormalizedConfig) -> List[ComplianceFinding]:
    """LEGACY: Rule CIS-1.2: Verify passwords are encrypted."""
    if not _field_supported(config, "users"):
        return [ComplianceFinding(
            rule_id='CIS-1.2',
            title='Password Encryption Required',
            severity='Medium',
            status='UNKNOWN',
            evidence='User account information is not available for this vendor format.',
            remediation='Manually verify that passwords are stored using strong hashing.'
        )]

    plain_password_users = [u for u in config.users if u.name and u.encrypted is False]
    unknown_encryption_users = [u for u in config.users if u.name and u.encrypted is None]

    if plain_password_users:
        names = ', '.join(u.name for u in plain_password_users)
        return [ComplianceFinding(
            rule_id='CIS-1.2',
            title='Password Encryption Required',
            severity='Medium',
            status='FAIL',
            evidence=f'Users with plain-text password storage: {names}',
            remediation='Enable password encryption service and re-enter passwords.'
        )]
    elif unknown_encryption_users:
        names = ', '.join(u.name for u in unknown_encryption_users)
        return [ComplianceFinding(
            rule_id='CIS-1.2',
            title='Password Encryption Required',
            severity='Medium',
            status='UNKNOWN',
            evidence=f'Password encryption status unknown for: {names}',
            remediation='Manually verify password encryption.'
        )]
    elif config.users:
        return [ComplianceFinding(
            rule_id='CIS-1.2',
            title='Password Encryption Required',
            severity='Medium',
            status='PASS',
            evidence='All configured users have encrypted passwords.',
            remediation='No action required.'
        )]
    else:
        return [ComplianceFinding(
            rule_id='CIS-1.2',
            title='Password Encryption Required',
            severity='Medium',
            status='UNKNOWN',
            evidence='No user accounts found to evaluate password encryption.',
            remediation='Configure user accounts with encrypted password storage.'
        )]


def _check_logging(config: NormalizedConfig) -> List[ComplianceFinding]:
    """LEGACY: Rule CIS-2.1: Verify logging is configured."""
    if not _field_supported(config, "logging_hosts"):
        return [ComplianceFinding(
            rule_id='CIS-2.1',
            title='Syslog Configuration Required',
            severity='Medium',
            status='UNKNOWN',
            evidence='Syslog/logging host information is not available for this vendor format.',
            remediation='Manually verify that remote logging is configured.'
        )]

    if config.logging_hosts:
        return [ComplianceFinding(
            rule_id='CIS-2.1',
            title='Syslog Configuration Required',
            severity='Medium',
            status='PASS',
            evidence=f'Logging hosts configured: {", ".join(config.logging_hosts)}',
            remediation='No action required.'
        )]
    return [ComplianceFinding(
        rule_id='CIS-2.1',
        title='Syslog Configuration Required',
        severity='Medium',
        status='FAIL',
        evidence='No syslog/logging hosts configured.',
        remediation='Configure remote syslog server for audit trail.'
    )]


def _check_ntp(config: NormalizedConfig) -> List[ComplianceFinding]:
    """LEGACY: Rule CIS-2.2: Verify NTP is configured."""
    if config.ntp_servers:
        return [ComplianceFinding(
            rule_id='CIS-2.2',
            title='NTP Configuration Required',
            severity='Low',
            status='PASS',
            evidence=f'NTP servers configured: {", ".join(config.ntp_servers)}',
            remediation='No action required.'
        )]
    return [ComplianceFinding(
        rule_id='CIS-2.2',
        title='NTP Configuration Required',
        severity='Low',
        status='FAIL',
        evidence='No NTP servers configured.',
        remediation='Configure NTP servers for accurate timestamp logging.'
    )]


def _check_snmp_version(config: NormalizedConfig) -> List[ComplianceFinding]:
    """LEGACY: Rule CIS-3.1: Verify SNMP security."""
    if not _field_supported(config, "snmp_communities"):
        return [ComplianceFinding(
            rule_id='CIS-3.1',
            title='Secure SNMP Configuration',
            severity='High',
            status='UNKNOWN',
            evidence='SNMP community information is not available for this vendor format.',
            remediation='Manually verify that SNMPv3 is used.'
        )]

    weak_snmp = [s for s in config.snmp_communities
                 if s.name and s.name.lower() in ('public', 'private')]
    if weak_snmp:
        names = ', '.join(s.name for s in weak_snmp)
        return [ComplianceFinding(
            rule_id='CIS-3.1',
            title='Secure SNMP Configuration',
            severity='High',
            status='FAIL',
            evidence=f'Weak/default SNMP communities found: {names}',
            remediation='Use SNMPv3 with authentication and encryption.'
        )]
    if config.snmp_communities:
        return [ComplianceFinding(
            rule_id='CIS-3.1',
            title='Secure SNMP Configuration',
            severity='High',
            status='PASS',
            evidence='No default SNMP communities detected.',
            remediation='No action required.'
        )]
    return [ComplianceFinding(
        rule_id='CIS-3.1',
        title='Secure SNMP Configuration',
        severity='High',
        status='UNKNOWN',
        evidence='No SNMP communities found; cannot determine SNMP security posture.',
        remediation='Verify SNMP version and community configuration manually.'
    )]


def _check_network_segmentation(config: NormalizedConfig) -> List[ComplianceFinding]:
    """LEGACY: Rule CIS-4.1: Verify network segmentation."""
    if not _field_supported(config, "zones"):
        return [ComplianceFinding(
            rule_id='CIS-4.1',
            title='Network Segmentation',
            severity='Medium',
            status='UNKNOWN',
            evidence='Security zone information is not available for this vendor format.',
            remediation='Manually verify traffic segmentation controls.'
        )]

    if config.zones:
        zone_names = ', '.join(z.name for z in config.zones)
        return [ComplianceFinding(
            rule_id='CIS-4.1',
            title='Network Segmentation',
            severity='Medium',
            status='PASS',
            evidence=f'Security zones configured: {zone_names}',
            remediation='Ensure zones follow least-privilege access.'
        )]

    if not _field_supported(config, "security_rules"):
        return [ComplianceFinding(
            rule_id='CIS-4.1',
            title='Network Segmentation',
            severity='Medium',
            status='UNKNOWN',
            evidence='Security zones not configured and security-rule information unavailable.',
            remediation='Configure security zones and verify inter-zone policies.'
        )]

    return [ComplianceFinding(
        rule_id='CIS-4.1',
        title='Network Segmentation',
        severity='Medium',
        status='FAIL',
        evidence='No security zones detected.',
        remediation='Implement security zones to segment network traffic.'
    )]


def evaluate_compliance(config: NormalizedConfig) -> List[ComplianceFinding]:
    """LEGACY: Evaluate all compliance rules against normalized config.

    NOTE: This function is NO LONGER CALLED in production.
    It is preserved for testing and historical reference.
    """
    all_findings = []
    all_findings.extend(_check_default_credentials(config))
    all_findings.extend(_check_password_encryption(config))
    all_findings.extend(_check_logging(config))
    all_findings.extend(_check_ntp(config))
    all_findings.extend(_check_snmp_version(config))
    all_findings.extend(_check_network_segmentation(config))
    return all_findings


def calculate_compliance_score(findings: List[ComplianceFinding]) -> Dict[str, Any]:
    """LEGACY: Calculate overall compliance score from findings.

    NOTE: This function is NO LONGER CALLED in production.
    Score calculation is now done in routes.py using AI results.
    """
    pass_count = sum(1 for f in findings if f.status == 'PASS')
    fail_count = sum(1 for f in findings if f.status == 'FAIL')
    unknown_count = sum(1 for f in findings if f.status == 'UNKNOWN')
    total = len(findings)

    if total == 0:
        return {"score": None, "summary": {"pass": 0, "fail": 0, "unknown": 0, "total": 0}}

    score = round((pass_count / total) * 100, 1)
    return {
        "score": score,
        "summary": {
            "pass": pass_count,
            "fail": fail_count,
            "unknown": unknown_count,
            "total": total,
        }
    }


def get_rule_ids() -> List[str]:
    """Return list of all rule IDs (still needed by AI system for policy text)."""
    return ['CIS-1.1', 'CIS-1.2', 'CIS-2.1', 'CIS-2.2', 'CIS-3.1', 'CIS-4.1']


RULE_DETAILS = {
    'CIS-1.1': {
        'rule_id': 'CIS-1.1',
        'title': 'Avoid Default Credentials',
        'severity': 'High',
        'description': 'Default usernames like admin, root, or default should not be used.',
        'remediation': 'Change all default usernames to unique accounts.',
    },
    'CIS-1.2': {
        'rule_id': 'CIS-1.2',
        'title': 'Password Encryption Required',
        'severity': 'Medium',
        'description': 'Passwords should be encrypted, not stored in plain text.',
        'remediation': 'Enable password encryption service and re-enter passwords.',
    },
    'CIS-2.1': {
        'rule_id': 'CIS-2.1',
        'title': 'Syslog Configuration Required',
        'severity': 'Medium',
        'description': 'Remote logging should be configured for audit trails.',
        'remediation': 'Configure remote syslog server.',
    },
    'CIS-2.2': {
        'rule_id': 'CIS-2.2',
        'title': 'NTP Configuration Required',
        'severity': 'Low',
        'description': 'NTP should be configured for accurate timestamps.',
        'remediation': 'Configure NTP servers.',
    },
    'CIS-3.1': {
        'rule_id': 'CIS-3.1',
        'title': 'Secure SNMP Configuration',
        'severity': 'High',
        'description': 'Default SNMP communities like public/private indicate weak security.',
        'remediation': 'Use SNMPv3 with authentication and encryption.',
    },
    'CIS-4.1': {
        'rule_id': 'CIS-4.1',
        'title': 'Network Segmentation',
        'severity': 'Medium',
        'description': 'Security zones should be configured to segment traffic.',
        'remediation': 'Implement security zones following least-privilege.',
    },
}


def get_rule_details(rule_id: str) -> Dict[str, Any]:
    """Return metadata for a rule ID (still needed by AI system)."""
    if rule_id in RULE_DETAILS:
        return RULE_DETAILS[rule_id]
    raise ValueError(f'Unknown rule ID: {rule_id}')
