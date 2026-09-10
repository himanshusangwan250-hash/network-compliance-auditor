"""
Tests for rule-specific evidence extraction.

Verifies that each CIS rule receives only the relevant evidence,
not the entire configuration.
"""

import unittest
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))
os.environ['KMP_DUPLICATE_LIB_OK'] = 'TRUE'

from backend.ml.evidence_extractor import (
    extract_rule_evidence,
    format_evidence_for_ai,
)
from backend.compliance.models import NormalizedConfig, NormalizedUser, NormalizedZone, NormalizedSnmpCommunity
from backend.parser.vendor_detector import detect_vendor
from backend.parser.paloalto_panos import parse_paloalto_panos
from backend.compliance.models import normalize


def make_config(**kwargs):
    """Helper to create a NormalizedConfig with defaults."""
    return NormalizedConfig(
        vendor=kwargs.get('vendor', 'cisco'),
        format=kwargs.get('format', 'ios'),
        hostname=kwargs.get('hostname', 'RTR-1'),
        users=kwargs.get('users', []),
        logging_hosts=kwargs.get('logging_hosts', []),
        ntp_servers=kwargs.get('ntp_servers', []),
        snmp_communities=kwargs.get('snmp_communities', []),
        zones=kwargs.get('zones', []),
        security_rules=kwargs.get('security_rules', []),
        unsupported_fields=kwargs.get('unsupported_fields', []),
    )


class TestEvidenceExtractor(unittest.TestCase):
    """Test evidence extraction for each rule."""

    def test_cis11_extracts_users(self):
        """CIS-1.1 should extract user credential information."""
        config = make_config(
            users=[
                NormalizedUser(name='admin', privilege_or_class='15', encrypted=True),
                NormalizedUser(name='svc-monitor', privilege_or_class='15', encrypted=False),
            ],
        )
        evidence = extract_rule_evidence('CIS-1.1', config)
        self.assertIn('admin', evidence)
        self.assertIn('svc-monitor', evidence)
        self.assertIn('password 0', evidence)  # plaintext indicator

    def test_cis12_extracts_password_encryption(self):
        """CIS-1.2 should extract password encryption status."""
        config = make_config(
            users=[
                NormalizedUser(name='admin', privilege_or_class='15', encrypted=True),
                NormalizedUser(name='svc-monitor', privilege_or_class='15', encrypted=False),
            ],
        )
        evidence = extract_rule_evidence('CIS-1.2', config)
        self.assertIn('service password-encryption', evidence)
        self.assertIn('password 0', evidence)  # plaintext indicator

    def test_cis21_extracts_logging(self):
        """CIS-2.1 should extract syslog hosts."""
        config = make_config(
            logging_hosts=['192.168.1.100', '10.0.0.50'],
        )
        evidence = extract_rule_evidence('CIS-2.1', config)
        self.assertIn('192.168.1.100', evidence)
        self.assertIn('10.0.0.50', evidence)

    def test_cis22_extracts_ntp(self):
        """CIS-2.2 should extract NTP servers."""
        config = make_config(
            ntp_servers=['8.8.8.8', '8.8.4.4'],
        )
        evidence = extract_rule_evidence('CIS-2.2', config)
        self.assertIn('8.8.8.8', evidence)
        self.assertIn('8.8.4.4', evidence)

    def test_cis31_extracts_snmp(self):
        """CIS-3.1 should extract SNMP community info."""
        config = make_config(
            snmp_communities=[
                NormalizedSnmpCommunity(name='secure-monitoring', permission='v3'),
            ],
        )
        evidence = extract_rule_evidence('CIS-3.1', config)
        self.assertIn('secure-monitoring', evidence)
        self.assertIn('snmp-server', evidence)

    def test_cis41_extracts_zones(self):
        """CIS-4.1 should extract zone configuration."""
        config = make_config(
            zones=[
                NormalizedZone(name='trust', interfaces=['eth0']),
                NormalizedZone(name='untrust', interfaces=['eth1']),
            ],
        )
        evidence = extract_rule_evidence('CIS-4.1', config)
        self.assertIn('trust', evidence)
        self.assertIn('untrust', evidence)
        self.assertIn('interface', evidence)

    def test_unknown_rule_returns_fallback(self):
        """Unknown rules should return fallback message."""
        config = make_config()
        evidence = extract_rule_evidence('CIS-9.9', config)
        self.assertEqual(evidence, "no_config")

    def test_empty_users_returns_no_evidence(self):
        """Empty users list should indicate no users configured."""
        config = make_config(users=[])
        evidence = extract_rule_evidence('CIS-1.1', config)
        self.assertIn('No user accounts', evidence)


class TestEndToEndPaloAlto(unittest.TestCase):
    """End-to-end test with Palo Alto config to verify rule-specific evidence."""

    PA_CONFIG = '''<?xml version="1.0" encoding="UTF-8"?>
<config version="10.0" urldb="panupv2-all-contents-8625-7698">
  <mgt-config>
    <users>
      <entry name="admin">
        <phash>$1$abcd1234$XyZQeR9tKp7mNv3sLf0Hq1</phash>
        <permissions>
          <role-based>
            <superuser>yes</superuser>
          </role-based>
        </permissions>
      </entry>
      <entry name="svc-monitor">
        <password>Monitor@123</password>
        <permissions>
          <role-based>
            <superreader>yes</superreader>
          </role-based>
        </permissions>
      </entry>
    </users>
  </mgt-config>
  <log-settings>
    <syslog>
      <entry name="syslog-primary">
        <server>
          <entry name="server1">
            <ip-address>192.168.1.50</ip-address>
            <port>514</port>
            <transport>UDP</transport>
            <facility>LOG_USER</facility>
          </entry>
        </server>
      </entry>
    </syslog>
  </log-settings>
  <deviceconfig>
    <system>
      <hostname>TEST-PAFW-02</hostname>
      <ntp-servers>
        <primary>192.168.1.10</primary>
        <secondary>192.168.1.11</secondary>
      </ntp-servers>
    </system>
  </deviceconfig>
  <vsys>
    <entry name="vsys1">
      <zone>
        <entry name="trust"><network><member>ethernet1/1</member></network></entry>
        <entry name="untrust"><network><member>ethernet1/2</member></network></entry>
      </zone>
    </entry>
  </vsys>
  <snmp>
    <community>
      <entry name="secure-monitoring"><version>v3</version></entry>
    </community>
  </snmp>
</config>'''

    def setUp(self):
        """Parse Palo Alto config once."""
        vendor = detect_vendor(self.PA_CONFIG)
        self.parsed = parse_paloalto_panos(self.PA_CONFIG)
        self.normalized = normalize(vendor['vendor'], self.parsed)

    def test_evidence_does_not_contain_secrets(self):
        """Evidence should never contain actual passwords or secrets."""
        for rule_id in ['CIS-1.1', 'CIS-1.2', 'CIS-2.1', 'CIS-2.2', 'CIS-3.1', 'CIS-4.1']:
            evidence = extract_rule_evidence(rule_id, self.normalized)
            self.assertNotIn('Monitor@123', evidence,
                             f"{rule_id} evidence leaks plaintext password!")
            self.assertNotIn('$1$abcd', evidence,
                             f"{rule_id} evidence leaks hash!")

    def test_cis11_evidence_show_users(self):
        """CIS-1.1 evidence should show user names and credential types."""
        evidence = extract_rule_evidence('CIS-1.1', self.normalized)
        self.assertIn('admin', evidence)
        self.assertIn('svc-monitor', evidence)

    def test_cis12_evidence_show_encryption(self):
        """CIS-1.2 evidence should show encryption status."""
        evidence = extract_rule_evidence('CIS-1.2', self.normalized)
        self.assertIn('service password-encryption', evidence)
        self.assertIn('password 0', evidence)  # plaintext indicator

    def test_cis21_evidence_show_logging_hosts(self):
        """CIS-2.1 evidence should show logging hosts."""
        evidence = extract_rule_evidence('CIS-2.1', self.normalized)
        self.assertIn('192.168.1.50', evidence)

    def test_cis22_evidence_show_ntp(self):
        """CIS-2.2 evidence should show NTP servers."""
        evidence = extract_rule_evidence('CIS-2.2', self.normalized)
        self.assertIn('192.168.1.10', evidence)

    def test_cis31_evidence_show_snmp(self):
        """CIS-3.1 evidence should show SNMP communities."""
        evidence = extract_rule_evidence('CIS-3.1', self.normalized)
        self.assertIn('secure-monitoring', evidence)

    def test_cis41_evidence_show_zones(self):
        """CIS-4.1 evidence should show zones."""
        evidence = extract_rule_evidence('CIS-4.1', self.normalized)
        self.assertIn('trust', evidence)
        self.assertIn('untrust', evidence)

    def test_evidence_per_rule_is_different(self):
        """Each rule should get different evidence content."""
        cis11 = extract_rule_evidence('CIS-1.1', self.normalized)
        cis21 = extract_rule_evidence('CIS-2.1', self.normalized)
        cis22 = extract_rule_evidence('CIS-2.2', self.normalized)
        cis41 = extract_rule_evidence('CIS-4.1', self.normalized)

        # CIS-1.1 and CIS-2.1 should be different
        self.assertNotEqual(cis11, cis21)
        self.assertNotEqual(cis11, cis22)
        self.assertNotEqual(cis41, cis21)

    def test_format_evidence_for_ai(self):
        """Test evidence formatting for AI model input."""
        policy = "Passwords should be encrypted"
        evidence = "hostname TEST\nusername admin privilege 15 password 0 weakpass"
        formatted = format_evidence_for_ai(policy, evidence)
        self.assertIn(policy, formatted)
        self.assertIn(evidence, formatted)


if __name__ == '__main__':
    unittest.main()
