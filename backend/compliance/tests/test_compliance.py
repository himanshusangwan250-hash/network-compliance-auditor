import unittest
from backend.compliance.models import NormalizedConfig, NormalizedUser, NormalizedSnmpCommunity, NormalizedZone
from backend.compliance.rules_engine import evaluate_compliance, calculate_compliance_score, get_rule_ids, get_rule_details, ComplianceFinding

class TestComplianceRules(unittest.TestCase):
    def test_get_all_rule_ids(self):
        rule_ids = get_rule_ids()
        expected = ['CIS-1.1', 'CIS-1.2', 'CIS-2.1', 'CIS-2.2', 'CIS-3.1', 'CIS-4.1']
        self.assertEqual(rule_ids, expected)
    
    def test_get_rule_details(self):
        details = get_rule_details('CIS-1.1')
        self.assertEqual(details['rule_id'], 'CIS-1.1')
        self.assertEqual(details['title'], 'Avoid Default Credentials')
        self.assertEqual(details['severity'], 'High')
    
    def test_unknown_rule_raises(self):
        with self.assertRaises(ValueError):
            get_rule_details('INVALID-RULE')
    
    def test_default_credentials_found(self):
        config = NormalizedConfig(
            vendor='cisco_ios',
            format=None,
            hostname='test',
            users=[NormalizedUser(name='admin'), NormalizedUser(name='root')]
        )
        findings = evaluate_compliance(config)
        cis11 = [f for f in findings if f.rule_id == 'CIS-1.1']
        self.assertEqual(len(cis11), 1)
        self.assertEqual(cis11[0].status, 'FAIL')
        self.assertIn('admin', cis11[0].evidence)
    
    def test_no_default_credentials(self):
        config = NormalizedConfig(
            vendor='cisco_ios',
            format=None,
            hostname='test',
            users=[NormalizedUser(name='john'), NormalizedUser(name='jane')]
        )
        findings = evaluate_compliance(config)
        cis11 = [f for f in findings if f.rule_id == 'CIS-1.1']
        self.assertEqual(len(cis11), 1)
        self.assertEqual(cis11[0].status, 'PASS')
    
    def test_password_encryption_plain(self):
        config = NormalizedConfig(
            vendor='cisco_ios',
            format=None,
            hostname='test',
            users=[NormalizedUser(name='admin', encrypted=False)]
        )
        findings = evaluate_compliance(config)
        cis12 = [f for f in findings if f.rule_id == 'CIS-1.2']
        self.assertEqual(len(cis12), 1)
        self.assertEqual(cis12[0].status, 'FAIL')
    
    def test_password_encryption_encrypted(self):
        config = NormalizedConfig(
            vendor='cisco_ios',
            format=None,
            hostname='test',
            users=[NormalizedUser(name='admin', encrypted=True)]
        )
        findings = evaluate_compliance(config)
        cis12 = [f for f in findings if f.rule_id == 'CIS-1.2']
        self.assertEqual(len(cis12), 1)
        self.assertEqual(cis12[0].status, 'PASS')
    
    def test_logging_configured(self):
        config = NormalizedConfig(
            vendor='cisco_ios',
            format=None,
            hostname='test',
            logging_hosts=['192.168.1.50']
        )
        findings = evaluate_compliance(config)
        cis21 = [f for f in findings if f.rule_id == 'CIS-2.1']
        self.assertEqual(len(cis21), 1)
        self.assertEqual(cis21[0].status, 'PASS')
    
    def test_logging_not_configured(self):
        config = NormalizedConfig(
            vendor='cisco_ios',
            format=None,
            hostname='test'
        )
        findings = evaluate_compliance(config)
        cis21 = [f for f in findings if f.rule_id == 'CIS-2.1']
        self.assertEqual(len(cis21), 1)
        self.assertEqual(cis21[0].status, 'FAIL')
    
    def test_ntp_configured(self):
        config = NormalizedConfig(
            vendor='cisco_ios',
            format=None,
            hostname='test',
            ntp_servers=['192.168.1.10', '192.168.1.11']
        )
        findings = evaluate_compliance(config)
        cis22 = [f for f in findings if f.rule_id == 'CIS-2.2']
        self.assertEqual(len(cis22), 1)
        self.assertEqual(cis22[0].status, 'PASS')
    
    def test_ntp_not_configured(self):
        config = NormalizedConfig(
            vendor='cisco_ios',
            format=None,
            hostname='test'
        )
        findings = evaluate_compliance(config)
        cis22 = [f for f in findings if f.rule_id == 'CIS-2.2']
        self.assertEqual(len(cis22), 1)
        self.assertEqual(cis22[0].status, 'FAIL')
    
    def test_snmp_weak_community(self):
        config = NormalizedConfig(
            vendor='cisco_ios',
            format=None,
            hostname='test',
            snmp_communities=[NormalizedSnmpCommunity(name='public', permission='RO')]
        )
        findings = evaluate_compliance(config)
        cis31 = [f for f in findings if f.rule_id == 'CIS-3.1']
        self.assertEqual(len(cis31), 1)
        self.assertEqual(cis31[0].status, 'FAIL')
    
    def test_snmp_secure(self):
        config = NormalizedConfig(
            vendor='cisco_ios',
            format=None,
            hostname='test',
            snmp_communities=[NormalizedSnmpCommunity(name='secure_community', permission='rw')]
        )
        findings = evaluate_compliance(config)
        cis31 = [f for f in findings if f.rule_id == 'CIS-3.1']
        self.assertEqual(len(cis31), 1)
        self.assertEqual(cis31[0].status, 'PASS')
    
    def test_zones_configured(self):
        config = NormalizedConfig(
            vendor='juniper_junos',
            format=None,
            hostname='test',
            zones=[NormalizedZone(name='trust'), NormalizedZone(name='untrust')]
        )
        findings = evaluate_compliance(config)
        cis41 = [f for f in findings if f.rule_id == 'CIS-4.1']
        self.assertEqual(len(cis41), 1)
        self.assertEqual(cis41[0].status, 'PASS')
    
    def test_no_zones(self):
        config = NormalizedConfig(
            vendor='cisco_ios',
            format=None,
            hostname='test',
            unsupported_fields=['zones']
        )
        findings = evaluate_compliance(config)
        cis41 = [f for f in findings if f.rule_id == 'CIS-4.1']
        self.assertEqual(len(cis41), 1)
        # Cisco parser doesn't support zones, so should be UNKNOWN
        self.assertEqual(cis41[0].status, 'UNKNOWN')
    
    def test_all_findings_have_required_fields(self):
        config = NormalizedConfig(
            vendor='cisco_ios',
            format=None,
            hostname='test',
            users=[NormalizedUser(name='admin', encrypted=False)],
            snmp_communities=[NormalizedSnmpCommunity(name='public', permission='RO')]
        )
        findings = evaluate_compliance(config)
        for f in findings:
            self.assertTrue(hasattr(f, 'rule_id'))
            self.assertTrue(hasattr(f, 'title'))
            self.assertTrue(hasattr(f, 'severity'))
            self.assertTrue(hasattr(f, 'status'))
            self.assertTrue(hasattr(f, 'evidence'))
            self.assertTrue(hasattr(f, 'remediation'))
            self.assertIn(f.status, ['PASS', 'FAIL', 'UNKNOWN'])

if __name__ == '__main__':
    unittest.main()

class TestComplianceScoring(unittest.TestCase):
    def test_all_pass(self):
        findings = [
            ComplianceFinding('CIS-1.1', 'Test', 'High', 'PASS', 'e', 'r'),
            ComplianceFinding('CIS-2.1', 'Test', 'Medium', 'PASS', 'e', 'r'),
        ]
        result = calculate_compliance_score(findings)
        self.assertEqual(result['score'], 100.0)
        self.assertEqual(result['summary']['pass'], 2)
        self.assertEqual(result['summary']['fail'], 0)
        self.assertEqual(result['summary']['unknown'], 0)

    def test_mixed_pass_fail(self):
        findings = [
            ComplianceFinding('CIS-1.1', 'Test', 'High', 'PASS', 'e', 'r'),
            ComplianceFinding('CIS-1.2', 'Test', 'Medium', 'FAIL', 'e', 'r'),
            ComplianceFinding('CIS-2.1', 'Test', 'Medium', 'PASS', 'e', 'r'),
        ]
        result = calculate_compliance_score(findings)
        self.assertEqual(result['score'], 66.7)
        self.assertEqual(result['summary']['pass'], 2)
        self.assertEqual(result['summary']['fail'], 1)

    def test_unknown_findings_reduce_score(self):
        findings = [
            ComplianceFinding('CIS-1.1', 'Test', 'High', 'PASS', 'e', 'r'),
            ComplianceFinding('CIS-3.1', 'Test', 'High', 'UNKNOWN', 'e', 'r'),
        ]
        result = calculate_compliance_score(findings)
        self.assertEqual(result['score'], 50.0)
        self.assertEqual(result['summary']['unknown'], 1)
        self.assertEqual(result['summary']['total'], 2)

    def test_all_unknown(self):
        findings = [
            ComplianceFinding('CIS-1.1', 'Test', 'High', 'UNKNOWN', 'e', 'r'),
            ComplianceFinding('CIS-4.1', 'Test', 'Medium', 'UNKNOWN', 'e', 'r'),
        ]
        result = calculate_compliance_score(findings)
        self.assertEqual(result['score'], 0.0)
        self.assertEqual(result['summary']['unknown'], 2)

    def test_empty_findings(self):
        result = calculate_compliance_score([])
        self.assertIsNone(result['score'])
        self.assertEqual(result['summary']['total'], 0)

    def test_all_fail(self):
        findings = [
            ComplianceFinding('CIS-1.1', 'Test', 'High', 'FAIL', 'e', 'r'),
            ComplianceFinding('CIS-2.1', 'Test', 'Medium', 'FAIL', 'e', 'r'),
        ]
        result = calculate_compliance_score(findings)
        self.assertEqual(result['score'], 0.0)

    def test_cisco_users_unsupported_returns_unknown(self):
        config = NormalizedConfig(
            vendor='paloalto_panos', format='xml', hostname='test',
            unsupported_fields=['users', 'logging_hosts']
        )
        findings = evaluate_compliance(config)
        cis11 = [f for f in findings if f.rule_id == 'CIS-1.1']
        cis12 = [f for f in findings if f.rule_id == 'CIS-1.2']
        cis21 = [f for f in findings if f.rule_id == 'CIS-2.1']
        self.assertEqual(cis11[0].status, 'UNKNOWN')
        self.assertEqual(cis12[0].status, 'UNKNOWN')
        self.assertEqual(cis21[0].status, 'UNKNOWN')

    def test_cisco_snmp_unsupported_returns_unknown(self):
        config = NormalizedConfig(
            vendor='paloalto_panos', format='xml', hostname='test',
            unsupported_fields=['snmp_communities']
        )
        findings = evaluate_compliance(config)
        cis31 = [f for f in findings if f.rule_id == 'CIS-3.1']
        self.assertEqual(cis31[0].status, 'UNKNOWN')


class TestPaloAltoUserLogging(unittest.TestCase):
    """Regression tests for Palo Alto user and logging extraction."""

    def test_paloalto_mixed_encrypted_plaintext_users(self):
        """CIS-1.2 should FAIL when one user has plaintext password and another has hash."""
        config = NormalizedConfig(
            vendor='paloalto_panos',
            format='xml',
            hostname='test',
            users=[
                NormalizedUser(name='admin', encrypted=True),
                NormalizedUser(name='svc-monitor', encrypted=False),
            ]
        )
        findings = evaluate_compliance(config)
        cis12 = [f for f in findings if f.rule_id == 'CIS-1.2']
        self.assertEqual(len(cis12), 1)
        self.assertEqual(cis12[0].status, 'FAIL')
        self.assertIn('svc-monitor', cis12[0].evidence)

    def test_paloalto_all_encrypted_users_pass(self):
        """CIS-1.2 should PASS when all users have encrypted passwords."""
        config = NormalizedConfig(
            vendor='paloalto_panos',
            format='xml',
            hostname='test',
            users=[
                NormalizedUser(name='admin', encrypted=True),
                NormalizedUser(name='operator', encrypted=True),
            ]
        )
        findings = evaluate_compliance(config)
        cis12 = [f for f in findings if f.rule_id == 'CIS-1.2']
        self.assertEqual(len(cis12), 1)
        self.assertEqual(cis12[0].status, 'PASS')

    def test_paloalto_logging_hosts_configured_pass(self):
        """CIS-2.1 should PASS when logging hosts are configured."""
        config = NormalizedConfig(
            vendor='paloalto_panos',
            format='xml',
            hostname='test',
            logging_hosts=['192.168.1.50', 'syslog-backup.example.com']
        )
        findings = evaluate_compliance(config)
        cis21 = [f for f in findings if f.rule_id == 'CIS-2.1']
        self.assertEqual(len(cis21), 1)
        self.assertEqual(cis21[0].status, 'PASS')
        self.assertIn('192.168.1.50', cis21[0].evidence)
        self.assertIn('syslog-backup.example.com', cis21[0].evidence)

    def test_paloalto_logging_hosts_empty_fail(self):
        """CIS-2.1 should FAIL when no logging hosts are configured."""
        config = NormalizedConfig(
            vendor='paloalto_panos',
            format='xml',
            hostname='test',
            logging_hosts=[]
        )
        findings = evaluate_compliance(config)
        cis21 = [f for f in findings if f.rule_id == 'CIS-2.1']
        self.assertEqual(len(cis21), 1)
        self.assertEqual(cis21[0].status, 'FAIL')

    def test_paloalto_unknown_encryption_returns_unknown(self):
        """CIS-1.2 should return UNKNOWN when users have no password data (external auth)."""
        config = NormalizedConfig(
            vendor='paloalto_panos',
            format='xml',
            hostname='test',
            users=[
                NormalizedUser(name='ldap-user', encrypted=None),
                NormalizedUser(name='radius-user', encrypted=None),
            ]
        )
        findings = evaluate_compliance(config)
        cis12 = [f for f in findings if f.rule_id == 'CIS-1.2']
        self.assertEqual(len(cis12), 1)
        self.assertEqual(cis12[0].status, 'UNKNOWN')
        self.assertIn('ldap-user', cis12[0].evidence)

    def test_curly_brace_users_and_logging_unsupported(self):
        """CIS-1.1, CIS-1.2, CIS-2.1 should return UNKNOWN when format is curly_brace."""
        config = NormalizedConfig(
            vendor='paloalto_panos',
            format='curly_brace',
            hostname='test',
            unsupported_fields=['users', 'logging_hosts', 'routes']
        )
        findings = evaluate_compliance(config)
        cis11 = [f for f in findings if f.rule_id == 'CIS-1.1']
        cis12 = [f for f in findings if f.rule_id == 'CIS-1.2']
        cis21 = [f for f in findings if f.rule_id == 'CIS-2.1']
        self.assertEqual(cis11[0].status, 'UNKNOWN')
        self.assertEqual(cis12[0].status, 'UNKNOWN')
        self.assertEqual(cis21[0].status, 'UNKNOWN')

    def test_missing_encrypted_key_unchanged(self):
        """A user dict with no 'encrypted' key should not default to True or False."""
        from backend.compliance.models import NormalizedConfig, NormalizedUser
        # NormalizedUser should have encrypted=None as default
        user = NormalizedUser(name='test-user')
        self.assertIsNone(user.encrypted)
        # When unsupported, CIS-1.2 should be UNKNOWN
        config = NormalizedConfig(
            vendor='paloalto_panos',
            format='xml',
            hostname='test',
            users=[user],
            unsupported_fields=['users']
        )
        findings = evaluate_compliance(config)
        cis12 = [f for f in findings if f.rule_id == 'CIS-1.2']
        self.assertEqual(cis12[0].status, 'UNKNOWN')
