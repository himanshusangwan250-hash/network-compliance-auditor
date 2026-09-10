import unittest
from backend.compliance.models import NormalizedConfig, NormalizedInterface, NormalizedUser, NormalizedSnmpCommunity, NormalizedZone, NormalizedSecurityRule
from backend.compliance.models import normalize
import json

def load_parser_output(vendor, filename):
    with open(filename) as f:
        return json.load(f)

class TestNormalization(unittest.TestCase):
    def test_cisco_normalization(self):
        parsed = load_parser_output('cisco_ios', 'sample_configs/cisco_ios_sample.json')
        normalized = normalize('cisco_ios', parsed)
        self.assertEqual(normalized.hostname, parsed['hostname'])
        self.assertEqual(len(normalized.interfaces), len(parsed['interfaces']))
        self.assertEqual(len(normalized.users), len(parsed['users']))
        self.assertEqual(len(normalized.ntp_servers), len(parsed['ntp']))
        # Add more assertions as needed

    def test_juniper_normalization(self):
        parsed = load_parser_output('juniper_junos', 'sample_configs/juniper_junos_sample.json')
        normalized = normalize('juniper_junos', parsed)
        self.assertEqual(normalized.hostname, parsed['hostname'])
        self.assertEqual(len(normalized.interfaces), len(parsed['interfaces']))
        self.assertEqual(len(normalized.users), len(parsed['users']))
        self.assertEqual(len(normalized.ntp_servers), len(parsed['ntp']))
        # Add more assertions as needed

    def test_paloalto_normalization(self):
        parsed = load_parser_output('paloalto_panos', 'sample_configs/paloalto_panos_sample.json')
        normalized = normalize('paloalto_panos', parsed)
        # Add assertions here

if __name__ == '__main__':
    unittest.main()
