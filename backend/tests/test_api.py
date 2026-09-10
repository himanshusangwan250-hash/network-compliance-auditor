import json
from fastapi.testclient import TestClient
import unittest
from backend.main import app

client = TestClient(app)

class TestAPI(unittest.TestCase):
    def test_health(self):
        response = client.get('/health')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {'status': 'ok'})

    def test_vendors(self):
        response = client.get('/vendors')
        self.assertEqual(response.status_code, 200)
        self.assertSetEqual(set(response.json()), {'cisco_ios', 'juniper_junos', 'paloalto_panos'})

    def test_rules(self):
        response = client.get('/rules')
        self.assertEqual(response.status_code, 200)
        expected = ['CIS-1.1', 'CIS-1.2', 'CIS-2.1', 'CIS-2.2', 'CIS-3.1', 'CIS-4.1']
        self.assertEqual(response.json(), expected)

    def test_rule_detail(self):
        response = client.get('/rules/CIS-1.1')
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data['rule_id'], 'CIS-1.1')
        self.assertEqual(data['title'], 'Avoid Default Credentials')
        self.assertEqual(data['severity'], 'High')

    def test_rule_detail_not_found(self):
        response = client.get('/rules/INVALID')
        self.assertEqual(response.status_code, 404)

    def test_audit_cisco(self):
        with open('sample_configs/cisco_ios_sample.txt') as f:
            cfg = f.read()
        files = {'file': ('cisco.cfg', cfg)}
        response = client.post('/audit', files=files)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data['vendor'], 'cisco_ios')
        self.assertIn('format', data)
        self.assertIn('score', data)
        self.assertIn('summary', data)
        self.assertIn('findings', data)
        self.assertIn('unsupported_fields', data)

        # Verify findings contain expected rules
        finding_ids = [f['rule_id'] for f in data['findings']]
        self.assertIn('CIS-1.1', finding_ids)
        self.assertIn('CIS-1.2', finding_ids)
        self.assertIn('CIS-2.1', finding_ids)
        self.assertIn('CIS-2.2', finding_ids)
        self.assertIn('CIS-3.1', finding_ids)
        self.assertIn('CIS-4.1', finding_ids)

        # Verify score structure
        self.assertIsInstance(data['score'], (int, float, type(None)))
        summary = data['summary']
        self.assertEqual(summary['pass'] + summary['fail'] + summary['unknown'], summary['total'])

    def test_audit_juniper(self):
        with open('sample_configs/juniper_junos_sample.txt') as f:
            cfg = f.read()
        files = {'file': ('juniper.cfg', cfg)}
        response = client.post('/audit', files=files)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data['vendor'], 'juniper_junos')
        self.assertIn('format', data)
        self.assertIn('score', data)
        self.assertIn('findings', data)
        # Juniper has zones
        finding_ids = [f['rule_id'] for f in data['findings']]
        self.assertIn('CIS-4.1', finding_ids)

    def test_audit_paloalto(self):
        with open('sample_configs/paloalto_panos_sample.txt') as f:
            cfg = f.read()
        files = {'file': ('paloalto.cfg', cfg)}
        response = client.post('/audit', files=files)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data['vendor'], 'paloalto_panos')
        self.assertEqual(data['format'], 'xml')
        self.assertIn('score', data)
        self.assertIn('findings', data)

    def test_audit_empty_file(self):
        files = {'file': ('empty.cfg', '')}
        response = client.post('/audit', files=files)
        self.assertEqual(response.status_code, 400)

    def test_audit_malformed_file(self):
        files = {'file': ('bad.cfg', b'\x80\x81\x82')}
        response = client.post('/audit', files=files)
        self.assertEqual(response.status_code, 400)

    def test_audit_output_has_no_secrets(self):
        """Verify audit response doesn't leak sensitive data."""
        with open('sample_configs/cisco_ios_sample.txt') as f:
            cfg = f.read()
        files = {'file': ('cisco.cfg', cfg)}
        response = client.post('/audit', files=files)
        data = response.json()
        response_str = json.dumps(data)
        # Should not contain actual password secrets
        self.assertNotIn('$1$m8R$', response_str)

    def test_audit_file_too_large(self):
        """Verify server rejects oversized uploads."""
        big_content = 'x' * (11 * 1024 * 1024)  # 11 MB
        files = {'file': ('big.cfg', big_content)}
        response = client.post('/audit', files=files)
        self.assertEqual(response.status_code, 413)

    def test_audit_paloalto_curly(self):
        with open('sample_configs/paloalto_panos_curly.txt') as f:
            cfg = f.read()
        files = {'file': ('paloalto-curly.cfg', cfg)}
        response = client.post('/audit', files=files)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data['vendor'], 'paloalto_panos')
        self.assertEqual(data['format'], 'curly_brace')
        self.assertIn('score', data)
        self.assertIn('findings', data)

if __name__ == '__main__':
    unittest.main()
