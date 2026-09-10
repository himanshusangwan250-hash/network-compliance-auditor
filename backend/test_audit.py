import requests
import json

url = "http://localhost:8000/audit"

# Test Juniper config
with open('sample_configs/juniper_junos_sample.txt', 'rb') as f:
    juniper_cfg = f.read()
files = {'file': ('juniper.cfg', juniper_cfg)}
response = requests.post(url, files=files)
print('Juniper Status:', response.status_code)
if response.status_code == 200:
    data = response.json()
    print('Vendor:', data.get('vendor'))
    print('Format:', data.get('format'))
    print('Score:', data.get('score'))
    print('Summary:', data.get('summary'))
    print('Findings count:', len(data.get('findings', [])))
    print('Unsupported fields:', data.get('unsupported_fields'))
    print('First 3 findings:', json.dumps(data.get('findings', [])[:3], indent=2))
else:
    print('Error:', response.text)

# Test Cisco config
with open('sample_configs/cisco_ios_sample.txt', 'rb') as f:
    cisco_cfg = f.read()
files = {'file': ('cisco.cfg', cisco_cfg)}
response = requests.post(url, files=files)
print('\nCisco Status:', response.status_code)
if response.status_code == 200:
    data = response.json()
    print('Vendor:', data.get('vendor'))
    print('Score:', data.get('score'))
    print('Findings count:', len(data.get('findings', [])))
else:
    print('Error:', response.text)

# Test Palo Alto XML config
with open('sample_configs/paloalto_panos_sample.txt', 'rb') as f:
    palo_cfg = f.read()
files = {'file': ('palo.cfg', palo_cfg)}
response = requests.post(url, files=files)
print('\nPalo Alto Status:', response.status_code)
if response.status_code == 200:
    data = response.json()
    print('Vendor:', data.get('vendor'))
    print('Format:', data.get('format'))
    print('Score:', data.get('score'))
    print('Findings count:', len(data.get('findings', [])))
else:
    print('Error:', response.text)

# Test Palo Alto curly brace config
with open('sample_configs/paloalto_panos_curly.txt', 'rb') as f:
    palo_curly = f.read()
files = {'file': ('palo-curly.cfg', palo_curly)}
response = requests.post(url, files=files)
print('\nPalo Alto Curly Status:', response.status_code)
if response.status_code == 200:
    data = response.json()
    print('Vendor:', data.get('vendor'))
    print('Format:', data.get('format'))
    print('Score:', data.get('score'))
    print('Findings count:', len(data.get('findings', [])))
else:
    print('Error:', response.text)