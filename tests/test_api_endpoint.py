from fastapi.testclient import TestClient
from backend.main import app
import json

client = TestClient(app)

vendors = [
    ('Cisco', 'sample_configs/cisco_ios_sample.txt'),
    ('Juniper', 'sample_configs/juniper_junos_sample.txt'),
    ('Palo Alto XML', 'sample_configs/paloalto_panos_sample.txt'),
    ('Palo Alto Curly', 'sample_configs/paloalto_panos_curly.txt'),
]

print('=== Testing POST /audit endpoint ===')
for name, path in vendors:
    with open(path) as f:
        cfg = f.read()
    r = client.post('/audit', files={'file': ('config.cfg', cfg)})
    if r.status_code == 200:
        data = r.json()
        print(f'{name}: {data["vendor"]} - Score: {data["score"]} - Findings: {len(data["findings"])}')
    else:
        print(f'{name}: {r.status_code} - {r.json()}')

print('\n=== Testing GET /api/audit (should 404) ===')
r = client.get('/api/audit')
print(f'GET /api/audit: {r.status_code}')
