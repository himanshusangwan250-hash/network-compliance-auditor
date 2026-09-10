import json
from fastapi.testclient import TestClient
from main import app
from pathlib import Path

client = TestClient(app)

# Test health endpoint
response = client.get('/health')
print('Health status:', response.status_code, json.dumps(response.json()))

# Test audit endpoint with sample config
config_path = Path('sample_configs/cisco_ios_sample.txt')
print('Config file exists:', config_path.exists())
if config_path.exists():
    with open(config_path) as f:
        cfg = f.read()
    files = {'file': ('cisco.cfg', cfg)}
    response = client.post('/audit', files=files)
    print('Audit status:', response.status_code)
    if response.status_code == 200:
        data = response.json()
        print('Response keys:', list(data.keys()))
        print('Vendor:', data.get('vendor'))
        print('Score:', data.get('score'))
        print('Full response:', json.dumps(data, indent=2))
else:
    print('Config file not found:', config_path)