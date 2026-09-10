from fastapi.testclient import TestClient
from backend.main import app
import json

client = TestClient(app)

samples = [
    ("Cisco IOS", "sample_configs/cisco_ios_sample.txt"),
    ("Juniper Junos", "sample_configs/juniper_junos_sample.txt"),
    ("Palo Alto XML", "sample_configs/paloalto_panos_sample.txt"),
    ("Palo Alto Curly", "sample_configs/paloalto_panos_curly.txt"),
]

for label, path in samples:
    print(f"=== {label} ===")
    with open(path) as f:
        cfg = f.read()
    r = client.post("/audit", files={"file": ("config.cfg", cfg)})
    d = r.json()
    print(f"  Vendor: {d['vendor']}, Format: {d['format']}, Hostname: {d['hostname']}")
    print(f"  Score: {d['score']}, Summary: {d['summary']}")
    for finding in d["findings"]:
        print(f"    {finding['rule_id']} [{finding['status']}] {finding['title']}")
    print(f"  Unsupported fields: {d.get('unsupported_fields', [])}")
    print()

print("=== Error cases ===")
r = client.post("/audit", files={"file": ("empty.txt", "")})
print(f"Empty file: {r.status_code} - {r.json()['detail']}")

r = client.post("/audit", files={"file": ("bad.bin", b"\x80\x81\x82")})
print(f"Malformed bytes: {r.status_code} - {r.json()['detail']}")

r = client.post("/audit", files={"file": ("weird.cfg", "some random text")})
print(f"Unknown vendor: {r.status_code} - {r.json()['detail']}")
