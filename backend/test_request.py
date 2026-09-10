import requests
import json

url = "http://localhost:8000/audit"
files = {'file': ('cisco.cfg', open('sample_configs/cisco_ios_sample.txt', 'rb').read())}
response = requests.post(url, files=files)
print('Status:', response.status_code)
print('Response:', response.json() if response.content else 'No content')