import urllib.request as r, json as j, sys
url = 'http://localhost:8080/api/app/dataflow-analyse/config'
body = j.dumps({'project_id': 'test', 'config': {}}).encode()
req = r.Request(url, data=body, headers={'Content-Type': 'application/json'}, method='PUT')
try:
    resp = r.urlopen(req, timeout=10)
    print('STATUS:', resp.status)
    print('BODY:', resp.read().decode())
except Exception as e:
    print('ERROR:', type(e).__name__, str(e))
