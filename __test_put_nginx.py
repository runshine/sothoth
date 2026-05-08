import urllib.request as r, json as j
url = 'http://secflow.ai.icsl.huawei.com/api/app/dataflow-analyse/config'
body = j.dumps({'project_id': 'test', 'config': {}}).encode()
req = r.Request(url, data=body, headers={'Content-Type': 'application/json'}, method='PUT')
try:
    resp = r.urlopen(req, timeout=15)
    print('STATUS:', resp.status)
    print('BODY:', resp.read().decode()[:200])
except Exception as e:
    print('ERROR:', type(e).__name__, str(e))
