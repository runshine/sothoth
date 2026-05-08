const http = require('http');
const body = JSON.stringify({ project_id: 'test', config: {} });

// 测试1：不带 Content-Length（让 http-proxy 的流式转发方式）
function test1() {
  const options = {
    hostname: 'secflow.ai.icsl.huawei.com',
    port: 80,
    path: '/api/app/dataflow-analyse/config',
    method: 'PUT',
    headers: {
      'Content-Type': 'application/json',
      'Transfer-Encoding': 'chunked',
      'Authorization': 'Bearer test-token',
    },
  };
  const req = http.request(options, (res) => {
    let data = '';
    res.on('data', (c) => data += c);
    res.on('end', () => console.log('Test1 (chunked):', res.statusCode));
  });
  req.on('error', (e) => console.error('Test1 ERROR:', e.message, e.code));
  req.write(body);
  req.end();
}

// 测试2：明确 Content-Length + Authorization
function test2() {
  const options = {
    hostname: 'secflow.ai.icsl.huawei.com',
    port: 80,
    path: '/api/app/dataflow-analyse/config',
    method: 'PUT',
    headers: {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(body),
      'Authorization': 'Bearer test-token',
    },
  };
  const req = http.request(options, (res) => {
    let data = '';
    res.on('data', (c) => data += c);
    res.on('end', () => console.log('Test2 (content-length + auth):', res.statusCode));
  });
  req.on('error', (e) => console.error('Test2 ERROR:', e.message, e.code));
  req.write(body);
  req.end();
}

test1();
setTimeout(test2, 500);
