const http = require('http');
const body = JSON.stringify({ project_id: 'test', config: {} });
const options = {
  hostname: 'secflow.ai.icsl.huawei.com',
  port: 80,
  path: '/api/app/dataflow-analyse/config',
  method: 'PUT',
  headers: {
    'Content-Type': 'application/json',
    'Content-Length': Buffer.byteLength(body),
  },
};
const req = http.request(options, (res) => {
  let data = '';
  res.on('data', (chunk) => data += chunk);
  res.on('end', () => console.log('STATUS:', res.statusCode, '\nBODY:', data.slice(0, 200)));
});
req.on('error', (e) => console.error('ERROR:', e.message, e.code));
req.write(body);
req.end();
