'use strict';

const fs = require('fs');
const http = require('http');
const path = require('path');
const { assert, createJourney, runNodeAsync } = require('../lib');

const REQUIRED_MARKERS = [
  '假 Alertmanager 收到投递',
  '探针记录为 queued-unacked',
  '--ack 后',
  '投递失败可见',
];

function startFakeAlertmanager() {
  const received = [];
  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', (chunk) => chunks.push(chunk));
    req.on('end', () => {
      received.push({
        method: req.method,
        url: req.url,
        headers: req.headers,
        raw: Buffer.concat(chunks).toString('utf8'),
      });
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ status: 'success' }));
    });
  });
  return new Promise((resolve, reject) => {
    server.on('error', reject);
    server.listen(0, '127.0.0.1', () => {
      resolve({ server, received, port: server.address().port });
    });
  });
}

function probe(root, target, outFile) {
  return runNodeAsync(
    path.join(root, 'scripts', 'alert-delivery-probe.js'),
    ['--url', target, '--out', outFile, '--timeout-ms', '5000'],
    { timeoutMs: 15000 }
  );
}

async function main(config) {
  const { root, tmpDir } = config;
  const outDir = path.join(tmpDir, 'alert-delivery');
  fs.mkdirSync(outDir, { recursive: true });
  const outFile = path.join(outDir, 'alert-probe.json');
  const { evaluateProbeRecord } = require(path.join(root, 'scripts', 'alertProbeRecord.js'));
  const journey = createJourney('alert-delivery', REQUIRED_MARKERS);
  const fake = await startFakeAlertmanager();
  let correlationId = null;

  try {
    await journey.step('假 Alertmanager 收到投递且载荷标注为探针', async () => {
      const result = await probe(root, `http://127.0.0.1:${fake.port}`, outFile);
      assert.equal(result.status, 0, `探针退出码 ${result.status}\n${result.stderr}`);
      assert.equal(fake.received.length, 1, 'Alertmanager 未收到请求');
      const req = fake.received[0];
      assert.equal(req.method, 'POST');
      assert.equal(req.url, '/api/v2/alerts');
      const payload = JSON.parse(req.raw);
      assert.ok(Array.isArray(payload) && payload.length === 1, '告警载荷应为单元素数组');
      assert.equal(payload[0].labels.alertname, 'FsmsDeliveryProbe');
      assert.equal(payload[0].labels.probe, 'true');
      assert.match(payload[0].annotations.summary, /探针/);
      const record = JSON.parse(fs.readFileSync(outFile, 'utf8'));
      correlationId = record.correlationId;
      assert.equal(record.ok, true);
      assert.equal(correlationId, payload[0].labels.probe_id);
    });

    await journey.step('探针记录为 queued-unacked（入队不等于有人收到）', async () => {
      const verdict = evaluateProbeRecord({
        record: JSON.parse(fs.readFileSync(outFile, 'utf8')),
      });
      assert.equal(verdict.state, 'queued-unacked');
      assert.equal(verdict.ok, false, '未人工确认的投递不应被判为已验过');
    });

    await journey.step('--ack 后记录变为 ok，且 correlationId 保持不变', async () => {
      const ack = await runNodeAsync(
        path.join(root, 'scripts', 'alert-delivery-probe.js'),
        ['--out', outFile, '--ack', '值班-ops-e2e'],
        { timeoutMs: 15000 }
      );
      assert.equal(ack.status, 0, `--ack 失败：${ack.stderr}`);
      const record = JSON.parse(fs.readFileSync(outFile, 'utf8'));
      assert.equal(record.acknowledgedBy, '值班-ops-e2e');
      assert.ok(record.acknowledgedAt);
      assert.equal(record.correlationId, correlationId);
      const verdict = evaluateProbeRecord({ record });
      assert.equal(verdict.state, 'ok');
      assert.equal(verdict.ok, true);
    });

    await journey.step('投递失败可见：不可达时退出码 1 且记录 ok=false', async () => {
      await new Promise((resolve) => fake.server.close(resolve));
      const result = await probe(root, 'http://127.0.0.1:1', outFile);
      assert.equal(result.status, 1, `期望退出码 1，实得 ${result.status}\n${result.stdout}`);
      const record = JSON.parse(fs.readFileSync(outFile, 'utf8'));
      assert.equal(record.ok, false);
      assert.ok(record.error, '失败记录必须写明原因');
      const verdict = evaluateProbeRecord({ record });
      assert.equal(verdict.state, 'failed');
    });

    return journey.finish();
  } finally {
    if (fake.server.listening) {
      await new Promise((resolve) => fake.server.close(resolve));
    }
  }
}

module.exports = { main, startFakeAlertmanager, probe, REQUIRED_MARKERS };
