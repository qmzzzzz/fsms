#!/usr/bin/env node
/**
 * 告警投递探针（F-09，2026-10-17）
 *
 * 解决的问题：`ALERT_WEBHOOK_CHECK=production` 只能判出"配置里还是占位 URL"，
 * 判不出"配了真实 URL 但打不通"。一个写对了地址却已失效的 access_token，
 * 在所有静态判据里与一条健康的通道长得一模一样——直到真出事那天。
 *
 * 本脚本向 Alertmanager 的 `/api/v2/alerts` 投一条**明确标注为探针**的告警，
 * 记录结果与 correlationId 到 `logs/alert-probe.json`，供 `scripts/compliance-check.js`
 * 判定"链路到底验没验过"（判据在 `scripts/alertProbeRecord.js`）。
 *
 * ⚠ 能证明什么、不能证明什么（别把这条当成"端到端已验证"）：
 *   能证明：Alertmanager 活着、接受写入、这条告警匹配到了某个 receiver。
 *   不能证明：receiver 背后的 webhook 真把消息送到了人手上（取决于 access_token
 *            是否有效、适配器是否在跑、群是否还在）。
 *   所以投递成功只是 `queued-unacked`；值班需按 correlationId 到接收端确认后，
 *   执行 `--ack <姓名/角色>` 补记，记录才会变成 `ok`。
 *
 * 用法：
 *   node scripts/alert-delivery-probe.js                    # 投递探针（默认 127.0.0.1:9093）
 *   node scripts/alert-delivery-probe.js --url http://am:9093 --out logs/alert-probe.json
 *   node scripts/alert-delivery-probe.js --ack 值班-张三     # 补记人工确认（不重发）
 *
 * 退出码：0 投递成功（或确认已记录）/ 1 投递失败 / 2 用法错误。
 */
'use strict';

const fs = require('fs');
const path = require('path');
const http = require('http');
const https = require('https');
const { randomUUID } = require('crypto');

const ROOT = path.resolve(__dirname, '..');
const DEFAULT_TARGET = 'http://127.0.0.1:9093';
const DEFAULT_OUT = path.join(ROOT, 'logs', 'alert-probe.json');

/** 解析参数；未知参数必须拒绝（手误的 `--ack` 拼错会静默变成"投递"，在群里刷一条测试告警） */
function parseArgs(argv) {
  const args = { url: DEFAULT_TARGET, out: DEFAULT_OUT, ack: null, timeoutMs: 5000 };
  const errors = [];
  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    const next = argv[i + 1];
    if (token === '--url' || token === '--out' || token === '--ack' || token === '--timeout-ms') {
      if (!next || next.startsWith('--')) {
        errors.push(`${token} 缺少参数`);
        continue;
      }
      if (token === '--url') args.url = next;
      else if (token === '--out') args.out = path.resolve(next);
      else if (token === '--ack') args.ack = next;
      else {
        const ms = Number(next);
        if (!Number.isFinite(ms) || ms <= 0) errors.push(`--timeout-ms 不是正整数：${next}`);
        else args.timeoutMs = ms;
      }
      i += 1;
    } else {
      errors.push(`未知参数：${token}（只接受 --url / --out / --ack / --timeout-ms）`);
    }
  }
  return { args, errors };
}

/** 构造探针告警：label 与 annotation 都要写明"这是探针"，避免值班误当真实告警 */
function buildProbeAlert(correlationId, now = new Date()) {
  return [
    {
      labels: {
        alertname: 'FsmsDeliveryProbe',
        severity: 'warning',
        probe_id: correlationId,
        // 独立 label 便于在 Alertmanager 侧按它做静默规则（如需要）
        probe: 'true',
      },
      annotations: {
        summary: '【探针·请忽略】告警投递链路自检',
        description:
          `这是 F-09 告警投递探针，不是真实故障。correlationId=${correlationId}。` +
          '收到即说明链路可达；请在巡检记录里按该 id 核对。',
      },
      startsAt: now.toISOString(),
    },
  ];
}

/** POST 到 Alertmanager（零依赖：内置 http/https） */
function postAlerts(target, body, timeoutMs) {
  return new Promise((resolve) => {
    let url;
    try {
      url = new URL('/api/v2/alerts', target);
    } catch (err) {
      resolve({ ok: false, statusCode: 0, error: `目标 URL 非法：${err.message}` });
      return;
    }
    const payload = JSON.stringify(body);
    const client = url.protocol === 'https:' ? https : http;
    const started = Date.now();
    const req = client.request(
      url,
      {
        method: 'POST',
        headers: { 'content-type': 'application/json', 'content-length': Buffer.byteLength(payload) },
        timeout: timeoutMs,
      },
      (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          const text = Buffer.concat(chunks).toString('utf8');
          resolve({
            ok: res.statusCode >= 200 && res.statusCode < 300,
            statusCode: res.statusCode,
            durationMs: Date.now() - started,
            error: res.statusCode >= 200 && res.statusCode < 300 ? null : text.slice(0, 300),
          });
        });
      }
    );
    req.on('timeout', () => req.destroy(new Error(`超时（${timeoutMs}ms）`)));
    req.on('error', (err) => {
      resolve({ ok: false, statusCode: 0, durationMs: Date.now() - started, error: err.message });
    });
    req.write(payload);
    req.end();
  });
}

/** 读已有记录（损坏时返回 null 而不是抛：探针的价值是"留下证据"，不该因旧文件坏了就罢工） */
function readRecord(file) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch {
    return null;
  }
}

function writeRecord(file, record) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, `${JSON.stringify(record, null, 2)}\n`, 'utf8');
}

async function main() {
  const { args, errors } = parseArgs(process.argv.slice(2));
  if (errors.length > 0) {
    for (const e of errors) console.error(`[alert-probe] ${e}`);
    process.exit(2);
  }

  // --ack 模式：不重发，只补记人工确认（避免为了留痕而在群里再刷一条测试告警）
  if (args.ack) {
    const record = readRecord(args.out);
    if (!record || !record.correlationId) {
      console.error(`[alert-probe] 没有可确认的记录：${args.out}（先执行一次投递）`);
      process.exit(1);
    }
    if (record.ok !== true) {
      console.error('[alert-probe] 最近一次探针是失败的，不能补记为"已确认"');
      process.exit(1);
    }
    record.acknowledgedBy = args.ack;
    record.acknowledgedAt = new Date().toISOString();
    writeRecord(args.out, record);
    console.log(`[alert-probe] 已记录人工确认：${args.ack}（correlationId=${record.correlationId}）`);
    return;
  }

  const correlationId = randomUUID();
  const body = buildProbeAlert(correlationId);
  const result = await postAlerts(args.url, body, args.timeoutMs);
  const record = {
    probedAt: new Date().toISOString(),
    target: args.url,
    correlationId,
    ok: result.ok,
    statusCode: result.statusCode,
    durationMs: result.durationMs || null,
    error: result.error || null,
    acknowledgedBy: null,
    acknowledgedAt: null,
  };
  writeRecord(args.out, record);

  if (!result.ok) {
    console.error(
      `[alert-probe] 投递失败：${result.error || `HTTP ${result.statusCode}`}（记录已写入 ${args.out}）`
    );
    process.exit(1);
  }
  console.log(
    `[alert-probe] 已投递（HTTP ${result.statusCode}，${result.durationMs}ms），` +
      `correlationId=${correlationId}`
  );
  console.log(
    '[alert-probe] 注意：入队成功 ≠ 有人收到。请按 correlationId 到接收端核对后执行 ' +
      `--ack <姓名> 补记（否则合规检查只会判到 queued-unacked）`
  );
}

if (require.main === module) {
  main().catch((err) => {
    console.error(`[alert-probe] 执行失败：${err.message}`);
    process.exit(1);
  });
}

module.exports = { parseArgs, buildProbeAlert, postAlerts, readRecord, writeRecord, DEFAULT_TARGET };
