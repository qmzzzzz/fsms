/**
 * 重签操作的 append-only 留痕（resign-audit-hmac / resign-audit-chain-v3 共用）。
 *
 * ## 为什么必须落盘
 * 两个重签脚本各有一个"越权放行"旗标（--allow-suspect-hmac / --allow-suspect-chain）：
 * 放行后，验签失败的记录会被覆盖成"通过"——审计链的事后不可抵赖性因此取决于
 * "谁、何时、凭什么放行"。此前这个事实只打到 stdout，进程结束即消失，持钥者
 * 作恶不留痕。本模块在每次 --apply 改写前/完成后追加 intent/result JSON 到
 * logs/audit-resign-log.jsonl，以同一 operationId 关联；只有 started 的操作不得视为完成。
 *
 * ## append-only 纪律
 * 只追加、绝不改写既有行；追加前校验文件**末行**是合法 JSON——末行损坏（手编或
 * 上次崩溃截断）时拒绝登记并让调用方退出非零：留痕文件本身也要能被发现篡改，
 * 否则攻击者删行灭迹只是多一步。行数单调性由 backup-integrity-patrol 顺带核对
 * （logs/ 已在备份口径内）。
 *
 * 演练（无 --apply）不登记：一行未改，登记反而稀释信号。
 */

'use strict';

const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');
const { randomUUID } = require('crypto');

const LEDGER_PATH = path.resolve(__dirname, '..', 'logs', 'audit-resign-log.jsonl');

/** 当前 git 提交短哈希（失败回退 'unknown'：留痕不因仓库外执行而中断） */
function gitRev() {
  try {
    return execFileSync('git', ['rev-parse', '--short', 'HEAD'], { encoding: 'utf8' }).trim();
  } catch (_) {
    return 'unknown';
  }
}

/**
 * 追加一条重签留痕。
 *
 * @param {object} input
 * @param {string} input.script 脚本名（resign-audit-hmac.js / resign-audit-chain-v3.js）
 * @param {string|null} input.ticketId 越权放行时必填的变更单号（旗标带值）
 * @param {boolean} input.overridden 本次是否放行了验签失败记录
 * @param {string} input.dbName 目标库名
 * @param {string} input.host 目标库 host
 * @param {object} input.counts 预检计数（逐脚本自有键，原样入行）
 * @param {string} input.operationId 同次重签的关联 ID
 * @param {string} input.phase intent / result
 * @param {string} input.status started / completed
 * @param {object} [input.result] 改写结果（与预检计数分开）
 * @param {string} [ledgerPath] 可注入测试文件，不提供 CLI/env 覆盖入口
 * @returns {void} 写入或同步落盘失败直接抛：意图留痕失败不得改库
 */
function appendResignLedger(
  { script, ticketId, overridden, dbName, host, counts, operationId, phase, status, result },
  ledgerPath = LEDGER_PATH
) {
  const ticket = typeof ticketId === 'string' ? ticketId.trim() : '';
  if (overridden && (!ticket || ticket.startsWith('-'))) {
    throw new Error('越权放行必须携带变更单号（--allow-suspect-*=<单号>），拒绝无据留痕');
  }
  let separator = '';
  if (fs.existsSync(ledgerPath) && fs.statSync(ledgerPath).size > 0) {
    const raw = fs.readFileSync(ledgerPath, 'utf8');
    const lines = raw.split('\n').filter((l) => l.trim() !== '');
    const last = lines[lines.length - 1];
    try {
      JSON.parse(last);
    } catch (_) {
      throw new Error(
        `重签留痕文件末行不是合法 JSON（${ledgerPath}）：可能被手工编辑或上次写入截断，` +
          '先人工核查该文件再操作（append-only 纪律：不得改写既有行）'
      );
    }
    // 既有末行合法但无换行时只补分隔符，不能把新 JSON 拼进旧行。
    if (!raw.endsWith('\n')) separator = '\n';
  }
  const line = JSON.stringify({
    ts: new Date().toISOString(),
    script,
    gitRev: gitRev(),
    dbName,
    host,
    mode: 'apply',
    overridden: Boolean(overridden),
    ticketId: ticket || null,
    counts,
    operationId,
    phase,
    status,
    result,
  });
  fs.mkdirSync(path.dirname(ledgerPath), { recursive: true });
  const fd = fs.openSync(ledgerPath, 'a');
  try {
    fs.appendFileSync(fd, separator + line + '\n', { encoding: 'utf8' });
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
}

/** 意图落盘成功才调用写库；异常不补 completed，保留 started 供人工核查。 */
async function withResignLedger(input, write, ledgerPath = LEDGER_PATH) {
  const entry = { ...input, operationId: randomUUID() };
  appendResignLedger({ ...entry, phase: 'intent', status: 'started' }, ledgerPath);
  const result = await write();
  appendResignLedger({ ...entry, phase: 'result', status: 'completed', result }, ledgerPath);
  return result;
}

module.exports = { appendResignLedger, withResignLedger, LEDGER_PATH };
