/**
 * P2-13：留存合规判定的行为级钉子
 *
 * scripts/compliance-check.js 的 checkRetention 判据是
 *   passed = meetsMinimum && !wasAdjusted
 * 变异实测：把合取项删成 `passed = meetsMinimum` 后，既有 33/33 用例仍全绿——
 * 即「配置被钳制/回退必须判不合规」这一半完全没有设防（存量断言全是文本断言）。
 *
 * wasAdjusted 的产生机制在 src/constants/retention.js：AUDIT_RETENTION_DAYS
 * 在模块加载期一次性解析，越界值被钳制到 [90, 3650]，原始值 ≠ 生效值即
 * wasAdjusted=true。因此构造越界配置即可驱动该分支。
 *
 * 本文件两条腿钉住它（删掉 `!wasAdjusted` 合取项时都会转红）：
 *  A. 端到端：子进程真跑脚本，喂越界配置，断言退出码非 0 且留存行不通过；
 *     对照组喂合法值，退出码必须为 0（守卫不得把正常用法一起拦下）。
 *  B. 进程内：直接跑登记表里的 checkRetention，断言钳制场景结论为 false。
 */

const { spawnSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const ROOT = path.resolve(__dirname, '../../..');
const SCRIPT = path.join(ROOT, 'scripts/compliance-check.js');
const RETENTION_ROW = '留存天数 (AUDIT_RETENTION_DAYS)';

// 脚本会连带加载 logger（文件 transport 落在 LOG_DIR）；指到临时目录，
// 不给仓库 logs/ 添新的轮转清单（与 P2-24 的卫生口径一致）
const PROBE_LOG_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'retention-gate-'));
afterAll(() => {
  fs.rmSync(PROBE_LOG_DIR, { recursive: true, force: true });
});

const spawnGate = (extraEnv) =>
  spawnSync(process.execPath, [SCRIPT], {
    cwd: ROOT,
    encoding: 'utf8',
    env: {
      ...process.env,
      COMPLIANCE_STRICT: '',
      ALERT_WEBHOOK_CHECK: '',
      LOG_DIR: PROBE_LOG_DIR,
      ...extraEnv,
    },
  });

const parseReport = (stdout) =>
  JSON.parse(stdout.slice(stdout.indexOf('{'), stdout.indexOf('\n\n==========')));

const retentionRow = (report) => {
  const row = report.checks.find((c) => c.name === RETENTION_ROW);
  expect(row).toBeDefined();
  return row;
};

describe('P2-13 留存合规（端到端）：配置被静默修正 ⇒ 退出码非 0', () => {
  it('低于下限的配置（1 天，被钳到 90）⇒ 退出 1，留存行不通过并说明钳制', () => {
    const r = spawnGate({ AUDIT_RETENTION_DAYS: '1' });
    expect(r.status).toBe(1);
    expect(r.stdout).toContain('总体: 存在缺失');
    const row = retentionRow(parseReport(r.stdout));
    expect(row.passed).toBe(false);
    expect(row.detail).toContain('配置意图与实际留存不一致');
  });

  it('高于上限的配置（10000 天，被钳到 3650）⇒ 同样退出 1', () => {
    const r = spawnGate({ AUDIT_RETENTION_DAYS: '10000' });
    expect(r.status).toBe(1);
    expect(retentionRow(parseReport(r.stdout)).passed).toBe(false);
  });

  it('对照组：合法配置 180 原样生效 ⇒ 退出 0 且留存行通过', () => {
    const r = spawnGate({ AUDIT_RETENTION_DAYS: '180' });
    expect(r.status).toBe(0);
    const row = retentionRow(parseReport(r.stdout));
    expect(row.passed).toBe(true);
    expect(row.detail).toContain('原样生效');
  });

  it('对照组：边界值 90 / 3650 恰在区间内 ⇒ 退出 0', () => {
    for (const v of ['90', '3650']) {
      const r = spawnGate({ AUDIT_RETENTION_DAYS: v });
      expect(r.status).toBe(0);
      expect(retentionRow(parseReport(r.stdout)).passed).toBe(true);
    }
  });
});

describe('P2-13 留存合规（进程内）：checkRetention 对钳制场景判不通过', () => {
  let savedEnv;

  beforeEach(() => {
    savedEnv = process.env.AUDIT_RETENTION_DAYS;
    // retention.js 在模块加载期读 env，必须整体重置注册表才能以新 env 重新求值
    jest.resetModules();
  });
  afterEach(() => {
    if (savedEnv === undefined) delete process.env.AUDIT_RETENTION_DAYS;
    else process.env.AUDIT_RETENTION_DAYS = savedEnv;
    jest.resetModules();
  });

  const runRetentionCheck = () => {
    const gate = require('../../../scripts/compliance-check.js');
    const checkRetention = gate.COMPLIANCE_CHECKS.find((f) => f.name === 'checkRetention');
    const rows = gate.runRegisteredChecks([checkRetention]);
    expect(rows).toHaveLength(1);
    return rows[0];
  };

  it('AUDIT_RETENTION_DAYS=1 被钳制 ⇒ 结论不通过，detail 指名原始配置', () => {
    process.env.AUDIT_RETENTION_DAYS = '1';
    const retention = require('../../../src/constants/retention');
    expect(retention.wasAdjusted).toBe(true);
    expect(retention.RETENTION_DAYS).toBe(90);
    const row = runRetentionCheck();
    expect(row.passed).toBe(false);
    expect(row.detail).toContain('原始配置 1');
  });

  it('未配置 ⇒ 默认 180 原样生效 ⇒ 通过（证明红是因为钳制，不是判据写死为假）', () => {
    delete process.env.AUDIT_RETENTION_DAYS;
    const retention = require('../../../src/constants/retention');
    expect(retention.wasAdjusted).toBe(false);
    const row = runRetentionCheck();
    expect(row.passed).toBe(true);
  });
});
