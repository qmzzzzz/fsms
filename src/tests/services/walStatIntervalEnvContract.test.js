/**
 * AUDIT_WAL_STAT_INTERVAL 的判据契约（对方交接 §49.2 交回来的一条）
 *
 * 修复前那一行是 `Math.max(1, Number(env) || 32)`，而它上面的注释写着
 * "0/负值按 1 处理（恢复逐条检查，供测试注入）"。本机 `node -e` 实测：
 *   "0"→32   "-5"→1   "abc"→32   "2.5"→2.5   ""→32
 * 也就是**只有负值**兑现了注释；`0` 被 `||` 吞成 32 —— 注释承诺的最保守那一档
 * 恰好给出最松那一档，且零反馈。`2.5` 原样生效后 `count % 2.5 === 0` 实际等价"每 5 次"，
 * 同样不是注释说的值。按本仓口径，假注释本身就是缺陷（下一个读代码的人会照它办事）。
 *
 * 现在收口到仓内统一判据 utils/envNumber：只有正整数被采纳，其余（含 0）回落默认 32
 * 并留一条 warn。刻意**不**给 0 保留"按 1 处理"的第二种拼法——要逐条检查就注入 1，
 * 那是既有测试的实际做法；同一个意图留两种写法，正是刚才那句假注释的来路。
 *
 * 判据是行为面的，不是源码文本面的：抽查间隔唯一可观测的后果是
 * "N 次追加之内到底有没有去 stat 文件大小、有没有真的裁剪"。
 * 所以每条臂都用 MAX_BYTES=200 + 固定追加次数驱动，读 getStats() 的裁剪计数。
 * 注意臂与臂之间换 AUDIT_WAL_PATH：WAL 文件是跨用例留存的，不换文件的话
 * "这一轮没裁剪"会被上一轮留下的超限状态污染。
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const { TEST_CLIENT_IP } = require('../fixtures');
const logger = require('../../utils/logger');

// 每臂追加条数：足够越过 200 字节上限（单条审计行 ~150-250 字节），
// 又远小于回落后的默认间隔 32 ⇒ "间隔被回落成 32" 与 "间隔是 1" 在计数上可分。
const APPENDS = 10;

describe('AUDIT_WAL_STAT_INTERVAL：只有正整数被采纳，非法值回落默认并留痕', () => {
  let tmpDir;
  let auditBuffer;
  let wal;
  let arm = 0;

  beforeAll(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'wal-stat-interval-'));
    process.env.AUDIT_WAL_MAX_BYTES = '200';
    auditBuffer = require('../../services/auditBuffer');
    wal = require('../../services/auditBufferWal');
  });

  afterAll(() => {
    auditBuffer.stop();
    delete process.env.AUDIT_WAL_STAT_INTERVAL;
    delete process.env.AUDIT_WAL_MAX_BYTES;
    try {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    } catch (_) {
      /* 忽略 */
    }
  });

  /**
   * 注入一个间隔值、写 APPENDS 条审计、返回这一轮的裁剪计数与 warn 文案。
   * 每臂独占一个 WAL 文件（见文件头说明），计数器靠 __resetForTest 归零。
   */
  const drive = async (rawValue) => {
    auditBuffer.stop();
    await wal.drain();
    const tag = rawValue === undefined ? 'unset' : `v${++arm}`;
    process.env.AUDIT_WAL_PATH = path.join(tmpDir, `iv-${tag}.wal`);
    if (rawValue === undefined) delete process.env.AUDIT_WAL_STAT_INTERVAL;
    else process.env.AUDIT_WAL_STAT_INTERVAL = String(rawValue);
    auditBuffer.__resetForTest();

    const warnSpy = jest.spyOn(logger, 'warn').mockImplementation(() => {});
    try {
      auditBuffer.start();
      for (let i = 0; i < APPENDS; i++) {
        auditBuffer.push({
          action: 'wal_iv_probe',
          category: 'auth',
          ip: TEST_CLIENT_IP,
          success: true,
          seq: i,
        });
      }
      await wal.drain();
      const stats = auditBuffer.getStats();
      const text = warnSpy.mock.calls.map((c) => c.join(' ')).join('\n');
      return { stats, text };
    } finally {
      warnSpy.mockRestore();
    }
  };

  const trimmed = (s) => s.walDroppedLines + s.walTrimFailures;

  test('活体对照：间隔 1 时这 APPENDS 条里必须真的发生裁剪（否则下面每条负断言都是假绿）', async () => {
    const { stats, text } = await drive('1');
    expect(trimmed(stats)).toBeGreaterThan(0);
    expect(stats.walAppendFailures).toBe(0);
    // 合法值不得触发任何"非法"告警
    expect(text).not.toContain('AUDIT_WAL_STAT_INTERVAL');
  });

  test('0 ⇒ 回落默认 32（修复前注释承诺的是 1，实测给的是最松那一档）', async () => {
    const { stats, text } = await drive('0');
    expect(trimmed(stats)).toBe(0); // 10 次追加内一次都没抽查
    expect(text).toContain('AUDIT_WAL_STAT_INTERVAL');
  });

  test('-5 ⇒ 回落默认 32（修复前这里按 1 生效，方向与其余旋钮相反）', async () => {
    const { stats, text } = await drive('-5');
    expect(trimmed(stats)).toBe(0);
    expect(text).toContain('AUDIT_WAL_STAT_INTERVAL');
  });

  test('2.5 ⇒ 回落默认 32（修复前原样生效，且 % 2.5 实际等价"每 5 次"）', async () => {
    const { stats, text } = await drive('2.5');
    expect(trimmed(stats)).toBe(0);
    expect(text).toContain('AUDIT_WAL_STAT_INTERVAL');
  });

  test('abc ⇒ 回落默认 32 并留痕', async () => {
    const { stats, text } = await drive('abc');
    expect(trimmed(stats)).toBe(0);
    expect(text).toContain('AUDIT_WAL_STAT_INTERVAL');
  });

  test('未设置 ⇒ 默认 32，且一条告警都不产生（"没配"不是错误）', async () => {
    const { stats, text } = await drive(undefined);
    expect(trimmed(stats)).toBe(0);
    expect(text).not.toContain('AUDIT_WAL_STAT_INTERVAL');
  });

  test('空串按"未配置"处理：回落默认且不告警（与仓内统一判据同口径）', async () => {
    const { stats, text } = await drive('');
    expect(trimmed(stats)).toBe(0);
    expect(text).not.toContain('AUDIT_WAL_STAT_INTERVAL');
  });

  test('边界 1 之外的合法值仍被采纳：间隔 5 ⇒ 10 次追加内会抽查到并裁剪', async () => {
    // 这条与"2.5 ⇒ 不裁"是一对：如果哪天有人把 integer 校验去掉，
    // 2.5 会重新被接受并在第 5、第 10 次命中 % 判据 ⇒ 上面的 2.5 臂变红。
    const { stats } = await drive('5');
    expect(trimmed(stats)).toBeGreaterThan(0);
  });
});
