'use strict';

/**
 * （2026-09-19）：WAL 的两条"崩溃后唯一取证残留"防线
 *
 * `AUDIT_WAL_MAX_BYTES` 原实现 `Number(env) || 50MB`：负数是**被静默接受的真值**，
 *   而 `stat.size <= 负数` 恒假 ⇒ 每次抽查都判定"超限"并弃掉一半行 ⇒ WAL 被持续销毁式裁剪。
 *   （测试会注入 1/200 这类小正数，所以修法只能是"非有限正数按未配置处理 + 告警"，
 *    不能是最小值钳制。）
 * WAL 的格式契约是"每行一条 JSON"，但换行由调用方负责。少一个 '\n' 会把相邻两条
 *   记录拼成同一行 ⇒ 两条同时不可恢复，而且拼出来的行解析不出 `__walSeq`，
 *   裁剪（F-97 后按序号精确匹配）再也认不得它 ⇒ 那行永远留在 WAL 里。
 *   现在写路径自己补齐行尾。
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const logger = require('../../src/utils/logger');
const wal = require('../../src/services/auditBufferWal');

const saved = {
  max: process.env.AUDIT_WAL_MAX_BYTES,
  interval: process.env.AUDIT_WAL_STAT_INTERVAL,
};
let dir = null;

function startWal() {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'zzqoder-wal-'));
  wal.startup(path.join(dir, 'audit-buffer.test.wal'));
  process.env.AUDIT_WAL_STAT_INTERVAL = '1'; // 每次追加都抽查大小，让上限判据立即生效
  return wal.getWalPath();
}

afterEach(() => {
  wal.disable();
  wal.resetCounters();
  delete process.env.AUDIT_WAL_MAX_BYTES;
  if (saved.interval === undefined) delete process.env.AUDIT_WAL_STAT_INTERVAL;
  else process.env.AUDIT_WAL_STAT_INTERVAL = saved.interval;
  if (dir) fs.rmSync(dir, { recursive: true, force: true });
  dir = null;
});

/** 追加 n 条带序号的假记录（模拟 auditBuffer 的行格式：文档 + __walSeq 一起序列化） */
async function appendDocs(n, { withNewline = true, seqPrefix = 'run' } = {}) {
  for (let i = 0; i < n; i += 1) {
    const line = JSON.stringify({
      seq: i,
      __walSeq: `${seqPrefix}-${i}`,
      msg: `m-${i}`.padEnd(24, 'x'),
    });
    wal.appendLine(withNewline ? `${line}\n` : line);
  }
  await wal.drain();
}

describe('zzqoder WAL 大小上限的非法配置', () => {
  test('AUDIT_WAL_MAX_BYTES 为负数 ⇒ 按默认处理，绝不逐次"超限"弃行', async () => {
    startWal();
    process.env.AUDIT_WAL_MAX_BYTES = '-1';
    const errSpy = jest.spyOn(logger, 'error').mockImplementation(() => {});
    try {
      await appendDocs(8);
      const lines = await wal.readLines();
      expect(lines).toHaveLength(8); // 旧行为：每追加一条就弃掉一半，最终只剩个位数
      expect(wal.getStats().walDroppedLines).toBe(0);
      const logged = errSpy.mock.calls.map((c) => c.join(' ')).join('\n');
      expect(logged).toContain('AUDIT_WAL_MAX_BYTES');
      expect(logged).toContain('非法');
    } finally {
      errSpy.mockRestore();
    }
  });

  test('同一个坏值只告警一次（本函数每次追加都会被调用）', async () => {
    startWal();
    process.env.AUDIT_WAL_MAX_BYTES = '-5';
    const errSpy = jest.spyOn(logger, 'error').mockImplementation(() => {});
    try {
      await appendDocs(5);
      expect(
        errSpy.mock.calls.filter((c) => String(c[0]).includes('AUDIT_WAL_MAX_BYTES'))
      ).toHaveLength(1);
    } finally {
      errSpy.mockRestore();
    }
  });

  test('正对照：合法的小阈值仍然真的裁剪（护栏没把止损能力一起废掉）', async () => {
    startWal();
    process.env.AUDIT_WAL_MAX_BYTES = '200'; // 约 2~3 行就超
    await appendDocs(8);
    const lines = await wal.readLines();
    expect(lines.length).toBeLessThan(8);
    expect(wal.getStats().walDroppedLines).toBeGreaterThan(0);
    // 保留的必须是**较新**的一半（与 BUFFER_HARD_LIMIT 丢最旧同向）
    expect(Number(JSON.parse(lines[lines.length - 1]).seq)).toBe(7);
  });

  test('未配置该变量时用 50MB 默认：正常小流量一条都不该被丢', async () => {
    startWal();
    delete process.env.AUDIT_WAL_MAX_BYTES;
    await appendDocs(10);
    expect(await wal.readLines()).toHaveLength(10);
    expect(wal.getStats().walDroppedLines).toBe(0);
  });
});

describe('zzqoder WAL 行尾由写路径自己补齐', () => {
  test('调用方漏掉换行也不会把两条记录拼成一行', async () => {
    const file = startWal();
    await appendDocs(4, { withNewline: false });
    const raw = fs.readFileSync(file, 'utf8');
    expect(raw.endsWith('\n')).toBe(true);
    expect(raw.split('\n').filter(Boolean)).toHaveLength(4);
    const lines = await wal.readLines();
    expect(lines).toHaveLength(4);
    // 每一行都必须单独可解析——旧行为是 4 条拼成 1 条损坏行，四条取证记录同时报废
    lines.forEach((l, i) => expect(JSON.parse(l).seq).toBe(i));
  });

  test('正对照：调用方自带换行时不产生空行（补齐逻辑不许反向劣化）', async () => {
    const file = startWal();
    await appendDocs(3);
    const raw = fs.readFileSync(file, 'utf8');
    expect(raw).toBe(raw.replace(/\n\n+/g, '\n'));
    expect(raw.endsWith('\n')).toBe(true);
    expect(await wal.readLines()).toHaveLength(3);
  });

  test('行格式与裁剪的按序号语义仍然对齐（裁 2 条剩 2 条，且不误伤别的行）', async () => {
    startWal();
    await appendDocs(4);
    wal.trimBySeqs(['run-1', 'run-3']); // 刻意不按行序：裁第 2、4 行
    await wal.drain();
    const lines = await wal.readLines();
    // 旧实现按"文件前 N 行"裁剪，裁谁留下谁取决于行序而非落库事实（F-97）；
    // 现在必须精确等于"未被点名的那两行"
    expect(lines.map((l) => JSON.parse(l).seq)).toEqual([0, 2]);
  });

  test('裁剪集合里的未知序号只裁不到东西，一行都不许动（空洞场景的结构保证）', async () => {
    startWal();
    await appendDocs(3);
    wal.trimBySeqs(['别的进程-7', '别的进程-8']);
    await wal.drain();
    expect(await wal.readLines()).toHaveLength(3);
  });
});
