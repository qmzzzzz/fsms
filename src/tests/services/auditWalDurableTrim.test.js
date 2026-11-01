/**
 * 审计 WAL 超限裁剪：按「持久化承诺」分级（2026-10-21）
 *
 * 锁的不变式（这是 P1 修复的判据，不是实现细节）：
 *   1. `auditOutbox` 写出的行带 `__walDurable`，它代表"敏感操作已向调用方回成功"；
 *   2. `.discarded` 永不回灌（auditBuffer 的 start() 只读序号用于跳过），
 *      因此 durable 行一旦被裁 = "承诺已持久化却永久不入库"；
 *   3. 所以超限裁剪必须**先丢普通行**，普通行不足时默认**停手**，
 *      只有显式 `AUDIT_WAL_ALLOW_DURABLE_TRIM=true` 才允许裁 durable 并单独计数。
 *
 * 可证伪性：把 `isDurableLine` 改成恒返回 false（等价于退回"按位置丢最旧一半"），
 * 用例 1 会红（durable 行被裁）；把 `allowDurableTrim` 改成恒 true，
 * 用例 2 会红（本该拒绝却裁了）。两条都不是"函数被调用"式断言。
 */

const fs = require('fs');
const os = require('os');
const path = require('path');

const cap = require('../../services/auditWalCap');
const wal = require('../../services/auditBufferWal');

/** 一条 WAL 行；durable=true 时带上 outbox 的持久化承诺标记 */
const walLine = (seq, durable) =>
  `${JSON.stringify({
    action: 'zzq_durable_trim',
    seq,
    __walSeq: `zzq-${seq}`,
    ...(durable ? { __walDurable: true } : {}),
  })}\n`;

describe('审计 WAL 超限裁剪按持久化承诺分级', () => {
  let tmpDir;
  let walPath;

  /** 与 auditBufferWal.readWalRecords 同形的读实现（只读文件，不碰模块状态） */
  const readWalRecords = async () => {
    const content = fs.readFileSync(walPath, 'utf8');
    if (!content) return { records: [], content: '' };
    const parts = content.split('\n');
    const hasTrailingNewline = parts[parts.length - 1] === '';
    return { records: hasTrailingNewline ? parts.slice(0, -1) : parts, content };
  };
  const atomicReplaceWal = async (nextContent) => {
    fs.writeFileSync(walPath, nextContent, 'utf8');
  };

  const enforce = () => cap.enforceWalLimit({ walPath, readWalRecords, atomicReplaceWal });

  const writeLines = (lines) => {
    fs.writeFileSync(walPath, lines.join(''), 'utf8');
  };

  const remaining = () =>
    fs
      .readFileSync(walPath, 'utf8')
      .split('\n')
      .filter(Boolean)
      .map((l) => JSON.parse(l));

  const durableCount = () => remaining().filter((d) => d.__walDurable === true).length;

  beforeAll(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'audit-wal-durable-'));
    walPath = path.join(tmpDir, 'test.wal');
  });

  beforeEach(() => {
    cap.resetCounters();
    delete process.env.AUDIT_WAL_ALLOW_DURABLE_TRIM;
    // 指标是模块级 Map，跨用例累积；不清会让"本次是否上报"变成看用例顺序
    require('../../utils/metricsAuditDrops')._auditDrops.delete('wal_durable_lost');
    // 阈值只用于让 stat.size 判超限；本套件自己写文件，不经过追加路径
    process.env.AUDIT_WAL_MAX_BYTES = '100';
    process.env.AUDIT_WAL_STAT_INTERVAL = '1';
    // 同目录复用 walPath：前序用例的归档会留在这里，不清理会让
    // 「本轮未裁剪 ⇒ 不应有 .discarded」这条断言被前序产物污染成假红。
    fs.rmSync(`${walPath}.discarded`, { force: true });
  });

  afterAll(() => {
    delete process.env.AUDIT_WAL_ALLOW_DURABLE_TRIM;
    delete process.env.AUDIT_WAL_MAX_BYTES;
    delete process.env.AUDIT_WAL_STAT_INTERVAL;
    try {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    } catch (_) {
      /* 忽略 */
    }
  });

  test('普通行足够时，durable 行一条都不裁', async () => {
    // 7 行 ⇒ dropTarget = 3；普通行 4 条 ⇒ 足够
    writeLines([
      walLine(0, false),
      walLine(1, true),
      walLine(2, false),
      walLine(3, true),
      walLine(4, false),
      walLine(5, true),
      walLine(6, false),
    ]);

    await enforce();

    // 丢的必须是最旧 3 条**普通**行（seq 0/2/4），durable 三条全留
    expect(cap.getStats().walDroppedLines).toBe(3);
    expect(cap.getStats().walDurableTrimRefusals).toBe(0);
    expect(cap.getStats().walDurableDropped).toBe(0);

    const kept = remaining();
    expect(kept).toHaveLength(4);
    expect(durableCount()).toBe(3);
    // 保留的普通行必须是**较新**的那条（seq 6），证明"最旧优先"在普通行内部仍成立
    expect(kept.filter((d) => d.__walDurable !== true).map((d) => d.seq)).toEqual([6]);
  });

  test('普通行不足且未显式放开时，拒绝裁剪 durable 行', async () => {
    // 5 行 ⇒ dropTarget = 2；普通行只有 1 条 ⇒ shortfall = 1
    writeLines([
      walLine(0, false),
      walLine(1, true),
      walLine(2, true),
      walLine(3, true),
      walLine(4, true),
    ]);

    await enforce();

    expect(cap.getStats().walDurableTrimRefusals).toBe(1);
    expect(cap.getStats().walDurableDropped).toBe(0);
    // 只裁掉了那 1 条普通行，durable 4 条原样保留
    expect(cap.getStats().walDroppedLines).toBe(1);
    expect(durableCount()).toBe(4);
  });

  test('显式放开后允许裁 durable，并单独计数', async () => {
    process.env.AUDIT_WAL_ALLOW_DURABLE_TRIM = 'true';
    writeLines([
      walLine(0, false),
      walLine(1, true),
      walLine(2, true),
      walLine(3, true),
      walLine(4, true),
    ]);

    await enforce();

    expect(cap.getStats().walDurableTrimRefusals).toBe(0);
    // dropTarget = 2：1 条普通 + 1 条最旧 durable（seq 1）
    expect(cap.getStats().walDurableDropped).toBe(1);
    expect(cap.getStats().walDroppedLines).toBe(2);
    expect(durableCount()).toBe(3);
    // 必须进 Prometheus：这条路径的严重度高于其余 drop reason，
    // 只写日志 + 面板 JSON 等于"丢了承诺却没人被叫醒"。
    expect(require('../../utils/metricsAuditDrops')._auditDrops.get('wal_durable_lost')).toBe(1);
  });

  test('全是 durable 且未放开时不动文件（避免空归档）', async () => {
    writeLines([walLine(0, true), walLine(1, true), walLine(2, true)]);
    const before = fs.readFileSync(walPath, 'utf8');

    await enforce();

    expect(cap.getStats().walDurableTrimRefusals).toBe(1);
    expect(cap.getStats().walDroppedLines).toBe(0);
    expect(fs.readFileSync(walPath, 'utf8')).toBe(before);
    // 未发生裁剪 ⇒ 不应产生 .discarded（空归档会污染"被丢弃取证"的语义）
    expect(fs.existsSync(`${walPath}.discarded`)).toBe(false);
    // 拒绝必须可被 Prometheus 看见：这是"WAL 正在无界增长"的唯一早期信号，
    // 只写 error 日志等于等磁盘写满才发现。
    const rendered = require('../../utils/metricsAuditDrops').formatAuditDrops().join('\n');
    expect(rendered).toContain('audit_wal_durable_trim_refusals_total 1');
  });

  test('重放时剥掉 __walDurable，但保留 __walSeq', async () => {
    const seen = [];
    const line = JSON.stringify({ action: 'zzq_replay', __walSeq: 'zzq-r1', __walDurable: true });
    // 已有 __walSeq ⇒ 不触发回写（dirty=false），不会碰磁盘上的 WAL 文件
    await wal.stampReplaySeqs([line], (doc) => seen.push(doc));

    expect(seen).toHaveLength(1);
    expect(seen[0].__walSeq).toBe('zzq-r1');
    expect(seen[0].__walDurable).toBeUndefined();
  });
  test('普通行被裁必须进 Prometheus：wal_trim_ordinary，与 durable 的 wal_durable_lost 分开', async () => {
    // 第十一轮 D5：普通行被裁只累加 walDroppedLines（JSON/面板），不进指标；
    // 而 .discarded 永不回灌 ⇒ 它们同样是永久丢失。这条按"降到零"的方式钉住上报。
    const drops = require('../../utils/metricsAuditDrops');
    const incSpy = jest.spyOn(drops, 'incAuditDrop').mockImplementation(() => {});
    writeLines([0, 1, 2, 3, 4, 5, 6].map((s) => walLine(s, false)));
    try {
      await enforce();
      expect(cap.getStats().walDroppedLines).toBe(3);
      expect(incSpy.mock.calls).toEqual([['wal_trim_ordinary', 3]]);
    } finally {
      incSpy.mockRestore();
    }
  });

  test('两种丢弃的标签可区分：混合裁剪时普通行与 durable 行各报各的', async () => {
    process.env.AUDIT_WAL_ALLOW_DURABLE_TRIM = 'true';
    const drops = require('../../utils/metricsAuditDrops');
    const incSpy = jest.spyOn(drops, 'incAuditDrop').mockImplementation(() => {});
    // 7 行 ⇒ dropTarget = 3：普通 2 条（seq 0/2）+ 最旧 durable 1 条（seq 1）
    writeLines([
      walLine(0, false),
      walLine(1, true),
      walLine(2, false),
      walLine(3, true),
      walLine(4, true),
      walLine(5, true),
      walLine(6, true),
    ]);
    try {
      await enforce();
      expect(cap.getStats().walDroppedLines).toBe(3);
      expect(incSpy.mock.calls).toEqual([
        ['wal_trim_ordinary', 2],
        ['wal_durable_lost', 1],
      ]);
    } finally {
      incSpy.mockRestore();
    }
  });
});
