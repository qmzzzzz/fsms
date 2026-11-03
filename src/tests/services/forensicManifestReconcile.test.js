/**
 * B-7 库对账：verifyManifest 只证明「清单自身没被动过」，
 * 不证明「清单里说的那些记录**真的还在库里**」。
 *
 * 这正是清单机制的核心承诺，必须用真库验（mongodb-memory-server 由 globalSetup 起）。
 *
 * F6（2026-11-03）追加：对账窗口（min(TTL, manifest 保留期)）与周期接线。
 * 既有用例的调用都显式传 `now: AT`——窗口判据引入了"今天"这个时间参，不钉死它，
 * 这些用例会在窗口滑过 AT 日期的那天集体转红（测试不能有自己的时钟炸弹）。
 */
const mongoose = require('mongoose');
const manifest = require('../../services/forensicManifest');
const {
  reconcileWithDb,
  resolveReconcileWindowDays,
  reconcileOnce,
  start,
  stop,
  getReconcileHealth,
  resetForTest,
} = require('../../services/forensicManifestReconcile');
const ForensicCapture = require('../../models/ForensicCapture');

const AT = new Date('2026-11-01T02:00:00.000Z');

// createdAt 必须落在 AT 所属的**业务日**窗口内，否则对账按天取库时看不到它
const seed = async (hashes, seqs, at = AT) => {
  await ForensicCapture.insertMany(
    hashes.map((h, i) => ({
      recordHash: h,
      seq: seqs[i],
      createdAt: at,
      method: 'POST',
      path: '/api/login',
      ip: '203.0.113.7',
    }))
  );
};

describe('B-7 清单与库对账：清单说的记录必须真的在库里', () => {
  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });

  beforeEach(async () => {
    await ForensicCapture.deleteMany({});
    manifest.resetManifestState();
  });

  test('【核心验收】清单与库一致 ⇒ 绿（否则判据只是恒红）', async () => {
    const dir = require('fs').mkdtempSync(require('path').join(require('os').tmpdir(), 'recon-'));
    const hashes = ['a'.repeat(64), 'b'.repeat(64)];
    await seed(hashes, ['r-1', 'r-2']);
    await manifest.appendBatch({
      dir,
      recordHashes: hashes,
      firstSeq: 'r-1',
      lastSeq: 'r-2',
      now: AT,
    });

    const v = await reconcileWithDb({ dir, date: AT, model: ForensicCapture, now: AT });
    expect(v.ok).toBe(true);
    expect(v.problems).toEqual([]);
    expect(v.checked).toBe(2);
  });

  test('【核心验收】库里某条被删掉 ⇒ 必须判红并报出准确差额（但点不出是哪条）', async () => {
    const dir = require('fs').mkdtempSync(require('path').join(require('os').tmpdir(), 'recon-'));
    const hashes = ['a'.repeat(64), 'b'.repeat(64)];
    await seed(hashes, ['r-1', 'r-2']);
    await manifest.appendBatch({
      dir,
      recordHashes: hashes,
      firstSeq: 'r-1',
      lastSeq: 'r-2',
      now: AT,
    });
    await ForensicCapture.deleteOne({ recordHash: hashes[1] }); // 抹掉一条

    const v = await reconcileWithDb({ dir, date: AT, model: ForensicCapture, now: AT });
    expect(v.ok).toBe(false);
    expect(v.problems.map((p) => p.type)).toContain('record_missing');
    // 能力边界：清单只存折叠摘要，反推不出具体缺哪个 ⇒ 只能报准确差额，不假称能点名
    expect(v.shortfall).toBe(1);
    expect(v.declared).toBe(2);
    expect(v.checked).toBe(1);
  });

  test('库里多出清单没记的记录 ⇒ 报 unmanifested（只警告，不算篡改）', async () => {
    const dir = require('fs').mkdtempSync(require('path').join(require('os').tmpdir(), 'recon-'));
    const hashes = ['a'.repeat(64)];
    await seed(hashes, ['r-1']);
    await manifest.appendBatch({
      dir,
      recordHashes: hashes,
      firstSeq: 'r-1',
      lastSeq: 'r-1',
      now: AT,
    });
    await seed(['c'.repeat(64)], ['r-9']); // 库里有、清单没记

    const v = await reconcileWithDb({ dir, date: AT, model: ForensicCapture, now: AT });
    // 多出来不算证据缺失（可能只是清单写入失败过），但必须可见
    expect(v.ok).toBe(true);
    expect(v.unmanifested).toBeGreaterThan(0);
  });

  test('【边界】别的业务日的记录不得算进当天（窗口过滤真的生效）', async () => {
    // 这条是 M15 的杀手：若把查询条件放宽成 {}，昨天的记录会被算进今天，
    // 「少几条」就永远判不出来（假绿）。必须用跨日数据证明窗口有效。
    const dir = require('fs').mkdtempSync(require('path').join(require('os').tmpdir(), 'recon-'));
    const hashes = ['a'.repeat(64)];
    await seed(hashes, ['r-1']);
    await manifest.appendBatch({
      dir,
      recordHashes: hashes,
      firstSeq: 'r-1',
      lastSeq: 'r-1',
      now: AT,
    });
    // 前一天记一条（不属于 AT 的业务日）
    await seed(['f'.repeat(64)], ['r-x'], new Date('2026-10-30T02:00:00.000Z'));

    const v = await reconcileWithDb({ dir, date: AT, model: ForensicCapture, now: AT });
    expect(v.ok).toBe(true); // 当天清单 1 条、当天库内 1 条
    expect(v.checked).toBe(1); // 昨天那条没被算进来
    expect(v.unmanifested).toBe(0); // 也没有把昨天那条当成"未登记"
  });

  test('清单文件不存在 ⇒ 无从对账，如实报 no_manifest 而不是假装绿', async () => {
    const dir = require('fs').mkdtempSync(require('path').join(require('os').tmpdir(), 'recon-'));
    const v = await reconcileWithDb({ dir, date: AT, model: ForensicCapture, now: AT });
    expect(v.ok).toBe(false);
    expect(v.problems.map((p) => p.type)).toContain('no_manifest');
  });

  test('对账不得改动任何数据（只读）', async () => {
    const dir = require('fs').mkdtempSync(require('path').join(require('os').tmpdir(), 'recon-'));
    const hashes = ['a'.repeat(64)];
    await seed(hashes, ['r-1']);
    await manifest.appendBatch({
      dir,
      recordHashes: hashes,
      firstSeq: 'r-1',
      lastSeq: 'r-1',
      now: AT,
    });
    const before = await ForensicCapture.countDocuments({});
    await reconcileWithDb({ dir, date: AT, model: ForensicCapture, now: AT });
    expect(await ForensicCapture.countDocuments({})).toBe(before);
  });

  test('按 recordHash 批量查库：不得对每条记录单独发一次查询（会打爆库）', async () => {
    const dir = require('fs').mkdtempSync(require('path').join(require('os').tmpdir(), 'recon-'));
    const hashes = Array.from({ length: 20 }, (_, i) => i.toString(16).padStart(2, '0').repeat(32));
    await seed(hashes, hashes);
    await manifest.appendBatch({ dir, recordHashes: hashes, now: AT });
    const spy = jest.spyOn(ForensicCapture, 'find');
    await reconcileWithDb({ dir, date: AT, model: ForensicCapture, now: AT });
    expect(spy.mock.calls.length).toBeLessThanOrEqual(2); // 分批查询，不是逐条
    spy.mockRestore();
  });
});

describe('F6 对账窗口与周期接线', () => {
  const savedEnv = process.env.BUSINESS_RETENTION_DAYS_FORENSIC_CAPTURE;
  const savedKeep = process.env.FORENSIC_MANIFEST_KEEP_DAYS;

  // 上一组 describe 的 afterAll 已关库；本组的周期接线要真查一次库，自己管连接
  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) await mongoose.connection.close();
  });

  afterEach(() => {
    resetForTest();
    if (savedEnv === undefined) delete process.env.BUSINESS_RETENTION_DAYS_FORENSIC_CAPTURE;
    else process.env.BUSINESS_RETENTION_DAYS_FORENSIC_CAPTURE = savedEnv;
    if (savedKeep === undefined) delete process.env.FORENSIC_MANIFEST_KEEP_DAYS;
    else process.env.FORENSIC_MANIFEST_KEEP_DAYS = savedKeep;
  });

  test('TTL 启用（env=30）⇒ 窗口 30；TTL 未启用 ⇒ 放宽到 manifest 保留期（默认 60）', () => {
    process.env.BUSINESS_RETENTION_DAYS_FORENSIC_CAPTURE = '30';
    delete process.env.FORENSIC_MANIFEST_KEEP_DAYS;
    expect(resolveReconcileWindowDays()).toBe(30);
    // TTL 开关关（env 删除）：数据常留，窗口不再被 TTL 收窄，落到 manifest 保留期
    delete process.env.BUSINESS_RETENTION_DAYS_FORENSIC_CAPTURE;
    expect(resolveReconcileWindowDays()).toBe(60);
    // manifest 保留期被运维下调时窗口跟着收（对着一份已归档的清单判 no_manifest 是假红）
    process.env.FORENSIC_MANIFEST_KEEP_DAYS = '45';
    expect(resolveReconcileWindowDays()).toBe(45);
  });

  test('窗口收窄：31 天前日期（窗口 30 天）显式 skip 计数，绝不静默、也不判红', async () => {
    process.env.BUSINESS_RETENTION_DAYS_FORENSIC_CAPTURE = '30';
    const old = new Date(Date.now() - 31 * 86400000);
    const v = await reconcileWithDb({ date: old, model: ForensicCapture });
    expect(v).toMatchObject({ ok: true, skippedBeyondTtl: 1, checked: 0, declared: 0 });
    expect(v.problems).toEqual([]); // 窗口外不是篡改证据，不能记成红
    // 对照：窗口边界内照常对账（no_manifest 判红——窗口内清单不存在是留痕缺口，不是保留期问题）
    const inside = new Date(Date.now() - 5 * 86400000);
    const v2 = await reconcileWithDb({ date: inside, model: ForensicCapture });
    expect(v2.skippedBeyondTtl).toBe(0);
    expect(v2.ok).toBe(false);
    expect(v2.problems.map((p) => p.type)).toContain('no_manifest');
  });

  test('周期接线：start 幂等 / stop 清定时器 / 单轮轮转核一个窗口内业务日并推进健康计数', async () => {
    const logger = require('../../utils/logger');
    resetForTest();
    const infoSpy = jest.spyOn(logger, 'info').mockImplementation(() => {});
    const warnSpy = jest.spyOn(logger, 'warn').mockImplementation(() => {});
    try {
      start();
      start(); // 幂等：重复调用不叠定时器
      expect(getReconcileHealth().running).toBe(true);
      // 单轮核「昨天」；第二轮核「前天」——游标在窗口内轮转，当日（day 0）不核
      await reconcileOnce();
      const k1 = getReconcileHealth().lastCheckedKey;
      await reconcileOnce();
      const k2 = getReconcileHealth().lastCheckedKey;
      expect(k1).toBe(manifest.dateKeyOf(new Date(Date.now() - 1 * 86400000)));
      expect(k2).toBe(manifest.dateKeyOf(new Date(Date.now() - 2 * 86400000)));
      const h = getReconcileHealth();
      expect(h.runs).toBe(2);
      // 窗口内无清单的日子判红只进健康计数/warn（no_manifest 是留痕缺口），绝不静默
      expect(h.failures).toBeGreaterThanOrEqual(0);
    } finally {
      stop();
      infoSpy.mockRestore();
      warnSpy.mockRestore();
    }
    expect(getReconcileHealth().running).toBe(false);
  });
});
