/** 取证清单的 B-3（写失败重试）/ B-4（时钟回拨）/ B-5（保留与归档）三条边界。 */
const fs = require('fs');
const os = require('os');
const path = require('path');

const manifest = require('../../services/forensicManifest');
const retry = require('../../services/forensicManifestRetry');
const prune = require('../../services/forensicManifestPrune');
const LOCK = require('../../services/forensicManifestLock');

const tmpdir = () => fs.mkdtempSync(path.join(os.tmpdir(), 'mret-'));
const AT = new Date('2026-11-01T02:00:00.000Z');

describe('B-4 时钟回拨：必须能与篡改区分开', () => {
  beforeEach(() => manifest.resetManifestState());

  test('批次时间倒流 ⇒ 报 clock_skew 并点名行号（不再与篡改混为一谈）', async () => {
    const dir = tmpdir();
    await manifest.appendBatch({
      dir,
      recordHashes: ['a'.repeat(64)],
      now: new Date('2026-11-01T05:00:00.000Z'),
    });
    await manifest.appendBatch({
      dir,
      recordHashes: ['b'.repeat(64)],
      now: new Date('2026-11-01T04:00:00.000Z'),
    });
    const v = manifest.verifyManifest({ dir, date: AT });
    expect(v.problems.map((p) => p.type)).toContain('clock_skew');
    expect(v.problems.find((p) => p.type === 'clock_skew').line).toBe(2);
  });

  test('正常递增 ⇒ 不得误报 clock_skew（否则判据只是恒红）', async () => {
    const dir = tmpdir();
    for (const h of ['a', 'b', 'c']) {
      await manifest.appendBatch({ dir, recordHashes: [h.repeat(64)], now: AT });
    }
    const v = manifest.verifyManifest({ dir, date: AT });
    expect(v.problems.map((p) => p.type)).not.toContain('clock_skew');
    expect(v.ok).toBe(true);
  });

  test('容差内的微小回退（NTP 微调）不算回拨，避免天天假红', async () => {
    const dir = tmpdir();
    await manifest.appendBatch({ dir, recordHashes: ['a'.repeat(64)], now: AT });
    await manifest.appendBatch({
      dir,
      recordHashes: ['b'.repeat(64)],
      now: new Date(AT.getTime() - 500),
    });
    const v = manifest.verifyManifest({ dir, date: AT });
    expect(v.problems.map((p) => p.type)).not.toContain('clock_skew');
  });
});

describe('B-3 写失败重试：批次不得因为一次失败就永久消失', () => {
  beforeEach(() => {
    manifest.resetManifestState();
    retry.resetRetryState();
    LOCK.resetLockState();
  });

  test('写失败的批次进待重试队列，下一次追加时按原顺序补写', async () => {
    const dir = tmpdir();
    fs.mkdirSync(dir, { recursive: true });
    const lockPath = path.join(dir, LOCK.LOCK_FILE);
    fs.writeFileSync(lockPath, 'held', 'utf8');
    process.env.FORENSIC_MANIFEST_LOCK_TIMEOUT_MS = '60';
    try {
      const r1 = await manifest.appendBatch({
        dir,
        recordHashes: ['a'.repeat(64)],
        firstSeq: 'r-1',
        lastSeq: 'r-1',
        now: AT,
      });
      expect(r1.written).toBe(false);
      expect(retry.getRetryStats().pending).toBe(1);
      fs.unlinkSync(lockPath);
      const r2 = await manifest.appendBatch({
        dir,
        recordHashes: ['b'.repeat(64)],
        firstSeq: 'r-2',
        lastSeq: 'r-2',
        now: AT,
      });
      expect(r2.written).toBe(true);
      const v = manifest.verifyManifest({ dir, date: AT });
      expect(v.problems).toEqual([]);
      expect(v.count).toBe(2);
      expect(retry.getRetryStats().retried).toBe(1);
      expect(retry.getRetryStats().pending).toBe(0);
    } finally {
      delete process.env.FORENSIC_MANIFEST_LOCK_TIMEOUT_MS;
    }
  });

  test('补写必须保持原顺序（链序错了等于白补）', async () => {
    const dir = tmpdir();
    fs.mkdirSync(dir, { recursive: true });
    const lockPath = path.join(dir, LOCK.LOCK_FILE);
    fs.writeFileSync(lockPath, 'held', 'utf8');
    process.env.FORENSIC_MANIFEST_LOCK_TIMEOUT_MS = '50';
    try {
      await manifest.appendBatch({ dir, recordHashes: ['a'.repeat(64)], now: AT });
      await manifest.appendBatch({ dir, recordHashes: ['b'.repeat(64)], now: AT });
      expect(retry.getRetryStats().pending).toBe(2);
      fs.unlinkSync(lockPath);
      await manifest.appendBatch({ dir, recordHashes: ['c'.repeat(64)], now: AT });
      const read = manifest.readManifest({ dir, date: AT });
      const digests = read.entries.map((e) => e.hashesDigest);
      const expected = ['a', 'b', 'c'].map(
        (h) => manifest.batchEntryOf({ recordHashes: [h.repeat(64)], now: AT }).hashesDigest
      );
      expect(digests).toEqual(expected);
    } finally {
      delete process.env.FORENSIC_MANIFEST_LOCK_TIMEOUT_MS;
    }
  });

  test('队列必须有界：写不进去一直堆会撑爆内存，超限丢弃且计数可见', () => {
    const max = retry.MAX_PENDING;
    for (let i = 0; i < max + 5; i += 1) {
      retry.enqueue({ dir: '/nowhere', recordHashes: ['x'], now: AT });
    }
    const s = retry.getRetryStats();
    expect(s.pending).toBe(max);
    expect(s.droppedPending).toBe(5);
  });
});

describe('B-5 保留与归档：老清单文件必须归档而不是静默删除', () => {
  // --randomize 乱序防护：prunedFiles 是 forensicManifestPrune 模块级累计计数，
  // manifest.resetManifestState 只重置 manifest 侧，不重置 prune 侧——乱序下
  // 前序 describe 的 prune 会把本用例的「计数=1」推成 2。
  beforeEach(() => {
    manifest.resetManifestState();
    prune.resetPruneState();
  });

  test('超过保留期的日文件被归档到 .discarded 并计数（不是删掉）', () => {
    const dir = tmpdir();
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, '2026-08-01.jsonl'), '{}\n', 'utf8');
    fs.writeFileSync(path.join(dir, '2026-10-31.jsonl'), '{}\n', 'utf8');
    fs.writeFileSync(path.join(dir, '2026-11-01.jsonl'), '{}\n', 'utf8');

    const r = prune.pruneManifest({ dir, keepDays: 60, today: '2026-11-01' });
    expect(r.archived).toEqual(['2026-08-01.jsonl']);
    expect(r.kept).toBe(2);
    expect(fs.existsSync(path.join(dir, '.discarded', '2026-08-01.jsonl'))).toBe(true);
    expect(fs.existsSync(path.join(dir, '2026-08-01.jsonl'))).toBe(false);
    expect(prune.getPruneStats().prunedFiles).toBe(1);
  });

  test('保留期内一个都不动（否则等于自己把证据删了）', () => {
    const dir = tmpdir();
    fs.mkdirSync(dir, { recursive: true });
    for (const d of ['2026-10-30', '2026-10-31', '2026-11-01']) {
      fs.writeFileSync(path.join(dir, d + '.jsonl'), '{}\n', 'utf8');
    }
    const r = prune.pruneManifest({ dir, keepDays: 60, today: '2026-11-01' });
    expect(r.archived).toEqual([]);
    expect(r.kept).toBe(3);
  });

  test('非清单文件不得被动（锁文件、别的日志混在同目录时不误伤）', () => {
    const dir = tmpdir();
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, '2026-01-01.jsonl'), '{}\n', 'utf8');
    fs.writeFileSync(path.join(dir, '.manifest.lock'), 'x', 'utf8');
    fs.writeFileSync(path.join(dir, 'README.md'), 'x', 'utf8');
    const r = prune.pruneManifest({ dir, keepDays: 60, today: '2026-11-01' });
    expect(r.archived).toEqual(['2026-01-01.jsonl']);
    expect(fs.existsSync(path.join(dir, 'README.md'))).toBe(true);
  });

  test('归档目录不可写等异常不得抛（清理是尽力而为，不能反过来拖垮主流程）', () => {
    const r = prune.pruneManifest({ dir: path.join(tmpdir(), 'nope', 'deep') });
    expect(r.archived).toEqual([]);
  });
});
