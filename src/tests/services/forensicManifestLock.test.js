/**
 * B-1 跨进程并发：单进程串行链管不住多进程同时写同一份清单。
 *
 * 判据必须用**真子进程**验：同进程内的并发已有 appendChain 保护，测不出跨进程分叉。
 */
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');

const LOCK = require('../../services/forensicManifestLock');
const manifest = require('../../services/forensicManifest');

const REPO = path.resolve(__dirname, '../../..');
const MANIFEST_PATH = path.join(REPO, 'src/services/forensicManifest.js');
const AT = '2026-11-01T02:00:00.000Z';
const tmpdir = () => fs.mkdtempSync(path.join(os.tmpdir(), 'mlock-'));

const childScript = (dir, seq) =>
  [
    `const M = require(${JSON.stringify(MANIFEST_PATH)});`,
    '(async () => {',
    '  for (let i = 0; i < 6; i += 1) {',
    '    await M.appendBatch({',
    `      dir: ${JSON.stringify(dir)},`,
    `      recordHashes: [String(i + ${seq}).repeat(64)],`,
    `      firstSeq: 'p${seq}-' + i,`,
    `      lastSeq: 'p${seq}-' + i,`,
    `      now: new Date(${JSON.stringify(AT)}),`,
    '    });',
    '  }',
    '})().catch((e) => { console.error(e); process.exit(1); });',
  ].join('\n');

describe('B-1 跨进程锁：多进程同时追加不得把链写成分叉', () => {
  beforeEach(() => LOCK.resetLockState());

  test('【核心验收】两个真子进程各追加 6 批 ⇒ 链必须自洽（12 批全部串联）', () => {
    const dir = tmpdir();
    const run = (seq) => {
      const s = path.join(dir, `_child${seq}.js`);
      fs.writeFileSync(s, childScript(dir, seq), 'utf8');
      execFileSync(process.execPath, [s], { cwd: REPO, stdio: 'pipe' });
    };
    run(1);
    run(2);

    const v = manifest.verifyManifest({ dir, date: new Date(AT) });
    expect(v.problems).toEqual([]);
    expect(v.count).toBe(12);
  });

  test('互斥：并发的 withLock 不得重叠执行临界区', async () => {
    const dir = tmpdir();
    let active = 0;
    let maxActive = 0;
    const job = () =>
      LOCK.withLock(dir, { timeoutMs: 5000 }, async () => {
        active += 1;
        maxActive = Math.max(maxActive, active);
        await new Promise((r) => setTimeout(r, 10));
        active -= 1;
        return 'done';
      });
    const rs = await Promise.all(Array.from({ length: 8 }, job));
    expect(maxActive).toBe(1);
    expect(rs.every((r) => r.ok && r.value === 'done')).toBe(true);
  });

  test('拿不到锁 ⇒ 超时返回 lock_timeout，且不误删别人的锁', async () => {
    const dir = tmpdir();
    fs.mkdirSync(dir, { recursive: true });
    const lockPath = path.join(dir, LOCK.LOCK_FILE);
    fs.writeFileSync(lockPath, 'held-by-someone', 'utf8');
    const r = await LOCK.withLock(dir, { timeoutMs: 120 }, async () => 'never');
    expect(r.ok).toBe(false);
    expect(r.reason).toBe('lock_timeout');
    expect(LOCK.getLockStats().lockTimeouts).toBe(1);
    expect(fs.existsSync(lockPath)).toBe(true);
  });

  test('崩溃残留的陈旧锁可以被接管，且接管次数可见（不静默）', async () => {
    const dir = tmpdir();
    fs.mkdirSync(dir, { recursive: true });
    const lockPath = path.join(dir, LOCK.LOCK_FILE);
    fs.writeFileSync(lockPath, 'crashed-holder', 'utf8');
    const old = new Date(Date.now() - 60 * 60 * 1000);
    fs.utimesSync(lockPath, old, old);
    const r = await LOCK.withLock(dir, { staleMs: 1000, timeoutMs: 1000 }, async () => 'ok');
    expect(r.ok).toBe(true);
    expect(r.value).toBe('ok');
    expect(LOCK.getLockStats().staleTakeovers).toBe(1);
  });

  test('临界区抛错也必须释放锁（否则一次异常会把清单永久锁死）', async () => {
    const dir = tmpdir();
    await expect(
      LOCK.withLock(dir, {}, async () => {
        throw new Error('boom');
      })
    ).rejects.toThrow('boom');
    expect(fs.existsSync(path.join(dir, LOCK.LOCK_FILE))).toBe(false);
  });

  test('正常结束不残留锁文件（否则下次启动全部超时）', async () => {
    const dir = tmpdir();
    const r = await LOCK.withLock(dir, {}, async () => 'v');
    expect(r.ok).toBe(true);
    expect(fs.existsSync(path.join(dir, LOCK.LOCK_FILE))).toBe(false);
  });

  test('锁超时必须 fail-visible：appendBatch 计 writeFailures 并给出可诊断原因', async () => {
    manifest.resetManifestState();
    const dir = tmpdir();
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, LOCK.LOCK_FILE), 'held', 'utf8');
    process.env.FORENSIC_MANIFEST_LOCK_TIMEOUT_MS = '80';
    try {
      const r = await manifest.appendBatch({ dir, recordHashes: ['a'.repeat(64)] });
      expect(r.written).toBe(false);
      expect(r.reason).toBe('lock_timeout');
      expect(manifest.getManifestStats().writeFailures).toBe(1);
      expect(manifest.getManifestStats().lastError).toMatch(/lock/i);
    } finally {
      delete process.env.FORENSIC_MANIFEST_LOCK_TIMEOUT_MS;
    }
  });
});
