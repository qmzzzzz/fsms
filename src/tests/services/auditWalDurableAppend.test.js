/**
 * 敏感操作审计 outbox 的「先 fsync 落盘再回成功」路径直测。
 *
 * auditOutbox.test.js 把 wal.appendLineDurable / auditOutbox.spool 都 mock 掉了，
 * 只证明"调用了哪个函数"。这里用真实临时文件覆盖承重行为：
 *  - appendLineDurable 只有 write+fsync 完成后才 resolve(true)；
 *  - 并发追加串行化，不产生交错行；
 *  - 未启用 / 写失败都返回 false（调用方据此 fail-closed，而不是抛错或假装成功）；
 *  - outbox.spool 先落 WAL 成功、再以 push(doc, true) 放进内存缓冲。
 */
const fs = require('fs');
const os = require('os');
const path = require('path');

const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'wal-durable-'));
const walPath = path.join(tmpDir, 'durable.wal');

const wal = require('../../services/auditBufferWal');
const auditBuffer = require('../../services/auditBuffer');
const auditOutbox = require('../../services/auditOutbox');

/** 一份能通过 AuditLog schema 的最小文档 */
const validEntry = () => ({
  action: 'password_changed',
  category: 'auth',
  userId: '507f1f77bcf86cd799439011',
  username: 'durable',
  success: true,
});

const removeWal = () => {
  try {
    fs.rmSync(walPath, { recursive: true, force: true });
  } catch (_) {
    /* 尽力清理 */
  }
};

afterEach(() => {
  auditBuffer.__resetForTest();
  wal.disable();
  wal.resetCounters();
  removeWal();
});

afterAll(() => {
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

describe('审计 WAL fsync 追加', () => {
  test('appendLineDurable 落盘后才 resolve(true)', async () => {
    expect(wal.startup(walPath)).toBe(true);
    wal.resetCounters();
    const line = JSON.stringify({ tag: 'one', __walSeq: 'x' }) + '\n';

    await expect(wal.appendLineDurable(line)).resolves.toBe(true);

    expect(fs.readFileSync(walPath, 'utf8')).toBe(line);
    expect(wal.getStats().walAppendFailures).toBe(0);
  });

  test('并发追加串行落盘：三条记录逐行完整，不交错', async () => {
    expect(wal.startup(walPath)).toBe(true);
    wal.resetCounters();
    const lines = ['a', 'b', 'c'].map((x) => JSON.stringify({ x }) + '\n');

    await expect(Promise.all(lines.map((l) => wal.appendLineDurable(l)))).resolves.toEqual([
      true,
      true,
      true,
    ]);

    const records = fs.readFileSync(walPath, 'utf8').split('\n').filter(Boolean);
    expect(records).toHaveLength(3);
    expect(records.map((r) => JSON.parse(r).x)).toEqual(['a', 'b', 'c']);
  });

  test('WAL 未启用 ⇒ false（调用方不得声称已留痕）', async () => {
    wal.disable();
    await expect(wal.appendLineDurable('{}\n')).resolves.toBe(false);
  });

  test('写失败 ⇒ false 且计入 walAppendFailures，不 reject', async () => {
    // 用目录占住 WAL 文件路径：open(path, 'a') 必然失败，但 startup 的目录探测仍通过。
    fs.mkdirSync(walPath, { recursive: true });
    expect(wal.startup(walPath)).toBe(true);
    wal.resetCounters();

    await expect(wal.appendLineDurable('{}\n')).resolves.toBe(false);

    expect(wal.getStats().walAppendFailures).toBe(1);
  });

  test('outbox spool：WAL 未启用时拒绝 spool，调用方据此重抛', async () => {
    wal.disable();
    auditBuffer.__resetForTest();

    await expect(auditOutbox.spool(validEntry())).resolves.toEqual({
      spooled: false,
      reason: 'wal_disabled',
    });
    expect(auditBuffer.getStats().bufferLength).toBe(0);
  });

  test('outbox spool：WAL fsync 成功后才入内存缓冲，且不重复追加一行', async () => {
    expect(wal.startup(walPath)).toBe(true);
    wal.resetCounters();
    auditBuffer.__resetForTest();

    await expect(auditOutbox.spool(validEntry())).resolves.toEqual({
      spooled: true,
      reason: null,
    });

    const lines = fs.readFileSync(walPath, 'utf8').split('\n').filter(Boolean);
    expect(lines).toHaveLength(1);
    const parsed = JSON.parse(lines[0]);
    expect(parsed.username).toBe('durable');
    expect(parsed.__walSeq).toBeTruthy();
    expect(auditBuffer.getStats().bufferLength).toBe(1);
  });
});
