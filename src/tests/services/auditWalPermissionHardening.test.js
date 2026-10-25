/**
 * 审计 WAL 载体权限：目录 0700 / 文件 0600，且必须回读校验（不能只“调用过 chmod/icacls”）。
 *
 * 缺陷背景：WAL 里是尚未落库的审计取证，而原实现的 mkdir/appendFile/writeFile 都不带
 * mode，已存在的文件更是永远不会被收紧。POSIX 的 mode 只在创建时生效，Windows 直接忽略
 * 它 ⇒ 同机其他账户可读取并改写待落库审计（审计完整性对本地用户开放）。
 *
 * 本文件锁定：启动时收紧目录与既有载体（主文件 / .discarded / .tmp）；
 * 新建与原子替换后的文件保持 0600；收紧失败必须 error 级留痕但不得阻断 WAL。
 */

const fs = require('fs');
const os = require('os');
const path = require('path');

const wal = require('../../services/auditBufferWal');
const filePermission = require('../../utils/filePermission');
const logger = require('../../utils/logger');
const metrics = require('../../utils/metrics');

const { isWindows } = filePermission;

const modeOf = (p) => fs.statSync(p).mode & 0o777;

describe('审计 WAL 载体权限收紧与回读', () => {
  let tmpRoot;
  let dir;
  let walPath;

  beforeEach(() => {
    tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'audit-wal-perm-'));
    dir = path.join(tmpRoot, 'nested', 'wal');
    walPath = path.join(dir, 'audit-test.wal');
  });

  afterEach(async () => {
    wal.disable();
    await wal.drain();
    jest.restoreAllMocks();
    fs.rmSync(tmpRoot, { recursive: true, force: true });
  });

  test('startup 创建缺失目录时用 0700，并回读确认已收紧', () => {
    wal.startup(walPath);

    expect(fs.existsSync(dir)).toBe(true);
    if (!isWindows) expect(modeOf(dir)).toBe(0o700);
    expect(filePermission.verifyHardened(dir).tightened).toBe(true);
  });

  test('已存在的载体文件（主 WAL / .discarded / .tmp）在 startup 时被收紧', () => {
    fs.mkdirSync(dir, { recursive: true });
    const targets = [walPath, `${walPath}.discarded`, `${walPath}.tmp`];
    for (const p of targets) fs.writeFileSync(p, '{"action":"seeded"}\n', { mode: 0o644 });

    wal.startup(walPath);

    for (const p of targets) {
      if (!isWindows) expect(modeOf(p)).toBe(0o600);
      expect(filePermission.verifyHardened(p).tightened).toBe(true);
    }
  });

  test('新建 WAL 文件为 0600（Windows 下由已收紧目录继承）', async () => {
    wal.startup(walPath);
    wal.appendLine('{"action":"fresh"}\n');
    await wal.drain();

    expect(fs.existsSync(walPath)).toBe(true);
    if (!isWindows) expect(modeOf(walPath)).toBe(0o600);
    expect(filePermission.verifyHardened(walPath).tightened).toBe(true);
  });

  test('裁剪的原子替换与毒批归档写出的文件仍为 0600', async () => {
    fs.mkdirSync(dir, { recursive: true });
    const line = `${JSON.stringify({ action: 'poison', __walSeq: 'perm-run-1' })}\n`;
    fs.writeFileSync(walPath, line, { mode: 0o644 });
    wal.startup(walPath);

    wal.discardBySeqs(['perm-run-1']);
    await wal.drain();

    const archived = `${walPath}.discarded`;
    expect(fs.readFileSync(archived, 'utf8')).toContain('perm-run-1');
    if (!isWindows) {
      expect(modeOf(archived)).toBe(0o600);
      expect(modeOf(walPath)).toBe(0o600);
    }
    expect(filePermission.verifyHardened(archived).tightened).toBe(true);
    expect(filePermission.verifyHardened(walPath).tightened).toBe(true);
  });

  test('收紧失败：error 级留痕 + 安全告警，但 WAL 仍可写入（best-effort 不阻断审计）', async () => {
    jest
      .spyOn(filePermission, 'hardenPath')
      .mockReturnValue({ ok: false, method: 'icacls', detail: 'access denied' });
    jest
      .spyOn(filePermission, 'verifyHardened')
      .mockReturnValue({ tightened: false, evidence: 'ACE 仍含 Everyone' });
    const errorSpy = jest.spyOn(logger, 'error').mockImplementation(() => {});
    const alertSpy = jest.spyOn(metrics, 'incSecurityAlert').mockImplementation(() => {});

    wal.startup(walPath);
    wal.appendLine('{"action":"still-written"}\n');
    await wal.drain();

    const logged = errorSpy.mock.calls.map((c) => c.join(' ')).join('\n');
    expect(logged).toContain('权限未能收紧');
    expect(logged).toContain('ACE 仍含 Everyone');
    expect(alertSpy).toHaveBeenCalledWith('audit_wal_permission_not_tightened', 'high');
    expect(fs.readFileSync(walPath, 'utf8')).toContain('still-written');
  });
});
