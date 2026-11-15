/**
 * P3：明文口令文件改为"先建 0600 临时文件 → 写入 → rename 落位"。
 *
 * 旧实现直接写最终路径（mode 在 Windows 上被忽略），存在"明文已出现在最终路径、
 * 权限加固尚未执行"的窗口。新流程的判据：rename 之前最终路径不出现明文；写入或
 * rename 失败时不留临时文件、不留最终文件，口令绝不进日志，管理员创建回滚（fail-closed 不变）。
 * 走 createDefaultAdmin 真实入口（persistInitialPassword 未导出）；用例内设唯一的
 * SUPER_ADMIN_USERNAME/ADMIN_INITIAL_EMAIL，避免与共享测试库里的既有管理员相撞。
 */
const fs = require('fs');
const os = require('os');
const path = require('path');

jest.mock('../../utils/logger', () => ({
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
  debug: jest.fn(),
}));

describe('初始口令文件的原子落位（P3）', () => {
  let mongoose;
  let Role;
  let User;
  let adminAccount;
  let filePermission;
  let metrics;
  let logger;
  let tmpDir;
  let originalCwd;
  const UNIQUE = `p3atom${Date.now()}`.replace(/\d/g, (d) => 'abcdefghij'[Number(d)]);

  const savedEnv = {};

  const pwdPath = () => path.join(tmpDir, '.admin-initial-password');
  const tmpFiles = () => fs.readdirSync(tmpDir).filter((name) => name.includes('.tmp-'));
  const loggedText = () =>
    ['info', 'warn', 'error', 'debug']
      .flatMap((k) => logger[k].mock.calls.map((args) => args.map(String).join(' ')))
      .join('\n');

  beforeAll(async () => {
    mongoose = require('mongoose');
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    Role = require('../../models/Role');
    User = require('../../models/User');
    adminAccount = require('../../services/initData/adminAccount');
    filePermission = require('../../utils/filePermission');
    metrics = require('../../utils/metrics');
    logger = require('../../utils/logger');

    savedEnv.SUPER_ADMIN_USERNAME = process.env.SUPER_ADMIN_USERNAME;
    savedEnv.ADMIN_INITIAL_EMAIL = process.env.ADMIN_INITIAL_EMAIL;
    savedEnv.ADMIN_INITIAL_PASSWORD = process.env.ADMIN_INITIAL_PASSWORD;
    process.env.SUPER_ADMIN_USERNAME = UNIQUE;
    process.env.ADMIN_INITIAL_EMAIL = `${UNIQUE}@example.com`;
    delete process.env.ADMIN_INITIAL_PASSWORD;

    if (!(await Role.findOne({ code: 'SUPER_ADMIN' }))) {
      await Role.create({
        name: '超级管理员',
        code: 'SUPER_ADMIN',
        level: 10,
        isBuiltIn: true,
        permissions: [],
      });
    }

    originalCwd = process.cwd();
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'admin-pwd-atomic-'));
    process.chdir(tmpDir);
    jest.spyOn(filePermission, 'hardenPath').mockReturnValue({ ok: true, method: 'icacls' });
    jest.spyOn(filePermission, 'verifyHardened').mockReturnValue({ tightened: true });
    jest.spyOn(metrics, 'incSecurityAlert').mockImplementation(() => {});
  });

  afterEach(async () => {
    await User.deleteOne({ username: UNIQUE }).catch(() => {});
    fs.rmSync(pwdPath(), { force: true });
  });

  afterAll(async () => {
    process.chdir(originalCwd);
    for (const [key, value] of Object.entries(savedEnv)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
    fs.rmSync(tmpDir, { recursive: true, force: true });
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });

  test('成功路径：rename 之前最终路径无明文，落位后内容完整、无临时残留、口令不进日志', async () => {
    const realRename = fs.renameSync.bind(fs);
    const renameSpy = jest.spyOn(fs, 'renameSync').mockImplementation((from, to) => {
      expect(fs.existsSync(from)).toBe(true); // rename 时临时文件已带完整明文
      expect(fs.existsSync(to)).toBe(false); // 落位前最终路径没有明文
      return realRename(from, to);
    });
    let renameCalls = [];
    try {
      const admin = await adminAccount.createDefaultAdmin();
      expect(admin).not.toBeNull();
      expect(admin.username).toBe(UNIQUE);
      renameCalls = renameSpy.mock.calls.slice(); // mockRestore 会连带清空 mock.calls，先取快照
    } finally {
      renameSpy.mockRestore();
    }
    expect(path.basename(renameCalls[0][0])).toMatch(/\.admin-initial-password\.tmp-\d+-\d+$/);
    expect(renameCalls[0][1]).toBe(pwdPath());
    const content = fs.readFileSync(pwdPath(), 'utf8');
    expect(content).toContain(`username: ${UNIQUE}`);
    expect(content).toMatch(/password: \S+/); // 初始口令为随机生成，只钉"非空口令已落盘"
    expect(tmpFiles()).toEqual([]);
    expect(loggedText()).not.toMatch(/password: [0-9a-f]{32}/); // 口令绝不进日志
  });

  test('写入失败：不留最终/临时文件，metrics 告警，管理员回滚，口令不进日志', async () => {
    const writeSpy = jest.spyOn(fs, 'writeFileSync').mockImplementation(() => {
      throw new Error('disk full');
    });
    try {
      await expect(adminAccount.createDefaultAdmin()).rejects.toThrow(/未能安全保存/);
    } finally {
      writeSpy.mockRestore();
    }
    expect(fs.existsSync(pwdPath())).toBe(false);
    expect(tmpFiles()).toEqual([]);
    expect(metrics.incSecurityAlert).toHaveBeenCalledWith(
      'admin_initial_password_write_failed',
      'high'
    );
    expect(await User.findByUsername(UNIQUE)).toBeNull(); // 创建已回滚
    expect(loggedText()).not.toMatch(/password: [0-9a-f]{32}/);
  });

  test('rename 失败：临时文件被清理，最终路径不出现明文', async () => {
    const renameSpy = jest.spyOn(fs, 'renameSync').mockImplementation(() => {
      throw new Error('rename denied');
    });
    try {
      await expect(adminAccount.createDefaultAdmin()).rejects.toThrow(/未能安全保存/);
    } finally {
      renameSpy.mockRestore();
    }
    expect(fs.existsSync(pwdPath())).toBe(false);
    expect(tmpFiles()).toEqual([]);
    expect(await User.findByUsername(UNIQUE)).toBeNull();
  });
});
