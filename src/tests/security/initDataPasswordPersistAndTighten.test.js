/**
 * ──────────────────────────────────────────────────────────────────────────
 * 本文件的定位（2026-09-20 补注，由变异审计批量补齐）
 *
 * 被测对象：初始密码文件的「落盘 + 收紧 + 复核」闭环（M-05）
 * 守护的不变式：初始密码文件落盘即必须实际收紧（NTFS 上 chmod 是空操作）并可回读复核
 * 可证伪性：本轮未做变异实测
 *
 * 命名沿革：2026-09-20 由 `initDataPasswordHardening.test.js` 更名。旧名里的
 *   Coverage / Gap / Hardening / Branch 说的是「当初为什么写它」（补覆盖率基线），
 *   **不是它的价值判据**；它能否挡住回归，由变异实测回答，不由文件名回答。
 *   旧名保留在本行，便于既往审计报告的 `grep 旧文件名` 仍能定位到本文件。
 * 依据：`deliverables/AGENT工作总账与待办-2026-09-21.md`（§2.9 测试资产 / §6 方法；原编号 §6-AW/AX/AY/AZ/BA 已随原台账删除，无法逐条映射）
 * ──────────────────────────────────────────────────────────────────────────
 */

/**
 * M-05 回归：初始密码文件的「落盘 + 收紧 + 复核」闭环
 *
 * 缺陷历史（两轮）：
 *   1. 原实现只做 chmod(0600)。NTFS 上 chmod 是空操作，文件继续继承父目录
 *      宽松 ACL，而日志照打「权限 600」——最具误导性的失败形态：用户以为
 *      受保护，实际任何本地用户可读。
 *   2. 第一轮修复只**打印** icacls 命令让用户手动执行，等于把安全语义降级
 *      为建议，实践中多数人不做。
 *
 * 本次改动改为实际执行 + 回读校验（utils/filePermission），并把这段逻辑从
 * createDefaultAdmin 中抽出为 persistInitialPassword。
 *
 * 本套件锁定的不变量：
 *   (a) 未显式注入 ADMIN_INITIAL_PASSWORD 时，密码必须落盘且**权限已收紧**；
 *   (b) 已显式注入时（运维已知晓口令），不落盘——少一处泄露面；
 *   (c) 无论收紧成败，**密码明文绝不进入日志**（M-02：容器 stdout 会被
 *       日志驱动持久化，等同泄露）。
 *
 * (c) 是本套件最关键的断言：它是「收紧失败」与「日志泄露」两害相权时的
 * 底线——收紧可以失败并告警，密码不得因告警而泄露。
 *
 * 清理说明：清理超管角色必须走 `Role.collection`（原生驱动）——Role schema 的
 * deleteMany 钩子会拦截内置角色（这是生产上正确的保护），测试里需绕过。
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const mongoose = require('mongoose');

jest.mock('../../utils/logger', () => ({
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
  debug: jest.fn(),
}));

const logger = require('../../utils/logger');
const { createDefaultAdmin } = require('../../services/initData');

const SUPER_ADMIN_ROLE_CODE = 'SUPER_ADMIN';
const ADMIN_PASSWORD = 'Unit-Test-Password-1!';

/** 在临时工作目录内执行 fn（persistInitialPassword 落在 process.cwd()） */
async function inTempCwd(fn) {
  const original = process.cwd();
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'm05-init-'));
  process.chdir(dir);
  try {
    return await fn(dir);
  } finally {
    process.chdir(original);
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

/** 所有 logger 调用拼接后的全文，用于断言「密码未出现在日志中」 */
const loggedText = () =>
  ['info', 'warn', 'error', 'debug']
    .flatMap((k) => logger[k].mock.calls.map((args) => args.map(String).join(' ')))
    .join('\n');

describe('M-05 初始密码落盘与权限收紧闭环', () => {
  let Role;
  let User;
  let userIds = [];

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    ({ Role, User } = require('../../models'));
  });

  /** 绕过内置角色删除保护（原生驱动），仅测试清理使用 */
  const removeSuperAdminRole = () => Role.collection.deleteMany({ code: SUPER_ADMIN_ROLE_CODE });

  /** 播种超管角色并清掉同名管理员，使 createDefaultAdmin 走到创建分支 */
  const seedFreshAdminState = async () => {
    await removeSuperAdminRole();
    await User.deleteMany({ username: 'admin' });
    return Role.create({
      name: '超级管理员',
      code: SUPER_ADMIN_ROLE_CODE,
      level: 10,
      isBuiltIn: true,
      permissions: [],
    });
  };

  afterEach(async () => {
    if (userIds.length) {
      await User.deleteMany({ _id: { $in: userIds } });
      userIds = [];
    }
    await removeSuperAdminRole();
    delete process.env.ADMIN_INITIAL_PASSWORD;
    delete process.env.ADMIN_INITIAL_EMAIL;
    jest.clearAllMocks();
  });

  afterAll(async () => {
    await removeSuperAdminRole();
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });

  describe('口令注入方式决定是否落盘', () => {
    it('显式注入 ADMIN_INITIAL_PASSWORD 时不落盘（运维已知晓口令，少一处泄露面）', async () => {
      await seedFreshAdminState();
      process.env.ADMIN_INITIAL_PASSWORD = ADMIN_PASSWORD;

      await inTempCwd(async (dir) => {
        const admin = await createDefaultAdmin();
        userIds.push(admin._id);

        expect(fs.existsSync(path.join(dir, '.admin-initial-password'))).toBe(false);
        // 仍须提醒尽快改密
        expect(loggedText()).toContain('请及时修改默认管理员密码');
      });
    });

    it('未注入时生成随机口令并落盘，且权限收紧复核通过', async () => {
      await seedFreshAdminState();
      delete process.env.ADMIN_INITIAL_PASSWORD;

      await inTempCwd(async (dir) => {
        const admin = await createDefaultAdmin();
        userIds.push(admin._id);

        const pwdFile = path.join(dir, '.admin-initial-password');
        expect(fs.existsSync(pwdFile)).toBe(true);

        const content = fs.readFileSync(pwdFile, 'utf8');
        expect(content).toMatch(/^username: admin\npassword: [0-9a-f]{32}\n$/);

        // 收紧闭环：校验函数必须判为已收紧（失败即本用例红，
        // 这正是「伪修复」与「真收紧」的分界线）
        const { verifyHardened } = require('../../utils/filePermission');
        expect(verifyHardened(pwdFile).tightened).toBe(true);
      });
    });
  });

  describe('日志保密性：密码绝不进入日志（M-02 底线）', () => {
    it('收紧成功路径：日志中不含生成的明文口令', async () => {
      await seedFreshAdminState();
      delete process.env.ADMIN_INITIAL_PASSWORD;

      await inTempCwd(async (dir) => {
        const admin = await createDefaultAdmin();
        userIds.push(admin._id);

        const content = fs.readFileSync(path.join(dir, '.admin-initial-password'), 'utf8');
        const generated = content.match(/password: (.+)\n/)[1];

        expect(generated).toHaveLength(32);
        expect(loggedText()).not.toContain(generated);
        // 确认确实记了日志，否则上面的断言可能因「什么都没记」而恒真
        expect(logger.info).toHaveBeenCalled();
      });
    });

    it('文件写入失败路径：日志给出可操作恢复途径，且不含口令', async () => {
      await seedFreshAdminState();
      delete process.env.ADMIN_INITIAL_PASSWORD;

      const originalWrite = fs.writeFileSync;
      fs.writeFileSync = () => {
        throw new Error('EACCES: permission denied (simulated)');
      };

      try {
        await inTempCwd(async () => {
          const admin = await createDefaultAdmin();
          userIds.push(admin._id);

          const text = loggedText();
          // 不得把口令当作「补救办法」打印出来
          expect(text).not.toMatch(/password: [0-9a-f]{32}/);
          // 必须指引到环境变量注入这条可操作的恢复路径
          expect(text).toContain('ADMIN_INITIAL_PASSWORD');
          expect(logger.error).toHaveBeenCalled();
        });
      } finally {
        fs.writeFileSync = originalWrite;
      }
    });
  });

  describe('前置分支：不满足创建条件时既不建号也不落盘', () => {
    it('管理员已存在时直接返回，不产生新的密码文件', async () => {
      const role = await seedFreshAdminState();
      const existing = await User.create({
        username: 'admin',
        email: 'existing-admin@example.com',
        password: ADMIN_PASSWORD,
        realName: '既有管理员',
        status: 'active',
        roles: [role._id],
      });
      userIds.push(existing._id);

      await inTempCwd(async (dir) => {
        const admin = await createDefaultAdmin();
        expect(String(admin._id)).toBe(String(existing._id));
        expect(fs.existsSync(path.join(dir, '.admin-initial-password'))).toBe(false);
      });
    });

    it('缺少超管角色时跳过创建（避免在未播种环境里造出无权限账户）', async () => {
      await removeSuperAdminRole();
      await User.deleteMany({ username: 'admin' });

      await inTempCwd(async (dir) => {
        await expect(createDefaultAdmin()).resolves.toBeNull();
        expect(fs.existsSync(path.join(dir, '.admin-initial-password'))).toBe(false);
      });
    });
  });
});
