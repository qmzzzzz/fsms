/**
 * initData 启动播种与安全对账（行为回归）
 *
 * 背景：initData.js 是全仓最大的覆盖洼地（2026-09-17 lcov 实测 行 97/218、
 * 分支 35/100、函数 20/64），而它是安全相关代码——每次服务启动都执行权限播种、
 * 内置角色权限对账、超管唯一性对账、username/tokenblacklist 索引对账、初始口令
 * 落盘与权限收紧。此前只有 4 个点被间接覆盖（reconcileSuperAdmin /
 * reconcileTokenBlacklistIndexes / createDefaultAdmin / initSystemConfig），
 * 播种主体（initPermissions / initRoles）与 reconcileUserIndexes 完全无测试。
 *
 * 本套件锁定的是**行为契约**（查库结果与可观测副作用），不是实现细节：
 *   1. 幂等：重复启动不重复插入、不改写已有数据、不下发无谓写入；
 *   2. 不虚报：并发唯一键冲突导致返回值丢失时，created 必须回查数据库取真实数量，
 *      不得按 toInsert.length 上报（注释承诺的防退化点）；
 *   3. 收敛：内置角色每次启动都收敛回 rolePermissionMap 的精确权限集
 *      （防「GUEST 曾拥有 device:*」这类残留过宽权限无法被收回），
 *      且对「等量替换」也生效（只比数量会漏掉 device:read → device:delete 这类替换）；
 *      非内置角色属于管理员自定义，启动播种不得触碰；
 *   4. 零约束窗口：username 索引对账在存在大小写冲突时必须保留旧索引
 *      （先删后建会让冲突库两个约束都没有）；
 *   5. fail-loud / fail-safe 的分界：播种失败必须上抛（启动即失败优于半初始化），
 *      索引对账失败只告警不阻断启动。
 *
 * 变异验证：每条用例都做过「把被测逻辑改错 → 用例必须转红 → 还原」的实测，
 * 证据见交付报告。断言全部是数据状态（查库/索引列表/可观测日志），
 * 未使用任何「仅断言被调用过」的弱断言作为主判据。
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
const { randomPassword } = require('../helpers/buildLoginEnvelope');

const PASSWORD = randomPassword();

/** 在临时工作目录内执行 fn（persistInitialPassword 落在 process.cwd()） */
async function inTempCwd(fn) {
  const original = process.cwd();
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'initdata-lifecycle-'));
  process.chdir(dir);
  try {
    return await fn(dir);
  } finally {
    process.chdir(original);
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

/** 所有 logger 调用拼接后的全文，用于断言「密码未进入日志」等全局性质 */
const loggedText = () =>
  ['info', 'warn', 'error', 'debug']
    .flatMap((k) => logger[k].mock.calls.map((args) => args.map(String).join(' ')))
    .join('\n');

describe('initData 启动播种与安全对账', () => {
  let User;
  let Role;
  let Permission;
  let TokenBlacklist;
  let SystemConfig;
  let defaultPermissions;
  let defaultRoles;
  let initPermissions;
  let initRoles;
  let createDefaultAdmin;
  let reconcileSuperAdmin;
  let reconcileUserIndexes;
  let reconcileTokenBlacklistIndexes;
  let initializeSystem;

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    ({ User, Role, Permission, TokenBlacklist, SystemConfig } = require('../../models'));
    ({
      defaultPermissions,
      defaultRoles,
      initPermissions,
      initRoles,
      createDefaultAdmin,
      reconcileSuperAdmin,
      reconcileUserIndexes,
      reconcileTokenBlacklistIndexes,
      initializeSystem,
    } = require('../../services/initData'));
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });

  beforeEach(() => {
    jest.clearAllMocks();
    delete process.env.SUPER_ADMIN_USERNAME;
    delete process.env.ADMIN_INITIAL_PASSWORD;
    delete process.env.ADMIN_INITIAL_EMAIL;
  });

  /**
   * 清空本套件用到的集合。
   * Role 必须走原生驱动：Role schema 的 deleteMany 钩子会拦截内置角色
   * （这是生产上正确的保护），测试清理需要绕过。
   */
  const resetDb = async () => {
    await User.deleteMany({});
    await Role.collection.deleteMany({});
    await Permission.deleteMany({});
    await TokenBlacklist.deleteMany({});
    await SystemConfig.deleteMany({});
    SystemConfig.invalidateRegistrationCache();
    SystemConfig.invalidateLoginCaptchaCache();
    // 把 users 索引强制同步回 schema 定义。E 组用例会 dropCollection 后手工造
    // legacy 索引，若其中某条断言先失败，它末尾的 syncIndexes() 就不会执行，
    // 后续用例（如 F2 依赖 email 唯一索引触发降级分支）会因「索引不存在」
    // 走到完全不同的代码路径而级联失败。每个用例自建前置，不依赖前序是否成功。
    await User.syncIndexes();
  };

  /** 用 code 精确取权限 id（断言 parent 关联用） */
  const permIdByCode = async () => {
    const docs = await Permission.find({}).select('code').lean();
    return new Map(docs.map((d) => [d.code, String(d._id)]));
  };

  /** 某角色的权限 code 集合（排序后，便于精确比较） */
  const rolePermCodes = async (code) => {
    const role = await Role.findOne({ code });
    const perms = await Permission.find({ _id: { $in: role.permissions } })
      .select('code')
      .lean();
    return perms.map((p) => p.code).sort();
  };

  // ==================================================================
  // A. initPermissions —— 权限播种
  // ==================================================================
  describe('initPermissions：权限播种', () => {
    test('A1 空库播种：全部权限落库，非通配符权限挂到所属模块的通配符父权限', async () => {
      await resetDb();

      const result = await initPermissions();
      expect(result).toEqual({ created: defaultPermissions.length, skipped: 0 });

      const docs = await Permission.find({}).select('code module parent').lean();
      expect(docs).toHaveLength(defaultPermissions.length);

      const idByCode = new Map(docs.map((d) => [d.code, String(d._id)]));
      const parentByCode = new Map(docs.map((d) => [d.code, d.parent ? String(d.parent) : null]));

      // 前置不变量：每个 module 都必须有对应的 `${module}:*` 通配符权限，
      // 否则下面的期望值本身就是 undefined（会把「父权限缺失」误判为通过）
      // 关联口径由**权限码前缀**决定（user:read → user:*），不是 Permission.module 字段：
      // system:read 与 user:read 的 module 同为 system，按 module 关联会把所有子权限
      // 都挂到 system:* 上，前端的「模块菜单 → 模块内权限」两层结构就无法还原。
      const prefixOf = (code) => code.split(':')[0];
      const wildcardCodes = new Set(docs.map((d) => d.code));
      for (const perm of defaultPermissions) {
        expect(wildcardCodes.has(`${prefixOf(perm.code)}:*`)).toBe(true);
      }

      const problems = defaultPermissions
        .filter((p) => `${prefixOf(p.code)}:*` !== p.code)
        .filter((p) => parentByCode.get(p.code) !== idByCode.get(`${prefixOf(p.code)}:*`))
        .map(
          (p) =>
            `${p.code} 的 parent=${parentByCode.get(p.code)}，` +
            `期望 ${prefixOf(p.code)}:* = ${idByCode.get(`${prefixOf(p.code)}:*`)}`
        );
      expect(problems).toEqual([]);
    });

    test('A2 幂等：重复播种不下发写入、不重复插入、不破坏已有 parent 关联', async () => {
      await resetDb();
      await initPermissions();
      const snapshot = async () =>
        (await Permission.find({}).select('code parent').lean())
          .map((d) => `${d.code}=${d.parent ? String(d.parent) : 'null'}`)
          .sort();
      const before = await snapshot();

      const insertSpy = jest.spyOn(Permission, 'insertMany');
      const bulkSpy = jest.spyOn(Permission, 'bulkWrite');
      let result;
      let insertCalls;
      let bulkCalls;
      try {
        result = await initPermissions();
      } finally {
        // 必须在 mockRestore() 之前取调用次数：mockRestore 会连带 mockReset，
        // 清空 mock.calls —— 之后断言 not.toHaveBeenCalled() 会恒真（假断言）
        insertCalls = insertSpy.mock.calls.length;
        bulkCalls = bulkSpy.mock.calls.length;
        insertSpy.mockRestore();
        bulkSpy.mockRestore();
      }

      expect(result).toEqual({ created: 0, skipped: defaultPermissions.length });
      // 早退语义：不是「插了再撞唯一键」，而是根本不发起写入
      expect(insertCalls).toBe(0);
      expect(bulkCalls).toBe(0);
      expect(await snapshot()).toEqual(before);
    });

    test('A3 并发冲突（零落库）：11000 被吞下，created 不虚报、流程继续', async () => {
      await resetDb();
      const duplicate = Object.assign(new Error('E11000 duplicate key error'), { code: 11000 });
      const spy = jest.spyOn(Permission, 'insertMany').mockRejectedValueOnce(duplicate);
      let result;
      try {
        result = await initPermissions();
      } finally {
        spy.mockRestore();
      }

      expect(result).toEqual({ created: 0, skipped: defaultPermissions.length });
      expect(await Permission.countDocuments({})).toBe(0);
      // 并发冲突必须留下可检索的告警（多实例部署时这是唯一的排查线索）
      expect(logger.warn).toHaveBeenCalledWith(expect.stringContaining('并发冲突'));
    });

    test('A4 并发冲突（部分落库）：created 回查数据库真实数量，不按 toInsert.length 虚报', async () => {
      await resetDb();
      const realInsertMany = Permission.insertMany.bind(Permission);
      const PARTIAL = 5;
      const spy = jest
        .spyOn(Permission, 'insertMany')
        .mockImplementationOnce(async (docs, opts) => {
          // 模拟 ordered:false 下的部分成功：前 5 条已落库，随后撞唯一键
          await realInsertMany(docs.slice(0, PARTIAL), opts);
          throw Object.assign(new Error('E11000 duplicate key error'), { code: 11000 });
        });

      let result;
      try {
        result = await initPermissions();
      } finally {
        spy.mockRestore();
      }

      expect(await Permission.countDocuments({})).toBe(PARTIAL);
      expect(result.created).toBe(PARTIAL);
      // 防退化：created 绝不能是 toInsert.length（那会把没插进去的也算成已创建）
      expect(result.created).not.toBe(defaultPermissions.length);
      expect(result.skipped).toBe(defaultPermissions.length - PARTIAL);

      // 冲突路径仍须完成 parent 关联（部分落库的父/子权限都要挂上）
      const idByCode = await permIdByCode();
      for (const code of ['system:read', 'user:read', 'user:create']) {
        const doc = await Permission.findOne({ code }).select('parent').lean();
        expect(`${code}→${String(doc.parent)}`).toBe(
          `${code}→${idByCode.get(`${code.split(':')[0]}:*`)}`
        );
      }
    });

    test('A5 非唯一键错误必须上抛（fail-loud），不得被并发冲突处理吞掉', async () => {
      await resetDb();
      const spy = jest
        .spyOn(Permission, 'insertMany')
        .mockRejectedValueOnce(new Error('connection reset by peer'));
      let caught = null;
      try {
        await initPermissions();
      } catch (e) {
        caught = e;
      } finally {
        spy.mockRestore();
      }

      expect(caught).not.toBeNull();
      expect(caught.message).toBe('connection reset by peer');
      expect(logger.error).toHaveBeenCalledWith(
        expect.stringContaining('connection reset by peer')
      );
      expect(await Permission.countDocuments({})).toBe(0);
    });

    test('A6 增量播种：已存在的模块通配符父权限必须参与 parent 映射', async () => {
      await resetDb();
      // 模拟旧版本残留：user:* 已存在且 parent 为空，本次只补插其余 46 条
      const existingWildcard = await Permission.create({
        name: '用户管理菜单',
        code: 'user:*',
        type: 'menu',
        module: 'system',
        path: '/system/users',
      });

      const result = await initPermissions();
      expect(result).toEqual({ created: defaultPermissions.length - 1, skipped: 1 });

      // 承重点：新插入的 user:read 必须挂到「本次未插入」的 user:* 上
      const read = await Permission.findOne({ code: 'user:read' }).select('parent').lean();
      expect(String(read.parent)).toBe(String(existingWildcard._id));

      // 已存在的数据不得被播种流程改写
      const wildcardAfter = await Permission.findOne({ code: 'user:*' }).select('parent').lean();
      expect(wildcardAfter.parent).toBeNull();
    });

    test('A7 bulkOps 为空时不发起 bulkWrite（不下发空操作）', async () => {
      await resetDb();
      // 构造：预查返回空（toInsert = 全部），插入成功，但 parent 映射查询返回空
      // → 没有任何可关联的 parent/permId → bulkOps 为空
      const emptyQuery = () => ({ select: () => ({ lean: async () => [] }) });
      const findSpy = jest.spyOn(Permission, 'find');
      findSpy.mockImplementationOnce(emptyQuery).mockImplementationOnce(emptyQuery);
      const bulkSpy = jest.spyOn(Permission, 'bulkWrite');

      let result;
      let bulkCalls;
      try {
        result = await initPermissions();
      } finally {
        // 同 A2：先取次数再还原，否则 not.toHaveBeenCalled() 恒真
        bulkCalls = bulkSpy.mock.calls.length;
        findSpy.mockRestore();
        bulkSpy.mockRestore();
      }

      expect(result.created).toBe(defaultPermissions.length);
      expect(bulkCalls).toBe(0);
      expect(await Permission.countDocuments({})).toBe(defaultPermissions.length);
    });

    // ===== 已知缺陷（test.failing：当前必然失败；修复后本用例转红以提醒更新） =====
    test('A8 权限不得把自身作为父级——自环会让 /api/roles/permissions/tree 整棵塌陷（2026-09-18 修复）', async () => {
      await resetDb();
      await initPermissions();
      const docs = await Permission.find({}).select('_id code parent').lean();
      const selfParent = docs.filter((d) => String(d.parent) === String(d._id)).map((d) => d.code);
      expect(selfParent).toEqual([]);

      // 通配符是模块的根，parent 必须为 null（子权限挂到它下面）
      const wildcards = docs.filter((d) => d.code.endsWith(':*'));
      expect(wildcards.length).toBeGreaterThan(0);
      expect(wildcards.filter((d) => d.parent !== null).map((d) => d.code)).toEqual([]);

      // 非通配符权限必须挂到所属模块的通配符下（否则权限树第二层起全部丢失）
      const byId = new Map(docs.map((d) => [String(d._id), d]));
      const misParented = docs
        .filter((d) => !d.code.endsWith(':*'))
        .filter((d) => {
          const parent = d.parent ? byId.get(String(d.parent)) : null;
          return !parent || parent.code !== `${d.code.split(':')[0]}:*`;
        })
        .map((d) => d.code);
      expect(misParented).toEqual([]);
    });
  });
  // ==================================================================
  // B. initRoles —— 角色播种与内置角色权限对账（安全关键）
  // ==================================================================
  describe('initRoles：角色播种与内置角色权限对账', () => {
    // GUEST 的最小权限定义（rolePermissionMap.GUEST 的字面值）。
    // 刻意写成字面量而非从被测代码派生：从实现派生期望值会让「实现改了期望跟着改」，
    // 断言永远为真，等于没断言。
    const GUEST_CODES = ['alarm:read', 'device:read', 'inspection:read', 'report:read'];

    test('B1 空库播种：5 个内置角色落库，权限关联与最小权限定义一致', async () => {
      await resetDb();
      await initPermissions();

      const result = await initRoles();
      expect(result).toEqual({ created: defaultRoles.length, reconciled: 0, skipped: 0 });

      const roles = await Role.find({}).select('code isBuiltIn').lean();
      expect(roles.map((r) => r.code).sort()).toEqual(defaultRoles.map((r) => r.code).sort());
      expect(roles.every((r) => r.isBuiltIn === true)).toBe(true);

      // 最小权限代表：GUEST 必须恰好是 4 个只读权限（多一个都是越权）
      expect(await rolePermCodes('GUEST')).toEqual(GUEST_CODES);
      // 超管：唯一持有 *:* 通配的角色
      expect(await rolePermCodes('SUPER_ADMIN')).toEqual(['*:*']);
    });

    test('B2 幂等：第二次播种不创建、不对账、不下发任何写入', async () => {
      await resetDb();
      await initPermissions();
      await initRoles();
      const before = (await Role.find({}).select('code permissions').lean()).map((r) => [
        r.code,
        r.permissions.map(String).sort(),
      ]);

      const insertSpy = jest.spyOn(Role, 'insertMany');
      const bulkSpy = jest.spyOn(Role, 'bulkWrite');
      let result;
      let insertCalls;
      let bulkCalls;
      try {
        result = await initRoles();
      } finally {
        // 同 A2：先取次数再还原，否则 not.toHaveBeenCalled() 恒真
        insertCalls = insertSpy.mock.calls.length;
        bulkCalls = bulkSpy.mock.calls.length;
        insertSpy.mockRestore();
        bulkSpy.mockRestore();
      }

      expect(result).toEqual({ created: 0, reconciled: 0, skipped: defaultRoles.length });
      expect(insertCalls).toBe(0);
      expect(bulkCalls).toBe(0);
      const after = (await Role.find({}).select('code permissions').lean()).map((r) => [
        r.code,
        r.permissions.map(String).sort(),
      ]);
      expect(after).toEqual(before);
    });

    test('B3 内置角色被手工扩权（超集）时收敛回预定义精确集合', async () => {
      await resetDb();
      await initPermissions();
      await initRoles();

      // 构造「残留过宽权限」：GUEST 额外持有 device:* 通配符与 device:delete
      const wildcard = await Permission.findOne({ code: 'device:*' }).select('_id').lean();
      const destructive = await Permission.findOne({ code: 'device:delete' }).select('_id').lean();
      const guest = await Role.findOne({ code: 'GUEST' });
      await Role.collection.updateOne(
        { _id: guest._id },
        { $set: { permissions: [...guest.permissions, wildcard._id, destructive._id] } }
      );
      const widened = await rolePermCodes('GUEST');
      expect(widened).toContain('device:*');
      expect(widened).toContain('device:delete');

      const result = await initRoles();

      expect(result.reconciled).toBe(1);
      expect(await rolePermCodes('GUEST')).toEqual(GUEST_CODES);
      // 收回过宽权限是安全事件，必须留痕
      expect(logger.warn).toHaveBeenCalledWith(expect.stringContaining('GUEST'));
    });

    test('B4 权限被等量替换（仍是 4 项但含 device:delete）时同样收敛', async () => {
      await resetDb();
      await initPermissions();
      await initRoles();

      const keep = await Permission.findOne({ code: 'alarm:read' }).select('_id').lean();
      const destructive = await Permission.findOne({ code: 'device:delete' }).select('_id').lean();
      const guest = await Role.findOne({ code: 'GUEST' });
      // 4 项换 4 项：只比数量会漏判，必须逐成员比较
      await Role.collection.updateOne(
        { _id: guest._id },
        { $set: { permissions: [keep._id, destructive._id, ...guest.permissions.slice(2)] } }
      );
      expect(await rolePermCodes('GUEST')).toHaveLength(4);
      expect(await rolePermCodes('GUEST')).toContain('device:delete');

      const result = await initRoles();

      expect(result.reconciled).toBe(1);
      expect(await rolePermCodes('GUEST')).toEqual(GUEST_CODES);
    });

    test('B5 权限码缺失（Permission 表为空）时跳过关联，且不留下 null 空洞', async () => {
      await resetDb();

      const result = await initRoles();

      expect(result).toEqual({ created: defaultRoles.length, reconciled: 0, skipped: 0 });
      const raw = await mongoose.connection.collection('roles').find({}).toArray();
      expect(raw).toHaveLength(defaultRoles.length);
      for (const role of raw) {
        // 缺失的权限码必须被过滤掉，而不是在数组里留 null（null 槽位会让
        // populate/$in 查询语义漂移，是「看似关联了、实际指空」的脏数据）
        expect(role.permissions || []).toEqual([]);
      }
    });

    test('B6 角色创建失败必须上抛（fail-loud：不得留下权限未关联的半成品）', async () => {
      await resetDb();
      await initPermissions();
      const spy = jest
        .spyOn(Role, 'insertMany')
        .mockRejectedValueOnce(new Error('write concern timeout'));

      let caught = null;
      try {
        await initRoles();
      } catch (e) {
        caught = e;
      } finally {
        spy.mockRestore();
      }

      expect(caught).not.toBeNull();
      expect(caught.message).toBe('write concern timeout');
      expect(await Role.countDocuments({})).toBe(0);
    });

    test('B8 内置角色 permissions 为 null（直连数据库残留）时对账不崩且能收敛', async () => {
      await resetDb();
      await initPermissions();
      // 原生驱动写入 null：绕过 mongoose 默认 []，复刻历史数据形态
      await Role.collection.insertOne({
        name: '访客',
        code: 'GUEST',
        level: 1,
        isBuiltIn: true,
        permissions: null,
      });

      const result = await initRoles();

      expect(result.reconciled).toBe(1);
      expect(await rolePermCodes('GUEST')).toEqual(GUEST_CODES);
    });

    test('B7 对账判定取自播种定义，篡改数据库 isBuiltIn 字段不能豁免收敛', async () => {
      await resetDb();
      await initPermissions();
      // 模拟直连数据库把 GUEST 的 isBuiltIn 改成 false 以逃避启动期对账
      await Role.create({
        name: '访客',
        code: 'GUEST',
        level: 1,
        isBuiltIn: false,
        permissions: [],
      });

      const result = await initRoles();

      expect(result.reconciled).toBe(1);
      expect(await rolePermCodes('GUEST')).toEqual(GUEST_CODES);
    });
  });

  // ==================================================================
  // C. reconcileSuperAdmin —— 超管唯一性对账
  // ==================================================================
  describe('reconcileSuperAdmin：超管归属对账', () => {
    test('C1 SUPER_ADMIN 角色缺失时只告警不创建、不抛错', async () => {
      await resetDb();
      await User.create({ username: 'admin', email: 'c1@example.com', password: PASSWORD });
      const usersBefore = await User.countDocuments({});
      const rolesBefore = await mongoose.connection.collection('roles').countDocuments({});

      await expect(reconcileSuperAdmin()).resolves.toBeUndefined();

      // 凭空造号会绕开密码策略与审计，因此这里必须一个文档都不新增
      expect(await User.countDocuments({})).toBe(usersBefore);
      expect(await mongoose.connection.collection('roles').countDocuments({})).toBe(rolesBefore);
      expect(logger.error).toHaveBeenCalledWith(expect.stringContaining('未找到 SUPER_ADMIN 角色'));
    });

    test('C3 已对齐时不下发写入（幂等：$addToSet 只在缺失时执行）', async () => {
      await resetDb();
      await initPermissions();
      await initRoles();
      const superRole = await Role.findOne({ code: 'SUPER_ADMIN' }).select('_id').lean();
      process.env.SUPER_ADMIN_USERNAME = 'c3_admin';
      await User.create({
        username: 'c3_admin',
        email: 'c3@example.com',
        password: PASSWORD,
        roles: [superRole._id],
      });

      const updateSpy = jest.spyOn(User, 'updateOne');
      const updateManySpy = jest.spyOn(User, 'updateMany');
      let updateCalls;
      let updateManyCalls;
      try {
        await expect(reconcileSuperAdmin()).resolves.toBeUndefined();
      } finally {
        // 同 A2：先取次数再还原，否则 not.toHaveBeenCalled() 恒真
        updateCalls = updateSpy.mock.calls.length;
        updateManyCalls = updateManySpy.mock.calls.length;
        updateSpy.mockRestore();
        updateManySpy.mockRestore();
      }

      expect(updateCalls).toBe(0);
      expect(updateManyCalls).toBe(0);
    });

    test('C4 缓存失效不可用时只记 debug 并继续（自愈不得因缓存层缺失而中断）', async () => {
      await resetDb();
      await initPermissions();
      await initRoles();
      const superRole = await Role.findOne({ code: 'SUPER_ADMIN' }).select('_id').lean();
      process.env.SUPER_ADMIN_USERNAME = 'c4_admin';
      await User.create({
        username: 'c4_admin',
        email: 'c4@example.com',
        password: PASSWORD,
        roles: [],
      });

      // 让惰性 require('../middleware/auth') 抛错，模拟模块不可用的降级场景
      jest.doMock('../../middleware/auth', () => {
        throw new Error('auth module unavailable');
      });
      try {
        await expect(reconcileSuperAdmin()).resolves.toBeUndefined();
      } finally {
        jest.dontMock('../../middleware/auth');
      }

      // 角色必须已补回（缓存失效失败不得回滚对账结果）
      const after = await User.findOne({ username: 'c4_admin' }).select('roles').lean();
      expect(after.roles.map(String)).toContain(String(superRole._id));
      expect(logger.debug).toHaveBeenCalledWith(expect.stringContaining('auth module unavailable'));
      // 复核模块注册表已恢复：后续用例仍能正常拿到真实的 invalidateUserCache
      const auth = require('../../middleware/auth');
      expect(typeof auth.invalidateUserCache).toBe('function');
    });

    test('C5 剥离扩散持有者时缓存失效不可用，同样只记 debug 且剥离已完成', async () => {
      await resetDb();
      await initPermissions();
      await initRoles();
      const superRole = await Role.findOne({ code: 'SUPER_ADMIN' }).select('_id').lean();
      process.env.SUPER_ADMIN_USERNAME = 'c5_admin';
      const target = await User.create({
        username: 'c5_admin',
        email: 'c5a@example.com',
        password: PASSWORD,
        roles: [superRole._id],
      });
      const extra = await User.create({
        username: 'c5_extra',
        email: 'c5b@example.com',
        password: PASSWORD,
        roles: [superRole._id],
      });

      jest.doMock('../../middleware/auth', () => {
        throw new Error('auth module unavailable');
      });
      try {
        await expect(reconcileSuperAdmin()).resolves.toBeUndefined();
      } finally {
        jest.dontMock('../../middleware/auth');
      }

      const extraAfter = await User.findById(extra._id).select('roles').lean();
      expect(extraAfter.roles.map(String)).not.toContain(String(superRole._id));
      const targetAfter = await User.findById(target._id).select('roles').lean();
      expect(targetAfter.roles.map(String)).toContain(String(superRole._id));
      expect(logger.error).toHaveBeenCalledWith(expect.stringContaining('c5_extra'));
      expect(logger.debug).toHaveBeenCalledWith(expect.stringContaining('auth module unavailable'));
    });

    test('C2 目标账户 roles 被直连数据库置为 null 时自愈（原会使启动崩溃，2026-09-18 修复）', async () => {
      await resetDb();
      await initPermissions();
      await initRoles();
      const superRole = await Role.findOne({ code: 'SUPER_ADMIN' }).select('_id').lean();
      process.env.SUPER_ADMIN_USERNAME = 'c2_target';
      // 绕过 schema 直连写：$addToSet 对 null 字段会抛 MongoServerError
      // （Cannot apply $addToSet to non-array field），而这是启动路径上唯一的自愈入口
      await User.collection.insertOne({
        username: 'c2_target',
        email: 'c2@example.com',
        password: 'x',
        roles: null,
      });

      await expect(reconcileSuperAdmin()).resolves.toBeUndefined();

      const after = await User.collection.findOne({ username: 'c2_target' });
      // 自愈后必须是真正的数组（不是 null 也不是被包一层）
      expect(Array.isArray(after.roles)).toBe(true);
      expect(after.roles.map(String)).toContain(String(superRole._id));
      expect(after.roles).toHaveLength(1);
    });
  });
  // ==================================================================
  // D. reconcileTokenBlacklistIndexes —— 遗留 token 索引清理
  // ==================================================================
  describe('reconcileTokenBlacklistIndexes：遗留 token 索引清理', () => {
    test('D1 真实遗留索引：第二条文档被 E11000 拒绝，对账删除后恢复写入', async () => {
      await mongoose.connection.dropCollection('tokenblacklists').catch(() => {});
      await TokenBlacklist.syncIndexes();
      const coll = mongoose.connection.collection('tokenblacklists');
      // 复刻早期 schema：明文 token 唯一索引 + 文档已不含该字段
      await coll.createIndex({ token: 1 }, { name: 'token_1', unique: true });
      const exp = new Date(Date.now() + 60_000);
      await coll.insertOne({ tokenHash: 'hash-a', expiresAt: exp });

      // 复现故障：第二条起必然撞 null 唯一键——这正是「refresh 轮换被误判为重放」的根因
      let blockedCode = null;
      try {
        await coll.insertOne({ tokenHash: 'hash-b', expiresAt: exp });
      } catch (e) {
        blockedCode = e.code;
      }
      expect(blockedCode).toBe(11000);

      await reconcileTokenBlacklistIndexes();

      const names = (await coll.indexes()).map((i) => i.name);
      expect(names).not.toContain('token_1');
      // 只删遗留索引：tokenHash 唯一索引与 TTL 索引必须存活
      expect(names).toContain('tokenHash_1');
      expect(names).toContain('expiresAt_1');

      // 行为闭环：清理后第二条文档可正常写入（故障已解除，而非只是索引名变了）
      await coll.insertOne({ tokenHash: 'hash-b', expiresAt: exp });
      expect(await coll.countDocuments({})).toBe(2);
      expect(logger.warn).toHaveBeenCalledWith(expect.stringContaining('token_1'));
    });

    test('D2 无遗留索引时幂等：重复启动不下发 dropIndex', async () => {
      await mongoose.connection.dropCollection('tokenblacklists').catch(() => {});
      await TokenBlacklist.syncIndexes();
      const coll = mongoose.connection.collection('tokenblacklists');
      const dropSpy = jest.spyOn(coll, 'dropIndex');
      let dropCalls;
      try {
        await reconcileTokenBlacklistIndexes();
        await reconcileTokenBlacklistIndexes();
        dropCalls = dropSpy.mock.calls.length;
      } finally {
        dropSpy.mockRestore();
      }
      expect(dropCalls).toBe(0);
      const names = (await coll.indexes()).map((i) => i.name);
      expect(names).toContain('tokenHash_1');
    });

    test('D3 复合索引含 token 时不得误删（只匹配 token 单键索引）', async () => {
      await mongoose.connection.dropCollection('tokenblacklists').catch(() => {});
      const coll = mongoose.connection.collection('tokenblacklists');
      await coll.createIndex({ token: 1, userId: 1 }, { name: 'token_1_userId_1' });
      await coll.createIndex({ token: 1 }, { name: 'token_1' });

      await reconcileTokenBlacklistIndexes();

      const names = (await coll.indexes()).map((i) => i.name);
      expect(names).toContain('token_1_userId_1');
      expect(names).not.toContain('token_1');
      await TokenBlacklist.syncIndexes();
    });

    test('D4 索引项缺少 key 字段时不抛错、不误删', async () => {
      const fake = {
        indexes: jest
          .fn()
          .mockResolvedValue([{ name: 'weird' }, { name: 'token_1', key: { token: 1 } }]),
        dropIndex: jest.fn(),
      };
      const spy = jest.spyOn(mongoose.connection, 'collection').mockReturnValueOnce(fake);
      try {
        await expect(reconcileTokenBlacklistIndexes()).resolves.toBeUndefined();
      } finally {
        spy.mockRestore();
      }
      // 无 key 的条目视为非遗留；真正的遗留索引仍被删除
      expect(fake.dropIndex.mock.calls.map((c) => c[0])).toEqual(['token_1']);
    });

    test('D5 集合不存在（全新部署）静默跳过，不告警不抛错', async () => {
      await mongoose.connection.dropCollection('tokenblacklists').catch(() => {});
      const nsErr = new Error('ns does not exist: test.tokenblacklists');
      nsErr.codeName = 'NamespaceNotFound';
      const fake = { indexes: jest.fn().mockRejectedValue(nsErr), dropIndex: jest.fn() };
      const spy = jest.spyOn(mongoose.connection, 'collection').mockReturnValueOnce(fake);
      try {
        await expect(reconcileTokenBlacklistIndexes()).resolves.toBeUndefined();
      } finally {
        spy.mockRestore();
      }
      expect(fake.dropIndex).not.toHaveBeenCalled();
      expect(logger.warn).not.toHaveBeenCalled();
    });

    test('D7 抛出物不是 Error（无 message）时告警不崩、仍不阻断启动', async () => {
      const fake = {
        indexes: jest.fn().mockRejectedValue({ codeName: 'Other' }),
        dropIndex: jest.fn(),
      };
      const spy = jest.spyOn(mongoose.connection, 'collection').mockReturnValueOnce(fake);
      try {
        // e.message 为 undefined：`e.message || ''` 兜底必须存在，否则正则匹配抛 TypeError
        await expect(reconcileTokenBlacklistIndexes()).resolves.toBeUndefined();
      } finally {
        spy.mockRestore();
      }
      const warnText = logger.warn.mock.calls.map((c) => String(c[0])).join('\n');
      expect(warnText).toContain('tokenblacklists 索引对账跳过');
      // 已知诊断缺口（非安全缺陷，已在报告中列出）：告警正文用 `${e.message}` 直接拼接，
      // 抛出物不是 Error 时会打印字面 "undefined"。此处刻意不断言其缺失——
      // 断言实现未承诺的行为只会制造假红。
    });

    test('D6 非 NamespaceNotFound 异常只告警不阻断启动', async () => {
      const fake = {
        indexes: jest.fn().mockRejectedValue(new Error('not authorized to list indexes')),
        dropIndex: jest.fn(),
      };
      const spy = jest.spyOn(mongoose.connection, 'collection').mockReturnValueOnce(fake);
      try {
        await expect(reconcileTokenBlacklistIndexes()).resolves.toBeUndefined();
      } finally {
        spy.mockRestore();
      }
      expect(logger.warn).toHaveBeenCalledWith(
        expect.stringContaining('not authorized to list indexes')
      );
    });
  });

  // ==================================================================
  // E. reconcileUserIndexes —— username 索引对账（零约束窗口防护）
  // ==================================================================
  describe('reconcileUserIndexes：username 索引对账', () => {
    /**
     * 重建 users 集合，只保留 legacy username_1（模拟升级前的库）。
     *
     * 必须显式删掉 schema 注册的 username_ci：dropCollection 在 mongoose 连接池下
     * 可能被同 worker 的 autoIndex/前序 syncIndexes 重新建回来，届时「大小写冲突」
     * 两条测试数据在插入阶段就会撞 username_ci（seed=5 实测），E2 再也走不到被测分支。
     */
    const seedLegacyIndex = async () => {
      await mongoose.connection.dropCollection('users').catch(() => {});
      const coll = mongoose.connection.collection('users');
      await coll.createIndex({ username: 1 }, { unique: true, name: 'username_1' });
      await coll.createIndex({ email: 1 }, { unique: true, name: 'email_1' });
      const names = (await coll.indexes()).map((i) => i.name);
      if (names.includes('username_ci')) {
        await coll.dropIndex('username_ci');
      }
      return coll;
    };

    test('E1 无 legacy 索引时幂等返回，不下发任何删除', async () => {
      await mongoose.connection.dropCollection('users').catch(() => {});
      await User.syncIndexes();
      const coll = mongoose.connection.collection('users');
      const dropSpy = jest.spyOn(coll, 'dropIndex');
      let dropCalls;
      try {
        await reconcileUserIndexes();
        dropCalls = dropSpy.mock.calls.length;
      } finally {
        dropSpy.mockRestore();
      }
      expect(dropCalls).toBe(0);
      const names = (await coll.indexes()).map((i) => i.name);
      expect(names).toContain('username_ci');
    });

    test('E2 存在大小写冲突时必须保留旧索引（不出现零约束窗口）', async () => {
      const coll = await seedLegacyIndex();
      await coll.insertOne({ username: 'AdminX', email: 'e2a@example.com', password: 'x' });
      await coll.insertOne({ username: 'adminx', email: 'e2b@example.com', password: 'x' });

      await reconcileUserIndexes();

      // 承重点：冲突未消除前不得删旧索引——先删后建若新建失败则两个约束都没有
      const names = (await coll.indexes()).map((i) => i.name);
      expect(names).toContain('username_1');
      expect(names).toContain('email_1');

      // 约束仍然生效：大小写等同的第三个别名必须被拒
      // 约束仍在：完全相同的用户名必须被拒（username_1 是二进制比较，
      // ADminX/adminx 在它眼里并不冲突——这正是必须换成 username_ci 的原因）
      let blockedCode = null;
      try {
        await coll.insertOne({ username: 'AdminX', email: 'e2c@example.com', password: 'x' });
      } catch (e) {
        blockedCode = e.code;
      }
      expect(blockedCode).toBe(11000);
      // 冲突必须被点名（含具体用户名），否则运维无法定位要合并哪个账号。
      // 用户名集合来自 $addToSet，顺序不定，故逐名断言而非拼串断言
      const conflictLog = logger.error.mock.calls
        .map((c) => String(c[0]))
        .find((m) => m.includes('大小写冲突'));
      expect(conflictLog).toBeDefined();
      expect(conflictLog).toContain('AdminX');
      expect(conflictLog).toContain('adminx');
    });

    test('E3 无冲突时删除 legacy 索引（大小写仿冒面收敛）', async () => {
      const coll = await seedLegacyIndex();
      await coll.insertOne({ username: 'solo', email: 'e3@example.com', password: 'x' });

      await reconcileUserIndexes();

      const names = (await coll.indexes()).map((i) => i.name);
      expect(names).not.toContain('username_1');
      expect(names).toContain('email_1');
      expect(logger.warn).toHaveBeenCalledWith(expect.stringContaining('username_1'));
      await User.syncIndexes();
    });

    test('E4 users 集合不存在（全新部署）静默跳过，不告警不抛错', async () => {
      await mongoose.connection.dropCollection('users').catch(() => {});
      logger.warn.mockClear();
      logger.error.mockClear();

      await expect(reconcileUserIndexes()).resolves.toBeUndefined();

      expect(logger.warn).not.toHaveBeenCalled();
      expect(logger.error).not.toHaveBeenCalled();
      await User.syncIndexes();
    });

    test('E6 抛出物不是 Error（无 message）时告警不崩、仍不阻断启动', async () => {
      const fake = {
        indexes: jest.fn().mockRejectedValue({ codeName: 'Other' }),
        dropIndex: jest.fn(),
      };
      const spy = jest.spyOn(mongoose.connection, 'collection').mockReturnValueOnce(fake);
      try {
        await expect(reconcileUserIndexes()).resolves.toBeUndefined();
      } finally {
        spy.mockRestore();
      }
      const warnText = logger.warn.mock.calls.map((c) => String(c[0])).join('\n');
      expect(warnText).toContain('users 索引对账跳过');
      // 同 D7：告警正文对非 Error 抛出物会打印 "undefined"（已知诊断缺口，报告列出）
    });

    test('E5 非 NamespaceNotFound 异常只告警不阻断启动', async () => {
      const fake = {
        indexes: jest.fn().mockRejectedValue(new Error('not authorized to list indexes')),
        dropIndex: jest.fn(),
      };
      const spy = jest.spyOn(mongoose.connection, 'collection').mockReturnValueOnce(fake);
      try {
        await expect(reconcileUserIndexes()).resolves.toBeUndefined();
      } finally {
        spy.mockRestore();
      }
      expect(logger.warn).toHaveBeenCalledWith(
        expect.stringContaining('not authorized to list indexes')
      );
    });
  });
  // ==================================================================
  // F. persistInitialPassword / createDefaultAdmin 边界（落盘与收紧）
  // ==================================================================
  describe('初始口令落盘与创建边界', () => {
    /** 播种超管角色并清掉同名管理员，使 createDefaultAdmin 走到创建分支 */
    const seedFreshAdminState = async () => {
      await resetDb();
      return Role.create({
        name: '超级管理员',
        code: 'SUPER_ADMIN',
        level: 10,
        isBuiltIn: true,
        permissions: [],
      });
    };

    test('F1 权限收紧失败时：如实告警「未能收紧」且绝不把口令打进日志', async () => {
      await seedFreshAdminState();
      const filePermission = require('../../utils/filePermission');
      const hardenSpy = jest.spyOn(filePermission, 'hardenPath').mockImplementation((_p, opts) => {
        // filePermission 的约定：告警经 opts.log 回传，且带 ⚠️ 前缀
        if (opts && typeof opts.log === 'function') opts.log('\u26a0\ufe0f icacls 执行失败');
        return { ok: false, method: 'icacls', detail: 'icacls 执行失败' };
      });
      const verifySpy = jest
        .spyOn(filePermission, 'verifyHardened')
        .mockReturnValue({ tightened: false, evidence: 'ACE 主体 3 条' });

      try {
        await inTempCwd(async (dir) => {
          const admin = await createDefaultAdmin();
          expect(admin).not.toBeNull();

          const warns = logger.warn.mock.calls.map((c) => String(c[0])).join('\n');
          // 收紧失败必须明说，而不是照打「已收紧」（这正是 M-05 修的误导形态）
          expect(warns).toContain('未能收紧');
          expect(warns).toContain('icacls 执行失败');
          // 回传前缀已被剥掉，否则日志里出现双重 ⚠️ 标记
          expect(warns).not.toContain('\u26a0\ufe0f icacls');

          const content = fs.readFileSync(path.join(dir, '.admin-initial-password'), 'utf8');
          const generated = content.match(/password: (.+)\n/)[1];
          expect(generated).toHaveLength(32);
          // M-02 底线：收紧失败告警不得把口令当「补救办法」打印出来
          expect(loggedText()).not.toContain(generated);
        });
      } finally {
        hardenSpy.mockRestore();
        verifySpy.mockRestore();
      }
    });

    test('F1b 收紧失败且 hardenPath 无 detail 时，告警回退到 verifyHardened 的 evidence', async () => {
      await seedFreshAdminState();
      const filePermission = require('../../utils/filePermission');
      const hardenSpy = jest
        .spyOn(filePermission, 'hardenPath')
        .mockReturnValue({ ok: false, method: 'none', detail: '' });
      const verifySpy = jest
        .spyOn(filePermission, 'verifyHardened')
        .mockReturnValue({ tightened: false, evidence: 'ACE 主体 2 条' });

      try {
        await inTempCwd(async () => {
          await createDefaultAdmin();
          // detail 为空时必须回退到 evidence，否则告警里没有任何可诊断线索
          expect(loggedText()).toContain('ACE 主体 2 条');
        });
      } finally {
        hardenSpy.mockRestore();
        verifySpy.mockRestore();
      }
    });

    test('F2 邮箱被外部抢占时降级为唯一后备邮箱，且角色与账户同一次写入完成', async () => {
      const role = await seedFreshAdminState();
      // 抢占 admin@example.com：公开注册开启期间任何外部人都能完成
      await User.create({
        username: 'squatter',
        email: 'admin@example.com',
        password: PASSWORD,
      });
      process.env.ADMIN_INITIAL_PASSWORD = PASSWORD;

      const admin = await createDefaultAdmin();

      // 不降级会让 User.create 抛 E11000 → initializeSystem rethrow → 进程退出，
      // 形成「可远程触发的开机 DoS」（代码注释承诺的防护）
      expect(admin.username).toBe('admin');
      expect(admin.email).toMatch(/^admin\+[0-9a-z]+@localhost\.invalid$/);
      expect(admin.roles.map(String)).toContain(String(role._id));
      expect(logger.warn).toHaveBeenCalledWith(expect.stringContaining('已被占用'));
      const stored = await User.findByUsername('admin');
      expect(String(stored._id)).toBe(String(admin._id));
    });

    test('F7 11000 但无 keyPattern 时不得误判为邮箱冲突（原样上抛）', async () => {
      await seedFreshAdminState();
      process.env.ADMIN_INITIAL_PASSWORD = PASSWORD;
      // 部分驱动/代理会剥掉 keyPattern；此时无法证明是 email 冲突，
      // 降级反而会把真实故障（如 username 冲突）掩盖成「邮箱被占用」
      const spy = jest
        .spyOn(User, 'create')
        .mockRejectedValueOnce(
          Object.assign(new Error('E11000 duplicate key error'), { code: 11000 })
        );

      let caught = null;
      try {
        await createDefaultAdmin();
      } catch (e) {
        caught = e;
      } finally {
        spy.mockRestore();
      }

      expect(caught).not.toBeNull();
      expect(caught.code).toBe(11000);
      expect(logger.warn).not.toHaveBeenCalledWith(expect.stringContaining('已被占用'));
    });

    test('F6 校验类错误（非 11000）原样上抛，不得被降级逻辑改写', async () => {
      await seedFreshAdminState();
      process.env.ADMIN_INITIAL_PASSWORD = PASSWORD;
      // 非法邮箱触发 schema 校验失败（非唯一键错误）
      process.env.ADMIN_INITIAL_EMAIL = 'not-an-email';

      let caught = null;
      try {
        await createDefaultAdmin();
      } catch (e) {
        caught = e;
      }

      expect(caught).not.toBeNull();
      expect(caught.name).toBe('ValidationError');
      // 没有降级告警：校验错误必须原样暴露，而不是被改写成「邮箱被占用」
      expect(logger.warn).not.toHaveBeenCalledWith(expect.stringContaining('已被占用'));
    });

    test('F3 非 email 的唯一键冲突必须上抛（不得被降级逻辑吞掉）', async () => {
      await seedFreshAdminState();
      process.env.ADMIN_INITIAL_PASSWORD = PASSWORD;
      const spy = jest.spyOn(User, 'create').mockRejectedValueOnce(
        Object.assign(new Error('E11000 duplicate key error'), {
          code: 11000,
          keyPattern: { username: 1 },
        })
      );

      let caught = null;
      try {
        await createDefaultAdmin();
      } catch (e) {
        caught = e;
      } finally {
        spy.mockRestore();
      }

      expect(caught).not.toBeNull();
      expect(caught.keyPattern).toEqual({ username: 1 });
      // 没有降级告警：这不是「邮箱被抢占」场景
      expect(logger.warn).not.toHaveBeenCalledWith(expect.stringContaining('已被占用'));
    });

    test('F4 缺少超管角色时不创建账户（避免造出无权限账户）', async () => {
      await resetDb();

      await inTempCwd(async (dir) => {
        await expect(createDefaultAdmin()).resolves.toBeNull();
        expect(fs.existsSync(path.join(dir, '.admin-initial-password'))).toBe(false);
        expect(await User.countDocuments({ username: 'admin' })).toBe(0);
      });
    });

    test('F5 管理员已存在时直接复用，不落盘、不覆盖其角色', async () => {
      const role = await seedFreshAdminState();
      const existing = await User.create({
        username: 'admin',
        email: 'existing-admin@example.com',
        password: PASSWORD,
        roles: [role._id],
      });

      await inTempCwd(async (dir) => {
        const admin = await createDefaultAdmin();
        expect(String(admin._id)).toBe(String(existing._id));
        expect(fs.existsSync(path.join(dir, '.admin-initial-password'))).toBe(false);
      });
    });
  });

  // ==================================================================
  // G. initializeSystem —— 启动编排顺序与失败语义
  // ==================================================================
  describe('initializeSystem：启动编排', () => {
    test('G1 全新空库一次启动即可自洽（权限/角色/管理员/配置齐备且互相关联）', async () => {
      await resetDb();
      process.env.SUPER_ADMIN_USERNAME = 'g1_admin';
      process.env.ADMIN_INITIAL_PASSWORD = PASSWORD;

      await inTempCwd(async (dir) => {
        await expect(initializeSystem()).resolves.toBeUndefined();

        expect(await Permission.countDocuments({})).toBe(defaultPermissions.length);
        expect(await Role.countDocuments({})).toBe(defaultRoles.length);

        // 超管账户必须存在且已绑定超管角色（createDefaultAdmin → reconcileSuperAdmin 的编排结果）
        const superRole = await Role.findOne({ code: 'SUPER_ADMIN' }).select('_id').lean();
        const admin = await User.findByUsername('g1_admin');
        expect(admin).not.toBeNull();
        expect(admin.roles.map(String)).toContain(String(superRole._id));

        expect(await SystemConfig.findOne({ key: 'allowPublicRegistration' })).not.toBeNull();
        expect(await SystemConfig.findOne({ key: 'loginCaptchaEnabled' })).not.toBeNull();

        // 显式注入口令时不落盘（运维已知晓，少一处泄露面）
        expect(fs.existsSync(path.join(dir, '.admin-initial-password'))).toBe(false);
      });
    });

    test('G2 播种阶段失败必须上抛（半初始化状态不得静默继续启动）', async () => {
      await resetDb();
      const spy = jest.spyOn(Permission, 'find').mockImplementationOnce(() => {
        throw new Error('db unreachable');
      });

      let caught = null;
      try {
        await initializeSystem();
      } catch (e) {
        caught = e;
      } finally {
        spy.mockRestore();
      }

      expect(caught).not.toBeNull();
      expect(caught.message).toBe('db unreachable');
      // 后续步骤不得被执行（角色未被播种）
      expect(await Role.countDocuments({})).toBe(0);
      expect(logger.error).toHaveBeenCalledWith(expect.stringContaining('db unreachable'));
    });

    test('G3 重复启动幂等：第二次启动不新增任何文档、不改动既有角色权限', async () => {
      await resetDb();
      process.env.SUPER_ADMIN_USERNAME = 'g3_admin';
      process.env.ADMIN_INITIAL_PASSWORD = PASSWORD;

      await inTempCwd(async () => {
        await initializeSystem();
        const snapshot = async () => ({
          perms: await Permission.countDocuments({}),
          roles: await Role.countDocuments({}),
          users: await User.countDocuments({}),
          guest: await rolePermCodes('GUEST'),
        });
        const before = await snapshot();

        await initializeSystem();

        expect(await snapshot()).toEqual(before);
      });
    });

    test('G4 内置角色被扩权后，一次重启即收敛（端到端自愈）', async () => {
      await resetDb();
      process.env.SUPER_ADMIN_USERNAME = 'g4_admin';
      process.env.ADMIN_INITIAL_PASSWORD = PASSWORD;

      await inTempCwd(async () => {
        await initializeSystem();
        const destructive = await Permission.findOne({ code: 'device:delete' })
          .select('_id')
          .lean();
        const guest = await Role.findOne({ code: 'GUEST' });
        await Role.collection.updateOne(
          { _id: guest._id },
          { $addToSet: { permissions: destructive._id } }
        );
        expect(await rolePermCodes('GUEST')).toContain('device:delete');

        await initializeSystem();

        expect(await rolePermCodes('GUEST')).toEqual([
          'alarm:read',
          'device:read',
          'inspection:read',
          'report:read',
        ]);
      });
    });
  });
});
