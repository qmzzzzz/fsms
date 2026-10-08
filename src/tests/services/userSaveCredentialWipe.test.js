/**
 * ──────────────────────────────────────────────────────────────────────────
 * 被测对象：models/User.js 的 unselectedCredentialProjection 与它的三个使用点
 *   - services/authService.js  updateUserProfile（PUT /api/auth/profile）
 *   - services/authService.js  setUserLockStatus（POST /api/security/users/:id/lock）
 *   - services/userService.js  findUserForUpdate（PUT /api/users/:id 的载入端）
 * 守护的不变式：一次"读-改-save"不得把**本次根本没加载**的凭证列按 schema 默认值写回。
 *   具体说：save 的 $set 里不许出现 password/passwordHistory/phoneKey/mfaSecret/
 *   mfaLastCounter/mfaRecoveryCodes/mfaFailCount/mfaLockUntil，除非这次业务确实显式改了它。
 * 可证伪性：见文件末「变异实测」——三处 `.select(...)` 任一删除、或把 helper 改成
 *   字符串形态投影，本文件立刻转红；helper 退化成 `{}` 同样红。
 * ──────────────────────────────────────────────────────────────────────────
 *
 * 缺陷形状（Mongoose 8.24.1，实测非推断）：`findById` 不写投影时，发给 mongod 的是
 * `_optionsForExec()`（schema 的 select:false 已并入 ⇒ 服务器确实不返回凭证列），
 * 而**文档构造**拿的是 `_fieldsForExec()`（只含调用方自己写的投影 ⇒ 此处为 null）。
 * applyDefaults 因此看不见那份排除，给未返回的路径填上 schema 默认值，填出来的键被
 * 标记为脏 ⇒ 进 `$set`。于是"改一次头像"= 关掉 MFA + 抹掉 TOTP 重放防护与恢复码 +
 * 爆破计数清零 + 手机号检索键失联 + 口令历史清空。
 *
 * 全部用例都不连库：载入端用 `RealUser.hydrate(raw, query._fieldsForExec())` 复现
 * 服务器返回行 + 投影 这两件事的真实组合（raw 刻意**不含**凭证列，与 mongod 的返回一致），
 * `doc.save` 换成 `$__delta()` 采样 ⇒ 断言的就是"这条命令真发出去会带哪些键"。
 * 采样点选在 delta 而不是 DB 写入，是为了让判据对"投影怎么写"敏感、对"有没有库"无关。
 */

const mongoose = require('mongoose');

// ===== mock 声明区（必须在 require 被测模块之前）=====

const mockFindById = jest.fn();
const mockFindOne = jest.fn();
jest.mock('../../models/User', () => {
  const actual = jest.requireActual('../../models/User');
  return {
    ...actual,
    findById: (...args) => mockFindById(...args),
    findOne: (...args) => mockFindOne(...args),
  };
});

const mockRoleFind = jest.fn();
jest.mock('../../models/Role', () => ({
  find: (...args) => mockRoleFind(...args),
}));

jest.mock('../../models/AuditLog', () => ({
  create: jest.fn(() => Promise.resolve({ _id: 'audit-id' })),
  record: jest.fn(() => Promise.resolve(null)),
}));

jest.mock('../../utils/logger', () => ({
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
  debug: jest.fn(),
}));

// 操作者层级：走真函数的话要 populate 两条链，这里只把"操作者最高层级"这一个数交给测试
jest.mock('../../utils/permissionHelper', () => ({
  ...jest.requireActual('../../utils/permissionHelper'),
  getOperatorMaxLevel: jest.fn(() => Promise.resolve(10)),
}));

// 惰性 require 的两个副作用依赖：桩掉，避免把 redis/统计缓存拖进本套件
jest.mock('../../middleware/auth', () => ({
  invalidateUserCache: jest.fn(),
}));
jest.mock('../../services/statsCache', () => ({
  invalidateByUserId: jest.fn(),
}));

const RealUser = jest.requireActual('../../models/User');
const authService = require('../../services/authService');
const userService = require('../../services/userService');

/**
 * 凭证列清单：这里是**独立字面量**，不从 helper 取。
 * 否则 helper 退化成 `{}` 时，断言集合也同步变小，判据空转（第 2 族"零断言台账"）。
 */
const CREDENTIAL_PATHS = [
  'password',
  'passwordHistory',
  'phoneKey',
  'mfaSecret',
  'mfaLastCounter',
  'mfaRecoveryCodes',
  'mfaFailCount',
  'mfaLockUntil',
];

const ID = new mongoose.Types.ObjectId();
const OPERATOR_ID = new mongoose.Types.ObjectId();

/** mongod 在 select:false 生效时返回的那一行：不含任何凭证列 */
function serverRow(extra = {}) {
  return {
    _id: ID,
    username: 'zhangsan',
    realName: '张三',
    email: 'zhangsan@example.com',
    phone: 'ENC(v1:cipher-old)',
    department: 'd1',
    roles: [new mongoose.Types.ObjectId()],
    allowedIPs: '',
    avatar: '/upload/avatar/old.png',
    status: 'active',
    tokenVersion: 3,
    failedLoginCount: 2,
    lockUntil: null,
    lastLoginAt: new Date('2026-10-01T02:00:00Z'),
    mfaEnabled: true,
    passwordChangedAt: new Date('2026-01-01T00:00:00Z'),
    lastLoginIp: '10.0.0.7',
    remark: '',
    createdAt: new Date('2026-01-01T00:00:00Z'),
    updatedAt: new Date('2026-01-01T00:00:00Z'),
    __v: 0,
    ...extra,
  };
}

const saveLog = [];

/**
 * 复现"载入端拿到的是什么形状的文档"。
 * `carrier._fieldsForExec()` 就是缺陷的判定面：无用户投影时为 null（⇒ 默认值被填），
 * 对象形态排除投影时原样透传（⇒ 默认值被跳过），字符串形态时键带 `-` 前缀（⇒ 仍被填）。
 */
function hydrateThrough(selectArgs, rowExtra) {
  const carrier = RealUser.find({});
  for (const arg of selectArgs) carrier.select(arg);
  const fields = carrier._fieldsForExec();
  const doc = RealUser.hydrate(serverRow(rowExtra), fields);
  doc.save = async () => {
    const delta = doc.$__delta();
    const keys = delta && delta[1] && delta[1].$set ? Object.keys(delta[1].$set).sort() : [];
    saveLog.push({ keys, hit: keys.filter((k) => CREDENTIAL_PATHS.includes(k)) });
    return doc;
  };
  return doc;
}

/** 可链式再 await 的查询替身：形状与真实 Query 一致（select 返回自身、await 触发解析） */
function fakeQuery(rowExtra) {
  const selectArgs = [];
  const q = {
    select: (...args) => {
      selectArgs.push(...args);
      return q;
    },
    populate: () => q,
    lean: () => q,
    collation: () => q,
    exec: () => Promise.resolve(hydrateThrough(selectArgs, rowExtra)),
    then: (onFulfilled, onRejected) =>
      Promise.resolve()
        .then(() => hydrateThrough(selectArgs, rowExtra))
        .then(onFulfilled, onRejected),
  };
  return q;
}

const credentialHit = () => saveLog.flatMap((s) => s.hit);

beforeEach(() => {
  saveLog.length = 0;
  jest.clearAllMocks();
  mockFindById.mockImplementation(() => fakeQuery());
  mockFindOne.mockImplementation(() => fakeQuery());
  mockRoleFind.mockImplementation(() => {
    const roles = [
      { _id: new mongoose.Types.ObjectId(), level: 1, code: 'GUEST', isBuiltIn: false },
    ];
    return { select: () => Promise.resolve(roles), then: (f) => Promise.resolve(roles).then(f) };
  });
});

describe('第 0 组 · 仪器自证：采样点确实能看见清空', () => {
  test('无投影载入 + save：$set 里出现 5 个以上凭证列（这条不成立时后面全部判据都是空转）', () => {
    const doc = hydrateThrough([]);
    doc.avatar = '/upload/avatar/new.png';
    return doc.save().then(() => {
      expect(saveLog).toHaveLength(1);
      expect(saveLog[0].hit.length).toBeGreaterThanOrEqual(5);
      expect(saveLog[0].hit).toEqual(
        expect.arrayContaining([
          'mfaSecret',
          'mfaRecoveryCodes',
          'mfaFailCount',
          'phoneKey',
          'passwordHistory',
        ])
      );
    });
  });

  test('_fieldsForExec 的三种形状：null / 对象 0 / 字符串仍带 - 前缀', () => {
    expect(RealUser.find({})._fieldsForExec()).toBeNull();
    const obj = RealUser.find({})
      .select(RealUser.unselectedCredentialProjection())
      ._fieldsForExec();
    // 先钉"投影非空"：Mongoose 把空投影**归一化成 null**（实测 select({}) ⇒ _fieldsForExec()===null），
    // 少了这一句，helper 退化成 {} 时这条腿会以 TypeError 发红——红得不指名道姓（第 8 族）。
    expect(obj && Object.keys(obj).length).toBe(CREDENTIAL_PATHS.length);
    expect(Object.values(obj).every((v) => v === 0)).toBe(true);
    const str = RealUser.find({}).select('-mfaSecret -phoneKey')._fieldsForExec();
    // 字符串形态"看着是排除投影"却对 applyDefaults 不可见：键名带前缀，`in fields` 判不出
    expect(Object.keys(str)).toEqual(['-mfaSecret', '-phoneKey']);
  });

  test('字符串形态投影不是修法：照样清空（挡住"把 helper 换成一行字符串"的简化）', () => {
    const doc = hydrateThrough([CREDENTIAL_PATHS.map((p) => `-${p}`).join(' ')]);
    doc.avatar = '/x.png';
    return doc.save().then(() => {
      expect(credentialHit().length).toBeGreaterThanOrEqual(5);
    });
  });
});

describe('第 1 组 · helper 的派生形状', () => {
  test('键集合等于独立字面量的 8 条凭证路径，值全为 0，无 - 前缀', () => {
    const projection = RealUser.unselectedCredentialProjection();
    expect(Object.keys(projection).sort()).toEqual([...CREDENTIAL_PATHS].sort());
    expect(Object.values(projection).every((v) => v === 0)).toBe(true);
    expect(Object.keys(projection).some((k) => k.startsWith('-') || k.includes(' '))).toBe(false);
  });

  test('返回的是新对象：调用方就地改动投影不得污染下一次载入', () => {
    const a = RealUser.unselectedCredentialProjection();
    delete a.mfaSecret;
    expect('mfaSecret' in RealUser.unselectedCredentialProjection()).toBe(true);
  });

  test('派生自 schema 而非手写清单：临时给 schema 加一条 select:false 路径即出现在投影里', () => {
    const path = 'canaryCredentialPath';
    RealUser.schema.path(path, { type: String, select: false, default: 'SENTINEL' });
    try {
      expect(Object.keys(RealUser.unselectedCredentialProjection())).toContain(path);
    } finally {
      delete RealUser.schema.paths[path];
      delete RealUser.schema.tree[path];
      // 复原后必须立刻回到 8 条：金丝雀留在 schema 里就等于给真模型加了个字段
      expect(Object.keys(RealUser.unselectedCredentialProjection())).toHaveLength(
        CREDENTIAL_PATHS.length
      );
    }
  });
});

describe('第 2 组 · 显式写凭证列仍然落库（排除的是读，不是写）', () => {
  test('改手机号：pre 钩子形态的 phoneKey 显式赋值必须与 phone 一起进 $set', () => {
    const doc = hydrateThrough([RealUser.unselectedCredentialProjection()]);
    doc.phone = 'ENC(v2:cipher-new)';
    doc.phoneKey = 'hmac-of-new-phone';
    return doc.save().then(() => {
      expect(saveLog[0].keys).toEqual(expect.arrayContaining(['phone', 'phoneKey']));
      expect(saveLog[0].hit).toEqual(['phoneKey']);
    });
  });

  test('显式重置口令历史：被排除的 passwordHistory 照样能写回去', () => {
    const doc = hydrateThrough([RealUser.unselectedCredentialProjection()]);
    doc.passwordHistory = ['$2b$10$aaa', '$2b$10$bbb'];
    return doc.save().then(() => {
      expect(saveLog[0].hit).toEqual(['passwordHistory']);
    });
  });
});

describe('第 3 组 · 三个真实站点的端到端 delta', () => {
  test('updateUserProfile 只改头像：$set 里没有凭证列，且头像确实写出去了', async () => {
    const result = await authService.updateUserProfile(ID, { avatar: '/upload/avatar/new.png' });
    expect(result.outcome).toBe('OK');
    expect(saveLog).toHaveLength(1);
    expect(saveLog[0].hit).toEqual([]);
    expect(saveLog[0].keys).toContain('avatar');
  });

  test('updateUserProfile 改手机号：除本次确实要写的 phone 外不得命中任何凭证列', async () => {
    const result = await authService.updateUserProfile(ID, { phone: '13800001234' });
    expect(result.outcome).toBe('OK');
    expect(saveLog).toHaveLength(1);
    expect(saveLog[0].keys).toContain('phone');
    // 本套件的假 save 只取 $__delta()，不跑 pre('validate') ⇒ 钩子那份 phoneKey 同步
    // 不会自动出现（它由第 2 组用显式赋值单独钉）。这里判的是"有没有多写"：
    // 除 phone 之外出现任何一个凭证列键，就是清空回归。
    expect(saveLog[0].keys.filter((k) => CREDENTIAL_PATHS.includes(k))).toEqual([]);
  });

  test('setUserLockStatus 锁定：不得改动 MFA/口令侧任何凭证列', async () => {
    const result = await authService.setUserLockStatus(
      ID,
      { locked: true, reason: '违规操作' },
      { operatorId: OPERATOR_ID, operatorUsername: 'admin', ip: '10.0.0.9', userAgent: 'node-test' }
    );
    expect(result.outcome).toBe('OK');
    expect(saveLog).toHaveLength(1);
    expect(saveLog[0].hit).toEqual([]);
    expect(saveLog[0].keys).toContain('status');
  });

  test('setUserLockStatus 解锁：清 lockUntil/failedLoginCount 时不得顺手清 mfaFailCount', async () => {
    mockFindById.mockImplementation(() =>
      fakeQuery({ status: 'locked', lockUntil: new Date('2026-10-04T00:00:00Z') })
    );
    const result = await authService.setUserLockStatus(
      ID,
      { locked: false },
      { operatorId: OPERATOR_ID, operatorUsername: 'admin', ip: '10.0.0.9', userAgent: 'node-test' }
    );
    expect(result.outcome).toBe('OK');
    expect(saveLog).toHaveLength(1);
    expect(saveLog[0].hit).toEqual([]);
    expect(saveLog[0].keys).toEqual(
      expect.arrayContaining(['status', 'lockUntil', 'failedLoginCount'])
    );
  });

  test('userService.findUserForUpdate 交出去的文档自带排除投影（PUT /api/users/:id 的载入端）', async () => {
    const doc = await userService.findUserForUpdate(ID);
    doc.avatar = '/upload/avatar/edited.png';
    await userService.saveUser(doc);
    expect(saveLog).toHaveLength(1);
    expect(saveLog[0].hit).toEqual([]);
    expect(saveLog[0].keys).toContain('avatar');
  });
});

/*
 * 变异实测（2026-10-03，`node tools/ledger.js <被测> <本文件> <模式=预测>`，
 * 施加→跑闸→按字节恢复并 sha 校验；基线 4 次全绿 13/13）：
 *
 *   腿号：#1 无投影控制 #2 _fieldsForExec 三形状 #3 字符串形态非修法 #4 键集合=独立字面量
 *         #5 返回新对象 #6 schema 派生金丝雀 #7 phoneKey 显式写 #8 passwordHistory 显式写
 *         #9 profile 改头像 #10 profile 改手机号 #11 锁定 #12 解锁 #13 findUserForUpdate
 *
 *   drop-profile-projection            预测 红9,10      实测 红9,10
 *   drop-lock-projection               预测 红11,12     实测 红11,12
 *   drop-findforupdate-projection      预测 红13        实测 红13
 *   helper-select-true（投影退化成 {}） 预测 红2,4-13    实测 红2,4-13
 *   helper-to-string-form（一行字符串） 预测 红4-13      实测 红4-13
 *   sample-delta-as-empty（改闸自身）   预测 红1,3,7-13  实测 红1,3,7-13
 *
 *   三条载入端各自独立可杀：删 A 处的投影只红 A 处那两条腿，不会连带把 B 处也报绿，
 *   所以"只补了一处"这种半修复挡得住。
 *   #1/#3 是不依赖 helper 的仪器控制腿：helper 变异时它们必须**不红**（红了说明它们在
 *   重复测同一件事），采样点变异时它们必须**红**（不红说明整套行为判据在空转）。
 *   两次预测失手都记在这里：
 *   ① helper-select-true 起初预测 #2 为绿，实测红——原因是 Mongoose 把空投影归一化成
 *      null（`select({})` ⇒ `_fieldsForExec()===null`），旧版 #2 直接 `Object.values(null)`
 *      以 TypeError 发红：红得不指名道姓，属自家门禁的第 8 族。已改成先钉投影非空。
 *   ② 假 save 不跑 pre('validate')，所以 phoneKey 的自动同步在第 3 组不可观测——
 *      #10 起初按"会命中 phoneKey"预测，属仪器能力盲区（第 10 族），已改为
 *      "除本次确实要写的 phone 外不得命中任何凭证列"，phoneKey 那条由 #7 显式赋值钉住。
 */
