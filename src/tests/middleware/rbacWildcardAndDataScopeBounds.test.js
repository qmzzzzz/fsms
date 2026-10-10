/**
 * ──────────────────────────────────────────────────────────────────────────
 * 本文件的定位（2026-09-20 补注，由变异审计批量补齐）
 *
 * 被测对象：rbac.js：通配符权限、角色匹配、数据范围 level 阈值、ownerField 数组
 * 守护的不变式：`module:*` 通配必须与 AND 逻辑一致；level 阈值边界必须精确；ownerField 数组必须被展开
 * 可证伪性：本轮未做变异实测
 *
 * 命名沿革：2026-09-20 由 `rbacBranches.test.js` 更名。旧名里的
 *   Coverage / Gap / Hardening / Branch 说的是「当初为什么写它」（补覆盖率基线），
 *   **不是它的价值判据**；它能否挡住回归，由变异实测回答，不由文件名回答。
 *   旧名保留在本行，便于既往审计报告的 `grep 旧文件名` 仍能定位到本文件。
 * 依据：`deliverables/AGENT工作总账与待办-2026-09-21.md`（§2.9 测试资产 / §6 方法；原编号 §6-AW/AX/AY/AZ/BA 已随原台账删除，无法逐条映射）
 * ──────────────────────────────────────────────────────────────────────────
 */

/**
 * rbac.js 分支补齐
 *
 * 【行号说明】本文件早期版本按覆盖率基线逐条标注 `L<行号>`。后续修复使 rbac.js
 * 行号位移，部分标注已指向注释行。按「注释必须与实现同步」的要求，现改为语义
 * 描述、不再写行号。
 *
 * 覆盖分支：
 *  - checkPermission：模块通配符 `module:*` 正向命中、AND 逻辑、无权限 403
 *  - checkRole：数组/单字符串入参、roleCodes 缺失回退查库、无匹配角色 403
 *  - getDataScope：用户不存在、角色为空、level 阈值边界（9/8/7/4/1）
 *    与 maxLevel 多角色取最大
 *  - buildDataScopeFilter / isRecordInScope：纯函数的空入参、department 空、
 *    ownerField 数组、none、getPath 数组中间层
 *
 * 说明：userHasPermission 内层的重复 `*:*` 检查为防御性死分支
 * （外层已 return），不为其构造测试。
 */

const mongoose = require('mongoose');
const {
  checkPermission,
  checkRole,
  getDataScope,
  buildDataScopeFilter,
  applyDataScopeToQuery,
  isRecordInScope,
} = require('../../middleware/rbac');
const { randomPassword } = require('../helpers/buildLoginEnvelope');

// ---- mock res/next 工具 ----
const makeRes = () => {
  const res = {};
  res.status = jest.fn(() => res);
  res.json = jest.fn(() => res);
  res.statusCode = undefined;
  res.status.mockImplementation((code) => {
    res.statusCode = code;
    return res;
  });
  return res;
};

describe('rbac.js 分支补齐', () => {
  let User;
  let Role;
  const PASSWORD = randomPassword();
  const stamp = `rbb${Date.now()}`.replace(/\d/g, (d) => 'abcdefghij'[Number(d)]);

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    User = require('../../models/User');
    Role = require('../../models/Role');
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });

  describe('checkPermission（mock User.getPermissions）', () => {
    const makeReq = () => ({ user: { userId: new mongoose.Types.ObjectId().toString() } });

    afterEach(() => {
      jest.restoreAllMocks();
    });

    test('模块通配符命中：持有 device:* 时通过 device:read 检查', async () => {
      jest.spyOn(User, 'getPermissions').mockResolvedValue(['device:*']);
      const req = makeReq();
      const res = makeRes();
      const next = jest.fn();
      await checkPermission('device:read')(req, res, next);
      expect(next).toHaveBeenCalled();
      expect(res.status).not.toHaveBeenCalled();
    });

    test('模块通配符不命中：持有 alarm:* 时请求 device:read → 403', async () => {
      jest.spyOn(User, 'getPermissions').mockResolvedValue(['alarm:*']);
      const req = makeReq();
      const res = makeRes();
      const next = jest.fn();
      await checkPermission('device:read')(req, res, next);
      expect(next).not.toHaveBeenCalled();
      expect(res.status).toHaveBeenCalledWith(403);
    });

    test('AND 逻辑：两个权限都持有才通过，缺一即 403', async () => {
      jest.spyOn(User, 'getPermissions').mockResolvedValue(['user:read', 'user:export']);
      const req = makeReq();
      const res = makeRes();

      const nextOk = jest.fn();
      await checkPermission(['user:read', 'user:export'], 'AND')(req, res, nextOk);
      expect(nextOk).toHaveBeenCalled();

      const nextFail = jest.fn();
      await checkPermission(['user:read', 'user:delete'], 'AND')(req, res, nextFail);
      expect(nextFail).not.toHaveBeenCalled();
      expect(res.status).toHaveBeenCalledWith(403);
    });

    test('精确匹配命中：无需通配符直接通过', async () => {
      jest.spyOn(User, 'getPermissions').mockResolvedValue(['user:read']);
      const req = makeReq();
      const res = makeRes();
      const next = jest.fn();
      await checkPermission('user:read')(req, res, next);
      expect(next).toHaveBeenCalled();
    });

    test('超管通配：持有 *:* 时任意权限检查直接通过', async () => {
      jest.spyOn(User, 'getPermissions').mockResolvedValue(['*:*']);
      const req = makeReq();
      const res = makeRes();
      const next = jest.fn();
      // AND 多权限同样直通：*:* 短路发生在逐项匹配之前
      await checkPermission(['device:delete', 'user:export'], 'AND')(req, res, next);
      expect(next).toHaveBeenCalled();
      expect(res.status).not.toHaveBeenCalled();
    });
  });

  describe('checkRole（mock User.findById 回退路径）', () => {
    afterEach(() => {
      jest.restoreAllMocks();
    });

    const makeReq = () => ({
      user: { userId: new mongoose.Types.ObjectId().toString() },
    });

    test('roleCodes 缺失时回退查库并命中', async () => {
      jest.spyOn(User, 'findById').mockReturnValue({
        populate: jest.fn().mockReturnThis(),
        lean: jest.fn().mockResolvedValue({ roles: [{ code: 'OPERATOR' }] }),
      });
      const req = makeReq(); // 无 roleCodes 字段
      const res = makeRes();
      const next = jest.fn();
      await checkRole('OPERATOR')(req, res, next);
      expect(next).toHaveBeenCalled();
      // 请求级缓存生效：第二次不再查库
      const next2 = jest.fn();
      await checkRole('OPERATOR')(req, res, next2);
      expect(User.findById).toHaveBeenCalledTimes(1);
      expect(next2).toHaveBeenCalled();
    });

    test('回退查库后仍无匹配角色 → 403', async () => {
      jest.spyOn(User, 'findById').mockReturnValue({
        populate: jest.fn().mockReturnThis(),
        lean: jest.fn().mockResolvedValue({ roles: [{ code: 'GUEST' }] }),
      });
      const req = makeReq();
      const res = makeRes();
      const next = jest.fn();
      await checkRole(['ADMIN', 'SUPER_ADMIN'])(req, res, next);
      expect(next).not.toHaveBeenCalled();
      expect(res.status).toHaveBeenCalledWith(403);
    });

    test('roleCodes 存在时优先使用，不查库', async () => {
      const findById = jest.spyOn(User, 'findById');
      const req = { user: { userId: 'x', roleCodes: ['ADMIN'] } };
      const res = makeRes();
      const next = jest.fn();
      await checkRole('ADMIN')(req, res, next);
      expect(next).toHaveBeenCalled();
      expect(findById).not.toHaveBeenCalled();
    });
  });

  describe('getDataScope（真实 DB：level 阈值边界）', () => {
    const ids = {};

    beforeAll(async () => {
      // level 阈值：ALL=9 / DEPARTMENT=7 / SELF=4（与 initData 种子角色 10/8/6/4/1 的口径对应）
      const mkRole = (name, code, level) => Role.create({ name, code, level, permissions: [] });
      const r9 = await mkRole(`RB边界9${stamp}`, `rbb9${stamp}`, 9);
      const r7 = await mkRole(`RB边界7${stamp}`, `rbb7${stamp}`, 7);
      const r4 = await mkRole(`RB边界4${stamp}`, `rbb4${stamp}`, 4);
      const r1 = await mkRole(`RB边界1${stamp}`, `rbb1${stamp}`, 1);

      const mkUser = async (tag, roles) => {
        const u = await User.create({
          username: `rbb${tag}${stamp}`,
          email: `rbb${tag}${stamp}@example.com`,
          password: PASSWORD,
          roles,
        });
        ids[tag] = String(u._id);
      };

      await mkUser('noRoles', []); // 无角色 → none
      await mkUser('lv9', [r9._id]); // >=9 → all（边界）
      await mkUser('lv7', [r7._id]); // >=7 → department（边界）
      await mkUser('lv4', [r4._id]); // >=4 → self（边界）
      await mkUser('lv1', [r1._id]); // <4 → none
      await mkUser('mix', [r4._id, r7._id]); // 多角色取 maxLevel=7 → department
    });

    test('用户不存在 → { type: none }', async () => {
      const scope = await getDataScope(new mongoose.Types.ObjectId().toString());
      expect(scope.type).toBe('none');
    });

    test('角色为空 → { type: none }', async () => {
      const scope = await getDataScope(ids.noRoles);
      expect(scope.type).toBe('none');
    });

    test('level 9（ALL 边界）→ all；level 7（DEPARTMENT 边界）→ department', async () => {
      expect((await getDataScope(ids.lv9)).type).toBe('all');
      expect((await getDataScope(ids.lv7)).type).toBe('department');
    });

    test('level 4（SELF 边界）→ self；level 1 → none', async () => {
      expect((await getDataScope(ids.lv4)).type).toBe('self');
      expect((await getDataScope(ids.lv1)).type).toBe('none');
    });

    test('多角色取 maxLevel：4+7 → department', async () => {
      expect((await getDataScope(ids.mix)).type).toBe('department');
    });
  });

  describe('buildDataScopeFilter（纯函数）', () => {
    test('null / undefined → deny（{ _id: null }）；all → 空条件', () => {
      // 无范围信息一律 deny，与同模块 isRecordInScope / applyDataScopeToQuery 同向。
      // 原断言 `buildDataScopeFilter(null) === {}` 把 fail-open 写成了契约：`{}` 是
      // **空条件 = 全量放行**，而两个兄弟函数对同一情形给出的是 deny——
      // 「谁都可能被下一个调用方当成依据」（同 isRecordInScope 的注释）。
      expect(buildDataScopeFilter(null)).toEqual({ _id: null });
      expect(buildDataScopeFilter(undefined)).toEqual({ _id: null });
      expect(buildDataScopeFilter({ type: 'all' })).toEqual({});
    });

    test('department 为空 → 显式 deny { _id: null }（不得回落到 ownerCondition(null)）', () => {
      // ownerCondition(null) 形如 {createdBy:null}，在 Mongo 里匹配"字段缺失"的文档，
      // 并非永不匹配——曾把"部门为空"错当成接近空集，实为按属主粗筛（越权面）。
      expect(buildDataScopeFilter({ type: 'department' })).toEqual({ _id: null });
    });

    test('department 有值 → 精确等值匹配（不用 RegExp，防正则注入绕过隔离）', () => {
      expect(buildDataScopeFilter({ type: 'department', department: 'A栋' })).toEqual({
        'location.building': 'A栋',
      });
      expect(buildDataScopeFilter({ type: 'department', department: '.*' })).toEqual({
        'location.building': '.*',
      });
    });

    // deny 的另一臂：self 缺 userId 时 ownerCondition(undefined) 语义含糊，必须显式空集。
    test('self 缺 userId → deny（{ _id: null }），不落到 ownerCondition(undefined)', () => {
      expect(buildDataScopeFilter({ type: 'self' })).toEqual({ _id: null });
      expect(buildDataScopeFilter({ type: 'self', userId: '' })).toEqual({ _id: null });
    });

    test('ownerField 为数组 → $or 取并集', () => {
      const f = buildDataScopeFilter({ type: 'self', userId: 'u1' }, ['createdBy', 'operator']);
      expect(f).toEqual({ $or: [{ createdBy: 'u1' }, { operator: 'u1' }] });
    });

    test('none → 永不匹配条件 { _id: null }', () => {
      expect(buildDataScopeFilter({ type: 'none' })).toEqual({ _id: null });
    });
  });

  describe('applyDataScopeToQuery（纯函数：冲突合并与 deny 信号）', () => {
    test('department 与用户筛选同字段冲突 → $and 交集，不覆盖任一方', () => {
      const query = { 'location.building': 'A栋' };
      const ok = applyDataScopeToQuery(
        query,
        { type: 'department', department: 'B栋' },
        {
          ownerField: 'createdBy',
          departmentField: 'location.building',
        }
      );
      expect(ok).toBe(true);
      expect(query.$and).toEqual([{ 'location.building': 'A栋' }, { 'location.building': 'B栋' }]);
      expect(query['location.building']).toBeUndefined();
    });

    test('department 为空 → 抛 403 显式 deny（P1-3 零过滤越权入口的回归）', () => {
      const query = {};
      // #12 之后 deny 的形态是抛 ApiError(403, DATA_SCOPE_DENIED)，不再返回 false：
      // false 返回值没有任何机制保证每个调用方都检查它（#12 的出发点）。
      // query 必须保持原样——抛错不得顺带修改调用方的查询对象。
      expect(() =>
        applyDataScopeToQuery(
          query,
          { type: 'department', department: '' },
          {
            ownerField: 'createdBy',
            departmentField: 'location.building',
          }
        )
      ).toThrow(/没有可用的数据范围/);
      expect(query).toEqual({});
    });
  });

  describe('isRecordInScope（纯函数）', () => {
    // 无范围信息一律 deny（与同模块 applyDataScopeToQuery 同向）。
    // 原断言 `isRecordInScope(null, ...) === true` 把 fail-open 写成了契约：
    // 两个兄弟函数对同一情形给出相反答案，谁都可能被下一个调用方当成依据。
    test('无范围 → deny；all → true；无文档 → false', () => {
      expect(isRecordInScope(null, {}, {})).toBe(false);
      expect(isRecordInScope({ type: 'all' }, null, {})).toBe(true);
      expect(
        isRecordInScope({ type: 'self' }, null, { ownerField: 'createdBy', userId: 'u1' })
      ).toBe(false);
    });

    test('department：命中与未命中', () => {
      const scope = { type: 'department', department: 'A栋' };
      expect(
        isRecordInScope(
          scope,
          { location: { building: 'A栋' } },
          {
            ownerField: 'createdBy',
            departmentField: 'location.building',
          }
        )
      ).toBe(true);
      expect(
        isRecordInScope(
          scope,
          { location: { building: 'B栋' } },
          {
            ownerField: 'createdBy',
            departmentField: 'location.building',
          }
        )
      ).toBe(false);
    });

    test('department 范围但 scope 无 department 值 → false', () => {
      expect(
        isRecordInScope(
          { type: 'department' },
          { location: { building: 'A栋' } },
          {
            ownerField: 'createdBy',
            departmentField: 'location.building',
          }
        )
      ).toBe(false);
    });

    test('ownerField 数组：任一字段命中即在范围内', () => {
      const scope = { type: 'self' };
      const ok = isRecordInScope(
        scope,
        { createdBy: 'u1', operator: 'u2' },
        {
          ownerField: ['createdBy', 'operator'],
          userId: 'u2',
        }
      );
      expect(ok).toBe(true);
    });

    test('中间层为数组：getPath 展开后命中元素字段', () => {
      const scope = { type: 'self' };
      const doc = { maintenanceRecord: [{ operator: 'u1' }, { operator: 'u2' }] };
      expect(
        isRecordInScope(scope, doc, { ownerField: 'maintenanceRecord.operator', userId: 'u2' })
      ).toBe(true);
    });

    test('populate 后的文档对象：取 _id 比较（collectValues _id 分支）', () => {
      const scope = { type: 'self' };
      const doc = { createdBy: { _id: 'u1', name: '张三' } };
      expect(isRecordInScope(scope, doc, { ownerField: 'createdBy', userId: 'u1' })).toBe(true);
    });

    test('none → false', () => {
      expect(
        isRecordInScope(
          { type: 'none' },
          { createdBy: 'u1' },
          { ownerField: 'createdBy', userId: 'u1' }
        )
      ).toBe(false);
    });

    test('ObjectId 值与字符串 userId 比较（collectValues _bsontype 分支）', () => {
      const oid = new mongoose.Types.ObjectId();
      const scope = { type: 'self' };
      const doc = { createdBy: oid };
      expect(isRecordInScope(scope, doc, { ownerField: 'createdBy', userId: oid.toString() })).toBe(
        true
      );
    });
  });
});
