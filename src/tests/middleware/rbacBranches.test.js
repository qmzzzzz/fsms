/**
 * rbac.js 分支补齐（branches 72.7% → 目标 85%+）
 *
 * 依据全量覆盖率基线（coverage-final.json）的未覆盖分支行号：
 *  - checkPermission：模块通配符 `module:*` 正向命中（L54）、AND 逻辑（L59）、
 *    无权限 403（L70-72）
 *  - checkRole：数组/单字符串入参、roleCodes 缺失回退查库（L93-99）、
 *    无匹配角色 403（L110）
 *  - getDataScope：用户不存在（L141）、角色为空（L144）、level 阈值边界
 *    9/8/7/4/1 与 maxLevel 多角色取最大（L159-167）
 *  - buildDataScopeFilter / isRecordInScope：纯函数的空入参、department 空、
 *    ownerField 数组、none、getPath 数组中间层（L186-273）
 *
 * 说明：L49 的 userHasPermission 内部重复 `*:*` 检查为防御性死分支
 * （外层 L37 已 return），不为其构造测试。
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

    test('模块通配符命中：持有 device:* 时通过 device:read 检查（L54）', async () => {
      jest.spyOn(User, 'getPermissions').mockResolvedValue(['device:*']);
      const req = makeReq();
      const res = makeRes();
      const next = jest.fn();
      await checkPermission('device:read')(req, res, next);
      expect(next).toHaveBeenCalled();
      expect(res.status).not.toHaveBeenCalled();
    });

    test('模块通配符不命中：持有 alarm:* 时请求 device:read → 403（L54-56）', async () => {
      jest.spyOn(User, 'getPermissions').mockResolvedValue(['alarm:*']);
      const req = makeReq();
      const res = makeRes();
      const next = jest.fn();
      await checkPermission('device:read')(req, res, next);
      expect(next).not.toHaveBeenCalled();
      expect(res.status).toHaveBeenCalledWith(403);
    });

    test('AND 逻辑：两个权限都持有才通过，缺一即 403（L59-64）', async () => {
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

    test('精确匹配命中：无需通配符直接通过（L47）', async () => {
      jest.spyOn(User, 'getPermissions').mockResolvedValue(['user:read']);
      const req = makeReq();
      const res = makeRes();
      const next = jest.fn();
      await checkPermission('user:read')(req, res, next);
      expect(next).toHaveBeenCalled();
    });

    test('超管通配：持有 *:* 时任意权限检查直接通过（L37-40）', async () => {
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

    test('roleCodes 缺失时回退查库并命中（L93-99 回退分支）', async () => {
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

    test('回退查库后仍无匹配角色 → 403（L108-110）', async () => {
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

    test('roleCodes 存在时优先使用，不查库（L93 正向分支）', async () => {
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

      await mkUser('noRoles', []); // 无角色 → none（L144）
      await mkUser('lv9', [r9._id]); // >=9 → all（边界）
      await mkUser('lv7', [r7._id]); // >=7 → department（边界）
      await mkUser('lv4', [r4._id]); // >=4 → self（边界）
      await mkUser('lv1', [r1._id]); // <4 → none
      await mkUser('mix', [r4._id, r7._id]); // 多角色取 maxLevel=7 → department（L148）
    });

    test('用户不存在 → { type: none }（L141）', async () => {
      const scope = await getDataScope(new mongoose.Types.ObjectId().toString());
      expect(scope.type).toBe('none');
    });

    test('角色为空 → { type: none }（L144）', async () => {
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

    test('多角色取 maxLevel：4+7 → department（L148）', async () => {
      expect((await getDataScope(ids.mix)).type).toBe('department');
    });
  });

  describe('buildDataScopeFilter（纯函数）', () => {
    test('null / all → 空条件（L186）', () => {
      expect(buildDataScopeFilter(null)).toEqual({});
      expect(buildDataScopeFilter({ type: 'all' })).toEqual({});
    });

    test('department 为空 → 兜底 ownerCondition(null)（L200-202）', () => {
      expect(buildDataScopeFilter({ type: 'department' })).toEqual({ createdBy: null });
    });

    test('ownerField 为数组 → $or 取并集（L191-193）', () => {
      const f = buildDataScopeFilter({ type: 'self', userId: 'u1' }, ['createdBy', 'operator']);
      expect(f).toEqual({ $or: [{ createdBy: 'u1' }, { operator: 'u1' }] });
    });

    test('none → 永不匹配条件 { _id: null }（L210-212）', () => {
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

    test('department 为空 → false 显式 deny（P1-3 零过滤越权入口的回归）', () => {
      const query = {};
      const ok = applyDataScopeToQuery(
        query,
        { type: 'department', department: '' },
        {
          ownerField: 'createdBy',
          departmentField: 'location.building',
        }
      );
      expect(ok).toBe(false);
      expect(query).toEqual({});
    });
  });

  describe('isRecordInScope（纯函数）', () => {
    test('无范围 / all → true；无文档 → false（L224-225）', () => {
      expect(isRecordInScope(null, {}, {})).toBe(true);
      expect(isRecordInScope({ type: 'all' }, null, {})).toBe(true);
      expect(
        isRecordInScope({ type: 'self' }, null, { ownerField: 'createdBy', userId: 'u1' })
      ).toBe(false);
    });

    test('department：命中与未命中（L260-263）', () => {
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

    test('department 范围但 scope 无 department 值 → false（L261-262）', () => {
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

    test('ownerField 数组：任一字段命中即在范围内（L266-268）', () => {
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

    test('中间层为数组：getPath 展开后命中元素字段（L229-234 数组分支）', () => {
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

    test('none → false（L270-272）', () => {
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
