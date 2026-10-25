/**
 * T-5：巡检数据范围守卫的真实链路（不 mock 权限层）
 *
 * 审计 §7.2 T-5 指出 inspectionScopeAndSensitiveViewGuards.test.js 直接 mock 了
 * `assertRecordInScope` / `getDataScope`，只断言分支落点：权限守卫是否真的被调用、
 * 参数是否正确、越权响应会不会泄露记录字段，都没有被证明。
 *
 * 本文件保留一条**完全不 mock** 的端到端用例：真实 User/Role/Inspection 文档、
 * 真实 getDataScope + isRecordInScope + InspectionService。覆盖：
 *   - self 档看/改他人记录 → 403，且响应体不泄露标题、描述、属主；
 *   - self 档看自己的记录 → 200（正对照，证明上面不是「一律拒绝」）；
 *   - department 档跨部门记录 → 403，本部门 → 200。
 */

const mongoose = require('mongoose');

describe('T-5：巡检数据范围守卫真实链路（不 mock）', () => {
  let User;
  let Role;
  let Inspection;
  let inspectionController;

  const stamp = `${Date.now().toString(36)}${Math.random().toString(36).slice(2, 6)}`;
  const SECRET_TITLE = `跨部门机密巡检-${stamp}`;
  const SECRET_DESC = `仅属主可见的描述-${stamp}`;

  let selfRole;
  let deptRole;
  let operator; // self 档（level 4）
  let owner; // 记录属主
  let deptOperator; // department 档（level 7，D-1）
  let foreignInspection;
  let ownInspection;
  let sameDeptInspection;
  let otherDeptInspection;

  const makeReq = (userId, body = {}) => ({
    params: { id: '' },
    body,
    query: {},
    user: { userId: String(userId), username: 'probe', sid: 'sid-probe' },
    ip: '192.0.2.10',
    get: () => 'jest-agent',
  });

  const makeRes = () => {
    const res = { statusCode: null, body: null };
    res.status = jest.fn((code) => {
      res.statusCode = code;
      return res;
    });
    res.json = jest.fn((body) => {
      res.body = body;
      return res;
    });
    return res;
  };

  const invoke = async (handler, req) => {
    const res = makeRes();
    const next = jest.fn((error) => {
      if (error) throw error;
    });
    await handler(req, res, next);
    return res;
  };

  const createInspection = (ownerId, { title, building }) =>
    Inspection.create({
      inspectionType: 'daily',
      title,
      description: SECRET_DESC,
      status: 'pending',
      assignedTo: [ownerId],
      createdBy: ownerId,
      locations: [{ building }],
      planStartTime: new Date(Date.now() + 24 * 60 * 60 * 1000),
    });

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    User = require('../../models/User');
    Role = require('../../models/Role');
    Inspection = require('../../models/Inspection');
    // populate 的 ref 模型必须先注册，否则路径非空时会抛 MissingSchemaError
    require('../../models/FireDevice');
    inspectionController = require('../../controllers/inspectionController');

    selfRole = await Role.create({
      name: `T5自范围-${stamp}`,
      code: `T5_SELF_${stamp.toUpperCase()}`,
      level: 4,
      status: 'active',
    });
    deptRole = await Role.create({
      name: `T5部门范围-${stamp}`,
      code: `T5_DEPT_${stamp.toUpperCase()}`,
      level: 7,
      status: 'active',
    });

    const createUser = (name, roles, department) =>
      User.create({
        username: `${name}_${stamp}`,
        email: `${name}_${stamp}@example.com`,
        password: 'Aa1!aaaaaaaaaaaaaaaa',
        status: 'active',
        roles,
        department,
      });

    operator = await createUser('t5op', [selfRole._id], 'D-1');
    owner = await createUser('t5owner', [selfRole._id], 'D-2');
    deptOperator = await createUser('t5dept', [deptRole._id], 'D-1');

    foreignInspection = await createInspection(owner._id, {
      title: SECRET_TITLE,
      building: 'D-2',
    });
    ownInspection = await createInspection(operator._id, {
      title: `自己的巡检-${stamp}`,
      building: 'D-1',
    });
    sameDeptInspection = await createInspection(owner._id, {
      title: `同部门巡检-${stamp}`,
      building: 'D-1',
    });
    otherDeptInspection = await createInspection(owner._id, {
      title: `他部门巡检-${stamp}`,
      building: 'D-2',
    });
  }, 30000);

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      await Inspection.deleteMany({
        _id: {
          $in: [
            foreignInspection?._id,
            ownInspection?._id,
            sameDeptInspection?._id,
            otherDeptInspection?._id,
          ].filter(Boolean),
        },
      });
      await User.deleteMany({ username: new RegExp(`_${stamp}$`) });
      await Role.deleteMany({ code: new RegExp(`_${stamp.toUpperCase()}$`) });
      await mongoose.connection.close();
    }
  });

  test('self 档查看他人记录：403 且响应体不泄露任何记录字段', async () => {
    const req = makeReq(operator._id);
    req.params.id = String(foreignInspection._id);

    const res = await invoke(inspectionController.getInspectionById, req);

    expect(res.statusCode).toBe(403);
    expect(res.body.errors.errorCode).toBe('INSPECTION_VIEW_FORBIDDEN');
    const serialized = JSON.stringify(res.body);
    expect(serialized).not.toContain(SECRET_TITLE);
    expect(serialized).not.toContain(SECRET_DESC);
    expect(serialized).not.toContain(owner.username);
    expect(res.body.data).toBeUndefined();
  });

  test('self 档修改他人记录：403 且数据库内容原样保留', async () => {
    const req = makeReq(operator._id, { title: '被越权篡改的标题' });
    req.params.id = String(foreignInspection._id);

    const res = await invoke(inspectionController.updateInspection, req);

    expect(res.statusCode).toBe(403);
    expect(res.body.errors.errorCode).toBe('INSPECTION_OPERATE_FORBIDDEN');

    const stored = await Inspection.findById(foreignInspection._id).lean();
    expect(stored.title).toBe(SECRET_TITLE);
  });

  test('self 档查看自己的记录：200（正对照，守卫不是一律拒绝）', async () => {
    const req = makeReq(operator._id);
    req.params.id = String(ownInspection._id);

    const res = await invoke(inspectionController.getInspectionById, req);

    expect(res.statusCode).toBe(200);
    expect(res.body.data.title).toContain('自己的巡检');
  });

  test('department 档：同部门记录放行、跨部门记录 403', async () => {
    const sameReq = makeReq(deptOperator._id);
    sameReq.params.id = String(sameDeptInspection._id);
    const sameRes = await invoke(inspectionController.getInspectionById, sameReq);
    expect(sameRes.statusCode).toBe(200);
    expect(sameRes.body.data.title).toContain('同部门巡检');

    const otherReq = makeReq(deptOperator._id);
    otherReq.params.id = String(otherDeptInspection._id);
    const otherRes = await invoke(inspectionController.getInspectionById, otherReq);
    expect(otherRes.statusCode).toBe(403);
    expect(otherRes.body.errors.errorCode).toBe('INSPECTION_VIEW_FORBIDDEN');
  });
});
