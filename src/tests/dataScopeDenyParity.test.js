/**
 * 数据范围 deny 语义的跨路径一致性
 *
 * 背景：本仓库已经把数据范围的"唯一收敛点"定为 `applyDataScopeToQuery`
 * （见 middleware/rbac.js 该函数头注释的 P1-3 修复记录），它把
 * "type=department 但 department 为空" 显式判为 deny。
 * 但 `buildDataScopeFilter` 对同一情形返回的是 `ownerCondition(null)`，
 * 而报表/仪表盘/统计/导出（scopeFilterFor）、设备统计（deviceController）、
 * 用户统计（userController.getUserStats）三条路径直接调的是后者。
 *
 * 本套件要证伪的是这两句话：
 *   ① "null 值匹配不到任何文档"（rbacWildcardAndDataScopeBounds.test.js 与
 *      businessStateConsistencyInvariants.test.js 的注释都这么写，因而把兜底当成 deny）——
 *      MongoDB 的 `{field: null}` 匹配"字段为 null **或字段缺失**"的文档，
 *      未建档/未维护的 seeded 设备恰好全是这一类，所以它是**跨部门可见集**，不是空集。
 *   ② "列表与详情口径一致"（isRecordInScope 头注释这么写）——
 *      同一份数据范围下，详情路径 isRecordInScope 已经返回 false（deny），
 *      列表路径却能匹配到文档。两者必须逐条相等，否则就是自相矛盾的闸。
 *
 * 用例 1 钉住"事实"，用例 2-5 钉住"结论"：修好之前 2-5 必红。
 */

const mongoose = require('mongoose');

describe('数据范围：空部门/空属主必须 deny，且列表与详情口径必须一致', () => {
  let FireDevice;
  let rbac;
  let scopeFilterFor;
  let deviceFields;

  const otherOperator = () => new mongoose.Types.ObjectId();

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    FireDevice = require('../models/FireDevice');
    rbac = require('../middleware/rbac');
    scopeFilterFor = require('../services/reportExportService').scopeFilterFor;
    deviceFields = require('../constants/dataScopeFields').DATA_SCOPE_FIELDS.device;
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });

  beforeEach(async () => {
    await FireDevice.deleteMany({});
  });

  /** 属主缺失、但确实存在于库中的一台设备（模拟系统播种/未建档设备） */
  const makeOwnerlessDevice = (building) =>
    FireDevice.create({
      deviceName: '泵房烟感-无属主',
      deviceType: 'smoke_detector',
      installDate: new Date('2025-01-01'),
      location: { building },
    });

  /** 明确属于别人的设备 */
  const makeOwnedDevice = (building, operator) =>
    FireDevice.create({
      deviceName: '推车灭火器-有属主',
      deviceType: 'extinguisher',
      installDate: new Date('2025-01-01'),
      location: { building },
      createdBy: operator,
      maintenanceRecord: [{ date: new Date('2025-02-01'), operator }],
    });

  test('事实前提：ownerCondition(null) 的泄漏臂是"属主字段缺失"，确非空集', async () => {
    // 这一条今天就是绿的——它的作用是把"null 条件本来就匹配不到东西"的误解答掉，
    // 让后续用例的红不会被"也许匹配不到"解释掉。
    // 关键更正：真正命中"未建档设备"的是 {createdBy:null}（Mongo 里 null 匹配"字段缺失"）；
    // 而 {maintenanceRecord.operator:null} 对 maintenanceRecord 默认为空数组 [] 的文档
    // 在本环境返回 0（空数组子字段不算 null 命中）。危险性来自 createdBy 缺失这一臂，
    // 与另一臂是否为空无关——旧实现"department 为空 → ownerCondition(null)"仍是跨部门可见集。
    await makeOwnerlessDevice('B栋');
    await makeOwnedDevice('A栋', otherOperator());

    await expect(FireDevice.countDocuments({ createdBy: null })).resolves.toBe(1);
    await expect(FireDevice.countDocuments({ 'maintenanceRecord.operator': null })).resolves.toBe(
      0
    );
  });

  test('空部门的数据范围用户，报表口径不得看到任何其他部门的无属主设备', async () => {
    await makeOwnerlessDevice('B栋'); // 别的楼、别的部门的设备
    const visibleToOtherDept = await makeOwnedDevice('A栋', otherOperator());

    const filter = scopeFilterFor('device', { type: 'department', department: undefined });
    const hits = await FireDevice.find(filter).select('_id').lean();

    expect(hits.map((h) => String(h._id))).not.toContain(String(visibleToOtherDept._id));
    expect(hits).toHaveLength(0);
  });

  test('空部门：列表命中集必须与详情闸 isRecordInScope 的结论逐条一致', async () => {
    const leaky = await makeOwnerlessDevice('B栋');
    const owned = await makeOwnedDevice('A栋', otherOperator());
    const scope = { type: 'department', department: '' };

    const filter = scopeFilterFor('device', scope);
    const listSays = new Set(
      (await FireDevice.find(filter).select('_id').lean()).map((d) => String(d._id))
    );

    for (const doc of [leaky, owned]) {
      const detailSays = rbac.isRecordInScope(scope, doc, {
        ownerField: deviceFields.ownerField,
        departmentField: deviceFields.departmentField,
      });
      // 列表能看见 ⇔ 详情允许打开。不一致即"清单与闸互相矛盾"。
      expect(listSays.has(String(doc._id))).toBe(detailSays);
    }
    // 并且两边都必须是拒绝：详情闸对空部门本来就返回 false。
    expect(
      rbac.isRecordInScope(scope, leaky, {
        ownerField: deviceFields.ownerField,
        departmentField: deviceFields.departmentField,
      })
    ).toBe(false);
    expect(listSays.size).toBe(0);
  });

  test('空 userId 的 self 范围同样必须 deny（不得退化成"属主为空"的全库匹配）', async () => {
    await makeOwnerlessDevice('B栋');
    const filter = scopeFilterFor('device', { type: 'self', userId: null });
    await expect(FireDevice.countDocuments(filter)).resolves.toBe(0);
  });

  test('收敛点一致性：applyDataScopeToQuery 判 deny 的范围，报表口径也必须 deny', async () => {
    await makeOwnerlessDevice('B栋');
    await makeOwnedDevice('A栋', otherOperator());

    const denyScopes = [
      { type: 'department', department: '' },
      { type: 'department', department: null },
      { type: 'department' },
      { type: 'self', userId: null },
      { type: 'self', userId: undefined },
      { type: 'none' },
      { type: 'bogus' },
    ];

    for (const scope of denyScopes) {
      const converged = rbac.applyDataScopeToQuery({}, scope, deviceFields);
      const reportFilter = scopeFilterFor('device', scope);
      const reportHits = await FireDevice.countDocuments(reportFilter);

      expect(converged).toBe(false); // 收敛点：拒绝
      expect(reportHits).toBe(0); // 报表路径：同一范围必须一条都查不到
    }
  });

  test('反向保护：有效范围不得被误伤（deny 修复不能变成"一律拒绝"）', async () => {
    const mine = otherOperator();
    await makeOwnerlessDevice('B栋');
    const inMyDept = await makeOwnedDevice('A栋', mine);

    const deptFilter = scopeFilterFor('device', { type: 'department', department: 'A栋' });
    await expect(FireDevice.countDocuments(deptFilter)).resolves.toBe(1);

    const selfFilter = scopeFilterFor('device', { type: 'self', userId: mine });
    const selfHits = await FireDevice.find(selfFilter).select('_id').lean();
    expect(selfHits.map((h) => String(h._id))).toContain(String(inMyDept._id));

    const allFilter = scopeFilterFor('device', { type: 'all' });
    await expect(FireDevice.countDocuments(allFilter)).resolves.toBe(2);
  });
});
