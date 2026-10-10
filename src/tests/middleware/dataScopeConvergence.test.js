/**
 * P1-3 / P2-9 回归：数据范围过滤的唯一收敛点 applyDataScopeToQuery
 *
 * 背景（实测越权）：三个 Service（Alarm/Device/Inspection）与 userController
 * 各自手写了 `if (type==='department' && dataScope.department) {...}
 * else if (type==='self') {...} else if (type==='none') {return 空}`。
 * 当 type==='department' 但 department 为空串/null（用户未填部门，业务常见）时，
 * 三个分支全不命中 → **零过滤返回全组织数据**；而 buildDataScopeFilter
 * 对同一情形兜底为空集，导致「列表看到全公司、统计显示 0」的自相矛盾。
 *
 * 本套件锁定收敛后的不变量：任何非 all 的范围都不得产出「无约束」查询。
 */

const { buildDataScopeFilter, applyDataScopeToQuery } = require('../../middleware/rbac');

const FIELDS = { ownerField: 'createdBy', departmentField: 'location.building' };

describe('applyDataScopeToQuery — 数据范围收敛', () => {
  test('type=all 不加任何条件且允许查询', () => {
    const query = { status: 'active' };
    expect(applyDataScopeToQuery(query, { type: 'all' }, FIELDS)).toBe(true);
    expect(query).toEqual({ status: 'active' });
  });

  test('type=self 按属主字段约束', () => {
    const query = {};
    expect(applyDataScopeToQuery(query, { type: 'self', userId: 'u1' }, FIELDS)).toBe(true);
    expect(query).toEqual({ createdBy: 'u1' });
  });

  test('type=department 且部门非空：按部门字段精确匹配', () => {
    const query = {};
    expect(applyDataScopeToQuery(query, { type: 'department', department: 'A栋' }, FIELDS)).toBe(
      true
    );
    expect(query).toEqual({ 'location.building': 'A栋' });
  });

  // ===== 核心回归：曾经零过滤的三种输入 =====
  // #12 起这三类输入的处置从"返回 false、调用方各自回空集"改成**抛 403**：
  // 空集让调用方分不清「没有数据」与「没有可见范围」，而这两者的后续动作相反。
  describe('曾导致零过滤越权的输入一律拒绝（403，不再回空集）', () => {
    test.each([
      ['department 为空字符串', { type: 'department', department: '' }],
      ['department 为 null', { type: 'department', department: null }],
      ['department 字段缺失', { type: 'department' }],
      ['type=none', { type: 'none' }],
      ['type 为未知值', { type: 'bogus' }],
    ])('%s → 抛 403 DATA_SCOPE_DENIED', (_label, dataScope) => {
      const query = { status: 'active' };
      expect(() => applyDataScopeToQuery(query, dataScope, FIELDS)).toThrow(/没有可用的数据范围/);
      // 「拒绝」不得顺手污染查询：异常抛出时 query 必须原样不动
      expect(query).toEqual({ status: 'active' });
    });

    // 期望值表驱动：每种范围形态的 allowed 结果显式列出，不再在函数行为上开
    // 条件分支。原写法 `if (allowed) { expect(...) }` 在 applyDataScopeToQuery
    // 恒返回 false（拒绝一切数据的可用性退化）时一条断言都不执行、用例恒绿。
    test.each([
      ['department 为空串 → 拒绝', { type: 'department', department: '' }, false],
      ['department 为 null → 拒绝', { type: 'department', department: null }, false],
      ['department 字段缺失 → 拒绝', { type: 'department' }, false],
      ['department 有效 → 允许且必须加约束', { type: 'department', department: 'A栋' }, true],
      ['self 有效 → 允许且必须加约束', { type: 'self', userId: 'u1' }, true],
      ['type=none → 拒绝', { type: 'none' }, false],
      ['type 未知值 → 拒绝', { type: 'bogus' }, false],
      ['空对象（无 type）→ 拒绝', {}, false],
    ])('%s', (_label, scope, expectedAllowed) => {
      const query = {};
      // 两个方向由同一期望值锁定：
      //   - expectedAllowed=true：必须返回 true 且施加至少一个约束键（防零过滤越权）；
      //   - expectedAllowed=false：必须抛 403，且不得残留任何约束键
      //     （防「拒绝」却把查询污染了——异常路径同样要干净）。
      if (expectedAllowed) {
        expect(applyDataScopeToQuery(query, scope, FIELDS)).toBe(true);
        expect(Object.keys(query).length > 0).toBe(true);
      } else {
        expect(() => applyDataScopeToQuery(query, scope, FIELDS)).toThrow(/没有可用的数据范围/);
        expect(Object.keys(query).length).toBe(0);
      }
    });
  });

  describe('与用户显式筛选的冲突处理', () => {
    test('同字段冲突用 $and 取交集，不让任一方覆盖另一方', () => {
      // 覆盖会造成两种事故：范围覆盖筛选=可见集被越权放大；筛选覆盖范围=跨部门泄露
      const query = { 'location.building': 'B栋' };
      expect(applyDataScopeToQuery(query, { type: 'department', department: 'A栋' }, FIELDS)).toBe(
        true
      );

      expect(query['location.building']).toBeUndefined();
      expect(query.$and).toEqual([{ 'location.building': 'B栋' }, { 'location.building': 'A栋' }]);
    });

    test('已有 $and 时追加而非覆盖', () => {
      const query = { $and: [{ status: 'x' }], createdBy: 'other' };
      expect(applyDataScopeToQuery(query, { type: 'self', userId: 'u1' }, FIELDS)).toBe(true);
      expect(query.$and).toEqual([{ status: 'x' }, { createdBy: 'other' }, { createdBy: 'u1' }]);
    });

    test('不同字段直接合并', () => {
      const query = { status: 'active' };
      expect(applyDataScopeToQuery(query, { type: 'self', userId: 'u1' }, FIELDS)).toBe(true);
      expect(query).toEqual({ status: 'active', createdBy: 'u1' });
    });

    // 调用方先写 $or（关键词搜索）、范围随后到达的情形。设备的属主字段是数组
    // （createdBy ∪ maintenanceRecord.operator），范围条件本身就是 $or —— 两个 $or
    // 相撞是最容易写错的一种冲突（DeviceService 曾在 search 分支直接覆盖 query.$or，
    // 等于带关键词就不做范围过滤）。这里把原语层的正确行为钉住。
    test('两侧都是 $or 时取交集（数组属主 × 关键词搜索）', () => {
      const search = { deviceName: /泵/, deviceCode: /泵/ };
      const query = { $or: [{ deviceName: search.deviceName }, { deviceCode: search.deviceCode }] };
      expect(
        applyDataScopeToQuery(
          query,
          { type: 'self', userId: 'u1' },
          { ownerField: ['createdBy', 'maintenanceRecord.operator'], departmentField: 'b' }
        )
      ).toBe(true);
      expect(query.$or).toBeUndefined();
      expect(query.$and).toEqual([
        { $or: [{ deviceName: search.deviceName }, { deviceCode: search.deviceCode }] },
        { $or: [{ createdBy: 'u1' }, { 'maintenanceRecord.operator': 'u1' }] },
      ]);
    });
  });

  test('与 buildDataScopeFilter 的 deny 哨兵口径一致', () => {
    // buildDataScopeFilter 仍用 { _id: null } 表示「永不匹配」（直接调用方照旧可用）；
    // applyDataScopeToQuery 则必须把它翻译成**抛 403**，而不是把 _id:null 塞进查询
    expect(buildDataScopeFilter({ type: 'none' }, 'createdBy')).toEqual({ _id: null });
    const query = {};
    expect(() => applyDataScopeToQuery(query, { type: 'none' }, FIELDS)).toThrow(
      /没有可用的数据范围/
    );
    expect(query._id).toBeUndefined();
  });
});
