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
  describe('曾导致零过滤越权的输入一律拒绝', () => {
    test.each([
      ['department 为空字符串', { type: 'department', department: '' }],
      ['department 为 null', { type: 'department', department: null }],
      ['department 字段缺失', { type: 'department' }],
      ['type=none', { type: 'none' }],
      ['type 为未知值', { type: 'bogus' }],
    ])('%s → 返回 false（调用方返回空集）', (_label, dataScope) => {
      const query = { status: 'active' };
      expect(applyDataScopeToQuery(query, dataScope, FIELDS)).toBe(false);
    });

    test('绝不出现「返回 true 且未加任何约束」的组合', () => {
      // 穷举所有非 all 的范围形态，逐一确认：要么被拒绝，要么至少加了一个约束键
      const scopes = [
        { type: 'department', department: '' },
        { type: 'department', department: null },
        { type: 'department' },
        { type: 'department', department: 'A栋' },
        { type: 'self', userId: 'u1' },
        { type: 'none' },
        { type: 'bogus' },
        {},
      ];
      for (const scope of scopes) {
        const query = {};
        const allowed = applyDataScopeToQuery(query, scope, FIELDS);
        if (allowed) {
          expect(Object.keys(query).length).toBeGreaterThan(0);
        }
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
  });

  test('与 buildDataScopeFilter 的 deny 哨兵口径一致', () => {
    // buildDataScopeFilter 用 { _id: null } 表示「永不匹配」；
    // applyDataScopeToQuery 必须把它翻译成 false，而不是把 _id:null 塞进查询
    expect(buildDataScopeFilter({ type: 'none' }, 'createdBy')).toEqual({ _id: null });
    const query = {};
    expect(applyDataScopeToQuery(query, { type: 'none' }, FIELDS)).toBe(false);
    expect(query._id).toBeUndefined();
  });
});
