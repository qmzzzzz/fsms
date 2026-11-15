/**
 * U5 回归：ApiResponse.paginated 的分页信息必须有明确默认值
 *
 * 原实现直接读 pagination.page/limit/total/totalPages：
 *   · pagination 为 undefined/null ⇒ TypeError（响应直接 500）；
 *   · pagination 为 {} ⇒ 吐出四个字段全 undefined 的 pagination，
 *     前端 total 变 undefined、分页器算出 NaN 页数。
 * 判据：三种入参都产出**数值**字段，且显式传值不被覆盖。
 */

'use strict';

const ApiResponse = require('../../utils/apiResponse');
const logger = require('../../utils/logger');

const makeRes = () => ({
  statusCode: null,
  body: null,
  status(code) {
    this.statusCode = code;
    return this;
  },
  json(payload) {
    this.body = payload;
    return this;
  },
});

describe('U5 paginated 分页字段兜底', () => {
  test('pagination 缺失（undefined）不抛错，给出默认值', () => {
    const res = makeRes();
    expect(() => ApiResponse.paginated(res, [], undefined)).not.toThrow();
    expect(res.statusCode).toBe(200);
    expect(res.body.pagination).toEqual({ page: 1, limit: 0, total: 0, totalPages: 0 });
  });

  test('pagination 为 null 同样兜底', () => {
    const res = makeRes();
    ApiResponse.paginated(res, [], null);
    expect(res.body.pagination).toEqual({ page: 1, limit: 0, total: 0, totalPages: 0 });
  });

  test('空对象 {} 不再吐 undefined 字段', () => {
    const res = makeRes();
    ApiResponse.paginated(res, [], {});
    const p = res.body.pagination;
    for (const key of ['page', 'limit', 'total', 'totalPages']) {
      expect(typeof p[key]).toBe('number');
      expect(Number.isFinite(p[key])).toBe(true);
    }
  });

  test('正向对照：显式传值不被默认值覆盖，游标字段按需透传', () => {
    const res = makeRes();
    ApiResponse.paginated(res, [1], { page: 3, limit: 20, total: 41, totalPages: 3 });
    expect(res.body.pagination).toEqual({ page: 3, limit: 20, total: 41, totalPages: 3 });
    const res2 = makeRes();
    ApiResponse.paginated(res2, [], {
      page: 1,
      limit: 10,
      total: 0,
      totalPages: 0,
      hasMore: true,
      nextCursor: 'c1',
    });
    expect(res2.body.pagination.hasMore).toBe(true);
    expect(res2.body.pagination.nextCursor).toBe('c1');
  });

  test('非数值 meta 字段按契约回退默认值，但必须留 warn 信号（审计 2026-11-15）', () => {
    const warnSpy = jest.spyOn(logger, 'warn').mockImplementation(() => {});
    try {
      const res = makeRes();
      ApiResponse.paginated(res, [], { page: '2', limit: '10', total: null, totalPages: 3 });
      const p = res.body.pagination;
      // 修复前：'2' 被静默兜成 page=1、无任何信号；修复后：兜底行为不变（不破坏
      // 既有调用方契约），但逐字段告警一次，让"调用方传错类型"可见。
      expect(p.page).toBe(1);
      expect(p.limit).toBe(0);
      expect(p.total).toBeNull(); // 显式 null 仍按游标契约透传，不告警
      expect(p.totalPages).toBe(3);
      const warned = warnSpy.mock.calls.map((c) => String(c[0])).join('\n');
      expect(warned).toContain('分页字段 page');
      expect(warned).toContain('分页字段 limit');
      expect(warned).not.toContain('分页字段 total'); // 合法数值与契约 null 都不告警

      // 去重：同一字段重复出现只告一次（避免高频列表接口刷日志）
      ApiResponse.paginated(makeRes(), [], { page: '5' });
      expect(warnSpy.mock.calls.filter((c) => String(c[0]).includes('page'))).toHaveLength(1);
    } finally {
      warnSpy.mockRestore();
    }
  });
});
