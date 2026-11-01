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
});
