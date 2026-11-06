/**
 * materializeQuery 失败臂补齐（覆盖率门禁缺口：sanitize.js :143 / :172 两臂）
 *
 * 两个臂都是"防线自我证伪即拒绝"的 fail-closed 出口：
 *  - :143 query getter 抛错（query parser 配置错误）⇒ 500，不放行未清洗请求；
 *  - :172 defineProperty 物化抛错 ⇒ 500，同样不放行。
 * 纯中间件单元测试：req 用 getter 桩制造两条失败路径，不经过 app 装配。
 */
'use strict';

const { materializeQuery } = require('../../middleware/security/sanitize');

const makeRes = () => {
  const res = {};
  res.status = jest.fn(() => res);
  res.json = jest.fn(() => res);
  return res;
};

describe('materializeQuery 失败臂（fail-closed 出口）', () => {
  test('query getter 抛错 ⇒ 500 INTERNAL_ERROR 且不放行（:143 臂）', () => {
    const middleware = materializeQuery();
    const req = { id: 'r1' };
    Object.defineProperty(req, 'query', {
      get() {
        throw new Error('query parser misconfigured');
      },
      configurable: true,
    });
    const res = makeRes();
    const next = jest.fn();
    middleware(req, res, next);
    expect(next).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(500);
    expect(res.json).toHaveBeenCalledWith(
      expect.objectContaining({ errors: expect.objectContaining({ errorCode: 'INTERNAL_ERROR' }) })
    );
  });

  test('defineProperty 物化抛错 ⇒ 500 且不放行（:172 臂，冻结对象上定义必抛）', () => {
    const middleware = materializeQuery();
    const req = Object.freeze({ id: 'r2', query: { q: 'normal' } });
    const res = makeRes();
    const next = jest.fn();
    middleware(req, res, next);
    expect(next).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(500);
  });
});
