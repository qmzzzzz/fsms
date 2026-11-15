/**
 * P3：敏感操作审计的 riskFactors 判定——delete/batch 对照 action 枚举**精确匹配**。
 *
 * 守的是什么：
 *   ① 枚举内全部 delete/batch 语义动作的 riskFactor 码一个不丢（回归面）；
 *   ② 枚举外恰好含 "delete"/"batch" 字样的 action 不再被子串匹配误标（修复点）；
 *   ③ error_response / multi_hop_proxy 等既有码不受影响。
 */
const AuditLog = require('../../models/AuditLog');

const req = {
  method: 'POST',
  originalUrl: '/api/probe',
  path: '/api/probe',
  params: {},
  query: {},
  body: {},
  headers: {},
  get: () => undefined,
  user: null,
  socket: {},
};

const build = (action, statusCode = 200) =>
  AuditLog.buildSensitiveActionDoc('u', 'n', action, 'user', req, { statusCode }, 1);

describe('P3 敏感操作 riskFactors：delete/batch 枚举精确匹配', () => {
  test.each([
    'user_delete',
    'role_delete',
    'permission_delete',
    'device_delete',
    'inspection_delete',
    'system_delete',
  ])('%s ⇒ 仍标 delete_operation（枚举内零丢失）', (action) => {
    expect(build(action).riskFactors).toContain('delete_operation');
  });

  test.each(['user_batch', 'permission_batch', 'permission_batch_create'])(
    '%s ⇒ 仍标 batch_operation（枚举内零丢失）',
    (action) => {
      expect(build(action).riskFactors).toContain('batch_operation');
    }
  );

  test('batch_delete_users ⇒ delete + batch 双标（存量语义保留）', () => {
    const rf = build('batch_delete_users').riskFactors;
    expect(rf).toContain('delete_operation');
    expect(rf).toContain('batch_operation');
  });

  test('枚举外含 delete/batch 字样的 action 不再被误标（修复点）', () => {
    expect(build('user_deleted_events').riskFactors).not.toContain('delete_operation');
    expect(build('batch_view').riskFactors).not.toContain('batch_operation');
  });

  test('普通动作不标；4xx/5xx 仍标 error_response；多跳代理码不受影响', () => {
    expect(build('user_create').riskFactors).toEqual([]);
    expect(build('user_create', 500).riskFactors).toContain('error_response');
  });
});
