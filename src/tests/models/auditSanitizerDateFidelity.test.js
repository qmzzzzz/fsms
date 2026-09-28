'use strict';

/**
 * 审计副本里的时间戳不得被清洗成空对象
 *
 * `auditLogSanitizer.walk()` 的通用分支用 `Object.entries()` 逐键重建对象。
 * `Date` 是 `typeof 'object'` 且没有可枚举键 ⇒ 走通用分支就被摊成 `{}`。
 * 后果不是"少显示一个字段"，而是本模块存在的理由（"审计副本与实际请求体同形"）
 * 对所有时间戳失效：取证时只看到一个空对象，且没有任何痕迹说明它曾是时间。
 * 现在 Date 走专门的分支保成 ISO 串。
 *
 * 第 3 条是这条修复的真正落点：防篡改链的哈希取自清洗后的文档，
 * 时间戳被摊成 {} 时，"改这个时间戳"与"不改"算出同一个摘要 ⇒ 该字段完全不在
 * 篡改检测的覆盖范围内（尽管今天没有生产写入路径能造成这种文档 —— 请求体是 JSON，
 * JSON 里没有日期字面量 —— 但服务端手写 `AuditLog.record({body:{...}})` 就会踩到，
 * 而这条覆盖缺口在链路里静默存在是不可接受的）。
 */

const { sanitizeAuditBody, sanitizeAuditQuery } = require('../../models/auditLogSanitizer');
const { canonicalPayload } = require('../../utils/auditChainPayload');

const T1 = new Date('2026-05-05T10:00:00.000Z');
const T2 = new Date('2027-11-11T11:11:11.000Z');

describe('审计清洗对时间戳保真', () => {
  test('嵌套对象与数组里的 Date 都保成 ISO 串（不再是 {}）', () => {
    const out = sanitizeAuditBody({
      window: { start: T1, end: T2 },
      events: [T1, { at: T2 }],
      plain: { keep: 'me' },
    });
    expect(out.window).toEqual({
      start: '2026-05-05T10:00:00.000Z',
      end: '2027-11-11T11:11:11.000Z',
    });
    expect(out.events[0]).toBe('2026-05-05T10:00:00.000Z');
    expect(out.events[1]).toEqual({ at: '2027-11-11T11:11:11.000Z' });
    // 反向前提：普通嵌套对象/数组的结构不得因为新分支而变形
    expect(out.plain).toEqual({ keep: 'me' });
  });

  test('无法表示的时间（Invalid Date）留下显式痕迹，而不是 "Invalid Date" 或 {}', () => {
    const out = sanitizeAuditBody({ at: new Date('不是时间') });
    expect(out.at).toBe('[无效时间]');
    expect(JSON.stringify(out)).not.toContain('Invalid Date');
    // query/params 走同一条 walk，行为必须一致（否则两条流水线又会各自漂移）
    expect(sanitizeAuditQuery({ at: new Date('不是时间') })).toEqual({ at: '[无效时间]' });
  });

  test('时间戳现在落在防篡改哈希的覆盖范围内（改时间 ⇒ 摘要必须变）', () => {
    const docFor = (at) => ({
      action: 'user_locked',
      category: 'user',
      userId: null,
      username: 'u',
      ip: '10.0.0.1',
      path: '/api/security/users/x/lock',
      method: 'PUT',
      statusCode: 200,
      success: true,
      riskLevel: 'high',
      timestamp: new Date('2026-01-01T00:00:00.000Z'),
      prevHash: null,
      body: sanitizeAuditBody({ at, actor: 'admin' }),
    });
    const h1 = canonicalPayload(docFor(T1));
    const h2 = canonicalPayload(docFor(T2));
    expect(h1).not.toBe(h2);
    // 自证不是"两个文档本来就处处不同"：把 T1 文档的 body 换成 T2 的 body 后，
    // 它必须与 T2 文档逐字同摘要 ⇒ 前后两摘要的唯一差异来源就是那个时间戳
    const sameExceptAt = docFor(T1);
    sameExceptAt.body = docFor(T2).body;
    expect(canonicalPayload(sameExceptAt)).toBe(h2);
  });
});
