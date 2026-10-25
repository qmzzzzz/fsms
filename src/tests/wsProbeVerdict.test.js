/**
 * 安全探针 ws-session-bypass.cjs 的判据回归
 *
 * 背景（两轮）：
 *   1) 探针原来**无论结论如何都 exit 0**，而且"没绑上 userId"就宣布 ✅ 修复生效——
 *      可"没绑上"还有第二种成因：握手层变了使请求根本没走到 authenticateSocket。
 *   2) 即便改成三态，"收到任何 auth-error 就算拒绝"仍不够：原探针只用一个令牌，
 *      同时带「已吊销会话 + 非白名单 IP」两条违规，于是它只证明了**至少一条**控制在生效。
 *      删掉 sid 校验、只留 IP 校验，探针照样 exit 0 报"P0-2 修复在位"。
 *
 * 现在拆成两个单违规场景，并要求拒绝理由**与本场景期望的那条控制匹配**。
 * 本文件钉住：三态真值表、绕过优先、以及"拒绝必须可归因"这条新不变量。
 */

const mongoose = require('mongoose');

// require 而不是 node 执行：探针自身有 require.main 守卫
const { decideVerdict, SCENARIOS } = require('../../scripts/audit-probes/ws-session-bypass.cjs');

/** 本文件里各场景的期望理由（与探针 SCENARIOS 同源，避免手写第二份文案） */
const expectedOf = (key) => SCENARIOS.find((s) => s.key === key).ws;

describe('ws-session-bypass 探针的三态判据', () => {
  test('前提自证：require 探针不得把它跑起来（未连库、未建服务）', () => {
    // 若缺了 require.main 守卫，这一句 require 就会去起内存 MongoDB 并 process.exit，
    // 表现为整个套件挂死/退出——所以这条断言本身就是那道守卫的红灯。
    expect(typeof decideVerdict).toBe('function');
    expect(mongoose.connection.readyState).toBe(0);
  });

  test('场景表就是两个**单违规**场景（合并回一个令牌就会重新失去归因能力）', () => {
    expect(SCENARIOS.map((s) => s.key)).toEqual(['session_revoked', 'ip_not_allowed']);
    // 每个场景只允许一条违规：allowedIPs 与 sessionStatus 不得同时"有问题"
    expect(SCENARIOS[0]).toMatchObject({ allowedIPs: '', sessionStatus: 'revoked' });
    expect(SCENARIOS[1]).toMatchObject({ allowedIPs: '10.0.0.0/8', sessionStatus: 'active' });
    // 两条控制的 HTTP 期望必须不同，否则前置对照分不清是谁拒的
    expect(SCENARIOS[0].http.code).not.toBe(SCENARIOS[1].http.code);
  });

  test('三种输入各自落到不同状态与退出码（判据不是恒真也不是恒假）', () => {
    const bypass = decideVerdict({ boundUserId: 'u1', downstream: 'auth-error whatever' });
    const rejected = decideVerdict({
      boundUserId: undefined,
      downstream: '42["auth-error",{"message":"当前网络不在允许的 IP 范围内"}]',
      expected: expectedOf('ip_not_allowed'),
    });
    const unknown = decideVerdict({ boundUserId: undefined, downstream: '0{"sid":"abc"}' });

    expect([bypass.state, rejected.state, unknown.state]).toEqual([
      'bypass',
      'rejected',
      'inconclusive',
    ]);
    // 三个退出码必须两两不同：否则"不可判定"会被 CI 当成通过或当成漏洞
    expect(new Set([bypass.code, rejected.code, unknown.code]).size).toBe(3);
    expect(unknown.code).not.toBe(0);
  });

  test('绕过优先于 auth-error 证据（只要 socket 真绑上了用户就是漏洞，不因帧内容改判）', () => {
    const v = decideVerdict({ boundUserId: 'u1', downstream: '42["auth-error"]' });
    expect(v).toMatchObject({ state: 'bypass', code: 1 });
    expect(v.why).toContain('确认绕过');
  });

  test('"没绑上用户"但没有任何认证层回帧 ⇒ 判不可判定，不得判成已修复', () => {
    // 这条是上一批修复的核心：旧写法在这种情形下打印 ✅，把探针自身失效当成安全结论。
    const v = decideVerdict({ boundUserId: null, downstream: '' });
    expect(v.state).toBe('inconclusive');
    expect(v.why).toContain('不构成');
  });

  test('收到 auth-error 但理由不是本场景期望的 ⇒ 不可判定（本轮修复的核心）', () => {
    // 这是"单令牌双违规"造成的假通过：IP 控制的拒绝帧，不能当作"会话控制也在位"的证据。
    const v = decideVerdict({
      boundUserId: undefined,
      downstream: '42["auth-error",{"message":"当前网络不在允许的 IP 范围内"}]',
      expected: expectedOf('session_revoked'),
    });
    expect(v.state).toBe('inconclusive');
    expect(v.code).toBe(2);
    expect(v.why).toContain('没有被证明在位');
  });

  test('两个场景的拒绝理由互不通用（互为反例，证明归因真的在起作用）', () => {
    const ipFrame = '42["auth-error",{"message":"当前网络不在允许的 IP 范围内"}]';
    const sidFrame = '42["auth-error",{"message":"该设备会话已失效，请重新登录"}]';

    expect(
      decideVerdict({ downstream: ipFrame, expected: expectedOf('ip_not_allowed') }).state
    ).toBe('rejected');
    expect(
      decideVerdict({ downstream: ipFrame, expected: expectedOf('session_revoked') }).state
    ).toBe('inconclusive');
    expect(
      decideVerdict({ downstream: sidFrame, expected: expectedOf('session_revoked') }).state
    ).toBe('rejected');
    expect(
      decideVerdict({ downstream: sidFrame, expected: expectedOf('ip_not_allowed') }).state
    ).toBe('inconclusive');
  });

  test('未声明期望理由 ⇒ 不可判定（拒绝必须可归因才算是某条控制的证据）', () => {
    const v = decideVerdict({
      boundUserId: undefined,
      downstream: '42["auth-error",{"message":"当前网络不在允许的 IP 范围内"}]',
    });
    expect(v.state).toBe('inconclusive');
    expect(v.why).toContain('无法归因');
  });

  test('下游帧缺失/非字符串不得抛错（探针崩了要落到不可判定，而不是抛在退出码之前）', () => {
    for (const bad of [undefined, null, 0, { toString() {} }]) {
      const v = decideVerdict({
        boundUserId: undefined,
        downstream: bad,
        expected: expectedOf('ip_not_allowed'),
      });
      expect(['rejected', 'inconclusive']).toContain(v.state);
    }
  });
});
