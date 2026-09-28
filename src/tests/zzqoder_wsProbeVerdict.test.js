/**
 * 安全探针 ws-session-bypass.cjs 的判据回归
 *
 * 背景：该探针原来**无论结论如何都 exit 0**（`process.exit(0)` 写在成功路径末尾，
 * 打印 ❌❌ 确认绕过 时也是 0），而且"没绑上 userId"就宣布 ✅ 修复生效——
 * 可"没绑上"还有第二种成因：握手层变了使请求根本没走到 authenticateSocket。
 * 一个把"自己失效"报成"漏洞已修"的安全探针比没有探针更糟。
 *
 * 现在三态可机判：0=已拒且有 auth-error 正向证据 / 1=确认绕过 / 2=不可判定。
 * 本文件钉住真值表与优先级，并自证 require 该探针不会真的跑起探针（不连库）。
 */

const mongoose = require('mongoose');

// require 而不是 node 执行：探针自身有 require.main 守卫
const { decideVerdict } = require('../../scripts/audit-probes/ws-session-bypass.cjs');

describe('ws-session-bypass 探针的三态判据', () => {
  test('前提自证：require 探针不得把它跑起来（未连库、未建服务）', () => {
    // 若缺了 require.main 守卫，这一句 require 就会去起内存 MongoDB 并 process.exit，
    // 表现为整个套件挂死/退出——所以这条断言本身就是那道守卫的红灯。
    expect(typeof decideVerdict).toBe('function');
    expect(mongoose.connection.readyState).toBe(0);
  });

  test('三种输入各自落到不同状态与退出码（判据不是恒真也不是恒假）', () => {
    const bypass = decideVerdict({ boundUserId: 'u1', downstream: 'auth-error whatever' });
    const rejected = decideVerdict({
      boundUserId: undefined,
      downstream: '42["auth-error","网络"]',
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
    // 这条是本批修复的核心：旧写法在这种情形下打印 ✅，把探针自身失效当成安全结论。
    const v = decideVerdict({ boundUserId: null, downstream: '' });
    expect(v.state).toBe('inconclusive');
    expect(v.why).toContain('不构成');
  });

  test('auth-error 之外的拒绝理由也算正向证据（拒绝出自认证逻辑即可）', () => {
    for (const msg of [
      '42["auth-error","当前网络不在允许的 IP 范围内"]',
      '42["auth-error","会话已吊销"]',
      '42["auth-error","token invalid"]',
    ]) {
      expect(decideVerdict({ boundUserId: undefined, downstream: msg }).state).toBe('rejected');
    }
  });

  test('下游帧缺失/非字符串不得抛错（探针崩了要落到不可判定，而不是抛在退出码之前）', () => {
    for (const bad of [undefined, null, 0, { toString() {} }]) {
      const v = decideVerdict({ boundUserId: undefined, downstream: bad });
      expect(['rejected', 'inconclusive']).toContain(v.state);
    }
  });
});
