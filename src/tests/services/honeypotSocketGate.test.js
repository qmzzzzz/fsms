/**
 * 蜜罐会话的 WS 入口（P1b）：不建立推送通道 + 留痕
 *
 * 为什么要单独锁一条 WS：HTTP 侧的改道由 middleware/auth.js 的单点接线保证，而 WS 是
 * **另一条认证入口**（websocketService/handshake.js 的 authenticateSocket），它不经过那个接线点。
 * 本文件锁三件事：
 *  1. 位置闸：判据必须落在「在途断开复检之后、_bindHandshakeIdentity 之前」，且必须是**同步**调用
 *     ——握手链的 await 序列被 websocketAuthGhostConnection 的位置闸钉死，不能因审计 IO 被改写；
 *  2. 投影闸：握手读的用户字段集必须含 isHoneypot（少取一个字段就等于少一条判据）；
 *  3. 行为闸：拒绝与真实失败**同形**（同一条 auth-error + disconnect），审计落 honeypot_probe、
 *     风险等级 critical（建通道是主动行为），告警每账户每日一次。
 */

'use strict';

const fs = require('fs');
const path = require('path');
const mongoose = require('mongoose');
const honeypotWatch = require('../../services/honeypotWatch');
const securityAlert = require('../../services/securityAlert');

const WS_PATH = path.join(__dirname, '../../services/websocketService/handshake.js');
const RAW = fs.readFileSync(WS_PATH, 'utf8');
const BODY = (() => {
  const from = RAW.indexOf('async authenticateSocket(');
  const to = RAW.indexOf('\n  /**', from);
  return RAW.slice(from, to);
})();

describe('蜜罐会话 WS 入口：不绑定身份、不建通道、留痕', () => {
  const honeypotName = 'wstrap';
  const saved = {};
  let AuditLog;
  let dispatchSpy;
  const setEnv = (key, value) => {
    if (!(key in saved)) saved[key] = process.env[key];
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  };
  const makeSocket = () => ({
    id: 'sock-' + Math.random().toString(36).slice(2, 8),
    emitted: [],
    disconnected: null,
    handshake: { address: '203.0.113.7' },
    emit(event, payload) {
      this.emitted.push({ event, payload });
    },
    disconnect(force) {
      this.disconnected = force;
    },
  });

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) await mongoose.connect(process.env.MONGODB_URI);
    require('../../models/User');
    require('../../models/TokenBlacklist');
    AuditLog = require('../../models/AuditLog');
    setEnv('HONEYPOT_ENABLED', 'true');
    setEnv('HONEYPOT_USERNAMES', honeypotName);
  });

  afterAll(async () => {
    await mongoose.connection
      .collection('auditlogs')
      .deleteMany({ action: 'honeypot_probe', method: 'WS' })
      .catch(() => {});
    for (const [key, value] of Object.entries(saved)) setEnv(key, value);
    honeypotWatch.__resetForTest();
    if (mongoose.connection.readyState !== 0) await mongoose.connection.close();
  });

  beforeEach(() => {
    dispatchSpy = jest.spyOn(securityAlert, 'dispatchNotification').mockImplementation(() => {});
  });

  afterEach(() => {
    dispatchSpy.mockRestore();
  });

  test('位置闸：同步判据位于身份绑定之前（判据独立成方法，免得顶破 authenticateSocket 的复杂度预算）', () => {
    const guardAt = BODY.indexOf('_assertHandshakeUserUsable(socket, freshUser)');
    expect(guardAt).toBeGreaterThan(-1);
    expect(guardAt).toBeLessThan(BODY.indexOf('_bindHandshakeIdentity'));
    const guardLine = BODY.slice(BODY.lastIndexOf('\n', guardAt) + 1, BODY.indexOf('\n', guardAt));
    expect(guardLine.split('//')[0]).not.toContain('await'); // 同步：握手链的 await 序列不许被改写（注释里的说明不算）
    expect(RAW.includes("require('../honeypotWatch')")).toBe(true);
    expect(BODY.split('if (!socket.connected)')).toHaveLength(2); // 复检锚点唯一
    expect(BODY.split('_bindHandshakeIdentity')).toHaveLength(2); // 方法体内只有一次调用（定义在方法体外）
    const mFrom = RAW.indexOf('_assertHandshakeUserUsable(socket, freshUser) {');
    const methodBody = RAW.slice(mFrom, RAW.indexOf('\n  },', mFrom));
    expect(methodBody).toContain('return honeypotWatch.isHoneypotSocket(freshUser, socket);');
    const methodCode = methodBody
      .split(/\r?\n/)
      .map((line) => line.split('//')[0])
      .join('\n');
    expect(methodCode).not.toContain('await'); // 判据体同步：不引入新的 await 窗口（注释里的说明不算）
    // 台账声明「status 与 lockUntil 都写在自己函数体里」：这条不变量由本用例一并钉住
    expect(BODY).toContain("status !== 'active'");
    expect(BODY).toContain('lockUntil');
  });

  test('投影闸：握手 select 必须取到 isHoneypot，且判据体真的调用留痕函数', () => {
    expect(RAW).toMatch(/select\(\s*'[^']*\bmustChangePassword\b[^']*\bisHoneypot\b[^']*'\s*\)/);
    const fn = fs.readFileSync(path.join(__dirname, '../../services/honeypotWatch.js'), 'utf8');
    expect(fn).toMatch(
      /recordHoneypotSocketProbe\(freshUser\.username, socket\)\.catch\(\(\) => \{\}\)/
    );
  });

  test('行为闸：标志位账户被同形拒绝（auth-error + 强制断开），返回 true 表示已接管', () => {
    const socket = makeSocket();
    expect(
      honeypotWatch.isHoneypotSocket({ username: honeypotName, isHoneypot: true }, socket)
    ).toBe(true);
    expect(socket.emitted).toEqual([
      { event: 'auth-error', payload: { message: '账户已被禁用或锁定' } },
    ]);
    expect(socket.disconnected).toBe(true);
    expect(
      honeypotWatch.isHoneypotSocket({ username: 'zhangwei', isHoneypot: false }, socket)
    ).toBe(false);
    expect(honeypotWatch.isHoneypotSocket(undefined, socket)).toBe(false);
    expect(socket.emitted).toHaveLength(1);
  });

  test('开关闸（fail-closed）：HONEYPOT_ENABLED 关闭也不放诱饵进推送面——WS 判据只看 DB 标志', () => {
    setEnv('HONEYPOT_ENABLED', 'false');
    const socket = makeSocket();
    expect(
      honeypotWatch.isHoneypotSocket({ username: honeypotName, isHoneypot: true }, socket)
    ).toBe(true);
    expect(socket.emitted).toHaveLength(1);
    expect(socket.disconnected).toBe(true);
    setEnv('HONEYPOT_ENABLED', 'true');
  });

  test('留痕：WS 探测落 honeypot_probe / critical / method=WS，告警每账户每日一次', async () => {
    honeypotWatch.__resetForTest();
    const loneName = honeypotName + '-lone'; // 与行为闸用过的名字错开：上一轮 fire-and-forget 可能仍在途，按名字取行才是确定性的
    const socket = makeSocket();
    await honeypotWatch.recordHoneypotSocketProbe(loneName, socket);
    const rows = await AuditLog.find({
      action: 'honeypot_probe',
      method: 'WS',
      username: loneName,
    }).lean();
    expect(rows).toHaveLength(1);
    expect(rows[0].riskLevel).toBe('critical');
    expect(rows[0].category).toBe('security');
    expect(rows[0].path).toBe('ws://handshake');
    expect(rows[0].riskFactors).toContain('honeypot_account_socket_attempt');
    expect(rows[0].body.honeypot).toBe(loneName);
    const targetCalls = () =>
      dispatchSpy.mock.calls.filter((call) => String(call[2]).includes(loneName));
    expect(targetCalls()).toHaveLength(1);
    expect(targetCalls()[0][1]).toBe(securityAlert.ALERT_LEVELS.CRITICAL);
    await honeypotWatch.recordHoneypotSocketProbe(loneName, socket);
    expect(targetCalls()).toHaveLength(1); // 第二次只落审计：告警每日一次
  });
});
