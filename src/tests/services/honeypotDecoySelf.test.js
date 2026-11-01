/**
 * 诱饵会话的「本人自助面」（P2）：七条读侧自服务端点的形态、边界与零泄漏
 *
 * 与既有测试的分工：
 *  - tests/services/honeypotDecoy.test.js 管"改道"（哪些路径被接管、留了什么痕）；
 *  - 本文件管"接管之后回什么"：逐端点钉住字段集合、脱敏次数、时间同源、
 *    参数拒绝的逐字响应体，以及"绝不出现任何合成物/内部标志"这条底线。
 *
 * 为什么这些断言值钱：P2 要消掉的正是"读侧 403 或答非所问"这个最强指纹——
 * 一旦回得不像真的本人数据，前面 P0/P1 做的隐身全部白费。故每条断言都对着
 * 真实控制器（authController/session.js、securityController/account.js）的口径写，
 * 判据一律复用真实模块（DataMasking / searchPatterns / AUDIT_CATEGORIES / parseUserAgent）。
 */

'use strict';

const ApiResponse = require('../../utils/apiResponse');
const { DataMasking } = require('../../utils/encryption');
const { AUDIT_CATEGORIES } = require('../../constants/audit');
const { SECURITY_SUGGESTION_CODES } = require('../../constants/securitySuggestions');
const { HONEYPOT_VERDICT } = require('../../constants/honeypotDecoy');
const { DECOY_PERMISSION_CATALOG, DECOY_SELF_LOGS } = require('../../constants/honeypotDecoySelf');
const {
  DECOY_ALARMS,
  DECOY_DEVICES,
  DECOY_PERMISSIONS,
  DECOY_ROLE_CODES,
  DECOY_USERS,
} = require('../../constants/honeypotDecoyData');
const {
  SELF_ENDPOINTS,
  resolveSelfResponse,
  sendSelfResponse,
  sessionContextOf,
} = require('../../services/honeypotDecoySelf');

const NOW = Date.UTC(2026, 9, 31, 12, 0, 0);
const DAY_MS = 24 * 60 * 60 * 1000;
const SESSION = {
  sid: '5f1a0f3e-2f6b-4c1a-9a0e-7c2b1d3e4f50',
  userId: '68c1a4e07f3b2d0e9a5b7c31',
  username: 'liwei',
  realName: '李伟',
  mustChangePassword: false,
  ua: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
  ip: '10.44.0.9',
  iatMs: NOW - 60 * 60 * 1000,
  now: NOW,
};

const call = (path, options = {}) =>
  resolveSelfResponse({
    method: options.method || 'GET',
    path,
    query: options.query || {},
    session: { ...SESSION, ...(options.session || {}) },
  });

const mockRes = () => ({
  headers: {},
  status(code) {
    this.statusCode = code;
    return this;
  },
  json(payload) {
    this.body = payload;
    return this;
  },
  setHeader(k, v) {
    this.headers[k] = v;
    return this;
  },
});

describe('诱饵会话本人自助面（P2）：七条读侧端点', () => {
  test('端点表：七条逐条命中，大小写与一个尾斜杠同形，写方法与未登记拼写交回上层', () => {
    expect(SELF_ENDPOINTS.map((e) => e.id)).toEqual([
      'me',
      'mfa-status',
      'sessions',
      'my-info',
      'bindings',
      'my-logs',
      'report-targets',
    ]);
    expect(new Set(SELF_ENDPOINTS.map((e) => e.path)).size).toBe(SELF_ENDPOINTS.length);
    for (const endpoint of SELF_ENDPOINTS) {
      expect(call(endpoint.path).endpoint).toBe(endpoint.id);
      expect(call(endpoint.path + '/').endpoint).toBe(endpoint.id);
      expect(call(endpoint.path.toUpperCase()).endpoint).toBe(endpoint.id);
      expect(call(endpoint.path, { method: 'HEAD' }).head).toBe(true);
      for (const method of ['POST', 'PUT', 'PATCH', 'DELETE']) {
        expect(call(endpoint.path, { method })).toBeNull();
      }
    }
    expect(call('/api/auth/me//')).toBeNull();
    expect(call('/api/auth/%6de')).toBeNull();
    expect(call('/api/auth/me/extra')).toBeNull();
    expect(call('/api/users/me')).toBeNull();
  });

  test('/me：字段集合与真实 getMe 同形，身份取自会话、权限取合成目录（并集不变量）', () => {
    const me = call('/api/auth/me');
    expect(me.message).toBe('获取成功');
    expect(Object.keys(me.data)).toEqual([
      'user',
      'permissions',
      'menuPermissions',
      'buttonPermissions',
      'apiPermissions',
      'menus',
      'buttons',
      'dataScope',
    ]);
    expect(Object.keys(me.data.user)).toEqual([
      'id',
      'username',
      'realName',
      'email',
      'phone',
      'department',
      'avatar',
      'lastLoginAt',
      'createdAt',
      'roles',
      'mustChangePassword',
    ]);
    expect(me.data.user.id).toBe(SESSION.userId);
    expect(me.data.user.username).toBe(SESSION.username);
    expect(me.data.user.email).toBe(SESSION.username + '@ljxfw.cn');
    expect(me.data.user.lastLoginAt).toBe(new Date(SESSION.iatMs).toISOString());
    expect(me.data.user.avatar).toBeNull();
    expect(me.data.user.mustChangePassword).toBe(false);
    expect(me.data.user.roles.map((role) => role.code)).toEqual([...DECOY_ROLE_CODES]);
    expect(me.data.permissions).toEqual(DECOY_PERMISSIONS);
    expect(me.data.buttons).toEqual(me.data.buttonPermissions.map((row) => row.code));
    expect(me.data.dataScope).toEqual({ type: 'all' });
    expect(me.data.menus.map((node) => node.id)).toEqual([
      'system',
      'device',
      'alarm',
      'inspection',
      'report',
    ]);
    expect(me.data.menus.every((node) => node.children.length > 0 && node.name)).toBe(true);
    const union = new Set([
      ...me.data.menuPermissions.map((row) => row.code),
      ...me.data.buttonPermissions.map((row) => row.code),
      ...me.data.apiPermissions.map((row) => row.code),
    ]);
    expect([...union].sort()).toEqual([...DECOY_PERMISSION_CATALOG.map((row) => row.code)].sort());
  });

  test('/my-info 与 /bindings：脱敏各一次、与 /me 时间同源，评分与建议按真实判据算', () => {
    const me = call('/api/auth/me');
    const info = call('/api/security/my-info');
    const bindings = call('/api/security/bindings');
    expect(info.data.user.lastLoginAt).toBe(me.data.user.lastLoginAt);
    expect(info.data.user.createdAt).toBe(me.data.user.createdAt);
    expect(Object.keys(info.data.user)).toEqual([
      '_id',
      'username',
      'email',
      'phone',
      'lastLoginAt',
      'createdAt',
      'status',
      '__v',
    ]);
    expect(info.data.user.email).toBe(DataMasking.maskEmail(me.data.user.email));
    expect(info.data.user.email).toBe('l***i@ljxfw.cn'); // 本地段只留首尾：与 DataMasking 同值（恰好脱敏一次）
    expect(info.data.user.phone).toBe(DataMasking.maskPhone(me.data.user.phone));
    expect(info.data.user.phone).toBe('138****1001');
    expect(info.data.securityScore).toBe(100);
    expect(info.data.suggestions).toEqual([]);
    const stale = call('/api/security/my-info', {
      session: { iatMs: NOW - 40 * DAY_MS },
    });
    expect(stale.data.securityScore).toBe(90);
    expect(stale.data.suggestions).toEqual([SECURITY_SUGGESTION_CODES.ACCOUNT_INACTIVE_LONG]);
    expect(info.data.recentLogins.map((row) => row.action)).toEqual([
      'login_success',
      'login_failed',
    ]);
    expect(info.data.recentLogins[0].time).toBe(new Date(NOW - 95 * 60000).toISOString());
    expect(info.data.recentLogins.every((row) => /^\d+\.\d+\.\*\.\*$/.test(row.ip))).toBe(true);
    expect(bindings.data.bindings.map((row) => row.type)).toEqual(['email', 'phone', 'department']);
    expect(bindings.data.bindings.map((row) => row.required)).toEqual([true, false, false]);
    expect(bindings.data.bindings[0].value).toBe(info.data.user.email);
    expect(bindings.data.bindings[1].value).toBe(info.data.user.phone);
    expect(bindings.data.bindings[2].value).toBe(me.data.user.department);
  });

  test('/my-logs：行形态、时间窗与参数拒绝逐字复用真实口径', () => {
    const logs = call('/api/security/my-logs');
    expect(logs.message).toBe('获取成功');
    expect(Array.isArray(logs.data)).toBe(true);
    expect(logs.data).toHaveLength(DECOY_SELF_LOGS.length);
    expect(logs.data.map((row) => row.action)).toEqual([
      'security_my-logs',
      'auth_sessions',
      'device_view',
      'auth_me',
      'login_success',
      'login_failed',
      'report_export',
    ]);
    for (const row of logs.data) {
      expect(row._id).toMatch(/^[0-9a-f]{24}$/);
      expect(row.timestamp).toBe(row.createdAt);
      expect(row.userId).toBe(SESSION.userId);
      expect(row.username).toBe(SESSION.username);
    }
    expect(logs.data[0].sessionId).toBe(SESSION.sid);
    expect(logs.data[0].ip).toBe(SESSION.ip);
    expect(logs.data[0].userAgent).toBe(SESSION.ua);
    expect(logs.data.at(-1).sessionId).not.toBe(SESSION.sid); // 上一次会话另有 sid
    expect(logs.data.at(-1).ip).not.toBe(SESSION.ip);
    expect(
      call('/api/security/my-logs', { query: { category: 'auth' } }).data.every(
        (r) => r.category === 'auth'
      )
    ).toBe(true);
    expect(call('/api/security/my-logs', { query: { limit: '2' } }).data).toHaveLength(2);
    expect(call('/api/security/my-logs', { query: { limit: '0' } }).data).toHaveLength(
      DECOY_SELF_LOGS.length
    );
    expect(call('/api/security/my-logs', { query: { limit: 'abc' } }).data).toHaveLength(
      DECOY_SELF_LOGS.length
    );
    const narrowed = call('/api/security/my-logs', { query: { days: '1' } });
    expect(narrowed.data.length).toBeGreaterThan(0);
    expect(narrowed.data.length).toBeLessThan(logs.data.length);
    const bad = call('/api/security/my-logs', { query: { category: 'nope' } });
    expect(bad.errorCode).toBe('VALIDATION_FAILED');
    expect(bad.verdict).toBe(HONEYPOT_VERDICT.DENY);
    expect(bad.options.fieldErrors).toEqual([{ path: 'category', msg: '不支持的操作类别' }]);
    expect(AUDIT_CATEGORIES).toContain('auth');
  });

  test('/sessions：只呈现当前这一条，键序与 toClientJSON 同形；无 sid 回空表', () => {
    const sessions = call('/api/auth/sessions');
    expect(sessions.data.total).toBe(1);
    expect(sessions.data.currentSidPresent).toBe(true);
    expect(Object.keys(sessions.data.sessions[0])).toEqual([
      'sid',
      'current',
      'deviceType',
      'browser',
      'browserVersion',
      'os',
      'osVersion',
      'deviceVendor',
      'deviceModel',
      'engine',
      'cpu',
      'userAgent',
      'ip',
      'lastIp',
      'createdAt',
      'lastSeenAt',
      'expiresAt',
      'location',
      'loginLocation',
    ]);
    const row = sessions.data.sessions[0];
    expect(row.sid).toBe(SESSION.sid);
    expect(row.current).toBe(true);
    expect(row.browser).toBe('Chrome');
    expect(row.os).toBe('Windows');
    expect(row.deviceType).toBe('desktop');
    expect(row.ip).toBe(SESSION.ip);
    expect(row.createdAt).toBe(new Date(SESSION.iatMs).toISOString());
    expect(row.lastSeenAt).toBe(new Date(NOW).toISOString());
    expect(new Date(row.expiresAt).getTime() - new Date(row.createdAt).getTime()).toBe(7 * DAY_MS);
    expect(call('/api/auth/sessions', { session: { sid: null } }).data).toEqual({
      sessions: [],
      total: 0,
      currentSidPresent: false,
    });
  });

  test('/mfa/status：与真实控制器同形（默认消息，不开 MFA 是诱饵账户的真实状态）', () => {
    const status = call('/api/auth/mfa/status');
    expect(status.data).toEqual({ enabled: false, recoveryCodesRemaining: 0 });
    expect(status.message).toBe('操作成功');
  });

  test('/report-targets：候选来自合成表（含本人一行），id 为真记录形态，未知类型逐字 400', () => {
    const users = call('/api/security/report-targets', { query: { type: 'user' } });
    expect(users.message).toBe('操作成功');
    expect(users.data.items[0]).toEqual({
      id: SESSION.userId,
      kind: 'user',
      code: SESSION.username,
      name: SESSION.realName,
      detail: '中控室',
    });
    expect(users.data.items).toHaveLength(DECOY_USERS.length + 1);
    const devices = call('/api/security/report-targets', { query: { type: 'device' } });
    expect(devices.data.items).toHaveLength(DECOY_DEVICES.length);
    // detail 是位置标签串（真实链 formatLocationLabel，sensitive.js:236-241,272）：' · ' 连接、空段跳过
    expect(devices.data.items[0].detail).toBe('A1 厂房 · 2 层 · 东侧');
    expect(devices.data.items.every((item) => typeof item.detail === 'string')).toBe(true);
    expect(
      devices.data.items.every((item, index) =>
        DECOY_DEVICES[index].location
          ? item.detail ===
            [
              DECOY_DEVICES[index].location.building,
              DECOY_DEVICES[index].location.floor,
              DECOY_DEVICES[index].location.room,
            ]
              .filter((part) => typeof part === 'string' && part.trim() !== '')
              .join(' · ')
          : item.detail === ''
      )
    ).toBe(true);
    for (const item of [...users.data.items, ...devices.data.items]) {
      expect(item.id).toMatch(/^[0-9a-f]{24}$/);
    }
    const hit = call('/api/security/report-targets', {
      query: { type: 'device', keyword: 'SD-A1-014' },
    });
    expect(hit.data.items.map((item) => item.code)).toEqual(['SD-A1-014']);
    expect(
      call('/api/security/report-targets', {
        query: { type: 'device', keyword: 'sd-a1' },
      }).data.items.map((item) => item.code)
    ).toEqual(['SD-A1-014', 'SD-A1-027']); // 设备码走真实 upperCodePrefixPattern：词先转大写再锚定前缀
    const alarms = call('/api/security/report-targets', {
      query: { type: 'alarm', keyword: 'AL-2026-0731' },
    });
    expect(alarms.data.items[0].name).toBe('smoke');
    expect(typeof alarms.data.items[0].occurredAt).toBe('string');
    // 报警候选的 detail 与设备候选同形（位置子文档拼成一行人话）：跟着字段走——location 已换成真实子文档
    expect(alarms.data.items[0].detail).toBe(
      [
        DECOY_ALARMS[0].location.building,
        DECOY_ALARMS[0].location.floor,
        DECOY_ALARMS[0].location.room,
      ]
        .filter((part) => typeof part === 'string' && part.trim() !== '')
        .join(' · ')
    );
    for (const type of ['system', 'nope', '__proto__', 'users']) {
      const bad = call('/api/security/report-targets', { query: { type } });
      expect(bad.errorCode).toBe('VALIDATION_FAILED');
      expect(bad.verdict).toBe(HONEYPOT_VERDICT.DENY);
      expect(bad.options.fieldErrors).toEqual([{ field: 'type', message: '无效的目标类型' }]);
    }
    expect(call('/api/security/report-targets').errorCode).toBe('VALIDATION_FAILED');
    expect(call('/api/security/report-targets', { query: { type: [] } }).errorCode).toBe(
      'VALIDATION_FAILED'
    );
  });

  test('零泄漏：七条响应里不出现 hp- 前缀、honeypot 字样与内部标志', () => {
    const payload = SELF_ENDPOINTS.map((endpoint) =>
      JSON.stringify(call(endpoint.path, { query: { type: 'user' } }))
    ).join('\n');
    expect(payload).not.toMatch(/hp-/);
    expect(payload.toLowerCase()).not.toContain('honeypot');
    expect(payload).not.toContain('isHoneypot');
  });

  test('零真实集合读取：七条响应全程不碰 User / UserSession / AuditLog', () => {
    const models = [
      require('../../models/User'),
      require('../../models/UserSession'),
      require('../../models/AuditLog'),
    ];
    const spies = [];
    for (const model of models) {
      for (const method of ['find', 'findOne', 'countDocuments', 'aggregate']) {
        if (typeof model[method] === 'function') spies.push(jest.spyOn(model, method));
      }
    }
    expect(spies.length).toBeGreaterThanOrEqual(3); // 反证：替身真的挂上了，否则"没被调用"是空转
    for (const endpoint of SELF_ENDPOINTS) {
      call(endpoint.path, { query: { type: 'device' } });
    }
    for (const spy of spies) expect(spy).not.toHaveBeenCalled();
    for (const spy of spies) spy.mockRestore();
  });

  test('出口：成功与错误都走真实响应构造器（状态码与响应体逐字一致）', () => {
    const res = mockRes();
    sendSelfResponse(res, { data: { a: 1 }, message: '获取成功' });
    const expected = mockRes();
    ApiResponse.success(expected, { a: 1 }, '获取成功');
    expect(res.statusCode).toBe(expected.statusCode);
    expect(res.body).toEqual(expected.body);

    const bad = mockRes();
    sendSelfResponse(bad, call('/api/security/my-logs', { query: { category: 'nope' } }));
    const expectedBad = mockRes();
    ApiResponse.codeError(expectedBad, 'VALIDATION_FAILED', {
      fieldErrors: [{ path: 'category', msg: '不支持的操作类别' }],
    });
    expect(bad.statusCode).toBe(expectedBad.statusCode);
    expect(bad.body).toEqual(expectedBad.body);
  });

  test('会话上下文：只摘 req 上已有的身份，非法输入不回退成"看起来像真的"', () => {
    const ctx = sessionContextOf({
      user: {
        userId: 12345,
        username: 'liwei',
        realName: '李伟',
        sid: 'sid-1',
        iat: 1700000000,
        mustChangePassword: true,
      },
      headers: { 'user-agent': 'UA' },
      ip: '10.44.0.9',
    });
    expect(ctx).toEqual({
      sid: 'sid-1',
      userId: '12345',
      username: 'liwei',
      realName: '李伟',
      mustChangePassword: true,
      ua: 'UA',
      ip: '10.44.0.9',
      iatMs: 1700000000000,
      now: expect.any(Number),
    });
    const empty = sessionContextOf(null);
    expect(empty.sid).toBeNull();
    expect(empty.userId).toBeNull();
    expect(empty.iatMs).toBeNull();
    expect(empty.ua).toBe('');
    expect(empty.username).toBe('');
    expect(
      call('/api/auth/me', { session: { username: '', iatMs: null, ip: null } }).data.user.email
    ).toBe('');
  });
});
