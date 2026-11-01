/**
 * 蜜罐会话的影子数据面（P1）：判定表、合成数据与接管留下的痕迹
 *
 * 与既有测试的分工：
 *  - tests/services/honeypotWatch.test.js 管「物化 + 诱饵登录 + 枚举面排除」（P0）；
 *  - 本文件管「登录之后」：陷阱会话的每个请求怎么被改道、改道后给什么、留下什么证据。
 *
 * 钉住的边界：
 *  1. 合成数据必须**冻结**且 id 形态与真实 ObjectId 不相交（撞号即等于读到真记录）；
 *  2. 写方法（POST/PUT/PATCH/DELETE）**永不**返回合成数据面，一律与真实 403 用同一个响应构造器
 *     （错误体逐字相同，否则对方能靠响应体指纹认出陷阱）；
 *  3. 放行白名单只允许会话自身的续期/登出等不读业务数据的端点，且必须是非写业务语义；
 *  4. 非蜜罐会话、以及总开关关闭时的老会话，一律不被接管（回落到常规 RBAC）；
 *  5. 每次接管都留一条 honeypot_probe 审计（写尝试 critical / 只读 high），告警按类别每账户每日一次。
 */

'use strict';

const mongoose = require('mongoose');
const honeypotDecoy = require('../../services/honeypotDecoy');
const honeypotWatch = require('../../services/honeypotWatch');
const ApiResponse = require('../../utils/apiResponse');
const {
  AGGREGATE_ENDPOINTS,
  resolveAggregatePayload,
} = require('../../constants/honeypotDecoyAggregates');
const securityAlert = require('../../services/securityAlert');
const {
  DECOY_ALARMS,
  DECOY_DEVICES,
  DECOY_PERMISSIONS,
  DECOY_ROLE_CODES,
  DECOY_SELF,
  DECOY_SUMMARY,
  DECOY_TABLES,
  DECOY_USERS,
  HONEYPOT_DECOY_ID_PREFIX,
  HONEYPOT_VERDICT,
  PASSTHROUGH_ROUTES,
  WRITE_METHODS,
  resolveDecoyPayload,
  resolveDecoyVerdict,
} = require('../../constants/honeypotDecoy');

describe('蜜罐影子数据面（P1）：改道判定、合成数据与留痕', () => {
  const honeypotName = 'decoytrap';
  const saved = {};
  let AuditLog;
  let dispatchSpy;

  const setEnv = (key, value) => {
    if (!(key in saved)) saved[key] = process.env[key];
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  };
  const makeRes = () => {
    const res = { headers: {} };
    res.status = (code) => {
      res.statusCode = code;
      return res;
    };
    res.json = (payload) => {
      res.body = payload;
      return res;
    };
    res.setHeader = (k, v) => {
      res.headers[k] = v;
      return res;
    };
    return res;
  };
  const makeReq = (method, url, query) => ({
    method,
    originalUrl: url,
    query: query || {},
    ip: '10.44.0.9',
    user: { userId: 'hp-u1', username: honeypotName, isHoneypot: true },
  });
  const probeRows = (username, riskLevel) =>
    AuditLog.countDocuments({
      action: 'honeypot_probe',
      username,
      ...(riskLevel ? { riskLevel } : {}),
    });
  const probeDispatches = () => dispatchSpy.mock.calls.filter((c) => c[0] === 'honeypot_probe');

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
      .deleteMany({ action: 'honeypot_probe' })
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

  test('合成数据自证：冻结、id 形态与真实 ObjectId 不相交、计数与列表自洽', () => {
    const tables = [DECOY_USERS, DECOY_DEVICES, DECOY_ALARMS, DECOY_TABLES.roles];
    for (const table of tables) {
      expect(Object.isFrozen(table)).toBe(true);
      for (const row of table) {
        expect(Object.isFrozen(row)).toBe(true);
        expect(row._id.startsWith(HONEYPOT_DECOY_ID_PREFIX)).toBe(true);
        expect(mongoose.isValidObjectId(row._id)).toBe(false);
      }
    }
    expect(DECOY_SUMMARY.users).toBe(DECOY_USERS.length);
    expect(DECOY_SUMMARY.devices).toBe(DECOY_DEVICES.length);
    expect(DECOY_SUMMARY.alarms).toBe(DECOY_ALARMS.length);
    expect(DECOY_TABLES.roles.every((r) => typeof r.userCount === 'number')).toBe(true);
    const roleById = new Map(DECOY_TABLES.roles.map((role) => [role._id, role])); // M5：users.roles 元素与 roles 表同源（populate 形状 {_id,name,code}）
    for (const user of DECOY_USERS) {
      for (const role of user.roles) {
        expect(roleById.get(role._id)).toMatchObject({ name: role.name, code: role.code });
      }
    }
    expect(DECOY_DEVICES.every((d) => d.location && typeof d.location === 'object')).toBe(true); // M2：location 是子文档而非字符串
    expect(
      DECOY_DEVICES.every(
        (d) =>
          d.lifecycleStage &&
          d.maintenanceRecordCount === 0 &&
          [d.maintenanceRecord, d.inspectionRecord, d.images].every(Array.isArray)
      )
    ).toBe(true); // M3：真实必现键齐了
    const materialized = resolveDecoyPayload({ path: '/api/users' });
    expect(materialized.total).toBe(DECOY_USERS.length);
    expect(Object.isFrozen(materialized.data[0])).toBe(false); // 物化出来的是每请求新副本，冻结的只有源数据
    expect(new Date(materialized.data[0].createdAt).getTime()).toBeLessThan(Date.now() + 60000);
  });

  test('判定表：已声明读路由给数据面，写方法与未声明路径各按真实链的 403/404，放行白名单逐条钉死', () => {
    expect(resolveDecoyVerdict({ method: 'GET', path: '/api/users' })).toBe(HONEYPOT_VERDICT.DECOY);
    expect(resolveDecoyVerdict({ method: 'GET', path: '/api/users/hp-u3' })).toBe(
      HONEYPOT_VERDICT.DECOY
    );
    // 聚合子路径也是「已声明路由」：必须落在数据面，而不是被当成查不到的 id
    expect(resolveDecoyVerdict({ method: 'GET', path: '/api/users/stats' })).toBe(
      HONEYPOT_VERDICT.DECOY
    );
    expect(resolveDecoyVerdict({ method: 'GET', path: '/api/reports/dashboard' })).toBe(
      HONEYPOT_VERDICT.DECOY
    );
    expect(resolveDecoyVerdict({ method: 'GET', path: '/api/users/hp-u9' })).toBe(
      HONEYPOT_VERDICT.DECOY
    );
    // 表里有 PUT /api/users/:id、没有 PUT /api/users：两句话分别对应真实链的 403 与 404
    expect(resolveDecoyVerdict({ method: 'POST', path: '/api/users' })).toBe(HONEYPOT_VERDICT.DENY);
    expect(resolveDecoyVerdict({ method: 'PUT', path: '/api/users/hp-u3' })).toBe(
      HONEYPOT_VERDICT.DENY
    );
    expect(resolveDecoyVerdict({ method: 'PUT', path: '/api/users' })).toBe(
      HONEYPOT_VERDICT.NOT_FOUND
    );
    for (const method of WRITE_METHODS) {
      const verdict = resolveDecoyVerdict({ method, path: '/api/users' });
      expect([HONEYPOT_VERDICT.DENY, HONEYPOT_VERDICT.NOT_FOUND]).toContain(verdict);
    }
    // 未声明路径：真实链落到 app.js 兜底 404。过去这里写 DENY，而那个 403 在 HTTP 上不可达
    expect(resolveDecoyVerdict({ method: 'GET', path: '/api/health' })).toBe(
      HONEYPOT_VERDICT.NOT_FOUND
    );
    expect(resolveDecoyVerdict({ method: 'GET', path: '/api/users/hp-u9/extra' })).toBe(
      HONEYPOT_VERDICT.NOT_FOUND
    );
    // 无 authenticate 的路由在改道点不可达，声明真相是「不接管」
    expect(resolveDecoyVerdict({ method: 'GET', path: '/health' })).toBe(
      HONEYPOT_VERDICT.PASSTHROUGH
    );
    expect(resolveDecoyVerdict({ method: 'GET', path: '/api/auth/me' })).toBe(
      HONEYPOT_VERDICT.DECOY
    );
    expect(resolveDecoyVerdict({ method: 'POST', path: '/api/auth/refresh' })).toBe(
      HONEYPOT_VERDICT.PASSTHROUGH
    );
    expect(resolveDecoyVerdict({ method: 'GET', path: '/api/version' })).toBe(
      HONEYPOT_VERDICT.PASSTHROUGH
    );
    // 放行白名单不得含任一写业务方法指向业务前缀
    for (const route of PASSTHROUGH_ROUTES) {
      expect(route.path.startsWith('/api/auth/') || route.path === '/api/version').toBe(true);
    }
    expect(PASSTHROUGH_ROUTES.map((r) => r.method + ' ' + r.path).sort()).toEqual([
      'GET /api/version',
      'POST /api/auth/logout',
      'POST /api/auth/refresh',
    ]);
  });

  test('非蜜罐会话不被接管：steer 返回 false，且不落探测审计', async () => {
    const before = await probeRows(honeypotName);
    const res = makeRes();
    const normal = makeReq('GET', '/api/users');
    normal.user = { userId: 'real-1', username: 'zhangwei', isHoneypot: false };
    expect(await honeypotDecoy.steer(normal, res)).toBe(false);
    expect(res.body).toBeUndefined();
    const anonymous = makeReq('GET', '/api/users');
    anonymous.user = undefined;
    expect(await honeypotDecoy.steer(anonymous, res)).toBe(false);
    expect(await probeRows(honeypotName)).toBe(before);
    expect(honeypotDecoy.isHoneypotSession({ user: { isHoneypot: 'true' } })).toBe(false);
  });

  test('诱饵会话只读：接管后返回合成列表并留 high 审计 + 一条 HIGH 告警（重复探测审计逐条、告警仍一条）', async () => {
    honeypotWatch.__resetForTest();
    const res = makeRes();
    expect(await honeypotDecoy.steer(makeReq('GET', '/api/users'), res)).toBe(true);
    expect(res.statusCode).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.data).toHaveLength(DECOY_USERS.length);
    expect(res.body.data.map((u) => u.username)).not.toContain('admin');
    expect(res.body.pagination.total).toBe(DECOY_USERS.length);
    const rows = await AuditLog.find({ action: 'honeypot_probe', username: honeypotName }).lean();
    expect(rows).toHaveLength(1);
    expect(rows[0].riskLevel).toBe('high');
    expect(rows[0].category).toBe('security');
    expect(rows[0].path).toBe('/api/users');
    expect(rows[0].body.honeypot).toBe(honeypotName);
    expect(probeDispatches()).toHaveLength(1);
    expect(probeDispatches()[0][1]).toBe(securityAlert.ALERT_LEVELS.HIGH);

    await honeypotDecoy.steer(makeReq('GET', '/api/users/hp-u2'), makeRes());
    expect(await probeRows(honeypotName, 'high')).toBe(2);
    expect(probeDispatches()).toHaveLength(1);
  });

  test('写尝试：403 且响应体与真实 403 逐字相同（同一构造器）+ critical 审计 + 独立告警', async () => {
    const res = makeRes();
    const expected = makeRes();
    ApiResponse.codeError(expected, 'PERMISSION_DENIED');
    expect(await honeypotDecoy.steer(makeReq('POST', '/api/users'), res)).toBe(true);
    expect(res.statusCode).toBe(403);
    expect(res.body).toEqual(expected.body);
    expect(await probeRows(honeypotName, 'critical')).toBe(1);
    const writeCall = probeDispatches().find((c) => c[1] === securityAlert.ALERT_LEVELS.CRITICAL);
    expect(writeCall).toBeTruthy();
    expect(writeCall[3].verdict).toBe(HONEYPOT_VERDICT.DENY);
  });

  test('合成档案：/api/users/me 按会话身份呈现（P2），且不带 isHoneypot 这类内部标志', async () => {
    const res = makeRes();
    await honeypotDecoy.steer(makeReq('GET', '/api/users/me'), res);
    expect(res.body.data.username).toBe(honeypotName); // 本人是谁就呈现谁：回合成首行会让"本人"对不上攻击者手里的名字
    expect(res.body.data._id).toBe('hp-u1');
    expect(Object.keys(res.body.data.roles[0])).toEqual(['_id', 'name', 'code']); // populate 投影 userService.js:56
    expect(DECOY_ROLE_CODES).toContain(res.body.data.roles[0].code);
    expect(Object.keys(res.body.data)).not.toContain('isHoneypot');
    expect(DECOY_PERMISSIONS.length).toBeGreaterThan(0);
    expect(resolveDecoyPayload({ path: '/api/users/me' }).data.username).toBe(DECOY_SELF.username); // 无会话身份时才回合成首行
  });

  test('明细未命中回集合点名的 404：与真实控制器同一个构造器，统一文案本身就是指纹', async () => {
    const res = makeRes();
    const expected = makeRes();
    ApiResponse.codeError(expected, 'USER_NOT_FOUND', { statusCode: 404 });
    expect(await honeypotDecoy.steer(makeReq('GET', '/api/users/hp-u9'), res)).toBe(true);
    expect(res.statusCode).toBe(404);
    expect(res.body).toEqual(expected.body);
    expect(res.body.errors.errorCode).toBe('USER_NOT_FOUND');
  });

  test('未声明路径回 app.js 兜底 404 的逐字副本：无 errors 键、URL 打码同源', async () => {
    const res = makeRes();
    expect(await honeypotDecoy.steer(makeReq('GET', '/api/users/hp-u9/extra'), res)).toBe(true);
    expect(res.statusCode).toBe(404);
    expect(res.body).toEqual({
      success: false,
      message: '接口不存在：GET /api/users/hp-u9/extra',
    });
    expect('errors' in res.body).toBe(false);
  });

  test('聚合读面：10 条同前缀聚合路由都会被接管，且信封/键集与真实控制器同形（HTTP 级）', async () => {
    const keysOf = (data) =>
      Array.isArray(data) ? Object.keys(data[0] || {}).sort() : Object.keys(data || {}).sort(); // 只对形状：行里的相对时间量每次物化都差几毫秒，逐字节比对会是假红
    for (const endpoint of AGGREGATE_ENDPOINTS) {
      const res = makeRes();
      expect(await honeypotDecoy.steer(makeReq(endpoint.method, endpoint.path), res)).toBe(true);
      expect(res.statusCode).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.message).toBe(endpoint.message);
      const expected = resolveAggregatePayload({
        method: endpoint.method,
        path: endpoint.path,
        query: {},
      });
      expect(keysOf(res.body.data)).toEqual(keysOf(expected.data));
      if (endpoint.envelope === 'paginated') {
        expect(res.body.pagination).toEqual(expected.pagination);
        // 分页信封必带 page/limit/total/totalPages：null 位是真实链的形态（游标模式），不能被 numOr 折成数字
        for (const key of ['page', 'limit', 'total', 'totalPages'])
          expect(key in res.body.pagination).toBe(true);
      } else {
        expect('pagination' in res.body).toBe(false); // success 信封不带分页键：多一个键就是可指纹差异
      }
    }
  });

  test('聚合读面吃请求参数，且不吃「不属于它」的参数：days 生效、非法日期不伪造 200', async () => {
    const wide = makeRes();
    await honeypotDecoy.steer(makeReq('GET', '/api/devices/expiring', { days: '3650' }), wide);
    const narrow = makeRes();
    await honeypotDecoy.steer(makeReq('GET', '/api/devices/expiring', { days: '1' }), narrow);
    expect(wide.body.pagination.total).toBeGreaterThanOrEqual(narrow.body.pagination.total);
    expect(wide.body.data.length).toBeGreaterThanOrEqual(narrow.body.data.length);
    // 参数非法时真实链是 400 + codeError(DATE_PARAM_INVALID / DATE_RANGE_INVALID)：合成面必须用**同一个响应构造器**
    // 出同一份体（多一个字段、少一个键、或回落成 404「资源不存在」都是一次请求就能拿到的指纹）。
    const mirrorOf = (code) => {
      const mirror = makeRes();
      ApiResponse.codeError(mirror, code);
      return { status: mirror.statusCode, body: mirror.body };
    };
    for (const point of [
      {
        target: '/api/inspections/stats',
        code: 'DATE_PARAM_INVALID',
        query: { startDate: '2026-13-99', endDate: '2026-01-01' },
      },
      { target: '/api/alarms/stats', code: 'DATE_PARAM_INVALID', query: { startDate: 'zzz' } },
      {
        target: '/api/alarms/stats',
        code: 'DATE_RANGE_INVALID',
        query: { startDate: '2026-11-02', endDate: '2026-11-01' },
      },
      {
        target: '/api/inspections/stats',
        code: 'DATE_RANGE_INVALID',
        query: { startDate: '2026-11-02', endDate: '2026-11-01' },
      },
    ]) {
      const res = makeRes();
      expect(await honeypotDecoy.steer(makeReq('GET', point.target, point.query), res)).toBe(true);
      expect({ status: res.statusCode, body: res.body }).toEqual(mirrorOf(point.code));
    }
  });
  test('放行白名单不接管：续期/登出/版本走真实处理器', async () => {
    const before = await probeRows(honeypotName);
    for (const [method, path] of [
      ['POST', '/api/auth/refresh'],
      ['POST', '/api/auth/logout'],
      ['GET', '/api/version'],
    ]) {
      expect(await honeypotDecoy.steer(makeReq(method, path), makeRes())).toBe(false);
    }
    expect(await probeRows(honeypotName)).toBe(before);
  });

  test('总开关关闭：老会话不被接管（回落到常规 RBAC），且不留探测痕迹', async () => {
    setEnv('HONEYPOT_ENABLED', 'false');
    const before = await probeRows(honeypotName);
    const res = makeRes();
    expect(await honeypotDecoy.steer(makeReq('GET', '/api/users'), res)).toBe(false);
    expect(res.body).toBeUndefined();
    expect(await probeRows(honeypotName)).toBe(before);
    setEnv('HONEYPOT_ENABLED', 'true');
  });
});
