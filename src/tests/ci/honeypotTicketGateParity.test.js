/**
 * 缺票闸逐字对拍（P2-2 批次 B）：陷阱在二次验证路由上回的那句话，必须与真实中间件**逐字**相同
 *
 * 为什么值得一个闸：诱饵的整条价值线是「拿不到差异」。这 7 条路由在真实链上是
 * checkPermission('security:audit') → requireReauthTicket()，而呈现身份（/api/auth/me 那张权限表）
 * 经 security:* 已经过掉第一道闸——所以对陷阱会话而言「缺票」是唯一可能的真实答案。批次 A 之前这里是
 * 403 PERMISSION_DENIED：状态同、**理由不同**，对方比对两次响应即可分辨（详见路由表判据的登记项三）。
 *
 * 本闸只做三件事，且全部从源码现采、不抄期望值：
 * ① 字面量同源：马甲回的码 === middleware/security/reauthTicket.js 里写给 res 的那个码；
 * ② 逐字同形：马甲两个面（通用载荷面 / 文件面）的 statusCode + body 与 ApiResponse.codeError(res, 码)
 *    一模一样——同一个构造器、同一个注册表条目，含 Cache-Control: no-store；
 * ③ 有牙：把声明挪掉一个，答复必须立刻变（否则「同形」只是这 7 条恰好没被覆盖）；
 * 另加一条反向前提：陷阱**不可能**自己过这道闸（换票端点 POST /api/security/reauth 是拒绝面）。
 */
'use strict';

const fs = require('fs');
const path = require('path');

const ApiResponse = require('../../utils/apiResponse');
const { ERROR_CODES } = require('../../utils/errorCodes');
const { jsCodeOnly } = require('../helpers/jsCodeOnly');
const { ROUTE_TABLE, TRAP_HANDLING } = require('../../constants/honeypotRouteTable');
const { resolveDecoyPayload } = require('../../constants/honeypotDecoy');
const { resolveFileResponse } = require('../../services/honeypotDecoyFiles');
const {
  REAUTH_TICKET_REQUIRED_CODE,
  isReauthGated,
  reauthGateOf,
  reauthPayload,
} = require('../../constants/honeypotTicketGate');

const ROOT = path.resolve(__dirname, '../../..');
const read = (rel) => jsCodeOnly(fs.readFileSync(path.join(ROOT, rel), 'utf8'));
const keyOf = (row) => row.method + ' ' + row.path;
const SESSION = { userId: 'hp-u1', username: 'sample' };

/** 真实中间件（它是缺票那一句的唯一出处，期望值从这里现采，不抄常量） */
const MIDDLEWARE = 'src/middleware/security/reauthTicket.js';

/** 缺票分支实际发出的码：取该文件里唯一「先判没有票据、再回码」的那一处 */
const realMissingTicketCode = () => {
  const source = read(MIDDLEWARE);
  const at = source.indexOf('if (!ticket)');
  expect(at).toBeGreaterThan(0);
  const branch = source.slice(at, source.indexOf('}', at));
  const match = /codeError\(res,\s*'([A-Z0-9_]+)'/.exec(branch);
  expect(match).toBeTruthy();
  return match[1];
};

/** 真实构造器对同一个码的答复（对照物由生产代码现场产出，不是手写 JSON） */
const referenceAnswer = () => {
  const res = makeRes();
  ApiResponse.codeError(res, REAUTH_TICKET_REQUIRED_CODE);
  return { statusCode: res.statusCode, body: res.body, cacheControl: res.headers['cache-control'] };
};

function makeRes() {
  const res = {
    statusCode: 200,
    headers: {},
    body: null,
    status(code) {
      res.statusCode = code;
      return res;
    },
    setHeader(key, value) {
      res.headers[String(key).toLowerCase()] = value;
      return res;
    },
    json(payload) {
      res.body = payload;
      return res;
    },
  };
  return res;
}

const GATED_ROWS = ROUTE_TABLE.filter((row) => isReauthGated(row)); // 声明侧：有没有闸写在表的那一行上

describe('蜜罐缺票闸逐字对拍（P2-2 批次 B）', () => {
  test('前提：闸的声明恰好 9 条，且每条都真的在源码里挂了 requireReauthTicket', () => {
    // 2026-11-04 攻击告警查询面（LANSEC 复原）在 ROUTE_TABLE 登记 GET /api/security/
    // attack-events 与 /summary 两条 REAUTH 行 ⇒ 7→9；挂闸文件同步加 attackEventRoutes。
    expect(GATED_ROWS.length).toBe(9);
    for (const row of GATED_ROWS) {
      expect(row.handling).toBe(TRAP_HANDLING.REAUTH);
      expect(row.method).toBe('GET');
    }
    // 声明不是自己说了算：这 9 条必须都能在真实路由文件里找到 requireReauthTicket()。
    // 挂闸点分布在四个文件里（安全面 5 条 + 撞库画像面 1 条 + 攻击画像面 1 条 +
    // 攻击事件面 2 条），按文件分别点名，
    // 不写「全仓共 N 处」——那种总数在拆分/合并路由文件时会被无声地满足
    const gateSites = (rel) => (read(rel).match(/requireReauthTicket\(\)/g) || []).length;
    expect({
      securityRoutes: gateSites('src/routes/securityRoutes.js'),
      stuffingProfileRoutes: gateSites('src/routes/stuffingProfileRoutes.js'),
      attackProfileRoutes: gateSites('src/routes/attackProfileRoutes.js'),
      attackEventRoutes: gateSites('src/routes/attackEventRoutes.js'),
    }).toEqual({
      securityRoutes: 5,
      stuffingProfileRoutes: 1,
      attackProfileRoutes: 1,
      attackEventRoutes: 2,
    });
    const totalSites = [
      'src/routes/securityRoutes.js',
      'src/routes/stuffingProfileRoutes.js',
      'src/routes/attackProfileRoutes.js',
      'src/routes/attackEventRoutes.js',
    ].reduce((sum, rel) => sum + gateSites(rel), 0);
    // 两侧总数必须相等：声明 9 条 ⇔ 源码 9 处挂点。少一处意味着某条声明是凭空写的
    expect(totalSites).toBe(GATED_ROWS.length);
  });

  test('字面量同源：马甲回的码 === 真实中间件缺票分支写的码，且登记在码表里是 401', () => {
    expect(REAUTH_TICKET_REQUIRED_CODE).toBe(realMissingTicketCode());
    expect(reauthPayload().code).toBe(realMissingTicketCode());
    expect(ERROR_CODES[REAUTH_TICKET_REQUIRED_CODE]).toBeTruthy();
    expect(ERROR_CODES[REAUTH_TICKET_REQUIRED_CODE].status).toBe(401);
    // 冻结单例：调用方改不动它，两个面不会各回各的
    expect(Object.isFrozen(reauthPayload())).toBe(true);
    expect(reauthPayload()).toBe(reauthPayload());
  });

  test('逐字同形（通用载荷面）：7 条 gated 路由的答复 === ApiResponse.codeError(res, 真实码)', () => {
    const expected = referenceAnswer();
    for (const row of GATED_ROWS) {
      const res = makeRes();
      const payload = resolveDecoyPayload({ method: row.method, path: row.path, user: SESSION });
      expect(payload).toBeTruthy();
      ApiResponse.codeError(res, payload.code, payload.options);
      expect({ key: keyOf(row), statusCode: res.statusCode, body: res.body }).toEqual({
        key: keyOf(row),
        statusCode: expected.statusCode,
        body: expected.body,
      });
      expect(res.statusCode).toBe(401);
      expect(res.headers['cache-control']).toBe(expected.cacheControl);
      expect(res.body.errors).toEqual({ errorCode: REAUTH_TICKET_REQUIRED_CODE });
    }
  });

  test('逐字同形（文件面）：审计导出的拒绝体与同一个构造器同形，且不带任何文件头/字节', () => {
    const expected = referenceAnswer();
    const response = resolveFileResponse({
      method: 'GET',
      path: '/api/security/audit-logs/export',
      query: {},
    });
    expect(response.kind).toBe('codeError');
    const res = makeRes();
    ApiResponse.codeError(res, response.code, response.options);
    expect({ statusCode: res.statusCode, body: res.body }).toEqual({
      statusCode: expected.statusCode,
      body: expected.body,
    });
    // 拒绝绝不带文件头：真链在这条上是 JSON 401，不是一个空 xlsx
    expect(res.headers['content-type']).toBeUndefined();
    expect(response.verdict).toBe('deny');
    expect(response.write).toBe(false);
  });

  test('两个面同一个码：同一个 gated 路径经载荷面与文件面拿到的都是缺票 401', () => {
    const payload = resolveDecoyPayload({
      method: 'GET',
      path: '/api/security/audit-logs/export',
      user: SESSION,
    });
    const file = resolveFileResponse({
      method: 'GET',
      path: '/api/security/audit-logs/export',
      query: {},
    });
    expect(payload.code).toBe(file.code);
    expect(payload.code).toBe(REAUTH_TICKET_REQUIRED_CODE);
  });

  test('有牙：声明挪掉一行，那一行的答复必须立刻不再是缺票闸', () => {
    const row = GATED_ROWS[0];
    // 两个函数是两条轴，别混用：isReauthGated 吃**行**（声明轴），reauthGateOf 吃**请求**（路径轴）
    expect(isReauthGated(row)).toBe(true);
    expect(isReauthGated(Object.assign({}, row, { handling: TRAP_HANDLING.DENY }))).toBe(false);
    expect(isReauthGated(null)).toBe(false);
    // 路径轴认的是表里那条行的 handling，不是路径字符串本身
    expect(reauthGateOf({ method: row.method, path: row.path })).toBeTruthy();
    // 源码层：真去挂闸的函数被改掉，前提用例的现采必须跟着红（这里只证明正则吃得住正反样本）
    expect(realMissingTicketCode()).toBe(REAUTH_TICKET_REQUIRED_CODE);
    // 判定层：未被声明的路径不该凭空拿到缺票答复
    expect(reauthGateOf({ method: 'GET', path: '/api/security/overview' })).toBe(null);
    expect(reauthGateOf({ method: 'GET', path: '/api/ghost' })).toBe(null);
    expect(reauthGateOf()).toBe(null);
  });

  test('路径口径与判定层同源：大小写、一个尾斜杠、HEAD 回退 GET 都算同一条，双斜杠不算', () => {
    const gate = reauthGateOf({ method: 'GET', path: '/api/security/alerts' });
    expect(gate).toBeTruthy();
    expect(reauthGateOf({ method: 'get', path: '/API/Security/Alerts/' })).toBe(gate);
    expect(reauthGateOf({ method: 'HEAD', path: '/api/security/alerts' })).toBe(gate);
    expect(reauthGateOf({ method: 'GET', path: '/api//security/alerts' })).toBe(null);
    expect(reauthGateOf({ method: 'GET', path: '/api/security/alerts/extra' })).toBe(null);
  });

  test('反向前提：陷阱不可能自己过这道闸——换票端点是拒绝面，且不泄漏任何票据', () => {
    const reauthEndpoint = ROUTE_TABLE.find((row) => row.path === '/api/security/reauth');
    expect(reauthEndpoint).toBeTruthy();
    expect(isReauthGated(reauthEndpoint)).toBe(false);
    expect(reauthEndpoint.handling).toBe(TRAP_HANDLING.DENY);
    // 缺票答复里不许夹带任何可用的票据/窗口线索：只有 success/message/errors 三个键
    const res = makeRes();
    ApiResponse.codeError(res, REAUTH_TICKET_REQUIRED_CODE);
    expect(Object.keys(res.body).sort()).toEqual(['errors', 'message', 'success']);
    // 只准有「缺票」这个结论本身（码名里带 TICKET 是正常的）：不许夹带可用材料——JWT 串、
    // jti、窗口、签发时间，也不许回一个 x-reauth-ticket 响应头（那等于把「我发过票」写在头上）
    expect(JSON.stringify(res.body)).not.toMatch(/eyJ|jti|grantId|window|expiresAt/);
    expect(Object.keys(res.headers)).toEqual(['cache-control']);
    expect(res.headers['x-reauth-ticket']).toBeUndefined();
  });
});
