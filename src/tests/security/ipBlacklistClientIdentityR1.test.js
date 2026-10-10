/**
 * 黑/白名单匹配身份取「安全裁决尺」（2026-10-10 待裁定 #24 → R1）
 *
 * 缺陷形状（第 32 轮实测五例 A/B/C/D/E）：checkIPBlacklist 拿 req.ip 查名单，而开
 * trust proxy 时 req.ip 来自请求方自己写的 X-Forwarded-For。于是真身已在黑名单的
 * 公网直连方，只要伪造一个白名单地址（或任意不在名单里的地址）就整条免检（探针 A/B/D）。
 *
 * 修法（R1）：名单匹配身份改取 utils/ipUtils.js 的 clientIpForSecurityDecision——与
 * auth.js 准入侧、securityController 的 PII 留痕同一把尺：可信边界内取 req.ip，边界外
 * （公网直连+伪造 XFF）退回不可伪造的 socket 对端 ⇒ 真身被黑名单者伪造白名单地址不再免检。
 *
 * 本文件只钉 HTTP 侧这一改的可观测契约，并用**对参数敏感**的名单 mock（只有真身对端命中
 * 才返回 true）保证可证伪：把 security.js:590 改回 req.ip，A/B 两例立刻判红。
 * 遗留边界（不在本改）：容器内直连的对端是 RFC1918 ⇒ 仍判可信形态 3) ⇒ 该形态伪造一跳仍
 * 可用（探针 D）；关它属 #24 的 R3（可信代理集合）。
 *
 * E 例（经内网 nginx 的真实办公网客户）在任何修法下都必须放行并拿到豁免标记——打红它就是
 * 把整个白名单功能打成可用性回退。
 */

'use strict';

jest.mock('../../models/AuditLog', () => ({
  record: jest.fn(() => Promise.resolve(null)),
}));

const { checkIPBlacklist } = require('../../middleware/security');
const IPBlacklist = require('../../models/IPBlacklist');

const REAL_PEER = '198.51.100.7'; // 真身：公网直连方，已在黑名单
const FORGED_WHITELIST = '10.20.30.40'; // 攻击者伪造的"白名单 IP"（办公网段形态）

/** 极简 req 替身：只含判据真正读到的字段（ip / socket / connection / app / get） */
const makeReq = (overrides = {}) => {
  const headers = overrides.headers || { 'user-agent': 'jest-r1' };
  return {
    ip: '203.0.113.77',
    socket: { remoteAddress: '203.0.113.77' },
    connection: { remoteAddress: '203.0.113.77' },
    method: 'GET',
    path: '/api/devices',
    originalUrl: '/api/devices',
    params: {},
    query: {},
    body: {},
    app: undefined,
    get: (name) => headers[String(name).toLowerCase()],
    ...overrides,
  };
};

const appTrustProxy1 = { get: (k) => (k === 'trust proxy' ? 1 : undefined) };

/** res 替身：codeError → res.status(code).json({..., errors:{ errorCode }}) */
const makeRes = () => {
  const res = {
    statusCode: 0,
    body: null,
    status: jest.fn((c) => {
      res.statusCode = c;
      return res;
    }),
    json: jest.fn((b) => {
      res.body = b;
      return res;
    }),
  };
  return res;
};

const errCodeOf = (res) => (res.body && res.body.errors && res.body.errors.errorCode) || null;

describe('#24 R1 · 黑/白名单匹配身份取安全裁决尺（HTTP 侧 checkIPBlacklist）', () => {
  afterEach(() => jest.restoreAllMocks());

  test('A 公网直连+伪造白名单 XFF，真身对端在黑名单 ⇒ 必须拦截（改前放行）', async () => {
    // 对参数敏感：只有真身对端命中才判封禁——若代码改回 req.ip，查的是伪造地址 ⇒ 不拦 ⇒ 判红
    const isBlocked = jest
      .spyOn(IPBlacklist, 'isBlocked')
      .mockImplementation(async (ip) => ip === REAL_PEER);
    jest.spyOn(IPBlacklist, 'isWhitelisted').mockResolvedValue(false);

    const req = makeReq({
      app: appTrustProxy1,
      ip: FORGED_WHITELIST,
      socket: { remoteAddress: REAL_PEER },
      connection: { remoteAddress: REAL_PEER },
      headers: { 'user-agent': 'jest-r1', 'x-forwarded-for': FORGED_WHITELIST },
    });
    const res = makeRes();
    const next = jest.fn();

    await checkIPBlacklist(req, res, next);

    expect(next).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalled();
    expect(errCodeOf(res)).toBe('IP_BLOCKED');
    // 独立于拦截结果也证伪：查名单必须用真身对端，而非请求头写的伪造地址
    expect(isBlocked).toHaveBeenCalledWith(REAL_PEER);
  });

  test('B 公网直连+伪造任意非名单 XFF，真身对端在黑名单 ⇒ 必须拦截（改前放行）', async () => {
    const FORGED = '203.0.113.9'; // 既不在黑也不在白
    const isBlocked = jest
      .spyOn(IPBlacklist, 'isBlocked')
      .mockImplementation(async (ip) => ip === REAL_PEER);
    jest.spyOn(IPBlacklist, 'isWhitelisted').mockResolvedValue(false);

    const req = makeReq({
      app: appTrustProxy1,
      ip: FORGED,
      socket: { remoteAddress: REAL_PEER },
      connection: { remoteAddress: REAL_PEER },
      headers: { 'user-agent': 'jest-r1', 'x-forwarded-for': FORGED },
    });
    const res = makeRes();
    const next = jest.fn();

    await checkIPBlacklist(req, res, next);

    expect(next).not.toHaveBeenCalled();
    expect(errCodeOf(res)).toBe('IP_BLOCKED');
    expect(isBlocked).toHaveBeenCalledWith(REAL_PEER);
  });

  test('C 无 trust proxy 直连，真身对端在黑名单 ⇒ 照常拦截（不过度放行）', async () => {
    jest.spyOn(IPBlacklist, 'isBlocked').mockImplementation(async (ip) => ip === REAL_PEER);
    jest.spyOn(IPBlacklist, 'isWhitelisted').mockResolvedValue(false);

    const req = makeReq({
      ip: REAL_PEER,
      socket: { remoteAddress: REAL_PEER },
      connection: { remoteAddress: REAL_PEER },
    });
    const res = makeRes();
    const next = jest.fn();

    await checkIPBlacklist(req, res, next);

    expect(next).not.toHaveBeenCalled();
    expect(errCodeOf(res)).toBe('IP_BLOCKED');
  });

  test('E 经内网 nginx 的白名单客户 ⇒ 放行且拿到豁免标记（可用性不得回退）', async () => {
    // 对端是内网（nginx/容器网络）⇒ 可信形态 3) ⇒ 采信 req.ip（代理认定的真实客户）
    jest
      .spyOn(IPBlacklist, 'isWhitelisted')
      .mockImplementation(async (ip) => ip === FORGED_WHITELIST);
    jest.spyOn(IPBlacklist, 'isBlocked').mockResolvedValue(false);

    const req = makeReq({
      app: appTrustProxy1,
      ip: FORGED_WHITELIST,
      socket: { remoteAddress: '::ffff:172.18.0.2' },
      connection: { remoteAddress: '::ffff:172.18.0.2' },
      headers: { 'user-agent': 'jest-r1', 'x-forwarded-for': FORGED_WHITELIST },
    });
    const res = makeRes();
    const next = jest.fn();

    await checkIPBlacklist(req, res, next);

    expect(next).toHaveBeenCalled();
    expect(req.ipWhitelisted).toBe(true);
    expect(res.status).not.toHaveBeenCalled();
  });
});
