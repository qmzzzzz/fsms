/**
 * 客户端 IP 身份的可信边界判据（utils/ipUtils.js）
 *
 * 由来：`isWhitelistExemptionTrustworthy` 原本只服务于"发放限流/CSRF/query 豁免标记"，
 * 而认证侧的用户 IP 访问范围（`allowedIPs`）各自写 `req.ip || socket 对端`。开着
 * trust proxy 时 req.ip 取自 X-Forwarded-For，能直连应用端口的主体（同 compose 网络内
 * 的服务、误配入口、SSRF 跳板——`docker-compose.yml` 把应用端口发布为
 * `127.0.0.1:3000:3000`，但容器之间走的是 `app:3000`）伪造一跳即可把它换成任意地址：
 * 同一把伪造的头，一边买到豁免，一边**买到访问控制**。后者后果更重，判据必须同源。
 *
 * 本套件覆盖四种组合（对齐 whitelistExemptionTrustBoundary 的口径），并钉住两条
 * 单边回归都会放过的性质：
 *   - `::ffff:127.0.0.1` 这类映射形态的对端要按内网/回环算（否则 nginx 换 IPv6
 *     监听就把正常流量判成不可信）；
 *   - 判据退回 socket 对端时，安全裁决必须用**对端**而不是 req.ip（这才是修复本体）。
 */

const {
  isClientIpIdentityTrustworthy,
  clientIpForSecurityDecision,
} = require('../../utils/ipUtils');

/** 替身 req：只带判据实际读取的四个面（app.get / get / socket / ip） */
const makeReq = ({ trustProxy, xff, peer, ip }) => ({
  app: { get: (k) => (k === 'trust proxy' ? trustProxy : undefined) },
  get: (h) => (h.toLowerCase() === 'x-forwarded-for' ? xff : undefined),
  socket: { remoteAddress: peer },
  ip,
});

describe('客户端 IP 身份可信边界（ipUtils）', () => {
  test('未启用 trust proxy：req.ip 恒等于对端，头不参与判定 ⇒ 可信', () => {
    const req = makeReq({ trustProxy: false, xff: '203.0.113.9', peer: '8.8.8.8', ip: '8.8.8.8' });
    expect(isClientIpIdentityTrustworthy(req)).toBe(true);
    expect(clientIpForSecurityDecision(req)).toBe('8.8.8.8');
  });

  test('开了 trust proxy 但请求没有 XFF：req.ip 只能是 socket 对端 ⇒ 可信', () => {
    const req = makeReq({ trustProxy: 1, xff: undefined, peer: '8.8.8.8', ip: '8.8.8.8' });
    expect(isClientIpIdentityTrustworthy(req)).toBe(true);
    expect(clientIpForSecurityDecision(req)).toBe('8.8.8.8');
  });

  test('trust proxy + XFF + 对端为内网/回环（正常经 nginx）⇒ 采信 req.ip', () => {
    for (const peer of ['10.0.0.7', '172.16.3.4', '192.168.1.1', '127.0.0.1', '::1']) {
      const req = makeReq({ trustProxy: 1, xff: '203.0.113.9', peer, ip: '203.0.113.9' });
      expect({ peer, ok: isClientIpIdentityTrustworthy(req) }).toMatchObject({ peer, ok: true });
      expect(clientIpForSecurityDecision(req)).toBe('203.0.113.9');
    }
  });

  test('IPv4-mapped 回环对端（::ffff:127.0.0.1）仍算可信，nginx 换 IPv6 监听不误伤', () => {
    const req = makeReq({
      trustProxy: 1,
      xff: '203.0.113.9',
      peer: '::ffff:127.0.0.1',
      ip: '203.0.113.9',
    });
    expect(isClientIpIdentityTrustworthy(req)).toBe(true);
    expect(clientIpForSecurityDecision(req)).toBe('203.0.113.9');
  });

  test('公网直连 + 伪造 XFF ⇒ 不可信，裁决退回 socket 对端（修复本体）', () => {
    const req = makeReq({ trustProxy: 1, xff: '10.0.0.5', peer: '198.51.100.23', ip: '10.0.0.5' });
    expect(isClientIpIdentityTrustworthy(req)).toBe(false);
    // req.ip 是攻击者写的办公网内网地址；IP 访问范围若按它裁 ⇒ 一次请求头通过校验
    expect(clientIpForSecurityDecision(req)).toBe('198.51.100.23');
  });

  test('不可信且对端取不到时退回 req.ip，不把裁决变成空 IP', () => {
    const req = {
      app: { get: () => 1 },
      get: () => '10.0.0.5',
      socket: {},
      ip: '10.0.0.5',
    };
    expect(isClientIpIdentityTrustworthy(req)).toBe(false);
    expect(clientIpForSecurityDecision(req)).toBe('10.0.0.5');
  });

  /**
   * 可证伪性对照：这条是"修复前必红"的那一半。
   * 修前 assertIpAllowed 用 `req.ip`，本例里即 XFF 写的 10.0.0.5 —— 恰好落在
   * allowedIPs 允许的段内；修后按对端 198.51.100.23 裁 ⇒ 被拒。
   */
  test('同一伪造现场：按修复后口径 IP 范围必须判拒', () => {
    const { isIPAllowed } = require('../../utils/ipRange');
    const req = makeReq({ trustProxy: 1, xff: '10.0.0.5', peer: '198.51.100.23', ip: '10.0.0.5' });
    const allowedIPs = '10.0.0.0/8';

    expect(isIPAllowed(req.ip, allowedIPs).allowed).toBe(true); // 旧口径：伪造头即可通过
    expect(isIPAllowed(clientIpForSecurityDecision(req), allowedIPs).allowed).toBe(false); // 新口径：拒
  });

  test('再导出面不变：security.js 的豁免判定与本体同源（防两套事实来源）', () => {
    const { isWhitelistExemptionTrustworthy } = require('../../middleware/security');
    const req = makeReq({ trustProxy: 1, xff: '10.0.0.5', peer: '198.51.100.23', ip: '10.0.0.5' });
    expect(isWhitelistExemptionTrustworthy(req)).toBe(isClientIpIdentityTrustworthy(req));
    const ok = makeReq({ trustProxy: 1, xff: '10.0.0.5', peer: '10.0.0.1', ip: '10.0.0.5' });
    expect(isWhitelistExemptionTrustworthy(ok)).toBe(true);
  });
});
