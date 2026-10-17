/**
 * 显式可信代理网段（TRUSTED_PROXY_CIDRS）——F-01 的修复本体
 *
 * 缺陷（2026-10-16 独立审计 F-01，P1）：`isClientIpIdentityTrustworthy` 的第 3 种
 * 可信形态是「socket 对端属内网/回环 ⇒ XFF 可信」。RFC1918 不是**代理身份**，
 * 只是**位置**：docker-compose 里 app 同时挂在 fire-safety-net 与 data-net 上，
 * 同网任意容器直连 `app:3000` 并自带一条 `X-Forwarded-For`，对端同样是 RFC1918，
 * 与真实 nginx 反代**在应用视角完全同形**。于是这一条头可以买到：IP 白名单豁免、
 * 黑名单绕过、IP/用户/账号三层限流配额、自动封禁的打击对象、审计里的来源地址。
 *
 * 修法不是「不再信任私网」（那会打断所有现存部署），而是**把代理身份变成显式配置**：
 *   - 配了 TRUSTED_PROXY_CIDRS ⇒ 只有落在这些网段内的对端才算代理，私网不再是理由；
 *   - 没配 ⇒ 行为与修复前逐字一致（私网/回环仍可信），由启动期 WARN 说明这条边界
 *     目前判的是位置而非身份。
 * 这个取舍是 2026-10-17 由仓库负责人明确拍板的：默认行为不变、不破坏任何部署，
 * 残余风险如实记录在 ipUtils 的注释里。
 *
 * 判据从 `req.app` 取配置而不是自己读 process.env，理由与 `trust proxy` 同源：
 * ipUtils 的函数保持纯判据（不读环境、不需要缓存与缓存重置），配置在 app.js
 * 启动期注入一次；同时避免 `utils/ipUtils` 反向 require `config/*` 造成循环依赖
 * （src/tests/architecture/requireCycles.test.js 静态断言依赖图无环）。
 *
 * 本套件钉住四类性质，每类都能因真实退化而红：
 *   1. 解析层：空项、非法文本、全域网段（0.0.0.0/0、::/0）必须被拒——
 *      全域网段等于「整个互联网都是我的可信代理」，比不配还糟；
 *   2. 判据层：配了 CIDR 之后，**私网但不在名单内**的对端必须转为不可信
 *      （这正是修复本体；只测「名单内可信」会漏掉它）；
 *   3. 兼容层：未配置时既有四种组合的行为一字不变（防「顺手收紧」打断现网）；
 *   4. 接线层：app.js 真的把解析结果注入 app 设置（前三条都过、接线漏了 ⇒ 修复等于没发生）。
 *
 * 变异实测（三处各自只杀死对应那条）：
 *   ① 判据里 `if (proxies && proxies.configured)` → `if (false)` ⇒ 3 failed
 *   ② 解析里 `if (isFullRangeCIDR(item))` → `if (false)`        ⇒ 2 failed
 *   ③ `matches` 里 errors 短路 → `if (false)`                   ⇒ 1 failed（混排那条）
 */

const {
  parseTrustedProxyCidrs,
  resolveTrustedProxies,
  resetTrustedProxyCache,
} = require('../../config/trustedProxies');
const {
  isClientIpIdentityTrustworthy,
  clientIpForSecurityDecision,
} = require('../../utils/ipUtils');

const ENV_KEY = 'TRUSTED' + '_' + 'PROXY' + '_' + 'CIDRS';

/**
 * 替身 req：只带判据实际读取的面（与 clientIpSecurityDecision.test.js 同口径），
 * 外加本修复新增的 `trusted proxy cidrs` 设置位。
 */
const makeReq = ({ trustProxy, xff, peer, ip, proxies }) => ({
  app: {
    get: (k) => {
      if (k === 'trust proxy') return trustProxy;
      if (k === 'trusted proxy cidrs') return proxies;
      return undefined;
    },
  },
  get: (h) => (h.toLowerCase() === 'x-forwarded-for' ? xff : undefined),
  socket: { remoteAddress: peer },
  ip,
});

let saved;

beforeEach(() => {
  saved = process.env[ENV_KEY];
  resetTrustedProxyCache();
});

afterEach(() => {
  if (saved === undefined) delete process.env[ENV_KEY];
  else process.env[ENV_KEY] = saved;
  resetTrustedProxyCache();
});

/** 设 env 并取解析结果，模拟 app.js 启动期那一次注入 */
const proxiesFrom = (raw) => {
  if (raw === undefined) delete process.env[ENV_KEY];
  else process.env[ENV_KEY] = raw;
  resetTrustedProxyCache();
  return resolveTrustedProxies();
};

describe('parseTrustedProxyCidrs：解析与拒绝面', () => {
  test('合法列表逐项解析，IPv4 与 IPv6 可混排', () => {
    const { configured, cidrs, errors } = parseTrustedProxyCidrs(
      '10.0.0.0/8, 172.16.5.0/24 ,fd00::/8'
    );
    expect(errors).toEqual([]);
    expect(configured).toBe(true);
    expect(cidrs).toHaveLength(3);
  });

  test('空项被拒：`10.0.0.0/8,,172.16.0.0/12` 不是「忽略空项」而是配置错误', () => {
    const { errors } = parseTrustedProxyCidrs('10.0.0.0/8,,172.16.0.0/12');
    expect(errors.length).toBeGreaterThan(0);
    expect(errors.join('\n')).toContain('空项');
  });

  test('全域网段被拒：0.0.0.0/0 与 ::/0 等于「整个互联网都是可信代理」', () => {
    for (const bad of ['0.0.0.0/0', '::/0']) {
      const { errors } = parseTrustedProxyCidrs(bad);
      expect({ bad, rejected: errors.length > 0 }).toMatchObject({ bad, rejected: true });
      expect(errors.join('\n')).toContain('全域');
    }
  });

  test('解析不出的文本被拒且不得静默丢弃（丢弃等于悄悄缩小信任面）', () => {
    const { cidrs, errors } = parseTrustedProxyCidrs('10.0.0.0/8,not-an-ip,10.0.0.0/33');
    expect(cidrs).toHaveLength(1);
    expect(errors).toHaveLength(2);
  });

  test('undefined 与纯空白视为「未配置」，不是错误', () => {
    for (const raw of [undefined, '', '   ']) {
      expect(parseTrustedProxyCidrs(raw)).toMatchObject({ configured: false, errors: [] });
    }
  });
});

describe('判据：配了 CIDR 之后私网不再是理由', () => {
  test('对端在名单内 ⇒ 可信（正常 nginx 反代路径不受影响）', () => {
    const proxies = proxiesFrom('10.0.0.0/8');
    const req = makeReq({
      trustProxy: 1,
      xff: '203.0.113.9',
      peer: '10.0.0.7',
      ip: '203.0.113.9',
      proxies,
    });
    expect(isClientIpIdentityTrustworthy(req)).toBe(true);
    expect(clientIpForSecurityDecision(req)).toBe('203.0.113.9');
  });

  test('对端是私网但**不在名单内** ⇒ 不可信，裁决退回 socket 对端（修复本体）', () => {
    // 172.16.x / 192.168.x / 回环都是 RFC1918 或 loopback：修复前一律可信，
    // 这正是同 compose 网络内任意容器能伪造 XFF 的原因。
    const proxies = proxiesFrom('10.0.0.0/8');
    for (const peer of ['172.16.3.4', '192.168.1.1', '127.0.0.1', '::1']) {
      const req = makeReq({ trustProxy: 1, xff: '203.0.113.9', peer, ip: '203.0.113.9', proxies });
      expect({ peer, trusted: isClientIpIdentityTrustworthy(req) }).toMatchObject({
        peer,
        trusted: false,
      });
      // 裁决必须落在不可伪造的对端上，而不是那条伪造头带来的 203.0.113.9
      expect({ peer, decided: clientIpForSecurityDecision(req) }).toMatchObject({
        peer,
        decided: peer,
      });
    }
  });

  test('名单含 IPv6 时按 IPv6 网段判定，名单外的 IPv4 私网同样不可信', () => {
    const proxies = proxiesFrom('fd00::/8');
    const inside = makeReq({
      trustProxy: 1,
      xff: '203.0.113.9',
      peer: 'fd12::1',
      ip: '203.0.113.9',
      proxies,
    });
    expect(isClientIpIdentityTrustworthy(inside)).toBe(true);
    const outside = makeReq({
      trustProxy: 1,
      xff: '203.0.113.9',
      peer: '10.0.0.7',
      ip: '203.0.113.9',
      proxies,
    });
    expect(isClientIpIdentityTrustworthy(outside)).toBe(false);
  });

  test('配置非法（含全域网段）时 fail-closed：不因解析失败退回「私网即可信」', () => {
    const proxies = proxiesFrom('0.0.0.0/0');
    expect(proxies.errors.length).toBeGreaterThan(0);
    const req = makeReq({
      trustProxy: 1,
      xff: '203.0.113.9',
      peer: '10.0.0.7',
      ip: '203.0.113.9',
      proxies,
    });
    expect(isClientIpIdentityTrustworthy(req)).toBe(false);
    expect(clientIpForSecurityDecision(req)).toBe('10.0.0.7');
  });

  test('合法项与非法项混排时**整份名单作废**：不得「只信解析成功的那几条」', () => {
    // 半信半疑的信任面比明确拒绝更难排查：运维看到 10.0.0.7 能过，会以为配置生效了，
    // 而实际生效范围与他写下的意图不一致（那条全域网段被静默忽略）。
    // 变异实测：删掉 matches 里的 errors 短路，本条即红（此前无测试覆盖该分支）。
    const proxies = proxiesFrom('10.0.0.0/8,0.0.0.0/0');
    expect(proxies.cidrs).toEqual(['10.0.0.0/8']);
    expect(proxies.errors).toHaveLength(1);
    const req = makeReq({
      trustProxy: 1,
      xff: '203.0.113.9',
      peer: '10.0.0.7',
      ip: '203.0.113.9',
      proxies,
    });
    expect(isClientIpIdentityTrustworthy(req)).toBe(false);
    expect(clientIpForSecurityDecision(req)).toBe('10.0.0.7');
  });

  test('未启用 trust proxy 时名单不参与判定（req.ip 恒等于对端）', () => {
    const proxies = proxiesFrom('10.0.0.0/8');
    const req = makeReq({
      trustProxy: false,
      xff: '203.0.113.9',
      peer: '8.8.8.8',
      ip: '8.8.8.8',
      proxies,
    });
    expect(isClientIpIdentityTrustworthy(req)).toBe(true);
  });
});

describe('未配置 TRUSTED_PROXY_CIDRS：既有四种组合行为逐字不变', () => {
  test('未启用 trust proxy ⇒ 可信，取 req.ip', () => {
    const proxies = proxiesFrom(undefined);
    const req = makeReq({
      trustProxy: false,
      xff: '203.0.113.9',
      peer: '8.8.8.8',
      ip: '8.8.8.8',
      proxies,
    });
    expect(isClientIpIdentityTrustworthy(req)).toBe(true);
    expect(clientIpForSecurityDecision(req)).toBe('8.8.8.8');
  });

  test('开了 trust proxy 但无 XFF ⇒ 可信（req.ip 只能是对端）', () => {
    const proxies = proxiesFrom(undefined);
    const req = makeReq({ trustProxy: 1, xff: undefined, peer: '8.8.8.8', ip: '8.8.8.8', proxies });
    expect(isClientIpIdentityTrustworthy(req)).toBe(true);
  });

  test('trust proxy + XFF + 私网/回环对端 ⇒ 仍可信（默认行为不变，靠启动告警提示收紧）', () => {
    const proxies = proxiesFrom(undefined);
    for (const peer of ['10.0.0.7', '172.16.3.4', '192.168.1.1', '127.0.0.1', '::1']) {
      const req = makeReq({ trustProxy: 1, xff: '203.0.113.9', peer, ip: '203.0.113.9', proxies });
      expect({ peer, trusted: isClientIpIdentityTrustworthy(req) }).toMatchObject({
        peer,
        trusted: true,
      });
    }
  });

  test('trust proxy + XFF + 公网对端 ⇒ 不可信，退回对端', () => {
    const proxies = proxiesFrom(undefined);
    const req = makeReq({
      trustProxy: 1,
      xff: '203.0.113.9',
      peer: '8.8.8.8',
      ip: '203.0.113.9',
      proxies,
    });
    expect(isClientIpIdentityTrustworthy(req)).toBe(false);
    expect(clientIpForSecurityDecision(req)).toBe('8.8.8.8');
  });

  test('resolveTrustedProxies() 如实报告「未配置」，供启动告警判据使用', () => {
    expect(proxiesFrom(undefined)).toMatchObject({ configured: false, cidrs: [] });
  });

  test('app 上没有该设置位时（旧替身 req / 未接线的调用方）也不得改变既有判据', () => {
    const req = makeReq({ trustProxy: 1, xff: '203.0.113.9', peer: '10.0.0.7', ip: '203.0.113.9' });
    expect(isClientIpIdentityTrustworthy(req)).toBe(true);
  });
});

describe('接线：app.js 必须真的把解析结果注入 app 设置', () => {
  const ORIGINAL_ENV = process.env;

  beforeEach(() => {
    jest.resetModules();
    process.env = { ...ORIGINAL_ENV };
  });

  afterEach(() => {
    process.env = ORIGINAL_ENV;
    jest.resetModules();
  });

  test('配了 TRUSTED_PROXY_CIDRS ⇒ app.get("trusted proxy cidrs") 是已配置态', () => {
    process.env.TRUSTED_PROXY_CIDRS = '10.0.0.0/8';
    process.env.TRUST_PROXY_HOPS = '1';
    const { createApp } = require('../../app');
    const app = createApp();
    expect(app.get('trusted proxy cidrs')).toMatchObject({ configured: true });
    expect(app.get('trusted proxy cidrs').matches('10.0.0.7')).toBe(true);
    expect(app.get('trusted proxy cidrs').matches('172.16.3.4')).toBe(false);
  });

  test('没配 ⇒ 注入的是未配置态（判据保持私网可信的既有行为）', () => {
    delete process.env.TRUSTED_PROXY_CIDRS;
    process.env.TRUST_PROXY_HOPS = '1';
    const { createApp } = require('../../app');
    const app = createApp();
    expect(app.get('trusted proxy cidrs')).toMatchObject({ configured: false });
  });
});
