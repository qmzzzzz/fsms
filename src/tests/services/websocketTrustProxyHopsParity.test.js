/**
 * trust proxy 跳数的判据必须只有一个来源
 *
 * 缺陷形态（2026-09-24 实测确认）：同一条「TRUST_PROXY_HOPS → 信任几跳」的规则
 * 写了两份——src/app.js 一份（带 MAX_TRUST_PROXY_HOPS=5 夹取），
 * src/services/websocketService.js 一份（**漏了夹取**）。
 * WS 侧把 999999 原样交给 resolveHandshakeClientIP，等价于信任整条 X-Forwarded-For，
 * 于是 allowedIPs 的握手 IP 校验按请求方自己填的地址判定 ⇒ 登录 IP 白名单在
 * 实时推送面上失效。非 production 可达：config/validate.js 的启动硬闸对
 * staging/dev 早退（用例 src/tests/app/appTrustProxyAndReadyzGuards.test.js 已钉过
 * HTTP 侧同一条），而既有 WS「一致性」用例把 hops 当入参传给
 * resolveHandshakeClientIP，从未检验 hops 是怎么来的——缺口因此隐身。
 *
 * 本文件三段：
 *  1) 纯函数真值表（钉住每一条分支，防止再被复制粘贴出第三份）
 *  2) WS 侧确实委托它（含错配留痕、每进程一次）
 *  3) 端到端安全判据：伪造 XFF 不得让人通过 allowedIPs
 */

const ORIGINAL_ENV = { ...process.env };

afterEach(() => {
  process.env = { ...ORIGINAL_ENV };
  jest.restoreAllMocks();
});

describe('resolveTrustProxyHops 真值表（src/config/validate.js 纯函数）', () => {
  const { resolveTrustProxyHops, MAX_TRUST_PROXY_HOPS } = require('../../config/validate');

  test('上限本身是 5：夹取判据来自该常量，改动需同步评审启动硬闸', () => {
    expect(MAX_TRUST_PROXY_HOPS).toBe(5);
  });

  // [raw, nodeEnv, hops, illegal, clamped]
  it.each([
    ['1', 'production', 1, false, false],
    ['2', 'production', 2, false, false],
    ['5', 'production', 5, false, false], // 等于上限：不夹取
    ['6', 'production', 5, false, true], // 刚超：夹取
    ['999999', 'staging', 5, false, true], // 实测过的取值，且 staging 无启动硬闸
    [' 3 ', 'production', 3, false, false], // 带空白仍是合法正整数，不该报非法
    ['0', 'production', 0, true, false], // 显式 0 也是「配了但不是正整数」
    ['-3', 'production', 0, true, false],
    ['abc', 'production', 0, true, false],
    ['abc', 'development', 1, true, false], // dev 退化到缺省 1 跳，不是 0
    ['1', 'development', 1, false, false],
    ['', 'production', 0, false, false], // 空串等同未配置：不该告警
    [undefined, 'production', 0, false, false], // 未配置：不信任（含生产直连）
    [undefined, 'development', 1, false, false],
  ])('raw=%s / env=%s → hops=%i, illegal=%s, clamped=%s', (raw, env, hops, illegal, clamped) => {
    const r = resolveTrustProxyHops(raw, env);
    expect(r.hops).toBe(hops);
    expect(r.illegal).toBe(illegal);
    expect(r.clamped).toBe(clamped);
  });

  test('不读 process.env：同一入参在任意环境下结论一致（可被直接钉，无需造环境）', () => {
    process.env.TRUST_PROXY_HOPS = '999999';
    expect(resolveTrustProxyHops('2', 'production').hops).toBe(2);
  });
});

describe('WS 握手侧的跳数与 HTTP 侧同源', () => {
  const loadWS = () => {
    jest.resetModules(); // config.nodeEnv 在加载期定格，必须整链重载
    return require('../../services/websocketService');
  };

  test('TRUST_PROXY_HOPS=999999（staging）→ 5 跳，而非原样透传', () => {
    process.env.NODE_ENV = 'staging';
    process.env.TRUST_PROXY_HOPS = '999999';
    expect(loadWS().resolveTrustProxyHops()).toBe(5);
  });

  test('上限边界：5 保留、6 夹取，与 HTTP 侧 appTrustProxy 用例同口径', () => {
    process.env.NODE_ENV = 'staging';
    process.env.TRUST_PROXY_HOPS = '5';
    expect(loadWS().resolveTrustProxyHops()).toBe(5);
    process.env.TRUST_PROXY_HOPS = '6';
    expect(loadWS().resolveTrustProxyHops()).toBe(5);
  });

  test('缺省分叉：development 未配置 → 1；production 未配置 → 0', () => {
    process.env.NODE_ENV = 'development';
    delete process.env.TRUST_PROXY_HOPS;
    expect(loadWS().resolveTrustProxyHops()).toBe(1);

    process.env.NODE_ENV = 'production';
    expect(loadWS().resolveTrustProxyHops()).toBe(0);
  });

  test('错配必须留痕，且每进程一次（握手是重入路径）', () => {
    process.env.NODE_ENV = 'staging';
    process.env.TRUST_PROXY_HOPS = '999999';
    jest.resetModules();
    const logger = require('../../utils/logger');
    const warnSpy = jest.spyOn(logger, 'warn').mockImplementation(() => {});
    const WS = require('../../services/websocketService');

    expect(WS.resolveTrustProxyHops()).toBe(5);
    expect(warnSpy).toHaveBeenCalledTimes(1);
    expect(String(warnSpy.mock.calls[0][0])).toContain('TRUST_PROXY_HOPS');

    WS.resolveTrustProxyHops();
    WS.resolveTrustProxyHops();
    expect(warnSpy).toHaveBeenCalledTimes(1);
  });

  test('对照：取值合法时不多说话', () => {
    process.env.NODE_ENV = 'production';
    process.env.TRUST_PROXY_HOPS = '2';
    jest.resetModules();
    const logger = require('../../utils/logger');
    const warnSpy = jest.spyOn(logger, 'warn').mockImplementation(() => {});
    const WS = require('../../services/websocketService');

    expect(WS.resolveTrustProxyHops()).toBe(2);
    expect(warnSpy).not.toHaveBeenCalled();
  });
});

describe('端到端：伪造 XFF 不得通过 allowedIPs（本用例是 999999 漏判的直接复现）', () => {
  test('白名单填 10.0.0.1 的用户，用 XFF 把自己写成 10.0.0.1 仍被拒', () => {
    process.env.NODE_ENV = 'staging'; // 该环境无启动硬闸，只有运行时夹取挡得住
    process.env.TRUST_PROXY_HOPS = '999999';
    jest.resetModules();
    const WS = require('../../services/websocketService');

    const handshake = {
      address: '127.0.0.1',
      headers: {
        'x-forwarded-for': '10.0.0.1, 10.0.0.2, 10.0.0.3, 10.0.0.4, 10.0.0.5, 10.0.0.6',
      },
    };
    // 机制自证：不夹取时判定 IP 就是攻击者填的最左段（放行），夹到 5 后右移一跳
    expect(WS.resolveHandshakeClientIP(handshake, 999999)).toBe('10.0.0.1');
    expect(WS.resolveHandshakeClientIP(handshake, 5)).toBe('10.0.0.2');

    const socket = { id: 'sock-1', handshake, emit: jest.fn(), disconnect: jest.fn() };
    const rejected = WS.prototype._assertHandshakeIpAllowed.call(null, socket, {
      username: 'finance01',
      allowedIPs: '10.0.0.1',
    });

    expect(rejected).toBe(true);
    expect(socket.disconnect).toHaveBeenCalledWith(true);
    expect(String(socket.emit.mock.calls[0][1].message)).toContain('IP');
  });
});
