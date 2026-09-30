/**
 * 日志转发 transport 的出站协议白名单
 *
 * 缺陷（在**生产运行时**实测，非推演）：`_post` 原先写
 *   const lib = parsed.protocol === 'https:' ? https : http;
 * 也就是"凡不是 https 就按 http 发"。任何拼错的 scheme 都不会报错，而是把整批日志
 * 连同 `Authorization: Bearer <LOG_SHIPPING_TOKEN>` 以明文送到同一个 host。
 * `node -e` 实测（Node 24 的 WHATWG URL 对非特殊协议照样解析 host/port）：
 *   htps://siem.internal:9999/logs → protocol='htps:' host='siem.internal' port='9999'
 *   shttps://siem.internal:9999/logs → 同上
 *   htp://169.254.169.254/latest/meta-data → host 原样保留
 *   file:///var/log/app.log → host='' ⇒ Node 回落 localhost:80
 * ⇒ 三种拼法在旧代码里都会真的发出去，而运维看到的仍是启动日志那句
 *   "日志转发已启用 → htps://…"，降级本身零信号。
 *
 * 判据用 **spy http/https.request**，不用真端口：
 *  - 与 jest 沙箱里 URL 实现的差异无关（该沙箱对"非特殊协议 + 显式端口"更严，
 *    会直接判 Invalid URL；生产 Node 不会——所以断言只用两侧都解析得了的形态，
 *    带端口的真实危害写在本注释里作为实测记录）；
 *  - 且能精确断言"旧代码会拿 http 模块打到哪个 host:port"，
 *    而不是只能观察"没有命中"。
 * logShipper 在调用点才取 `lib.request`，故对同一模块对象的 spy 生效。
 */

const http = require('http');
const https = require('https');

let httpSpy;
let httpsSpy;
let consoleSpies;

// 传输层的告警走 console（挂载期 logger 正在加载），本用例静音并留副本备查
beforeAll(() => {
  consoleSpies = [
    jest.spyOn(console, 'warn').mockImplementation(() => {}),
    jest.spyOn(console, 'error').mockImplementation(() => {}),
  ];
});

afterAll(() => {
  consoleSpies.forEach((s) => s.mockRestore());
  if (httpSpy) httpSpy.mockRestore();
  if (httpsSpy) httpsSpy.mockRestore();
});

beforeEach(() => {
  httpSpy = jest.spyOn(http, 'request').mockImplementation(() => {
    throw new Error('SENTINEL_REQUEST_ATTEMPTED');
  });
  httpsSpy = jest.spyOn(https, 'request').mockImplementation(() => {
    throw new Error('SENTINEL_REQUEST_ATTEMPTED');
  });
});

// 必须每条用例后摘掉：jest.spyOn 对"已被 spy 的方法"再 spy 一次时，
// 拿到的是同一个 mock 并继续累计 calls ⇒ 下一条用例的 toHaveBeenCalledTimes(0)
// 会读到上一条的调用（实测首轮就是这样红了 7 条）。
afterEach(() => {
  httpSpy.mockRestore();
  httpsSpy.mockRestore();
});

const { HttpShipperTransport } = require('../utils/logShipper');

function makeTransport(url, token = 'ZZSENTINEL_TOKEN') {
  return new HttpShipperTransport({
    url,
    token,
    batchSize: 5,
    intervalMs: 600000, // 定时器不参与，只手动 _post
    timeoutMs: 1500,
  });
}

/** _post 的 settle 结果统一成 {err} / {ok}，便于断言"有没有打出去" */
async function tryPost(url) {
  const t = makeTransport(url);
  try {
    await t._post(['line-1']);
    return { ok: true };
  } catch (e) {
    return { err: e };
  } finally {
    t.close();
  }
}

describe('日志转发只允许 http/https 出站，拼错的 scheme 必须零投递', () => {
  test('前提自证：spy 装在了 transport 真正使用的那两个模块对象上', async () => {
    // 放行对照（http）必须撞进 spy —— 否则后面所有"spy 没被调用"的断言都是空转
    const t = makeTransport('http://siem.internal/logs');
    // 我们的 spy 抛错 ⇒ _post 会以该错 settle（证明 request 真的被调用过）
    const err = await t._post(['line-1']).then(
      () => null,
      (e) => e
    );
    t.close();
    expect(httpSpy).toHaveBeenCalledTimes(1);
    expect(err && err.message).toMatch(/SENTINEL_REQUEST_ATTEMPTED|request/i);
  });

  test('http 对照按 host/port/path 正确建请求，并携带 Bearer 令牌', async () => {
    const t = makeTransport('http://siem.internal:8080/logs');
    await t._post(['line-1']).catch(() => {});
    t.close();
    const [options, callback] = httpSpy.mock.calls[0];
    expect(typeof options).toBe('object');
    // port 是**字符串**：来自 `parsed.port || (https?443:80)`，显式端口取 URL.port，
    // 缺省端口才是数字。两种类型 Node 都接受，这里如实钉住现状（不是判据，是别把它改糊）。
    expect(options).toMatchObject({ method: 'POST', host: 'siem.internal', port: '8080' });
    expect(options.path).toBe('/logs');
    expect(options.headers.Authorization).toBe('Bearer ZZSENTINEL_TOKEN');
    expect(typeof callback).toBe('function');
  });

  test('https 对照走 https 模块（白名单不得把加密路径也一起掐掉）', async () => {
    const t = makeTransport('https://siem.internal/logs');
    await t._post(['line-1']).catch(() => {});
    t.close();
    expect(httpsSpy).toHaveBeenCalledTimes(1);
    expect(httpSpy).not.toHaveBeenCalled();
    expect(httpsSpy.mock.calls[0][0]).toMatchObject({ host: 'siem.internal', port: 443 });
  });

  // ---- 缺陷本体：以下每一种都必须"一个字节都不出站" ----
  const REJECTED = [
    ['少一个字母的 https（htps:）', 'htps://siem.internal/logs'],
    ['多一个字母的 https（shttps:）', 'shttps://siem.internal/logs'],
    ['云元数据地址配上错拼 scheme', 'htp://169.254.169.254/latest/meta-data'],
    ['gopher:（旧代码会用 http 打到 169.254.169.254:80）', 'gopher://10.0.0.5/logs'],
    ['file:（host 为空 ⇒ 旧代码回落 localhost:80）', 'file:///var/log/app.log'],
    ['javascript:', 'javascript:siem.internal'],
  ];

  test.each(REJECTED)('%s → 拒绝，且 http/https 两个模块都没有被调用', async (_label, url) => {
    const { err } = await tryPost(url);
    expect(err).toBeDefined();
    expect(err.message).toMatch(/仅支持 http\/https/);
    expect(httpSpy).not.toHaveBeenCalled();
    expect(httpsSpy).not.toHaveBeenCalled();
  });

  test('拒绝文案带上实际收到的 scheme（运维要一眼看出是拼错而不是网络问题）', async () => {
    const { err } = await tryPost('htps://siem.internal/logs');
    expect(err.message).toContain('htps:');
  });

  test('非法 URL 仍报"无效的 LOG_SHIPPING_URL"（既有契约不得被新分支吃掉）', async () => {
    const { err } = await tryPost('not-a-valid-url');
    expect(err.message).toMatch(/无效的 LOG_SHIPPING_URL/);
    expect(httpSpy).not.toHaveBeenCalled();
  });

  test('大写协议（HTtP://）由 WHATWG 归一为 http: 后照常放行', async () => {
    const t = makeTransport('HTtP://siem.internal/logs');
    await t._post(['line-1']).catch(() => {});
    t.close();
    expect(httpSpy).toHaveBeenCalledTimes(1);
  });

  test('取数有效：拒绝清单非空，放行与拒绝两侧都有断言（防空集恒绿）', () => {
    expect(REJECTED.length).toBeGreaterThanOrEqual(5);
  });
});

describe('出站目标门禁：私网/回环/元数据目标零投递（P2-⑨）', () => {
  // scheme 合法、目标危险——这正是 scheme 白名单管不到的那一半
  const PRIVATE_TARGETS = [
    'http://169.254.169.254/latest/meta-data', // 云元数据端点（链路本地，经典 SSRF 目标）
    'https://10.1.2.3/logs', // RFC1918
    'http://192.168.1.1/logs',
    'https://172.16.0.9/logs',
    'http://127.0.0.1:9200/_bulk', // IPv4 回环
    'https://[::1]:9200/_bulk', // IPv6 回环
    'http://[::ffff:127.0.0.1]/logs', // IPv4-mapped 形态的回环
    'https://[fc00::1]/logs', // IPv6 uniqueLocal
  ];

  test.each(PRIVATE_TARGETS)('%s ⇒ 拒绝且零投递', async (url) => {
    const { err } = await tryPost(url);
    expect({ url, rejected: Boolean(err) }).toEqual({ url, rejected: true });
    expect(err.message).toContain('LOG_SHIPPING_ALLOW_PRIVATE_HOSTS');
    expect({ url, http: httpSpy.mock.calls.length, https: httpsSpy.mock.calls.length }).toEqual({
      url,
      http: 0,
      https: 0,
    });
  });

  test.each([
    '127.1', // 歧义点分：OS 仍按 127.0.0.1 连
    '2130706433', // 整数形态的回环
    '0x7f.0.0.1', // 十六进制形态
  ])('歧义 IPv4 形态 %s 同样拒绝（严格解析判 null 不得成为旁路）', async (host) => {
    const { err } = await tryPost(`http://${host}/logs`);
    expect(err).toBeTruthy();
    expect(httpSpy).not.toHaveBeenCalled();
  });

  /** 门禁放行的信号：_post 真正发起请求（撞上 spy 的哨兵抛错），而非被门禁拦下 */
  const gatePassed = (err) => err && err.message === 'SENTINEL_REQUEST_ATTEMPTED';

  test('公网目标不受影响（http/https 两个协议都放行）', async () => {
    expect(gatePassed((await tryPost('http://siem.example.com/logs')).err)).toBe(true);
    expect(gatePassed((await tryPost('https://siem.example.com/logs')).err)).toBe(true);
    expect(httpSpy).toHaveBeenCalledTimes(1);
    expect(httpsSpy).toHaveBeenCalledTimes(1);
  });

  test('allowlist 显式放行内网 SIEM：精确主机名 / IP / 网段三种条目形态', async () => {
    const cases = [
      ['http://169.254.169.254/latest/meta-data', '169.254.169.254'],
      ['https://10.1.2.3/logs', 'siem.corp, 10.1.2.3'],
      ['http://10.9.9.9/logs', '10.0.0.0/8'],
    ];
    for (const [url, allow] of cases) {
      process.env.LOG_SHIPPING_ALLOW_PRIVATE_HOSTS = allow;
      try {
        const { err } = await tryPost(url);
        expect({ url, allow, gatePassed: gatePassed(err) }).toEqual({
          url,
          allow,
          gatePassed: true,
        });
      } finally {
        delete process.env.LOG_SHIPPING_ALLOW_PRIVATE_HOSTS;
      }
    }
    // 全部都打到了对应目标（spy 计数 = 3 证明真的发起而非静默吞掉）
    expect(httpSpy.mock.calls.length + httpsSpy.mock.calls.length).toBe(3);
  });

  test('allowlist 精确匹配才放行：同网段的其他私网地址仍被拒', async () => {
    process.env.LOG_SHIPPING_ALLOW_PRIVATE_HOSTS = '10.1.2.3';
    try {
      const { err } = await tryPost('https://10.1.2.99/logs');
      expect(err).toBeTruthy();
      expect(httpsSpy).not.toHaveBeenCalled();
    } finally {
      delete process.env.LOG_SHIPPING_ALLOW_PRIVATE_HOSTS;
    }
  });
});
