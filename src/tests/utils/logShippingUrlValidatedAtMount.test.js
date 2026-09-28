/**
 * F-215：日志转发的"到底在不在跑"必须来自实际挂载，而不是环境变量的真值
 *
 * 缺陷（生产 Node 运行时实测，非推演）：`resolveShippingTarget` 原先只在**每个批次
 * 发送时**被 `_post` 调用，`logger.js` 的挂载路径上没有任何一处解析过 URL。于是
 * `LOG_SHIPPING_URL` 写错时，挂载一定成功、启动日志一定说"已启用"、而那个专门用来
 * 报挂载失败的 catch 对 URL 完全不可达。实测三个取值（捕获 winston 的 console 输出）：
 *
 *   LOG_SHIPPING_URL                     saysEnabled saysMountFailed transports
 *   https://siem.example.test/ingest     true        false           6
 *   htps://siem.example.test/ingest      true        false           6   ← 错
 *   not-a-url                            true        false           6   ← 错
 *
 * `transports` 停在 6 = 真的挂上了一个每批必死的 HttpShipperTransport：它会拉起
 * intervalMs 定时器、把整条日志流堆进 BUFFER_CAP=5000 的缓冲、堆满后裁头留断档标记，
 * 而唯一的失败信号是 `_flush` 里每分钟一条、走 console.error 且**不经过 winston**
 * （因此不进 combined-*.log）的告警。容器不采 stderr 时，这条链彻底无声。
 *
 * 同一根的第二处出口：`securityController` 的合规面板原先写
 * `shippingEnabled: !!process.env.LOG_SHIPPING_URL`。同一个对象里的邻居
 * （walEnabled / monitorRunning / monitorHealth）一律查运行态，只有它查环境变量——
 * 面板于是会把"配过一个非法字符串"显示成"日志正在送 SIEM"。
 *
 * 判据来自哪里：非法 scheme 不再静默降级成明文出站，是
 * `zzqoder_logShipperSchemeAllowlist` 那轮修的；该轮注释点名的残留
 * （"运维看到的仍是『日志转发已启用 → htps://…』"）就是本用例钉的东西。
 *
 * 替身为什么要继承 winston-transport（第一版就踩了这个坑）：
 * `logger.add()` 要求参数是 TransportStream，普通对象会让它抛 TypeError、被
 * catch 接住 ⇒ "合法 URL 也该挂上"的正向对照臂会变成在测替身形状而不是测代码。
 * 拒绝臂不受影响（它断言的是构造函数**没被调用** + 报错文案是 URL 专属的那两条），
 * 但正向臂一旦失真，整份用例就分不清"闸拦住了坏配置"和"闸把好配置也拦了"。
 */

const path = require('path');
const fs = require('fs');
const TransportStream = require('winston-transport');

const REPO_ROOT = path.join(__dirname, '..', '..', '..');

const mockTransportCtor = jest.fn(function FakeTransport(opts) {
  TransportStream.call(this, opts);
  Object.assign(this, opts);
});
mockTransportCtor.prototype = Object.create(TransportStream.prototype);
mockTransportCtor.prototype.log = function log(info, callback) {
  callback();
};

jest.mock('../../utils/logShipper', () => ({
  HttpShipperTransport: mockTransportCtor,
  // 真判据。给空壳等于把挂载期闸从这些用例里删掉。
  resolveShippingTarget: jest.requireActual('../../utils/logShipper').resolveShippingTarget,
}));

/**
 * 以给定环境变量集合**全新加载** logger，并捕获 winston 写到 stdout 的全部内容。
 * winston 的 Console transport 持有 process.stdout 对象本身、在调用点才取 .write，
 * 所以替换方法可以采到挂载期那两条 INFO/WARN。
 * 返回的 transports 数量在加载结束时读取——loadLogger 会还原 env，
 * 计数只反映这次加载真正挂上了几个 transport。
 */
const loadLogger = (env) => {
  jest.resetModules();
  mockTransportCtor.mockClear();
  const saved = {};
  for (const [k, v] of Object.entries(env)) {
    saved[k] = process.env[k];
    if (v === undefined) delete process.env[k];
    else process.env[k] = String(v);
  }
  const chunks = [];
  const realWarn = console.warn;
  const realWrite = process.stdout.write;
  console.warn = () => {};
  process.stdout.write = (c) => {
    chunks.push(String(c));
    return true;
  };
  let mod;
  let loadErr = null;
  try {
    mod = require('../../utils/logger');
  } catch (e) {
    loadErr = e;
  }
  const transportCount = mod ? mod.transports.length : -1;
  process.stdout.write = realWrite;
  console.warn = realWarn;
  for (const [k, v] of Object.entries(saved)) {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
  return { mod, out: chunks.join(''), loadErr, transports: transportCount };
};

const ENABLED = '日志转发已启用';
const MOUNT_FAILED = '日志转发 transport 挂载失败';

// 三种"配了但送不出去"的形态：不可解析 / 非 http(s) scheme / 无 host 的本地协议
const BAD_URLS = ['not-a-url', 'htps://siem.example.test/ingest', 'file:///var/log/app.log'];
const GOOD_URL = 'https://siem.example.test/ingest';

describe('F-215 ①：挂载期解析 URL——坏 URL 不得挂载、不得报"已启用"', () => {
  test.each(BAD_URLS)('坏 URL %s ⇒ 不构造 transport，报挂载失败且不报已启用', (bad) => {
    const { mod, out } = loadLogger({ LOG_SHIPPING_URL: bad, LOG_SHIPPING_TOKEN: 't' });
    expect(mod).toBeTruthy();
    // ① 构造函数压根不该被调用（更不该挂上定时器与 5000 行缓冲）
    expect(mockTransportCtor).not.toHaveBeenCalled();
    // ② 成功判据不得出现
    expect(out).not.toContain(ENABLED);
    // ③ 失败判据必须出现，且原因是"真判据"抛的那两条文案（不是 TypeError 之类的意外）
    expect(out).toContain(MOUNT_FAILED);
    expect(out).toMatch(/无效的 LOG_SHIPPING_URL|仅支持 http\/https/);
  });

  test('对照臂：合法 URL 仍然挂载并报"已启用"（挂载期闸没有顺手把好的拦掉）', () => {
    const { mod, out } = loadLogger({ LOG_SHIPPING_URL: GOOD_URL, LOG_SHIPPING_TOKEN: 't' });
    expect(mockTransportCtor).toHaveBeenCalledTimes(1);
    expect(out).toContain(ENABLED);
    expect(out).not.toContain(MOUNT_FAILED);
    expect(mod).toBeTruthy();
  });

  test('反向对照：一条都没配 ⇒ 既不构造也不报失败（"未启用"不是错误）', () => {
    const { out } = loadLogger({ LOG_SHIPPING_URL: undefined });
    expect(mockTransportCtor).not.toHaveBeenCalled();
    expect(out).not.toContain(ENABLED);
    expect(out).not.toContain(MOUNT_FAILED);
  });

  test('transport 数量：坏 URL 一个都不加，好 URL 恰好加一个', () => {
    const baseline = loadLogger({ LOG_SHIPPING_URL: undefined }).transports;
    expect(baseline).toBeGreaterThan(0);
    for (const bad of BAD_URLS) {
      expect(loadLogger({ LOG_SHIPPING_URL: bad }).transports).toBe(baseline);
    }
    expect(loadLogger({ LOG_SHIPPING_URL: GOOD_URL }).transports).toBe(baseline + 1);
  });
});

describe('F-215 ②：isShippingEnabled() 以实际挂载为准', () => {
  test('未配置 ⇒ false', () => {
    const { mod } = loadLogger({ LOG_SHIPPING_URL: undefined });
    expect(typeof mod.isShippingEnabled).toBe('function');
    expect(mod.isShippingEnabled()).toBe(false);
  });

  test('配置为坏 URL ⇒ false（这一档在修复前与"真的在送"完全无法区分）', () => {
    for (const bad of BAD_URLS) {
      const { mod } = loadLogger({ LOG_SHIPPING_URL: bad });
      expect(mod.isShippingEnabled()).toBe(false);
    }
  });

  test('配置为好 URL ⇒ true；摘掉 transport 后必须回到 false', () => {
    const { mod } = loadLogger({ LOG_SHIPPING_URL: GOOD_URL });
    expect(mod.isShippingEnabled()).toBe(true);
    const mounted = mockTransportCtor.mock.instances[mockTransportCtor.mock.instances.length - 1];
    mod.remove(mounted);
    expect(mod.transports.includes(mounted)).toBe(false);
    expect(mod.isShippingEnabled()).toBe(false);
  });

  test('判据不看 env：加载后把变量改成非法值，答案不得随之变化', () => {
    const { mod } = loadLogger({ LOG_SHIPPING_URL: GOOD_URL });
    const saved = process.env.LOG_SHIPPING_URL;
    try {
      process.env.LOG_SHIPPING_URL = 'not-a-url';
      expect(mod.isShippingEnabled()).toBe(true);
      delete process.env.LOG_SHIPPING_URL;
      expect(mod.isShippingEnabled()).toBe(true);
    } finally {
      if (saved === undefined) delete process.env.LOG_SHIPPING_URL;
      else process.env.LOG_SHIPPING_URL = saved;
    }
  });
});

describe('F-215 ③：合规面板的 shippingEnabled 不再回答"配过变量"', () => {
  const { jsCodeOnly } = require('../helpers/jsCodeOnly');
  const codeView = (rel) => jsCodeOnly(fs.readFileSync(path.join(REPO_ROOT, rel), 'utf8'));

  test('面板字段读挂载态谓词', () => {
    const view = codeView('src/controllers/securityController.js');
    const from = view.indexOf('shippingEnabled:');
    expect(from).toBeGreaterThan(-1);
    expect(view.slice(from, from + 240)).toContain('logger.isShippingEnabled(');
  });

  test('生产代码里不得再有"用 env 真值回答转发是否启用"的写法', () => {
    const BANNED = /!!\s*process\.env\.LOG_SHIPPING_URL/;
    const walk = (dir, acc = []) => {
      for (const name of fs.readdirSync(dir)) {
        const full = path.join(dir, name);
        const rel = path.relative(REPO_ROOT, full).split(path.sep).join('/');
        if (rel === 'src/tests' || rel.startsWith('src/tests/')) continue;
        if (fs.statSync(full).isDirectory()) walk(full, acc);
        else if (name.endsWith('.js')) acc.push({ rel, text: fs.readFileSync(full, 'utf8') });
      }
      return acc;
    };
    const offenders = walk('src')
      .filter(({ text }) => BANNED.test(jsCodeOnly(text)))
      .map(({ rel }) => rel);
    expect(offenders).toEqual([]);
  });

  test('自检：上面那条判据真的能识别被禁写法、且不被注释欺骗（否则它是个假闸）', () => {
    const BANNED = /!!\s*process\.env\.LOG_SHIPPING_URL/;
    const stripped = (src) => BANNED.test(jsCodeOnly(src));
    expect(stripped('const a = !!process.env.LOG_SHIPPING_URL;\n')).toBe(true);
    expect(stripped('const a = logger.isShippingEnabled();\n')).toBe(false);
    // 行注释与块注释里的反例都不该让闸变绿，也不该让它变红
    expect(stripped('// const a = !!process.env.LOG_SHIPPING_URL;\nconst b = 1;\n')).toBe(false);
    expect(stripped('/* const a = !!process.env.LOG_SHIPPING_URL; */\nconst b = 1;\n')).toBe(false);
    // 而 logger.js 里"是否配置过"的合法读取不能被误判成违规
    expect(
      stripped('const shippingUrl = process.env.LOG_SHIPPING_URL;\nif (shippingUrl) {}\n')
    ).toBe(false);
  });
});
