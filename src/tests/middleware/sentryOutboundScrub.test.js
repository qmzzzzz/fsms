/**
 * F-180：Sentry 出网事件不得携带凭据/身份
 *
 * 判据口径（与 src/middleware/sentry.js 的头注释一致）：不看 beforeSend 的入参，
 * 只看**真的写进 transport 的字节**。此前踩过的两个坑都已收口：
 *  1) 用 `defaultIntegrations:false` 会把负责写 event.request 的 RequestData 集成一起关掉
 *     ⇒ 事件里没有 request 字段，"没检测到泄漏"其实是探测器坏了（实测：三臂全 clean 的假绿）。
 *     所以这里显式只装 RequestData，并**先断言探测器能看到泄漏**（臂 0）。
 *  2) 事件对象上的 `sdkProcessingMetadata.request` 是未裁剪的原始 req，但 SDK 序列化前会剥掉，
 *     按它判泄漏会得出"修不住"的错结论。所以只认 transport 截获的 envelope。
 *  3) 第一版收口是"黑名单逐个删已知字段名"，跑变异时才被暴露：`include.request` 里放一个 SDK
 *     不认识的键名（'user'）会走 extractRequestData 的 default 分支，把 `req.user` 整个原样抄进
 *     `event.request.user` ⇒ 黑名单永远追不上字段名。现在咽喉改成保留白名单制，
 *     臂4/臂5 就是这条通道的"能泄漏 / 已被削"对照（变异 M3 实测把它逼出来的）。
 */
const fs = require('fs');
const path = require('path');
const { EventEmitter } = require('events');
const Sentry = require('@sentry/node');
const sentryModule = require('../../middleware/sentry');

const { scrubOutboundEvent, SENTRY_REQUEST_INCLUDE, SENTRY_ALLOWED_REQUEST_FIELDS } = sentryModule;

// 即便 transport 被绕过，DSN 也只指向本机一个没人监听的端口
const FAKE_DSN = 'http://aaa@127.0.0.1:1/1';

/**
 * `channels` 是"这条凭据能从哪几格出去"的通道名，与 @sentry/utils 的采集分支一一对应：
 *  - body/headers/cookies/query 走 `case 'data'|'headers'|'cookies'|'query_string'`（query 含 url 里那份）；
 *  - user 走 `include.user`（默认表，只抠 DEFAULT_USER_INCLUDES 命中的键）；
 *  - requestUser 走 extractRequestData 的 `default:` 分支：白名单里出现它不认识的键名时，
 *    它把 `req` 上的同名属性**整个原样抄进 event.request**。sessionId 只存在于 req.user，
 *    所以它是这条通道独有的判别标记（user 通道抠不出它）⇒ 拿它钉"咽喉只不只认自己的保留白名单"。
 * 一个标记可以有多条通道（email 既可能来自 user、也可能随原始 req.user 整块出去），
 * 所以判据是"任一开放通道在场 ⇒ 该标记必须在场"，缺一条通道就红。
 */
const MARKERS = [
  { label: '登录口令', token: 'P@ssw0rd!Xy', channels: ['body'] },
  { label: 'MFA 码', token: 'MFA_9f3c_secret', channels: ['body'] },
  { label: 'Bearer 令牌', token: 'BEARER_7ab1_secret', channels: ['headers'] },
  { label: '会话 cookie 值', token: 'SIDCOOKIE_4d2e_secret', channels: ['cookies'] },
  { label: '查询串里的重置令牌', token: 'RESETTOKEN_8c5f_secret', channels: ['query'] },
  {
    label: '邮箱（身份）',
    token: 'probe-identity@example.test',
    channels: ['user', 'requestUser'],
  },
  { label: '会话 sessionId（原始 req.user 直拷）', token: 'SID_3e7b', channels: ['requestUser'] },
];

const mkReq = () => ({
  method: 'POST',
  url: '/api/auth/login?next=/home&token=RESETTOKEN_8c5f_secret',
  originalUrl: '/api/auth/login?next=/home&token=RESETTOKEN_8c5f_secret',
  baseUrl: '',
  path: '/api/auth/login',
  headers: {
    authorization: 'Bearer BEARER_7ab1_secret',
    cookie: 'sid=SIDCOOKIE_4d2e_secret',
    'content-type': 'application/json',
  },
  body: { username: 'admin', password: 'P@ssw0rd!Xy', mfaCode: 'MFA_9f3c_secret' },
  ip: '203.0.113.9',
  socket: { remoteAddress: { address: '10.0.0.1', port: 43210 } },
  // auth.js buildAuthContext 的真实形状（userId 而非 id）
  user: {
    userId: 'U1',
    username: 'admin',
    email: 'probe-identity@example.test',
    realName: '张三',
    sessionId: 'SID_3e7b',
  },
  getHeader(name) {
    return this.headers[String(name).toLowerCase()];
  },
});

const mkRes = () => {
  const res = new EventEmitter();
  res.statusCode = 200;
  res.setHeader = () => {};
  res.getHeader = () => undefined;
  return res;
};

/**
 * 跑一条臂：init → 过 handler → captureException → 截获真正出网的 envelope
 * @returns {Promise<{bytes: string, event: object, frameCount: number}>}
 */
const runArm = async ({ handlerFactory, beforeSend }) => {
  const frames = [];
  Sentry.init({
    dsn: FAKE_DSN,
    environment: 'test',
    tracesSampleRate: 0,
    autoSessionTracking: false,
    defaultIntegrations: false,
    // 只装这一个集成：它就是往 event.request 写字段的那个组件（生产里它在默认表里）
    integrations: [new Sentry.Integrations.RequestData()],
    beforeSend: beforeSend || ((event) => event),
    transport: () => ({
      send: (request) => {
        // 实测本版本直接把 envelope 元组传给 send（不是 {body: envelope}）；两种形状都接住，
        // 但下面会断言"解析得出的是 event 帧"，形状变了就报错而不是静默假绿
        const envelope =
          request && typeof request === 'object' && 'body' in request ? request.body : request;
        frames.push(JSON.stringify(envelope));
        return Promise.resolve({ reason: 'sent' });
      },
      flush: () => Promise.resolve(true),
    }),
  });

  const handler = handlerFactory();
  handler(mkReq(), mkRes(), () => {
    Sentry.captureException(new Error('boom-5xx'));
  });

  const deadline = Date.now() + 4000;
  while (frames.length === 0) {
    if (Date.now() > deadline) throw new Error('探测器失效：4s 内 transport 没有收到任何 envelope');
    await new Promise((r) => setTimeout(r, 20));
  }
  await Sentry.close(1000);

  const bytes = frames.join('\n');
  const envelope = JSON.parse(frames[0]);
  const [itemHeader, itemPayload] = envelope[1][0];
  if (itemHeader.type !== 'event') {
    throw new Error(`探测器形状已变：首帧 item type = ${String(itemHeader.type)}`);
  }
  return { bytes, event: typeof itemPayload === 'string' ? JSON.parse(itemPayload) : itemPayload };
};

/**
 * 臂＝"两层收口各自开关"的矩阵，而不是一臂一情形。`open` 声明这条臂上还开着哪些泄漏通道，
 * 用例据此推导每个标记该不该出现（不是逐臂手写断言，加一个通道就会到处漏钉）。
 *  - 'query' 在只留白名单的臂上仍然开着：白名单里保留了 'url'，而它由 req.originalUrl 拼成，
 *    天然带查询串 ⇒ 这一格只有 beforeSend 能削，是"两层缺一不可"的实测依据。
 *  - 'requestUser' 只在臂4/臂5 上场：臂5 证明这条通道真的能出网（探测器对照），
 *    臂4 证明咽喉只认自己的保留白名单、采集侧被人加了键也带不出去。
 */
/** 被人"顺手加一个字段"的采集白名单：'user' 不在 SDK 的 case 表里 ⇒ 走 default 分支原样抄 req.user */
const tamperedInclude = () =>
  Sentry.Handlers.requestHandler({ include: { request: ['method', 'url', 'user'], user: false } });

const ARMS = [
  {
    name: '臂0 修复前形态：无参 requestHandler + 无 beforeSend',
    handlerFactory: () => Sentry.Handlers.requestHandler(),
    beforeSend: undefined,
    isControl: true,
    open: ['body', 'headers', 'cookies', 'query', 'user'],
  },
  {
    name: '臂1 本模块真实装配：采集白名单 + beforeSend 两层',
    handlerFactory: () => sentryModule.sentryRequestHandler(),
    beforeSend: scrubOutboundEvent,
    open: [],
  },
  {
    name: '臂2 只剩 beforeSend（有人把 handler 改回无参）',
    handlerFactory: () => Sentry.Handlers.requestHandler(),
    beforeSend: scrubOutboundEvent,
    open: [],
  },
  {
    name: '臂3 只剩采集白名单（beforeSend 被摘掉）',
    handlerFactory: () => sentryModule.sentryRequestHandler(),
    beforeSend: undefined,
    open: ['query'],
  },
  {
    name: '臂4 采集白名单被人加了 user + beforeSend 在场（咽喉必须自己兜住）',
    handlerFactory: tamperedInclude,
    beforeSend: scrubOutboundEvent,
    open: [],
  },
  {
    name: '臂5 采集白名单被人加了 user、beforeSend 被摘（新通道的探测器有效性对照）',
    handlerFactory: tamperedInclude,
    beforeSend: undefined,
    open: ['query', 'requestUser'],
  },
];

/**
 * 每条开放通道"该在事件哪儿看到什么"的探测器判据。对照臂（isControl）逐条过一遍：
 * 通道声明开着却看不到证据 ⇒ 报错，而不是静默全绿——这是本套件唯一能证明
 * "没检测到泄漏 = 真没泄漏"而不是"探测方式坏了"的地方（已被这条坑过一次，见文件头）。
 */
const CHANNEL_PROOF = {
  body: (event) => expect(event.request.data).toContain('P@ssw0rd!Xy'),
  headers: (event) => expect(event.request.headers.authorization).toContain('BEARER_7ab1_secret'),
  cookies: (event) => expect(event.request.cookies.sid).toBe('SIDCOOKIE_4d2e_secret'),
  query: (event) =>
    expect(`${event.request.query_string || ''}|${event.request.url || ''}`).toContain(
      'RESETTOKEN_8c5f_secret'
    ),
  user: (event) =>
    expect(event.user).toMatchObject({ username: 'admin', email: 'probe-identity@example.test' }),
  requestUser: (event) =>
    expect(event.request.user).toMatchObject({
      userId: 'U1',
      sessionId: 'SID_3e7b',
      realName: '张三',
    }),
};

describe('端到端：真正写进 transport 的字节（六臂矩阵）', () => {
  const results = new Map();

  beforeAll(async () => {
    for (const arm of ARMS) {
      results.set(arm.name, await runArm(arm));
    }
  });

  afterAll(async () => {
    await Sentry.close(1000);
  });

  it.each(ARMS.map((a) => [a.name, a]))(
    '%s — 每条凭据标记的出现与否都与该臂开放的通道一致',
    (name, arm) => {
      const { bytes } = results.get(name);
      for (const marker of MARKERS) {
        const present = bytes.includes(marker.token);
        expect({ marker: marker.label, present }).toEqual({
          marker: marker.label,
          present: marker.channels.some((c) => arm.open.includes(c)),
        });
      }
    }
  );

  it.each(ARMS.filter((a) => a.isControl).map((a) => [a.name, a]))(
    '%s — 对照臂上每个声明开放的通道都真能看到凭据（探测器有效性，否则上面的全绿没有意义）',
    (name, arm) => {
      const { event } = results.get(name);
      expect(arm.open.length).toBeGreaterThan(0);
      for (const channel of arm.open) {
        const proof = CHANNEL_PROOF[channel];
        if (!proof)
          throw new Error(`通道 ${channel} 没有登记探测器判据（新增通道必须补，否则等于没测）`);
        proof(event);
      }
    }
  );

  it.each(ARMS.filter((a) => a.beforeSend).map((a) => [a.name, a]))(
    '%s — beforeSend 在场时 event.request 只剩保留白名单的键（不认采集侧给了什么）',
    (name) => {
      const { event } = results.get(name);
      expect(Object.keys(event.request).sort()).toEqual([...SENTRY_ALLOWED_REQUEST_FIELDS].sort());
    }
  );

  it.each(ARMS.map((a) => [a.name, a]))(
    '%s — 原始 req.user 有没有整块抄进 request.user 与预期一致',
    (name, arm) => {
      const { event } = results.get(name);
      expect('user' in event.request).toBe(arm.open.includes('requestUser'));
    }
  );

  it.each(ARMS.map((a) => [a.name]))(
    '%s — 泄漏面收窄后仍保留定位能力（反"过度削减把事件削废"）',
    (name) => {
      const { event } = results.get(name);
      expect(event.request.method).toBe('POST');
      expect(event.request.url).toContain('/api/auth/login');
      expect(event.exception.values[0].value).toBe('boom-5xx');
      // 参数化路由名（实测本版本不含查询串）保留 ⇒ Sentry 侧分组不受影响
      expect(event.transaction).toBe('POST /api/auth/login');
    }
  );

  it.each(ARMS.map((a) => [a.name, a]))(
    '%s — url 是否残留查询串与预期一致（证明 beforeSend 这一层不可省）',
    (name, arm) => {
      const { event } = results.get(name);
      expect(event.request.url.includes('?')).toBe(arm.open.includes('query'));
    }
  );

  it.each(ARMS.map((a) => [a.name, a]))('%s — event.user 整块在/不在与预期一致', (name, arm) => {
    const { event } = results.get(name);
    expect('user' in event).toBe(arm.open.includes('user'));
  });

  it('六臂都恰好产出一个 event envelope（clean 不等于"什么都没发"）', () => {
    for (const arm of ARMS) {
      const bytes = results.get(arm.name).bytes;
      expect((bytes.match(/"type":"event"/g) || []).length).toBe(1);
    }
  });

  it('出网字节里不存在未裁剪的原始 req（sdkProcessingMetadata 不入 envelope）', () => {
    // 这条钉的是"判据面"：如果哪天它上了线，本模块的收口口径就得跟着改
    for (const arm of ARMS) {
      expect(results.get(arm.name).bytes).not.toContain('sdkProcessingMetadata');
    }
  });
});

describe('scrubOutboundEvent —— 纯函数真值表', () => {
  it('非对象与假值原样透传', () => {
    for (const value of [null, undefined, 0, '', false]) {
      expect(scrubOutboundEvent(value)).toBe(value);
    }
  });

  it('就地削减并返回同一引用（不复制事件）', () => {
    const event = { request: { method: 'GET', url: '/a?b=1' } };
    expect(scrubOutboundEvent(event)).toBe(event);
    expect(event.request.url).toBe('/a');
  });

  it('request 不是对象时不动它', () => {
    const event = { request: 'oops-a-string' };
    expect(scrubOutboundEvent(event).request).toBe('oops-a-string');
  });

  // 这份清单是"实测过的字段名"样本，不是代码里的删除清单：咽喉现在是保留白名单制，
  // 未知字段名同样被删 ⇒ 清单只负责钉住"这些已知名字确实进不去"
  it.each([
    'data',
    'body',
    'params',
    'cookies',
    'headers',
    'query_string',
    'env',
    'user',
    'someFieldNameAFutureSdkWillAdd',
  ])('保留白名单之外的键 %s 被删除（未知字段名也删，这是黑名单式收口做不到的）', (field) => {
    const event = { request: { method: 'POST', url: '/a', [field]: { keep: false } } };
    scrubOutboundEvent(event);
    expect(field in event.request).toBe(false);
  });

  it('削减后的键面恰好等于保留白名单（反"过度削减"：method/url 必须留着）', () => {
    const event = { request: { method: 'POST', url: '/a', data: 'x', user: { sessionId: 'x' } } };
    scrubOutboundEvent(event);
    expect(Object.keys(event.request).sort()).toEqual(['method', 'url']);
  });

  it('保留白名单只含定位用的两个键（扩列必须同时把凭据探测器补上）', () => {
    expect([...SENTRY_ALLOWED_REQUEST_FIELDS].sort()).toEqual(['method', 'url']);
  });

  it.each([
    ['/a?b=1', '/a'],
    ['/a?b=1?c=2', '/a'],
    ['/a', '/a'],
    ['', ''],
    ['/?token=x', '/'],
  ])('url 查询串剥离：%s → %s', (input, expected) => {
    expect(scrubOutboundEvent({ request: { url: input } }).request.url).toBe(expected);
  });

  it('url 非字符串时保持原值（不参与 split）', () => {
    expect(scrubOutboundEvent({ request: { url: 8080 } }).request.url).toBe(8080);
  });

  it.each([
    ['POST /a?b=1', 'POST /a'],
    ['GET /a', 'GET /a'],
  ])('transaction 查询串剥离：%s → %s', (input, expected) => {
    expect(scrubOutboundEvent({ transaction: input }).transaction).toBe(expected);
  });

  it('transaction 非字符串时保持原值', () => {
    expect(scrubOutboundEvent({ transaction: 42 }).transaction).toBe(42);
  });

  it('缺失的 transaction / request 不会被凭空补出键', () => {
    const out = scrubOutboundEvent({ event_id: 'x' });
    expect('transaction' in out).toBe(false);
    expect('request' in out).toBe(false);
  });

  it.each([
    ['完整身份', { username: 'admin', email: 'a@b.co', id: 'U1' }],
    ['只有 email', { email: 'a@b.co' }],
    ['空对象', {}],
  ])('user 整块删除（%s）', (_label, user) => {
    const out = scrubOutboundEvent({ user });
    expect('user' in out).toBe(false);
  });

  it('user 为假值时同样不留键', () => {
    expect('user' in scrubOutboundEvent({ user: null })).toBe(false);
    expect('user' in scrubOutboundEvent({ event_id: 'x' })).toBe(false);
  });

  it('非请求面（异常/上下文/tags/extra）不受影响', () => {
    const event = {
      exception: { values: [{ type: 'Error', value: 'boom' }] },
      contexts: { os: { name: 'linux' } },
      tags: { env: 'prod' },
      extra: { note: 'keep' },
      request: { method: 'POST', url: '/a?b=1', data: 'x' },
      user: { username: 'admin' },
    };
    scrubOutboundEvent(event);
    expect(event.exception).toEqual({ values: [{ type: 'Error', value: 'boom' }] });
    expect(event.contexts).toEqual({ os: { name: 'linux' } });
    expect(event.tags).toEqual({ env: 'prod' });
    expect(event.extra).toEqual({ note: 'keep' });
  });

  it('幂等：削减两次与一次结果相同', () => {
    const make = () => ({ request: { method: 'POST', url: '/a?b=1', data: 'x' }, user: { id: 1 } });
    const once = scrubOutboundEvent(make());
    const twice = scrubOutboundEvent(make());
    scrubOutboundEvent(twice);
    expect(twice).toEqual(once);
  });
});

describe('装配实参（Sentry.init / Handlers.requestHandler 收到什么）', () => {
  const realInit = Sentry.init;
  const realRequestHandler = Sentry.Handlers.requestHandler;
  const realCaptureException = Sentry.captureException;
  const realNodeEnv = process.env.NODE_ENV;
  let initCalls;
  let handlerCalls;
  let captureCalls;

  beforeEach(() => {
    initCalls = [];
    handlerCalls = [];
    captureCalls = [];
    Sentry.init = (opts) => {
      initCalls.push(opts);
      return {};
    };
    Sentry.Handlers.requestHandler = (...args) => {
      handlerCalls.push(args);
      return (_req, _res, next) => next();
    };
    Sentry.captureException = (err, hint) => captureCalls.push({ err, hint });
  });

  afterEach(() => {
    Sentry.init = realInit;
    Sentry.Handlers.requestHandler = realRequestHandler;
    Sentry.captureException = realCaptureException;
    delete process.env.SENTRY_DSN;
    process.env.NODE_ENV = realNodeEnv;
  });

  it('initSentry 把 scrubOutboundEvent 作为 beforeSend 交给 SDK', () => {
    process.env.SENTRY_DSN = FAKE_DSN;
    expect(sentryModule.initSentry()).toBe(true);
    expect(initCalls).toHaveLength(1);
    expect(initCalls[0].beforeSend).toBe(scrubOutboundEvent);
  });

  it('未配置 DSN 时不初始化（且不会传一个空 beforeSend）', () => {
    delete process.env.SENTRY_DSN;
    expect(sentryModule.initSentry()).toBe(false);
    expect(initCalls).toHaveLength(0);
  });

  it('sentryRequestHandler 传的是白名单而不是无参调用', () => {
    sentryModule.sentryRequestHandler();
    expect(handlerCalls).toHaveLength(1);
    expect(handlerCalls[0]).toHaveLength(1);
    expect(handlerCalls[0][0]).toEqual({ include: { request: ['method', 'url'], user: false } });
  });

  it('白名单里不含任何正文/凭据类字段', () => {
    // 'user' 在这一列是有实测依据的：它不是 SDK 的 case 名，走 default 分支 ⇒ 原样抄 req.user
    const dangerous = ['data', 'body', 'cookies', 'headers', 'query_string', 'user', 'session'];
    expect(SENTRY_REQUEST_INCLUDE.request.filter((k) => dangerous.includes(k))).toEqual([]);
    expect(SENTRY_REQUEST_INCLUDE.user).toBe(false);
  });

  it('isSentryInitialized 是单向开关：初始化后为 true，未配置 DSN 不翻它', () => {
    // wellKnownRoutes.js:169 拿它决定要不要走 Sentry 分支。
    // 这里先读当前值再断言"不变"，而不是断言初始为 false —— 同一文件里别的用例会真的调用
    // initSentry，写成断言 false 就是一条文件内顺序耦合（--randomize 迟早翻红）。
    const before = sentryModule.isSentryInitialized();
    delete process.env.SENTRY_DSN;
    expect(sentryModule.initSentry()).toBe(false);
    expect(sentryModule.isSentryInitialized()).toBe(before);
    process.env.SENTRY_DSN = FAKE_DSN;
    expect(sentryModule.initSentry()).toBe(true);
    expect(sentryModule.isSentryInitialized()).toBe(true);
  });

  it('tracing/error 两个中间件是 app.js 直接挂的形状（errorHandler 收 (err,req,res,next)）', () => {
    expect(typeof sentryModule.sentryTracingHandler()).toBe('function');
    expect(sentryModule.sentryErrorHandler().length).toBe(4);
  });

  it('production 采样 10%、environment 跟随 NODE_ENV（未设置时回落 development）', () => {
    process.env.SENTRY_DSN = FAKE_DSN;
    process.env.NODE_ENV = 'production';
    sentryModule.initSentry();
    expect(initCalls[0]).toMatchObject({ environment: 'production', tracesSampleRate: 0.1 });
    delete process.env.NODE_ENV;
    sentryModule.initSentry();
    expect(initCalls[1]).toMatchObject({ environment: 'development', tracesSampleRate: 1 });
  });

  it('captureException 不传 context 时 extra 是空对象（默认参数真的在生效）', () => {
    sentryModule.captureException(new Error('x'));
    expect(captureCalls).toHaveLength(1);
    expect(captureCalls[0].hint).toEqual({ extra: {} });
  });

  it('captureException 把 context 放进 extra（不改写事件本身）', () => {
    const err = new Error('x');
    sentryModule.captureException(err, { requestId: 'r1' });
    expect(captureCalls).toHaveLength(1);
    expect(captureCalls[0].err).toBe(err);
    expect(captureCalls[0].hint).toEqual({ extra: { requestId: 'r1' } });
  });
});

describe('单一咽喉（源码门禁：出网收口不能被旁路）', () => {
  const SRC_ROOT = path.resolve(__dirname, '../..');

  /** 注释遮掉的"代码视图"——否则门禁会被注释自己满足（本仓既有教训） */
  const codeView = (text) =>
    text.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|\s)\/\/[^\r\n]*/g, '');

  const walk = (dir, acc = []) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      if (entry.name === 'tests' || entry.name === 'node_modules') continue;
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) walk(full, acc);
      else if (entry.name.endsWith('.js')) acc.push(full);
    }
    return acc;
  };

  const files = walk(SRC_ROOT);
  const sdkUsers = files
    .filter((f) => codeView(fs.readFileSync(f, 'utf8')).includes("require('@sentry/node')"))
    .map((f) => path.relative(SRC_ROOT, f).replace(/\\/g, '/'));

  it('遮注释的判据自身有效（否则整组门禁都是假绿）', () => {
    expect(codeView("require('@sentry/node')")).toContain('@sentry/node');
    expect(codeView("// const S = require('@sentry/node');")).not.toContain('@sentry/node');
    expect(codeView("/* require('@sentry/node') */")).not.toContain('@sentry/node');
    expect(codeView('const a = 1; // x')).toBe('const a = 1;');
  });

  it('全仓只有一个文件真的引用 @sentry/node：收口只可能出现在那一处', () => {
    expect(sdkUsers).toEqual(['middleware/sentry.js']);
  });

  it('该文件从不无参调用 Handlers.requestHandler（无参 = 走默认全量采集表）', () => {
    const src = codeView(fs.readFileSync(path.join(SRC_ROOT, 'middleware/sentry.js'), 'utf8'));
    // 锚点必须带 Handlers. 前缀：本模块自己导出的 sentryRequestHandler() 就是零参的，
    // 只写 requestHandler\(\s*\) 会让这条门禁永远红（也永远没人去修它）
    expect(src.match(/Handlers\.requestHandler\(\s*\)/g) || []).toEqual([]);
    expect(src).toMatch(/Handlers\.requestHandler\(\{\s*include:/);
  });

  it('该文件的 Sentry.init 一定带 beforeSend', () => {
    const src = codeView(fs.readFileSync(path.join(SRC_ROOT, 'middleware/sentry.js'), 'utf8'));
    expect(src.match(/beforeSend:/g) || []).toHaveLength(1);
    expect(src).toMatch(/beforeSend:\s*scrubOutboundEvent/);
  });
});
