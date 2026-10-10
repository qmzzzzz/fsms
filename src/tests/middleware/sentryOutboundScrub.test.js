/**
 * F-180：Sentry 出网事件不得携带凭据/身份
 *
 * 判据口径（与 src/middleware/sentry.js 的头注释一致）：不看 beforeSend 的入参，
 * 只看**真的写进 transport 的字节**。本文件已随 @sentry/node 7.x → 11.4.0 重写探测器，
 * v7 时代踩过的坑与 v11 链路的实测事实一并留档：
 *  1) 用 `defaultIntegrations:false` 会把负责写 event.request 的集成一起关掉
 *     ⇒ 事件里没有 request 字段，"没检测到泄漏"其实是探测器坏了（实测：全臂 clean 的假绿）。
 *     所以这里显式只装 httpServerIntegration + requestDataIntegration，并**先断言探测器
 *     能看到泄漏**（臂 0）。
 *  2) v11 的 request 数据来自真实 HTTP 请求：httpServerIntegration 在请求经过时把
 *     normalizedRequest 写进 scope，requestDataIntegration 再按 include 摘进 event
 *     ⇒ 每条臂都起真服务器、发真请求，比 v7 的"手工造 req 过 handler"更接近生产。
 *  3) 事件对象上的 `sdkProcessingMetadata.normalizedRequest` 不会进 envelope（SDK 序列化前
 *     剥掉），按它判泄漏会得出"修不住"的错结论。所以只认 transport 截获的 envelope。
 *  4) v11 采集侧默认值是 deny 黑名单（敏感子串匹配）：名单认不出的头名/cookie 名/参数名
 *     原样出网（臂 0 的 x-probe-ticket / probe_ticket / next= 三处实测），与 v7 的
 *     extractRequestData default 分支同族 ⇒ beforeSend 保留白名单仍不可省。
 *  5) 第一版收口是"黑名单逐个删已知字段名"（v7 变异 M3 逼出来的教训）：咽喉现为保留
 *     白名单制；v11 的臂 4/臂 5 是"采集侧被人显式打开通道"的"能漏 / 已被削"对照。
 *  6) 实测负结果（本版本链路）：请求体在本探测器形态下不进 event.request.data——
 *     httpServerIntegration 的 body 采集与 captureException 的调用时机相互错开
 *     （同步 capture 时流未读完；等 end 再 capture 时 async context 丢失、request 整块消失）。
 *     body 通道因此不在任何臂的 open 里；口令/MFA 标记保留，谁把 body 放行（SDK 升级、
 *     换框架、改 dataCollection）推导立刻红，而不是无声多一条出网面。
 */
const fs = require('fs');
const path = require('path');
const http = require('http');
const Sentry = require('@sentry/node');
const sentryModule = require('../../middleware/sentry');

const { scrubOutboundEvent, SENTRY_REQUEST_INCLUDE, SENTRY_ALLOWED_REQUEST_FIELDS } = sentryModule;

// 即便 transport 被绕过，DSN 也只指向本机一个没人监听的端口
const FAKE_DSN = 'http://aaa@127.0.0.1:1/1';

// 探测令牌：命名刻意避开 v11 的敏感子串名单（SENSITIVE_KEY_SNIPPETS：auth/token/
// secret/session/password/key/jwt/bearer/sso/saml/csrf/xsrf/credentials/sid/identity/
// cookie…）与 SENSITIVE_COOKIE_NAME_SNIPPETS——只有"名单认不出"的名字原样出网，
// 才能证明 headers/cookies 通道真的开着。authorization 头与 sid cookie 一并放进请求
// 作对照：它们被 v11 替换成 [Filtered]，证明"黑名单只兜已知名"这条链路事实。
const HEADER_TICKET = 'HEADERVAL_7ab1';
const COOKIE_TICKET = 'COOKIEVAL_4d2e';
const QUERY_TICKET = 'RESETTOKEN_8c5f_secret';
const BODY_TICKET = 'P@ssw0rd!Xy';
const MFA_TICKET = 'MFA_9f3c_secret';

/**
 * `channels` 是"这条凭据能从哪几格出去"的通道名，与 v11 requestDataIntegration 的
 * include 键一一对应：
 *  - body    → include.data（request.data，v11 read-time 恒真，写入由 httpBodies 管）
 *  - headers → include.headers（request.headers）
 *  - cookies → include.cookies（request.cookies）
 *  - query   → include.query_string + url 里的查询串（url 恒开，只有 beforeSend 能削）
 *  - user    → include.ip（v11 的 user 通道只剩 event.user.ip_address）
 * 邮箱与 sessionId 两条身份通道在 v11 已断（无 DEFAULT_USER_INCLUDES、无 default
 * 抄属性分支），channels 置空 ⇒ 任何臂都不该出现；谁把通道改回来，推导立刻红。
 */
const MARKERS = [
  { label: '登录口令', token: BODY_TICKET, channels: ['body'] },
  { label: 'MFA 码', token: MFA_TICKET, channels: ['body'] },
  { label: 'Bearer 级自定义头（名单认不出）', token: HEADER_TICKET, channels: ['headers'] },
  { label: '会话 cookie 值（名单认不出的名字）', token: COOKIE_TICKET, channels: ['cookies'] },
  { label: '查询串里的重置令牌（名单认不出的参数名）', token: QUERY_TICKET, channels: ['query'] },
  { label: '邮箱（身份）', token: 'probe-identity@example.test', channels: [] },
  { label: '会话 sessionId', token: 'SID_3e7b', channels: [] },
];

/**
 * 跑一条臂：init → 起真服务器 → 发带全量敏感面的真请求 → 截获真正出网的 envelope
 * @returns {Promise<{bytes: string, event: object}>}
 */
const runArm = async ({ include, beforeSend }) => {
  const frames = [];
  Sentry.init({
    dsn: FAKE_DSN,
    environment: 'test',
    tracesSampleRate: 0,
    defaultIntegrations: false,
    // v11：只装这两个集成——httpServerIntegration 负责把请求归一化写进 scope，
    // requestDataIntegration 负责按 include 摘进 event（生产里两者都在默认表里）。
    // include 缺省 = 走 v11 推导默认（臂 0 的修复前形态：cookies/headers/query/ip 全开）。
    integrations: [
      Sentry.httpServerIntegration(),
      Sentry.requestDataIntegration(include ? { include } : {}),
    ],
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

  const server = http.createServer((req, res) => {
    Sentry.captureException(new Error('boom-5xx'));
    res.end('ok');
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const body = JSON.stringify({ username: 'admin', password: BODY_TICKET, mfaCode: MFA_TICKET });
  await new Promise((resolve) => {
    const req = http.request(
      {
        host: '127.0.0.1',
        port: server.address().port,
        path: '/api/auth/login?next=' + QUERY_TICKET,
        method: 'POST',
        headers: {
          // 名单内：v11 替换成 [Filtered]（对照，证明黑名单只兜已知名）
          authorization: 'Bearer BEARER_7ab1_secret',
          cookie: 'sid=SIDCOOKIE_4d2e_secret; probe_ticket=' + COOKIE_TICKET,
          // 名单外：原样出网（headers/cookies 通道的探测器）
          'x-probe-ticket': HEADER_TICKET,
          'content-type': 'application/json',
          'content-length': Buffer.byteLength(body),
        },
      },
      (res) => {
        res.resume();
        res.on('end', resolve);
      }
    );
    req.end(body);
  });

  const deadline = Date.now() + 4000;
  while (frames.length === 0) {
    if (Date.now() > deadline) throw new Error('探测器失效：4s 内 transport 没有收到任何 envelope');
    await new Promise((r) => setTimeout(r, 20));
  }
  await Sentry.close(1000);
  await new Promise((resolve) => server.close(resolve));

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
 *  - 'query' 在只留 include 的臂上仍然开着：白名单里保留了 url，而它由 originalUrl 拼成，
 *    天然带查询串 ⇒ 这一格只有 beforeSend 能削，是"两层缺一不可"的实测依据。
 *  - 'body' 不在任何臂的 open 里：本版本链路实测不可达（见文件头第 6 条），标记保留作告警。
 */
/** 被人"顺手打开"的采集配置：显式开 headers/cookies/ip 三个通道（v11 无未知键通道） */
const tamperedInclude = () => ({
  ...sentryModule.SENTRY_REQUEST_INCLUDE,
  headers: true,
  cookies: true,
  ip: true,
});

const ARMS = [
  {
    name: '臂0 修复前形态：不配 include（走 v11 推导默认）+ 无 beforeSend',
    include: undefined,
    beforeSend: undefined,
    isControl: true,
    open: ['headers', 'cookies', 'query', 'user'],
  },
  {
    name: '臂1 本模块真实装配：include 扁平全关 + beforeSend 两层',
    include: sentryModule.SENTRY_REQUEST_INCLUDE,
    beforeSend: scrubOutboundEvent,
    open: [],
  },
  {
    name: '臂2 只剩 beforeSend（有人把 include 删了）',
    include: undefined,
    beforeSend: scrubOutboundEvent,
    open: [],
  },
  {
    name: '臂3 只剩 include（beforeSend 被摘掉）',
    include: sentryModule.SENTRY_REQUEST_INCLUDE,
    beforeSend: undefined,
    open: ['query'],
  },
  {
    name: '臂4 采集侧被人显式打开三通道 + beforeSend 在场（咽喉必须自己兜住）',
    include: tamperedInclude(),
    beforeSend: scrubOutboundEvent,
    open: [],
  },
  {
    name: '臂5 采集侧被人显式打开三通道、beforeSend 被摘（多通道探测器有效性对照）',
    include: tamperedInclude(),
    beforeSend: undefined,
    open: ['headers', 'cookies', 'query', 'user'],
  },
];

/**
 * 每条开放通道"该在事件哪儿看到什么"的探测器判据。open 非空的臂逐条过一遍：
 * 通道声明开着却看不到证据 ⇒ 报错，而不是静默全绿——这是本套件唯一能证明
 * "没检测到泄漏 = 真没泄漏"而不是"探测方式坏了"的地方（已被这条坑过一次，见文件头）。
 */
const CHANNEL_PROOF = {
  body: (event) => expect(event.request.data).toContain(BODY_TICKET),
  headers: (event) => expect(event.request.headers['x-probe-ticket']).toBe(HEADER_TICKET),
  cookies: (event) => expect(event.request.cookies.probe_ticket).toBe(COOKIE_TICKET),
  query: (event) =>
    expect(`${event.request.query_string || ''}|${event.request.url || ''}`).toContain(
      QUERY_TICKET
    ),
  user: (event) => expect(typeof event.user.ip_address).toBe('string'),
};

describe('端到端：真正写进 transport 的字节（六臂矩阵，真 HTTP 链路）', () => {
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

  it.each(ARMS.filter((a) => a.open.length > 0).map((a) => [a.name, a]))(
    '%s — 每个声明开放的通道都真能看到凭据（探测器有效性，否则上面的全绿没有意义）',
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
    '%s — event.request 从不出现 v7 时代的 request.user 整块（v11 无该通道，未知键也不进 request）',
    (name) => {
      const { event } = results.get(name);
      expect('user' in event.request).toBe(false);
    }
  );

  it.each(ARMS.map((a) => [a.name, a]))(
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

  it.each(ARMS.map((a) => [a.name, a]))(
    '%s — event.user 在/不在与预期一致（v11 该通道只剩 ip_address）',
    (name, arm) => {
      const { event } = results.get(name);
      expect('user' in event).toBe(arm.open.includes('user'));
    }
  );

  it('六臂都恰好产出一个 event envelope（clean 不等于"什么都没发"）', () => {
    for (const arm of ARMS) {
      expect((results.get(arm.name).bytes.match(/"type":"event"/g) || []).length).toBe(1);
    }
  });

  it('出网字节里不存在未裁剪的归一化请求（sdkProcessingMetadata 不入 envelope）', () => {
    // 这条钉的是"判据面"：如果哪天它上了线，本模块的收口口径就得跟着改
    for (const arm of ARMS) {
      expect(results.get(arm.name).bytes).not.toContain('sdkProcessingMetadata');
      expect(results.get(arm.name).bytes).not.toContain('normalizedRequest');
    }
  });

  it('探测器自证：名单内的敏感名被 v11 替换成 [Filtered]，名单认不出的名字原样出网（黑名单只兜已知名，收口不能依赖它）', () => {
    const { event } = results.get(ARMS[0].name);
    expect(event.request.headers.authorization).toBe('[Filtered]');
    expect(event.request.cookies.sid).toBe('[Filtered]');
    expect(event.request.headers['x-probe-ticket']).toBe(HEADER_TICKET);
    expect(event.request.cookies.probe_ticket).toBe(COOKIE_TICKET);
    expect(event.request.url).toContain(QUERY_TICKET);
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

describe('真实装配端到端（initSentry 的 init 实参原样驱动）', () => {
  /**
   * 六臂矩阵验证的是"两层收口机制"，本组验证的是**本模块真实装配的那一份实参**：
   * initSentry 交给 Sentry.init 的 dataCollection / requestDataIntegration include /
   * beforeSend 原样驱动一次端到端。缺了它，摘掉 sentry.js 里的 beforeSend 只有装配
   * 用例和静态门禁会红、六臂矩阵全绿——v11 迁移时实测踩到过这个缺口（变异 M2）。
   */
  it('凭据不出网、request 只剩 method/url、beforeSend 就是 scrubOutboundEvent', async () => {
    const frames = [];
    const realInit = Sentry.init;
    let captured = null;
    Sentry.init = (opts) => {
      captured = opts;
      return {};
    };
    try {
      process.env.SENTRY_DSN = FAKE_DSN;
      expect(sentryModule.initSentry()).toBe(true);
    } finally {
      Sentry.init = realInit;
      delete process.env.SENTRY_DSN;
    }
    expect(captured).toBeTruthy();
    expect(captured.beforeSend).toBe(scrubOutboundEvent);

    // 用捕获到的真实实参 init：只补探测器需要的 transport 与 httpServerIntegration，
    // 其余（dataCollection / integrations / beforeSend）一概原样，不"为了好测而改配"
    Sentry.init({
      ...captured,
      dsn: FAKE_DSN,
      environment: 'test',
      tracesSampleRate: 0,
      defaultIntegrations: false,
      integrations: [Sentry.httpServerIntegration(), ...captured.integrations],
      transport: () => ({
        send: (request) => {
          const envelope =
            request && typeof request === 'object' && 'body' in request ? request.body : request;
          frames.push(JSON.stringify(envelope));
          return Promise.resolve({ reason: 'sent' });
        },
        flush: () => Promise.resolve(true),
      }),
    });

    const server = http.createServer((req, res) => {
      Sentry.captureException(new Error('boom-5xx'));
      res.end('ok');
    });
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    const body = JSON.stringify({ username: 'admin', password: BODY_TICKET, mfaCode: MFA_TICKET });
    await new Promise((resolve) => {
      const req = http.request(
        {
          host: '127.0.0.1',
          port: server.address().port,
          path: '/api/auth/login?next=' + QUERY_TICKET,
          method: 'POST',
          headers: {
            authorization: 'Bearer BEARER_7ab1_secret',
            cookie: 'sid=SIDCOOKIE_4d2e_secret; probe_ticket=' + COOKIE_TICKET,
            'x-probe-ticket': HEADER_TICKET,
            'content-type': 'application/json',
            'content-length': Buffer.byteLength(body),
          },
        },
        (res) => {
          res.resume();
          res.on('end', resolve);
        }
      );
      req.end(body);
    });
    const deadline = Date.now() + 4000;
    while (frames.length === 0) {
      if (Date.now() > deadline)
        throw new Error('探测器失效：4s 内 transport 没有收到任何 envelope');
      await new Promise((r) => setTimeout(r, 20));
    }
    await Sentry.close(1000);
    await new Promise((resolve) => server.close(resolve));

    const bytes = frames.join('\n');
    // jest 的 expect 只收一个参数（vitest 才收 message），故收集后一次断言
    const leaked = MARKERS.filter((m) => bytes.includes(m.token)).map((m) => m.label);
    expect(leaked).toEqual([]);
    const envelope = JSON.parse(frames[0]);
    const [itemHeader, itemPayload] = envelope[1][0];
    if (itemHeader.type !== 'event') {
      throw new Error(`探测器形状已变：首帧 item type = ${String(itemHeader.type)}`);
    }
    const event = typeof itemPayload === 'string' ? JSON.parse(itemPayload) : itemPayload;
    expect(Object.keys(event.request).sort()).toEqual([...SENTRY_ALLOWED_REQUEST_FIELDS].sort());
    expect('user' in event).toBe(false);
    // v11 真服务器请求的 url 带真实 host:port（v7 时代是 <no host>，别照抄记忆）；
    // 判据是"以路径结尾且不带查询串"——查询串只能被 beforeSend 削掉
    expect(event.request.url.endsWith('/api/auth/login')).toBe(true);
    expect(event.request.url).not.toContain('?');
  });
});

describe('装配实参（Sentry.init 收到什么）', () => {
  const realInit = Sentry.init;
  const realCaptureException = Sentry.captureException;
  const realNodeEnv = process.env.NODE_ENV;
  let initCalls;
  let captureCalls;

  beforeEach(() => {
    initCalls = [];
    captureCalls = [];
    Sentry.init = (opts) => {
      initCalls.push(opts);
      return {};
    };
    Sentry.captureException = (err, hint) => captureCalls.push({ err, hint });
  });

  afterEach(() => {
    Sentry.init = realInit;
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

  it('init 实参只带一个 requestDataIntegration（tracing 交给默认 httpIntegration，不重复挂）', () => {
    process.env.SENTRY_DSN = FAKE_DSN;
    sentryModule.initSentry();
    expect(initCalls[0].integrations).toHaveLength(1);
    expect(initCalls[0].integrations[0].name).toBe('RequestData');
  });

  it('init 实参带 dataCollection 总闸（v11.4.0 起 sendDefaultPii 不再映射 dataCollection，不写就是全开）', () => {
    process.env.SENTRY_DSN = FAKE_DSN;
    sentryModule.initSentry();
    expect(initCalls[0].dataCollection).toEqual({
      userInfo: false,
      cookies: false,
      httpHeaders: false,
      httpBodies: [],
      urlQueryParams: false,
    });
  });

  it('SENTRY_REQUEST_INCLUDE 是 v11 扁平六键、只放行 url（v7 的 request/user 两级写法已不存在）', () => {
    expect(Object.keys(SENTRY_REQUEST_INCLUDE).sort()).toEqual([
      'cookies',
      'data',
      'headers',
      'ip',
      'query_string',
      'url',
    ]);
    expect(Object.entries(SENTRY_REQUEST_INCLUDE).filter(([, v]) => v === true)).toEqual([
      ['url', true],
    ]);
    // v7 遗留键一个都不许有：它们在 v11 的 include 里不是"关了"，是"不存在"
    expect(SENTRY_REQUEST_INCLUDE).not.toHaveProperty('request');
    expect(SENTRY_REQUEST_INCLUDE).not.toHaveProperty('user');
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

  it('request/tracing 两个 handler 是直通中间件（v11 无 Handlers 导出，不能让 app.use 炸）', () => {
    for (const factory of [sentryModule.sentryRequestHandler, sentryModule.sentryTracingHandler]) {
      const mw = factory();
      expect(mw).toHaveLength(3);
      let nextCalled = false;
      mw({}, {}, () => {
        nextCalled = true;
      });
      expect(nextCalled).toBe(true);
    }
  });

  it('sentryErrorHandler 捕获后继续向后传（响应仍由本仓 errorHandler 出）', () => {
    const err = new Error('x');
    let nextArg = null;
    sentryModule.sentryErrorHandler()(err, {}, {}, (e) => {
      nextArg = e;
    });
    expect(nextArg).toBe(err);
    expect(captureCalls).toHaveLength(1);
    expect(captureCalls[0].err).toBe(err);
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

  const sentrySrc = () =>
    codeView(fs.readFileSync(path.join(SRC_ROOT, 'middleware/sentry.js'), 'utf8'));

  it('遮注释的判据自身有效（否则整组门禁都是假绿）', () => {
    expect(codeView("require('@sentry/node')")).toContain('@sentry/node');
    expect(codeView("// const S = require('@sentry/node');")).not.toContain('@sentry/node');
    expect(codeView("/* require('@sentry/node') */")).not.toContain('@sentry/node');
    expect(codeView('const a = 1; // x')).toBe('const a = 1;');
  });

  it('全仓只有一个文件真的引用 @sentry/node：收口只可能出现在那一处', () => {
    expect(sdkUsers).toEqual(['middleware/sentry.js']);
  });

  it('该文件不残留 v7 的 Handlers./Integrations. 调用（v11 这两个导出已移除，残留即装不上）', () => {
    const src = sentrySrc();
    expect(src.match(/Handlers\.\w+/g) || []).toEqual([]);
    expect(src.match(/Sentry\.Integrations\.\w+/g) || []).toEqual([]);
  });

  it('requestDataIntegration 必须显式接上 SENTRY_REQUEST_INCLUDE（不接 = 走 v11 推导默认：cookies/headers/query_string/ip 全开）', () => {
    expect(sentrySrc()).toMatch(
      /requestDataIntegration\(\{\s*include:\s*SENTRY_REQUEST_INCLUDE\s*\}\)/
    );
  });

  it('init 必须带 dataCollection 总闸（v11.4.0 起 sendDefaultPii 不再映射，缺了就是全开）', () => {
    const src = sentrySrc();
    expect(src).toMatch(/dataCollection:\s*\{/);
    expect(src).toMatch(/httpBodies:\s*\[\]/);
    expect(src).toMatch(/userInfo:\s*false/);
  });

  it('该文件的 Sentry.init 一定带 beforeSend', () => {
    const src = sentrySrc();
    expect(src.match(/beforeSend:/g) || []).toHaveLength(1);
    expect(src).toMatch(/beforeSend:\s*scrubOutboundEvent/);
  });
});
