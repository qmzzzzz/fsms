/**
 * 探针豁免必须精确到「探针路径 + 探针方法」；HEAD 打到敏感读取路径必须留审计
 *
 * 两条都是"闸门声称挡住了 X，实际豁免面比 X 宽"的同一类缺陷，各自实测复现过：
 *
 * 【一】`/health`、`/readyz` 的豁免原先用 `helpers.matchesAnyPathPrefix` 判定
 * （`f === p || f.startsWith(p + '/')`），且不看方法。于是一个名字免掉了整棵子树，
 * 而 `app.js` 把两处限流器提到 body 解析之前、把 protocolCompliance 提到
 * `express.json()` 之前的全部理由，在 `/health/任意后缀` 上都不成立。修复前实测：
 *   POST /health/zznope（text/plain）  → 404，且响应**没有**任何 RateLimit-* 头
 *   POST /api/zznope（同形请求）        → 415 CONTENT_TYPE_UNSUPPORTED + 全套 RateLimit-* 头
 *   40 × POST /health/zzflood（每发 ~200KB JSON）→ 全部 404，一条 429 都没有
 * 只把前缀改成精确还漏一半：`POST /health` 与 `POST /health/anything` 的代价同源
 * （都是"零配额 + 零闸门"地让服务端解析一个 1MB 级 body），所以方法维度一起收口，
 * 豁免只属于探活请求本身。反向的部署事故同样要设防：容器 HEALTHCHECK、
 * `.github/workflows/ci.yml` 与 `scripts/deploy.js` 都以 `curl GET /readyz|/health` 判活，
 * 收紧过头（把 GET 探针也吃 429）会让门禁对完全健康的新版本恒红并自动回滚。
 *
 * 【二】Express 的 `Route.dispatch` 把 HEAD 归一成 GET，所以 `app.get(...)` 的处理函数
 * 对 HEAD **全量执行**（Node 只是不把响应体写出去）。而审计闸门的敏感读取判据只认
 * `req.method === 'GET'`，`WRITE_METHODS` 又不含 HEAD ⇒ 一条"业务跑了、零留痕"的口子。
 * 修复前实测（真实 createApp + 带 user:read 的合法令牌）：
 *   GET  /api/users → 200，审计增量 1
 *   HEAD /api/users → 200，审计增量 0
 * 报表导出/审计日志查询都在这条白名单上，只读账号即可反复批量取数而审计页面一片空白。
 * action 派生（utils/auditMeta.deriveAction）必须与 GET 同尺：否则 HEAD 落到末尾兜底
 * 得到 `user_head`——一个不在 AUDIT_LOG_ACTIONS 里的值，审计页筛不到也统计不到。
 *
 * 【三】OPTIONS 只做现状登记，不修：`cors` 挂在两个限流器之前，对**任何** OPTIONS
 * 直接 `res.writeHead(204); res.end()`。我此前据此推断"Express 会回显 `Allow`，
 * 构成未认证的路由/方法存在性 oracle"——实测**证伪**（见第三个用例的四种形态）：
 * 2.8.6 连 `Origin` 都不要求，存在与不存在的路径返回逐字段同构的 204，既无 `Allow`
 * 也无 `Access-Control-Allow-Origin`。真正剩下的只有" OPTIONS 不吃配额"，而其一发的
 * 代价是一次表头写出（无 body 解析、无业务、无审计写入），与【一】修掉的
 * 「零配额 × 1MB JSON 解析 × 四条闸门」不是同一量级；把限流器前移到 `cors` 之前会让
 * 浏览器的预检开始消耗真实请求配额，代价大于收益。故本用例钉住的是**不变量**
 * （不反射 Origin、不作为 oracle、不写审计），任一被破坏都会红。
 */
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const request = require('supertest');
const { randomPassword } = require('../helpers/buildLoginEnvelope');

// —— 必须早于 require('../../app')：config 与两个 limiter 都在模块加载期取值 ——
const SAVED_ENV = {};
[
  'RATE_LIMIT_MAX_REQUESTS',
  'RATE_LIMIT_WINDOW_MS',
  'RATE_LIMIT_IP_MAX_REQUESTS',
  'RATE_LIMIT_IP_WINDOW_MS',
  'TRUST_PROXY_HOPS',
].forEach((key) => {
  SAVED_ENV[key] = process.env[key];
});
const MAX_GENERAL = 3;
const FLOOD = 8;
process.env.RATE_LIMIT_MAX_REQUESTS = String(MAX_GENERAL);
process.env.RATE_LIMIT_WINDOW_MS = '900000';
process.env.RATE_LIMIT_IP_MAX_REQUESTS = '100000';
process.env.RATE_LIMIT_IP_WINDOW_MS = '900000';
process.env.TRUST_PROXY_HOPS = '1';

const stamp = `zpe${Date.now().toString(36)}`.slice(0, 9);
const RATE_PREFIXES = ['ratelimit', 'x-ratelimit'];

/** 限流是否真的作用于这一发：被 skip 的请求不会带出任何 RateLimit-* 头 */
const rateHeaders = (res) =>
  Object.keys(res.headers).filter((h) => RATE_PREFIXES.some((p) => h.toLowerCase().startsWith(p)));

describe('探针豁免的边界与 HEAD 审计留痕', () => {
  let app;
  let AuditLog;
  let username;
  let userToken;

  /** 每个用例一个独立 IP：两个 limiter 在模块加载期创建，同文件共用同一份配额 */
  const freshIp = (n) => `10.64.${n}.1`;

  const auditCount = () => AuditLog.countDocuments({ username });

  /**
   * 取审计计数前先**主动冲刷**缓冲（services/auditBuffer.flush）。
   *
   * 这里不能用"轮询到数值稳定"：落库有几倍轮询间隔的延迟，第一次读 0、第二次还是 0
   * 就已经"稳定"了 ⇒ 用例立刻拿到修复前的值，红得有理由但理由错位（我第一版就是这样
   * 把 HEAD 的用例跑成"GET 也 0"）。反过来，纯 sleep 又会在缓冲被别的用例拖慢时
   * 误报。flush 把这两条都消掉：读到的就是此刻的全部。
   */
  const settleAudit = async () => {
    const auditBuffer = require('../../services/auditBuffer');
    if (typeof auditBuffer.flush === 'function') await auditBuffer.flush();
    return auditCount();
  };

  /**
   * 本用例刚落库的那一行。排序口径直接沿用审计列表游标的权威形状 `{ timestamp:-1, _id:-1 }`
   * （models/AuditLog.js:244 注释：同一毫秒要靠 `_id` 打散），
   * 这样"取最新"不会因为两行时间戳并列而回到未定义顺序。
   */
  const newestRow = async () =>
    (await AuditLog.find({ username }).sort({ timestamp: -1, _id: -1 }).limit(1))[0];

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) await mongoose.connect(process.env.MONGODB_URI);
    const User = require('../../models/User');
    const Role = require('../../models/Role');
    const Permission = require('../../models/Permission');
    AuditLog = require('../../models/AuditLog');
    require('../../models/TokenBlacklist');
    require('../../models/FireDevice');
    require('../../models/FireAlarm');
    require('../../models/Inspection');

    const p = await Permission.create({
      name: `${stamp} 读用户`,
      code: 'user:read',
      type: 'api',
      module: 'user',
    });
    const role = await Role.create({
      name: `${stamp} 角色`,
      code: `${stamp}_role`,
      level: 10,
      permissions: [p._id],
    });
    username = `${stamp}_u`;
    const u = await User.create({
      username,
      email: `${username}@example.com`,
      password: randomPassword(),
      roles: [role._id],
    });
    userToken = jwt.sign(
      { userId: String(u._id), username: u.username, tokenVersion: u.tokenVersion ?? 0 },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );
    const { createApp } = require('../../app');
    app = createApp();
  });

  afterAll(async () => {
    await AuditLog.deleteMany({ username: new RegExp(`^${stamp}`) }).catch(() => {});
    await mongoose.connection.close().catch(() => {});
    Object.entries(SAVED_ENV).forEach(([key, value]) => {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    });
  });

  test('子树与「精确探针路径 + 非探针方法」都不再免检（闸门与限流两侧同时生效）', async () => {
    const ip = freshIp(1);
    const calls = [
      { label: 'POST /health/zznope（子树）', path: '/health/zznope' },
      { label: 'POST /health（精确路径、非探针方法）', path: '/health' },
      { label: 'POST /readyz/x', path: '/readyz/x' },
    ];
    for (const c of calls) {
      const res = await request(app)
        .post(c.path)
        .set('Content-Type', 'text/plain')
        .set('X-Forwarded-For', ip)
        .send('x'.repeat(64));
      // 415 出自 protocolCompliance 自己的媒体类型闸 ⇒ 闸门确实碰了这一发
      expect({ label: c.label, status: res.status, code: res.body?.errors?.errorCode }).toEqual({
        label: c.label,
        status: 415,
        code: 'CONTENT_TYPE_UNSUPPORTED',
      });
      // 限流侧同样计入（原缺陷：这两个 limiter 的 skip 把它整棵子树放行）
      expect(rateHeaders(res).length).toBeGreaterThan(0);
    }
  });

  test('探针路径上的 body 洪水必须撞 429（修复前 40 发 200KB JSON 一条 429 都没有）', async () => {
    const ip = freshIp(2);
    const statuses = [];
    for (let i = 0; i < FLOOD; i += 1) {
      const res = await request(app)
        .post('/health/zzflood')
        .set('X-Forwarded-For', ip)
        .send({ payload: 'y'.repeat(200 * 1024) });
      statuses.push(res.status);
    }
    // Content-Type 合法 ⇒ 前 MAX 条过闸后落到兜底 404；其后必须全部 429
    expect(statuses.slice(0, MAX_GENERAL)).toEqual(new Array(MAX_GENERAL).fill(404));
    expect(statuses.slice(MAX_GENERAL)).toEqual(new Array(FLOOD - MAX_GENERAL).fill(429));
  });

  test('反向对照：GET/HEAD 探活在同 IP 配额耗尽后仍然整体豁免（不带 RateLimit 头）', async () => {
    const ip = freshIp(3);
    // 先把这个 IP 的通用配额吃干（探针路径上的 POST 已计入配额）
    for (let i = 0; i < MAX_GENERAL + 1; i += 1) {
      await request(app).post('/health/x').set('X-Forwarded-For', ip).send({ a: 1 });
    }
    const probes = ['/health', '/HEALTH', '/health/', '/readyz', '/ReadyZ/'];
    for (const probe of probes) {
      const res = await request(app).get(probe).set('X-Forwarded-For', ip);
      // 部署事故的形态就是这里变 429：容器 HEALTHCHECK / ci.yml / deploy.js 全部恒红
      expect({ probe, status: res.status, rate: rateHeaders(res) }).toEqual({
        probe,
        status: 200,
        rate: [],
      });
    }

    const headRes = await request(app).head('/health').set('X-Forwarded-For', ip);
    expect(headRes.status).toBe(200);
    expect(rateHeaders(headRes)).toEqual([]);
  });

  test('HEAD 打到敏感读取路径：业务全量执行且留下与 GET 同尺的 action', async () => {
    const before = await settleAudit();

    const get = await request(app)
      .get('/api/users')
      .set('Authorization', `Bearer ${userToken}`)
      .set('X-Forwarded-For', freshIp(4));
    expect(get.status).toBe(200);
    const afterGet = await settleAudit();
    const getRow = await newestRow();

    const head = await request(app)
      .head('/api/users')
      .set('Authorization', `Bearer ${userToken}`)
      .set('X-Forwarded-For', freshIp(4));
    // 200 是"处理函数真的跑了"的前提（Express 把 HEAD 归一成 GET）
    expect(head.status).toBe(200);
    const afterHead = await settleAudit();
    const headRow = await newestRow();

    expect(afterGet - before).toBe(1);
    expect(afterHead - afterGet).toBe(1);

    // 逐次取"刚落库的那一行"，不对整个 username 的行集合取原序：
    // OPTIONS 用例里也有一发真实 `GET /api/users`（它写的是同一个 username），
    // 按"该用户名下恰好两行且 GET 在前"取原序＝把文件内用例顺序当契约
    // ——`--randomize --seed=20260917` 下单文件即可复现多出的那个 "GET"。
    // 两条 +1 增量已经钉住"每次调用恰好一行"，所以这里读最新行的 method/action
    // 是等强且顺序无关的口径。
    expect([getRow.method, headRow.method]).toEqual(['GET', 'HEAD']);
    // action 必须与 GET 同尺：`user_head` 不在 AUDIT_LOG_ACTIONS 里，审计页筛不到
    expect([getRow.action, headRow.action]).toEqual(['user_view', 'user_view']);
  });

  test('反向对照：非敏感读取白名单的路径，GET 与 HEAD 都不产生审计', async () => {
    const before = await settleAudit();
    // device:read 不在这个账号上 ⇒ 403，但 403 与否都不该写审计（判据是路径不在白名单）

    const get = await request(app)
      .get('/api/devices')
      .set('Authorization', `Bearer ${userToken}`)
      .set('X-Forwarded-For', freshIp(5));

    const head = await request(app)
      .head('/api/devices')
      .set('Authorization', `Bearer ${userToken}`)
      .set('X-Forwarded-For', freshIp(5));
    expect([get.status, head.status]).toEqual([403, 403]);
    expect(await settleAudit()).toBe(before);
  });

  test('OPTIONS 现状：cors 早于限流短路，但既不反射 Origin 也不是路由 oracle', async () => {
    const shapes = [
      {
        label: '预检（Origin + ACRM）',
        res: await request(app)
          .options('/api/users')
          .set('Origin', 'http://localhost:5173')
          .set('Access-Control-Request-Method', 'POST')
          .set('X-Forwarded-For', freshIp(6)),
      },
      {
        label: 'Origin 但无 ACRM',
        res: await request(app)
          .options('/api/users')
          .set('Origin', 'http://localhost:5173')
          .set('X-Forwarded-For', freshIp(6)),
      },
      {
        label: '完全无 Origin',
        res: await request(app).options('/api/users').set('X-Forwarded-For', freshIp(6)),
      },
      {
        label: '不存在的路径',
        res: await request(app)
          .options('/api/zznotaroute')
          .set('Origin', 'http://localhost:5173')
          .set('X-Forwarded-For', freshIp(6)),
      },
    ];
    for (const { label, res } of shapes) {
      // 204 + 零 RateLimit 头 = cors 在两个 limiter 与协议闸门之前就 res.end() 了
      expect({ label, status: res.status, rate: rateHeaders(res) }).toEqual({
        label,
        status: 204,
        rate: [],
      });
      // 不反射 Origin（`origin` 是白名单数组，非白名单/缺 Origin 都拿不到 ACAO），
      // 也不回显 Allow ⇒ 四种形态逐字段同构，无法据此判断路径是否存在
      expect({
        label,
        acao: res.headers['access-control-allow-origin'],
        allow: res.headers.allow,
        body: res.body,
      }).toEqual({ label, acao: undefined, allow: undefined, body: {} });
    }
    expect(shapes[0].res.headers['access-control-allow-methods']).toBe(
      shapes[3].res.headers['access-control-allow-methods']
    );

    // 反向对照：真实请求同样跨域发起，但会带上限流头 ⇒ "免配额"只属于 OPTIONS
    const real = await request(app)
      .get('/api/users')
      .set('Authorization', `Bearer ${userToken}`)
      .set('Origin', 'http://evil.example.com')
      .set('X-Forwarded-For', freshIp(8));
    expect([real.status, real.headers['access-control-allow-origin']]).toEqual([200, undefined]);
    expect(rateHeaders(real).length).toBeGreaterThan(0);

    // 零成本的另一半证据：OPTIONS 连审计都不落（否则未认证一发就能写一条链）
    const before = await settleAudit();
    for (let i = 0; i < 5; i += 1) {
      await request(app).options('/api/users').set('X-Forwarded-For', freshIp(9));
    }
    expect(await settleAudit()).toBe(before);
  });
});
