/**
 * ──────────────────────────────────────────────────────────────────────────
 * 本文件的定位（2026-09-20 补注，由变异审计批量补齐）
 *
 * 被测对象：src/app.js：trust proxy 跳数夹取、/api 根路径、/readyz 的两种失败路径
 * 守护的不变式：代理跳数必须被夹取到上限（禁 `true`，否则 XFF 可伪造）；/api 根不得返回接口清单；探针自身故障不得冒充 ready
 * 可证伪性：变异实测（N=8 + flake 守卫 + `--no-cache`）：杀 5/12，基线 11 passed
 *
 * 命名沿革：2026-09-20 由 `appBranchBehavior.test.js` 更名。旧名里的
 *   Coverage / Gap / Hardening / Branch 说的是「当初为什么写它」（补覆盖率基线），
 *   **不是它的价值判据**；它能否挡住回归，由变异实测回答，不由文件名回答。
 *   旧名保留在本行，便于既往审计报告的 `grep 旧文件名` 仍能定位到本文件。
 * 依据：`deliverables/AGENT工作总账与待办-2026-09-21.md`（§2.9 测试资产 / §6 方法；原编号 §6-AW/AX/AY/AZ/BA 已随原台账删除，无法逐条映射）
 * ──────────────────────────────────────────────────────────────────────────
 */

/**
 * app.js 未覆盖分支的行为补齐（审计报告 §13 V-12）
 *
 * V-12 原问「app.js 的 16 个未覆盖分支具体是哪些」——答案是当时只有计数，
 * 未逐行解析 lcov。本次改动（2026-09-17）用 `jest --collectCoverageFrom=src/app.js`
 * 实测后逐行定位，其中的分支分两类：
 *
 *  A. **有诊断价值的真实路径**（本文件覆盖）：
 *     - trust proxy 显式有效值（app.js:150）：M-4 收紧后这是生产反代下唯一
 *       让 req.ip 正确的开关。此前只测了「非法值 → 退化 1 跳」，有效值分支零验证——
 *       一旦有人写错 `app.set('trust proxy', true)`（信任全部代理，可伪造 XFF
 *       击穿 IP 限流/黑名单），现有测试不会红。
 *     - /api 根路径（app.js:377）：注释声明「不再返回接口清单」，无测试锁定；
 *       若将来有人改回返回清单，属未认证信息暴露，须在此红。
 *     - /readyz 的 503 双路径（app.js:343-352）：checkMongoReady 返回
 *       not-ok 与**抛错**两种失败。M-1 脱敏（readyzSanitize.test.js）只测了
 *       checkMongoReady 本身，未验证 HTTP 响应体真的不含驱动错误消息——本文件
 *       补上 app 级闭环。
 *
 *  B. Sentry 三件套（app.js:189-190、app.js:429）——**不补测，理由如实记录**：
 *     `sentryInitialized` 是模块级常量，要覆盖需 SENTRY_DSN + 模块重置 + 对
 *     @sentry/node 打桩三件套齐备；而它覆盖的是「SDK 自己的中间件被 app.use」，
 *     属第三方库接线，行为已验证于 middleware/sentry 的单测
 *     （coverageBoostBatch3.test.js 的 handler 透传用例）。花哨的模块重置
 *     只会带来测试脆弱性，不增加防线——故留白而非硬凑。
 */

const ORIGINAL_ENV = process.env;

/** 重载 app 模块（config/app 均在加载期读 env，必须先设 env 再 require） */
const loadApp = () => {
  jest.resetModules();
  return require('../../app');
};

describe('§13 V-12：trust proxy 有效值分支（app.js:150）', () => {
  beforeEach(() => {
    jest.resetModules();
    process.env = { ...ORIGINAL_ENV };
  });

  afterEach(() => {
    process.env = ORIGINAL_ENV;
  });

  test('显式 TRUST_PROXY_HOPS=2：按跳数信任（不是布尔 true，避免信任链无上限）', () => {
    process.env.TRUST_PROXY_HOPS = '2';
    const { createApp } = loadApp();
    const app = createApp();

    // Express 对数字跳数原样存为 number；若误写成布尔 true 会信任整条 XFF 链
    expect(app.get('trust proxy')).toBe(2);
  });

  test('TRUST_PROXY_HOPS=0/负数：不信任代理头（生产直连场景）', () => {
    process.env.NODE_ENV = 'production';
    process.env.TRUST_PROXY_HOPS = '0';
    const { createApp } = loadApp();
    expect(createApp().get('trust proxy')).toBe(false);

    jest.resetModules();
    process.env = { ...ORIGINAL_ENV };
    process.env.NODE_ENV = 'production';
    process.env.TRUST_PROXY_HOPS = '-1';
    const { createApp: createApp2 } = loadApp();
    expect(createApp2().get('trust proxy')).toBe(false);
  });

  test('生产环境未配置：不信任代理头（禁止默认信任，防 XFF 伪造）', () => {
    process.env.NODE_ENV = 'production';
    delete process.env.TRUST_PROXY_HOPS;
    const { createApp } = loadApp();
    expect(createApp().get('trust proxy')).toBe(false);
  });

  test('开发环境未配置：默认信任 1 跳（本机 Vite 代理）', () => {
    process.env.NODE_ENV = 'development';
    delete process.env.TRUST_PROXY_HOPS;
    const { createApp } = loadApp();
    expect(createApp().get('trust proxy')).toBe(1);
  });
  // ============================================================
  // §8.3 点名场景「Trust proxy 过大值」——本次改动复审补测 + 补漏
  // ============================================================
  // 为什么必须测：config/validate.js 有 MAX_TRUST_PROXY_HOPS=5 的上限校验，
  // 但 validateConfig() 首行即对非 production 早退（src/config/validate.js:365），
  // 因此 staging/dev 可以绕过该闸门。而 app.js 原先对 parseInt 结果不做上界
  // 判断，超上限值被原样交给 Express。实测（2026-09-17，Node 24）：
  //   app.set('trust proxy', 999999) + XFF: "1.1.1.1, 2.2.2.2, ..."
  //   → req.ip = 1.1.1.1（即 XFF 链最左元素 = 客户端完全可控）
  // 与 app.set('trust proxy', true) 等价，等于击穿 IP 限流/IP 黑名单/审计溯源。
  // 现 app.js 对所有环境统一夹取到 5，本组用例锁定该行为。
  test('过大值（999999）→ 夹取到上限 5，而非原样信任（防 XFF 伪造轮换 IP）', () => {
    process.env.NODE_ENV = 'staging'; // 刻意非 production：验证它不受 validate 早退影响
    process.env.TRUST_PROXY_HOPS = '999999';
    const { createApp } = loadApp();
    const app = createApp();

    expect(app.get('trust proxy')).toBe(5);
    // 关键对照：绝不能是布尔 true（那会信任整条 XFF 链）
    expect(app.get('trust proxy')).not.toBe(true);
  });

  test('上限边界：5 原样保留，6 夹取为 5（与 config/validate.js 的 MAX 语义一致）', () => {
    process.env.NODE_ENV = 'staging';
    process.env.TRUST_PROXY_HOPS = '5';
    const { createApp } = loadApp();
    expect(createApp().get('trust proxy')).toBe(5);

    jest.resetModules();
    process.env = { ...ORIGINAL_ENV, NODE_ENV: 'staging', TRUST_PROXY_HOPS: '6' };
    const { createApp: createApp2 } = loadApp();
    expect(createApp2().get('trust proxy')).toBe(5);
  });

  test('端到端：超上限时伪造的 XFF 最左段不得成为 req.ip', async () => {
    // 这是「夹取」的安全意义所在——直接把 req.ip 值钉在测试里，
    // 而不是只断言 app.get('trust proxy') 的数字（那是实现细节，可被绕过）。
    process.env.NODE_ENV = 'staging';
    process.env.TRUST_PROXY_HOPS = '999999';
    jest.resetModules();
    process.env = { ...ORIGINAL_ENV, NODE_ENV: 'staging', TRUST_PROXY_HOPS: '999999' };
    require('mongoose').set('bufferTimeoutMS', 300); // 避免 IP 黑名单查询等待 10s
    const { createApp } = loadApp();
    const express = require('express');
    const request = require('supertest');
    const app = express();
    // 只借用被测的 trust proxy 取值，避免为一条断言拉起整个 app
    app.set('trust proxy', createApp().get('trust proxy'));
    app.get('/probe', (req, res) => res.json({ ip: req.ip }));

    const res = await request(app)
      .get('/probe')
      .set('X-Forwarded-For', '1.1.1.1, 2.2.2.2, 3.3.3.3, 4.4.4.4, 5.5.5.5, 6.6.6.6');

    // 夹取到 5 后：从右往左数第 5 跳，而不是最左的 1.1.1.1（纯客户端可控值）
    expect(res.body.ip).not.toBe('1.1.1.1');
    expect(res.body.ip).toBe('2.2.2.2');
  });
});

describe('§13 V-12：/api 根路径不泄露接口清单（app.js:377）', () => {
  const request = require('supertest');
  let app;

  beforeAll(() => {
    process.env.NODE_ENV = 'development';
    app = loadApp().createApp();
  });

  test('GET /api 返回固定成功标记，且**不含**任何接口清单字段', async () => {
    const res = await request(app).get('/api');
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ success: true, message: '消防管理系统 API' });
    // 防回归：早期版本曾返回接口清单（未认证的信息暴露）
    expect(res.body).not.toHaveProperty('endpoints');
    expect(res.body).not.toHaveProperty('routes');
    expect(JSON.stringify(res.body)).not.toContain('/api/auth');
  });
});

describe('§13 V-12：/readyz 的 503 双路径（app.js:334-355）', () => {
  const request = require('supertest');

  /**
   * app.js:57 在**加载期**解构 checkMongoReady，因此必须在 require('../../app')
   * 之前替换 utils/healthChecks 的导出——加载后 spyOn 已经晚了（拿到的是原函数）。
   * 用 jest.resetModules 保证每次拿到全新的模块实例，替换互不串扰。
   */
  const loadAppWithProbe = (probeImpl) => {
    jest.resetModules();
    // 性能：resetModules 后拿到全新 mongoose 实例（与 globalSetup 的连接不共享），
    // 无连接时 IP 黑名单查询默认 buffer 等 10s——本组用例会白等近 50 秒。
    // 压到 300ms：缓存未命中后 fail-open 放行的行为不变，仅省掉无意义等待。
    // 必须在 require(app) 之前设置，否则 app 拿到未打过配置的实例。
    require('mongoose').set('bufferTimeoutMS', 300);
    const healthChecks = require('../../utils/healthChecks');
    healthChecks.checkMongoReady = jest.fn(probeImpl);
    const { createApp } = require('../../app');
    return createApp();
  };

  let savedEnv;

  beforeEach(() => {
    savedEnv = process.env.NODE_ENV;
    process.env.NODE_ENV = 'development';
  });

  afterEach(() => {
    process.env.NODE_ENV = savedEnv;
    jest.resetModules();
  });

  test('checkMongoReady 返回 not-ok：HTTP 503 + 固定枚举，驱动细节不外泄', async () => {
    const leaked = 'MongoServerSelectionError: connect ECONNREFUSED 10.9.9.9:27017 (rs-secret)';
    const app = loadAppWithProbe(async () => ({
      ok: false,
      reason: 'unreachable',
      detail: leaked,
    }));

    const res = await request(app).get('/readyz');

    expect(res.status).toBe(503);
    expect(res.body.status).toBe('unready');
    expect(res.body.checks.mongo).toBe('unreachable');
    // M-1 的 app 级闭环：原始驱动消息只进日志，绝不进响应体
    expect(JSON.stringify(res.body)).not.toContain('10.9.9.9');
    expect(JSON.stringify(res.body)).not.toContain('rs-secret');
    expect(JSON.stringify(res.body)).not.toContain('ECONNREFUSED');
  });

  test('checkMongoReady 抛错：HTTP 503 + checks.mongo=error（探针自身故障也不冒充 ready）', async () => {
    const leaked = 'boom at mongodb://internal-host:27017/secret-db';
    const app = loadAppWithProbe(async () => {
      throw new Error(leaked);
    });

    const res = await request(app).get('/readyz');

    expect(res.status).toBe(503);
    expect(res.body.status).toBe('unready');
    expect(res.body.checks.mongo).toBe('error');
    expect(JSON.stringify(res.body)).not.toContain('internal-host');
    expect(JSON.stringify(res.body)).not.toContain('secret-db');
  });

  test('checkMongoReady 正常：HTTP 200 + ready（对照组，防探针被整体破坏后全 503）', async () => {
    const app = loadAppWithProbe(async () => ({ ok: true, reason: 'ok', detail: '' }));

    const res = await request(app).get('/readyz');

    expect(res.status).toBe(200);
    expect(res.body.status).toBe('ready');
    expect(res.body.checks.mongo).toBe('ok');
  });
});
