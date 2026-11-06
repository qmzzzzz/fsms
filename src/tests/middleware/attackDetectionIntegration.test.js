/**
 * 攻击检测面集成测试（真实 express + 内存 MongoDB）。
 *
 * 钉住「请求 → 检测 → 留痕 → 取证标记 → 处置」的全链路，每个样本各对应一类缺口：
 *   ① POST body 带 NoSQL 操作符 → 剥离放行 + nosql_injection_attempt 行（此前的零留痕面）
 *   ② GET query 带 SQLi 特征串 → 放行 + sql_injection_attempt 行（此前的零留痕面）
 *   ③ GET /.env（非 HTML）→ 404 + scan_probe_detected 行 + 取证标记（此前的全盲面）
 *   ④ GET /.env 带 Accept:text/html → SPA 吞成 200，但检测行照写（SPA 吞没补盲）
 *   ⑤ 404 风暴达阈值 → scan_probe_storm 行每窗口只一条
 *   ⑥ 指纹探测洪水撞 429 并接 ANON_ABUSE 升级阶梯（扫描 → 自动封禁链闭合）
 *   ⑦⑧ 注入检测与取证捕获的挂载面是**全站**而非 /api/（挂载面与声称面一致）
 *
 * 检测全部发生在鉴权/路由之前 ⇒ 不带 token 的请求即可触发（攻击者视角本来就是匿名）。
 */

'use strict';

const request = require('supertest');
const mongoose = require('mongoose');

// 风暴阈值压到 5（模块在 require 时读 env，必须先设再 require app）
process.env.SCAN_404_THRESHOLD = '5';
process.env.SCAN_404_WINDOW_MS = '60000';

const AuditLog = require('../../models/AuditLog');
const auditBuffer = require('../../services/auditBuffer');

const { tick } = require('../helpers/pollTick');

const waitForRow = async (action, predicate = () => true, tries = 40) => {
  for (let i = 0; i < tries; i += 1) {
    // 断言的行经真实应用的 auditBuffer 落库：每轮先主动 flush 一次再查，
    // 不依赖缓冲定时器的相位（审计断言受控化，见 auditBufferStartForAuditAssertions）。
    await auditBuffer.flush();
    const row = await AuditLog.findOne({ action }).sort({ timestamp: -1 }).lean();
    if (row && predicate(row)) return row;
    // 真实短延时而非 setImmediate：并行 worker 抢占下纯宏任务轮询会饿死（alarmView 同教训）
    await tick(25);
  }
  return null;
};

describe('攻击检测面 · 真实链路集成', () => {
  let app;

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    // 乱序防护（--randomize 打乱文件内用例顺序）：⑤ 风暴与 ⑥ 洪水会按客户端 IP 留下
    // 持久状态（限流桶 / 封禁行 / 升级计费表），全走 127.0.0.1 会毒化兄弟用例。
    // 开一跳反代形态后各破坏性用例自带互不相同的 XFF IP，状态天然按 IP 隔离；
    // 不带 XFF 的用例 req.ip 仍是 socket 对端 127.0.0.1，行为不变。
    process.env.TRUST_PROXY_HOPS = '1';
    const { createApp } = require('../../app');
    app = createApp();
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
    if (process.env.TRUST_PROXY_HOPS === '1') delete process.env.TRUST_PROXY_HOPS;
    // 检测阈值改为事件时现读后，文件级的压低值会漏给同 worker 的后续套件
    // （阈值 5 对生产形态的默认 40 来说形同无闸）——随套件归还
    delete process.env.SCAN_404_THRESHOLD;
    delete process.env.SCAN_404_WINDOW_MS;
  });

  beforeEach(() => {
    require('../../services/scanProbeDetector').resetScanProbeDetector();
    require('../../services/injectionDetector').resetInjectionDetector();
    // 链僵尸冻结是 worker 级跨文件泄漏：随机序下先跑的套件（auditBufferZombie 类）
    // 触发 freeze 后不随套件复位，本套件 waitForRow 里的主动 flush 会被
    // isChainFrozen 整窗跳过 ⇒ storm/注入行永远落不了库（seed 31337/777001 实测 ⑤ 0 行）。
    require('../../utils/auditChainFence').reset();
  });

  afterEach(async () => {
    // --randomize 打乱文件内用例顺序后，⑥ 洪水与 ⑤ 风暴留下的持久状态会毒化
    // 兄弟用例（③④ 的 /.env 探测在 ⑥ 之后会撞 429 而不是 404）。三份状态各自复位：
    //   ① 限流桶：express-rate-limit 实例内 MemoryStore，走 Store API 的 resetAll；
    //   ② IPBlacklist 封禁行：⑥ 的「扫描→自动封禁链闭合」真落库；
    //   ③ 检测器去重/风暴计数：beforeEach 已复位（与限流桶不同，它们在模块级 Map 里）。
    const rl = require('../../middleware/rateLimit');
    for (const limiter of Object.values(rl)) {
      if (limiter && typeof limiter.store?.resetAll === 'function') limiter.store.resetAll();
    }
    // ⑥ 的扫描→封禁阶梯在 rateLimitEscalation 的进程内计费表里留了 127.0.0.1 记录，
    // 升级闸会把它后续的探测请求直接 429——不清表 ③④ 在乱序下必红。
    require('../../services/rateLimitEscalation').resetForTest();
    const IPBlacklist = require('../../models/IPBlacklist');
    await IPBlacklist.deleteMany({}).catch(() => {});
  });

  test('① body 操作符剥离 → nosql_injection_attempt 行（剥离放行，行为零变更）', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({ username: { $ne: 1 }, password: 'x' });
    expect([400, 401, 403]).toContain(res.status); // 后续校验照常拒绝，检测不改变行为
    const row = await waitForRow('nosql_injection_attempt');
    expect(row).not.toBeNull();
    expect(row.riskFactors).toEqual(['mongo_operator_strip']);
    expect(row.reason).toContain('$ne');
    expect(row.username).toBe('anonymous'); // 未认证探测
  });

  test('② query SQLi 特征串 → sql_injection_attempt 行 + 取证标记', async () => {
    const res = await request(app).get('/api/devices?keyword=union%20select%20*%20from%20users');
    expect([200, 401, 403]).toContain(res.status); // 检测不改变行为
    const row = await waitForRow('sql_injection_attempt');
    expect(row).not.toBeNull();
    expect(row.riskFactors).toEqual(['injection_signature']);
    expect(row.reason).toContain('union');
    const { isForensicTarget } = require('../../services/forensicTrigger');
    expect(isForensicTarget('127.0.0.1')).toBe(true); // 命中即标记取证
  });

  test('③④ 探测路径：非 HTML 404 与（构建产物存在时的）SPA 吞没形态都留痕', async () => {
    // 非 HTML：404 JSON 兜底
    const res404 = await request(app).get('/.env');
    expect(res404.status).toBe(404);
    // HTML：生产有 dist 时被 SPA fallback 吞成 200 index.html（此前这条链路完全无痕）；
    // 测试环境无构建产物、staticFrontend 不挂载 ⇒ 走 404 兜底。两种形态的检测入口都已接线，
    // 断言的是"探测必留痕"，不钉具体响应码
    const resSpa = await request(app).get('/wp-login.php').set('Accept', 'text/html');
    expect([200, 404]).toContain(resSpa.status);

    const row = await waitForRow('scan_probe_detected');
    expect(row).not.toBeNull();
    expect(row.riskFactors).toContain('scanner_path');
    // 两个不同探测路径各留一行（IP+path 60s 去重不吸收不同路径）
    await new Promise((resolve) => setImmediate(resolve));
    const rows = await AuditLog.find({ action: 'scan_probe_detected' }).lean();
    expect(rows.length).toBeGreaterThanOrEqual(2);
  });

  test('⑤ 404 风暴：达阈值写一次 storm 行，窗口内不重复', async () => {
    // 乱序防护：本用例自己的精确时间窗起点——AuditLog 是全库查询，乱序下 ⑥/③④ 的
    // 探测也可能各写一行 storm（beforeEach 已复位计数器，各行都是各自窗口的合法产出），
    // 「同窗内不重复」只对本用例的探测序列成立。起点不回拨：回拨会把紧邻前序用例
    // （如 ⑥）刚写的 storm 行吞进本窗。
    const startedAt = new Date();
    for (let i = 0; i < 5; i += 1) {
      await request(app).get(`/storm-probe-${i}`).set('x-forwarded-for', '198.51.100.5');
    }
    const storm = await waitForRow('scan_probe_storm');
    expect(storm).not.toBeNull();
    expect(storm.riskLevel).toBe('high');
    expect(storm.riskFactors).toContain('unmatched_path_storm');
    await new Promise((resolve) => setImmediate(resolve));
    const storms = await AuditLog.find({
      action: 'scan_probe_storm',
      timestamp: { $gte: startedAt },
    }).lean();
    expect(storms).toHaveLength(1); // 触顶后保留 reported 到窗口过期：同窗内不重复写
  });

  test('⑥ 指纹路径的探测洪水撞 429，并把信号送进封禁阶梯（扫描→自动封禁链闭合）', async () => {
    // 缺陷本体：GET /.env 命中静态面豁免 ⇒ general/ipLimiter 一发不计，实际只进
    // staticSurfaceLimiter（12000/15min，刻意不接升级阶梯）⇒ 扫描永远走不到封禁判据。
    // 现在未匹配点上有一道紧桶：撞上即 429 + noteRateLimitHit('unmatched') → ANON_ABUSE。
    // 只打到第 2 次 429 就停：ANON_ABUSE 阀值是 10，真把 127.0.0.1 封进名单会污染同库的其他套件。
    let limited = 0;
    let sent = 0;
    for (let i = 0; i < 26 && limited < 2; i += 1) {
      // ⑥ 用独立 XFF IP：洪水的限流桶/封禁行/升级记录全落它名下，不毒化同文件兄弟用例
      // 与 ⑤ 的 198.51.100.5 分属不同 /24：风暴指纹是网段级（轮换 IP 封顶设计），
      // 同 /24 的两个 IP 会共享同一份风暴计数/窗口，乱序下互相污染
      const res = await request(app).get('/.env').set('x-forwarded-for', '203.0.113.66');
      sent += 1;
      if (res.status !== 429) {
        expect(res.status).toBe(404); // 未触顶前一律照旧 404，处置不改变检测面
        continue;
      }
      limited += 1;
      expect(res.body).toEqual({ success: false, message: '请求过于频繁，请稍后再试' });
      expect(res.headers['cache-control']).toContain('no-store');
    }
    expect({ sent, limited }).toEqual({ sent: expect.any(Number), limited: 2 });
    const anon = require('../../services/rateLimitEscalation').peekIp('203.0.113.66');
    expect(anon.ANON_ABUSE.byLimiter.unmatched).toBeGreaterThanOrEqual(1);
  });

  test('⑦ 注入特征检测覆盖非 /api 路径（挂载面与声称面一致）', async () => {
    // injectionSignature 的文件头自称要补"非 /api 早拒绝段全部无痕"，而挂载曾带 '/api/' 前缀
    const res = await request(app).get("/?q=' or 1=1 --");
    expect([200, 404]).toContain(res.status); // detect-only：不阻断、不改变响应
    const row = await waitForRow('sql_injection_attempt', (r) => r.path === '/');
    expect(row).not.toBeNull();
    expect(row.reason).toContain('or 1');
  });

  test('⑧ 取证捕获覆盖非 /api 路径（标记 IP 的后续请求真的落取证集合）', async () => {
    // forensicTrigger 的文件头与 scanProbeDetector 的留痕注释都声称"标记后捕获后续请求"，
    // 而 forensicCapture 曾挂 '/api/' 前缀 ⇒ 被标记的 IP 打非 /api 面时一条都不落。
    // 这里显式标记（不依赖前序用例的副作用），再打一个必然未匹配的非 /api 路径。
    const capture = require('../../services/forensicCapture');
    const probePath = '/forensic-nonapi-probe';
    // 先把索引建完：本用例是该集合在本套件里的首次访问，autoIndex 会与 afterAll 的
    // 关连接赛跑，留下"client was closed"的索引失败噪声（结论不变，但噪声会掩盖真错）
    await capture.captureModel().init();
    require('../../services/forensicTrigger').markForensicTarget('127.0.0.1', {
      reason: 'integration_global_mount',
      source: 'attackDetectionIntegration',
    });
    expect(capture.shouldCapture('127.0.0.1')).toBe(true); // 开关未关，标记已生效

    const res = await request(app).get(probePath);
    expect([200, 404]).toContain(res.status); // 捕获不改变响应
    await capture.flush(); // 缓冲 2s 定时刷，用例内显式刷一次，不靠 sleep
    const docs = await capture.captureModel().find({ path: probePath }).lean();
    expect(docs.length).toBeGreaterThanOrEqual(1);
    expect(docs[0].ip).toBe('127.0.0.1');
    expect(docs[0].method).toBe('GET');
  });
});
