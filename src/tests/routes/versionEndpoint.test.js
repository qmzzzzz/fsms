/**
 * 版本元数据端点（GET /api/version）
 *
 * 这个端点是热升级的「感知面」：蓝绿切换后运维靠它确认流量落在哪个构建，
 * 前端靠它发现「服务端已换版、本标签页还是旧壳子」。它自己一旦失效，
 * 升级仍然会发生，但**没有任何人会知道**——所以下面每条都要能被证伪。
 *
 * 三个失效形态，各有用例钉住：
 *   1. 响应被中间层缓存 ⇒ 前端永远比对到旧 buildId，「有更新」检测恒假。
 *      故断言 no-store 且无 ETag（ETag + 304 会让「内容变了却拿到 304」成立）。
 *   2. 端点进审计 ⇒ 每个标签页每 5 分钟一条审计记录，审计链被灌满。
 *      故断言连续请求后审计增量为 0。
 *   3. 响应里混进指纹原料（node 版本、依赖、镜像 digest、env 快照）⇒
 *      匿名可读的端点上等于免费给出 CVE 映射表。故断言只出现约定字段。
 */

const mongoose = require('mongoose');
const request = require('supertest');

const { resolveBuildInfo } = require('../../config/buildInfo');

describe('版本元数据端点', () => {
  let app;
  let AuditLog;

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) await mongoose.connect(process.env.MONGODB_URI);
    AuditLog = require('../../models/AuditLog');
    const { createApp } = require('../../app');
    app = createApp();
  });

  afterAll(async () => {
    await mongoose.connection.close();
  });

  test('匿名可读，返回版本与构建标识（蓝绿切换后靠它确认流量落在哪个构建）', async () => {
    const res = await request(app).get('/api/version');

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(typeof res.body.data.version).toBe('string');
    expect(res.body.data.version.length).toBeGreaterThan(0);
    // buildId 是前端比对用的唯一键，必须存在且非空——为空时比对退化成恒等，
    // 「有新版本」永远不会触发（这正是空 APP_BUILD_ID 赋值会造成的事故）
    expect(typeof res.body.data.buildId).toBe('string');
    expect(res.body.data.buildId.length).toBeGreaterThan(0);
  });

  test('响应不得缓存：no-store + no-cache（否则前端永远比对到旧 buildId）', async () => {
    const res = await request(app).get('/api/version');

    // 只断言 no-store 是不够的：no-store 管「存不存」，no-cache 管「用之前是否回源」，
    // 前者被代理放宽时后者仍能兜住
    expect(res.headers['cache-control']).toMatch(/no-store/);
    expect(res.headers['cache-control']).toMatch(/no-cache/);
    expect(res.headers['cache-control']).toMatch(/max-age=0/);
    // 不得出现任何「可以复用一段时间」的缓存头
    expect(res.headers.expires).toBeUndefined();
  });

  test('不暴露指纹原料：只有约定的四个字段，无 node 版本/依赖/digest/env', async () => {
    const res = await request(app).get('/api/version');

    expect(Object.keys(res.body.data).sort()).toEqual([
      'buildId',
      'buildTime',
      'startedAt',
      'uptimeSec',
      'version',
    ]);
    const raw = JSON.stringify(res.body.data);
    // 逐条钉住「明确不该出现」的东西，防止将来有人顺手把整份 config 塞进来
    expect(raw).not.toMatch(/nodeVersion|node_version|process\.version/i);
    expect(raw).not.toMatch(/digest/i);
    expect(raw).not.toMatch(/dependencies|devDependencies/i);
    expect(raw).not.toMatch(/MONGODB_URI|REDIS|JWT_SECRET|password/i);
  });

  test('不进审计：连续请求后审计增量为 0（否则审计链会被轮询灌满）', async () => {
    const auditBuffer = require('../../services/auditBuffer');
    const settle = async () => {
      if (typeof auditBuffer.flush === 'function') await auditBuffer.flush();
      return AuditLog.countDocuments({});
    };

    const before = await settle();
    for (let i = 0; i < 3; i += 1) {
      // 每发用不同 IP，避免撞上全局限流后拿到 429 而误判为「没进审计」
      const res = await request(app).get('/api/version').set('X-Forwarded-For', `10.99.${i}.7`);
      expect(res.status).toBe(200);
    }
    const after = await settle();

    expect(after - before).toBe(0);
  });
});

describe('构建信息解析（依赖注入，不碰真实环境）', () => {
  test('环境变量优先于 git 回退', () => {
    const info = resolveBuildInfo({
      env: { APP_BUILD_ID: 'sha-abc123', APP_BUILD_TIME: '2026-10-30T01:02:03.000Z' },
      gitSha: () => 'git-should-not-win',
      version: '2.3.4',
      now: Date.parse('2026-10-30T02:00:00.000Z'),
      uptimeSec: 60,
    });

    expect(info.buildId).toBe('sha-abc123');
    expect(info.buildTime).toBe('2026-10-30T01:02:03.000Z');
    expect(info.version).toBe('2.3.4');
    expect(info.startedAt).toBe('2026-10-30T01:59:00.000Z');
  });

  test('空字符串的 APP_BUILD_ID 视为未设置（CI 里 `APP_BUILD_ID=` 很常见）', () => {
    const info = resolveBuildInfo({
      env: { APP_BUILD_ID: '   ' },
      gitSha: () => 'deadbeef1234',
      version: '1.0.0',
    });

    // 若把空串当有效值，所有实例的 buildId 会一起变成 ''，前端比对恒等、永不提示
    expect(info.buildId).toBe('deadbeef1234');
  });

  test('环境变量与 git 都不可用时退到 unknown，而不是抛错', () => {
    const info = resolveBuildInfo({ env: {}, gitSha: () => '', version: '1.0.0' });

    expect(info.buildId).toBe('unknown');
    expect(info.buildTime).toBeNull();
  });

  test('非法构建时间归一为 null（不编造时间戳）', () => {
    const info = resolveBuildInfo({
      env: { APP_BUILD_ID: 'x', APP_BUILD_TIME: 'not-a-date' },
      gitSha: () => '',
      version: '1.0.0',
    });

    expect(info.buildTime).toBeNull();
  });

  test('uptimeSec 不为负（时钟回拨时不得出现负运行时长）', () => {
    const info = resolveBuildInfo({
      env: { APP_BUILD_ID: 'x' },
      gitSha: () => '',
      version: '1.0.0',
      now: Date.parse('2026-10-30T00:00:00.000Z'),
      uptimeSec: -5,
    });

    expect(info.uptimeSec).toBe(0);
  });
});
