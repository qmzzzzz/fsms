/**
 * 升级端点（GET /api/security/upgrade、GET /jobs/:id、POST /requests）
 *
 * 三个失效形态各有用例：
 *   1. 只靠 security:config 就能发布 ⇒ 运维角色被借号即可换生产代码。
 *      故断言「有 security:config 但不是 *:*」得到 SUPER_ADMIN_REQUIRED。
 *   2. 没有步进验证就能入队 ⇒ 被劫持的会话可直接发布。断言缺凭据时 REAUTH_REQUIRED。
 *   3. 入队成功却没有审计/POST 重复提交 ⇒ 无法追溯是谁把生产切到哪个 digest，
 *      或两个任务并发抢同一套颜色。断言 upgrade_triggered 落库 + 第二次 409。
 *
 * 队列目录用真实临时目录：这里验证的正是「写文件」这一契约本身。
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const request = require('supertest');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');

const QUEUE_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'fsms-upgrade-http-'));
process.env.UPGRADE_QUEUE_DIR = QUEUE_DIR;
process.env.UPGRADE_ENABLED = 'true';
process.env.HOT_UPGRADE_REGISTRY_ALLOWLIST = 'ghcr.io/fsms-test/';
process.env.UPGRADE_AGENT_STALE_SECONDS = '600';
process.env.HMAC_SECRET = 'test-hmac-secret-0123456789abcdef';

const DIGEST = `sha256:${'a'.repeat(64)}`;
const IMAGE = `ghcr.io/fsms-test/app@${DIGEST}`;
const PASSWORD = 'Test-Passw0rd!42';

describe('升级端点', () => {
  let app;
  let User;
  let Role;
  let Permission;
  let AuditLog;
  let upgradeConfig;
  let superToken;
  let configToken;
  let plainToken;
  const ids = { users: [], roles: [], permissions: [] };
  const stamp = `up${Date.now()}`;

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) await mongoose.connect(process.env.MONGODB_URI);
    User = require('../../models/User');
    Role = require('../../models/Role');
    Permission = require('../../models/Permission');
    require('../../models/TokenBlacklist');
    AuditLog = require('../../models/AuditLog');
    upgradeConfig = require('../../config/upgrade');

    fs.mkdirSync(upgradeConfig.requestsDir, { recursive: true });
    fs.mkdirSync(upgradeConfig.statusDir, { recursive: true });
    fs.mkdirSync(path.join(upgradeConfig.queueDir, 'processing'), { recursive: true });
    fs.writeFileSync(
      upgradeConfig.heartbeatFile,
      JSON.stringify({ lastSeenAt: new Date().toISOString(), version: 'test', ready: true })
    );

    const wildcard = await Permission.findOneAndUpdate(
      { code: '*:*' },
      { $setOnInsert: { name: '全部权限', code: '*:*', type: 'api', module: 'system' } },
      { upsert: true, new: true }
    );
    ids.permissions.push(wildcard._id);
    const securityConfigPerm = await Permission.findOneAndUpdate(
      { code: 'security:config' },
      {
        $setOnInsert: {
          name: '安全配置',
          code: 'security:config',
          type: 'api',
          module: 'security',
        },
      },
      { upsert: true, new: true }
    );
    ids.permissions.push(securityConfigPerm._id);

    let superRole = await Role.findOne({ code: 'SUPER_ADMIN' });
    if (!superRole) {
      superRole = await Role.create({
        name: '超级管理员',
        code: 'SUPER_ADMIN',
        level: 10,
        permissions: [wildcard._id],
      });
      ids.roles.push(superRole._id);
    }
    const configRole = await Role.create({
      name: `升级运维${stamp}`,
      code: `UPGRADE_OPS_${stamp}`,
      level: 5,
      permissions: [securityConfigPerm._id],
    });
    ids.roles.push(configRole._id);

    const makeUser = async (name, roles) => {
      const user = await User.create({
        username: name,
        email: `${name}@example.com`,
        password: PASSWORD,
        roles,
      });
      ids.users.push(user._id);
      return {
        id: String(user._id),
        token: jwt.sign(
          { userId: String(user._id), username: user.username, tokenVersion: 0 },
          process.env.JWT_SECRET,
          { expiresIn: '7d' }
        ),
      };
    };

    superToken = (await makeUser(`upsuper${stamp}`, [superRole._id])).token;
    configToken = (await makeUser(`upconfig${stamp}`, [configRole._id])).token;
    plainToken = (await makeUser(`upplain${stamp}`, [])).token;

    const { createApp } = require('../../app');
    app = createApp();
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      await User.deleteMany({ username: new RegExp(`^up(super|config|plain)${stamp}$`) }).catch(
        () => {}
      );
      await Role.deleteMany({ _id: { $in: ids.roles } }).catch(() => {});
      await mongoose.connection.close();
    }
    fs.rmSync(QUEUE_DIR, { recursive: true, force: true });
  });

  beforeEach(() => {
    for (const sub of ['requests', 'status', 'processing']) {
      const target = path.join(upgradeConfig.queueDir, sub);
      for (const name of fs.readdirSync(target)) fs.rmSync(path.join(target, name));
    }
  });

  test('未登录 401；无 security:config 403；有该权限可读概览', async () => {
    expect((await request(app).get('/api/security/upgrade')).status).toBe(401);
    expect(
      (await request(app).get('/api/security/upgrade').set('Authorization', `Bearer ${plainToken}`))
        .status
    ).toBe(403);

    const ok = await request(app)
      .get('/api/security/upgrade')
      .set('Authorization', `Bearer ${configToken}`);
    expect(ok.status).toBe(200);
    expect(ok.headers['cache-control']).toMatch(/no-store/);
    expect(ok.body.data.server.buildId.length).toBeGreaterThan(0);
    expect(ok.body.data.upgrade.ready).toBe(true);
    expect(ok.body.data.upgrade.allowlist).toEqual(['ghcr.io/fsms-test/']);
  });

  test('任务 ID 非 UUID 或不存在都按 404 处理（不拼任意路径）', async () => {
    const bad = await request(app)
      .get('/api/security/upgrade/jobs/../../etc/passwd')
      .set('Authorization', `Bearer ${configToken}`);
    expect([404, 400]).toContain(bad.status);

    const missing = await request(app)
      .get('/api/security/upgrade/jobs/550e8400-e29b-41d4-a716-446655440000')
      .set('Authorization', `Bearer ${configToken}`);
    expect(missing.status).toBe(404);
    expect(missing.body.errors.errorCode).toBe('UPGRADE_JOB_NOT_FOUND');
  });

  test('状态文件存在但读不出来 ⇒ 503 UPGRADE_QUEUE_UNAVAILABLE（不许渲染成 404「查无此任务」）', async () => {
    const jobId = '550e8400-e29b-41d4-a716-4466554400dd';
    const statusFile = path.join(upgradeConfig.statusDir, `${jobId}.json`);
    fs.writeFileSync(statusFile, '{ 坏文件', { mode: 0o640 });
    try {
      const res = await request(app)
        .get(`/api/security/upgrade/jobs/${jobId}`)
        .set('Authorization', `Bearer ${configToken}`);
      expect(res.status).toBe(503);
      expect(res.body.errors.errorCode).toBe('UPGRADE_QUEUE_UNAVAILABLE');
    } finally {
      fs.rmSync(statusFile, { force: true });
    }
  });

  test('缺少二次验证凭据时拒绝（被劫持会话不能直接发布）', async () => {
    const res = await request(app)
      .post('/api/security/upgrade/requests')
      .set('Authorization', `Bearer ${superToken}`)
      .send({ image: IMAGE });
    expect(res.status).toBe(403);
    expect(res.body.errors.errorCode).toBe('REAUTH_REQUIRED');
  });

  test('有 security:config 但不是唯一超管 ⇒ SUPER_ADMIN_REQUIRED（即使凭据正确）', async () => {
    const res = await request(app)
      .post('/api/security/upgrade/requests')
      .set('Authorization', `Bearer ${configToken}`)
      .send({ image: IMAGE, currentPassword: PASSWORD });
    expect(res.status).toBe(403);
    expect(res.body.errors.errorCode).toBe('SUPER_ADMIN_REQUIRED');
    expect(fs.readdirSync(upgradeConfig.requestsDir)).toHaveLength(0);
  });

  test('镜像形态错误 400、白名单外 403（输入错误与被拒策略可区分）', async () => {
    const tag = await request(app)
      .post('/api/security/upgrade/requests')
      .set('Authorization', `Bearer ${superToken}`)
      .send({ image: 'ghcr.io/fsms-test/app:v1', currentPassword: PASSWORD });
    expect(tag.status).toBe(400);
    expect(tag.body.errors.errorCode).toBe('UPGRADE_IMAGE_INVALID');

    const foreign = await request(app)
      .post('/api/security/upgrade/requests')
      .set('Authorization', `Bearer ${superToken}`)
      .send({ image: `ghcr.io/attacker/app@${DIGEST}`, currentPassword: PASSWORD });
    expect(foreign.status).toBe(403);
    expect(foreign.body.errors.errorCode).toBe('UPGRADE_IMAGE_NOT_ALLOWED');
    expect(fs.readdirSync(upgradeConfig.requestsDir)).toHaveLength(0);
  });

  test('成功入队：202 + 请求文件 + upgrade_triggered 审计 + 任务详情/概览可见', async () => {
    const before = await AuditLog.countDocuments({ action: 'upgrade_triggered' });
    const res = await request(app)
      .post('/api/security/upgrade/requests')
      .set('Authorization', `Bearer ${superToken}`)
      .send({ image: IMAGE, currentPassword: PASSWORD });

    expect(res.status).toBe(202);
    expect(res.body.data.job.state).toBe('queued');
    expect(res.body.data.job.image).toBe(IMAGE);
    const jobId = res.body.data.job.id;
    expect(fs.existsSync(path.join(upgradeConfig.requestsDir, `${jobId}.json`))).toBe(true);

    const audit = await AuditLog.findOne({ action: 'upgrade_triggered', 'body.jobId': jobId });
    expect(audit).toBeTruthy();
    expect(audit.riskLevel).toBe('high');
    expect(await AuditLog.countDocuments({ action: 'upgrade_triggered' })).toBe(before + 1);

    const detail = await request(app)
      .get(`/api/security/upgrade/jobs/${jobId}`)
      .set('Authorization', `Bearer ${configToken}`);
    expect(detail.status).toBe(200);
    expect(detail.body.data.job.id).toBe(jobId);

    const overview = await request(app)
      .get('/api/security/upgrade')
      .set('Authorization', `Bearer ${configToken}`);
    expect(overview.body.data.upgrade.activeJob.id).toBe(jobId);
  });

  test('同一时间只允许一个任务：第二次入队返回 409 且带 jobId', async () => {
    const first = await request(app)
      .post('/api/security/upgrade/requests')
      .set('Authorization', `Bearer ${superToken}`)
      .send({ image: IMAGE, currentPassword: PASSWORD });
    expect(first.status).toBe(202);

    const second = await request(app)
      .post('/api/security/upgrade/requests')
      .set('Authorization', `Bearer ${superToken}`)
      .send({ image: IMAGE, currentPassword: PASSWORD });
    expect(second.status).toBe(409);
    expect(second.body.errors.errorCode).toBe('UPGRADE_ALREADY_RUNNING');
    expect(second.body.errors.jobId).toBe(first.body.data.job.id);
    expect(fs.readdirSync(upgradeConfig.requestsDir)).toHaveLength(1);
  });

  test("mode='offline' 入队：任务带 mode、审计 body 记 mode（离线来源可追溯）", async () => {
    const res = await request(app)
      .post('/api/security/upgrade/requests')
      .set('Authorization', `Bearer ${superToken}`)
      .send({ image: IMAGE, mode: 'offline', currentPassword: PASSWORD });
    expect(res.status).toBe(202);
    expect(res.body.data.job.mode).toBe('offline');

    const audit = await AuditLog.findOne({
      action: 'upgrade_triggered',
      'body.jobId': res.body.data.job.id,
    });
    expect(audit).toBeTruthy();
    expect(audit.body.mode).toBe('offline');
  });

  test('mode 非法值 400（isIn 白名单）；mode=registry 与缺省行为一致', async () => {
    const bad = await request(app)
      .post('/api/security/upgrade/requests')
      .set('Authorization', `Bearer ${superToken}`)
      .send({ image: IMAGE, mode: 'evil', currentPassword: PASSWORD });
    expect(bad.status).toBe(400);
    expect(fs.readdirSync(upgradeConfig.requestsDir).filter((n) => n.endsWith('.json'))).toEqual(
      []
    );

    const ok = await request(app)
      .post('/api/security/upgrade/requests')
      .set('Authorization', `Bearer ${superToken}`)
      .send({ image: IMAGE, mode: 'registry', currentPassword: PASSWORD });
    expect(ok.status).toBe(202);
    expect(ok.body.data.job.mode).toBe('registry');
  });
});
