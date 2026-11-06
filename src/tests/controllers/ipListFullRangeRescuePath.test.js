'use strict';

/**
 * 全网段黑名单的**救援路径**：写下去之后，操作者自己还能不能解开
 *
 * 第 22 轮实测（work/lead/_b1probe.js）：
 *   超管带逐字确认写 `0.0.0.0/0` 黑名单 ⇒ 200；此后同一操作者的一切自救尝试全部 403 IP_BLOCKED——
 *   `/health`、`/api/security/ip-list`（连列表都读不到，故也拿不到 `_id` 去删）、
 *   `DELETE /api/security/ip-list/:id`、加白 `127.0.0.1`、`POST /api/auth/login`、`/readyz`——
 *   唯一恢复手段是直连数据库改库。这不是"权限收紧"，是把一个不可逆动作交给一次点击：
 *   逐字确认挡得住手滑，挡不住"确认完就把全站连同自己一起封死"。
 *
 * 对照实测：**先把操作者来源 IP 放进白名单**（`127.0.0.0/8` 白，永久），再写同一个 `/0` 黑，
 *   则 rescue-write 200 / rescue-delete 200 / rescue-health 200 —— 系统可恢复。
 *   机制是既有的：`middleware/security/ipBlacklist.js:138` 白名单命中即 `next()`，先于 `:188` 的 IP_BLOCKED。
 *
 * 故判据是「写 /0 黑名单之前，操作者自己的来源 IP 必须已被**永不过期**的白名单条目覆盖」。
 * 三条不可放宽的细节（每条都有对应的失败形态）：
 *   ①  取值必须用 `clientIpForSecurityDecision`，与拦截中间件同一把尺。
 *       若闸门读 `req.ip`、中间件读 `clientIpForSecurityDecision`，带一个 X-Forwarded-For 就能让闸门
 *       看到"已白名单的 1.2.3.4"而中间件仍按 socket 对端判 ⇒ 闸门放行、人照样锁死（假救援）。
 *   ②  救援条目必须永不过期（`expiresAt === null`）。临时白名单 1 小时 + 永久 /0 = 1 小时后二次自锁，
 *       而那时已经没人能登录去修。判据里显式要求 `!entry.expiresAt`，不只是"覆盖"。
 *   ③  覆盖判定用 CIDR 语义（`entryCovers`/快照匹配），不是字符串相等：运维的白名单通常是
 *       `10.0.0.0/8` 这种段，逼他加一条 /32 精确条目只会让白名单更碎。
 *
 * 反向要求（防"恒拒"假绿）：加白 /0 **不需要**救援路径——加白不拦任何人，写下去不会自锁。
 */

const request = require('supertest');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const { randomPassword } = require('../helpers/buildLoginEnvelope');

describe('全网段黑名单必须先有可用的救援路径', () => {
  let app;
  let IPBlacklist;
  let AuditLog;
  let superToken;
  let superUserId;
  const stamp = `frz${Date.now()}`.replace(/\d/g, (d) => 'abcdefghij'[Number(d)]);
  const PASSWORD = randomPassword();
  const FULL_RANGE = '0.0.0.0/0';
  const V6_FULL_RANGE = '::/0';
  const LOOPBACK_CIDR = '127.0.0.0/8';

  const post = (body) =>
    request(app)
      .post('/api/security/ip-list')
      .set('Authorization', `Bearer ${superToken}`)
      .send(body);

  const addFullRangeBlack = (typedConfirm = FULL_RANGE) =>
    post({ ip: FULL_RANGE, type: 'black', reason: '救援路径用例', typedConfirm });

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    const User = require('../../models/User');
    const Role = require('../../models/Role');
    const Permission = require('../../models/Permission');
    IPBlacklist = require('../../models/IPBlacklist');
    AuditLog = require('../../models/AuditLog');

    const wildcard = await Permission.findOneAndUpdate(
      { code: '*:*' },
      { $setOnInsert: { name: '全部权限', code: '*:*', type: 'api', module: 'system' } },
      { upsert: true, new: true }
    );
    let superRole = await Role.findOne({ code: 'SUPER_ADMIN' });
    if (!superRole) {
      superRole = await Role.create({
        name: '超级管理员',
        code: 'SUPER_ADMIN',
        level: 10,
        permissions: [wildcard._id],
      });
    }
    const u = await User.create({
      username: `frzsuper${stamp}`,
      email: `frzsuper${stamp}@example.com`,
      password: PASSWORD,
      roles: [superRole._id],
    });
    superUserId = String(u._id);
    superToken = jwt.sign(
      { userId: superUserId, username: u.username, tokenVersion: 0 },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

    const { createApp } = require('../../app');
    app = createApp();
  });

  afterEach(async () => {
    // 每条用例后立刻收回 /0：留到下一次会让后续请求先撞 IP_BLOCKED（失败原因错位）
    await IPBlacklist.deleteMany({ ip: FULL_RANGE });
    await IPBlacklist.deleteMany({ ip: LOOPBACK_CIDR });
    await IPBlacklist.deleteMany({ ip: V6_FULL_RANGE });
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      const User = require('../../models/User');
      await User.deleteMany({ username: new RegExp(`^frzsuper${stamp}$`) }).catch(() => {});
      await IPBlacklist.deleteMany({
        $or: [{ ip: { $in: [FULL_RANGE, LOOPBACK_CIDR] } }, { reason: /救援路径/ }],
      }).catch(() => {});
      await mongoose.connection.close();
    }
  });

  test('前提自证：同一操作者写普通白名单条目成功（证明权限链与校验链都通，下面每条"被拒"不是权限不足）', async () => {
    const ok = await post({ ip: '198.51.100.7', type: 'white', reason: '救援路径-前提' });
    expect(ok.status).toBe(200);
    await IPBlacklist.deleteMany({ ip: '198.51.100.7' });
  });

  test('无救援路径时写 /0 黑名单 → 400，且点名原因码，且不落库', async () => {
    const res = await addFullRangeBlack();
    expect(res.status).toBe(400);
    expect(res.body.errors.errorCode).toBe('IP_SEGMENT_WRITE_REFUSED');
    // 原因码必须与"缺确认串"可区分：两种情况的前端下一步动作完全不同
    // （缺确认 → 敲一遍再来；缺救援 → 先去加白自己，敲多少遍都没用）
    expect(res.body.errors.reason).toBe('no_rescue_path');
    expect(await IPBlacklist.countDocuments({ ip: FULL_RANGE })).toBe(0);
  });

  test('救援路径是**临时**白名单（有 expiresAt）⇒ 仍然拒绝：1 小时后会二次自锁', async () => {
    // 显式 1 小时（durationHours=1），不是永久的
    await IPBlacklist.blockIP(LOOPBACK_CIDR, {
      type: 'white',
      reason: '救援路径-临时白',
      source: 'manual',
      durationMs: 3600 * 1000,
    });
    const res = await addFullRangeBlack();
    expect(res.status).toBe(400);
    expect(res.body.errors.reason).toBe('no_rescue_path');
    expect(await IPBlacklist.countDocuments({ ip: FULL_RANGE })).toBe(0);
  });

  test('救援路径是**永久**白名单 ⇒ 放行，且写入后可删、系统仍可用（闭环自证）', async () => {
    await IPBlacklist.blockIP(LOOPBACK_CIDR, {
      type: 'white',
      reason: '救援路径-永久白',
      source: 'manual',
      durationMs: 0,
    });
    const res = await addFullRangeBlack();
    expect(res.status).toBe(200);
    expect(await IPBlacklist.countDocuments({ ip: FULL_RANGE, type: 'black' })).toBe(1);

    // 闭环：写入之后真的还能删掉（不是"写进去了就算过"）
    const doc = await IPBlacklist.findOne({ ip: FULL_RANGE, type: 'black' });
    const del = await request(app)
      .delete(`/api/security/ip-list/${doc._id}`)
      .set('Authorization', `Bearer ${superToken}`);
    expect(del.status).toBe(200);
    expect(await IPBlacklist.countDocuments({ ip: FULL_RANGE })).toBe(0);

    // 而且服务仍对操作者可达（白名单优先）
    const health = await request(app).get('/health');
    expect(health.status).toBe(200);
  });

  test('覆盖判定按 CIDR 语义：白名单是 /8 段且操作者落在其中，同样算有救援路径', async () => {
    // 上面几条用的就是 /8（127.0.0.0/8 覆盖 127.0.0.1），本条显式钉住"不是字符串相等"
    await IPBlacklist.blockIP(LOOPBACK_CIDR, {
      type: 'white',
      reason: '救援路径-CIDR覆盖',
      source: 'manual',
      durationMs: 0,
    });
    const res = await addFullRangeBlack();
    expect(res.status).toBe(200);
  });

  test('反向要求：加白 /0 不需要救援路径（加白不拦任何人，写下去不会自锁）', async () => {
    const res = await post({
      ip: FULL_RANGE,
      type: 'white',
      reason: '救援路径-加白豁免',
      typedConfirm: FULL_RANGE,
    });
    expect(res.status).toBe(200);
    expect(await IPBlacklist.countDocuments({ ip: FULL_RANGE, type: 'white' })).toBe(1);
  });

  test('缺救援路径的拒绝要留可检索的痕迹（否则事后只能说「好像有人试过」）', async () => {
    const res = await addFullRangeBlack();
    expect(res.status).toBe(400);
    // 留痕是 fire-and-forget 审计写（b820c32 同判例）：响应先回、行异步落库，
    // 随机序高负载下立即 findOne 会读到 null——轮询到真实条件成立再断言细节
    const { waitFor } = require('../helpers/waitFor');
    await waitFor(
      async () => {
        const audit = await AuditLog.findOne({
          action: 'privilege_escalation',
          'body.ip': FULL_RANGE,
          success: false,
          riskFactors: 'full_range_cidr_no_rescue_path',
        }).lean();
        return Boolean(audit);
      },
      { label: 'full_range 拒绝痕迹落库' }
    );
    const audit = await AuditLog.findOne({
      action: 'privilege_escalation',
      'body.ip': FULL_RANGE,
      success: false,
      riskFactors: 'full_range_cidr_no_rescue_path',
    }).lean();
    expect(audit).toBeTruthy();
    expect(audit.riskLevel).toBe('critical');
    expect(String(audit.userId)).toBe(superUserId);
  });

  test('边界：地址族不对口不构成救援——IPv6 整族白救不了 IPv4 整族黑', async () => {
    // 判据读的是操作者来源 IP（此处是 IPv4 回环）。一条 ::/0 永久白覆盖不了它，
    // 所以写 0.0.0.0/0 黑仍然自锁 ⇒ 必须拒。跨族放行会得到一个"看起来有救援路径"的假绿。
    const white = await post({
      ip: V6_FULL_RANGE,
      type: 'white',
      reason: '救援路径-v6整族白',
      typedConfirm: V6_FULL_RANGE,
    });
    expect(white.status).toBe(200);

    const res = await addFullRangeBlack();
    expect(res.status).toBe(400);
    expect(res.body.errors.reason).toBe('no_rescue_path');
    expect(await IPBlacklist.countDocuments({ ip: FULL_RANGE, type: 'black' })).toBe(0);
    const health = await request(app).get('/health');
    expect(health.status).toBe(200);
  });

  test('边界：族不对口但操作者仍可达时放行——只有 IPv4 永久白时写 IPv6 整族黑', async () => {
    // 反向对照（防恒拒）：IPv6 整族黑拦不到 IPv4 来源，而操作者的 IPv4 地址已被永久白覆盖，
    // 故写下去不会自锁。若这条被判据拒掉，说明判据退化成"整族一律拒"，那也是错的。
    await IPBlacklist.blockIP(LOOPBACK_CIDR, {
      type: 'white',
      reason: '救援路径-v4救v6',
      source: 'manual',
      durationMs: 0,
    });
    const res = await post({
      ip: V6_FULL_RANGE,
      type: 'black',
      reason: '救援路径-v6整族黑',
      typedConfirm: V6_FULL_RANGE,
    });
    expect(res.status).toBe(200);
    const doc = await IPBlacklist.findOne({ ip: V6_FULL_RANGE, type: 'black' });
    // 放行 ⇒ 可撤（闭环）：写进去之后操作者自己还能删掉它
    const del = await request(app)
      .delete('/api/security/ip-list/' + doc._id)
      .set('Authorization', 'Bearer ' + superToken);
    expect(del.status).toBe(200);
    const health = await request(app).get('/health');
    expect(health.status).toBe(200);
  });

  test('边界：缺救援路径的拒绝也要回带归一化 expected（客户端才知道该敲什么）', async () => {
    // 与"缺确认串"同一响应码，同一条前端分支：两者都必须回带 expected，否则
    // 用户先把确认串敲对了、再撞上救援路径拒绝时，会拿到一个没有 expected 的响应。
    const res = await addFullRangeBlack();
    expect(res.status).toBe(400);
    expect(res.body.errors.reason).toBe('no_rescue_path');
    expect(res.body.errors.expected).toBe(FULL_RANGE);
  });

  test('边界：救援判定与拦截中间件同一把尺（地址族归一化矩阵）', () => {
    const { ipMatchesEntry } = require('../../utils/ipUtils');
    // IPv4 映射形式必须被 IPv4 段识别：否则闸门看到"已白名单"而中间件照拦 = 假救援
    expect(ipMatchesEntry('::ffff:127.0.0.1', LOOPBACK_CIDR)).toBe(true);
    expect(ipMatchesEntry('::ffff:127.0.0.1', FULL_RANGE)).toBe(true);
    // 判不出地址时不算"已覆盖"：空值对任何段都为假（fail-closed，不是 fail-open）
    expect(ipMatchesEntry('', FULL_RANGE)).toBe(false);
    // 跨族不覆盖（除映射形式）：IPv4 段不覆盖纯 IPv6，反之亦然
    expect(ipMatchesEntry('::1', LOOPBACK_CIDR)).toBe(false);
    expect(ipMatchesEntry('127.0.0.1', V6_FULL_RANGE)).toBe(false);
    expect(ipMatchesEntry('::1', V6_FULL_RANGE)).toBe(true);
  });
});
