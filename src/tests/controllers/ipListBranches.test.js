/**
 * ipListController 分支补齐
 *
 * 依据全量覆盖率的未覆盖分支行号（securityDeep 已覆盖 CRUD 正向与全网段
 * 超管成功路径，这里补齐校验/冲突/拒绝侧）：
 *  - getIPList：路由校验链消费（L29-32，?type= 非法值）
 *  - queryIPMatch：缺 IP / CIDR 网段不是合法查询单址（L83-85）
 *  - addIPEntry：IP 必填（L127-129）、type 枚举（L130-132）、
 *    格式非法（L143-145）、时长越界（L147-150）、
 *    全网段非超管 403 + critical 审计（L161-186）、
 *    加黑被白名单覆盖冲突 400（L203-212）
 *  - removeIPEntry：记录不存在 404（L266-268）、全网段非超管 403（L282-304）
 *
 * 集成风格：supertest + createApp + JWT 直签（对齐 securityDeep.test.js）。
 */

const request = require('supertest');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const { randomPassword } = require('../helpers/buildLoginEnvelope');

describe('ipListController 分支补齐', () => {
  let app;
  let IPBlacklist;
  let superToken; // 内置超管：造全网段条目与白名单前置
  let secToken; // 安全员（security:config，非超管）：校验/冲突/403 分支主角
  const stamp = `ipl${Date.now()}`.replace(/\d/g, (d) => 'abcdefghij'[Number(d)]);
  const PASSWORD = randomPassword();
  const createdIds = [];

  const signToken = (userId, username) =>
    jwt.sign({ userId, username, tokenVersion: 0 }, process.env.JWT_SECRET, { expiresIn: '1h' });

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    const User = require('../../models/User');
    const Role = require('../../models/Role');
    const Permission = require('../../models/Permission');
    IPBlacklist = require('../../models/IPBlacklist');

    const wildcardPerm = await Permission.findOneAndUpdate(
      { code: '*:*' },
      { $setOnInsert: { name: '全部权限', code: '*:*', type: 'api', module: 'system' } },
      { upsert: true, new: true }
    );
    let builtInSuper = await Role.findOne({ code: 'SUPER_ADMIN' });
    if (!builtInSuper) {
      builtInSuper = await Role.create({
        name: '超级管理员',
        code: 'SUPER_ADMIN',
        level: 10,
        permissions: [wildcardPerm._id],
      });
    }
    const superUser = await User.create({
      username: `iplsuper${stamp}`,
      email: `iplsuper${stamp}@example.com`,
      password: PASSWORD,
      roles: [builtInSuper._id],
    });
    superToken = signToken(String(superUser._id), superUser.username);

    // 安全员：持 security:config 可进 IP 名单接口，但非内置超管
    const configPerm = await Permission.findOneAndUpdate(
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
    const secRole = await Role.create({
      name: `安全员_${stamp}`,
      code: `SEC_OP_${stamp}`,
      level: 5,
      permissions: [configPerm._id],
    });
    const secUser = await User.create({
      username: `iplsec${stamp}`,
      email: `iplsec${stamp}@example.com`,
      password: PASSWORD,
      roles: [secRole._id],
    });
    secToken = signToken(String(secUser._id), secUser.username);

    // 白名单豁免本机回环段：后续用例创建全网段黑名单（0.0.0.0/0）后，
    // checkIPBlacklist 会拦截一切来源 IP（含 supertest 的本机请求），
    // 白名单优先级更高，挂 ipWhitelisted 后 API 才能继续触达控制器分支。
    // 直接经模型层落库（同步名单快照），不依赖 app 实例，且必须先于
    // 任何全网段黑名单条目存在。
    const loopbackWhite = await IPBlacklist.blockIP('127.0.0.0/8', {
      type: 'white',
      reason: '分支补齐-回环豁免前置',
      source: 'manual',
    });
    if (loopbackWhite?._id) createdIds.push(loopbackWhite._id);

    const { createApp } = require('../../app');
    app = createApp();
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      const User = require('../../models/User');
      const Role = require('../../models/Role');
      await User.deleteMany({ username: new RegExp(`^ipl(super|sec)${stamp}$`) }).catch(() => {});
      await Role.deleteMany({ code: new RegExp(`^SEC_OP_${stamp}$`) }).catch(() => {});
      // 清理本文件创建的名单条目（含超管造的全网段/白名单前置与回环豁免）
      await IPBlacklist.deleteMany({
        $or: [
          { ip: { $in: ['10.0.0.0/8', '0.0.0.0/0', '127.0.0.0/8'] } },
          { source: 'manual', reason: /分支补齐/ },
        ],
      }).catch(() => {});
      await mongoose.connection.close();
    }
  });

  const superGet = (url) => request(app).get(url).set('Authorization', `Bearer ${superToken}`);
  const secPost = (url, body) =>
    request(app).post(url).set('Authorization', `Bearer ${secToken}`).send(body);
  const secDel = (url) => request(app).delete(url).set('Authorization', `Bearer ${secToken}`);

  test('GET ?type=非法值 → 路由校验链 400（P3-5：校验结果必须被消费）（L29-32）', async () => {
    const res = await superGet('/api/security/ip-list?type=bogus').set(
      'Authorization',
      `Bearer ${superToken}`
    );
    expect(res.status).toBe(400);
  });

  test('GET /query 缺 IP 或传 CIDR 网段 → 400 仅接受单地址（L83-85）', async () => {
    const empty = await superGet('/api/security/ip-list/query?ip=');
    expect(empty.status).toBe(400);

    const cidr = await superGet('/api/security/ip-list/query?ip=10.0.0.0/8');
    expect(cidr.status).toBe(400);
  });

  test('POST 空 IP → 400（必填校验）（L127-129）', async () => {
    const res = await secPost('/api/security/ip-list', { ip: '', type: 'black' });
    expect(res.status).toBe(400);
  });

  test('POST type 非法 → 400（路由校验器先行拦截，控制器枚举双保险 L130-132）', async () => {
    const res = await secPost('/api/security/ip-list', { ip: '203.0.113.50', type: 'grey' });
    expect(res.status).toBe(400);
  });

  test('POST 非法 IP 文本 → 400 IP_FORMAT_INVALID，拒绝入库死记录（L143-145）', async () => {
    const res = await secPost('/api/security/ip-list', { ip: '999.999.999.999', type: 'black' });
    expect(res.status).toBe(400);
  });

  test('POST durationHours 越界 → 400（0 至 8760 小时）（L147-150）', async () => {
    const res = await secPost('/api/security/ip-list', {
      ip: '203.0.113.51',
      type: 'black',
      durationHours: -5,
    });
    expect(res.status).toBe(400);
  });

  test('POST 全网段 0.0.0.0/0 by 非超管 → 403 + critical 越权审计（L161-186）', async () => {
    const res = await secPost('/api/security/ip-list', { ip: '0.0.0.0/0', type: 'black' });
    expect(res.status).toBe(403);
    expect(res.body.message).toContain('仅超级管理员');
  });

  test('POST 加黑被白名单覆盖 → 400 冲突，信任标记不可被封禁覆盖（L203-212）', async () => {
    // 前置：超管加白 10.0.0.0/8
    const white = await request(app)
      .post('/api/security/ip-list')
      .set('Authorization', `Bearer ${superToken}`)
      .send({ ip: '10.0.0.0/8', type: 'white', reason: '分支补齐-白名单前置' });
    expect([200, 201]).toContain(white.status);
    if (white.body?.data?._id) createdIds.push(white.body.data._id);

    const res = await secPost('/api/security/ip-list', { ip: '10.1.1.1', type: 'black' });
    expect(res.status).toBe(400);
    expect(res.body.message).toContain('已被白名单条目');
  });

  test('DELETE 不存在的记录 → 404（L266-268）', async () => {
    const res = await secDel('/api/security/ip-list/000000000000000000000000');
    expect(res.status).toBe(404);
  });

  test('DELETE 全网段条目 by 非超管 → 403（删除侧对称约束，L282-304）', async () => {
    // 前置：超管创建全网段黑名单条目
    const full = await request(app)
      .post('/api/security/ip-list')
      .set('Authorization', `Bearer ${superToken}`)
      .send({ ip: '0.0.0.0/0', type: 'black', reason: '分支补齐-全网段前置' });
    expect([200, 201]).toContain(full.status);
    const fullId = full.body?.data?._id || full.body?.data?.id;
    if (fullId) createdIds.push(fullId);

    const res = await secDel(`/api/security/ip-list/${fullId}`);
    expect(res.status).toBe(403);
    expect(res.body.message).toContain('仅超级管理员');
  });
});
