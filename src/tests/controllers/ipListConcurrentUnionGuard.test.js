/**
 * 并发并集绕过（round22 B2）——红线用例
 *
 * 被测的不变式：**非内置超管不得使名单覆盖整个地址族**（任一地址族铺满即等价于 /0：全站拒服、
 * 管理员自锁）。判据是「写入后并集是否覆盖整族」，因此它必须对**并发写入**同样成立。
 *
 * 为什么单独立文件：既有的 ipListValidationAndConflictGuards / ipListFullRangeTypedConfirm 都是
 * **顺序单请求**用例，天然构造不出「两个请求都在对方落库之前读快照」的窗口——缺陷存在时它们全绿。
 * 本文件的第 1 条用例就是那个窗口；第 2 条是顺序对照（顺序路径必须仍然 403），用来证明本套件
 * 不是恒绿/恒红：判据被拆掉时第 2 条会红，判据对并发失效时第 1 条会红。
 */

const request = require('supertest');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const { randomPassword } = require('../helpers/buildLoginEnvelope');

describe('ipListController 并发并集绕过', () => {
  let app;
  let IPBlacklist;
  let superToken;
  let secToken;
  const createdUserIds = [];
  const createdRoleIds = [];
  const createdPermIds = [];
  const PASSWORD = randomPassword();
  const stamp = 'conc' + Date.now().toString(36);

  const signToken = (userId, username) =>
    jwt.sign({ userId, username, tokenVersion: 0 }, process.env.JWT_SECRET, { expiresIn: '24h' });

  /** 以安全员（security:config、非内置超管）身份写入一条黑名单条目 */
  const secPost = (body) =>
    request(app)
      .post('/api/security/ip-list')
      .set('Authorization', 'Bearer ' + secToken)
      .send(body);

  const activeEntryIps = async () =>
    (await IPBlacklist.find({ type: 'black' }).lean()).map((e) => e.ip);

  /**
   * 回环**永久**白（durationMs=0）：救援路径判据要求覆盖操作者的白名单永不过期，
   * 缺省 1 小时的临时白不算（一小时后二次自锁）。它同时让 supertest 的本机请求
   * 不会被本套件自己写的黑名单拦成 IP_BLOCKED。
   * beforeEach 会清空名单，故每条用例前都要重播——否则第二条起就变成「无救援路径」。
   */
  const seedRescueWhitelist = () =>
    IPBlacklist.blockIP('127.0.0.0/8', {
      type: 'white',
      reason: '并发并集-回环豁免前置',
      source: 'manual',
      durationMs: 0,
    });

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    const User = require('../../models/User');
    const Role = require('../../models/Role');
    const Permission = require('../../models/Permission');
    require('../../models/AuditLog');
    IPBlacklist = require('../../models/IPBlacklist');
    const { createApp } = require('../../app');
    app = createApp();

    const wildcard = await Permission.findOneAndUpdate(
      { code: '*:*' },
      { $setOnInsert: { name: '全部权限', code: '*:*', type: 'api', module: 'system' } },
      { upsert: true, new: true }
    );
    createdPermIds.push(String(wildcard._id));
    let builtInSuper = await Role.findOne({ code: 'SUPER_ADMIN' });
    if (!builtInSuper) {
      builtInSuper = await Role.create({
        name: '超级管理员',
        code: 'SUPER_ADMIN',
        level: 10,
        permissions: [wildcard._id],
      });
      // 内置角色不可删除（models/Role.js:97），不登记进清理清单
    }
    const superUser = await User.create({
      username: 'concsuper' + stamp,
      email: 'concsuper' + stamp + '@example.com',
      password: PASSWORD,
      roles: [builtInSuper._id],
    });
    createdUserIds.push(String(superUser._id));
    superToken = signToken(String(superUser._id), superUser.username);

    await seedRescueWhitelist();

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
    createdPermIds.push(String(configPerm._id));
    const secRole = await Role.create({
      name: '并发用例安全员' + stamp,
      code: 'CONC_SEC_' + stamp,
      level: 5,
      permissions: [configPerm._id],
    });
    createdRoleIds.push(String(secRole._id));
    const secUser = await User.create({
      username: 'concsec' + stamp,
      email: 'concsec' + stamp + '@example.com',
      password: PASSWORD,
      roles: [secRole._id],
    });
    createdUserIds.push(String(secUser._id));
    secToken = signToken(String(secUser._id), secUser.username);
  });

  afterAll(async () => {
    const User = require('../../models/User');
    const Role = require('../../models/Role');
    const Permission = require('../../models/Permission');
    await IPBlacklist.deleteMany({});
    IPBlacklist.invalidateSnapshot();
    if (createdUserIds.length) await User.deleteMany({ _id: { $in: createdUserIds } });
    if (createdRoleIds.length) await Role.deleteMany({ _id: { $in: createdRoleIds } });
    if (createdPermIds.length) await Permission.deleteMany({ _id: { $in: createdPermIds } });
  });

  beforeEach(async () => {
    await IPBlacklist.deleteMany({});
    IPBlacklist.invalidateSnapshot();
    await seedRescueWhitelist();
  });

  test('并发提交互补 /1：非超管不得造成整族覆盖（任一路径被拒，或最终只落一条）', async () => {
    const { cidrUnionCoversAll } = require('../../utils/cidrCoverage');
    const [r1, r2] = await Promise.all([
      secPost({ ip: '::/1', type: 'black', reason: '并发用例', typedConfirm: '::/1' }),
      secPost({ ip: '8000::/1', type: 'black', reason: '并发用例', typedConfirm: '8000::/1' }),
    ]);

    const ips = await activeEntryIps();
    const coverage = cidrUnionCoversAll(ips);
    const accepted = [r1, r2].filter((r) => r.status === 200).length;
    const refused = [r1, r2].filter((r) => r.status === 403).length;

    // 不变式一：**最终数据库里不得出现整族覆盖**（这是缺陷的判据本体）
    expect({ ips, coversIPv6: coverage.ipv6 }).toEqual({ ips, coversIPv6: false });
    // 不变式二：两个请求不得都成功（至少一个被拒）
    expect(accepted).toBeLessThanOrEqual(1);
    expect(refused).toBeGreaterThanOrEqual(1);
    // 不变式三：最多落一条 —— 两条都在库里就说明回滚/拒绝都失效了
    expect(ips.length).toBeLessThanOrEqual(1);
  });

  test('顺序对照：第一条 200，第二条必须 403（判据本身存在且不是恒拒）', async () => {
    const first = await secPost({
      ip: '::/1',
      type: 'black',
      reason: '顺序对照',
      typedConfirm: '::/1',
    });
    expect(first.status).toBe(200);

    const second = await secPost({
      ip: '8000::/1',
      type: 'black',
      reason: '顺序对照',
      typedConfirm: '8000::/1',
    });
    expect(second.status).toBe(403);
    expect(second.body.errors.errorCode).toBe('FULL_RANGE_FORBIDDEN');
    expect(await activeEntryIps()).toEqual(['::/1']);
  });

  test('对照：内置超管写入互补 /1 仍放行（回滚不得殃及合法路径）', async () => {
    const { cidrUnionCoversAll } = require('../../utils/cidrCoverage');
    const r1 = await request(app)
      .post('/api/security/ip-list')
      .set('Authorization', 'Bearer ' + superToken)
      .send({ ip: '::/1', type: 'black', reason: '超管对照', typedConfirm: '::/1' });
    const r2 = await request(app)
      .post('/api/security/ip-list')
      .set('Authorization', 'Bearer ' + superToken)
      .send({ ip: '8000::/1', type: 'black', reason: '超管对照', typedConfirm: '8000::/1' });
    expect([r1.status, r2.status]).toEqual([200, 200]);
    // 超管本来就该能配全网段（typedConfirm + critical 留痕）：这条对照用来证明回滚判据不是恒拒
    expect(cidrUnionCoversAll(await activeEntryIps()).ipv6).toBe(true);
  });
  test('对照：单条 /24 加黑照常 200（本套件不是恒拒的）', async () => {
    const res = await secPost({
      ip: '203.0.113.0/24',
      type: 'black',
      reason: '对照',
      typedConfirm: '203.0.113.0/24',
    });
    expect(res.status).toBe(200);
    expect(await activeEntryIps()).toEqual(['203.0.113.0/24']);
  });

  afterAll(async () => {
    // 本套件自建连接自己关：mongodb-memory-server 是全仓共享的同一个 mongod，漏关会留下
    // hasRef 的 Socket，jest-worker 到点强杀该 worker 并连带吞掉本套件输出（见
    // src/tests/ci/mongooseTeardownLedger.test.js 头注）。
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });
});
