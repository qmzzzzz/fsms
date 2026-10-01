const mongoose = require('mongoose');

/**
 * UserSession 的 ip / lastIp 落库闸（2026-10-01 第 6 轮，与 AuditLog 的 ip 同族）。
 *
 * 【缺陷形状（先实测再定性）】`ip` / `lastIp` 都声明了 `maxlength: 64`，而 `lastIp` 的唯一
 * 写入者 `sessionService.touchSession` 用的是 `updateOne(..., { $set })`。Mongoose 的 update
 * 默认**不跑校验**，`maxlength` 又是校验器而非改写器，于是那个 64 在这条最忙的路径上
 * 从未生效过：trust proxy 打开时 `req.ip` 取自 X-Forwarded-For 的可信段，express 不校验其形态
 * （Node 头部上限 ~16KB）⇒ 一个超长 XFF 能把 16KB 写进一条**认证中会话**的文档。
 * 实测：同一条 4011 字符的值，绕过 mongoose 的 driver 直写会原样留存（下面第一条用例），
 * 所以这不是"渲染不好看"而是存储边界失守。
 *
 * 【危害定级（不是高危，写清楚为什么）】`lastIp` 上没有索引（实测本集合索引为
 * _id / sid / status / fingerprint / expiresAt / userId+status+lastSeenAt），因此不存在
 * 「超长键挤掉整行」那条形态，剩下的是无界的请求方可控存储与会话列表渲染负载。
 *
 * 【修法与备选方案的分野】用 schema 的 `set` 而不是 `runValidators: true`：
 * 实测后者会让整条 `$set` 因 ValidationError 被拒——连带 `lastSeenAt` 一起不写，
 * 会话活跃度从此停摆；为一个观测字段做 fail-closed 自伤，正是 createSession
 * 注释（sessionService.js:271-274）已经避过的坑。`set` 在 update 的 `$set` 上同样执行
 * （实测），一处管住 create 与 touch 两条路径。
 */

describe('UserSession 的 ip / lastIp 闸（请求方可控文本的存储边界）', () => {
  let UserSession;
  let sessionService;
  const MAX = 64;
  const stamp = `usip${Date.now().toString(36)}`;
  const userId = new mongoose.Types.ObjectId();
  const LF = String.fromCharCode(10);

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    UserSession = require('../../models/UserSession');
    sessionService = require('../../services/sessionService');
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      await UserSession.collection.deleteMany({ userId });
      await mongoose.connection.close();
    }
  });

  /** 每个用例独立 sid：touchSession 有 60s 节流表，同 sid 第二次调用会直接返回 false */
  const newSid = () => `${stamp}-${Math.random().toString(36).slice(2, 10)}`;
  const seed = (sid, fields = {}) =>
    UserSession.create({
      sid,
      userId,
      status: 'active',
      createdAt: new Date(),
      expiresAt: new Date(Date.now() + 3600000),
      ...fields,
    });
  /** 读"库里真正存了什么"：lean 仍会 cast，只有 driver 才是原始形态 */
  const rawDoc = (sid) => UserSession.collection.findOne({ sid });

  it('前提自证：maxlength 只是校验器，绕开 mongoose 无人拦超长；同一条值走 updateOne 必须被剪', async () => {
    const sid = newSid();
    await seed(sid, { lastIp: '10.0.0.1' });
    const junk = `1.2.3.4${'x'.repeat(4000)}`;

    // (a) 驱动直写：证明 64 不是数据库层的约束，闸只能落在 mongoose 的铸造期
    await UserSession.collection.updateOne({ sid }, { $set: { lastIp: junk } });
    const bypassed = await rawDoc(sid);
    expect(bypassed.lastIp.length).toBeGreaterThan(MAX);

    // (b) 同一条值经 mongoose 的 updateOne：假设法证伪对照——若 set 不在 update 上执行，
    // 库里仍是 (a) 留下的长值（(a) 已经先把它写进去了），这一条就必须把它剪回界内。
    await UserSession.updateOne({ sid }, { $set: { lastIp: junk } });
    const gated = await rawDoc(sid);
    expect(gated.lastIp.length).toBeLessThanOrEqual(MAX);
    expect(gated.lastIp.startsWith('1.2.3.4')).toBe(true);
  });

  it('touchSession（lastIp 的唯一写入者）：16KB 级 req.ip 被剪到界内，且 lastSeenAt 照常推进', async () => {
    const sid = newSid();
    const seeded = await seed(sid, {
      ip: '10.0.0.1',
      lastIp: '10.0.0.1',
      lastSeenAt: new Date(0),
    });
    const before = await rawDoc(sid);

    const wrote = await sessionService.touchSession(sid, { ip: `203.0.113.7${'x'.repeat(9000)}` });
    expect(wrote).toBe(true);

    const after = await rawDoc(sid);
    expect(after.lastIp.length).toBeLessThanOrEqual(MAX);
    expect(after.lastIp.startsWith('203.0.113.7')).toBe(true);
    // 这条钉的是"为什么选 set 而不是 runValidators"：整条 $set 必须照写，
    // 否则 lastSeenAt 停摆（会话列表的排序与"僵尸会话"收敛都靠它）。
    expect(after.lastSeenAt.getTime()).toBeGreaterThan(before.lastSeenAt.getTime());
    expect(seeded.status).toBe('active');
  });

  it('ip 与 lastIp 用同一个闸；合法值原样、控制字符中和、空白降级为 null 而非空串', () => {
    const ipSet = UserSession.schema.path('ip').options.set;
    const lastIpSet = UserSession.schema.path('lastIp').options.set;
    expect(typeof ipSet).toBe('function');
    // 「两条路径两种口径」就是本仓反复记录过的漏洗形态，这里钉成同一份实现
    expect(lastIpSet).toBe(ipSet);

    for (const legal of [
      '10.0.0.1',
      '203.0.113.7',
      '::ffff:203.0.113.7',
      '2001:0db8:0000:0000:0000:0000:0000:0001',
      '0000:0000:0000:0000:0000:ffff:255.255.255.255',
    ]) {
      expect(ipSet(legal)).toBe(legal);
    }
    // 上界 64 的前提是"IPv6 最长文本形态 = 45 字符"。实测两种常见形态都不是 45：
    // 8 组全展开是 39（24 个十六进制字符 + 7 个冒号），真正的 45 来自 IPv4 内嵌形态
    // （6 组 + 6 个冒号 + 15 的点分十进制）。钉住 45 这一条，改上界的人会先看到它。
    expect(ipSet('2001:0db8:0000:0000:0000:0000:0000:0001')).toHaveLength(39);
    expect(ipSet('0000:0000:0000:0000:0000:ffff:255.255.255.255')).toHaveLength(45);

    // 控制字符**替换成空格**而非删除（委托 stripControlChars）：删除会把两个地址
    // 粘成一个看似合法的 token，那是造假不是清洗
    expect(ipSet(`1.2.3.4${LF}5.6.7.8`)).toBe('1.2.3.4 5.6.7.8');

    expect(ipSet(`203.0.113.7${'x'.repeat(4000)}`)).toHaveLength(MAX);
    // 空白的三种形态一律降级成 null：'' 会被 `{ lastIp: '' }` 这类查询命中全体无 ip 的会话
    expect(ipSet('')).toBeNull();
    expect(ipSet('   ')).toBeNull();
    expect(ipSet(null)).toBeNull();
    expect(ipSet(undefined)).toBeUndefined();
    // 非字符串来自代码而非请求方：原样放行，让既有校验器报错而不是被闸悄悄吞掉
    expect(ipSet(123)).toBe(123);
  });

  it('回归：createSession 的两条字段在闸之后仍是"合法值原样 / 超长有界"', async () => {
    const mkReq = (ip, ua) => ({
      get: (name) => (String(name).toLowerCase() === 'user-agent' ? ua : ''),
      ip,
    });

    const legit = await sessionService.createSession({
      userId,
      req: mkReq('198.51.100.7', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0'),
    });
    const legitDoc = await rawDoc(legit.sid);
    expect(legitDoc.ip).toBe('198.51.100.7');
    expect(legitDoc.lastIp).toBe('198.51.100.7');

    const flooded = await sessionService.createSession({
      userId,
      req: mkReq(`198.51.100.9${'x'.repeat(3000)}`, 'curl/8.4.0'),
    });
    const floodedDoc = await rawDoc(flooded.sid);
    expect(floodedDoc.ip.length).toBeLessThanOrEqual(MAX);
    expect(floodedDoc.lastIp.length).toBeLessThanOrEqual(MAX);
    expect(floodedDoc.ip.startsWith('198.51.100.9')).toBe(true);
  });

  it('写法门禁：touchSession 的 $set 不得改成 runValidators（会把 lastSeenAt 一起拒掉）', () => {
    const fs = require('fs');
    const path = require('path');
    const src = fs
      .readFileSync(
        path.join(__dirname, '..', '..', '..', 'src', 'services', 'sessionService.js'),
        'utf8'
      )
      // 剥注释再判：本仓已经多次被"注释里写着、代码里没有"骗过
      .replace(/\/\*[\s\S]*?\*\//g, '')
      .replace(/^\s*\/\/.*$/gm, '');
    const body = src.slice(src.indexOf('const touchSession'), src.indexOf('const revokeSession'));
    expect(body.includes('runValidators')).toBe(false);
    // 前提自证：这段里确实有那条 $set，否则上面的断言会因为"切片切错"而假绿
    expect(/lastIp:\s*req\?\.ip/.test(body)).toBe(true);
  });
});
