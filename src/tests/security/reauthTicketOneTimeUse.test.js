/* ===== 附录（2026-10-31 注释密度治理迁出）：src/services/reauthTicketStore.js 的原委 =====
 * * 二次验证票据的一次性消费（配合 utils/reauthTicket 的 jti 与 models/ReauthTicketUse）
 * *
 * * 判据只有一条：**同一个 jti 只能成功消费一次**。判据的载体是唯一索引
 * * （见 models/ReauthTicketUse 的注释），因此并发请求下也只有一个赢家。
 * *
 * * 存储不可用时的方向：**fail-closed**（抛错）。这里不是"多一层校验"而是票据的
 * * 唯一性判据本身——读不到判据就无从知道这张票是不是已经用过。审计读取端点本来
 * * 就要读 Mongo（审计日志/告警都在库里），Mongo 不可用时它无论如到都会失败，
 * * 所以 fail-closed 不会额外制造"可用性换安全"的取舍。
 * *
 * * 为什么不复用 tokenBlacklist / sessionService：那两者判的是**身份是否仍然有效**，
 * * 而这里判的是"这张一次性凭据是否已被使用过"——同一个 token 被多次使用是正常的
 * * （会话就该支持多次请求），把它塞进黑名单语义会立刻自相矛盾。
 *
 * 迁出理由：NEW_FILE_MAX=0.30 的密度上限；正文约束在源码一行内保留，完整权衡留在这里。
 */

/* ===== 附录（2026-10-31 注释密度治理迁出）：src/models/ReauthTicketUse.js 的原委 =====
 * * 已消费的二次验证票据登记（一次性消费）。
 * *
 * * 存在理由：票据是 5 分钟有效的**bearer 凭据**，原实现无 jti、无消费记录——
 * * 同一张票在窗口内可无限次重放。持有它的攻击面有三条：前端内存泄漏/被 XSS 读取、
 * * 反向代理与访问日志把 X-REAUTH-TICKET 头留下来、以及"审计读取"本身被判定为
 * * 高敏操作却只做了一次 step-up。一次性消费把窗口压到"第一次使用"。
 * *
 * * 为什么落在 Mongo 而不是进程内 Set：多实例部署下内存不共享，同一张票在 A 实例
 * * 用一次、在 B 实例还能再用一次——判据必须与实例数无关。
 * *
 * * 唯一索引是**并发判据**：两个请求同时带同一张票时，只有一次 create 能成功，
 * * 另一次拿 E11000（驱动层不重试、不静默覆盖）。先查后写（findOne → insert）
 * * 会留下同一个竞态窗口，故不采用。
 * *
 * * TTL 索引只管空间：整份记录的寿命 = 票据剩余有效期。清理延迟不影响判据
 * * （过期票据在签名校验那一步就已经被拒），因此不设清理巡检。
 *
 * 迁出理由：NEW_FILE_MAX=0.30 的密度上限；正文约束在源码一行内保留，完整权衡留在这里。
 */

/**
 * 二次验证票据的一次性消费（审计一-3）
 *
 * 缺陷形状（改造前实测）：票据是无状态 HMAC 串，5 分钟内**可无限次重放**。
 * 票据是 bearer 凭据——前端内存被读、代理把 X-REAUTH-TICKET 头写进访问日志，
 * 任何一种泄漏都等于在整个窗口内拿到审计读取权。改造加了两条：
 *   ① 载荷带 jti（随机 32 位 hex），无 jti 的票据一律无效；
 *   ② 每次校验通过后消费 jti，判据落在 Mongo 唯一索引（models/ReauthTicketUse）。
 *
 * 本文件钉三件事：jti 的存在性与不可预测性、无 jti 票据被判无效（不给旁路）、
 * 消费判据的"首次 true / 再次 false"与 fail-closed 方向。HTTP 链路见
 * reauthTicketEnforcement.test.js（那里钉重放与并发双发）。
 */

const mongoose = require('mongoose');
const crypto = require('crypto');

const {
  issueReauthTicket,
  inspectReauthTicket,
  verifyReauthTicket,
  REAUTH_TICKET_TTL_MS,
  JTI_HEX_LENGTH,
} = require('../../utils/reauthTicket');
const { consumeReauthTicketJti } = require('../../services/reauthTicketStore');
const ReauthTicketUse = require('../../models/ReauthTicketUse');

const stamp = `tkt${Date.now()}`.replace(/\d/g, (d) => 'abcdefghij'[Number(d)]);

/** 手工签一张**不带 jti** 的票（模拟改造前旧实例签出的票据） */
function legacyTicketWithoutJti({ userId, sessionId, now = Date.now() }) {
  const { hmacSigner } = require('../../utils/encryption');
  const body = Buffer.from(
    JSON.stringify({
      uid: String(userId),
      sid: sessionId ?? null,
      exp: now + REAUTH_TICKET_TTL_MS,
    }),
    'utf8'
  ).toString('base64url');
  return `${body}.${hmacSigner.sign(`reauth-ticket:v1:${body}`)}`;
}

describe('票据载荷：jti', () => {
  test('签发的票带 32 位 hex jti，且两次签发不重复', () => {
    const a = issueReauthTicket({ userId: `u-${stamp}`, sessionId: 'sid-A' });
    const b = issueReauthTicket({ userId: `u-${stamp}`, sessionId: 'sid-A' });
    const jtiA = inspectReauthTicket(a.ticket, { userId: `u-${stamp}`, sessionId: 'sid-A' }).jti;
    const jtiB = inspectReauthTicket(b.ticket, { userId: `u-${stamp}`, sessionId: 'sid-A' }).jti;
    expect(jtiA).toMatch(new RegExp(`^[0-9a-f]{${JTI_HEX_LENGTH}}$`));
    expect(jtiA).not.toBe(jtiB);
  });

  test('jti 是随机字节、不是计数器：同毫秒连签 8 张，全不相同', () => {
    const now = Date.now();
    const jtis = new Set();
    for (let i = 0; i < 8; i += 1) {
      const { ticket } = issueReauthTicket({ userId: `u-${stamp}`, sessionId: 'sid-A' }, now);
      jtis.add(inspectReauthTicket(ticket, { userId: `u-${stamp}`, sessionId: 'sid-A' }).jti);
    }
    expect(jtis.size).toBe(8);
  });

  test('无 jti 的票据（改造前口径）一律无效：不给"没有 jti 就跳过唯一性判据"的旁路', () => {
    const userId = `u-${stamp}`;
    const ticket = legacyTicketWithoutJti({ userId, sessionId: 'sid-A' });
    expect(verifyReauthTicket(ticket, { userId, sessionId: 'sid-A' })).toBe(false);
    expect(inspectReauthTicket(ticket, { userId, sessionId: 'sid-A' })).toEqual({ valid: false });
  });

  test('jti 形状不对（长度/非 hex/大写）同样无效', () => {
    const { hmacSigner } = require('../../utils/encryption');
    const userId = `u-${stamp}`;
    const sign = (payload) => {
      const body = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
      return `${body}.${hmacSigner.sign(`reauth-ticket:v1:${body}`)}`;
    };
    const base = { uid: userId, sid: 'sid-A', exp: Date.now() + REAUTH_TICKET_TTL_MS };
    for (const jti of ['abc', crypto.randomBytes(16).toString('hex').toUpperCase(), 123, null]) {
      const ticket = sign({ ...base, jti });
      expect(verifyReauthTicket(ticket, { userId, sessionId: 'sid-A' })).toBe(false);
    }
  });

  test('inspect 成功时返回 jti 与 exp（供消费与 TTL 登记）', () => {
    const userId = `u-${stamp}`;
    const now = Date.now();
    const { ticket } = issueReauthTicket({ userId, sessionId: 'sid-A' }, now);
    const got = inspectReauthTicket(ticket, { userId, sessionId: 'sid-A' }, now);
    expect(got.valid).toBe(true);
    expect(got.exp).toBe(now + REAUTH_TICKET_TTL_MS);
    expect(typeof got.jti).toBe('string');
  });
});

describe('消费判据：同一个 jti 只能成功一次', () => {
  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      await ReauthTicketUse.deleteMany({ jti: new RegExp(`${stamp}`) }).catch(() => {});
      await mongoose.connection.close();
    }
  });

  test('首次消费成功，第二次同 jti 被拒（唯一索引是判据）', async () => {
    const jti = `${stamp}replay`;
    const expiresAt = new Date(Date.now() + REAUTH_TICKET_TTL_MS);
    expect(await consumeReauthTicketJti({ jti, expiresAt })).toBe(true);
    expect(await consumeReauthTicketJti({ jti, expiresAt })).toBe(false);
  });

  test('并发消费同一 jti：恰好一个赢家（不是"先查后写"的两个都过）', async () => {
    const jti = `${stamp}race`;
    const expiresAt = new Date(Date.now() + REAUTH_TICKET_TTL_MS);
    const results = await Promise.all(
      Array.from({ length: 5 }, () => consumeReauthTicketJti({ jti, expiresAt }))
    );
    expect(results.filter(Boolean)).toHaveLength(1);
  });

  test('存储故障 fail-closed：非唯一冲突的错误原样抛出，不得被读成"已用过"', async () => {
    const boom = Object.assign(new Error('mongo down'), { code: 'ECONNREFUSED' });
    const spy = jest.spyOn(ReauthTicketUse, 'create').mockRejectedValueOnce(boom);
    try {
      await expect(
        consumeReauthTicketJti({ jti: `${stamp}boom`, expiresAt: new Date() })
      ).rejects.toThrow('mongo down');
    } finally {
      spy.mockRestore();
    }
  });

  test('模型带 TTL 索引：票据过期后登记记录自动清理（空间由索引管，判据不依赖它）', () => {
    const indexes = ReauthTicketUse.schema.indexes();
    const ttl = indexes.find(([spec]) => spec.expiresAt === 1);
    expect(ttl).toBeTruthy();
    expect(ttl[1].expireAfterSeconds).toBe(0);
    // jti 唯一索引是判据本身，不得退化成普通索引
    expect(ReauthTicketUse.schema.path('jti').options.unique).toBe(true);
  });
});

describe('会话窗口的键口径：只认设备 sid，无 sid 的旧令牌退回一次性票据（代价显式化）', () => {
  const {
    recordReauthGrant,
    hasLiveReauthGrant,
    revokeReauthGrant,
  } = require('../../services/reauthGrantStore');
  const ReauthGrant = require('../../models/ReauthGrant');
  const { Types } = mongoose;

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      await ReauthGrant.deleteMany({ sid: new RegExp(stamp) }).catch(() => {});
      await mongoose.connection.close();
    }
  });

  test('无 sid 的令牌（存量/降级路径）不落窗口：读取只能靠一次性票据，且票据仍然一次性', async () => {
    const userId = String(new Types.ObjectId());
    // 代价写死在这里：旧令牌没有 sid ⇒ 窗口这条路不存在（不是"窗口写失败但读得到"）
    expect(await recordReauthGrant({ userId, sid: null })).toBe(false);
    expect(await hasLiveReauthGrant({ userId, sid: null })).toBe(false);
    expect(await ReauthGrant.countDocuments({ userId })).toBe(0);

    const { ticket } = issueReauthTicket({ userId, sessionId: null });
    const inspected = inspectReauthTicket(ticket, { userId, sessionId: null });
    expect(inspected.valid).toBe(true);
    const expiresAt = new Date(inspected.exp);
    expect(await consumeReauthTicketJti({ jti: inspected.jti, expiresAt })).toBe(true);
    expect(await consumeReauthTicketJti({ jti: inspected.jti, expiresAt })).toBe(false);
  });

  test('写/读/撤销是同一把键（设备 sid）：换个 jti 不妨碍窗口，撤销后行归零', async () => {
    const userId = String(new Types.ObjectId());
    const deviceSid = `dev-${stamp}-${Math.random().toString(36).slice(2, 8)}`;
    expect(await recordReauthGrant({ userId, sid: deviceSid })).toBe(true);
    // refresh 换了 jti 之后按同一把 sid 查：仍然是活的
    expect(await hasLiveReauthGrant({ userId, sid: deviceSid })).toBe(true);
    // 但换成"看起来像 jti"的键查不到：窗口不认 jti
    expect(await hasLiveReauthGrant({ userId, sid: `${deviceSid}-jti` })).toBe(false);
    await revokeReauthGrant(deviceSid); // 与 session.js:155 的撤销键同口径
    expect(await hasLiveReauthGrant({ userId, sid: deviceSid })).toBe(false);
    expect(await ReauthGrant.countDocuments({ userId })).toBe(0);
  });
});
