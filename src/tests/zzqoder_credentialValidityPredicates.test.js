'use strict';

/**
 * 凭证有效性判据的真实覆盖（此前两条判据**从未被真跑过**）
 *
 * 覆盖率 + 用例检索给出的事实：
 *   - `UserSession.isUsable`（会话能不能用来认证）在全仓只出现在
 *     `zzqA_sessionCrossInstance.test.js` 里，且两次都是 mock：
 *     `UserSession.findOne.mockResolvedValue({ isUsable: () => true })`
 *     ⇒ 谓词本体 0 覆盖：改坏它（例如删掉 `status !== 'active'` 或漏掉到期判断）
 *     没有任何用例会红，而它正是"踢掉这台设备"与"会话自然过期"的唯一实现。
 *   - `tokenService.isAccessTokenValid` / `isRefreshTokenValid` 只在
 *     `authControllerOutcomes.test.js` 里以 `jest.fn()` 出现（消费者用 mock 驱动），
 *     判据本体同样没有行为覆盖 —— 而它是 `/api/auth/session-status` 的**唯一**依据。
 *
 * 本文件用真库、真 JWT、真黑名单写入把两条判据的每个分支跑一遍。
 * 关键设计：断言"每个失败原因各自为 false"，而不是只断言 false ——
 * 否则"任何异常都返回 false"的退化实现也能全绿。
 */

const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const config = require('../config');

describe('zzqoder 凭证有效性判据（UserSession.isUsable / tokenService 探测）', () => {
  let UserSession;
  let User;
  let Role;
  let Permission;
  let tokenService;
  let tokenBlacklist;
  const stamp = `zzcv${Date.now()}`.replace(/\d/g, (d) => 'abcdefghij'[Number(d)]);

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    UserSession = require('../models/UserSession');
    User = require('../models/User');
    Role = require('../models/Role');
    Permission = require('../models/Permission');
    tokenService = require('../services/tokenService');
    tokenBlacklist = require('../middleware/tokenBlacklist');
  });

  afterAll(async () => {
    await UserSession.collection.deleteMany({ sid: new RegExp(`^${stamp}`) });
    await User.deleteMany({ username: new RegExp(`^${stamp}`) });
    if (mongoose.connection.readyState !== 0) await mongoose.connection.close();
  });

  describe('UserSession.isUsable —— 三态 + 边界', () => {
    const mk = (over) =>
      new UserSession({
        sid: `${stamp}-s-${Math.random().toString(36).slice(2)}`,
        userId: new mongoose.Types.ObjectId(),
        expiresAt: new Date(Date.now() + 60 * 60 * 1000),
        status: 'active',
        ...over,
      });

    test('active + 未到期 ⇒ true（唯一的通过格）', () => {
      expect(mk({}).isUsable()).toBe(true);
    });

    test.each([
      ['revoked（踢设备）', { status: 'revoked' }],
      ['expired（自然过期状态位）', { status: 'expired' }],
    ])('%s ⇒ false', (_name, over) => {
      expect(mk(over).isUsable()).toBe(false);
    });

    test('active 但 expiresAt 已过 ⇒ false（TTL 清理有延迟，状态位还是 active）', () => {
      expect(mk({ expiresAt: new Date(Date.now() - 1000) }).isUsable()).toBe(false);
    });

    test('边界：判据是"严格大于当前时刻"，且只依赖 status / expiresAt 两个字段', () => {
      expect(mk({ expiresAt: new Date(0) }).isUsable()).toBe(false);
      const future = Date.now() + 5000;
      // 裸对象也能判：说明谓词没有隐藏地依赖文档其它部分（populate/lean 都能用）
      expect(
        UserSession.prototype.isUsable.call({ status: 'active', expiresAt: new Date(future) })
      ).toBe(true);
      expect(
        UserSession.prototype.isUsable.call({
          status: 'active',
          expiresAt: new Date(future - 5000),
        })
      ).toBe(false);
    });

    test('expiresAt 缺失 ⇒ false（required 也可能被绕过：$unset / 旧文档）', async () => {
      const doc = mk({});
      doc.set('expiresAt', undefined);
      expect(doc.isUsable()).toBe(false);
    });

    test('真实文档往返：库里的 revoked 会话读出来必须判 false', async () => {
      const created = await UserSession.create({
        sid: `${stamp}-db`,
        userId: new mongoose.Types.ObjectId(),
        expiresAt: new Date(Date.now() + 3600_000),
      });
      expect((await UserSession.findOne({ sid: `${stamp}-db` })).isUsable()).toBe(true);
      await UserSession.updateOne({ _id: created._id }, { $set: { status: 'revoked' } });
      expect((await UserSession.findOne({ sid: `${stamp}-db` })).isUsable()).toBe(false);
    });
  });

  describe('tokenService 两个探测函数 —— 每个拒绝原因各自为 false', () => {
    let uid;
    let token; // 合法 access
    let refresh; // 合法 refresh

    const signAccess = (payload) => jwt.sign(payload, config.jwt.secret, { expiresIn: '1h' });
    const signRefresh = (payload) =>
      jwt.sign(payload, config.jwt.refreshSecret, { expiresIn: '1h' });

    beforeAll(async () => {
      const wildcard = await Permission.findOneAndUpdate(
        { code: `zzcv:*:${stamp}` },
        {
          $setOnInsert: { name: 'zzcv', code: `zzcv:*:${stamp}`, type: 'api', module: 'system' },
        },
        { upsert: true, new: true }
      );
      const role = await Role.create({
        name: `zzcv-${stamp}`,
        code: `ZZCV_${stamp}`.toUpperCase(),
        level: 3,
        permissions: [wildcard._id],
      });
      const u = await User.create({
        username: `${stamp}u`,
        email: `${stamp}u@example.com`,
        password: 'Aa1!aaaaaaaaaaaaaaaa',
        status: 'active',
        roles: [role._id],
        tokenVersion: 2,
      });
      uid = u._id;
      token = signAccess({
        userId: String(uid),
        username: u.username,
        roles: ['x'],
        tokenVersion: 2,
      });
      refresh = signRefresh({ userId: String(uid), type: 'refresh', tokenVersion: 2 });
    });

    test('配置前置：两套密钥都存在且不同（否则下面的"用错密钥"用例毫无意义）', () => {
      expect(config.jwt.secret).toBeTruthy();
      expect(config.jwt.refreshSecret).toBeTruthy();
      expect(config.jwt.secret).not.toBe(config.jwt.refreshSecret);
    });

    test('正对照：合法 access / 合法 refresh 各自判 true', async () => {
      await expect(tokenService.isAccessTokenValid(token)).resolves.toBe(true);
      await expect(tokenService.isRefreshTokenValid(refresh)).resolves.toBe(true);
    });

    test('交叉：access 令牌不是有效 refresh，反之亦然（密钥与 type 双闸）', async () => {
      await expect(tokenService.isRefreshTokenValid(token)).resolves.toBe(false);
      await expect(tokenService.isAccessTokenValid(refresh)).resolves.toBe(false);
    });

    /**
     * 上面那条"交叉"其实只证明了**密钥**这一闸（access 令牌过不了 refreshSecret 的验签）。
     * `type !== 'refresh'` 这一闸要用"用 refreshSecret 签、但没有 type"的令牌才可达
     * —— 这条是变异测出来的：删掉 type 判断后上一组用例全绿，说明当时没人真的测到它。
     */
    test('用 refreshSecret 签但没有 type=refresh 的令牌 ⇒ false（type 这一闸必须单独测）', async () => {
      const noType = signRefresh({ userId: String(uid), tokenVersion: 2 });
      const wrongType = signRefresh({ userId: String(uid), type: 'access', tokenVersion: 2 });
      await expect(tokenService.isRefreshTokenValid(noType)).resolves.toBe(false);
      await expect(tokenService.isRefreshTokenValid(wrongType)).resolves.toBe(false);
      // 反向对照：同一 payload 补上 type=refresh 就必须通过（证明上面的 false 来自 type 判断，
      // 而不是密钥/用户态/tokenVersion 之类共同前提）
      const right = signRefresh({ userId: String(uid), type: 'refresh', tokenVersion: 2 });
      await expect(tokenService.isRefreshTokenValid(right)).resolves.toBe(true);
    });

    test('签名被篡改 ⇒ false', async () => {
      const tampered = `${token.slice(0, -3)}aaa`;
      await expect(tokenService.isAccessTokenValid(tampered)).resolves.toBe(false);
    });

    test('垃圾/空令牌 ⇒ false（走 catch 分支而不是抛错）', async () => {
      await expect(tokenService.isAccessTokenValid('not.a.jwt')).resolves.toBe(false);
      await expect(tokenService.isRefreshTokenValid('')).resolves.toBe(false);
    });

    test('tokenVersion 不匹配（改密/强制下线后）⇒ 两个探测都 false', async () => {
      const stale = signAccess({ userId: String(uid), tokenVersion: 1 });
      const staleRefresh = signRefresh({ userId: String(uid), type: 'refresh', tokenVersion: 1 });
      await expect(tokenService.isAccessTokenValid(stale)).resolves.toBe(false);
      await expect(tokenService.isRefreshTokenValid(staleRefresh)).resolves.toBe(false);
    });

    test('用户被禁用 ⇒ false（用户态这一格不许只看令牌）', async () => {
      await User.updateOne({ _id: uid }, { $set: { status: 'disabled' } });
      await expect(tokenService.isAccessTokenValid(token)).resolves.toBe(false);
      await expect(tokenService.isRefreshTokenValid(refresh)).resolves.toBe(false);
      await User.updateOne({ _id: uid }, { $set: { status: 'active' } });
      expect(await tokenService.isAccessTokenValid(token)).toBe(true);
    });

    test('用户不存在 ⇒ false；且 userId 非法（触发库层异常）也走吞错分支 ⇒ false', async () => {
      const ghost = signAccess({ userId: String(new mongoose.Types.ObjectId()), tokenVersion: 0 });
      await expect(tokenService.isAccessTokenValid(ghost)).resolves.toBe(false);
      // userId 不是合法 ObjectId ⇒ findById 抛 CastError ⇒ catch ⇒ false（不得冒泡成 500）
      const broken = signAccess({ userId: 'not-an-objectid', tokenVersion: 0 });
      await expect(tokenService.isAccessTokenValid(broken)).resolves.toBe(false);
      await expect(tokenService.isRefreshTokenValid(broken)).resolves.toBe(false);
    });

    /**
     * 拉黑动作打的是「这一枚令牌」的状态（黑名单按 sha256(token) 存），
     * 所以必须用本用例专用的令牌，不能复用 describe 级共享的 token/refresh：
     * 否则共享令牌永久带黑名单，--randomize 打乱文件内顺序后
     * 上面的"正对照判 true"和"用户被禁用"的反向对照就都读不到 true 了。
     */
    test('已登出（令牌进黑名单）⇒ 两个探测都 false', async () => {
      const blAccess = signAccess({
        userId: String(uid),
        tokenVersion: 2,
        jti: `${stamp}-bl-access`,
      });
      const blRefresh = signRefresh({
        userId: String(uid),
        type: 'refresh',
        tokenVersion: 2,
        jti: `${stamp}-bl-refresh`,
      });
      await tokenBlacklist.blacklistToken(blAccess, Math.floor(Date.now() / 1000) + 3600);
      await expect(tokenService.isAccessTokenValid(blAccess)).resolves.toBe(false);
      // refresh 尚未拉黑，作为反向对照必须仍然为 true
      await expect(tokenService.isRefreshTokenValid(blRefresh)).resolves.toBe(true);
      await tokenBlacklist.blacklistToken(blRefresh, Math.floor(Date.now() / 1000) + 3600);
      await expect(tokenService.isRefreshTokenValid(blRefresh)).resolves.toBe(false);
    });
  });
});
