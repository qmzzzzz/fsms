'use strict';

/**
 * F-100：登出必须吊销**所有被出示的** refresh 令牌，且部分失败不得被吞
 *
 * 缺陷（台账 §4.1，本轮实测成立）：`authController.logout` 原先写
 *   `const refreshTokenRaw = req.body?.refreshToken || cookies[REFRESH_COOKIE_NAME];`
 * ——**二选一**且 body 优先。只要请求体里带一条 refresh 串（哪怕早已轮换掉、但签名仍有效），
 * 浏览器 cookie 里那条**还在有效期内**的 refresh 令牌就永远进不了登出流程：
 * 接口回 200「登出成功」，服务端那条线还活着，而用户已认为会话终止、不会再补救。
 * 这与 P2-26 是同族的两面：上一条堵的是"吊销失败却报成功"，这一条是"根本没试着吊销"。
 *
 * 四条判据互相补位：
 *   ① 两条不同的在用令牌同时出示 ⇒ **都**要写黑名单；
 *   ② 其中一条写失败 ⇒ `revokeFailed=true`（先成功的那条不得把后面的失败盖住）；
 *   ③ 同一条在 body 与 cookie 里重复 ⇒ 只写一次（去重，不留重复黑名单行）；
 *   ④ 控制器层：两个来源都要交给服务层（一个作主、另一个进 extraRefreshTokens）。
 *
 * ⑤⑥⑦（F-100 的另一半，属主判据）：出示的 refresh 串若不是当前操作者的，
 *   整次登出失败，且**任何副作用都不发生**。旧实现不判属主——拿到他人
 *   refresh 串即可代为吊销（会话 DoS），接口还回 200。三条各自守住一格：
 *   ⑤ 服务层：混入外来串 ⇒ foreignRefresh=true 且黑名单零写入（含自己那条）；
 *   ⑥ 控制器层：403 + errorCode=LOGOUT_REFRESH_FOREIGN，且不清 cookie、不动会话表；
 *   ⑦ 负前提与边界：漏传 userId 按外来处理（fail-closed）；签名无效/已过期的串
 *      **不算**外来（与 revokeOneRefreshToken 既有口径一致，否则带过期串的登出会被误拒）。
 *
 * 变异判据（本轮实测）：控制器改回 `body || cookie` ⇒ ③/④ 红；
 * 循环里去掉 `if (failed) revokeFailed = true` ⇒ ② 红；
 * 属主预检改成"外来就跳过那条、照常登出" ⇒ ⑤/⑥ 红；
 * 判别器对 verify 失败也返回 true ⇒ ⑦ 的边界用例红。
 *
 * 「预检移到 blacklistToken 之后」这一条**第一轮没被杀**：⑤ 当时只出示 refresh 串，
 * 没有 access 令牌可被提前写进黑名单，后移预检在本用例里无可观测差异。补上
 * accessToken 实参后才红（1 failed / 7 passed）。记在这里是因为它正是"断言写了但
 * 没断言到那一步"的典型形状——用例通过了，回归却活着。
 */

const jwt = require('jsonwebtoken');

const authService = require('../../services/authService');
const authController = require('../../controllers/authController');
const TokenBlacklist = require('../../models/TokenBlacklist');

const REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || process.env.JWT_SECRET;
const ACCESS_SECRET = process.env.JWT_SECRET;

const signRefresh = (jti, userId = 'f100-user') =>
  jwt.sign({ userId, type: 'refresh', tokenVersion: 0, jti }, REFRESH_SECRET, {
    expiresIn: '24h',
  });

/** 本人的有效 access 令牌：让"预检必须早于任何吊销"变得可观测 */
const signAccess = (userId = 'f100-user') =>
  jwt.sign({ userId, username: 'f100', tokenVersion: 0 }, ACCESS_SECRET, {
    expiresIn: '24h',
  });

/** 黑名单写入的观测点：blacklistToken 最终落到 findOneAndUpdate 的 upsert */
function watchBlacklistWrites() {
  return jest.spyOn(TokenBlacklist, 'findOneAndUpdate').mockResolvedValue(null);
}

afterEach(() => jest.restoreAllMocks());

describe('登出吊销所有被出示的 refresh 令牌（F-100）', () => {
  test('① 两条在用的不同令牌同时出示：都要进黑名单（旧实现只会处理第一条）', async () => {
    const spy = watchBlacklistWrites();
    const a = signRefresh('a');
    const b = signRefresh('b');

    const { revokeFailed } = await authService.revokeTokensOnLogout({
      refreshToken: a,
      extraRefreshTokens: [b],
      userId: 'f100-user',
    });

    const calls = spy.mock.calls;
    expect(calls).toHaveLength(2);
    // 两次写入必须针对**不同**的令牌（不依赖黑名单的键形态：明文还是哈希）
    expect(JSON.stringify(calls[0][0])).not.toEqual(JSON.stringify(calls[1][0]));
    expect(revokeFailed).toBe(false);
  });

  test('② 第二条写失败：必须报 revokeFailed=true，不被第一条的成功盖住', async () => {
    const spy = jest
      .spyOn(TokenBlacklist, 'findOneAndUpdate')
      .mockResolvedValueOnce(null) // 第一条成功
      .mockRejectedValueOnce(new Error('db down')); // 第二条失败
    const errSpy = jest.spyOn(require('../../utils/logger'), 'error').mockImplementation(() => {});

    const { revokeFailed } = await authService.revokeTokensOnLogout({
      refreshToken: signRefresh('ok'),
      extraRefreshTokens: [signRefresh('bad')],
      userId: 'f100-user',
    });

    expect(spy).toHaveBeenCalledTimes(2);
    expect(revokeFailed).toBe(true);
    errSpy.mockRestore();
  });

  test('③ 同一条令牌在 body 与 cookie 里重复出现：只写一次', async () => {
    const spy = watchBlacklistWrites();
    const same = signRefresh('dup');

    await authService.revokeTokensOnLogout({
      refreshToken: same,
      extraRefreshTokens: [same],
      userId: 'f100-user',
    });

    expect(spy).toHaveBeenCalledTimes(1);
  });

  test('④ 控制器把两个来源都交给服务层（不再二选一）', async () => {
    const bodyToken = signRefresh('body');
    const cookieToken = signRefresh('cookie');
    const revokeSpy = jest
      .spyOn(authService, 'revokeTokensOnLogout')
      .mockResolvedValue({ revokeFailed: false });

    const req = {
      headers: {
        authorization: 'Bearer access-token-f100',
        cookie: `refresh_token=${cookieToken}`,
      },
      body: { refreshToken: bodyToken },
      user: { userId: 'f100-user', username: 'f100' },
    };
    const res = {
      statusCode: 200,
      payload: null,
      status(c) {
        this.statusCode = c;
        return this;
      },
      json(data) {
        this.payload = data;
        return this;
      },
    };

    await authController.logout(req, res, (err) => {
      throw err;
    });

    expect(revokeSpy).toHaveBeenCalledTimes(1);
    const arg = revokeSpy.mock.calls[0][0];
    expect(arg.accessToken).toBe('access-token-f100');
    // 两个来源都必须在：一条作主、另一条进 extraRefreshTokens（顺序不敏感）
    expect(new Set([arg.refreshToken, ...(arg.extraRefreshTokens || [])])).toEqual(
      new Set([bodyToken, cookieToken])
    );
    expect(res.statusCode).toBe(200);
  });

  // ===== ⑤⑥⑦ 出示**非本人**的 refresh 令牌：整次登出必须被拒（F-100 的另一半）=====
  // 旧实现不判属主：任何已认证用户拿到他人 refresh 串即可代为吊销（会话 DoS），
  // 而登出接口还回 200「已登出」。现在属主预检走在任何黑名单写入之前，
  // 外来即整次失败——不清 cookie、不动会话表、不吊销任何令牌。
  describe('⑤ 服务层：外来 refresh 串 ⇒ 报 foreignRefresh 且零吊销', () => {
    test('混入一条他人的有效 refresh 串 ⇒ foreignRefresh=true，黑名单一次都不写', async () => {
      const spy = watchBlacklistWrites();
      const mine = signRefresh('mine');
      const theirs = signRefresh('theirs', 'someone-else');

      const result = await authService.revokeTokensOnLogout({
        // 必须同时带上本人的 access 令牌：否则"预检被挪到 access 吊销之后"这个回归
        // 在本用例里无可观测差异（没有 access 令牌可被提前写进黑名单）——变异 M2 实测
        // 正是从这个缺口全身而退，补上它才算真断言"预检早于任何写入"。
        accessToken: signAccess(),
        refreshToken: mine,
        extraRefreshTokens: [theirs],
        userId: 'f100-user',
      });

      expect(result.foreignRefresh).toBe(true);
      expect(result.revokeFailed).toBe(false);
      // 「不做任何吊销」必须可观察：自己的那条也不能写（部分成功会让登出状态说不清）
      expect(spy).not.toHaveBeenCalled();
    });

    test('负前提：拿不到操作者身份时按外来处理（fail-closed，不放行）', async () => {
      const spy = watchBlacklistWrites();
      const mine = signRefresh('mine');

      // 调用方漏传 userId ⇒ 无法证明「这串是我的」⇒ 必须按外来拒绝
      const result = await authService.revokeTokensOnLogout({ refreshToken: mine });

      expect(result.foreignRefresh).toBe(true);
      expect(spy).not.toHaveBeenCalled();
    });

    test('边界：签名无效/已过期的串不算外来（不影响登出结论，与既有口径一致）', async () => {
      const expired = jwt.sign(
        { userId: 'someone-else', type: 'refresh', tokenVersion: 0, jti: 'expired' },
        REFRESH_SECRET,
        { expiresIn: '-1s' }
      );
      const wrongSecret = jwt.sign(
        { userId: 'someone-else', type: 'refresh', tokenVersion: 0, jti: 'wrong' },
        'not-the-refresh-secret',
        { expiresIn: '24h' }
      );

      for (const bad of [expired, wrongSecret]) {
        const result = await authService.revokeTokensOnLogout({
          refreshToken: bad,
          userId: 'f100-user',
        });
        expect(result.foreignRefresh).toBeFalsy();
        expect(result.revokeFailed).toBe(false);
      }
    });
  });

  describe('⑥ 控制器：外来 refresh 串 ⇒ 403，且不清 cookie、不动会话表', () => {
    test('请求体带他人 refresh 串 ⇒ LOGOUT_REFRESH_FOREIGN，副作用全部不发生', async () => {
      const blacklistSpy = watchBlacklistWrites();
      const sessionSpy = jest
        .spyOn(require('../../services/sessionService'), 'revokeSessionSafe')
        .mockResolvedValue(undefined);

      const req = {
        headers: { authorization: 'Bearer access-token-f100' },
        body: { refreshToken: signRefresh('foreign', 'someone-else') },
        user: { userId: 'f100-user', username: 'f100', sid: 'sid-cur' },
        clearCookie: jest.fn(),
      };
      const res = {
        statusCode: 200,
        payload: null,
        status(c) {
          this.statusCode = c;
          return this;
        },
        json(data) {
          this.payload = data;
          return this;
        },
      };

      await authController.logout(req, res, (err) => {
        throw err;
      });

      expect(res.statusCode).toBe(403);
      expect(res.payload.errors.errorCode).toBe('LOGOUT_REFRESH_FOREIGN');
      // 三个副作用都必须没发生：
      //  - 不清 cookie：清了浏览器侧像已登出，用户不会重试
      //  - 不动会话表：登出已失败，会话状态不该被改写
      //  - 不吊销任何令牌（含自己那条 access/refresh）：预检走在写入之前
      expect(req.clearCookie).not.toHaveBeenCalled();
      expect(sessionSpy).not.toHaveBeenCalled();
      expect(blacklistSpy).not.toHaveBeenCalled();
    });
  });
});
