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
 * 变异判据（本轮实测）：控制器改回 `body || cookie` ⇒ ③/④ 红；
 * 循环里去掉 `if (failed) revokeFailed = true` ⇒ ② 红。
 */

const jwt = require('jsonwebtoken');

const authService = require('../../services/authService');
const authController = require('../../controllers/authController');
const TokenBlacklist = require('../../models/TokenBlacklist');

const REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || process.env.JWT_SECRET;

const signRefresh = (jti) =>
  jwt.sign({ userId: 'f100-user', type: 'refresh', tokenVersion: 0, jti }, REFRESH_SECRET, {
    expiresIn: '1h',
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
});
