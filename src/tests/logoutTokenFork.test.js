/**
 * 登出的 access token 必须与认证用的是**同一个提取实现**（fork 会 fail-open）
 *
 * 缺陷形态（authController.logout 原实现）：控制器自己复制了一份 Bearer 解析——
 *   if (authHeader.startsWith('Bearer ')) token = authHeader.split(' ')[1];
 *   else if (cookies[ACCESS_COOKIE_NAME]) token = cookies[ACCESS_COOKIE_NAME];
 * 而 `middleware/auth.js` 的 extractAccessToken 是另一套：Bearer 值取到**空串时回退 cookie**。
 * 于是 `Authorization: Bearer  T`（双空格，实测 Node 保留中间空格、只修剪尾随空格）
 * + 同名 cookie 的请求：
 *   authenticate → 回退 cookie → 用 T 认证通过；
 *   logout       → token = ''  → 不回退 → 吊销调用收到空令牌 → T 不进黑名单，
 *                  但接口照样 200「登出成功」。P2-26 用 LOGOUT_REVOKE_FAILED 堵的
 *                  正是这类"看起来登出了、服务端令牌还活着"，被一条复制粘贴绕开。
 *
 * 三层钉法：① 行为（真实控制器 + 真实提取器，不依赖实现细节）；
 *          ② 同源（把控制器里那行右值抠出来，逐形态与 extractAccessToken 求值比对，
 *             防止"看起来调了工具函数、其实又写回本地分支"）；
 *          ③ 静态禁令（自证正则抓得到被禁写法，避免空匹配假绿）。
 */

const fs = require('fs');
const path = require('path');
const express = require('express');
const request = require('supertest');

const authController = require('../controllers/authController');
const authService = require('../services/authService');
const { extractAccessToken } = require('../middleware/auth');

const TOKEN = 'probe-session-token-abcdef';

/** 构造只带 header 的 req（getCookies 会自己从 headers.cookie 解析） */
const makeReq = ({ authorization, cookie }) => {
  const headers = {};
  if (authorization !== undefined) headers.authorization = authorization;
  if (cookie !== undefined) headers.cookie = cookie;
  return { headers };
};

const SHAPES = [
  ['仅 Bearer 头', { authorization: `Bearer ${TOKEN}` }, TOKEN],
  ['仅 cookie', { cookie: `access_token=${TOKEN}` }, TOKEN],
  [
    '头与 cookie 同值',
    { authorization: `Bearer ${TOKEN}`, cookie: `access_token=${TOKEN}` },
    TOKEN,
  ],
  // 触发缺陷的那一形态：Bearer 值里有双空格 ⇒ 手写 split(' ')[1] 拿到空串
  [
    '双空格 Bearer + cookie',
    { authorization: `Bearer  ${TOKEN}`, cookie: `access_token=${TOKEN}` },
    TOKEN,
  ],
  [
    '非 Bearer 方案 + cookie',
    { authorization: 'Basic zzz', cookie: `access_token=${TOKEN}` },
    TOKEN,
  ],
  ['什么都没带', {}, null],
];

const buildApp = () => {
  const app = express();
  app.use(express.json());
  const fakeAuth = (req, _res, next) => {
    req.user = { userId: 'u-zz', username: 'zzlogout' }; // 不带 sid：跳过会话表分支
    next();
  };
  app.post('/api/auth/logout', fakeAuth, authController.logout);
  return app;
};

describe('登出令牌提取与认证同源', () => {
  afterEach(() => jest.restoreAllMocks());

  test('① 行为：双空格 Bearer + cookie 的登出，必须把那个 cookie 令牌交给吊销', async () => {
    const spy = jest
      .spyOn(authService, 'revokeTokensOnLogout')
      .mockResolvedValue({ revokeFailed: false });

    const res = await request(buildApp())
      .post('/api/auth/logout')
      .set('Authorization', `Bearer  ${TOKEN}`)
      .set('Cookie', `access_token=${TOKEN}; refresh_token=rt-zz`);

    expect(res.status).toBe(200);
    expect(spy).toHaveBeenCalledTimes(1);
    const arg = spy.mock.calls[0][0];
    // 修复前这里是 ''：登出报成功而令牌仍在有效期内可用
    expect(arg.accessToken).toBe(TOKEN);
    expect(arg.refreshToken).toBe('rt-zz');
  });

  test('① 对照：正常单空格与纯 cookie 两种形态本来就没问题（防"改出新回归"）', async () => {
    for (const [, authorization, cookie] of [
      ['单空格头+同 cookie', `Bearer ${TOKEN}`, `access_token=${TOKEN}`],
      ['纯 cookie', undefined, `access_token=${TOKEN}`],
    ]) {
      const spy = jest
        .spyOn(authService, 'revokeTokensOnLogout')
        .mockResolvedValue({ revokeFailed: false });
      const req = request(buildApp()).post('/api/auth/logout').set('Cookie', cookie);
      if (authorization) req.set('Authorization', authorization);
      const res = await req;
      expect(res.status).toBe(200);
      expect(spy.mock.calls[0][0].accessToken).toBe(TOKEN);
      spy.mockRestore();
    }
  });

  test('② 同源：六种令牌形态逐一过真实控制器，交给吊销的值必须等于提取器的答案', async () => {
    // 不"抠源码求值"（那是 eval，也会被自家 lint 拦），改成逐形态真跑一次登出：
    // 断言 revokeTokensOnLogout 收到的 accessToken === extractAccessToken(同一 req)，
    // 即"登出吊销的令牌"与"认证放行的令牌"恒等——分叉一出现就红。
    for (const [name, headers] of SHAPES) {
      const spy = jest
        .spyOn(authService, 'revokeTokensOnLogout')
        .mockResolvedValue({ revokeFailed: false });
      const req = makeReq(headers);
      const expected = extractAccessToken(req);

      let call = request(buildApp()).post('/api/auth/logout');
      if (headers.authorization !== undefined)
        call = call.set('Authorization', headers.authorization);
      if (headers.cookie !== undefined) call = call.set('Cookie', headers.cookie);
      const res = await call;

      expect(res.status).toBe(200);
      const received = spy.mock.calls[0][0].accessToken;
      // 把形态名一起放进断言对象：失败时 diff 直接点名是哪一形态分叉了，
      // 同时把 null（没带令牌）与 '' 归一成同一口径
      expect({ shape: name, accessToken: received || null }).toEqual({
        shape: name,
        accessToken: expected,
      });
      spy.mockRestore();
    }
  });

  test('③ 静态禁令：登出里不得再自行解析 Authorization', () => {
    const src = fs
      .readFileSync(path.resolve(__dirname, '../controllers/authController.js'), 'utf8')
      .replace(/\r\n/g, '\n');
    const start = src.indexOf('const logout = asyncHandler');
    const end = src.indexOf('/**', start);
    const body = src.slice(start, end === -1 ? undefined : end);

    const RE_LOCAL_PARSE = /authHeader\.split\(|authorization\.split\(|startsWith\('Bearer /;
    // 先自证这条正则抓得到被禁写法，空匹配才不是假绿
    expect(RE_LOCAL_PARSE.test("  token = authHeader.split(' ')[1];")).toBe(true);
    expect(RE_LOCAL_PARSE.test("if (authHeader.startsWith('Bearer ')) {")).toBe(true);
    expect(body.match(RE_LOCAL_PARSE)).toBeNull();
  });
});
