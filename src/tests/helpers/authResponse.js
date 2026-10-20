/**
 * 从 supertest 响应的 Set-Cookie 中取令牌。
 *
 * S-1 之后登录/刷新响应体不再回传 token/refreshToken，集成测试只能从 cookie 取。
 */
'use strict';

function cookieValue(res, name) {
  const raw = res?.headers?.['set-cookie'];
  const list = Array.isArray(raw) ? raw : raw ? [raw] : [];
  const hit = list.find((c) => String(c).startsWith(`${name}=`));
  if (!hit) return undefined;
  return String(hit)
    .split(';')[0]
    .slice(name.length + 1);
}

const accessToken = (res) => cookieValue(res, 'access_token');
const refreshToken = (res) => cookieValue(res, 'refresh_token');

module.exports = { cookieValue, accessToken, refreshToken };
