/**
 * 测试用二次验证票据：直接从 access token 解出 userId / jti 并本地签发。
 *
 * 审计读取端点要求 X-Reauth-Ticket；测试不必每次都走 POST /security/reauth
 * （那会占用 reauth 限流桶，且多数用例只关心审计读取本身）。
 */
'use strict';

const { issueReauthTicket } = require('../../utils/reauthTicket');

const decodeToken = (token) => {
  const parts = String(token || '').split('.');
  if (parts.length !== 3) throw new Error('reauthTicket 测试助手需要完整的 JWT access token');
  return JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
};

/** @returns {{ 'X-Reauth-Ticket': string }} 可直接传给 supertest 的 .set() */
function reauthHeaders(token) {
  const decoded = decodeToken(token);
  const { ticket } = issueReauthTicket({
    userId: decoded.userId,
    sessionId: decoded.jti || null,
  });
  return { 'X-Reauth-Ticket': ticket };
}

module.exports = { reauthHeaders };
