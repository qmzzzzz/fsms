'use strict';

/**
 * dev 访问日志格式（utils/accessLogDevFormat）的脱敏锚（审计 2026-11-14）。
 *
 * 'dev' 预设直接拼 req.originalUrl：本地调试 URL 里 query 的令牌/口令会原样进终端
 * 与 dev 日志文件。app.js 的 dev 分支因此改走本模块——用例钉住两点：
 *   ① query 经 redactUrlQuery 同源打码（凭据类参数 = ***），明文不得出现在日志行；
 *   ② 版式与 morgan 'dev' 预设同形（method :url :status :response-time ms - :res[content-length]，
 *      状态码按 500/400/300/200 分色），字段缺失按预设的 '-' 兜底。
 * 真实驱动机器：token 用与 app.js 相同的注册方式（morgan.token('safe-url', …)），
 * 不 mock morgan 本体。
 */

const morgan = require('morgan');
const { redactUrlQuery } = require('../../utils/helpers');
const { devSafeFormat } = require('../../utils/accessLogDevFormat');

// 与 app.js 同款注册（app.js 在 createApp 里注册；本文件直接驱动格式函数，同一注册表）
morgan.token('safe-url', (req) => redactUrlQuery(req.originalUrl || req.url));

/** headersSent 为真的最小 res 形状（morgan 的 status/res token 都先判它） */
const makeRes = (statusCode) => ({
  statusCode,
  headersSent: true,
  getHeader: () => undefined,
});
const req = { method: 'GET', originalUrl: '/api/devices?token=SUPERSECRET&page=2' };

describe('accessLogDevFormat：dev 分支的 query 脱敏', () => {
  test('凭据类 query 打码，明文不得出现在日志行', () => {
    const line = devSafeFormat(morgan, req, makeRes(200));
    expect(line).not.toContain('SUPERSECRET'); // 承重：红时直接看到明文令牌
    expect(line).toContain('token=***&page=2');
  });

  test('版式与 dev 预设同形：状态码分段取色，字段缺失兜底 -', () => {
    const ok = devSafeFormat(morgan, req, makeRes(200));
    expect(ok).toContain('\x1b[32m200\x1b[0m'); // 2xx 绿（与 morgan dev 同阈值）
    const denied = devSafeFormat(morgan, req, makeRes(403));
    expect(denied).toContain('\x1b[33m403\x1b[0m'); // 4xx 黄
    const boom = devSafeFormat(morgan, req, makeRes(500));
    expect(boom).toContain('\x1b[31m500\x1b[0m'); // 5xx 红
    for (const line of [ok, denied, boom]) {
      expect(line).toMatch(/ms - -/); // 夹具无 response-time / content-length ⇒ '-' 兜底
    }
    // 非 2xx/4xx/5xx（如 100）落回无色档 0，也不抛错
    expect(() => devSafeFormat(morgan, req, makeRes(100))).not.toThrow();
  });
});
