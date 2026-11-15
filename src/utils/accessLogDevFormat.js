/** morgan dev 预设的脱敏替身（app.js 的交互式开发分支专用，审计 2026-11-14）。'dev' 预设直接拼 req.originalUrl（含 query）：本地调试 URL 里的令牌/口令会原样进终端与 dev 日志文件——与生产分支弃用 'combined'、改用 :safe-url 的同一理由。本模块按 morgan 源码 developmentFormatLine 的同款阈值（500/400/300/200）复刻 dev 的版式与状态码分色，只把 :url 换成 app.js 注册的 :safe-url token（helpers.redactUrlQuery 同源打码）；生产/CI 分支的 COMBINED_SAFE_FORMAT 一字不动。 */
/** 单独成文件是体积棘轮的要求：app.js 的 max-lines 地板没有余量，而这份格式器只依赖 morgan 的 token 注册表（第一个实参，即 morgan 模块本体），与 app 的装配顺序解耦。 */

/** 逐请求生成一行访问日志（morgan 的自定义 format 函数形态）。token 取不到值（无响应耗时 / 无 content-length 头）时按编译预设的兜底输出 '-'，与 'dev' 预设可观测行为一致。@param {import('morgan').TokenIndexer} tokens morgan 模块本体（token 注册表） @param {import('express').Request} req @param {import('express').Response} res @returns {string} 与 dev 预设同版式的一行访问日志（URL 的 query 已打码） */
const devSafeFormat = (tokens, req, res) => {
  const status = res.statusCode;
  const color =
    status >= 500 ? 31 : status >= 400 ? 33 : status >= 300 ? 36 : status >= 200 ? 32 : 0;
  return (
    `\x1b[0m${req.method} ${tokens['safe-url'](req, res)} \x1b[${color}m` +
    `${tokens.status(req, res) || '-'}\x1b[0m ` +
    `${tokens['response-time'](req, res) || '-'} ms - ` +
    `${tokens.res(req, res, 'content-length') || '-'}\x1b[0m`
  );
};

module.exports = { devSafeFormat };
