/**
 * 查询参数长度限制中间件
 *
 * 背景：列表页搜索框（用户名/设备名/关键字等）对应的 GET query 参数
 * 未做长度校验，前端粘贴超长文本后会原样进入 MongoDB 正则/前缀查询，
 * 造成数据库负载放大（可被用于资源耗尽）。
 *
 * 策略：全局拦截所有字符串型 query 参数，超过上限直接返回 400，
 * 上限取业务查询场景的最大合理值（allowedIPs 之类的长文本走 body，不受影响）。
 */

const logger = require('../utils/logger');
// 日志里的 URL 必须过 redactUrlQuery（与 app.js:236 morgan 的 safe-url、
// errorHandler.js:26/100/107 同一口径）：本中间件恰好在"参数可疑"的路径上打日志，
// 未打码就会把 ?accessToken=... 这类凭据原样落盘。
const { redactUrlQuery } = require('../utils/helpers');

// 单个 query 参数值的最大长度（覆盖 IP 段查询、复合关键字等最长场景）
const MAX_QUERY_VALUE_LENGTH = 200;

// 回显安全清洗（L4）：query 键名进入响应与日志前去除控制字符等危险内容并截断，
// 防止日志注入/响应污染；仅保留常见安全字符
const sanitizeParamName = (name) =>
  String(name)
    .replace(/[^\w.\-\u4e00-\u9fff]/g, '*')
    .slice(0, 50);

/**
 * 形态/长度两类查询拒绝都要留审计痕迹。
 *
 * 本中间件挂在 auditLog 之前（它必须在任何业务查询前把畸形参数挡掉），
 * 于是它的 400 原本只进 logger：NoSQL 操作符探测（`?search[$regex]=`、
 * 对象/数组形态取值）与超长参数轰炸是**攻击者还没拿到任何凭据时就能做**的动作，
 * 恰好是最该留下趋势数据的一段流量，此前在合规留存里是一片空白。
 * 姊妹路径（黑名单、来源校验、IP 段）早就通过 recordEarlyRejection 补齐了这类留痕，
 * 这里补的是同一格，不是新发明一套机制。
 *
 * 延迟 require：security.js 与本模块同层且互相引用会成环（originCheck 用的是同一招）。
 */
const recordQueryRejection = (req, meta) => {
  require('./security').recordEarlyRejection(req, meta);
};

/**
 * 校验 req.query 中所有字符串值的长度
 * @param {number} [max=MAX_QUERY_VALUE_LENGTH] 单值最大长度
 * @returns {Function} Express 中间件
 */
function queryLengthLimit(max = MAX_QUERY_VALUE_LENGTH) {
  return (req, res, next) => {
    // IP 白名单豁免：可信来源不受 query 长度限制（内部工具/批量查询可能携带较长参数）
    if (req.ipWhitelisted === true) return next();

    const violated = [];

    const walk = (value, path) => {
      if (typeof value === 'string') {
        if (value.length > max) violated.push(sanitizeParamName(path));
      } else if (Array.isArray(value)) {
        value.forEach((item, i) => walk(item, `${path}[${i}]`));
      } else if (value && typeof value === 'object') {
        Object.entries(value).forEach(([key, item]) => walk(item, path ? `${path}.${key}` : key));
      }
    };

    Object.entries(req.query || {}).forEach(([key, value]) => walk(value, key));

    if (violated.length > 0) {
      logger.warn(`查询参数超长已拦截：${violated.join(', ')}（上限 ${max} 字符）`, {
        reqId: req.id,
        url: redactUrlQuery(req.originalUrl),
      });
      recordQueryRejection(req, {
        action: 'query_param_rejected',
        reason: `查询参数值超过 ${max} 字符：${violated.join(', ')}`,
        riskFactors: ['query_length_violation'],
        riskLevel: 'low',
        statusCode: 400,
      });
      return res.status(400).json({
        success: false,
        message: `查询参数超长：${violated.join(', ')}（单个参数不能超过 ${max} 个字符）`,
      });
    }

    next();
  };
}

/**
 * 查询参数必须为标量（AUX-04 第二例 / P3-4 修复）
 *
 * 问题：Express 的 qs 解析把 `?search[$regex]=^a` 变成对象、
 * `?status=a&status=b` 变成数组。控制器却按字符串消费：
 *   - `search.trim()` → TypeError → 全局兜底 500（可用于盲探内部处理结构）
 *   - `query.status = status` 把对象直接塞进 Mongo 过滤条件 →
 *     `?status[$ne]=active` 形式的操作符注入
 * sanitizeMongo 只删 `$`/`.` 开头的**键**，`search[$regex]=x` 被清成
 * `search: {}` —— 键没了但值仍是对象，`.trim()` 照样炸。
 *
 * 因此在入口统一收敛：query 的每个值必须是字符串（qs 只产出
 * string / string[] / 嵌套对象三种形态）。全仓无任何接口消费数组或对象型
 * query，故一律 400 拒绝，而非静默取首值——静默取值会让
 * `?status=admin&status=x` 之类的参数污染难以察觉。
 *
 * 注意（P1-33 修正，2026-09-17）：原注释称「本中间件须挂在 applySecurity（含
 * sanitizeMongo/hpp）之后，保证看到的是清洗后的最终形态」——该前提在 Express 5 下
 * **不成立**：req.query 是 getter（每次访问重新解析 URL 查询串），sanitizeMongo/hpp
 * 对 req.query 的原地清洗结果在下一次访问时即被丢弃，本中间件看到的始终是
 * **未经清洗的原始解析结果**（实测 `?search[$regex]=^a` 仍为对象、
 * `?status=a&status=b` 仍为数组）。
 * 判定强度不受此影响：本中间件对一切非字符串取值一律拒绝，不依赖上游是否清洗过。
 *
 * **query 侧的真正防线就是本函数（queryScalarGuard，src/app.js 以
 * `app.use('/api/', queryScalarGuard())` 挂载，命中即 400 QUERY_PARAM_MUST_BE_SCALAR）。
 * 若移除它，query 注入防线归零**——sanitizeMongo 与 hpp 对 req.query 的清洗在
 * Express 5 下均已失效，不要以「已有两道防线」为由移除本中间件。
 *
 * @returns {Function} Express 中间件
 */
function queryScalarGuard() {
  return (req, res, next) => {
    // 这里**不设** IP 白名单豁免：本中间件约束的是取值形态（对象/数组一律拒绝），
    // 不是滥用频次。原实现在首行 `if (req.ipWhitelisted) return next()`，
    // 而按本文件头注释，Express 5 下 sanitizeMongo 与 hpp 对 req.query 的清洗均已失效，
    // 于是白名单来源（内网运维段、被误加白的网段）可把 {"$ne":...} 这类操作符对象
    // 直接送进 mongoose 过滤条件——"唯一防线"对白名单归零。
    // 白名单豁免仍保留在 queryLengthLimit / 各限流器上：那才是频次/体量型约束。
    const offenders = [];

    for (const [key, value] of Object.entries(req.query || {})) {
      if (value === undefined || value === null) continue;
      if (typeof value !== 'string') {
        offenders.push(sanitizeParamName(key));
      }
    }

    if (offenders.length > 0) {
      logger.warn(`查询参数类型非法已拦截：${offenders.join(', ')}（要求标量，收到对象/数组）`, {
        reqId: req.id,
        url: redactUrlQuery(req.originalUrl),
      });
      recordQueryRejection(req, {
        action: 'query_param_rejected',
        reason: `查询参数收到对象/数组形态取值：${offenders.join(', ')}`,
        riskFactors: ['query_operator_violation'],
        riskLevel: 'medium',
        statusCode: 400,
      });
      return res.status(400).json({
        success: false,
        message: `查询参数格式无效：${offenders.join(', ')}（不接受对象或数组形式的取值）`,
        errors: { errorCode: 'QUERY_PARAM_MUST_BE_SCALAR', params: offenders.join(',') },
      });
    }

    next();
  };
}

module.exports = queryLengthLimit;
module.exports.queryLengthLimit = queryLengthLimit;
module.exports.queryScalarGuard = queryScalarGuard;
