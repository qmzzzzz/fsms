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

// 单个 query 参数值的最大长度（覆盖 IP 段查询、复合关键字等最长场景）
const MAX_QUERY_VALUE_LENGTH = 200;

// 回显安全清洗（L4）：query 键名进入响应与日志前去除控制字符等危险内容并截断，
// 防止日志注入/响应污染；仅保留常见安全字符
const sanitizeParamName = (name) =>
  String(name)
    .replace(/[^\w.\-\u4e00-\u9fff]/g, '*')
    .slice(0, 50);

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
        url: req.originalUrl,
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
 * 注意：本中间件须挂在 applySecurity（含 sanitizeMongo/hpp）之后，
 * 保证看到的是清洗后的最终形态。
 *
 * @returns {Function} Express 中间件
 */
function queryScalarGuard() {
  return (req, res, next) => {
    // IP 白名单豁免：可信来源不受 query 标量收敛约束
    if (req.ipWhitelisted === true) return next();

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
        url: req.originalUrl,
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
