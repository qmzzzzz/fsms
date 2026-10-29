'use strict';

/**
 * IP 名单写路径的字段闸门（自 ipListController 抽出）
 *
 * 为什么单独成文件：`ipListController.js` 已贴 max-lines 棘轮上限（300 行），
 * 内联这段会让整文件变红；本仓对这类"判据值得独立测试"的小逻辑既有出路口径
 * （inspectionGuards.js / roleGuards.js 先例），抽出来反而多一个可单测的单一事实来源。
 *
 * 判据本身（H-1 附带项，2026-10-29 二轮渗透）：
 * 本接口的时长语义是「`durationHours > 0` 才有时效，0/缺省 = 永久」。客户端如果把
 * 字段名写成 `duration` / `expiresIn` / `hours` 或任何拼写变体，express 不会报错、
 * 控制器也取不到值 ⇒ 归一化成 0 ⇒ **静默变永久封禁**：调用方以为只封一天，
 * 界面与审计里都看不出差别（`expiresAt` 为空）。
 * 这是"参数名错了却拿到 200"的最坏形态——结果比失败更糟，且没有任何信号。
 *
 * 故写路径只接受白名单字段，多一个就 400 并点名。用 `VALIDATION_FAILED` 而不是
 * 新错误码，是为了与既有校验错误的响应形状保持一致（前端只消费 `errors`，
 * 新增错误码还要同步 i18n 码表）。
 */

const ApiResponse = require('../utils/apiResponse');

/** POST /api/security/ip-list 允许的请求体字段 */
const IP_LIST_WRITE_FIELDS = new Set(['ip', 'type', 'reason', 'durationHours']);

/**
 * 拒绝白名单之外的字段（已写出 400 响应时返回 true，调用方应立即 return）
 * @param {import('express').Response} res
 * @param {object} body req.body
 * @returns {boolean} true = 已拒绝
 */
const rejectUnknownWriteFields = (res, body) => {
  const unknown = Object.keys(body || {}).filter((key) => !IP_LIST_WRITE_FIELDS.has(key));
  if (unknown.length === 0) return false;
  ApiResponse.codeError(res, 'VALIDATION_FAILED', {
    fieldErrors: unknown.map((key) => ({
      type: 'field',
      location: 'body',
      path: key,
      msg: `不支持的字段：${key}（生效时长请用 durationHours，0 表示永久）`,
    })),
  });
  return true;
};

module.exports = { IP_LIST_WRITE_FIELDS, rejectUnknownWriteFields };
