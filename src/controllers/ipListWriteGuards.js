'use strict';

/** IP 名单写路径的字段闸门（自 ipListController 抽出，后者已贴 max-lines 棘轮上限）。
 * 只接受白名单字段：字段名写成 duration/expiresIn/hours 等变体时 express 不报错、控制器
 * 取不到值 ⇒ 归一化成 0 ⇒ **静默变永久封禁**（调用方以为只封一天，界面与审计都看不出）。
 * 故多一个字段就 400 并点名；错误码沿用 VALIDATION_FAILED，与既有校验错误的响应形状一致。
 */

const ApiResponse = require('../utils/apiResponse');

const IP_LIST_WRITE_FIELDS = new Set(['ip', 'type', 'reason', 'durationHours', 'typedConfirm']);

/** 拒绝白名单之外的字段；已写出 400 响应时返回 true，调用方应立即 return。 */
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
