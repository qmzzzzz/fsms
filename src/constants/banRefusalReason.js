'use strict';

/**
 * 封段/段写入的拒绝原因枚举（单一事实来源）。此前有六份互不对账的副本（产出字面量 / OpenAPI /
 * 注册表注释 / ADR-018 / 前端映射 / 前端用例），实测差集已漏掉 typed_confirmation_required——
 * 唯一"再点一次就能自救"的原因。三向对账见 src/tests/ci/banRefusalEnumSingleSource.test.js。
 * ticket=false 是判据类（换台机器也一样，提示后停手），true 是票据类（重新发起即可）。
 */
const REFUSAL_REASONS = Object.freeze({
  unparsable_cidr: { text: '网段格式无法解析', ticket: false },
  full_range_cidr: { text: '这是全网段（/0）', ticket: false },
  whitelist_covers: { text: '白名单已覆盖该网段，封了不会生效', ticket: false },
  union_covers_family: { text: '与已有黑名单并集后覆盖整个地址族', ticket: false },
  operator_inside: { text: '操作者自己在该网段内', ticket: false },
  live_traffic_inside: { text: '该网段最近仍有真实业务请求', ticket: false },
  reason_required: { text: '未填写封禁理由', ticket: false },
  typed_confirmation_required: { text: '该网段影响面大，必须逐字输入网段本身', ticket: false },
  unknown_token: { text: '确认票据不存在或已失效', ticket: true },
  token_expired: { text: '确认票据已过期（有效期 10 分钟）', ticket: true },
});

const REFUSAL_REASON_KEYS = Object.freeze(Object.keys(REFUSAL_REASONS));
// CODES：产出方写 CODES.xxx 而不是字面量，拼错即 undefined 并被对账闸抓红
const CODES = Object.freeze(Object.fromEntries(REFUSAL_REASON_KEYS.map((key) => [key, key])));
const REFUSAL_TEXT = Object.freeze(
  Object.fromEntries(REFUSAL_REASON_KEYS.map((key) => [key, REFUSAL_REASONS[key].text]))
);
const isTicketReason = (reason) => Boolean(REFUSAL_REASONS[String(reason)]?.ticket);

module.exports = { CODES, REFUSAL_REASON_KEYS, REFUSAL_TEXT, REFUSAL_REASONS, isTicketReason };
