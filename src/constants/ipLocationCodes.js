/**
 * IP 归属地展示码的单一来源
 *
 * 背景（i18n 缺口）：`location` 原先是后端直接拼好的**展示文本**，私网/环回
 * 地址收敛成中文两字「内网」（src/services/ipLocationService.js）。这类字段
 * 一旦是成句文案，英文界面就没有任何办法正确显示——前端拿到的是已经定型的
 * 中文串，vue-i18n 无从下手。表现是：管理员把界面切到 en-US，会话管理 /
 * 审计日志 / IP 名单里内网 IP 旁边仍挂着「内网」两字。
 *
 * 修法与仓内既有口径一致（constants/securitySuggestions.js、utils/auditLabels.js
 * 的 audit.action.*、utils/labelMaps.js 的 DEVICE_TYPE）：**后端只出稳定码，
 * 文案归前端词表**。本文件是那份码表的唯一声明处——前端词表
 * （web-admin/src/utils/ipLocationLabels.js 消费的 ipLocation.* 组）必须逐一
 * 覆盖，由 web-admin/src/tests/utils/ipLocationCodeParity.test.js 直接
 * createRequire 本文件对账（同 securitySuggestionParity 的做法），所以
 * 「后端加一码、前端漏翻」会让该用例变红，而不是在界面上静默显示裸码。
 *
 * 覆盖面只含**非数据**的取值：公网 IP 的归属地是 ip2region 数据原样拼出的
 * 「中国·广东省·深圳市·电信」，那是数据不是文案，不进本表（数据侧本地化
 * 是另一个议题，与本修复无关）。
 *
 * 兼容性：`location` 的**类型不变**（仍是 string|null），只有私网这一支的
 * 取值从中文文本变为稳定码；前端映射带**原始串回退**（未知值原样显示），
 * 故老客户端/老响应不会白屏。滚动发布中新前端 + 老后端时收到中文「内网」，
 * 按原样透传显示——与修复前一致，不回退成空白。
 */

const IP_LOCATION_CODES = Object.freeze({
  /** 私网/回环/链路本地/ULA：IPv4 由 xdb 数据标「内网IP」，IPv6 由服务层按 range 判定 */
  PRIVATE_NETWORK: 'private',
});

// 全集（前端词表按此对账）。顺序即声明顺序，无业务含义。
const IP_LOCATION_CODE_VALUES = Object.freeze(Object.values(IP_LOCATION_CODES));

module.exports = { IP_LOCATION_CODES, IP_LOCATION_CODE_VALUES };
