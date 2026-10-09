/**
 * IP 归属地展示 → 界面文案 的单一映射（i18n）
 *
 * 后端 `location` 字段由两类值组成：
 *  1. **稳定码** `private`（私网/环回，见 src/constants/ipLocationCodes.js）——
 *     中文「内网」/ 英文 "Internal network" 由词表 ipLocation.* 给出；
 *  2. **数据文本**——ip2region xdb 的地区字段原样拼出的「中国·浙江省·杭州市·阿里云」。
 *     这是数据不是文案：xdb 只有中文一份，英文界面要能看就得有一本中英对照词典
 *     （src/data/ipLocationDictionary.json），否则切到 en-US 时这一格仍是中文。
 *
 * 消费方：SessionManager（会话管理）、AuditLogView（审计列表 + 详情弹窗）、
 * IpListView（IP 黑白名单）三处都走这里，避免各自维护一份映射。
 *
 * 回退口径与 utils/auditLabels.js / securityLabels.js 一致：**词典未收录的段原样
 * 透传**（含老后端发来的中文「内网」）。数据刷新带入新地名时，未收录的那一段保持
 * 中文而不是整块归属地消失——覆盖度由 tests/utils/ipLocationDictionary.test.js
 * 对真实 xdb 把关，缺段会以测试红的形式列出，而不是靠用户发现。
 *
 * 语言判定读 i18n 实例的 locale（而非把词典拆成中英两份）：调用点都在渲染期，
 * 读 ref 即建立响应式依赖，切语言会重算。同 utils/api.js 的 `i18n.global.t` 用法。
 */

import dictionary from '@/data/ipLocationDictionary.json'
import i18n from '@/i18n'

/** 数据段分隔符：与后端 formatRegion 的 join('·') 同一口径 */
const SEP = '·'

/** 私网/环回归属地码，取值与 src/constants/ipLocationCodes.js 的 PRIVATE_NETWORK 一致 */
const PRIVATE_NETWORK_CODE = 'private'

/**
 * 中英对照表。用 Map 而非裸对象：段名来自外部数据，裸对象的
 * `SEGMENTS['constructor']` 会拿到 Object 的原型属性（把数据当键查表必须防这个）。
 */
const SEGMENT_EN = new Map(Object.entries(dictionary.segments))

/** 当前界面语言是否需要英文地名（非中文界面一律给英文，含将来的第三种语言） */
const needsEnglish = () => !String(i18n.global.locale.value).startsWith('zh')

/**
 * @param {(key: string) => string} t vue-i18n 翻译函数
 * @param {string|null} location 后端 location 字段原值
 * @returns {string} 可展示文本；无归属地时返回空串
 */
export const ipLocationLabel = (t, location) => {
  if (!location) return ''
  if (location === PRIVATE_NETWORK_CODE) return t('ipLocation.private')
  if (!needsEnglish()) return location
  return location
    .split(SEP)
    .map((seg) => SEGMENT_EN.get(seg) || seg)
    .join(SEP)
}
