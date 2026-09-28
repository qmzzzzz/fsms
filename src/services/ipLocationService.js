/**
 * IP 归属地服务（会话管理等后台展示场景）
 *
 * 给后台界面把裸 IP 翻译成「国家·省·市·运营商」可读串：会话管理、安全审计
 * 核查时，运营商标级归属地比点分十进制更有辨识度（一眼看出"这台设备在
 * 深圳、走电信"，而不是对着一串数字回忆）。
 *
 * 为什么是本地离线检索而不是在线 API：归属地是纯增强信息，若为它引入
 * 一次外网往返，sessions 接口的耗时会从毫秒级抬到秒级且不可控（第三方限频、
 * 断网、SSRF 面都进来了）。改用仓库内置的 ip2region xdb 数据（见
 * src/utils/ip2regionSearcher.js），全内存二分检索约微秒级，列表页加载
 * 速度不受影响；进程内再做一层结果缓存，同一 IP（同会话反复刷新）直接命中。
 *
 * 失败语义（fail-soft）：归属地查不出 ≠ 会话有问题。任何异常（数据文件缺失、
 * 畸形 IP、格式不符预期）一律返回 null，调用方省略展示即可，绝不影响
 * 会话列表本身；数据文件加载失败只告警一次，避免每请求刷日志。
 */
const logger = require('../utils/logger');
const ipaddr = require('ipaddr.js');
const { normalizeIP } = require('../utils/ipUtils');
const searcher = require('../utils/ip2regionSearcher');

/** IPv6 的内网族 range（ipaddr.js 口径）：回环 / 链路本地 / ULA */
const IPV6_PRIVATE_RANGES = new Set(['loopback', 'linkLocal', 'uniqueLocal']);

/** 结果缓存上限：会话列表单页条数极小，2048 条足够覆盖多用户多会话的重复查询 */
const CACHE_LIMIT = 2048;

const resultCache = new Map();
/** 数据文件加载失败只告警一次的开关（防每请求刷日志） */
let loadFailureLogged = false;

/**
 * 把 xdb 原始串「国家|区域|省份|城市|ISP」拼成展示文本。
 *
 * 规则：'0' 占位与空段丢弃，剩余字段用 '·' 连接（语言中立，前端无需 i18n）；
 * 数据把私网/环回统一标为「内网IP」（城市与 ISP 位），收敛成两字「内网」，
 * 与后台列表里 IPv6 内网网段无法出归属地的情形保持同一口径。
 *
 * @param {string} raw xdb 原始地区串
 * @returns {string|null} 可读归属地；全空（理论不出现）返回 null
 */
const formatRegion = (raw) => {
  const parts = raw.split('|');
  if (parts.some((p) => p === '内网IP')) return '内网';
  // 字段序固定：国家|区域|省份|城市|ISP；「区域」（国家下级行政区）国内数据恒为占位
  const [country, , province, city, isp] = parts;
  const shown = [country, province, city, isp].filter((p) => p && p !== '0');
  return shown.length > 0 ? shown.join('·') : null;
};

/**
 * 查询 IP 的归属地展示文本。
 *
 * @param {string|null} ipText 客户端 IP 原文（允许带 ::ffff: 前缀、空白；允许任意垃圾输入）
 * @returns {string|null} 「中国·广东省·深圳市·电信」形态；查不出返回 null
 */
const locate = (ipText) => {
  if (typeof ipText !== 'string' || !ipText.trim()) return null;

  const key = ipText.trim();
  if (resultCache.has(key)) return resultCache.get(key);

  let result = null;
  try {
    // normalizeIP 复用名单/审计同一套入站判据：::ffff:1.2.3.4 收敛为纯 IPv4，
    // 歧义写法（0177.0.0.1 等）与非法文本直接 null——归属地不做"猜意图"的宽松解释
    const normalized = normalizeIP(key);
    if (normalized && !normalized.includes(':')) {
      const raw = searcher.search(normalized);
      if (typeof raw === 'string' && raw.length > 0) {
        result = formatRegion(raw);
      }
    } else if (normalized) {
      // IPv6 当前仅内置 v4 数据（v6 是独立数据文件，未随库分发），公网 v6 查不出
      // 归属；但回环/链路本地/ULA 这类内网形态必须给出「内网」——否则本机与内网
      // IPv6 会话（::1、fe80::、fc00::）在后台表现为"查不到"，与 IPv4 内网口径分裂
      const range = ipaddr.parse(normalized).range();
      if (IPV6_PRIVATE_RANGES.has(range)) result = '内网';
    }
  } catch (err) {
    // fail-soft：数据文件缺失/损坏时归属地整体降级为不展示，但不打断会话列表
    if (!loadFailureLogged) {
      loadFailureLogged = true;
      logger.warn(`IP 归属地检索不可用（已降级为不展示）：${err.message}`);
    }
  }

  if (resultCache.size >= CACHE_LIMIT) {
    // Map 迭代序即插入序：删最早一条，代价 O(1)。归属地不随时间变化，
    // FIFO 与 LRU 的命中率差异可忽略
    resultCache.delete(resultCache.keys().next().value);
  }
  resultCache.set(key, result);
  return result;
};

/** 清空结果缓存（仅测试用：验证缓存边界行为） */
const clearCache = () => {
  resultCache.clear();
};

module.exports = {
  CACHE_LIMIT,
  locate,
  clearCache,
};
