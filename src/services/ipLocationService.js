// IP 归属地服务：离线检索选型、懒加载三态与 fail-soft 语义见 docs/ip-location-service.md
const logger = require('../utils/logger');
const ipaddr = require('ipaddr.js');
const { normalizeIP } = require('../utils/ipUtils');
const searcher = require('../utils/ip2regionSearcher');
const { IP_LOCATION_CODES } = require('../constants/ipLocationCodes');

/** IPv6 的内网族 range（ipaddr.js 口径）：回环 / 链路本地 / ULA */
const IPV6_PRIVATE_RANGES = new Set(['loopback', 'linkLocal', 'uniqueLocal']);

/** 结果缓存上限：会话列表单页条数极小，2048 条足够覆盖多用户多会话的重复查询 */
const CACHE_LIMIT = 2048;

/** 加载失败哨兵的存续期：期内短路，过后重试一次 */
const LOAD_RETRY_MS = 5 * 60 * 1000;
/** 运行期异常 warn 的节流窗口 */
const RUNTIME_WARN_THROTTLE_MS = 60 * 1000;

const resultCache = new Map();
let handle; // undefined=未加载 | false=加载失败哨兵 | 检索句柄（ip2regionSearcher.loadDataFile 的返回值）
let loadFailedAt = 0;
let loadFailureLogged = false;
let lastRuntimeWarnAt = 0;

/**
 * 取检索句柄（懒加载独立层）。返回 null = 加载失败哨兵期内（调用方短路返回 null）。
 * 加载失败置哨兵与告警闩；成功则复位闩。哨兵过期自动重试一次。
 */
const acquireHandle = () => {
  if (handle) return handle; // 已加载：进程内复用，绝不重读数据文件
  if (handle === false) {
    if (Date.now() - loadFailedAt < LOAD_RETRY_MS) return null; // 哨兵期内短路：不重做 11MB 同步读
    // 哨兵已过期：下面的加载即是本回合的一次重试（数据修复 ⇒ 无需重启进程即恢复）
  }
  try {
    handle = searcher.loadDataFile();
    loadFailureLogged = false; // 成功复位闩：下次失败重新告警一次（每个故障回合一条）
    return handle;
  } catch (e) {
    handle = false;
    loadFailedAt = Date.now();
    if (!loadFailureLogged) {
      loadFailureLogged = true;
      logger.warn(
        `IP 归属地数据加载失败（5 分钟内短路返回 null，稍后自动重试；归属地整体降级为不展示）：${e.message}`
      );
    }
    return null;
  }
};

/**
 * 把 xdb 原始串「国家|区域|省份|城市|ISP」拼成展示文本。
 *
 * 规则：'0' 占位与空段丢弃，剩余字段用 '·' 连接（语言中立，前端无需 i18n）；
 * 数据把私网/环回统一标为「内网IP」（城市与 ISP 位），收敛成稳定码
 * `private`（constants/ipLocationCodes.js）——与后台列表里 IPv6 内网网段
 * 无法出归属地的情形保持同一口径，同时不把中文文案焊死在 API 响应里。
 *
 * @param {string} raw xdb 原始地区串
 * @returns {string|null} 可读归属地；全空（理论不出现）返回 null
 */
const formatRegion = (raw) => {
  const parts = raw.split('|');
  if (parts.some((p) => p === '内网IP')) return IP_LOCATION_CODES.PRIVATE_NETWORK;
  // 字段序固定：国家|区域|省份|城市|ISP；「区域」（国家下级行政区）国内数据恒为占位
  const [country, , province, city, isp] = parts;
  const shown = [country, province, city, isp].filter((p) => p && p !== '0');
  return shown.length > 0 ? shown.join('·') : null;
};

/**
 * IPv4 检索单步（拆出是给 locate 的 complexity 棘轮让路）：取句柄 → searchRaw → 拼展示串。
 * @returns {string|null|undefined} 展示文本；undefined = 加载失败哨兵期内（调用方短路返回 null）
 */
const lookupIPv4 = (normalized) => {
  const acquired = acquireHandle();
  if (acquired === null) return undefined; // 哨兵期内短路
  const raw = searcher.searchRaw(acquired, normalized);
  return typeof raw === 'string' && raw.length > 0 ? formatRegion(raw) : null;
};

/**
 * 查询 IP 的归属地展示文本。
 *
 * @param {string|null} ipText 客户端 IP 原文（允许带 ::ffff: 前缀、空白；允许任意垃圾输入）
 * @returns {string|null} 「中国·广东省·深圳市·电信」形态，或内网稳定码 private；查不出返回 null
 */
const locate = (ipText) => {
  if (typeof ipText !== 'string' || !ipText.trim()) return null;

  let result = null;
  let cacheable = false; // 失败路径（哨兵短路/运行期异常）不入缓存：恢复后下一条查询即用上新结果
  try {
    // normalizeIP 复用名单/审计同一套入站判据：::ffff:1.2.3.4 收敛为纯 IPv4，
    // 歧义写法（0177.0.0.1 等）与非法文本直接 null——归属地不做"猜意图"的宽松解释
    const normalized = normalizeIP(ipText.trim());
    // 缓存键必须用**归一化文本**：223.5.5.5 / ::ffff:223.5.5.5 / 带空白形态是同一个地址，
    // 各占一个槽会让 2048 上限被等价形态摊薄。归一化失败的垃圾输入按原文各自成键
    // （互相不污染），由 FIFO 上限兜底
    const cacheKey = normalized || ipText.trim();
    if (resultCache.has(cacheKey)) return resultCache.get(cacheKey);

    if (normalized && !normalized.includes(':')) {
      const shown = lookupIPv4(normalized);
      if (shown === undefined) return null; // 加载失败哨兵期内：短路，不入缓存
      result = shown;
    } else if (normalized) {
      // IPv6 当前仅内置 v4 数据（v6 是独立数据文件，未随库分发），公网 v6 查不出
      // 归属；但回环/链路本地/ULA 这类内网形态必须给出稳定码 private——否则本机
      // 与内网 IPv6 会话（::1、fe80::、fc00::）在后台表现为"查不到"，与 IPv4 内网口径分裂
      const range = ipaddr.parse(normalized).range();
      if (IPV6_PRIVATE_RANGES.has(range)) result = IP_LOCATION_CODES.PRIVATE_NETWORK;
    }

    cacheable = true;
    if (resultCache.size >= CACHE_LIMIT) {
      // Map 迭代序即插入序：删最早一条，代价 O(1)。归属地不随时间变化，
      // FIFO 与 LRU 的命中率差异可忽略
      resultCache.delete(resultCache.keys().next().value);
    }
    resultCache.set(cacheKey, result);
  } catch (err) {
    // 运行期异常（句柄已加载后的 searchRaw/formatRegion 抛错）：**不置位**加载闩——
    // 句柄还好好的，一次畸形输入不该杀掉整个归属地面 5 分钟。逐条 warn（60s 节流）
    // 返回 null；本条结果不入缓存。
    const now = Date.now();
    if (now - lastRuntimeWarnAt >= RUNTIME_WARN_THROTTLE_MS) {
      lastRuntimeWarnAt = now;
      logger.warn(`IP 归属地检索异常（本条降级为不展示）：${err.message}`);
    }
  }
  return cacheable ? result : null;
};

/** 清空结果缓存（仅测试用：验证缓存边界行为） */
const clearCache = () => {
  resultCache.clear();
};

/** 重置句柄三态与告警闩（仅测试用：验证加载失败哨兵/重试语义） */
const resetForTest = () => {
  resultCache.clear();
  handle = undefined;
  loadFailedAt = 0;
  loadFailureLogged = false;
  lastRuntimeWarnAt = 0;
};

module.exports = {
  CACHE_LIMIT,
  LOAD_RETRY_MS,
  RUNTIME_WARN_THROTTLE_MS,
  locate,
  clearCache,
  resetForTest,
};
