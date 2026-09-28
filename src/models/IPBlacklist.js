/**
 * IP 黑白名单模型
 * 持久化存储封禁（黑名单）与放行（白名单）的 IP 地址或 CIDR 网段，进程重启后不丢失
 * 黑名单使用 TTL 索引自动清理过期的封禁记录；白名单默认永久生效
 * 匹配支持：单地址精确匹配、IPv4/IPv6 等价文本归一化、CIDR 子网包含（见 utils/ipUtils）
 */

const mongoose = require('mongoose');
// 取值清单的单一来源（见 constants/ipList.js 头注释：schema enum / 路由 isIn /
// 控制器守卫 / OpenAPI 生成器四处曾各抄一份）
const { IP_LIST_TYPES } = require('../constants/ipList');
const {
  ipMatchesEntry,
  entryPrefixBits,
  entryCovers,
  normalizeIP,
  normalizeCIDR,
  // 严格形态判据住在 ipUtils（四个解析漏斗共用同一把尺子），
  // 过渡模块 utils/ipCanonical 已并入并删除
  isAmbiguousIpText,
} = require('../utils/ipUtils');

/**
 * 条目 IP 的存储前归一化：把"同一个地址的等价写法"收敛成一条记录。
 *
 * 为什么必须在模型里做：`ip` 上的唯一索引是**文本唯一**，而匹配是**语义唯一**
 * （ipMatchesEntry 会把 `::ffff:1.2.3.4` 与 `1.2.3.4`、`2001:0DB8::1` 与
 * `2001:db8::1` 视为同一地址）。两者不对齐时，同一个地址可以躺两条记录——
 * 后果不是"多一条脏数据"，而是 **解封失效**：管理面按精确文本删除其中一条，
 * 另一条继续命中，客户端看起来"封了又封不掉"。今天两个写入方
 * （ipListController / middleware/security 的自动封禁）各自先归一化所以没踩到，
 * 但这个不变行不该由调用方各自记住——存储边界才是它的归属层。
 *
 * 与控制器同一判据：含 `/` 的按 CIDR 归一，否则按单地址归一。
 * 解析不动的值（脏数据、测试里的 `'::::'`）原样保留：归一化只做收敛，
 * 不新增拒绝路径——格式校验属于入站边界（控制器）而不是这里。
 *
 * @param {unknown} value 原始条目文本
 * @returns {string} 归一化后的文本（无法归一化时返回去空格后的原文）
 */
function normalizeEntryIp(value) {
  const raw = typeof value === 'string' ? value.trim() : String(value ?? '');
  if (!raw) return raw;
  const normalized = raw.includes('/') ? normalizeCIDR(raw) : normalizeIP(raw);
  return normalized || raw;
}

const ipBlacklistSchema = new mongoose.Schema({
  ip: {
    type: String,
    required: true,
  },
  // 名单类型：black=黑名单（拦截）、white=白名单（放行，豁免黑名单与限流）
  type: {
    type: String,
    enum: IP_LIST_TYPES,
    default: 'black',
    index: true,
  },
  // 加入原因
  reason: {
    type: String,
    default: 'security_policy',
  },
  // 生效时长（毫秒），0 表示永久生效
  durationMs: {
    type: Number,
    default: 0,
  },
  // 来源：manual（手动配置）、auto（自动检测，如暴力破解）
  source: {
    type: String,
    enum: ['manual', 'auto'],
    default: 'manual',
  },
  // 关联的用户名（如暴力破解攻击的目标账户）
  targetUsername: {
    type: String,
  },
  // 到期时间（用于 TTL 索引自动清理；白名单一般为 null 即永久）
  expiresAt: {
    type: Date,
    default: null,
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
});

// TTL 索引：expiresAt 字段非空时，到期自动删除
ipBlacklistSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

// 复合唯一索引：同一 IP 在黑/白名单各最多一条，两种类型可并存（白名单运行时优先）
ipBlacklistSchema.index({ ip: 1, type: 1 }, { unique: true });

ipBlacklistSchema.pre('validate', function () {
  // create/save/insertMany 走这里；findOneAndUpdate 不跑校验，由 blockIP/unblockIP 自己归一
  if (this.ip !== undefined) this.ip = normalizeEntryIp(this.ip);
});

/**
 * 名单快照缓存（进程内，短 TTL）
 *
 * 背景：等价文本形式与 CIDR 包含关系无法用单一索引表达，匹配必须在内存完成，
 * 因此未命中精确索引时需要全量取回该类型名单。而「未命中」正是绝大多数正常请求的情形，
 * 意味着每个 API 请求都会把黑、白名单各拉一遍——名单增长到数千条后成为明显瓶颈。
 *
 * 策略：按 type 缓存名单快照，TTL 10 秒；所有写路径（blockIP/删除）主动失效。
 * 10 秒是安全性与性能的折中：封禁生效延迟上限 10 秒，且写路径失效后立即生效。
 */
const SNAPSHOT_TTL_MS = 10 * 1000;
const snapshotCache = new Map(); // type -> { entries, expireAt }

/**
 * 使名单快照失效
 * @param {string} [type] 名单类型（black/white）；省略则清空全部
 */
const invalidateSnapshot = (type) => {
  if (type) snapshotCache.delete(type);
  else snapshotCache.clear();
};

/**
 * 取指定类型的名单快照（命中缓存则复用，否则查库并写入缓存）
 * @param {string} type 名单类型
 * @returns {Promise<object[]>} 名单记录数组
 */
const getSnapshot = async function (type) {
  const cached = snapshotCache.get(type);
  if (cached && cached.expireAt > Date.now()) {
    return cached.entries;
  }

  const entries = await this.find({ type }).lean();
  snapshotCache.set(type, { entries, expireAt: Date.now() + SNAPSHOT_TTL_MS });
  return entries;
};

/**
 * 内部工具：取回与客户端 IP 匹配的全部有效名单记录（单地址精确 + 等价形式归一化 + CIDR 网段）
 * - 等价文本形式/CIDR 无法用单一索引查询表达，故取回名单快照后在内存匹配
 * - IPv6 等价文本形式与 IPv4 映射地址（::ffff:1.2.3.4 ≡ 1.2.3.4）均视为同一地址
 * - 过期记录惰性清理（含 CIDR 记录；deleteMany 异步执行不阻塞请求，另有 TTL 索引兜底）
 * - 排序：覆盖面最宽优先（/16 宽于 /24、/24 宽于 /32 单地址），同宽时永久记录优先、
 *   再按到期时间晚者优先——供 IP 查询等展示场景取「最宽泛命中」
 * @param {string} clientIp 客户端 IP
 * @param {string} type 名单类型：black / white
 * @returns {Promise<object[]>} 命中的有效记录（已排序）
 */
const findMatchingEntries = async function (clientIp, type) {
  if (!clientIp || typeof clientIp !== 'string') return [];
  // 形态有歧义的客户端文本（八进制/十六进制/简写）不参与匹配。
  // ipaddr 会把 `0x7f.0.0.1` 解释成 `127.0.0.1`（实测），于是"把自己写成白名单里的
  // 地址"就能同时豁免黑名单与限流。返回空集的方向是安全的：白名单不再被伪装命中；
  // 黑名单侧本来就能靠伪造 XFF 规避（trust proxy 语义），严格化不新增规避面。
  // 真实 socket 地址（含 `::ffff:` 映射形态）都是规范文本，一律通过严格判据。
  if (isAmbiguousIpText(clientIp)) return [];

  const candidates = await getSnapshot.call(this, type);

  const now = new Date();
  const expiredIds = [];
  const matched = [];

  for (const entry of candidates) {
    if (!ipMatchesEntry(clientIp, entry.ip)) continue;
    if (entry.expiresAt && entry.expiresAt <= now) {
      expiredIds.push(entry._id);
      continue;
    }
    matched.push(entry);
  }

  if (expiredIds.length > 0) {
    // 快照内已过期的记录需同时清出缓存，避免 TTL 未到期前反复触发删除
    invalidateSnapshot(type);
    this.deleteMany({ _id: { $in: expiredIds } }).catch(() => {});
  }

  const expiryOf = (entry) => (entry.expiresAt ? entry.expiresAt.getTime() : Infinity);
  matched.sort((a, b) => {
    // 覆盖宽度：前缀位数越小越宽（单地址视为 /32|/128）；无法解析的脏数据排最后
    const widthA = entryPrefixBits(a.ip);
    const widthB = entryPrefixBits(b.ip);
    const wa = widthA === null ? Number.MAX_SAFE_INTEGER : widthA;
    const wb = widthB === null ? Number.MAX_SAFE_INTEGER : widthB;
    if (wa !== wb) return wa - wb;
    return expiryOf(b) - expiryOf(a);
  });

  return matched;
};

/**
 * 内部工具：取客户端 IP 的主命中记录（多条命中时取覆盖面最宽的一条）
 * 走名单快照匹配，命中缓存时零数据库往返；
 * isBlocked/isWhitelisted 仅消费布尔值，不受排序影响
 * @param {string} clientIp 客户端 IP（通常来自 req.ip）
 * @param {string} type 名单类型：black / white
 * @returns {Promise<object|null>} 命中的记录，未命中返回 null
 */
const findMatchingEntry = async function (clientIp, type) {
  if (!clientIp || typeof clientIp !== 'string') return null;

  const matches = await findMatchingEntries.call(this, clientIp, type);
  return matches[0] || null;
};

// 静态方法：检查 IP 是否被封禁（仅黑名单；白名单不构成拦截；支持 CIDR 网段与等价地址归一化）
ipBlacklistSchema.statics.isBlocked = async function (clientIp) {
  const entry = await findMatchingEntry.call(this, clientIp, 'black');
  return !!entry;
};

// 静态方法：检查 IP 是否在白名单（命中则豁免黑名单拦截与限流；支持 CIDR 网段与等价地址归一化）
ipBlacklistSchema.statics.isWhitelisted = async function (clientIp) {
  const entry = await findMatchingEntry.call(this, clientIp, 'white');
  return !!entry;
};

// 静态方法：查询 IP 命中的全部名单记录（按覆盖面最宽优先排序，供 IP 命中查询接口使用）
ipBlacklistSchema.statics.matchIP = async function (clientIp, type) {
  return findMatchingEntries.call(this, clientIp, type);
};

// 静态方法：查找覆盖指定条目的名单记录（支持「网段被更宽网段覆盖」的判断）
// 用于管理面冲突检测：isBlocked/isWhitelisted 只接受单地址，
// 传入 CIDR 时客户端侧解析失败会返回 false，导致白名单优先规则对网段形式失效
ipBlacklistSchema.statics.findCoveringEntries = async function (entryIp, type) {
  if (!entryIp || typeof entryIp !== 'string') return [];

  const candidates = await getSnapshot.call(this, type);
  const now = new Date();

  return candidates.filter((item) => {
    if (item.expiresAt && item.expiresAt <= now) return false;
    return entryCovers(item.ip, entryIp);
  });
};

// 静态方法：添加 IP 到名单（黑/白通用，upsert 语义）
// upsert 键含 type：同一 IP 的黑/白记录相互独立，避免加入一侧时静默覆盖另一侧
// createdAt 用 $setOnInsert：重复封禁同一 IP 时保留首次加入时间，便于追溯「首封时间」
ipBlacklistSchema.statics.blockIP = async function (rawIp, options = {}) {
  const {
    reason = 'security_policy',
    durationMs = 3600000, // 默认 1 小时
    source = 'manual',
    targetUsername,
    type = 'black',
  } = options;
  // findOneAndUpdate 默认不跑 schema 校验，pre('validate') 覆盖不到这里
  const ip = normalizeEntryIp(rawIp);

  const expiresAt = durationMs > 0 ? new Date(Date.now() + durationMs) : null;

  const filter = { ip, type };
  const update = {
    $set: {
      ip,
      reason,
      durationMs,
      source,
      targetUsername,
      type,
      expiresAt,
    },
    $setOnInsert: { createdAt: new Date() },
  };

  let entry;
  try {
    entry = await this.findOneAndUpdate(filter, update, { upsert: true, new: true });
  } catch (err) {
    // 并发 upsert 撞复合唯一索引（E11000）：另一请求已插入同 (ip, type) 记录，
    // 重试一次同样的 findOneAndUpdate 即转为普通更新命中对方文档；仍失败再向上抛出
    if (err.code !== 11000) throw err;
    entry = await this.findOneAndUpdate(filter, update, { upsert: true, new: true });
  }

  invalidateSnapshot(type);
  return entry;
};

// 静态方法：移除指定 IP 的名单记录（不传 type 时清除该 IP 的黑白两侧记录）
// 删除侧同样归一化：否则"按 ::ffff:1.2.3.4 解封"删不掉存成 1.2.3.4 的那条，
// 表现为封得住、解不开（与 blockIP 必须用同一把尺子）
ipBlacklistSchema.statics.unblockIP = async function (rawIp, type) {
  const ip = normalizeEntryIp(rawIp);
  const filter = type ? { ip, type } : { ip };
  const result = await this.deleteMany(filter);
  invalidateSnapshot(type);
  return result;
};

// 静态方法：按 _id 移除单条名单记录（管理面删除入口，附带快照失效）
ipBlacklistSchema.statics.removeById = async function (id, type) {
  const result = await this.deleteOne({ _id: id });
  invalidateSnapshot(type);
  return result;
};

// 静态方法：使名单快照缓存失效（写路径变更后调用，保证下一次匹配读到最新数据）
ipBlacklistSchema.statics.invalidateSnapshot = function (type) {
  invalidateSnapshot(type);
};

// 条目归一化判据（导出给测试与需要预检的调用方；模型内部三个写路径已经用它）
ipBlacklistSchema.statics.normalizeEntryIp = normalizeEntryIp;

// 兜底失效：任何绕过上述静态方法的直接写操作（如测试中的 deleteMany({})、
// 其他模块直接调用 create/updateOne）同样清空快照，避免读到陈旧名单
[
  'save',
  'deleteOne',
  'deleteMany',
  'findOneAndDelete',
  'findOneAndUpdate',
  'updateOne',
  'updateMany',
  'insertMany',
].forEach((op) => {
  ipBlacklistSchema.post(op, function () {
    invalidateSnapshot();
  });
});

module.exports = mongoose.model('IPBlacklist', ipBlacklistSchema);
