/**
 * IP 黑白名单数据访问服务（A-4：控制器直连模型下沉）
 *
 * 控制器保留 HTTP 校验、冲突策略与响应编排；名单查询、匹配、写入与
 * 操作者超管判定集中在这里，避免 controllers/ 继续 expansion 模型引用。
 */
'use strict';

const IPBlacklist = require('../models/IPBlacklist');
const User = require('../models/User');
const AuditLog = require('../models/AuditLog');
const { isSuperAdminRole } = require('../utils/superAdmin');

/**
 * 分页列表：list 与三类计数共用同一批过滤条件（控制器构造并传入）。
 * @param {{filter: object, activeFilter: object, page: number, limit: number}} args
 */
async function listEntries({ filter, activeFilter, page, limit }) {
  const [list, total, blackCount, whiteCount] = await Promise.all([
    IPBlacklist.find(filter)
      .sort({ createdAt: -1 })
      .skip((page - 1) * limit)
      .limit(limit)
      .lean(),
    IPBlacklist.countDocuments(filter),
    IPBlacklist.countDocuments({ ...activeFilter, type: 'black' }),
    IPBlacklist.countDocuments({ ...activeFilter, type: 'white' }),
  ]);
  return { list, total, blackCount, whiteCount };
}

/** 查询某个地址在两类名单中的全部命中（匹配口径由模型静态方法提供） */
async function matchEntries(ip) {
  const [blackMatches, whiteMatches] = await Promise.all([
    IPBlacklist.matchIP(ip, 'black'),
    IPBlacklist.matchIP(ip, 'white'),
  ]);
  return { blackMatches, whiteMatches };
}

const findCoveringEntries = (ip, type) => IPBlacklist.findCoveringEntries(ip, type);
const unblockIP = (ip, type) => IPBlacklist.unblockIP(ip, type);
const blockIP = (ip, options) => IPBlacklist.blockIP(ip, options);
const findEntryById = (id) => IPBlacklist.findById(id);
const removeEntry = (id, type) => IPBlacklist.removeById(id, type);

/**
 * 取某类型名单当前**仍生效**的条目文本，供「并集是否铺满地址族」判定用。
 *
 * 走模型快照（10s TTL）而不是直查：覆盖判定与管理面运行期匹配必须读同一份口径，
 * 且该判定处在添加路径的请求热路径上。过期条目在快照里可能尚未被惰性清理，故显式按
 * expiresAt 过滤，不拿不参与匹配的条目凑满覆盖。顺序无关（调用方会做区间排序）。
 * @param {'black'|'white'} type
 * @returns {Promise<string[]>}
 */
async function listActiveEntryIps(type) {
  const entries = await IPBlacklist.getSnapshot(type);
  const now = Date.now();
  return entries
    .filter((entry) => entry.ip && (!entry.expiresAt || new Date(entry.expiresAt).getTime() > now))
    .map((entry) => entry.ip);
}

/** 取**永不过期**（expiresAt 为空）的条目文本：临时的也算生效，但只有永久条目能当救援路径
 * （临时白 + 永久 /0 = 一小时后就没人能解），与 listActiveEntryIps 各留一份取值。 */
async function listPermanentEntryIps(type) {
  const entries = await IPBlacklist.getSnapshot(type);
  return entries.filter((entry) => entry.ip && !entry.expiresAt).map((entry) => entry.ip);
}

/**
 * 操作者是否为内置超级管理员——只认生效角色，口径与 auth.js buildAuthContext、
 * rbac.js 的回退查询一致。字符串形式的 populate 无法携带 match，故必须写成对象形式：
 * 否则「直连数据库把 SUPER_ADMIN 置为 inactive」之后，其持有者仍被判定为超管。
 *
 * 防御性说明：实测 mongoose 8.24.1 对 populate+match 未命中的引用是**丢弃元素**
 * （不留 null），故 isSuperAdminRole 的 !!role 判空今天是冗余；保留以防版本改行为。
 * @param {string} userId
 * @returns {Promise<boolean>}
 */
async function operatorIsSuperAdmin(userId) {
  const operator = await User.findById(userId)
    .populate({ path: 'roles', select: 'code isBuiltIn', match: { status: 'active' } })
    .lean();
  return (operator?.roles || []).some(isSuperAdminRole);
}

/** 拒绝侧的高危留痕（调用方不 await，保持既有 best-effort 语义） */
function recordPrivilegeEscalation(doc) {
  return AuditLog.record(doc);
}

module.exports = {
  listEntries,
  matchEntries,
  findCoveringEntries,
  unblockIP,
  blockIP,
  findEntryById,
  removeEntry,
  listActiveEntryIps,
  listPermanentEntryIps,
  operatorIsSuperAdmin,
  recordPrivilegeEscalation,
};
