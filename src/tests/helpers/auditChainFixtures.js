/**
 * 审计链校验器的**免数据库**夹具（一处实现）。
 *
 * 为什么要有这个文件：`verifyAuditChain(AuditLog, opts)` 只用到
 * `find().sort().limit().lean()` 这一条链，所以整条判据可以在不启数据库的情况下真跑。
 * 但仓里已经各自抄了 **4 份** 这个夹具——
 *   src/tests/services/auditChainVerify.test.js:11、
 *   src/tests/services/auditChainGuardedIntegrity.test.js:22、
 *   src/tests/services/auditChainLegacyPrefixWash.test.js:23、
 *   src/tests/chainVerifyYieldAtScale.test.js:30，
 * 三份把它命名成 `docsNewestFirst`、一份命名成 `docs`，而且**只有一份真的截 limit**：
 * 其余三份里 `maxRecords` 对读回的条数没有任何影响，于是"窗口被 maxRecords 截断"这个
 * 形状在那些文件里根本不存在（它测的是别的东西，却容易被读成测了这个）。
 * 判据归一处同样适用于夹具：新增的校验器测试请从这里 require，别再抄第 5 份。
 */
const mongoose = require('mongoose');
const { computeHash, computeHmac, canonicalPayload } = require('../../utils/auditChain');

/**
 * @param {Array<Object>} docsNewestFirst 按 `_id` 降序（最新在前）——与真实 `sort({_id:-1})` 同形态，
 *   校验器自己会 reverse 成升序再逐条校验。
 */
function makeAuditLog(docsNewestFirst) {
  return {
    find: () => ({
      sort: () => ({
        // limit 必须真的截：否则"截断窗口"那条形状名不副实。
        limit: (n) => ({
          lean: () =>
            Promise.resolve(Number.isFinite(n) ? docsNewestFirst.slice(0, n) : docsNewestFirst),
        }),
      }),
    }),
  };
}

/** 造一条内容合法、哈希与 hmac 都算得回来的记录；`previous` 为 null 即链首。 */
function buildValidDoc(previous, overrides = {}) {
  const doc = {
    _id: new mongoose.Types.ObjectId(),
    timestamp: new Date('2026-09-04T08:00:00.000Z'),
    action: 'login',
    category: 'auth',
    userId: '64f000000000000000000001',
    username: 'alice',
    ip: '127.0.0.1',
    path: '/api/auth/login',
    statusCode: 200,
    body: {},
    hashVersion: 3,
    ...overrides,
  };
  doc.prevHash = previous ? previous.hash : null;
  doc.hash = computeHash(doc.prevHash, canonicalPayload(doc, doc.hashVersion));
  doc.hmac = computeHmac(doc.hash);
  return doc;
}

/**
 * 将一条记录的父哈希**改写**成指定的那个（内容仍自洽：hash/hmac 按新 prevHash 重算），
 * 这就是"同父两子"里的第二个孩子——分叉形态。
 */
function reParent(doc, parentHash, idOverride) {
  const next = { ...doc, prevHash: parentHash };
  if (idOverride) next._id = idOverride;
  next.hash = computeHash(next.prevHash, canonicalPayload(next, next.hashVersion));
  next.hmac = computeHmac(next.hash);
  return next;
}

/** 按时序构建 n 条诚实记录，返回**升序**数组（[0]=链首，[n-1]=链尾）。 */
function buildChain(n, startEpochSec = 1700000000) {
  const out = [];
  let previous = null;
  for (let index = 0; index < n; index += 1) {
    const doc = buildValidDoc(previous, {
      action: `action-${index}`,
      _id: mongoose.Types.ObjectId.createFromTime(startEpochSec + index),
    });
    out.push(doc);
    previous = doc;
  }
  return out;
}

/** 升序数组喂给校验器时要转成"最新在前"。 */
function toNewestFirst(asc) {
  return [...asc].reverse();
}

module.exports = { makeAuditLog, buildValidDoc, reParent, buildChain, toNewestFirst };
