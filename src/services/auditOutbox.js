/**
 * 敏感操作审计的**可靠 outbox**（F-03，2026-10-17）
 *
 * 缺口形状（已回源复核）：`AuditLog.record()` 与 `onAuditWriteFailure()` 在落库失败时
 * 只记日志与 `audit_write_failed` 指标，**不改变业务语义**。于是这些路径成立：
 *
 *   业务状态已经改变 → 审计写入失败 → 响应仍返回成功
 *
 * 已确认的调用面：改密码、吊销单个会话、吊销其他会话、开启 MFA、管理员重置 MFA、
 * 公开注册开关、登录验证码开关、注册验证码开关。客户端与运维都无法区分
 * 「业务成功且已记账」与「业务成功但记账失败」——审计链出现缺口而没有任何人知道。
 *
 * 【为什么不是"失败就返回 500"】
 * 这些动作在写审计**之前**就已经提交了（密码已改、会话已吊销、MFA 已开启）。
 * 返回 500 会让客户端以为失败并重试：改密码重试会撞"旧密码不对"，会话吊销重试是
 * 幂等的但会误导用户，MFA 开启重试可能让用户以为没成功而重复扫码。用一次已经完成的
 * 变更去换一个"看起来失败"的响应，是把可观测性问题转成用户体验问题，而且**审计缺口
 * 仍然存在**（500 不会让那条记录回来）。
 *
 * 【修法：先落 WAL 再返回成功】
 * 落库失败时，把**同一条文档**追加进审计 WAL（`services/auditBuffer` 的同步追加路径），
 * 由缓冲在 Mongo 恢复后重放落库。WAL 是 append-only 文件、与审计集合同一份 schema
 * 校验、崩溃后启动期自动重放（见 auditBuffer / auditBufferWal 的头注释）。
 * 因此「返回成功」的前提从"DB 已写"放宽为"**已持久化到可重放的介质**"——这才是
 * 审计留痕的真实要求，也是报告建议的"审计事件先进入可靠 WAL/outbox 后才允许返回成功"。
 *
 * 【什么情况下仍然失败（重抛）】
 *  - 文档本身不合法（schema 校验不过）：写进 WAL 也会被批量路径的预铸造拒掉，
 *    那时"已落 WAL"就是假话。这种情况是代码 bug，必须让调用方看见。
 *  - WAL 未启用（`auditBuffer.start()` 之前、或 logs 目录不可写）：没有可靠介质，
 *    无法声称已留痕 ⇒ 重抛，由 asyncHandler 转成 500。
 * 两者的共同点：**宁可在极端情况下报错，也不假装记账成功**。
 *
 * 【与 PII 查看 / 安全举报的边界】
 * 那两处仍用 `onAuditWriteFailureRethrow`（记账后重抛），**不**走本模块。理由不是
 * 保守：它们的前提是"留痕写不成就不许把结果交出去"——PII 明文、虚假 reportId。
 * 走 outbox 会让响应变成成功，而那正是要禁止的形状。语义分档见
 * `src/tests/controllers/skipGlobalAuditWriteFailure.test.js` 的登记表。
 */

const logger = require('../utils/logger');
const { onAuditWriteFailure } = require('../utils/auditWriteFailure');

/**
 * 把一条审计文档追加进审计 WAL（同步落盘）。
 *
 * @param {object} entry 审计文档
 * @returns {{spooled: boolean, reason: string|null}}
 */
function spool(entry) {
  const AuditLog = require('../models/AuditLog');
  const auditBuffer = require('./auditBuffer');

  // 先验 schema：不合法就不 spool（否则 WAL 行会被预铸造拒掉并归档到 .discarded，
  // 而调用方已经据此返回了成功 ⇒ 比不 spool 更糟）。
  // `typeof === 'function'` 这一档是给替身模型留的：单测里 AuditLog 常被 mock 成
  // 普通对象（只有 create 等静态桩），此时 `new` 会抛 TypeError——那是测试夹具的形态，
  // 不是"文档非法"。生产环境里 AuditLog 恒为 mongoose Model（构造器），校验照常生效。
  let doc = entry;
  if (typeof AuditLog === 'function') {
    const probe = new AuditLog(entry);
    const invalid = probe.validateSync();
    if (invalid) return { spooled: false, reason: 'invalid_document' };
    doc = probe.toObject({ getters: false, virtuals: false });
  }

  if (!auditBuffer.isWalEnabled()) return { spooled: false, reason: 'wal_disabled' };

  // 写回铸后形态：__walSeq 由 push 分配，批量路径再铸一次是幂等的
  auditBuffer.push(doc);
  return { spooled: true, reason: null };
}

/**
 * 落库；失败则转 WAL 兜底。
 *
 * @param {object} entry 审计文档
 * @param {{auditAction: string, req?: object}} meta 检索标识与操作者上下文
 * @returns {Promise<object|null>} 落库成功返回文档；转 WAL 成功返回 null
 * @throws 文档非法或 WAL 不可用时重抛原错误
 */
async function recordDurably(entry, { auditAction, req } = {}) {
  const AuditLog = require('../models/AuditLog');
  try {
    return await AuditLog.create(entry);
  } catch (err) {
    const result = spool(entry);
    onAuditWriteFailure(auditAction, req)(err);
    if (!result.spooled) throw err;
    // 这条 warn 是"补偿已发生"的唯一正常路径留痕：error 日志说的是失败，
    // 它说的是"没丢"。两条一起看才知道结论，只有前者会被读成"审计缺了一条"。
    logger.warn(
      `审计落库失败，事件已转入审计 WAL 待重放（${auditAction}）：${result.reason || 'ok'}`
    );
    return null;
  }
}

/**
 * `recordSensitiveAction` 形态的可靠版本（字段构造复用模型上的纯函数，口径不分叉）。
 *
 * @param {{userId: string, username: string, action: string, category: string,
 *   req: object, res: object, duration?: number, auditAction?: string}} input
 * @returns {Promise<object|null>}
 */
async function recordSensitiveActionDurably({
  userId,
  username,
  action,
  category,
  req,
  res,
  duration,
  auditAction,
}) {
  const AuditLog = require('../models/AuditLog');
  const entry = AuditLog.buildSensitiveActionDoc(
    userId,
    username,
    action,
    category,
    req,
    res,
    duration
  );
  return recordDurably(entry, { auditAction: auditAction || action, req });
}

module.exports = { recordDurably, recordSensitiveActionDurably, spool };
