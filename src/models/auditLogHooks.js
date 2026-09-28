/**
 * AuditLog 哈希链与 append-only 钩子：集中维护写入链尾、失败回滚与修改删除拦截。
 */

const {
  canonicalPayload,
  computeHash,
  computeHmac,
  CURRENT_PAYLOAD_VERSION,
  rollbackChainTail,
  withChainLock,
  getChainTail,
  advanceChainTail,
} = require('../utils/auditChain');

// L-25：append-only 钩子清单提升为模块级导出，供合规门禁（scripts/compliance-check.js）
// 直接引用——原先是两处手工同步（门禁列 6 项、实际挂 9 项），漏掉的恰好是
// updateMany / findOneAndReplace / bulkWrite 三个批量篡改路径。收敛为单一事实来源后，
// 新增钩子只需改这里，门禁自动覆盖。
const APPEND_ONLY_HOOKS = [
  'updateOne',
  'updateMany',
  'deleteOne',
  'deleteMany',
  'replaceOne',
  'findOneAndUpdate',
  'findOneAndDelete',
  'findOneAndReplace',
  'bulkWrite',
];

const applyHooks = (schema, logger) => {
  // P1-32：护栏状态为模块内部状态，**不再无条件暴露开关**。原先导出
  // setAppendOnlyEnforced 后，任何拿到 AuditLog 模型的生产代码都可在运行期
  // 关闭 append-only 防篡改护栏（全仓当前无生产调用点，但门不该存在）。
  // 现仅在测试环境保留开关（AuditLogBehavior.test.js 的清理路径依赖它），
  // 由 AuditLog.js 按 NODE_ENV === 'test' 条件导出；生产环境无此符号。
  let appendOnlyEnforced = true;

  const setAppendOnlyEnforced = (value) => {
    // 双保险：即使符号被绕过取得，非测试环境调用也不产生任何效果
    if (process.env.NODE_ENV !== 'test') return;
    appendOnlyEnforced = value === true;
  };

  schema.pre('save', async function () {
    // 护栏判据是「这不是一条新记录」，不能写成 `&& this.hash`。
    // 原式把护栏挂在**恰好会被失效形态抹掉的那个字段**上：chainBatch 抛错时
    // 无哈希记录仍会落库（observability/auditBufferFlushAndWalGuards.test.js 把这条行为当成期望钉着），
    // 于是这类存量行既绕开了 append-only 护栏，又会掉进下面的"补签"分支——
    // 被重新算哈希并**接到活链尾部**。后果不是"少一层校验"，而是
    // **篡改变得对链校验完全不可见**（重算出的哈希与改后的载荷自洽）。
    // 全仓无生产代码对已入库 AuditLog 调 save()（已 grep 核实），故收紧不影响任何路径。
    if (!this.isNew && appendOnlyEnforced) {
      throw new Error('审计日志为 append-only，禁止通过 save() 修改已入库记录');
    }

    if (this.hash) {
      if (!this.hmac) {
        try {
          this.hmac = computeHmac(this.hash);
        } catch {
          /* best-effort */
        }
      }
      if (!this.hashVersion) this.hashVersion = CURRENT_PAYLOAD_VERSION;
      return;
    }

    try {
      await withChainLock(async (generation) => {
        const prevHash = await getChainTail(this.constructor);
        const payload = canonicalPayload(this.toObject(), CURRENT_PAYLOAD_VERSION);
        this.prevHash = prevHash;
        this.hash = computeHash(prevHash, payload);
        this.hmac = computeHmac(this.hash);
        this.hashVersion = CURRENT_PAYLOAD_VERSION;
        // 【M-09】链尾推进刻意留在 pre('save')，与哈希计算同处一把 withChainLock
        // 临界区内。原因：
        //   ① 若移到 post('save')，锁无法跨 pre/post 两个钩子持有，并发写入会
        //      读到相同链尾、算出相同 prevHash → **真实分叉**，比幻影链尾严重；
        //   ② 若强行跨钩子持锁，则 post 钩子未触发时锁泄漏，其后所有审计写入
        //      无限排队（表现为「服务正常但审计彻底停摆」），是更差的失效模式。
        // 代价是崩溃时可能留下「幻影链尾」（链尾指向从未入库的 hash）。该风险
        // 改由**启动期自愈**消除：index.js 在 auditBuffer.start() **之前**调用
        // resyncChainTail()，从 DB 重建真实链尾。故完整性校验不会产生持续假阳性。
        // 次序不可颠倒（index.js 的 resyncChainTail() 在 :297、auditBuffer.start()
        // 在 :315）：自愈必须早于任何审计写入，否则新写入会立刻把链尾推回幻影值。
        // 修改此处前请先阅读 src/index.js 中的 M-09 说明。
        await advanceChainTail(this.hash, generation);
        this.$__chainAdvancedFrom = prevHash;
      });
    } catch (error) {
      logger.warn('审计日志哈希链计算失败', { action: this.action, error: error.message });
    }
  });

  schema.post('save', function (error, doc, next) {
    if (error && doc && doc.$__chainAdvancedFrom !== undefined && doc.hash) {
      Promise.resolve()
        .then(() => rollbackChainTail(doc.hash, doc.$__chainAdvancedFrom))
        .then((restored) => {
          if (!restored) {
            logger.error(
              `审计日志落库失败且链尾已被后续记录接续（action=${doc.action}），哈希链可能出现幻影分叉，请核查`
            );
          }
          delete doc.$__chainAdvancedFrom;
          next(error);
        })
        .catch(() => {
          delete doc.$__chainAdvancedFrom;
          next(error);
        });
      return;
    }
    next(error);
  });

  // #2（评价报告高危）：append-only 护栏此前漏掉 updateMany / bulkWrite /
  // findOneAndReplace 三类批量写入口——与 updateOne/deleteMany 走同一前置钩子，
  // 批量篡改审计日志的路径同样被拦截。注意该护栏仅覆盖 Mongoose ODM 层，
  // 经原生驱动（mongoose.connection.db.collection(...)）的写入不受此约束，
  // 「篡改可发现」的最终保障落在哈希链校验（scripts/verify-audit-chain）。
  //
  // L-25：清单已提升为模块级 APPEND_ONLY_HOOKS（见文件上方），合规门禁引用同一常量。
  schema.pre(APPEND_ONLY_HOOKS, function (next) {
    if (!appendOnlyEnforced) return next();
    const options = (this.getOptions && this.getOptions()) || {};
    // P1-32：bypassAppendOnly 原先接受任意真值即放行（运行时关闭护栏的后门）。
    // 现收紧为「仅测试环境 + 显式传入布尔 true」才放行：
    //   - 未传 / 传 false / 非布尔（如 'true'、1）一律拦截；
    //   - 生产环境（NODE_ENV !== 'test'）无论传什么都不放行。
    // 测试清理（deleteMany 等）依赖此契约，见 tests/compliance/auditChain.test.js
    // 与 tests/models/AuditLog.test.js；正常写入（create/insertMany）不经过本钩子。
    if (process.env.NODE_ENV === 'test' && options.bypassAppendOnly === true) return next();
    next(new Error('审计日志为 append-only，禁止修改/删除'));
  });
  // 合规出口需要报告**实际生效值**：护栏是上面的闭包变量，外部原先无从读取
  // （`setAppendOnlyEnforced` 又按 P1-32 只在测试环境导出）。给一个只读 getter，
  // 让 securityController 的 compliance 面板不必再写死 true。
  return { setAppendOnlyEnforced, isAppendOnlyEnforced: () => appendOnlyEnforced };
};

module.exports = { applyHooks, APPEND_ONLY_HOOKS };
