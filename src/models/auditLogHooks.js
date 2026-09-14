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

const applyHooks = (schema, logger) => {
  let appendOnlyEnforced = true;

  const setAppendOnlyEnforced = (value) => {
    appendOnlyEnforced = !!value;
  };

  schema.pre('save', async function () {
    if (!this.isNew && this.hash && appendOnlyEnforced) {
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
  const appendOnlyHooks = [
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
  schema.pre(appendOnlyHooks, function (next) {
    if (!appendOnlyEnforced) return next();
    const options = (this.getOptions && this.getOptions()) || {};
    if (options.bypassAppendOnly) return next();
    next(new Error('审计日志为 append-only，禁止修改/删除'));
  });

  return { setAppendOnlyEnforced };
};

module.exports = { applyHooks };
