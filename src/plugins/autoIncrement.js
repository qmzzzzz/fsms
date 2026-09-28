/**
 * Mongoose 自动编号插件
 * 基于 counters 集合的原子计数器，为文档生成唯一编号（如设备编号、报警编号）
 *
 * 用法：
 *   schema.plugin(autoIncrement, {
 *     field: 'deviceCode',
 *     generatePrefix: (doc, at) => `${getTypePrefix(doc.deviceType)}-${businessDateParts(at).year}`,
 *     counterPrefix: 'device',
 *     seqPadding: 4,
 *   });
 */

const mongoose = require('mongoose');
const logger = require('../utils/logger');
const { escapeRegExp } = require('../utils/helpers');

/**
 * 从 findOneAndUpdate 的返回值里取出文档本身。
 *
 * driver 7 默认 `includeResultMetadata:false`（返回文档或 null），但旧版/显式传
 * `includeResultMetadata:true` 时返回的是 `{ value, ok, lastErrorObject }`。
 * 仓库里原先写的是 `r.value || r`，它在"ModifyResult 且没匹配到文档"这一格会退化成
 * 把整个结果壳当成文档（`.seq` 为 undefined）——两处调用点都靠这种形状猜。
 * 按载荷本身判别：自带 seq 就是文档，否则取 .value（可能是 null）。
 */
const docOfResult = (r) => {
  if (!r) return null;
  return r.seq !== undefined ? r : (r.value ?? null);
};

/**
 * @param {Object} options
 * @param {string} options.field - 要填充的字段名
 * @param {Function} [options.generatePrefix] - 根据文档生成编号前缀，签名 (doc, at) → string；
 *   `at` 是本次取号的时刻，凡前缀里带日期/年份的一律用它，不要在自己内部再 new Date()
 * @param {string} [options.counterPrefix='auto'] - counters 集合中 _id 的前缀
 * @param {number} [options.seqPadding=4] - 序号补零位数
 */
module.exports = function autoIncrementPlugin(schema, options = {}) {
  const { field, generatePrefix = () => '', counterPrefix = 'auto', seqPadding = 4 } = options;

  if (!field) {
    throw new Error('autoIncrement 插件必须指定 field 选项');
  }

  schema.pre('save', async function (next) {
    try {
      await assignNumber(this);
      next();
    } catch (err) {
      next(err);
    }
  });

  // 必须同时挂在 validate 前：Mongoose 内置的 validateBeforeSave 插件以
  // `unshift = true` 把校验钩子插到 pre('save') 队列最前端，因此仅注册
  // pre('save') 时「必填校验」会先于「编号生成」执行——对 required 的编号字段
  // （如 FireDevice.deviceCode）意味着任何不显式传编号的创建都必然抛
  // ValidationError（实测：`FireDevice validation failed: deviceCode: 设备编号不能为空`）。
  // 两处都注册 + 幂等守卫（已有值即跳过），同时覆盖
  // save({ validateBeforeSave: false }) 绕过校验的调用方。
  schema.pre('validate', async function (next) {
    try {
      await assignNumber(this);
      next();
    } catch (err) {
      next(err);
    }
  });

  const formatCode = (prefix, seq) =>
    prefix
      ? `${prefix}-${String(seq).padStart(seqPadding, '0')}`
      : String(seq).padStart(seqPadding, '0');

  /**
   * 存量里本前缀已用掉的最大序号（没有匹配文档时返回 null）。
   * 必须按**数值**取最大：编号是补零定宽字符串，跨宽度时字典序会骗人
   * （'ZZP-9999' 逐字符大于 'ZZP-10000'），按字符串取最大会算出已被占用的号。
   * `$match` 的前缀是锚定的字面量，走 field 上的 unique 索引；且只数
   * 形如 `前缀-数字` 的编号——外部写入的其它形态不参与对齐。
   */
  async function maxPersistedSeq(model, prefix) {
    const shape = `^${escapeRegExp(prefix)}${prefix ? '-' : ''}\\d{${seqPadding},}$`;
    const offset = prefix.length + (prefix ? 1 : 0);
    const rows = await model.aggregate([
      { $match: { [field]: { $regex: shape } } },
      { $project: { _id: 0, seq: { $toInt: { $substrBytes: [`$${field}`, offset, 32] } } } },
      { $sort: { seq: -1 } },
      { $limit: 1 },
    ]);
    return rows.length ? rows[0].seq : null;
  }

  /**
   * "我拿到这一把计数器的第一个号"时的对齐判定，返回对齐后的序号（不对齐则原样返回）。
   *
   * seq === 1 只可能是两种情况：该前缀的第一条记录（一生一次），或 counters 丢失后被重建。
   * 后者的代价是**该实体永久无法新建**——编号从 1 重排，撞上 field 上的 unique 索引，
   * E11000 被 errorHandler 报成「资源已存在」，而请求里没有任何已存在的资源，
   * 真正的病灶（计数器）在错误信息里毫不露面。所以只在这一格里付存量对齐的查询成本。
   *
   * 但"拿到 1 号"本身不足以说明是后者：并发创建本前缀的第一批记录时，取到 1 号的那条
   * 读存量会看见兄弟刚落库的 2 号、3 号 —— 那是它自己落后，不是计数器丢了。
   * 只看"存量最大号 ≥ 我拿到的号"就对齐，会让这一批**静默跳号**（1 号空着、中间挖洞），
   * 并留下一条指控计数器的 warn，把运维的排查方向整个指错。
   * 因此要两条**互相独立**的证据，任一成立才对齐：
   *   脱节 —— 存量里有一个本轮从未发放过的大号。这次读计数器必须放在存量查询之后：
   *           晚读一次，在飞兄弟取走的号就必定已被计数器计入，"并发诞生"因此不可能被
   *           误判成脱节（早读会留下兄弟取了号还没落库的窗口）。
   *   占用 —— 我手里这个号已经被占。计数器丢失的瞬间若有多条创建在飞，存量恰好是 1..N
   *           而计数器也被发到 N，两条数值重合、"脱节"这条证据失灵，只剩这一条还分得开
   *           （等值查询走 field 上的 unique 索引）。
   * 边界：多条创建同时撞上一次刚丢失的计数器时，救回的是"至少一条能写成"，其余仍会撞
   * 唯一键而失败——那是可重试的常规冲突，不是这里要治的"永久不可写"。
   */
  async function realignSeq({ counters, model, prefix, counterId, seq }) {
    let persisted = null;
    try {
      persisted = await maxPersistedSeq(model, prefix);
    } catch (err) {
      // 对齐是"恢复"路径，不能反过来变成正常创建的新单点故障：
      // 查询失败就退回原行为（由 unique 索引兜住重号），但必须留声。
      logger.error(`自动编号存量对齐查询失败，退回计数器原值: ${err.message}`, { counterId });
      return seq;
    }
    if (persisted === null || persisted < seq) return seq;

    const live = await counters.findOne({ _id: counterId }, { projection: { _id: 0, seq: 1 } });
    const diverged = live !== null && persisted > live.seq;
    let taken = false;
    if (!diverged) {
      try {
        taken = Boolean(await model.exists({ [field]: formatCode(prefix, seq) }));
      } catch (err) {
        // 同存量查询：探测失败就退回"不对齐"，由 unique 索引兜住（代价是一次可重试冲突）
        logger.error(`自动编号占用探测失败，退回计数器原值: ${err.message}`, { counterId });
      }
    }
    if (!diverged && !taken) return seq;

    // 原子推进而不是赋值：不写回"我算出来的号"，而是让计数器自己前进后再取返回值，
    // 避免两个对齐者互相覆盖。
    const bumped = docOfResult(
      await counters.findOneAndUpdate(
        { _id: counterId },
        { $inc: { seq: persisted + 1 - seq } },
        { returnDocument: 'after' }
      )
    );
    // 这里不能加 upsert：驱动"计数器文档在读存量之后被删"这一格时，upsert 会按
    // `$inc` 的增量从 0 起算，算出 persisted+1-seq（seq=1 时正好等于已被占的
    // persisted），把一个可恢复的失败换成一次静默重号。取不到回值就退回原号，
    // 与本函数另两处失败口径一致（交给 unique 索引兜住一次可重试冲突）。
    if (!bumped) {
      logger.error(`自动编号对齐推进失败（计数器文档已不存在），退回计数器原值: ${counterId}`, {
        counterId,
        persistedSeq: persisted,
      });
      return seq;
    }
    const aligned = bumped.seq;
    logger.warn(
      `自动编号计数器与存量不一致：${counterId} 从 1 重排，` +
        `但存量最大编号已是 ${formatCode(prefix, persisted)}，已对齐到 ${formatCode(prefix, aligned)}`,
      { counterId, persistedSeq: persisted, seq: aligned }
    );
    return aligned;
  }

  /** 生成并填充编号（幂等：非新建或字段已有值时直接返回） */
  async function assignNumber(doc) {
    if (!doc.isNew || doc[field]) return;

    // 时刻只取一次并往下传：按时间分档的前缀（日期段、年份段）必须与本次取号
    // 用的是同一个瞬间，且**必须**用这里的实参而不是在回调里再 new Date()——
    // 回调里自建的时刻读的是服务器本地分量，与全站业务时区口径不同源。
    const prefix =
      typeof generatePrefix === 'function'
        ? generatePrefix(doc, new Date())
        : String(generatePrefix || '');

    // counterId 由调用方前缀 + 生成的前缀组成，年份等维度由 generatePrefix 自行控制
    const counterId = `${counterPrefix}_${prefix || 'default'}`;

    const counters = mongoose.connection.db.collection('counters');
    const result = await counters.findOneAndUpdate(
      { _id: counterId },
      { $inc: { seq: 1 } },
      { upsert: true, returnDocument: 'after' }
    );

    const counterDoc = docOfResult(result) || {};
    let seq = counterDoc.seq || 1;

    // seq === 1 这一格的判据与代价分析都在 realignSeq 里；常规取号路径一次存量查询都不付。
    if (seq === 1) {
      seq = await realignSeq({ counters, model: doc.constructor, prefix, counterId, seq });
    }

    doc[field] = formatCode(prefix, seq);
  }
};
