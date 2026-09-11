/**
 * Mongoose 自动编号插件
 * 基于 counters 集合的原子计数器，为文档生成唯一编号（如设备编号、报警编号）
 *
 * 用法：
 *   schema.plugin(autoIncrement, {
 *     field: 'deviceCode',
 *     generatePrefix: (doc) => `${getTypePrefix(doc.deviceType)}-${new Date().getFullYear()}`,
 *     counterPrefix: 'device',
 *     seqPadding: 4,
 *   });
 */

const mongoose = require('mongoose');

/**
 * @param {Object} options
 * @param {string} options.field - 要填充的字段名
 * @param {Function} [options.generatePrefix] - 根据文档生成编号前缀，返回字符串
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

  /** 生成并填充编号（幂等：非新建或字段已有值时直接返回） */
  async function assignNumber(doc) {
    if (!doc.isNew || doc[field]) return;

    const prefix =
      typeof generatePrefix === 'function' ? generatePrefix(doc) : String(generatePrefix || '');

    // counterId 由调用方前缀 + 生成的前缀组成，年份等维度由 generatePrefix 自行控制
    const counterId = `${counterPrefix}_${prefix || 'default'}`;

    const counters = mongoose.connection.db.collection('counters');
    const result = await counters.findOneAndUpdate(
      { _id: counterId },
      { $inc: { seq: 1 } },
      { upsert: true, returnDocument: 'after' }
    );

    const counterDoc = result.value || result;
    const seq = counterDoc.seq || 1;
    doc[field] = prefix
      ? `${prefix}-${String(seq).padStart(seqPadding, '0')}`
      : String(seq).padStart(seqPadding, '0');
  }
};
