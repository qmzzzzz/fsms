/**
 * auditBuffer 的 flush 批次上限（A7）：**每次调用现读** env——模块级常量会让
 * "谁先 require 谁定值"，随机序下先跑的套件设过 env 就钉死后续套件（seed 31337 实测）。
 */
const { readClampedIntEnv } = require('../utils/envNumber');
const logger = require('../utils/logger');

const warnedRawEnv = new Set();

const flushBatchLimit = () =>
  readClampedIntEnv('AUDIT_FLUSH_BATCH_SIZE', 1000, [100, 5000], (name, raw) => {
    const key = `${name}=${raw}`;
    if (warnedRawEnv.has(key)) return; // 告警按原值去重，不会逐次刷屏
    warnedRawEnv.add(key);
    logger.warn(`${name}=${raw} 非法，已回退 1000 默认`);
  });

module.exports = { flushBatchLimit };
