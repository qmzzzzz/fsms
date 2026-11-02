'use strict';

/**
 * bcrypt worker 线程入口（仅供 utils/bcryptWorkerPool.js 加载）。
 * 协议：父线程 postMessage({ id, op, args })，本线程回 { id, ok, result } 或
 * { id, ok:false, error }；args 限字符串/数字，错误只回传 message（Error 附加字段不跨线程）。
 */
const { parentPort } = require('worker_threads');
const bcrypt = require('bcryptjs');

const SUPPORTED_OPS = new Set(['hash', 'compare', 'genSalt']); // 白名单而不是「bcrypt[op] 是函数」：裸下标会放行原型链上的 constructor/toString/hasOwnProperty 等

parentPort.on('message', ({ id, op, args }) => {
  const fn = SUPPORTED_OPS.has(op) ? bcrypt[op] : null;
  if (typeof fn !== 'function') {
    parentPort.postMessage({ id, ok: false, error: `bcryptjs 不支持的操作：${op}` });
    return;
  }
  Promise.resolve()
    .then(() => fn(...args))
    .then((result) => parentPort.postMessage({ id, ok: true, result }))
    .catch((error) => {
      parentPort.postMessage({ id, ok: false, error: String(error?.message ?? error) });
    });
});
