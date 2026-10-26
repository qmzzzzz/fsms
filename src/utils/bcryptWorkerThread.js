'use strict';

/**
 * bcrypt worker 线程入口（仅供 utils/bcryptWorkerPool.js 加载）。
 * 协议：父线程 postMessage({ id, op, args })，本线程回 { id, ok, result } 或
 * { id, ok:false, error }；args 限字符串/数字，错误只回传 message（Error 附加字段不跨线程）。
 */
const { parentPort } = require('worker_threads');
const bcrypt = require('bcryptjs');

parentPort.on('message', ({ id, op, args }) => {
  const fn = bcrypt[op];
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
