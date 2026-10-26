'use strict';

/**
 * bcrypt worker 线程入口（仅供 utils/bcryptWorkerPool.js 加载，勿直接引用）
 *
 * bcryptjs 是纯 JS 实现：cost-12 一次 compare 约百毫秒，异步版也只是在主线程
 * 上分片让出事件循环（慢而不卡），登录高峰会把 CPU 打满。本文件把真实的
 * hash/compare/genSalt 挪进 worker 线程执行，主线程只收结构化结果。
 *
 * 协议：父线程 postMessage({ id, op, args })，本线程回
 * { id, ok: true, result } 或 { id, ok: false, error: <message> }。
 * args 限字符串/数字（调用侧已是该形态），错误只回传 message，
 * 避免跨线程克隆不可序列化的 Error 附加字段。
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
