'use strict';

/**
 * bcrypt worker 线程入口的协议层（utils/bcryptWorkerThread.js）
 *
 * 这是"支持哪些操作"的**唯一判据**：池侧只发 hash/compare/genSalt 三个字面量，
 * 线程侧若用裸下标判类型，原型链上的方法名（constructor/toString/hasOwnProperty…）
 * 会被当成合法操作执行并回 ok:true —— 判据形同虚设（G-03）。
 * 本文件把协议面钉住：白名单内的三个操作照常，其余一律 ok:false。
 */

const { flushEventLoop } = require('../helpers/waitFor');

describe('bcryptWorkerThread 协议', () => {
  let handler;
  let postMock;

  /** 线程入口在 require 时就注册 parentPort.on，故注入假 parentPort 并截获 handler */
  const loadThread = () => {
    handler = null;
    postMock = jest.fn();
    jest.doMock('worker_threads', () => ({
      parentPort: {
        on: (event, cb) => {
          if (event === 'message') handler = cb;
        },
        postMessage: postMock,
      },
    }));
    jest.doMock('bcryptjs', () => ({
      hash: jest.fn(async () => 'HASHED'),
      compare: jest.fn(async () => true),
      genSalt: jest.fn(async () => 'SALT'),
    }));
    jest.isolateModules(() => {
      require('../../utils/bcryptWorkerThread');
    });
    return { call: (msg) => handler(msg) };
  };

  afterEach(() => {
    jest.dontMock('worker_threads');
    jest.dontMock('bcryptjs');
  });

  test('公平面：白名单内的操作照常执行（判据不是恒拒）', async () => {
    const { call } = loadThread();
    call({ id: 7, op: 'hash', args: ['pw', 4] });
    await flushEventLoop(2);
    expect(postMock).toHaveBeenCalledWith({ id: 7, ok: true, result: 'HASHED' });
  });

  test('原型链上的方法名一律拒收（修前 constructor/toString/hasOwnProperty 全部放行）', async () => {
    const { call } = loadThread();
    const ops = ['constructor', 'toString', 'hasOwnProperty'];
    ops.forEach((op, i) => call({ id: 100 + i, op, args: [] }));
    await flushEventLoop(3);

    const byId = new Map(postMock.mock.calls.map(([msg]) => [msg.id, msg]));
    ops.forEach((op, i) => {
      const msg = byId.get(100 + i);
      expect(msg).toBeTruthy();
      expect(msg.ok).toBe(false);
      expect(String(msg.error)).toContain(`bcryptjs 不支持的操作：${op}`);
    });
  });
});
