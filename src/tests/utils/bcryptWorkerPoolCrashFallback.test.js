'use strict';

/**
 * bcrypt worker 池的崩溃语义（utils/bcryptWorkerPool.js，G-02）
 *
 * 文件头与 :85 的承诺是「worker 初始化/运行失败 ⇒ 登录可用性优先于性能」，
 * 而 `kill()` 原先对**在飞任务**直接 reject（`task.reject(new Error('bcrypt worker …'))`），
 * 只对**排队任务**走进程内兜底 —— 同一函数两条路径两种待遇：
 * 线程崩在登录请求上 ⇒ bcrypt worker error 一路上抛 ⇒ 500。
 *
 * 三条用例分别钉住：① 正常时任务仍走线程（不得退化成永远进程内）；
 * ② 崩溃时在飞任务必须改走进程内并拿到结果；③ 兜底自身失败时必须照样 reject（不得吞错）；
 * ④ code-0 退出同样按 worker 死亡处理（审计 2026-11-14：exit(0) 原先被忽略，entry 留在
 *    池里 ⇒ 在飞任务永不 settle、新任务继续派给死槽位——登录路径挂死）。
 */

const { flushEventLoop } = require('../helpers/waitFor');

/** 假 worker 的共享状态（名以 mock 开头，jest.mock 工厂内可引用） */
const mockPoolState = { instances: [], sent: [], replyOnPost: null };

jest.mock('worker_threads', () => {
  const { EventEmitter } = require('events');
  class FakeWorker extends EventEmitter {
    constructor() {
      super();
      mockPoolState.instances.push(this);
    }

    postMessage(msg) {
      mockPoolState.sent.push(msg);
      if (mockPoolState.replyOnPost) {
        const reply = mockPoolState.replyOnPost(msg);
        setImmediate(() => this.emit('message', reply));
      }
    }

    unref() {}

    terminate() {
      return Promise.resolve();
    }
  }
  return { Worker: FakeWorker };
});

const loadPool = () => {
  let pool;
  jest.isolateModules(() => {
    pool = require('../../utils/bcryptWorkerPool');
  });
  return pool;
};

describe('bcryptWorkerPool 崩溃语义', () => {
  beforeEach(() => {
    process.env.BCRYPT_WORKER_THREADS = '1';
    process.env.BCRYPT_WORKERS = '1';
    mockPoolState.instances.length = 0;
    mockPoolState.sent.length = 0;
    mockPoolState.replyOnPost = null;
  });

  afterEach(() => {
    delete process.env.BCRYPT_WORKER_THREADS;
    delete process.env.BCRYPT_WORKERS;
    jest.dontMock('bcryptjs');
  });

  test('公平面：worker 正常回包时任务仍走线程（不得退化成永远进程内）', async () => {
    mockPoolState.replyOnPost = (msg) => ({ id: msg.id, ok: true, result: 'FROM_WORKER' });
    const hashMock = jest.fn(async () => 'FROM_INLINE');
    jest.doMock('bcryptjs', () => ({ hash: hashMock, compare: jest.fn(), genSalt: jest.fn() }));
    const pool = loadPool();

    try {
      await expect(pool.hash('pw', 4)).resolves.toBe('FROM_WORKER');
      expect(hashMock).not.toHaveBeenCalled(); // 健康路径不得被兜底接管
      expect(mockPoolState.sent).toHaveLength(1);
    } finally {
      await pool._shutdownForTests();
    }
  });

  test('线程崩溃时在飞任务必须改走进程内并拿到结果（登录不得因池问题 500）', async () => {
    const pool = loadPool();

    try {
      const p = pool.hash('pw', 4);
      expect(mockPoolState.sent).toHaveLength(1); // 已发给 worker ⇒ 此刻在飞
      mockPoolState.instances[0].emit('error', new Error('boom')); // 线程崩溃

      await flushEventLoop(1);
      await expect(p).resolves.toMatch(/^\$2[aby]\$04\$/);
    } finally {
      await pool._shutdownForTests();
    }
  });

  test('反例对照：兜底自身失败时必须照样 reject（不是把错误吞掉）', async () => {
    const pool = loadPool();

    try {
      const p = pool.compare(null, '$2a$04$whatever');
      expect(mockPoolState.sent).toHaveLength(1);
      mockPoolState.instances[0].emit('error', new Error('boom'));

      await flushEventLoop(1);
      await expect(p).rejects.toThrow();
    } finally {
      await pool._shutdownForTests();
    }
  });

  test('code-0 退出同样按 worker 死亡处理：在飞任务改走进程内，不得永久悬挂', async () => {
    const pool = loadPool();

    try {
      const p = pool.hash('pw', 4);
      expect(mockPoolState.sent).toHaveLength(1); // 已发给 worker ⇒ 此刻在飞
      mockPoolState.instances[0].emit('exit', 0); // 干净退出：worker 内显式 exit(0) / 循环排空

      await flushEventLoop(1);
      // 修复前：exit(0) 被忽略 ⇒ 在飞任务永不 settle，本断言只能靠用例超时变红
      await expect(p).resolves.toMatch(/^\$2[aby]\$04\$/);
      // 死槽位已移出（worker=1 ⇒ 全灭，initFailed）：后续任务直接走进程内，不再派给 worker
      const sentBefore = mockPoolState.sent.length;
      await expect(pool.hash('pw2', 4)).resolves.toMatch(/^\$2[aby]\$04\$/);
      expect(mockPoolState.sent.length).toBe(sentBefore);
    } finally {
      await pool._shutdownForTests();
    }
  });
});
