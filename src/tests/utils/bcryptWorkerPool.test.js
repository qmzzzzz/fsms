'use strict';

/**
 * bcrypt worker 线程池（utils/bcryptWorkerPool.js）
 *
 * 覆盖三条不变量：
 * 1. 测试环境默认回退进程内 bcryptjs（jest.mock/spy 必须继续生效——
 *    loginTimingParity 等测试的时序侧信道判据就是数 compare 调用次数）；
 * 2. BCRYPT_WORKER_THREADS=0 显式关闭，同样回退进程内；
 * 3. 强制开启（=1）时跨线程真实执行：hash/compare 语义与 bcryptjs 一致。
 *    worker 内加载的是**未 mock 的真实 bcryptjs**（jest 的模块注册表不跨线程），
 *    用低 cost（4）把单次耗时压到毫秒级，避免拖慢测试套件。
 */

describe('bcryptWorkerPool', () => {
  /** isolateModules 内同步创建的 Promise 需要先逃逸到闭包，await 才能触发 doMock */
  let poolPromise;
  const loadPool = () => {
    let mod;
    jest.isolateModules(() => {
      mod = require('../../utils/bcryptWorkerPool');
    });
    return mod;
  };

  afterEach(() => {
    delete process.env.BCRYPT_WORKER_THREADS;
    delete process.env.BCRYPT_WORKERS;
    jest.restoreAllMocks();
  });

  test('测试环境默认回退进程内 bcryptjs（mock 可拦截）', async () => {
    const compareMock = jest.fn().mockResolvedValue(false);
    jest.doMock('bcryptjs', () => ({ compare: compareMock, hash: jest.fn(), genSalt: jest.fn() }));
    jest.isolateModules(() => {
      const pool = require('../../utils/bcryptWorkerPool');
      poolPromise = pool.compare('candidate', '$2a$12$invalid');
    });
    await expect(poolPromise).resolves.toBe(false);
    expect(compareMock).toHaveBeenCalledWith('candidate', '$2a$12$invalid');
  });

  test('BCRYPT_WORKER_THREADS=0 显式关闭：同样回退进程内', async () => {
    process.env.BCRYPT_WORKER_THREADS = '0';
    const hashMock = jest.fn().mockResolvedValue('$2a$04$hashed');
    jest.doMock('bcryptjs', () => ({ compare: jest.fn(), hash: hashMock, genSalt: jest.fn() }));
    let hashPromise;
    jest.isolateModules(() => {
      const pool = require('../../utils/bcryptWorkerPool');
      hashPromise = pool.hash('secret', 4);
    });
    await expect(hashPromise).resolves.toBe('$2a$04$hashed');
    expect(hashMock).toHaveBeenCalledWith('secret', 4);
  });

  test('强制 worker 模式：跨线程真实 hash/compare 语义一致', async () => {
    process.env.BCRYPT_WORKER_THREADS = '1';
    process.env.BCRYPT_WORKERS = '1';
    const pool = loadPool();

    try {
      const hashed = await pool.hash('worker-secret', 4);
      expect(hashed).toMatch(/^\$2[aby]\$04\$/);
      await expect(pool.compare('worker-secret', hashed)).resolves.toBe(true);
      await expect(pool.compare('wrong-secret', hashed)).resolves.toBe(false);
    } finally {
      await pool._shutdownForTests();
    }
  });

  test('池初始化失败：必须留一条告警，且不重试、调用方仍拿到结果（G-01）', async () => {
    process.env.BCRYPT_WORKER_THREADS = '1';
    process.env.BCRYPT_WORKERS = '1';
    // 本用例的回退臂要的是**真实** bcryptjs：同文件先行用例（随机序下可能在前面）
    // 的 doMock('bcryptjs') 会注册到本文件的 mock 注册表并泄进 isolateModules——
    // 那个桩的 hash 返回 undefined，本用例就会红成 "Received has value: undefined"。
    // 双向解除（进入前清注册、finally 归还），与其他用例互不依赖执行顺序。
    jest.dontMock('bcryptjs');
    const warnMock = jest.fn();
    jest.doMock('../../utils/logger', () => ({
      warn: warnMock,
      error: jest.fn(),
      info: jest.fn(),
    }));
    let workerCtorCalls = 0;
    jest.doMock('worker_threads', () => ({
      Worker: class {
        constructor() {
          workerCtorCalls += 1;
          throw new Error('worker 不可用（注入）');
        }
      },
    }));

    try {
      let first;
      let second;
      jest.isolateModules(() => {
        const pool = require('../../utils/bcryptWorkerPool');
        first = pool.hash('secret', 4);
        second = pool.hash('secret-2', 4);
      });
      await expect(first).resolves.toMatch(/^\$2[aby]\$04\$/);
      await expect(second).resolves.toMatch(/^\$2[aby]\$04\$/);
      expect(workerCtorCalls).toBe(1); // initFailed 不复位：本进程不再重试（有意取舍，故必须有告警）
      expect(warnMock).toHaveBeenCalledTimes(1);
      expect(String(warnMock.mock.calls[0][0])).toContain('worker 不可用（注入）');
    } finally {
      jest.dontMock('worker_threads');
      jest.dontMock('../../utils/logger');
      jest.dontMock('bcryptjs');
    }
  });
  test('强制 worker 模式：compare 非字符串入参按 bcryptjs 语义拒绝', async () => {
    process.env.BCRYPT_WORKER_THREADS = '1';
    process.env.BCRYPT_WORKERS = '1';
    const pool = loadPool();

    try {
      // bcryptjs 对非字符串抛 TypeError；跨线程后以 Error(message) 形式回到主线程
      await expect(pool.compare(null, '$2a$04$whatever')).rejects.toThrow();
    } finally {
      await pool._shutdownForTests();
    }
  });
});
