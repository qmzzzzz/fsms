/**
 * withTransaction 拓扑能力感知——行为化测试
 *
 * 覆盖 transaction.js 的三条行为线：
 *   1. 拓扑不可读（未连接 / client 缺失）→ 按支持处理（fail-loud），
 *      走 startSession 事务路径；
 *   2. 事务路径成功/失败语义：fn 结果返回、业务失败 abort 并原样上抛、
 *      abort 自身失败不掩盖原始错误；
 *   3. standalone（Single 拓扑）降级为顺序写 fn(null)，降级告警每次进程只发一次。
 *
 * 1/2 用 mock session 纯单测（用桩把 client 置为不可读 → 触发 fail-loud）；
 * 3 连 mongodb-memory-server（standalone 拓扑 type='Single'，真实路径）。
 *
 * 【顺序无关】原 1/2 靠「本文件还没连库」这一**执行顺序**前提来触发 fail-loud，
 * 而 3 会连库：随机顺序下 3 先跑时，1/2 的前提断言 `connection.client` 为
 * undefined 立即失败（seed=42 实测）。改为显式把 client 置为不可读（并在用完后
 * 还原），前提由「顺序」变成「用例自己的设置」。
 */
const mongoose = require('mongoose');
const logger = require('../../utils/logger');

describe('withTransaction 拓扑能力感知', () => {
  let withTransaction;
  let _resetForTests;

  beforeAll(() => {
    ({ withTransaction, _resetForTests } = require('../../utils/transaction'));
  });

  describe('事务路径（拓扑不可读 → fail-loud，mock session）', () => {
    let fakeSession;
    let startSessionSpy;
    let savedClient;

    beforeEach(() => {
      // 显式把 connection.client 置为不可读：detectTransactionSupport 的 hello 探测
      // 会抛错 → 按支持处理（fail-loud）→ withTransaction 必然进入 startSession
      // 事务路径。不能用「本文件尚未连库」作前提（见文件头注释）。
      savedClient = mongoose.connection.client;
      Object.defineProperty(mongoose.connection, 'client', {
        value: undefined,
        configurable: true,
        writable: true,
      });
      expect(mongoose.connection.client).toBeUndefined();

      // 同时清掉探测缓存：detectTransactionSupport 把结果缓存在模块级变量里，
      // 随机顺序下若 standalone 块先跑（缓存 = false 支持），本块会直接走降级
      // 路径 fn(null)、根本不 startSession，四条断言全部落空。
      _resetForTests();

      fakeSession = {
        startTransaction: jest.fn(),
        commitTransaction: jest.fn().mockResolvedValue(undefined),
        abortTransaction: jest.fn().mockResolvedValue(undefined),
        endSession: jest.fn(),
      };
      startSessionSpy = jest.spyOn(mongoose, 'startSession').mockResolvedValue(fakeSession);
    });

    afterEach(() => {
      startSessionSpy.mockRestore();
      // 还原真实 client，避免影响本文件后续（standalone 块）与其他 describe
      Object.defineProperty(mongoose.connection, 'client', {
        value: savedClient,
        configurable: true,
        writable: true,
      });
    });

    test('成功路径：fn 收到 session，commit + endSession，返回 fn 结果', async () => {
      const result = await withTransaction(async (session) => {
        expect(session).toBe(fakeSession);
        return 'ok';
      });
      expect(result).toBe('ok');
      expect(fakeSession.startTransaction).toHaveBeenCalledTimes(1);
      expect(fakeSession.commitTransaction).toHaveBeenCalledTimes(1);
      expect(fakeSession.endSession).toHaveBeenCalledTimes(1);
    });

    test('业务失败：abort 并原样上抛同一错误，endSession 仍执行', async () => {
      const boom = new Error('业务写失败');
      await expect(
        withTransaction(async () => {
          throw boom;
        })
      ).rejects.toBe(boom);
      expect(fakeSession.abortTransaction).toHaveBeenCalledTimes(1);
      expect(fakeSession.commitTransaction).not.toHaveBeenCalled();
      expect(fakeSession.endSession).toHaveBeenCalledTimes(1);
    });

    test('abort 自身失败不掩盖原始错误', async () => {
      const boom = new Error('原始业务错误');
      fakeSession.abortTransaction.mockRejectedValue(new Error('abort 网络失败'));
      await expect(withTransaction(async () => Promise.reject(boom))).rejects.toBe(boom);
      expect(fakeSession.endSession).toHaveBeenCalledTimes(1);
    });

    test('options 透传给 startTransaction', async () => {
      const opts = { readConcern: { level: 'snapshot' } };
      await withTransaction(async () => 'x', opts);
      expect(fakeSession.startTransaction).toHaveBeenCalledWith(opts);
    });
  });

  describe('standalone 降级路径（mongodb-memory-server，type=Single）', () => {
    let startSessionSpy;
    let warnSpy;

    beforeAll(async () => {
      if (mongoose.connection.readyState === 0) {
        await mongoose.connect(process.env.MONGODB_URI);
      }
    });

    afterAll(async () => {
      if (mongoose.connection.readyState !== 0) {
        await mongoose.connection.close();
      }
    });

    beforeEach(() => {
      _resetForTests();
      startSessionSpy = jest.spyOn(mongoose, 'startSession');
      warnSpy = jest.spyOn(logger, 'warn').mockImplementation(() => {});
    });

    afterEach(() => {
      startSessionSpy.mockRestore();
      warnSpy.mockRestore();
    });

    test('内存库为 standalone 拓扑（前提断言）', () => {
      expect(mongoose.connection.client.topology.description.type).toBe('Single');
    });

    test('降级为 fn(null) 顺序执行且不开启事务，返回 fn 结果', async () => {
      const seen = await withTransaction(async (session) => session);
      expect(seen).toBeNull();
      expect(startSessionSpy).not.toHaveBeenCalled();
    });

    test('降级告警每次进程只发一次', async () => {
      await withTransaction(async () => 'a');
      await withTransaction(async () => 'b');
      expect(warnSpy).toHaveBeenCalledTimes(1);
      expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining('standalone'));
    });

    test('fn 抛错直接上抛（无事务可回滚，不吞错）', async () => {
      const boom = new Error('顺序写失败');
      await expect(withTransaction(async () => Promise.reject(boom))).rejects.toBe(boom);
      expect(startSessionSpy).not.toHaveBeenCalled();
    });
  });
});
