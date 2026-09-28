/**
 * transaction.js 的 hello 探测**缓存策略**（zzqoder 新增）
 *
 * 既有两份测试（utils/transaction.test.js、utils/transactionTopology.test.js）覆盖的是
 * 「拓扑可读时走哪条分支」和「事务路径的 commit/abort 语义」，没有一条断言
 * 「探测失败之后缓存里留下了什么」。而这正是缺陷所在：
 * 原实现把探测异常也写成 `cachedSupport = true` 并永久缓存，于是 standalone 部署上
 * 一次瞬时的 hello 抖动会让之后每一次 withTransaction 都走事务分支，
 * 在第一个写上抛 IllegalOperation（删除设备长期 500），本应可用的降级顺序写路径
 * 再也不被尝试——一个可自愈的抖动被固化成需要重启进程的故障。
 *
 * 因此本文件钉住缓存策略的**两侧**（缺一侧就是假门禁）：
 *   ① 失败不缓存：失败那次仍按副本集处理（fail-loud 保持），但下次调用必须重新探测，
 *      拓扑恢复后立即降级；
 *   ② 成功必须缓存：稳态下 hello 只发一次，不给健康副本集增加每请求往返。
 *
 * 全程用桩驱动（伪造 connection.client.db().command + 桩 mongoose.startSession），
 * 不连库：本文件断言的是纯分支选择，真连库反而会把「探测失败」这一前提冲掉。
 */
const mongoose = require('mongoose');
const logger = require('../utils/logger');

describe('withTransaction：拓扑探测结果的缓存语义', () => {
  let withTransaction;
  let _resetForTests;
  let originalClientDescriptor;

  let startSessionSpy;
  let warnSpy;
  let fakeSessions;

  beforeAll(() => {
    ({ withTransaction, _resetForTests } = require('../utils/transaction'));
    // 快照真实 descriptor：用例会把 client 换成桩，必须逐字节还原回去，
    // 否则同文件后续 describe（乃至本文件的"未连接"用例）前提被污染。
    originalClientDescriptor = Object.getOwnPropertyDescriptor(mongoose.connection, 'client');
  });

  afterAll(() => {
    if (originalClientDescriptor) {
      Object.defineProperty(mongoose.connection, 'client', originalClientDescriptor);
    }
  });

  /** 把 hello 探测的返回值/抛错行为插进 connection.client */
  const installClient = (command) => {
    const client = { db: jest.fn().mockReturnValue({ command }) };
    Object.defineProperty(mongoose.connection, 'client', {
      value: client,
      configurable: true,
      writable: true,
    });
    return client;
  };

  /** client 不可读（未连接时就是这个形态）→ 探测在 .db() 上抛 TypeError */
  const breakClient = () => {
    Object.defineProperty(mongoose.connection, 'client', {
      value: undefined,
      configurable: true,
      writable: true,
    });
  };

  const makeFakeSession = () => ({
    startTransaction: jest.fn(),
    commitTransaction: jest.fn().mockResolvedValue(undefined),
    abortTransaction: jest.fn().mockResolvedValue(undefined),
    endSession: jest.fn(),
  });

  beforeEach(() => {
    _resetForTests();
    fakeSessions = [];
    startSessionSpy = jest.spyOn(mongoose, 'startSession').mockImplementation(async () => {
      const session = makeFakeSession();
      fakeSessions.push(session);
      return session;
    });
    warnSpy = jest.spyOn(logger, 'warn').mockImplementation(() => {});
  });

  afterEach(() => {
    startSessionSpy.mockRestore();
    warnSpy.mockRestore();
    if (originalClientDescriptor) {
      Object.defineProperty(mongoose.connection, 'client', originalClientDescriptor);
    } else {
      delete mongoose.connection.client;
    }
  });

  describe('① 探测失败不缓存：瞬时抖动可自愈', () => {
    test('失败那一次按副本集处理（fail-loud 进事务分支）并告警留痕，不静默降级', async () => {
      breakClient();

      const seen = await withTransaction(async (session) => session);

      // 收到真 session 而不是 null：探测读不到拓扑时不得假装是 standalone
      expect(seen).toBe(fakeSessions[0]);
      expect(startSessionSpy).toHaveBeenCalledTimes(1);
      expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining('事务能力探测失败'));
    });

    test('下一次调用重新探测：拓扑恢复为 standalone 后自动降级为顺序写 fn(null)', async () => {
      const command = jest
        .fn()
        .mockRejectedValueOnce(new Error('hello 网络抖动'))
        // 第二次探测成功：standalone 响应既无 setName 也无 msg=isdbgrid
        .mockResolvedValue({ me: '127.0.0.1:27017' });
      const client = installClient(command);

      const first = await withTransaction(async (session) => session);
      expect(first).toBe(fakeSessions[0]);

      const second = await withTransaction(async (session) => session);

      // 修复前此处拿到的是 session（失败结论被永久缓存），第二个写在 standalone 上抛
      // IllegalOperation；现在必须重新探测并识别出 standalone → fn(null)
      expect(second).toBeNull();
      expect(command).toHaveBeenCalledTimes(2);
      expect(client.db).toHaveBeenCalledWith('admin');
      // 第二次不得再开事务：降级路径根本不该 startSession
      expect(startSessionSpy).toHaveBeenCalledTimes(1);
    });

    test('持续失败也不沉淀缓存：每次都重探、每次都告警（缓存值不会被写成 true）', async () => {
      const command = jest.fn().mockRejectedValue(new Error('拓扑不可达'));
      installClient(command);

      for (let i = 0; i < 3; i++) {
        const seen = await withTransaction(async (session) => session);
        expect(seen).toBe(fakeSessions[i]);
      }

      expect(command).toHaveBeenCalledTimes(3);
      expect(startSessionSpy).toHaveBeenCalledTimes(3);
      expect(warnSpy).toHaveBeenCalledTimes(3);
    });
  });

  describe('② 探测成功即缓存：稳态零额外往返', () => {
    test('副本集：两次调用只发一次 hello，两次都走事务分支', async () => {
      const command = jest.fn().mockResolvedValue({ setName: 'rs0', isWritablePrimary: true });
      installClient(command);

      expect(await withTransaction(async (s) => s)).toBe(fakeSessions[0]);
      expect(await withTransaction(async (s) => s)).toBe(fakeSessions[1]);

      expect(command).toHaveBeenCalledTimes(1);
      expect(startSessionSpy).toHaveBeenCalledTimes(2);
    });

    test('standalone：第二次不再发 hello，始终降级且从不 startSession', async () => {
      const command = jest.fn().mockResolvedValue({ me: '127.0.0.1:27017' });
      installClient(command);

      expect(await withTransaction(async (s) => s)).toBeNull();
      expect(await withTransaction(async (s) => s)).toBeNull();

      expect(command).toHaveBeenCalledTimes(1);
      expect(startSessionSpy).not.toHaveBeenCalled();
    });
  });

  describe('③ 分支判定只看 hello 的公开契约字段', () => {
    test('副本集/mongos 进事务分支，standalone 及近似形态降级（含空集防空守卫）', async () => {
      // [用例名, hello 响应, 是否应走事务分支]
      const cases = [
        ['副本集成员（含 setName）', { setName: 'rs0' }, true],
        ['mongos（msg=isdbgrid）', { msg: 'isdbgrid' }, true],
        ['standalone（两者皆无）', { me: '127.0.0.1:27017', ismaster: true }, false],
        ['空响应按 standalone 处理', {}, false],
        ['setName 为空串不算副本集', { setName: '' }, false],
        ['msg 拼错不算 mongos', { msg: 'isdbgridX' }, false],
      ];
      // 表测若因重构变成空数组会永久全绿——先自证用例真的存在
      expect(cases.length).toBeGreaterThanOrEqual(6);

      for (const [name, hello, shouldUseTransaction] of cases) {
        _resetForTests();
        installClient(jest.fn().mockResolvedValue(hello));
        // 表测在同一用例内循环：桩的调用史必须逐轮清零，否则第二次的 1 次调用
        // 会被读成累计的 2 次（首轮实跑即暴露此点，非事后补的断言）
        startSessionSpy.mockClear();

        const seen = await withTransaction(async (session) => session);
        expect({ name, tookTransactionBranch: seen !== null }).toEqual({
          name,
          tookTransactionBranch: shouldUseTransaction,
        });
        expect(startSessionSpy).toHaveBeenCalledTimes(shouldUseTransaction ? 1 : 0);
      }
    });
  });
});
