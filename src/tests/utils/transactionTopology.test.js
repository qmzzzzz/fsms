/**
 * withTransaction 拓扑能力感知——行为化测试
 *
 * 覆盖 transaction.js 的四条行为线：
 *   1. 拓扑不可读（未连接 / client 缺失）→ 按支持处理（fail-loud），
 *      走 startSession 事务路径；
 *   2. 事务路径成功/失败语义：fn 结果返回、业务失败 abort 并原样上抛、
 *      abort 自身失败不掩盖原始错误；
 *   3. standalone（Single 拓扑）降级为顺序写 fn(null)，降级告警每次进程只发一次；
 *   4. finally 里 endSession() 的「拒绝臂」：清理超时既不打死进程也不掩盖业务结果
 *      （2026-10-03 审计线；缺陷形状是裸调用丢返回值，见该 describe 的注释）。
 *
 * 1/2/4 用 mock session 纯单测（用桩把 client 置为不可读 → 触发 fail-loud）；
 * 3 连 mongodb-memory-server（standalone 拓扑 type='Single'，真实路径）。
 *
 * 【桩的返回值类型也是判据的一部分】原先 endSession 写成 `jest.fn()`（返回 undefined），
 * 于是被测代码无论 await 还是裸调用，四条老用例都不会变——夹具把整类"未持有的拒绝"抹平了。
 * 现在它与 commit/abort 同形（mockResolvedValue），并补了一条"夹具自证"用例钉住这点。
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
        // 真实驱动里 endSession 是 **async** 方法（node_modules/mongodb/lib/sessions.js:121），
        // 返回 Promise。原来写成 `jest.fn()`（返回 undefined）意味着：被测代码无论是
        // 裸调用、还是 await，本文件的断言都不变——夹具把整类"未持有的拒绝"抹平了。
        // commit/abort 本来就是 mockResolvedValue，只有这一项与它们不同形，是疏漏而非设计。
        endSession: jest.fn().mockResolvedValue(undefined),
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

    // ── endSession 的「拒绝臂」────────────────────────────────────────
    // 缺陷形状（2026-10-03 审计线）：`finally { session.endSession(); }` 丢掉了返回值。
    // 驱动里这个方法是 async，并且**只**对 MongoOperationTimeoutError 显式 rethrow
    // （node_modules/mongodb/lib/sessions.js:121-129，其余错误 squashError），
    // 于是"事务清理超时"会变成一个没人持有的拒绝 ⇒ src/index.js:446 起
    // 的 unhandledRejection 口径（所有环境）flush 审计后 process.exit(1)：
    // 一次清理超时打死整个进程。上游同一条链都是"接住"的：
    // mongoose/lib/connection.js:743 `session.endSession().catch(() => {})`、
    // mongodb/lib/cursor/abstract_cursor.js:579 `.then(undefined, squashError)`。
    describe('endSession 的拒绝臂（清理超时不得打死进程，也不得掩盖业务结果）', () => {
      const fs = require('fs');
      const path = require('path');

      test('前提自证：驱动的 endSession 确是 async，且确有一条会 rethrow 的拒绝路径', () => {
        // 不是推断：读依赖自己的源码。若哪天它不再 rethrow，这条先红，
        // 由人去判断"持有 promise"的判据要不要降级。
        const src = fs
          .readFileSync(
            path.join(__dirname, '..', '..', '..', 'node_modules', 'mongodb', 'lib', 'sessions.js'),
            'utf8'
          )
          .split(/\r?\n/);
        const decl = src.findIndex((l) => /^\s*async endSession\(/.test(l));
        expect(decl).toBeGreaterThan(-1);
        const body = src.slice(decl, decl + 14).join('\n');
        expect(body).toMatch(/throw error;/); // squash 之外留了一条真 rethrow
      });

      test('前提自证：上游自己也是「接住」而不是丢弃（同一条链的第二处印证）', () => {
        const read = (pkg, rel) =>
          fs
            .readFileSync(path.join(__dirname, '..', '..', '..', 'node_modules', pkg, rel), 'utf8')
            .split(/\r?\n/);
        const mongooseLine = read('mongoose', 'lib/connection.js').find((l) =>
          /session\.endSession\(\)\.catch\(/.test(l)
        );
        expect(mongooseLine).toBeDefined();
        const cursorLine = read('mongodb', 'lib/cursor/abstract_cursor.js').find((l) =>
          /cursorSession\.endSession\(\)\.then\(/.test(l)
        );
        expect(cursorLine).toBeDefined();
      });

      test('夹具自证：桩的 endSession 返回真 Promise（否则 await 与裸调用不可区分）', async () => {
        // 这一条是上面四条的对侧证据：父级夹具曾写成 `jest.fn()`（返回 undefined），
        // 那种桩下"未持有的拒绝"整类缺陷不可能被测出，四条断言全部空过。
        const p = fakeSession.endSession();
        expect(p).toBeInstanceOf(Promise);
        await p;
      });

      test('成功路径：清理超时也被持有——withTransaction 必须等清理 settle 后才返回', async () => {
        const order = [];
        fakeSession.endSession.mockImplementation(
          () =>
            new Promise((_, reject) =>
              setTimeout(() => {
                order.push('cleanup-settled');
                reject(new Error('MongoOperationTimeoutError: endSession 清理超时'));
              }, 0)
            )
        );

        const result = await withTransaction(async (session) => {
          expect(session).toBe(fakeSession);
          return 'ok';
        });
        order.push('withTransaction-resolved');

        expect(result).toBe('ok'); // 拒绝被就地吞掉：业务结果不受影响
        // 裸调用（缺陷形状）下 withTransaction 在微任务里就先返回 ⇒ 这条顺序反
        expect(order).toEqual(['cleanup-settled', 'withTransaction-resolved']);
        expect(fakeSession.endSession).toHaveBeenCalledTimes(1);
      });

      test('业务失败 + 清理失败：上抛的仍是原始错误，不是清理错误', async () => {
        const boom = new Error('业务写失败');
        fakeSession.endSession.mockRejectedValue(new Error('MongoOperationTimeoutError'));
        await expect(
          withTransaction(async () => {
            throw boom;
          })
        ).rejects.toBe(boom);
        expect(fakeSession.abortTransaction).toHaveBeenCalledTimes(1);
        expect(fakeSession.endSession).toHaveBeenCalledTimes(1);
      });

      test('abort 与 endSession 同时失败：两道吞叠加仍不掩盖原始错误', async () => {
        const boom = new Error('原始业务错误');
        fakeSession.abortTransaction.mockRejectedValue(new Error('abort 网络失败'));
        fakeSession.endSession.mockRejectedValue(new Error('endSession 清理超时'));
        await expect(withTransaction(async () => Promise.reject(boom))).rejects.toBe(boom);
        expect(fakeSession.endSession).toHaveBeenCalledTimes(1);
      });

      test('源码文本闸：src 下每个 endSession 调用点都必须持有它的 promise', () => {
        // 判据落在源码而非单次运行：将来新增一处 `session.endSession();`（例如另一个
        // 事务/会话封装），上面几条用例各自只覆盖已知的这条路径，全都可能依旧全绿。
        const stripComments = (text) =>
          text
            .split(/\r?\n/)
            .filter((l) => !/^\s*(?:\/\/|\/\*|\*)/.test(l))
            .join('\n');
        const walk = (dir, out = []) => {
          for (const name of fs.readdirSync(dir)) {
            const full = path.join(dir, name);
            if (name === 'node_modules' || name === 'tests') continue;
            if (fs.statSync(full).isDirectory()) walk(full, out);
            else if (name.endsWith('.js')) out.push(full);
          }
          return out;
        };
        const held = (line) =>
          /(?:^|[^.\w])(?:await|return)\s+[\w$.[\]]*\.endSession\(/.test(line) ||
          /\.endSession\(\)\s*\.\s*(?:catch|then)/.test(line);

        const sites = [];
        for (const file of walk(path.join(__dirname, '..', '..'))) {
          stripComments(fs.readFileSync(file, 'utf8'))
            .split(/\r?\n/)
            .forEach((line) => {
              if (line.includes('.endSession(')) sites.push(line.trim());
            });
        }
        // 当前全仓生产代码只有 transaction.js 一处会话清理；新增调用点时要么持有 promise
        // 要么更新这条基线（并在用例里说明为什么可以丢）。
        expect(sites.length).toBe(1);
        expect(sites.filter((s) => !held(s))).toEqual([]);
      });
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
