/**
 * 审计链核验的**服务端时间预算**（maxTimeMS）门禁（2026-10-01）
 *
 * 修的是哪一条：`auditChainMonitor` 用 `verificationRunning` 做单轮闸门，而它调的
 * `verifyAuditChain` 里那条 `find` 此前**不带任何服务端上限**。取数挂死（索引缺失/
 * 集合被锁/网络半开）时 `await` 永不返回 ⇒ `finally` 永不执行 ⇒ 闸门永久停在 true，
 * 之后每一轮都判"上一轮未结束"而跳过，`isRunning()` 却照样回答 true（定时器确实挂着）。
 * 即"看起来在跑、其实早已死"——本模块存在的意义正是让链的问题**被自动发现**，
 * 所以这条静默停摆路径必须构造上排除，而不是靠运维盯 lastRunAt。
 *
 * 判据分四层，缺一层都可能是"看起来修了"：
 *  A. 替身层——预算有没有从调用方传到 find 的 options 袋；默认路径调用面是否逐字不变。
 *  B. 取值层——服务端对 maxTimeMS 的**实测**约束（真库跑出来的，不是推测）：
 *     小数 ⇒ FailedToParse「Expected an integer」；负数 ⇒ BadValue「must be >= 0」；
 *     0 ⇒ 接受，但语义就是"不限"，所以不发（见下面 ②）。
 *  C. 真库层——**替身允许任何 API**。本仓已有一次「Aggregate 实例上根本没有
 *     .maxTimeMS()，链式写法在替身下全绿、真库下抛 TypeError 又被 catch 吞掉」的先例
 *     （tests/services/auditMonitorDetectionCoverage.test.js:157-159）。
 *     所以"选项真的被驱动与服务端接受"必须由打真库的用例判。
 *  D. 停摆反证——一轮被掐断后闸门必须释放；否则前三层全绿也挡不住"永久跳过"。
 */

const MINUTE = 60 * 1000;

// ---------------------------------------------------------------------------
// A + B. 服务层：预算进 options 袋，退化值一律不下发
// ---------------------------------------------------------------------------
describe('verifyAuditChain 的 maxTimeMS（服务层）', () => {
  const mongoose = require('mongoose');
  const { verifyAuditChain } = require('../../services/auditChainVerify');
  const { computeHash, computeHmac, canonicalPayload } = require('../../utils/auditChain');

  /**
   * 记录 find **全部实参**的模型替身。
   * lean 每次返回新数组：服务层会 `window.reverse()` 原地反转，同一条用例里调用两次
   * 若共用一个数组，第二次拿到的输入顺序就是反的（假红/假绿都可能）。
   */
  function makeBudgetSpyModel(docsNewestFirst) {
    const findCalls = [];
    const tail = {
      sort: jest.fn(() => tail),
      limit: jest.fn(() => tail),
      lean: jest.fn(() => Promise.resolve(docsNewestFirst.slice())),
    };
    const model = {
      find: jest.fn((...args) => {
        findCalls.push(args);
        return tail;
      }),
    };
    return { model, findCalls };
  }

  /** 造一条自身可重算的合法链，最新在前（服务层的入参口径） */
  function chainDocs(count) {
    const docs = [];
    let previous;
    for (let i = 0; i < count; i += 1) {
      const doc = {
        _id: new mongoose.Types.ObjectId(),
        timestamp: new Date(1761700000000 + i * 1000),
        action: `act${i}`,
        category: 'auth',
        userId: '64f000000000000000000001',
        username: 'alice',
        ip: '127.0.0.1',
        path: '/api/auth/login',
        statusCode: 200,
        body: {},
        hashVersion: 4,
      };
      doc.prevHash = previous ? previous.hash : null;
      doc.hash = computeHash(doc.prevHash, canonicalPayload(doc, doc.hashVersion));
      doc.hmac = computeHmac(doc.hash);
      previous = doc;
      docs.push(doc);
    }
    return docs.reverse();
  }

  test('带预算：find 第三参就是 { maxTimeMS }，第二参 null 是 projection 占位', async () => {
    const { model, findCalls } = makeBudgetSpyModel(chainDocs(3));
    const report = await verifyAuditChain(model, { maxRecords: 10, maxTimeMS: 4321 });

    expect(findCalls).toHaveLength(1);
    expect(findCalls[0][1]).toBeNull();
    expect(findCalls[0][2]).toEqual({ maxTimeMS: 4321 });
    // 预算不是"传到了"就算完：核验本身必须照常产出结论
    expect(report.total).toBe(3);
    expect(report.breaks).toBe(0);
  });

  test('反向：不传预算时第三参为 undefined —— HTTP 接口与离线脚本调用面逐字不变', async () => {
    const { model, findCalls } = makeBudgetSpyModel(chainDocs(2));
    await verifyAuditChain(model, { maxRecords: 10 });

    expect(findCalls[0]).toHaveLength(3);
    expect(findCalls[0][2]).toBeUndefined();
  });

  // 真库实测：`maxTimeMS: 0` 服务端**接受**（语义即"不限"）。所以不发 0 的理由不是
  // "会被拒"，而是"发了也不生效，却把默认调用面变成三参"——两条都必须在注释里说清，
  // 否则下一个人会以为 0 是危险值而把它改成 1（那才是真给服务端发一个必掐死的预算）。
  test.each([
    ['undefined', undefined],
    ['0（服务端接受但等于不限）', 0],
    ['负数（真库报 BadValue）', -5000],
    ['NaN', Number.NaN],
    ['Infinity', Number.POSITIVE_INFINITY],
    ['非数字字符串', 'abc'],
    ['null', null],
  ])('退化值 %s 不下发预算', async (_label, value) => {
    const { model, findCalls } = makeBudgetSpyModel(chainDocs(1));
    await verifyAuditChain(model, { maxRecords: 10, maxTimeMS: value });

    expect(findCalls[0][2]).toBeUndefined();
  });

  // 真库实测：小数 maxTimeMS 报 FailedToParse「Expected an integer」。间隔这个 env
  // 没有 integer 校验，90000.5 是合法配置值 ⇒ 服务层必须自己取整。
  test.each([
    ['小数向下取整', 1500.9, 1500],
    ['字符串数字', '9000', 9000],
    ['小于 1 的正数取整后为 0 ⇒ 不下发', 0.4, undefined],
  ])('取值归一：%s', async (_label, input, expected) => {
    const { model, findCalls } = makeBudgetSpyModel(chainDocs(1));
    await verifyAuditChain(model, { maxRecords: 10, maxTimeMS: input });

    expect(findCalls[0][2]).toEqual(expected === undefined ? undefined : { maxTimeMS: expected });
  });

  test('等价性：带预算与不带预算的报告除 verifiedAt 外逐字相同', async () => {
    const docs = chainDocs(4);
    const a = makeBudgetSpyModel(docs);
    const b = makeBudgetSpyModel(docs);

    const budgeted = await verifyAuditChain(a.model, { maxRecords: 50, maxTimeMS: 60000 });
    const plain = await verifyAuditChain(b.model, { maxRecords: 50 });

    expect(typeof budgeted.verifiedAt).toBe('string');
    const { verifiedAt: _v1, ...budgetedRest } = budgeted;
    const { verifiedAt: _v2, ...plainRest } = plain;
    // 这条是"预算不改变结论"的全部含义：计数、判据、口径回显都不因预算漂移。
    // 刻意不把 maxTimeMS 写进 scanned——那会改动既有消费方断言的字段形状。
    expect(budgetedRest).toEqual(plainRest);
  });

  test('断裂结论不受预算影响（预算不是"跳过校验"的开关）', async () => {
    const docs = chainDocs(3);
    delete docs[0].hash; // 位于带哈希记录之后 ⇒ hash_stripped
    delete docs[0].prevHash;
    delete docs[0].hmac;

    const { model } = makeBudgetSpyModel(docs);
    const report = await verifyAuditChain(model, { maxRecords: 10, maxTimeMS: 30000 });
    expect(report.breaks).toBe(1);
    expect(report.byType.hash_stripped).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// C. 真库层：驱动与服务端真的接受这条选项
// ---------------------------------------------------------------------------
describe('maxTimeMS 在真实 mongoose / mongod 上成立', () => {
  const mongoose = require('mongoose');

  test('Query 确有 maxTimeMS 入口，且 options 袋与链式落同一处', () => {
    // Mongoose 8 的 Aggregate 实例上**没有** .maxTimeMS()（只能走 aggregate 第二参），
    // Query 有——两条路径不能凭印象写，所以这里直接钉住实测事实。
    expect(typeof mongoose.Query.prototype.maxTimeMS).toBe('function');

    const schema = new mongoose.Schema({ probe: String });
    const Model = mongoose.models.ProbeMaxTime || mongoose.model('ProbeMaxTime', schema);
    const chained = Model.find({}).maxTimeMS(1234);
    const bagged = Model.find({}, null, { maxTimeMS: 1234 });
    expect(chained.options.maxTimeMS).toBe(1234);
    expect(bagged.options.maxTimeMS).toBe(chained.options.maxTimeMS);
    expect(Model.find({}, null, undefined).options.maxTimeMS).toBeUndefined();
  });

  test('真库核验：带预算与不带预算返回同一结论（选项被服务端接受且不改语义）', async () => {
    const RealAuditLog = jest.requireActual('../../models/AuditLog');
    const { verifyAuditChain: realVerify } = jest.requireActual('../../services/auditChainVerify');
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }

    const budgeted = await realVerify(RealAuditLog, { maxRecords: 200, maxTimeMS: 60000 });
    const plain = await realVerify(RealAuditLog, { maxRecords: 200 });

    expect(budgeted.total).toBe(plain.total);
    expect(budgeted.breaks).toBe(plain.breaks);
    expect(budgeted.byType).toEqual(plain.byType);
  }, 20000);

  // 实测：同一个"小数 maxTimeMS"在两套 mongod 上文案不同——
  //   本机（.env 的 MONGODB_URI）：FailedToParse「Expected an integer: maxTimeMS: 90000.5」
  //   测试用（内存 mongod）：      「maxTimeMS has non-integral value」
  // 所以断言只钉"必拒"，不钉文案（钉文案等于给 mongod 版本升级埋一条假红）。
  test('真库反向判据：小数预算必被拒（证明取整那条注释不是编的）', async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    const RealAuditLog = jest.requireActual('../../models/AuditLog');
    await expect(RealAuditLog.estimatedDocumentCount({ maxTimeMS: 90000.5 })).rejects.toThrow(
      /maxTimeMS/i
    );
    await expect(
      RealAuditLog.estimatedDocumentCount({ maxTimeMS: 60000 })
    ).resolves.toBeGreaterThanOrEqual(0);
  }, 20000);
});

// ---------------------------------------------------------------------------
// D. 监控层：预算来自 roundBudgetMs，覆盖本轮两次取数，且掐断后不永久停摆
// ---------------------------------------------------------------------------
describe('auditChainMonitor 的单轮预算与闸门释放', () => {
  jest.mock('../../models/AuditLog', () => ({
    estimatedDocumentCount: jest.fn().mockResolvedValue(7),
  }));
  jest.mock('../../services/auditChainVerify', () => ({
    verifyAuditChain: jest.fn(),
    computeChainVerdict: jest.fn(() => ({ code: 0 })),
  }));
  jest.mock('../../utils/logger', () => ({
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
    debug: jest.fn(),
  }));
  jest.mock('../../services/securityAlert', () => ({
    shouldSendAlert: jest.fn(() => true),
    sendNotification: jest.fn(async () => {}),
    ALERT_TYPES: {
      AUDIT_CHAIN_BREAK_DETECTED: 'audit_chain_break_detected',
      AUDIT_HASH_COMPUTE_FAILED: 'audit_hash_compute_failed',
    },
    ALERT_LEVELS: { CRITICAL: 'critical', HIGH: 'high' },
    THRESHOLDS: { alertRateLimitMs: 300000 },
  }));

  const AuditLog = require('../../models/AuditLog');
  const chainVerify = require('../../services/auditChainVerify');
  const auditChainMonitor = require('../../services/auditChainMonitor');

  const REPORT = {
    breaks: 0,
    total: 5,
    legacy: 0,
    hashComputeFailed: 0,
    hmacChecked: true,
    byType: {},
    samples: [],
    scanned: { maxRecords: 2000, fromLatest: true, filter: {} },
  };

  /** 用「start 读 env → stop → 直调一轮」取回生效间隔，不依赖 fake timers */
  async function runRoundWithInterval(intervalEnv) {
    if (intervalEnv === undefined) delete process.env.AUDIT_CHAIN_MONITOR_INTERVAL_MS;
    else process.env.AUDIT_CHAIN_MONITOR_INTERVAL_MS = String(intervalEnv);
    auditChainMonitor.start();
    auditChainMonitor.stop();
    await auditChainMonitor.runVerification();
    return chainVerify.verifyAuditChain.mock.calls.at(-1)[1];
  }

  beforeEach(() => {
    auditChainMonitor.stop();
    auditChainMonitor.__resetForTest();
    chainVerify.verifyAuditChain.mockReset();
    chainVerify.verifyAuditChain.mockResolvedValue(REPORT);
    chainVerify.computeChainVerdict.mockReset();
    chainVerify.computeChainVerdict.mockImplementation(() => ({ code: 0 }));
    AuditLog.estimatedDocumentCount.mockReset();
    AuditLog.estimatedDocumentCount.mockResolvedValue(7);
  });

  afterAll(() => {
    delete process.env.AUDIT_CHAIN_MONITOR_INTERVAL_MS;
  });

  test('正向：核验 find 与估算各拿到同一个正整数预算', async () => {
    const opts = await runRoundWithInterval(10 * MINUTE);

    expect(typeof opts.maxTimeMS).toBe('number');
    expect(Number.isInteger(opts.maxTimeMS)).toBe(true);
    expect(opts.maxTimeMS).toBeGreaterThan(0);
    // 两次取数共用一个数：写成两个常量时改一个不会让本用例变红，
    // 而"闸门会不会被第二次取数挂住"恰恰取决于两处**都**带预算。
    expect(AuditLog.estimatedDocumentCount).toHaveBeenCalledWith({ maxTimeMS: opts.maxTimeMS });
  });

  test('预算 = floor(max(下限, 生效间隔))，随间隔放大', async () => {
    const floor = auditChainMonitor.__MIN_ROUND_BUDGET_MS;
    const shortest = await runRoundWithInterval(1000); // 低于最小间隔 ⇒ 抬到 60s
    const defaultish = await runRoundWithInterval();
    const slow = await runRoundWithInterval(30 * MINUTE);

    expect(shortest.maxTimeMS).toBe(Math.max(floor, auditChainMonitor.__MIN_INTERVAL_MS));
    expect(defaultish.maxTimeMS).toBe(Math.max(floor, 10 * MINUTE));
    expect(slow.maxTimeMS).toBe(30 * MINUTE);
    expect(slow.maxTimeMS).toBeGreaterThan(shortest.maxTimeMS);
  });

  test('小数间隔不产生小数预算（真库会 FailedToParse）', async () => {
    const opts = await runRoundWithInterval(90000.5);
    expect(Number.isInteger(opts.maxTimeMS)).toBe(true);
    expect(opts.maxTimeMS).toBe(90000);
  });

  test('停摆反证：一轮被服务端掐断后，下一轮照常起跑', async () => {
    await auditChainMonitor.runVerification();

    chainVerify.verifyAuditChain.mockRejectedValueOnce(
      Object.assign(new Error('operation was interrupted'), { codeName: 'MaxTimeMSExpired' })
    );
    await auditChainMonitor.runVerification();

    const health = auditChainMonitor.getHealth();
    expect(health.failures).toBe(1);
    expect(health.consecutiveFailures).toBe(1);
    expect(health.lastFailureMessage).toMatch(/interrupted/);
    expect(health.skippedOverlaps).toBe(0);

    // 掐断之后还能跑第三轮 ⇒ 挂死不会变成永久停摆（这才是本修复的目的）
    await auditChainMonitor.runVerification();
    expect(chainVerify.verifyAuditChain).toHaveBeenCalledTimes(3);
    expect(auditChainMonitor.getHealth().consecutiveFailures).toBe(0);
  });
});

// 收尾必须关连接：mongodb-memory-server 是所有套件共用的同一个 mongod，
// 不关的套件会让 jest worker 在 FORCE_EXIT_DELAY(500ms) 后被强杀
// （"A worker process has failed to exit gracefully"），强杀会吞掉该套件的输出。
// readyState 守卫是为了不关别人建立的连接；本条挂在根作用域，故在本套件所有
// describe 自己的 afterAll 之后才跑。这里就地 require('mongoose')：本仓有 3 个套件
// 只在 describe 体内 require，从根作用域引用那个名字会 ReferenceError。
afterAll(async () => {
  const mongoose = require('mongoose');
  if (mongoose.connection.readyState !== 0) await mongoose.connection.close();
});
