/**
 * 审计链大扫描的「让出事件循环」回归
 *
 * 被测点：src/services/auditChainVerify.js 第 150 行
 *   if (total % 2000 === 0) await new Promise((resolve) => setImmediate(resolve));
 *
 * 为什么这条值得单独立一个文件：verifyAuditChain 对每条记录做 SHA-256 + 规范 JSON 序列化，
 * 是**纯 CPU 的同步循环**。除这个 2000 一批的让出之外，整个扫描不产生任何 await 点——
 * 也就是说：让出一旦被删掉，千万级审计集合的校验会把该进程**整段钉死**，
 * 期间 /health、/readyz、心跳、其他请求全都无法响应（表现为「服务起来了但查一次链就假死」）。
 *
 * 而这条可用性不变量此前**从未被任何测试证明过**：现有 auditChainVerify 用例最多造 3 条记录，
 * 那个让出回调（以及它所在的匿名函数）从未执行 → 该文件 functions 覆盖率被拖到 75%，
 * per-file 阈值 functions:100 因此常红（2026-09-19 并行会话实测）。
 * 这里不降阈值而是把它真跑过：让出发生了几次、发生在第几条、外部回调有没有插进来，全部可断言。
 *
 * 断言策略（避免依赖计时）：
 *   在扫描开始前先排一个 setImmediate 标记，再给「最后一条被处理的记录」的 hash 属性装一个
 *   getter，在它被读取的那一刻采样标记值。
 *   - 有让出 ⇒ 标记已翻为 true（让出期间 check 相位跑完了那条 immediate）；
 *   - 无让出 ⇒ 整个 for 循环是同一个宏任务，标记必然仍是 false。
 *   两个方向各一条用例，任何一侧失真都会红。
 */

const mongoose = require('mongoose');
const { computeHash, computeHmac, canonicalPayload } = require('../utils/auditChain');
const { verifyAuditChain } = require('../services/auditChainVerify');

/** 只实现 verifyAuditChain 用到的那条链式调用（与既有直连单测同形态，不碰数据库） */
const makeAuditLog = (docs) => ({
  find: jest.fn().mockReturnValue({
    sort: jest.fn().mockReturnValue({
      limit: jest.fn().mockReturnValue({
        lean: jest.fn().mockResolvedValue(docs),
      }),
    }),
  }),
});

/** 按时序构建 n 条**完整合法**的 v3 记录，返回升序数组（[0]=最早） */
function buildChain(n) {
  const out = [];
  let prev = null;
  for (let i = 0; i < n; i += 1) {
    const doc = {
      _id: new mongoose.Types.ObjectId(),
      timestamp: new Date(Date.parse('2026-09-04T08:00:00.000Z') + i * 1000),
      action: 'login',
      category: 'auth',
      userId: '64f000000000000000000001',
      username: 'alice',
      ip: '127.0.0.1',
      path: '/api/auth/login',
      statusCode: 200,
      body: {},
      description: `row-${i}`,
      hashVersion: 3,
    };
    doc.prevHash = prev ? prev.hash : null;
    doc.hash = computeHash(doc.prevHash, canonicalPayload(doc, doc.hashVersion));
    doc.hmac = computeHmac(doc.hash);
    out.push(doc);
    prev = doc;
  }
  return out;
}

/**
 * 跑一次「大扫描 + 交错探测」。
 * @param {number} n 记录条数
 * @returns {Promise<Object>} 报告、让出次数、以及最后一条被读取 hash 时的标记值
 */
async function scanWithInterleaveProbe(n) {
  const asc = buildChain(n);
  const newest = asc[asc.length - 1];
  const realHash = newest.hash;

  // 扫描开始前先排一个 immediate 标记：它只能在扫描让出时才可能被执行
  let ticked = false;
  setImmediate(() => {
    ticked = true;
  });

  // 在「最后被处理」的那条（升序末尾 = 最新）上采样标记值
  let probe = null;
  Object.defineProperty(newest, 'hash', {
    configurable: true,
    enumerable: true,
    get() {
      if (probe === null) probe = ticked;
      return realHash;
    },
  });

  // spy 必须在上面那次 setImmediate 之后装，否则计数会把探测自己算进去
  const spy = jest.spyOn(global, 'setImmediate');
  // 传入「最新在前」：被测函数内部 reverse() 成升序推进（与真实 find().sort({_id:-1}) 一致）
  const report = await verifyAuditChain(makeAuditLog(asc.slice().reverse()), { maxRecords: n });
  const yields = spy.mock.calls.length;
  spy.mockRestore();

  return { report, yields, probe, realHash, newestHash: report.chainTailHash };
}

describe('审计链大扫描：每 2000 条让出一次事件循环', () => {
  test('2001 条完整链：逐条校验通过，且让出恰好发生 1 次', async () => {
    const { report, yields, probe, realHash } = await scanWithInterleaveProbe(2001);

    // 前提自证：造的是真链，不是一堆空记录（否则"扫过 2000 条"没有意义）
    expect(report.total).toBe(2001);
    expect(report).toMatchObject({ intact: true, breaks: 0, legacy: 0, hmacChecked: true });
    expect(report.chainTailHash).toBe(realHash);

    expect(yields).toBe(1); // 只在 total=2000 处让出
    // 让出期间外部回调真的插进来了 ⇒ 这个进程在扫描中仍可服务其他事
    expect(probe).toBe(true);
  });

  test('1999 条：不足一批不让出（外部回调不得插进来）——上一条的负向对照', async () => {
    const { report, yields, probe } = await scanWithInterleaveProbe(1999);
    expect(report.total).toBe(1999);
    expect(report.intact).toBe(true);
    // 没有让出 ⇒ 整个扫描是一个宏任务 ⇒ 扫描中读到的标记必然还是 false
    expect(yields).toBe(0);
    expect(probe).toBe(false);
  });

  test('4001 条：让出次数为 2，即「每 2000 条一批」而非「每条一次」', async () => {
    // 这条锁的是让出**频率**：改成每条都 await 会让 CPU 占用同样的循环放大几个量级的
    // 调度开销（大集合校验从"分钟级"变"小时级"），也是一种退化。
    const { report, yields, probe } = await scanWithInterleaveProbe(4001);
    expect(report.total).toBe(4001);
    expect(report.intact).toBe(true);
    expect(yields).toBe(2);
    expect(probe).toBe(true);
  });
});
