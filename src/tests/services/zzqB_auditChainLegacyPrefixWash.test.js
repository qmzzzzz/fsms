const mongoose = require('mongoose');
const { computeHash, computeHmac, canonicalPayload } = require('../../utils/auditChain');
const { verifyAuditChain, computeChainVerdict } = require('../../services/auditChainVerify');

/**
 * 「抹掉除最新一条以外的全部哈希」不得等于链完整
 *
 * 【这条边界为什么单独测】判据里那道口是 `nothingHashed = legacyCount >= total`：
 * 抹光整窗会被它挡住，**留一条**就落在 `total-1 >= total` 为假的那一侧。
 * 于是攻击动作从"抹光"（已被否决）变成"抹光但留最新"——而后者在链接性这一层也是干净的：
 * 被抹的那些记录都排在前面（无哈希 ⇒ 全部计入 legacy），最新那条是**窗口里第一条带哈希的**，
 * 链接检查把它当"窗口起点，父在窗口外"给免检了。免检的前提不成立：
 * 它的父哈希并不是"在窗口外"，而是"就在它前面那条记录的位置上，而那条没有哈希"。
 *
 * 【反向口径同样必须成立，否则本判据是假阳性的来源】诚实形态下链启用时
 * `getChainTail` 从库里读不到任何带哈希的记录 ⇒ 链启用的第一条 prevHash 为 null，
 * "链首"本来就不做链接检查。所以：
 *   - 存量 legacy 前缀 + 其后第一条 prevHash=null ⇒ 一条断裂都不许有；
 *   - 真·窗口起点（maxRecords 截断 / TTL 把头删掉）那条 prevHash 非空 ⇒ 依旧免检。
 * 这两种形态与攻击形态在数据上唯一的区别就是"免检的那条到底是不是窗口的第一条"。
 */

function makeAuditLog(docsNewestFirst) {
  return {
    find: jest.fn().mockReturnValue({
      sort: jest.fn().mockReturnValue({
        limit: jest.fn().mockReturnValue({
          lean: jest.fn().mockResolvedValue(docsNewestFirst),
        }),
      }),
    }),
    estimatedDocumentCount: jest.fn().mockResolvedValue(docsNewestFirst.length),
  };
}

function buildDoc(previous, overrides = {}) {
  const doc = {
    _id: new mongoose.Types.ObjectId(),
    timestamp: new Date('2026-09-05T08:00:00.000Z'),
    action: 'login',
    category: 'auth',
    userId: '64f000000000000000000001',
    username: 'alice',
    ip: '127.0.0.1',
    path: '/api/auth/login',
    statusCode: 200,
    body: {},
    hashVersion: 3,
    ...overrides,
  };
  doc.prevHash = previous ? previous.hash : null;
  doc.hash = computeHash(doc.prevHash, canonicalPayload(doc, doc.hashVersion));
  doc.hmac = computeHmac(doc.hash);
  return doc;
}

/** 直连驱动 / mongosh 的 $unset 形态：整组哈希字段消失 */
function strip(doc) {
  delete doc.hash;
  delete doc.prevHash;
  delete doc.hmac;
  delete doc.hashVersion;
  return doc;
}

/** 与 auditController 同源的调用形状（不自己发明参数） */
function verdictOf(report, maxRecords) {
  return computeChainVerdict({
    breaks: report.breaks,
    total: report.total,
    maxRecords,
    collectionTotal: report.total,
    hmacChecked: report.hmacChecked,
    legacy: report.legacy,
    scanned: report.scanned,
  });
}

function buildChain(n) {
  const docs = [];
  for (let i = 0; i < n; i += 1) docs.push(buildDoc(i === 0 ? null : docs[i - 1]));
  return docs; // 升序
}

describe('审计链：legacy 前缀之后的那条不属于「窗口起点免检」', () => {
  test('① 抹掉除最新一条以外的全部哈希 ⇒ 最新那条必须计一条 chain_break', async () => {
    const asc = buildChain(5);
    for (let i = 0; i < 4; i += 1) strip(asc[i]);
    // 动手之后：窗口里只剩最后一条带哈希，且它的父哈希已经随着被抹掉的那条一起消失
    const report = await verifyAuditChain(makeAuditLog([...asc].reverse()), { maxRecords: 5 });

    expect(report.total).toBe(5);
    expect(report.legacy).toBe(4);
    // 阈值边界本身仍然放行（`legacy >= total` 为假），所以防线必须落在 breaks 上
    expect(report.byType.chain_break).toBe(1);
    expect(report.breaks).toBe(1);
    expect(report.intact).toBe(false);
    expect(report.samples[0]).toMatchObject({
      type: 'chain_break',
      _id: String(asc[4]._id),
      // 样本里带着"它声称的父哈希"：这条正是"父就在这窗口里、却没有哈希"的凭据
      actualPrevHash: expect.any(String),
    });

    const verdict = verdictOf(report, 5);
    expect(verdict.code).toBe(1); // 发现断裂，而不是"完整"或"不完整但也没证据"
    expect(verdict.canAttestIntact).toBe(false);
  });

  test('② 诚实形态：存量 legacy 前缀 + 链启用第一条 prevHash=null ⇒ 零断裂', async () => {
    const asc = buildChain(4);
    // 前两条是链启用之前的存量（本机数据里就是 hashVersion=null 那一批）
    strip(asc[0]);
    strip(asc[1]);
    // 链启用后的第一条：getChainTail 从库里读不到带哈希的记录 ⇒ prevHash 归零
    const genesis = buildDoc(null);
    asc[2] = genesis;
    asc[3] = buildDoc(genesis);

    const report = await verifyAuditChain(makeAuditLog([...asc].reverse()), { maxRecords: 4 });

    expect(report.legacy).toBe(2);
    expect(report.total).toBe(4);
    expect(report.breaks).toBe(0);
    expect(report.byType.chain_break).toBe(0);
    expect(report.intact).toBe(true);
    expect(verdictOf(report, 4).code).toBe(0);
  });

  test('③ 真·窗口起点仍免检（maxRecords 截断不得被当成篡改）', async () => {
    const asc = buildChain(6);
    // 只扫最近 3 条：窗口里最旧那条的 prevHash 指向窗口外的父——这是截断，不是抹除
    const window = asc.slice(3);
    expect(window[0].prevHash).toEqual(asc[2].hash);

    const report = await verifyAuditChain(makeAuditLog([...window].reverse()), { maxRecords: 3 });

    expect(report.total).toBe(3);
    expect(report.legacy).toBe(0);
    expect(report.breaks).toBe(0);
    expect(report.intact).toBe(true);
  });

  test('④ 混合形态：legacy 前缀之后又出现带哈希的两条，只有"父失联"那一条计断裂', async () => {
    const asc = buildChain(4);
    strip(asc[0]);
    const genesis = buildDoc(null);
    asc[1] = genesis;
    asc[2] = buildDoc(genesis);
    asc[3] = buildDoc(asc[2]);

    const report = await verifyAuditChain(makeAuditLog([...asc].reverse()), { maxRecords: 4 });

    // 链启用的第一条 prevHash=null ⇒ 免检；其后两条父哈希都在窗口里 ⇒ 命中
    expect(report.byType.chain_break).toBe(0);
    expect(report.breaks).toBe(0);
    expect(report.intact).toBe(true);
  });

  test('⑤ 只抹最新一条（不是留一条）仍然走 hash_stripped 那条既有判据', async () => {
    const asc = buildChain(3);
    strip(asc[2]);
    const report = await verifyAuditChain(makeAuditLog([...asc].reverse()), { maxRecords: 3 });

    expect(report.byType.hash_stripped).toBe(1);
    expect(report.byType.chain_break).toBe(0); // 其后没有记录了，不该凭空多一条
    expect(report.breaks).toBe(1);
  });
});
