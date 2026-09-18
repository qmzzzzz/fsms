const mongoose = require('mongoose');
const {
  computeHash,
  computeHmac,
  canonicalPayload,
  canonicalPayloadV2LegacyBatch,
} = require('../../utils/auditChain');
const { verifyAuditChain } = require('../../services/auditChainVerify');
const { LINK_WINDOW_SIZE } = require('../../services/auditChainVerify');

function makeAuditLog(docs) {
  return {
    find: jest.fn().mockReturnValue({
      sort: jest.fn().mockReturnValue({
        limit: jest.fn().mockReturnValue({
          lean: jest.fn().mockResolvedValue(docs),
        }),
      }),
    }),
  };
}

function buildValidDoc(previous, overrides = {}) {
  const doc = {
    _id: new mongoose.Types.ObjectId(),
    timestamp: new Date('2026-09-04T08:00:00.000Z'),
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

describe('auditChainVerify', () => {
  test('完整 v3 链校验通过并返回链尾哈希', async () => {
    const first = buildValidDoc(null);
    const second = buildValidDoc(first);
    const third = buildValidDoc(second);
    const report = await verifyAuditChain(makeAuditLog([third, second, first]), {
      maxRecords: 3,
    });

    expect(report).toMatchObject({
      intact: true,
      total: 3,
      legacy: 0,
      breaks: 0,
      hmacChecked: true,
      scanned: { maxRecords: 3, fromLatest: true },
      chainTailHash: third.hash,
    });
    expect(report.byType).toEqual({
      hash_mismatch: 0,
      hmac_missing: 0,
      hmac_mismatch: 0,
      chain_break: 0,
      hash_stripped: 0,
    });
  });

  // 洗白路径回归：把**链尾**那条记录的内容改掉后再 $unset 掉 hash/prevHash/hmac，
  // 校验端原先只把它累加进 legacy（不影响 intact），且它后面没有记录来暴露断链
  // —— 于是"改写最近一条审计并抹掉哈希"得到 intact:true。
  test('链尾记录被抹掉哈希时计入 hash_stripped（不得退化为 legacy 后判完整）', async () => {
    const first = buildValidDoc(null);
    const second = buildValidDoc(first);
    const tail = buildValidDoc(second);
    tail.description = '篡改后的描述';
    delete tail.hash;
    delete tail.prevHash;
    delete tail.hmac;
    delete tail.hashVersion;

    const report = await verifyAuditChain(makeAuditLog([tail, second, first]));

    expect(report.intact).toBe(false);
    expect(report.legacy).toBe(0);
    expect(report.byType.hash_stripped).toBe(1);
    expect(report.samples[0]).toMatchObject({ type: 'hash_stripped', action: tail.action });
  });

  // 中间记录被抹哈希时两层同时报警：本条 hash_stripped + 其后一条因窗口被清空
  // 而 prevHash 无从命中 → chain_break。两层互补，这里把组合行为钉成契约。
  test('中间记录被抹掉哈希时 hash_stripped 与后继 chain_break 同时可见', async () => {
    const first = buildValidDoc(null);
    const middle = buildValidDoc(first);
    const last = buildValidDoc(middle); // 先按真实链序串好，再对中间条动手
    middle.body = { poisoned: true };
    delete middle.hash;
    delete middle.prevHash;
    delete middle.hmac;
    delete middle.hashVersion;

    const report = await verifyAuditChain(makeAuditLog([last, middle, first]));

    expect(report.intact).toBe(false);
    expect(report.byType.hash_stripped).toBe(1);
    expect(report.byType.chain_break).toBe(1);
  });

  test('内容被篡改时报告 hash_mismatch', async () => {
    const first = buildValidDoc(null);
    const second = buildValidDoc(first);
    second.body = { poisoned: true };
    const report = await verifyAuditChain(makeAuditLog([second, first]));

    expect(report.intact).toBe(false);
    expect(report.breaks).toBe(1);
    expect(report.byType.hash_mismatch).toBe(1);
    expect(report.samples[0]).toMatchObject({
      _id: String(second._id),
      index: 2,
      type: 'hash_mismatch',
      hashVersion: 3,
    });
  });

  test('prevHash 乱序时报告 chain_break', async () => {
    const first = buildValidDoc(null);
    const second = buildValidDoc(first);
    second.prevHash = 'd'.repeat(64);
    second.hash = computeHash(second.prevHash, canonicalPayload(second, second.hashVersion));
    second.hmac = computeHmac(second.hash);
    const report = await verifyAuditChain(makeAuditLog([second, first]));

    expect(report.intact).toBe(false);
    expect(report.breaks).toBe(1);
    expect(report.byType.chain_break).toBe(1);
    expect(report.samples[0]).toMatchObject({
      type: 'chain_break',
      actualPrevHash: 'd'.repeat(64),
    });
  });

  test('HMAC 缺失和失配都计入断裂', async () => {
    const missing = buildValidDoc(null);
    delete missing.hmac;
    const mismatch = buildValidDoc(missing);
    mismatch.hmac = '0'.repeat(64);
    const report = await verifyAuditChain(makeAuditLog([mismatch, missing]));

    expect(report.intact).toBe(false);
    expect(report.breaks).toBe(2);
    expect(report.byType.hmac_missing).toBe(1);
    expect(report.byType.hmac_mismatch).toBe(1);
  });

  test('legacy 无哈希记录不计入断裂，且清空链接窗口', async () => {
    const legacy = { _id: new mongoose.Types.ObjectId(), action: 'legacy' };
    const first = buildValidDoc(null);
    const second = buildValidDoc(first);
    const report = await verifyAuditChain(makeAuditLog([second, first, legacy]));

    expect(report).toMatchObject({
      intact: true,
      total: 3,
      legacy: 1,
      breaks: 0,
      chainTailHash: second.hash,
    });
  });

  test('v2 批量路径历史默认值漂移被单独容忍', async () => {
    const first = buildValidDoc(null);
    const second = buildValidDoc(first, {
      hashVersion: 2,
      riskLevel: 'low',
      riskFactors: [],
    });
    second.hash = computeHash(second.prevHash, canonicalPayloadV2LegacyBatch(second));
    second.hmac = computeHmac(second.hash);
    const report = await verifyAuditChain(makeAuditLog([second, first]));

    expect(report).toMatchObject({
      intact: true,
      total: 2,
      legacy: 0,
      breaks: 0,
      legacyV2BatchTolerated: 1,
    });
  });

  test('空链返回完整且链尾为空', async () => {
    const report = await verifyAuditChain(makeAuditLog([]));

    expect(report).toMatchObject({
      intact: true,
      total: 0,
      breaks: 0,
      chainTailHash: null,
    });
  });

  test('滑动窗口按序淘汰旧哈希', async () => {
    const docs = [];
    let previous = null;
    for (let index = 0; index < LINK_WINDOW_SIZE + 1; index += 1) {
      const doc = buildValidDoc(previous, {
        action: `action-${index}`,
        _id: mongoose.Types.ObjectId.createFromTime(1700000000 + index),
      });
      docs.push(doc);
      previous = doc;
    }

    const report = await verifyAuditChain(makeAuditLog([...docs].reverse()), {
      maxRecords: docs.length,
    });

    expect(report).toMatchObject({
      intact: true,
      total: docs.length,
      breaks: 0,
      chainTailHash: docs.at(-1).hash,
    });
  });
});
