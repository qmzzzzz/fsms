/**
 * P2-01：链校验查询的**投影**闸。
 *
 * 守的是什么：fetchChainWindow 不得把**完整**审计文档拖进内存——HARD_MAX_RECORDS
 * （20 万）条 × 含 requestHeaders/responseBody 等大字段的完整文档，是事件循环上的
 * 百 MB 级峰值。哈希/hmac/链接三层判据只消费「载荷白名单 ∪ 链字段」，所以查询必须
 * 带投影，且投影字段集必须**覆盖 v1~v6 全部载荷口径**：存量记录按各自 hashVersion
 * 复算，少一个字段就会把那个版本整体误判成 hash_mismatch（假篡改告警）。
 *
 * 两条腿：
 *   ① 投影形状：= 载荷白名单并集 + 链字段；**不含** createdAt/updatedAt/__v；
 *   ② 语义不变：只含投影字段的文档（模拟 lean() 投影后的返回形态）校验结论与
 *      完整文档完全一致——投影不得吃掉任何参与判据的字段。
 */
const mongoose = require('mongoose');
const {
  PAYLOAD_FIELDS_V1,
  PAYLOAD_FIELDS_V2,
  PAYLOAD_FIELDS_V3,
  PAYLOAD_FIELDS_V4,
  PAYLOAD_FIELDS_V5,
  PAYLOAD_FIELDS_V6,
  canonicalPayload,
  computeHash,
  computeHmac,
} = require('../../utils/auditChain');
const { verifyAuditChain, CHAIN_VERIFY_PROJECTION } = require('../../services/auditChainVerify');

describe('P2-01 链校验投影', () => {
  test('投影 = 载荷白名单并集 + 链字段，且不含非载荷元字段', () => {
    const whitelist = new Set([...PAYLOAD_FIELDS_V1, ...PAYLOAD_FIELDS_V6]);
    // v2~v5 是 v6 的子集（auditChainPayload 的增量定义），并集必须吞掉全部版本
    for (const field of [
      ...PAYLOAD_FIELDS_V2,
      ...PAYLOAD_FIELDS_V3,
      ...PAYLOAD_FIELDS_V4,
      ...PAYLOAD_FIELDS_V5,
    ]) {
      whitelist.add(field);
    }

    for (const field of whitelist) expect(CHAIN_VERIFY_PROJECTION[field]).toBe(1);
    for (const field of ['_id', 'hash', 'prevHash', 'hmac', 'hashVersion', 'hashFailure']) {
      expect(CHAIN_VERIFY_PROJECTION[field]).toBe(1);
    }
    // 非载荷元字段不得进投影：它们与三层判据无关，拖进来就是白占内存
    for (const field of ['createdAt', 'updatedAt', '__v']) {
      expect(CHAIN_VERIFY_PROJECTION[field]).toBeUndefined();
    }
    // 投影是闭集：白名单之外的任何键都不许混入（防"顺手多带一个字段"回潮）
    const allowed = new Set([
      ...whitelist,
      '_id',
      'hash',
      'prevHash',
      'hmac',
      'hashVersion',
      'hashFailure',
    ]);
    for (const field of Object.keys(CHAIN_VERIFY_PROJECTION)) {
      expect(allowed.has(field)).toBe(true);
    }
  });

  test('fetchChainWindow 把投影作为 find 第二参下发', async () => {
    const tail = {
      sort: jest.fn(() => tail),
      limit: jest.fn(() => tail),
      lean: jest.fn(() => Promise.resolve([])),
    };
    const model = { find: jest.fn(() => tail) };
    await verifyAuditChain(model, { maxRecords: 5 });
    expect(model.find).toHaveBeenCalledTimes(1);
    expect(model.find.mock.calls[0][1]).toBe(CHAIN_VERIFY_PROJECTION);
  });

  test('语义不变：只含投影字段的文档校验结论与完整文档一致（intact 链不因投影翻红）', async () => {
    // 构造一条 v6 合法链，再**模拟投影**：只保留投影白名单里的键。
    // 若投影漏了任何参与判据的字段，这里会立刻 hash_mismatch / chain_break。
    const build = (previous, overrides = {}) => {
      const doc = {
        _id: new mongoose.Types.ObjectId(),
        timestamp: new Date('2026-11-01T08:00:00.000Z'),
        action: 'user_create',
        category: 'user',
        userId: '64f000000000000000000001',
        username: 'alice',
        ip: '127.0.0.1',
        method: 'POST',
        path: '/api/users',
        params: {},
        query: {},
        body: { username: 'alice' },
        statusCode: 200,
        success: true,
        riskLevel: 'low',
        riskFactors: [],
        requestHeaders: { 'content-type': 'application/json' },
        responseHeaders: {},
        responseBody: '{"ok":true}',
        responseBodyTruncated: false,
        responseBodySkipped: false,
        hashVersion: 6,
        ...overrides,
      };
      doc.prevHash = previous ? previous.hash : null;
      doc.hash = computeHash(doc.prevHash, canonicalPayload(doc, doc.hashVersion));
      doc.hmac = computeHmac(doc.hash);
      return doc;
    };
    const first = build(null);
    const second = build(first);
    const projected = [first, second].map((doc) => {
      const slim = {};
      for (const field of Object.keys(CHAIN_VERIFY_PROJECTION)) {
        if (doc[field] !== undefined) slim[field] = doc[field];
      }
      return slim;
    });

    const tail = {
      sort: jest.fn(() => tail),
      limit: jest.fn(() => tail),
      lean: jest.fn(() => Promise.resolve(projected.slice().reverse())),
    };
    const report = await verifyAuditChain({ find: jest.fn(() => tail) }, { maxRecords: 10 });

    expect(report.total).toBe(2);
    expect(report.intact).toBe(true);
    expect(report.breaks).toBe(0);
    expect(report.chainTailHash).toBe(second.hash);
  });
});
