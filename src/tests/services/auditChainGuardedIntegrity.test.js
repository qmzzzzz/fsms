/**
 * 审计哈希链「被守护」的行为门禁（2026-09-30）
 *
 * 背景：此前链的"防篡改"只**可被查询**——核验只在手动调接口/跑脚本时发生，
 * 没有任何自动核验循环；批次无哈希只有 logger.warn，"可检测 ≠ 已告警"。
 * 本轮补三件事：① 周期核验定时器（services/auditChainMonitor）；
 * ② 批次哈希失败 → incSecurityAlert + 落库打标；③ 核验端区分打标与人为抹除。
 *
 * 本文件覆盖三层，缺一层这个修复就可能是"看起来修了"：
 *  A. 核验端归因：带 hashFailure 标记的无哈希记录 → hash_compute_failed（不计 breaks），
 *     不带标记的 → hash_stripped（计 breaks）。**两种形态数据上只差一个字段**，
 *     这正是最容易写反的地方（写反了就是"攻击者加个字段即可洗白篡改"）。
 *  B. 判据：缺口 > 0 时不得给 code 0（"链完整"），否则缺口被静默掩盖。
 *  C. 监控：发现断裂/缺口 → 告警；存量问题指纹不变 → 不重复告警（噪声治理）；
 *     code 0 不告警；单轮闸门生效。
 */

const mongoose = require('mongoose');
const { computeHash, computeHmac, canonicalPayload } = require('../../utils/auditChain');
const { verifyAuditChain, computeChainVerdict } = require('../../services/auditChainVerify');

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
    timestamp: new Date('2026-09-30T08:00:00.000Z'),
    action: 'login',
    category: 'auth',
    userId: '64f000000000000000000001',
    username: 'alice',
    ip: '127.0.0.1',
    path: '/api/auth/login',
    statusCode: 200,
    body: {},
    hashVersion: 4,
    ...overrides,
  };
  doc.prevHash = previous ? previous.hash : null;
  doc.hash = computeHash(doc.prevHash, canonicalPayload(doc, doc.hashVersion));
  doc.hmac = computeHmac(doc.hash);
  return doc;
}

/** 人为抹除（直连驱动/mongosh 的 $unset 形态）：整组哈希字段消失，**无** hashFailure */
function stripByAttacker(doc) {
  delete doc.hash;
  delete doc.prevHash;
  delete doc.hmac;
  return doc;
}

/** auditBuffer 算 hash 抛错后的落库形态：无 hash、prevHash/hashVersion 归 null、**带** hashFailure */
function stripByHashFailure(doc, reason = 'chain lock timeout') {
  doc.hash = null;
  doc.prevHash = null;
  doc.hashVersion = null;
  doc.hashFailure = reason;
  return doc;
}

describe('A. 核验端归因：hashFailure 标记 vs 人为抹除', () => {
  test('带 hashFailure 的无哈希记录 → hash_compute_failed，不计 breaks', async () => {
    const a = buildDoc(null, { action: 'a' });
    const b = buildDoc(a, { action: 'b' });
    const c = stripByHashFailure(buildDoc(b, { action: 'c' }), 'canonicalPayload 序列化失败');

    // 注意顺序：verifyAuditChain 内部会把 find 结果 reverse 成升序
    const report = await verifyAuditChain(makeAuditLog([c, b, a]));

    expect(report.byType.hash_compute_failed).toBe(1);
    // 关键：这条**不**进 breaks，也不是 hash_stripped
    expect(report.byType.hash_stripped).toBe(0);
    expect(report.hashComputeFailed).toBe(1);
    // 它后面的记录因父哈希失联必然 chain_break —— 这是真实结论，必须保留
    expect(report.byType.chain_break).toBe(0); // c 是最后一条，无后继
    expect(report.breaks).toBe(report.byType.hash_mismatch + report.byType.chain_break);
  });

  test('不带标记的无哈希记录 → 仍是 hash_stripped，计入 breaks（攻击形态不得被洗白）', async () => {
    const a = buildDoc(null, { action: 'a' });
    const b = buildDoc(a, { action: 'b' });
    const c = stripByAttacker(buildDoc(b, { action: 'c' }));

    const report = await verifyAuditChain(makeAuditLog([c, b, a]));

    expect(report.byType.hash_stripped).toBe(1);
    expect(report.byType.hash_compute_failed).toBe(0);
    expect(report.hashComputeFailed).toBe(0);
    expect(report.intact).toBe(false); // 断裂 ⇒ 不完整
  });

  test('两种形态的样本 type 可区分（不是靠计数反推）', async () => {
    const a = buildDoc(null, { action: 'a' });
    const b = buildDoc(a, { action: 'b' });
    const cFail = stripByHashFailure(buildDoc(b, { action: 'c' }), 'boom');

    const report = await verifyAuditChain(makeAuditLog([cFail, b, a]));
    const s = report.samples.find((x) => x.type === 'hash_compute_failed');
    expect(s).toBeTruthy();
    expect(s.reason).toBe('boom');
    expect(s.action).toBe('c');
  });

  test('打标记录的内容篡改仍被 hash_mismatch 抓住（标记无法洗白内容）', async () => {
    // 攻击者既改内容、又顺手写上 hashFailure：内容层面的保护不依赖这个字段
    const a = buildDoc(null, { action: 'a' });
    const tampered = buildDoc(a, { action: 'b' });
    tampered.username = 'attacker'; // 改内容 ⇒ hash 不再匹配
    tampered.hashFailure = 'fake reason'; // 试图把归因带偏

    const report = await verifyAuditChain(makeAuditLog([tampered, a]));
    expect(report.byType.hash_mismatch).toBe(1);
    expect(report.breaks).toBeGreaterThan(0);
  });
});

describe('B. 判据：有缺口不得宣称链完整', () => {
  const base = {
    breaks: 0,
    total: 100,
    maxRecords: 20000,
    collectionTotal: 100,
    hmacChecked: true,
    legacy: 0,
    scanned: { maxRecords: 20000, fromLatest: true, filter: {} },
  };

  test('hashComputeFailed > 0 ⇒ code 2（不是 0），理由里点名缺口', () => {
    const v = computeChainVerdict({ ...base, hashComputeFailed: 3 });
    expect(v.code).toBe(2);
    expect(v.canAttestIntact).toBe(false);
    expect(v.hasUnattestableGap).toBe(true);
    expect(v.reasons.join(' ')).toContain('哈希计算失败');
  });

  test('hashComputeFailed = 0 ⇒ 其余条件满足时仍给 code 0（不误伤干净链）', () => {
    const v = computeChainVerdict({ ...base, hashComputeFailed: 0 });
    expect(v.code).toBe(0);
    expect(v.canAttestIntact).toBe(true);
    expect(v.hasUnattestableGap).toBe(false);
  });

  test('缺口不改变 breaks 的优先级：真断裂仍报 code 1', () => {
    const v = computeChainVerdict({ ...base, breaks: 2, hashComputeFailed: 5 });
    expect(v.code).toBe(1);
  });

  test('调用方漏传 hashComputeFailed 按 0 处理（避免每次核验都判 INCOMPLETE）', () => {
    // 注意 base 里本来就没有 hashComputeFailed 键——这个用例证的就是"旧调用方
    // 完全不传该字段时"的行为，故这里显式删掉可能的同名键再传。
    const withoutField = { ...base };
    delete withoutField.hashComputeFailed;
    const v = computeChainVerdict(withoutField);
    expect(v.code).toBe(0);
  });
});

describe('C. auditChainMonitor：周期核验与噪声治理', () => {
  const metrics = require('../../utils/metrics');
  const securityAlert = require('../../services/securityAlert');
  const auditChainMonitor = require('../../services/auditChainMonitor');
  const AuditLogModel = require('../../models/AuditLog');

  // 真频控表是 securityAlert 的模块级状态，跨用例共用：若时间不推进，
  // 上一条用例消费的表项会把下一条的第一轮直接拦掉（假红）。
  // 每条用例起点各差一天 ⇒ 旧表项（TTL 5 分钟）必然已过期。
  // 口径照搬 tests/services/auditMonitorDailyAlertCap.test.js。
  let realNow;
  let dateSpy;
  let caseSeq = 0;
  const clock = { now: 0 };

  beforeAll(() => {
    realNow = Date.now();
    dateSpy = jest.spyOn(Date, 'now').mockImplementation(() => clock.now);
  });
  afterAll(() => {
    dateSpy.mockRestore();
  });

  afterEach(() => {
    auditChainMonitor.__resetForTest();
    // 只恢复 spyOn 到方法上的 mock，**不动 Date.now 的 spy**：
    // restoreAllMocks 会把上面的时钟 mock 一并还原，后续用例的时间就不再推进 ⇒ 假红
    jest.restoreAllMocks();
    dateSpy = jest.spyOn(Date, 'now').mockImplementation(() => clock.now);
  });

  /** 造一个「最近窗口里有一条 hash_stripped」的真实链路 */
  function brokenChainFixture() {
    const a = buildDoc(null, { action: 'a' });
    const b = buildDoc(a, { action: 'b' });
    const c = stripByAttacker(buildDoc(b, { action: 'c' }));
    return [c, b, a];
  }

  function healthyChainFixture() {
    const a = buildDoc(null, { action: 'a' });
    const b = buildDoc(a, { action: 'b' });
    return [b, a];
  }

  beforeEach(() => {
    caseSeq += 1;
    clock.now = realNow + caseSeq * 24 * 60 * 60 * 1000;
    jest.spyOn(AuditLogModel, 'estimatedDocumentCount').mockResolvedValue(3);
  });

  test('发现真实断裂 ⇒ 投递 critical 告警并计入指标', async () => {
    jest.spyOn(AuditLogModel, 'find').mockReturnValue({
      sort: jest.fn().mockReturnValue({
        limit: jest.fn().mockReturnValue({
          lean: jest.fn().mockResolvedValue(brokenChainFixture()),
        }),
      }),
    });
    const sendSpy = jest.spyOn(securityAlert, 'sendNotification').mockResolvedValue();
    const alertSpy = jest.spyOn(metrics, 'incSecurityAlert').mockImplementation(() => {});

    await auditChainMonitor.runVerification();

    expect(sendSpy).toHaveBeenCalledTimes(1);
    const [type, level] = sendSpy.mock.calls[0];
    expect(type).toBe(securityAlert.ALERT_TYPES.AUDIT_CHAIN_BREAK_DETECTED);
    expect(level).toBe('critical');
    // 投递成功后由 securityAlertDelivery 计数；本层只断言"确实投了"
    expect(alertSpy).not.toHaveBeenCalled(); // inc 由 delivery 层负责，本层不重复计
    expect(auditChainMonitor.getHealth().lastVerdictCode).not.toBe(0);
  });

  test('链干净（code 0）⇒ 一条告警都不发', async () => {
    jest.spyOn(AuditLogModel, 'find').mockReturnValue({
      sort: jest.fn().mockReturnValue({
        limit: jest.fn().mockReturnValue({
          lean: jest.fn().mockResolvedValue(healthyChainFixture()),
        }),
      }),
    });
    const sendSpy = jest.spyOn(securityAlert, 'sendNotification').mockResolvedValue();

    await auditChainMonitor.runVerification();

    expect(sendSpy).not.toHaveBeenCalled();
  });

  test('存量断裂指纹不变 ⇒ 第二轮不重复告警（噪声治理的核心）', async () => {
    jest.spyOn(AuditLogModel, 'find').mockReturnValue({
      sort: jest.fn().mockReturnValue({
        limit: jest.fn().mockReturnValue({
          lean: jest.fn().mockResolvedValue(brokenChainFixture()),
        }),
      }),
    });
    const sendSpy = jest.spyOn(securityAlert, 'sendNotification').mockResolvedValue();

    await auditChainMonitor.runVerification();
    await auditChainMonitor.runVerification();
    await auditChainMonitor.runVerification();

    // 三次核验同一批存量问题：只响一次
    expect(sendSpy).toHaveBeenCalledTimes(1);
  });

  test('缺口（hash_compute_failed）走 high 档、类型不同，与被篡改区分', async () => {
    const a = buildDoc(null, { action: 'a' });
    const b = stripByHashFailure(buildDoc(a, { action: 'b' }), 'transient');
    jest.spyOn(AuditLogModel, 'find').mockReturnValue({
      sort: jest.fn().mockReturnValue({
        limit: jest.fn().mockReturnValue({ lean: jest.fn().mockResolvedValue([b, a]) }),
      }),
    });
    const sendSpy = jest.spyOn(securityAlert, 'sendNotification').mockResolvedValue();

    await auditChainMonitor.runVerification();

    expect(sendSpy).toHaveBeenCalledTimes(1);
    expect(sendSpy.mock.calls[0][0]).toBe(securityAlert.ALERT_TYPES.AUDIT_HASH_COMPUTE_FAILED);
    expect(sendSpy.mock.calls[0][1]).toBe('high');
  });

  /** 造一个「hash_mismatch 而非 hash_stripped」的真实断裂（父链仍相连，只哈希算错） */
  function tamperedHashFixture() {
    const a = buildDoc(null, { action: 'a' });
    const b = buildDoc(a, { action: 'b' });
    const c = buildDoc(b, { action: 'c' });
    c.hash = computeHash('deadbeef', canonicalPayload(c, c.hashVersion));
    return [c, b, a];
  }

  test('断裂告警文案按类型指认：有 hash_stripped 才提链锁降级窗口，纯 hash_mismatch 不提', async () => {
    // 正例：人为抹哈希（stripByAttacker ⇒ 无 hashFailure 标记）
    jest.spyOn(AuditLogModel, 'find').mockReturnValue({
      sort: jest.fn().mockReturnValue({
        limit: jest
          .fn()
          .mockReturnValue({ lean: jest.fn().mockResolvedValue(brokenChainFixture()) }),
      }),
    });
    const sendSpy = jest.spyOn(securityAlert, 'sendNotification').mockResolvedValue();

    await auditChainMonitor.runVerification();

    expect(sendSpy).toHaveBeenCalledTimes(1);
    const strippedMsg = sendSpy.mock.calls[0][2];
    // 计数形态仍在（否则运维看不到规模）
    expect(strippedMsg).toContain('hash_stripped=1');
    // #19 选项②：同形不同因，必须点名，否则读者按字面读成"已确认有人抹哈希"
    expect(strippedMsg).toContain('链锁降级窗口');
    // 指认必须落到可检索的日志词上，不是一句"去查日志"
    expect(strippedMsg).toContain('AUDIT_CHAIN_LOCK_TIMEOUT_MS 非法');
  });

  test('断裂告警文案：纯 hash_mismatch 不得被追加链锁降级指认（指认不是万能膏药）', async () => {
    jest.spyOn(AuditLogModel, 'find').mockReturnValue({
      sort: jest.fn().mockReturnValue({
        limit: jest
          .fn()
          .mockReturnValue({ lean: jest.fn().mockResolvedValue(tamperedHashFixture()) }),
      }),
    });
    const sendSpy = jest.spyOn(securityAlert, 'sendNotification').mockResolvedValue();

    await auditChainMonitor.runVerification();

    expect(sendSpy).toHaveBeenCalledTimes(1);
    const mismatchMsg = sendSpy.mock.calls[0][2];
    expect(mismatchMsg).toContain('hash_mismatch=1');
    expect(mismatchMsg).not.toContain('链锁降级窗口');
  });

  test('单轮闸门：上一轮未结束时本轮跳过并计数', async () => {
    let resolveFind;
    const pending = new Promise((r) => {
      resolveFind = r;
    });
    jest.spyOn(AuditLogModel, 'find').mockReturnValue({
      sort: jest.fn().mockReturnValue({
        limit: jest.fn().mockReturnValue({ lean: jest.fn().mockReturnValue(pending) }),
      }),
    });
    jest.spyOn(securityAlert, 'sendNotification').mockResolvedValue();

    const first = auditChainMonitor.runVerification();
    const second = auditChainMonitor.runVerification(); // 应被闸门挡下
    expect(auditChainMonitor.getHealth().skippedOverlaps).toBe(1);

    resolveFind(healthyChainFixture());
    await first;
    await second;
    expect(auditChainMonitor.getHealth().runs).toBe(1); // 被跳过的那轮不计
  });

  test('扫描抛错 ⇒ 记失败并释放闸门（不永久停摆）', async () => {
    jest.spyOn(AuditLogModel, 'find').mockImplementation(() => {
      throw new Error('db down');
    });

    await auditChainMonitor.runVerification();

    const h = auditChainMonitor.getHealth();
    expect(h.failures).toBe(1);
    expect(h.consecutiveFailures).toBe(1);
    expect(h.lastFailureMessage).toContain('db down');
    // 闸门必须已释放
    jest.spyOn(AuditLogModel, 'find').mockReturnValue({
      sort: jest.fn().mockReturnValue({
        limit: jest.fn().mockReturnValue({ lean: jest.fn().mockResolvedValue([]) }),
      }),
    });
    await auditChainMonitor.runVerification();
    expect(auditChainMonitor.getHealth().consecutiveFailures).toBe(0);
  });
});

describe('D. 告警类型登记（防新类型被静默丢弃）', () => {
  const { ALERT_TYPES } = require('../../services/securityAlert');

  test('审计链三个类型已登记且取值稳定', () => {
    expect(ALERT_TYPES.AUDIT_HASH_COMPUTE_FAILED).toBe('audit_hash_compute_failed');
    expect(ALERT_TYPES.AUDIT_CHAIN_BREAK_DETECTED).toBe('audit_chain_break_detected');
    expect(ALERT_TYPES.LEGACY_CBC_DECRYPT_ENABLED).toBe('legacy_cbc_decrypt_enabled');
  });
});

describe('E. CBC 开关升级为安全告警（validate.reportProductionWarnings）', () => {
  const metrics = require('../../utils/metrics');
  const { collectProductionWarnings } = require('../../config/validate');

  const originalCbc = process.env.ALLOW_LEGACY_CBC_DECRYPT;
  afterEach(() => {
    if (originalCbc === undefined) delete process.env.ALLOW_LEGACY_CBC_DECRYPT;
    else process.env.ALLOW_LEGACY_CBC_DECRYPT = originalCbc;
    jest.restoreAllMocks();
  });

  test('开关为 true ⇒ 告警文案 + incSecurityAlert 双留痕', () => {
    process.env.ALLOW_LEGACY_CBC_DECRYPT = 'true';
    const alertSpy = jest.spyOn(metrics, 'incSecurityAlert').mockImplementation(() => {});

    const warnings = collectProductionWarnings();

    expect(warnings.some((x) => x.includes('ALLOW_LEGACY_CBC_DECRYPT'))).toBe(true);
    expect(alertSpy).toHaveBeenCalledWith('legacy_cbc_decrypt_enabled', 'high');
  });

  test('开关未设 ⇒ 不触发该告警（不误报）', () => {
    delete process.env.ALLOW_LEGACY_CBC_DECRYPT;
    const alertSpy = jest.spyOn(metrics, 'incSecurityAlert').mockImplementation(() => {});

    collectProductionWarnings();

    const calls = alertSpy.mock.calls.filter((c) => c[0] === 'legacy_cbc_decrypt_enabled');
    expect(calls).toHaveLength(0);
  });
});
