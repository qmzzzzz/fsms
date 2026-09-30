const mongoose = require('mongoose');
const {
  computeHash,
  computeHmac,
  canonicalPayload,
  canonicalPayloadV2LegacyBatch,
} = require('../../utils/auditChain');
const { verifyAuditChain, computeChainVerdict } = require('../../services/auditChainVerify');
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
    // 这份字面量是 byType 的**独立抄本**（不是从被测模块推导）：新增一类断裂必须在这里
    // 显式登记，否则本条转红——F-184a 加 chain_fork 时正是被它挡了一下，登记而非删条目才是对的。
    expect(report.byType).toEqual({
      hash_mismatch: 0,
      hmac_missing: 0,
      hmac_mismatch: 0,
      chain_break: 0,
      chain_fork: 0,
      hash_stripped: 0,
      // 2026-09-30 登记：带 AuditLog.hashFailure 标记的无哈希记录（auditBuffer 算 hash
      // 抛错后落库）。它单列一类、**不计 breaks**，但与本清单里其余项并列——因为它同样
      // 是"链上有一段无法追认"的信号，只是成因不是篡改。登记而非删条目。
      hash_compute_failed: 0,
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

  // ---------------------------------------------------------------------
  // F-184a：分叉（一个父哈希挂两个孩子）
  //
  // 旧链接性判据是 `seen.has(doc.prevHash)` 的**成员测试**：它只能回答"父在不在窗口里"，
  // 而分叉的形态是"父在、而且已经被另一个孩子认领过了"⇒ 两条记录各自的 hash 都算得回来
  // （无 hash_mismatch）、prevHash 也都命中（无 chain_break）⇒ breaks=0、intact=true。
  // 也就是说：链一旦分叉成 DAG，"防篡改校验通过"这个结论本身就是假的。
  // 分叉不需要攻击者参与——共享链尾写入失败后各实例读到不同的尾、锁超时后的僵尸推进、
  // WAL 重放挑错链尾，都会产出同父两子（见 utils/auditChain 的 advanceChainTail）。
  // ---------------------------------------------------------------------
  test('同一个父哈希挂两条记录 ⇒ chain_fork，且不得同时报 chain_break（改前：intact 仍为真）', async () => {
    const first = buildValidDoc(null);
    const second = buildValidDoc(first);
    const twin = buildValidDoc(first, { action: 'logout' }); // 与 second 同父，自身哈希自洽

    // 喂 _id 降序（校验端 reverse 成升序推进）：twin 的 _id 最大 ⇒ 它是"第二个孩子"
    const report = await verifyAuditChain(makeAuditLog([twin, second, first]), { maxRecords: 3 });

    expect(report.intact).toBe(false);
    expect(report.breaks).toBe(1);
    expect(report.byType.chain_fork).toBe(1);
    // 反向对照：父就在窗口里，所以这**不是**"父找不到"。两类必须可区分，
    // 否则把它们合并成一类就等于把分叉降级成一次普通断链（丢失"有人另起一条链"这个信息）。
    expect(report.byType.chain_break).toBe(0);
    expect(report.samples[0]).toMatchObject({
      type: 'chain_fork',
      _id: String(twin._id),
      parentHash: first.hash,
      forkedWithId: String(second._id),
    });
  });

  test('第三个孩子同样计入分叉（不得只报"第二、第三之间"的那一次）', async () => {
    const first = buildValidDoc(null);
    const second = buildValidDoc(first);
    const twin = buildValidDoc(first, { action: 'logout' });
    const thirdChild = buildValidDoc(first, { action: 'delete' });

    const report = await verifyAuditChain(makeAuditLog([thirdChild, twin, second, first]), {
      maxRecords: 4,
    });

    // 两个孩子 ⇒ 两条分叉（都以 first.hash 为父、都以 second 为"已认领者"）
    expect(report.byType.chain_fork).toBe(2);
    expect(report.samples.map((s) => s._id)).toEqual([String(twin._id), String(thirdChild._id)]);
  });

  test('窗口被 legacy 重置后不再判分叉，而是回落到 chain_break（firstChildOf 必须与 seen 同生同灭）', async () => {
    const first = buildValidDoc(null);
    const second = buildValidDoc(first);
    const legacyRow = buildValidDoc(second);
    delete legacyRow.hash;
    delete legacyRow.prevHash;
    delete legacyRow.hmac;
    delete legacyRow.hashVersion;
    // 分叉的两个孩子都指向 first.hash——但 first.hash 已随窗口被清空
    const childA = buildValidDoc(first, { action: 'logout' });
    const childB = buildValidDoc(first, { action: 'delete' });

    const report = await verifyAuditChain(
      makeAuditLog([childB, childA, legacyRow, second, first]),
      { maxRecords: 5 }
    );

    // 陈旧条目若不清掉，childB 会被拿 childA 当"已认领者"报一次假分叉；
    // 这里要求的是链接性整体失联的那条路：两个孩子的父都不在窗口内 ⇒ 各自 chain_break。
    expect(report.byType.chain_fork).toBe(0);
    expect(report.byType.hash_stripped).toBe(1);
    expect(report.byType.chain_break).toBe(2);
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

  // ==================== 整表抹哈希：比"只抹链尾"更彻底，却曾在判据上更容易过 ====================
  //
  // 实测现场：把审计集合**整窗** $unset 掉 hash/prevHash/hmac（直连驱动/mongosh 可绕过
  // 模型中间件，正是本服务声明的威胁模型），报告层 legacy 把整窗全数吸收、breaks 恒为 0，
  // 于是判据给出 code=0「链完整」、核验审计记 riskLevel=low。
  // 与"只抹链尾"（既有契约，判 1 断裂）对照，构成**反向激励**：抹得越干净、结论越好。
  // 修法见 computeChainVerdict 的 nothingHashed 一段。
  const stripChain = (d) => {
    const c = { ...d };
    delete c.hash;
    delete c.prevHash;
    delete c.hmac;
    delete c.hashVersion;
    return c;
  };

  test('整表抹掉 hash/prevHash/hmac 时不得宣称链完整（全 legacy 窗口必须被否决）', async () => {
    const first = buildValidDoc(null);
    const second = buildValidDoc(first);
    const third = buildValidDoc(second);
    const report = await verifyAuditChain(makeAuditLog([third, second, first].map(stripChain)), {
      maxRecords: 3,
    });

    // 报告层如实回显"3 条全被 legacy 吸收、breaks 为 0"——这一层不负责判"是否被洗白"
    expect(report).toMatchObject({ total: 3, legacy: 3, breaks: 0 });

    // 判据层必须否决：一条都没经过哈希校验，不具备完整性背书
    const verdict = computeChainVerdict({
      breaks: report.breaks,
      total: report.total,
      maxRecords: 3,
      collectionTotal: 3,
      hmacChecked: report.hmacChecked,
      legacy: report.legacy,
      scanned: report.scanned,
    });
    expect(verdict.nothingHashed).toBe(true);
    expect(verdict.canAttestIntact).toBe(false);
    expect(verdict.code).toBe(2);
    expect(verdict.reasons.join('；')).toContain('全部无哈希');
  });

  test('对照：只抹链尾走断裂路径 code=1，与整表全抹的 code=2 必须可区分', async () => {
    const first = buildValidDoc(null);
    const second = buildValidDoc(first);
    const third = buildValidDoc(second);
    const report = await verifyAuditChain(makeAuditLog([stripChain(third), second, first]));
    const verdict = computeChainVerdict({
      breaks: report.breaks,
      total: report.total,
      maxRecords: 3,
      collectionTotal: 3,
      hmacChecked: report.hmacChecked,
      legacy: report.legacy,
      scanned: report.scanned,
    });

    expect(verdict.code).toBe(1);
    expect(verdict.nothingHashed).toBe(false);
  });

  test('allowAllLegacy 只豁免"整窗无哈希"，不得顶替 hmac 否决（豁免彼此独立）', () => {
    const base = {
      breaks: 0,
      total: 3,
      maxRecords: 3,
      collectionTotal: 3,
      legacy: 3,
      scanned: { maxRecords: 3, fromLatest: true, filter: {} },
      allowAllLegacy: true,
    };

    const waived = computeChainVerdict({ ...base, hmacChecked: true });
    expect(waived.nothingHashed).toBe(false);
    expect(waived.code).toBe(0);

    const stillVetoed = computeChainVerdict({ ...base, hmacChecked: false });
    expect(stillVetoed.hmacSkipped).toBe(true);
    expect(stillVetoed.code).toBe(2);
  });

  test('调用方漏传 legacy 时按"未知"处理：偏保守，不得产生假 PASS', () => {
    const verdict = computeChainVerdict({
      breaks: 0,
      total: 3,
      maxRecords: 3,
      collectionTotal: 3,
      hmacChecked: true,
      scanned: { maxRecords: 3, fromLatest: true, filter: {} },
    });

    expect(verdict.nothingHashed).toBe(true);
    expect(verdict.code).toBe(2);
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
