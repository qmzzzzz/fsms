/**
 * 无哈希的存量审计行也不得被 save() 改写并"补签进活链"
 *
 * `auditLogHooks.js` 的 append-only 护栏原先写成
 *     if (!this.isNew && this.hash && appendOnlyEnforced) throw ...
 * 也就是**把护栏挂在恰好会被失效形态抹掉的那个字段上**。而"无哈希的已入库行"不是
 * 假设，是本项目自己钉为期望的正常产物：`chainBatch` 抛错时记录仍会落库
 * （见 tests/observability/auditBufferFlushAndWalGuards.test.js 的既有期望）。
 *
 * 这类行原先有两重后果，第二重才是真正严重的：
 *   ① 绕开 append-only 护栏，可以被任意改写；
 *   ② 改写后走 `pre('save')` 的"缺哈希就补算"分支 → 重新计算 hash 并
 *      `advanceChainTail` **接到活链尾部**。于是篡改对链校验完全不可见
 *      （链验证重算出的哈希与改后的载荷自洽），"防篡改"在这条路径上归零。
 *
 * 修法：护栏判据只看「是不是新记录」。下面三条用例分别钉：
 *   拒绝改写 + 不得被补签（核心）、正常新建路径照常入链（反向保护）、
 *   以及"护栏关掉就放行"（证明这条断言真的在护栏管辖之内，而不是别的原因让它红）。
 */
const mongoose = require('mongoose');

const ACTION_TAMPER = 'h1_tamper';
const ACTION_OK = 'h1_ok';
// 链上"前驱"专用：不与上面两个 action 重叠，避免把 verifyAuditChain 的过滤集撑大
const ACTION_ANCHOR = 'h1_anchor';

const baseEntry = (action) => ({
  action,
  category: 'security',
  username: 'auditor',
  method: 'GET',
  path: '/api/probe-append-only',
  ip: '203.0.113.1',
  success: true,
});

describe('append-only 护栏不得依赖 hash 字段本身', () => {
  let AuditLog;

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    AuditLog = require('../models/AuditLog');
  });

  afterAll(async () => {
    await AuditLog.deleteMany(
      { action: { $in: [ACTION_TAMPER, ACTION_OK, ACTION_ANCHOR] } },
      { bypassAppendOnly: true }
    ).catch(() => {});
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });

  test('无哈希存量行：save() 必须被拒绝，且不得被补签到链上', async () => {
    const doc = await AuditLog.create(baseEntry(ACTION_TAMPER));
    // 前提自证：正常创建会入链（否则下面的"抹哈希"造不出目标形态）
    expect(doc.hash).toBeTruthy();

    await AuditLog.updateOne(
      { _id: doc._id },
      { $set: { hash: null, prevHash: null, hmac: null } },
      { bypassAppendOnly: true }
    );

    const fetched = await AuditLog.findById(doc._id);
    expect(fetched.isNew).toBe(false);
    expect(fetched.hash).toBeNull();

    fetched.username = 'erased';
    fetched.body = { tampered: true };

    await expect(fetched.save()).rejects.toThrow(/append-only/);

    const stored = await AuditLog.findById(doc._id);
    // 关键断言：改写没进去，而且**没有被重新签名接到链尾**
    expect(stored.username).toBe('auditor');
    expect(stored.hash).toBeNull();
    expect(stored.prevHash).toBeNull();
  });

  test('反向保护：新建记录照常算链（护栏收紧不得把正常写入掐死）', async () => {
    // 前提自行铺设：prevHash 取自链尾游标，空库里第一条没有前驱、必然为 null。
    // 早先版本是"蹭"上一条用例留下的那一行当隐式链尾 —— --randomize 把本用例排到
    // 前面时就红在 prevHash（F-112 同一类：用例之间通过库传递状态）。
    await AuditLog.create(baseEntry(ACTION_ANCHOR));

    const created = await AuditLog.create(baseEntry(ACTION_OK));
    expect(created.hash).toBeTruthy();
    expect(created.prevHash).toBeTruthy();
    expect(created.hashVersion).toBeTruthy();

    const { verifyAuditChain } = require('../services/auditChainVerify');
    const report = await verifyAuditChain(AuditLog, {
      filter: { action: ACTION_OK },
      maxRecords: 10,
    });
    expect(report.breaks).toBe(0);
  });

  test('护栏开关关掉后同一操作会放行（证明上一条的红确实来自护栏）', async () => {
    expect(typeof AuditLog._setAppendOnlyEnforced).toBe('function');
    const doc = await AuditLog.create(baseEntry(ACTION_TAMPER));
    await AuditLog.updateOne(
      { _id: doc._id },
      { $set: { hash: null, prevHash: null, hmac: null } },
      { bypassAppendOnly: true }
    );

    const fetched = await AuditLog.findById(doc._id);
    fetched.username = 'off_switch';

    AuditLog._setAppendOnlyEnforced(false);
    try {
      await fetched.save();
    } finally {
      AuditLog._setAppendOnlyEnforced(true);
    }

    // 关掉护栏就能改写 → 上一条的拒绝确实来自 appendOnlyEnforced 这道闸
    const stored = await AuditLog.findById(doc._id);
    expect(stored.username).toBe('off_switch');
    await AuditLog.deleteMany({ _id: doc._id }, { bypassAppendOnly: true });
  });
});
