'use strict';

/**
 * 合规出口报告的护栏状态必须是**真值**（securityController 的 compliance 块读它）
 *
 * 缺陷（台账 §4.2：合规端点把 `appendOnlyEnforced` 写成常量 true）：
 * 防篡改护栏的真实开关是 `models/auditLogHooks.js` 里的闭包变量，外部原先读不到，
 * 于是对外指标永远显示"在防"。修法是给模型加一个只读 getter，让控制器读实际值。
 *
 * 但"控制器读了 getter"这一半在 `securityControllerOutcomeAndGuards.test.js` 里只能
 * 拿**桩**验（那套件的 AuditLog 整个被 mock 掉）。本文件补齐另一半，且刻意不 mock 任何东西：
 *   ① getter 默认报 true，且此时改写的确被护栏拒绝；
 *   ② 关掉开关后 getter 报 false，**同一次改写就真的放行**
 *      ⇒ 证明 getter 与钩子读的是同一个变量（否则"报告实际值"只是换个地方写死）；
 *   ③ 必须复原，否则会把 false 漏给同一 worker 里的其它用例。
 *
 * 变异判据：把 getter 改成 `() => true`（回到常量语义）⇒ 本文件第 ② 条必红。
 */

const mongoose = require('mongoose');

const ACTION = 'zzcompliance_guard_state';

describe('AuditLog.isAppendOnlyEnforced 与 append-only 钩子同源（不 mock）', () => {
  let AuditLog;

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    AuditLog = require('../../models/AuditLog');
  });

  afterAll(async () => {
    await AuditLog.deleteMany({ action: ACTION }, { bypassAppendOnly: true }).catch(() => {});
  });

  const baseEntry = () => ({
    action: ACTION,
    category: 'security',
    username: 'zzcompliance_auditor',
    method: 'PUT',
    path: '/api/zzcompliance-guard-state',
    ip: '203.0.113.9',
    success: true,
  });

  test('① 默认在防：getter 报 true，且改写确实被护栏拒绝', async () => {
    expect(typeof AuditLog.isAppendOnlyEnforced).toBe('function');
    expect(AuditLog.isAppendOnlyEnforced()).toBe(true);

    const doc = await AuditLog.create(baseEntry());
    const fetched = await AuditLog.findById(doc._id);
    fetched.username = 'zzcompliance_tampered';
    await expect(fetched.save()).rejects.toThrow(/append-only/);

    const stored = await AuditLog.findById(doc._id);
    expect(stored.username).toBe('zzcompliance_auditor'); // 真的没写进去
  });

  test('②③ 开关一关：getter 与钩子同时改变行为（证明读的是同一个变量），复原后回到在防', async () => {
    expect(typeof AuditLog._setAppendOnlyEnforced).toBe('function'); // 仅测试环境导出
    const doc = await AuditLog.create(baseEntry());
    const fetched = await AuditLog.findById(doc._id);
    fetched.username = 'zzcompliance_off_switch';

    AuditLog._setAppendOnlyEnforced(false);
    try {
      expect(AuditLog.isAppendOnlyEnforced()).toBe(false);
      await fetched.save(); // 关护栏 ⇒ 放行：与上一条的 rejects 构成同一判据的两面
    } finally {
      AuditLog._setAppendOnlyEnforced(true);
    }

    expect(AuditLog.isAppendOnlyEnforced()).toBe(true); // 不泄漏给后续用例
    const stored = await AuditLog.findById(doc._id);
    expect(stored.username).toBe('zzcompliance_off_switch');

    await AuditLog.deleteMany({ _id: doc._id }, { bypassAppendOnly: true });
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
