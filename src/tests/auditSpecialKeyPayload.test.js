/**
 * 审计载荷里的特殊键（$ 前缀 / 点号）：记录必须存在、链必须自洽
 *
 * `PAYLOAD_FIELDS_V4` 把 `query` / `params` / `body` 三个**完全外控**的对象纳入哈希。
 * 这三个槽是"攻击者可控形状直连存储层"的唯一入口，而 JS 侧已有专门一档守住
 * `__proto__`（`auditBodyProtoFidelity`）。本文件守的是另外两档——
 * 它们不是 JS 语义问题，而是 **BSON/服务端**对键名的语义：
 *   · `$` 前缀：查询语言的操作符前缀，历史上被写入侧禁止；
 *   · 点号：子文档路径分隔符，存进去之后**按路径查询会歧义**。
 * 两者都能由一个裸 GET 造出来：`?$gt=1` 就让 `req.query` 带上 `$gt` 键，
 * 而 `query` 与 `body` 走同一个 Mixed 落库路径。
 *
 * 为什么这一档值得单独钉：`AuditLog.record` 落库失败时是**吞掉**的
 * （`auditLogWriteStatics.js:63-77`：记 error 日志 + 计入
 * `security_alerts_total{type=audit_write_failed}` 后 `resolve(null)`，
 * 调用方契约不变）。所以"某种键名让整条审计记录写不进去"这件事
 * 在请求侧完全不可见——一个未授权的人若能用固定载荷把自己每次都打成"无留存"，
 * 那已经不是记不记的问题，而是审计可以按载荷形状被关闭。
 *
 * 三格：
 *   ① `$` 前缀键（含 GET query 形态）：记录必须真的存在，且按自带哈希重算不得报断裂；
 *   ② 点号键：同上；
 *   ③ 存储层事实：把 cast 之后**实际留下哪些键**记进断言，使 ①② 的"链自洽"
 *      不是因为"整个字段被丢掉"而得到的空对空相等。
 *
 * ①②③ 全是"必须为 0 断裂"的正向断言，一句坏掉的"永远返回 0"也能让它们全绿。
 * 所以再加一格反向对照：把同一条记录的事后载荷改掉后**必须**报出断裂，
 * 否则前面三条的绿不构成证据。
 *
 * 作用域边界（避免误读成本文件守不到的东西）：走的是 `AuditLog.record` 直写路径，
 * 即模型 cast + 驱动序列化 + 链哈希这一段；键脱敏（`sanitizeAuditBody` /
 * `sanitizeAuditQuery`）在 `recordSensitiveAction` 与安全中间件那一层，
 * 由 `auditLogSanitizer` 的既有用例守，本文件不重复覆盖。
 */
const mongoose = require('mongoose');

const stamp = `zzbsk${Date.now().toString(36)}`.replace(/[^a-z0-9_]/g, '');
const CAT = 'security';

describe('审计载荷的 $ 前缀与点号键：存在性与链自洽', () => {
  let AuditLog;
  let verifyAuditChain;
  const actions = [];

  /** 每个用例一个独立 action，核验只在自己的子集里跑，不依赖执行顺序 */
  const mkAction = (tag) => {
    const action = `${stamp}_${tag}`;
    actions.push(action);
    return action;
  };

  const recordSpecial = async (tag, payload) => {
    const action = mkAction(tag);
    const doc = await AuditLog.record({
      action,
      category: CAT,
      username: `${stamp}_u`,
      method: 'POST',
      path: '/api/zz-special-key',
      ip: '203.0.113.9',
      success: true,
      ...payload,
    });
    return { action, doc };
  };

  /** 只在指定 action 子集内核验：全局链由别的套件并发写入，窄过滤才不受干扰 */
  const breaksFor = async (action) => {
    const report = await verifyAuditChain(AuditLog, { filter: { action }, maxRecords: 10 });
    return report.breaks;
  };

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    AuditLog = require('../models/AuditLog');
    verifyAuditChain = require('../services/auditChainVerify').verifyAuditChain;
  });

  afterAll(async () => {
    if (actions.length) {
      await AuditLog.deleteMany({ action: { $in: actions } }).catch(() => {});
    }
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });

  test('$ 前缀键的 body：记录必须落库，链不得报断裂', async () => {
    const body = JSON.parse(`{"$gt":"${stamp}","$ne":1,"normal":"kept"}`);
    const { action, doc } = await recordSpecial('dollar_body', { body });
    // record() 失败时 resolve(null)——这里必须是文档，否则该形状"每次都无留存"
    expect(doc && doc._id).toBeTruthy();
    expect(await breaksFor(action)).toBe(0);
  });

  test('$ 前缀键的 query（裸 GET 即可造出的形态）：同样必须落库且链自洽', async () => {
    const query = JSON.parse(`{"$gt":"1","$where":"${stamp}"}`);
    const { action, doc } = await recordSpecial('dollar_query', { query });
    expect(doc && doc._id).toBeTruthy();
    expect(await breaksFor(action)).toBe(0);
  });

  test('点号键：同样必须落库且链自洽', async () => {
    const body = JSON.parse(`{"a.b":"${stamp}","c.d.e":{"$eq":1}}`);
    const { action, doc } = await recordSpecial('dotted_body', { body });
    expect(doc && doc._id).toBeTruthy();
    const raw = await AuditLog.collection.findOne({ _id: doc._id });
    // 点号键必须仍是**顶层字面量键**（既不丢、也不被摊成嵌套子文档）：
    // 取证侧按 "body.a.b" 这种路径去查是另一种语义，见下面 byPath 的实测。
    expect(Object.keys(raw.body).sort()).toEqual(['a.b', 'c.d.e']);
    expect(raw.body['a.b']).toBe(stamp);
    const byPath = await AuditLog.collection.countDocuments({
      _id: doc._id,
      'body.a.b': stamp,
    });
    // 实测（本会话内存 MongoDB + driver 7.5.0）：**0**——字面量点号键不是子文档路径，
    // 任何按 `body.a.b` 写的查询/过滤都取不到这条已落库的数据。
    // 钉住这个方向而不是"能查到"：取证与读接口都是按路径写的，
    // 若哪天驱动改成能查到，本条会转红——那时要连带复核读侧的点号过滤口径，别只改断言。
    expect(byPath).toBe(0);
    expect(await breaksFor(action)).toBe(0);
  });

  test('存储层事实：cast 之后到底留下哪些键（把事实钉住，不让"链自洽"空对空）', async () => {
    const { action, doc } = await recordSpecial('dollar_mixed', {
      body: JSON.parse(`{"$gt":"${stamp}","a.b":"x","plain":"y"}`),
      params: JSON.parse(`{"$lt":"z"}`),
    });
    expect(doc && doc._id).toBeTruthy();
    const raw = await AuditLog.collection.findOne({ _id: doc._id });
    const bodyKeys = Object.keys(raw.body || {}).sort();
    const paramKeys = Object.keys(raw.params || {}).sort();
    // 三条都必须保住：这条链存在的理由是"事后能还原请求形状"，
    // 键被存储层吞掉就等于该攻击探针在取证库里从未发生过。
    expect(bodyKeys).toEqual(['$gt', 'a.b', 'plain']);
    expect(paramKeys).toEqual(['$lt']);
    // 复核：整份 body 不是被连根丢掉后"自然"没有断裂的
    expect(raw.body.plain).toBe('y');
    expect(await breaksFor(action)).toBe(0);
  });

  test('反向对照：事后改掉同一条记录的载荷必须报断裂（前面三格的 0 不是空转）', async () => {
    const { action, doc } = await recordSpecial('tamper_control', {
      body: JSON.parse(`{"$gt":"${stamp}","plain":"y"}`),
    });
    expect(doc && doc._id).toBeTruthy();
    const signed = await AuditLog.collection.findOne({ _id: doc._id });
    const original = signed.body;

    // 改掉受哈希保护的字段但保留原 hash：这正是"直连驱动改写、绕过模型中间件"的形态。
    await AuditLog.collection.updateOne({ _id: doc._id }, { $set: { 'body.plain': 'tampered' } });
    const report = await verifyAuditChain(AuditLog, { filter: { action }, maxRecords: 10 });
    expect(report.breaks).toBeGreaterThan(0);
    expect(report.byType.hash_mismatch).toBeGreaterThan(0);
    // 篡改者没有重签（重签需要 HMAC 密钥）：存的仍是原 hash，
    // 后继记录的 prevHash 仍指向它——所以这里必须"内容不符但指纹未变"。
    const after = await AuditLog.collection.findOne({ _id: doc._id });
    expect(after.hash).toBe(signed.hash);

    // 复位后必须重新自洽：一是还给全局校验一个干净的同一条记录（本库按 worker 共享，
    // 留一条断裂会替别人造出假断裂），二是反向证明这条判据是内容敏感的，
    // 不是"跑过一次就一直是红"。
    await AuditLog.collection.updateOne({ _id: doc._id }, { $set: { body: original } });
    expect(await breaksFor(action)).toBe(0);
  });
});
