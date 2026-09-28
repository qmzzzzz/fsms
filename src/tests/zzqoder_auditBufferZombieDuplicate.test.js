/**
 * 审计链锁超时后的「僵尸 insertMany」不得造成重复审计记录
 *
 *
 * 机理（逐行核实，两处证据）：
 *   utils/auditChain.js:197  `return await Promise.race([fn(gen), timeout])`
 *   —— Promise.race 在超时时只是**不等** fn，并不会取消它。
 *   services/auditBuffer.js  `finally { flushing = false }` 与 `unshiftChunked(retryDocs)`
 *   —— 超时错误来自锁而不是 insertMany，所以 err.__retryDocs 不存在 ⇒ **整批放回缓冲**。
 *
 * 于是时序是：
 *   t=0     flush#1 取走 3 条，insertMany 开始（Mongo 慢）
 *   t=150   链锁持有超时 → flush#1 外层 catch → 3 条放回缓冲，flushing=false
 *   t=600   那个"僵尸" insertMany 真正成功，3 条落库
 *   t=2000  定时器 flush#2 又把这 3 条插一遍 ⇒ 库里 6 条
 * 重复行各自重新串链（chainBatch 现算 hash），两份都自洽，
 * `verifyAuditChain` 看不出任何断裂——**篡改检测完好，但"每条请求只记一次"这个
 * 审计基本性质被破坏了**，而且 droppedCount/告警都不会响。
 *
 * 修复判据：flush 取走批次后预分配 `_id`（与原先 Mongoose 的分配时机一致），
 * 回退重试是同一批对象引用 ⇒ `_id` 存活 ⇒ 再插必撞 11000 ⇒ 识别为「已落库」；
 * 并且**知道真相的那一刻**（僵尸 fn 内）把缓冲里被超时回退重新排入的那几条撤掉，
 * 否则批次会在"每轮都超时"里永不收敛，最后被毒文档逻辑丢弃并虚增 droppedCount。
 * `_id` 不参与哈希 payload（utils/auditChainPayload.js 字段白名单实测无 _id），
 * 预分配不改变链；链锁超时已把内存链尾标记失效，重同步由 getChainTail 兜底。
 *
 * 判据用「同一批唯一 marker 的最终行数」，不依赖墙钟精度：
 * 异步落库/撤回一律 waitFor 轮询，避免共机负载造成的假红（也避免假绿）。
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const mongoose = require('mongoose');

// 必须在 require 之前设：链锁超时与 WAL 路径都在模块加载期读 env
const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'zzqoder-zombie-'));
process.env.AUDIT_WAL_PATH = path.join(tmpDir, 'zombie.wal');
process.env.AUDIT_CHAIN_LOCK_TIMEOUT_MS = '150';

const auditBuffer = require('../services/auditBuffer');
const wal = require('../services/auditBufferWal');
const AuditLog = require('../models/AuditLog');

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** 轮询等待条件成立（上限 8s），替代固定等待 */
async function waitFor(cond, timeoutMs = 8000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await cond()) return true;
    await sleep(25);
  }
  return false;
}

const countTag = async (tag) =>
  AuditLog.countDocuments({ username: new RegExp(`^zzombie_${tag}_`) });

describe('链锁超时与僵尸写入的重复落库', () => {
  let realInsertMany;

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    // 只手动 flush，排除定时器抖动
    auditBuffer.stop();
    // 把 WAL 路径 pin 到本套件的 mkdtemp：getWalPath() 在 startup() 之前返回的是
    // 模块加载期按库名派生的**默认路径**（logs/audit-buffer.<db>.wal），直接往那儿
    // 写等于污染仓库；start()→wal.startup() 才切到 AUDIT_WAL_PATH。
    auditBuffer.start();
    auditBuffer.stop();
    realInsertMany = AuditLog.insertMany.bind(AuditLog);
  });

  beforeEach(async () => {
    auditBuffer.__resetForTest();
    AuditLog.insertMany = realInsertMany;
    // 顺序无关：清掉本套件前序用例的行，否则计数断言会被残留污染。
    // bypassAppendOnly 只在 NODE_ENV=test 生效（auditLogHooks.js 的守卫），
    // 不带它会被 append-only 钩子直接拒掉——首次实跑就是在这里报的错。
    await cleanup();
    try {
      fs.writeFileSync(auditBuffer.getWalPath(), '');
    } catch (_) {
      /* 文件尚不存在 */
    }
  });

  afterAll(async () => {
    AuditLog.insertMany = realInsertMany;
    auditBuffer.stop();
    await cleanup();
    auditBuffer.__resetForTest();
    try {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    } catch (_) {
      /* 尽力清理 */
    }
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });

  async function cleanup() {
    try {
      await AuditLog.deleteMany({ username: /^zzombie_/ }, { bypassAppendOnly: true });
    } catch (_) {
      /* 库未连接时忽略 */
    }
  }

  const makeDocs = (tag, n) =>
    Array.from({ length: n }, (_, i) => ({
      action: 'device_export',
      category: 'system',
      username: `zzombie_${tag}_${i}`,
      ip: '10.9.9.9',
      method: 'GET',
      path: '/api/devices/export',
      success: true,
      riskLevel: 'low',
    }));

  /** 慢 insertMany：远大于 AUDIT_CHAIN_LOCK_TIMEOUT_MS=150，制造僵尸 */
  function slowInsertMany(delayMs) {
    const box = { calls: 0 };
    AuditLog.insertMany = async (docs, opts) => {
      box.calls += 1;
      await sleep(delayMs);
      return realInsertMany(docs, opts);
    };
    return box;
  }

  test('前提自证：category 取值合法（否则"零行"是校验失败而不是超时）', async () => {
    const docs = makeDocs('precheck', 1);
    const inserted = await realInsertMany(docs, { ordered: false });
    expect(inserted.length).toBe(1);
    await cleanup();
  });

  test('前提自证：_id 冲突的错误结构——已落库判据只能读 w.err.code + docs[w.index]', async () => {
    // collectDurableIds() 整条判据建立在这个结构上。驱动升级后若形状变了，本用例
    // 必须红：否则幂等识别会**静默失效**、退回"重复插入审计"，那种失效没人看得见。
    const docs = makeDocs('shape', 2);
    for (const d of docs) d._id = new mongoose.Types.ObjectId();
    await realInsertMany(docs, { ordered: false });

    let err = null;
    try {
      await realInsertMany(docs, { ordered: false });
    } catch (e) {
      err = e;
    }
    expect(err).not.toBeNull();
    expect(err.code).toBe(11000);
    expect(err.insertedDocs).toHaveLength(0); // 全批冲突 ⇒ 本次改动没有新插入
    expect(err.writeErrors).toHaveLength(2);
    // 实测形状：条目只有 { index, err }，服务端 code/op 嵌在 err 下。
    // 首版实现按 w.code 判 11000 取到空集，幂等识别静默失效（本文件把它钉成断言）。
    expect(err.writeErrors.map((w) => w.code)).toEqual([undefined, undefined]);
    expect(err.writeErrors.map((w) => w.err.code)).toEqual([11000, 11000]);
    expect(err.writeErrors.map((w) => w.index)).toEqual([0, 1]);
    expect(String(err.writeErrors[0].err.op._id)).toBe(String(docs[0]._id));
    await cleanup();
  });

  test('对照：插入很快时不超时、不重复（证明下面的红是超时造成的，而不是测试本身在造重复）', async () => {
    let calls = 0;
    AuditLog.insertMany = async (docs, opts) => {
      calls += 1;
      return realInsertMany(docs, opts);
    };
    for (const d of makeDocs('fast', 2)) auditBuffer.push(d);

    await auditBuffer.flush();
    expect(await waitFor(async () => (await countTag('fast')) === 2)).toBe(true);

    await auditBuffer.flush();
    expect(calls).toBe(1); // 缓冲已空，第二次 flush 不该再插
    expect(await countTag('fast')).toBe(2);
  });

  test('★ 慢 insertMany 撞上链锁超时：僵尸落库后，下一轮 flush 不得再插一遍', async () => {
    const box = slowInsertMany(600);
    for (const d of makeDocs('slow', 3)) auditBuffer.push(d);

    // flush#1：150ms 就被锁超时打断并返回（错误被内部吞掉）
    await auditBuffer.flush();
    // 为什么这里必须有界等待，不能直接 expect(box.calls).toBe(1)：
    // 链锁内第一步是 getChainTail（一次真实 DB 读），整机满载（274 套件并行）时
    // 它自己就能超过 150ms 的锁预算 ⇒ flush#1 可能在**还没调到 insertMany** 时就返回。
    // 被超时打断的 fn 仍在后台继续执行（这正是"僵尸写入"的定义），所以启动只是延后，
    // 被测语义一点没变；写成同步断言只会得到一个反映机器负载的假红（实测发生过一次）。
    expect(await waitFor(() => box.calls >= 1)).toBe(true);
    expect(box.calls).toBe(1);

    // 僵尸写入最终落库 3 条
    expect(await waitFor(async () => (await countTag('slow')) >= 3)).toBe(true);

    // flush#2 模拟下一个定时 tick：修复前会把同 3 条再插一次 ⇒ 6 条
    await auditBuffer.flush();
    // 只数行数会被"永久重试"骗过（每轮都撞 11000、每轮都超时回退，行数也是 3）：
    // 批次必须真的从缓冲里排掉，否则第 5 轮它会被毒文档逻辑丢弃。
    expect(await waitFor(() => auditBuffer.getStats().bufferLength === 0)).toBe(true);
    expect(await countTag('slow')).toBe(3);
  });

  test('幂等重放不得计入毒文档失败次数（否则早已落库的记录会被"丢弃"并虚增 droppedCount）', async () => {
    slowInsertMany(600);
    for (const d of makeDocs('poison', 2)) auditBuffer.push(d);

    await auditBuffer.flush();
    expect(auditBuffer.getStats().consecutiveFailures).toBe(1); // 超时那次仍算失败
    expect(await waitFor(async () => (await countTag('poison')) >= 2)).toBe(true);

    await auditBuffer.flush();
    expect(await waitFor(() => auditBuffer.getStats().consecutiveFailures === 0)).toBe(true);
    expect(auditBuffer.getStats().droppedCount).toBe(0);
    expect(auditBuffer.getStats().bufferLength).toBe(0);
    expect(await countTag('poison')).toBe(2);
  });

  test('僵尸落库确认的那一刻就撤回被超时回退重排的批次（单轮闭环，不等下一轮撞 11000）', async () => {
    slowInsertMany(600);
    for (const d of makeDocs('retract', 2)) auditBuffer.push(d);

    await auditBuffer.flush();
    expect(auditBuffer.getStats().bufferLength).toBe(2); // 超时回退，此刻还不知道真相
    // 成功分支里 insertMany 已确认落库 ⇒ 直接按 _id 撤掉缓冲中的同一批对象。
    // 去掉这一步，本用例会红到超时（批次留在缓冲里等下一轮撞 11000）。
    expect(await waitFor(() => auditBuffer.getStats().bufferLength === 0)).toBe(true);
    expect(await countTag('retract')).toBe(2);
    // 撤回之后不再有第二次插入：重复的可能性从源头消失
    await auditBuffer.flush();
    await sleep(300);
    expect(await countTag('retract')).toBe(2);
  });

  test('混合错误：insertedDocs 与 11000 两个来源都必须算已落库', async () => {
    // 真实驱动错误（不伪造 shape）：先让 2 条正常落库，再把其中 1 条原对象重新入队，
    // 与 1 条新记录凑成同一批 —— 落库时旧的那条撞 11000、新的那条进 insertedDocs。
    const realDocs = [];
    AuditLog.insertMany = async (docs, opts) => {
      realDocs.push(...docs);
      return realInsertMany(docs, opts);
    };
    for (const d of makeDocs('mix', 2)) auditBuffer.push(d);
    await auditBuffer.flush();
    expect(await countTag('mix')).toBe(2);
    AuditLog.insertMany = realInsertMany;

    const stale = realDocs.find((d) => d.username === 'zzombie_mix_0');
    expect(stale).toBeDefined();
    // 同一批里混入 1 条早已落库的旧对象 + 1 条新记录：
    // 旧的那条撞 11000（走 writeErrors），新的那条进 insertedDocs。
    // 只处理任一来源都会让另一条留在缓冲里重试 ⇒ 下面的 bufferLength===0 转红。
    auditBuffer.push(stale);
    for (const d of makeDocs('mixnew', 1)) auditBuffer.push(d);

    await auditBuffer.flush();
    expect(await waitFor(() => auditBuffer.getStats().bufferLength === 0)).toBe(true);
    // 两条都已落库 ⇒ 不得回退重试；stale 那份也不得变成第二行
    expect(await AuditLog.countDocuments({ username: 'zzombie_mix_0' })).toBe(1);
    expect(await AuditLog.countDocuments({ username: 'zzombie_mixnew_0' })).toBe(1);
    expect(auditBuffer.getStats().droppedCount).toBe(0);
  });

  test('幂等重放不得裁剪 WAL：在途新记录的行必须留在磁盘上', async () => {
    // WAL 只在 start() 之后才写（stop() 会 disable），所以本用例必须真开 WAL。
    // 用 setInterval 桩抓住定时器但不触发，落库全部由本用例手动 flush。
    const siSpy = jest.spyOn(global, 'setInterval');
    siSpy.mockImplementation(() => ({ unref() {} }));
    auditBuffer.start();
    await wal.drain();
    try {
      // 第 1 轮：正常落库，本批 2 行 WAL 被裁剪
      const landed = [];
      AuditLog.insertMany = async (docs, opts) => {
        landed.push(...docs);
        return realInsertMany(docs, opts);
      };
      for (const d of makeDocs('wal', 2)) auditBuffer.push(d);
      await wal.drain();
      expect(walLines('wal')).toBe(2);
      await auditBuffer.flush();
      expect(await waitFor(async () => (await countTag('wal')) === 2)).toBe(true);
      expect(await waitFor(() => walLines('wal') === 0)).toBe(true);

      // 第 2 轮：同一批对象（_id 已在库）再次过 flush ⇒ 真实 E11000 幂等重放路径。
      // 重放插入进行中入队 2 条新记录：它们的行不属于本批账目，本批若"顺手裁一下"
      // 就会把它们连坐抹掉——此刻磁盘上仅有的就是这 2 行。
      const stale = landed.filter((d) => String(d.username).startsWith('zzombie_wal_'));
      expect(stale).toHaveLength(2);
      for (const d of stale) auditBuffer.push(d);
      await wal.drain();
      // 回到"第 1 轮已裁完"的磁盘状态（stale 重入队补写的行不算本用例账目）
      fs.writeFileSync(auditBuffer.getWalPath(), '');

      let calls = 0;
      AuditLog.insertMany = async (docs, opts) => {
        calls += 1;
        for (const d of makeDocs('mid', 2)) auditBuffer.push(d);
        await wal.drain();
        return realInsertMany(docs, opts);
      };
      await auditBuffer.flush();
      expect(await waitFor(() => auditBuffer.getStats().bufferLength === 2)).toBe(true);
      AuditLog.insertMany = realInsertMany;
      await wal.drain();

      expect(calls).toBe(1);
      expect(await countTag('wal')).toBe(2); // 整批重放没有产生第 3 份
      expect(await countTag('mid')).toBe(0); // mid 此刻只在内存缓冲里
      // 少裁是安全的（重放时撞 11000 由同一判据识别）；多裁是静默丢失。
      expect(walLines('mid')).toBe(2);
    } finally {
      siSpy.mockRestore();
      AuditLog.insertMany = realInsertMany;
      auditBuffer.stop();
    }
  });

  test('重放那一轮自己也超时时，知道 11000 的当场撤回（不留待第三轮）', async () => {
    // 先真实落库 2 条并抓回原对象
    const landed = [];
    AuditLog.insertMany = async (docs, opts) => {
      landed.push(...docs);
      return realInsertMany(docs, opts);
    };
    for (const d of makeDocs('again', 2)) auditBuffer.push(d);
    await auditBuffer.flush();
    expect(await countTag('again')).toBe(2);

    // 同一批对象再走一次慢 flush：本次改动 150ms 被锁超时打断（整批回缓冲），
    // 600ms 才在 catch 里知道"全部早已在库"。撤回必须发生在这个 catch 里——
    // 少了它，这 2 条会永远留在缓冲里每轮超时回退，最后被毒文档逻辑丢弃。
    const stale = landed.filter((d) => String(d.username).startsWith('zzombie_again_'));
    expect(stale).toHaveLength(2);
    AuditLog.insertMany = realInsertMany;
    slowInsertMany(600);
    for (const d of stale) auditBuffer.push(d);

    await auditBuffer.flush();
    expect(auditBuffer.getStats().bufferLength).toBe(2); // 超时回退
    expect(await waitFor(() => auditBuffer.getStats().bufferLength === 0)).toBe(true);
    expect(await countTag('again')).toBe(2);
    // 幂等重放不是失败：这里若仍计失败，5 轮后整批会被"毒文档"名义丢弃
    expect(auditBuffer.getStats().consecutiveFailures).toBe(0);
    expect(auditBuffer.getStats().droppedCount).toBe(0);
  });

  test('非 11000 的写失败一条都不能算已落库（否则审计记录被静默丢弃）', async () => {
    // writeErrors 里 code 不是 11000（如 DocumentValidationFailure 121）意味着
    // 这条**没有**在库里。判据若只看"有条目"而不看 code，就会把它当成已落库：
    // 不重试、不裁剪、也不计入 droppedCount —— 审计记录凭空消失。
    const docs = makeDocs('notdup', 2);
    let calls = 0;
    AuditLog.insertMany = async () => {
      calls += 1;
      const e = new Error('Document validation failure (simulated)');
      e.code = 11000; // 顶层 code 不足以判据，必须看每条 writeErrors 的 code
      e.insertedDocs = [];
      e.writeErrors = [
        { index: 0, err: { index: 0, code: 121, errmsg: 'DocumentValidationFailure' } },
      ];
      throw e;
    };
    for (const d of docs) auditBuffer.push(d);

    await auditBuffer.flush();
    expect(calls).toBe(1);
    // 整批（2 条）都必须留在缓冲里重试：只有 code 11000 才允许剔除
    expect(auditBuffer.getStats().bufferLength).toBe(2);
    expect(auditBuffer.getStats().consecutiveFailures).toBe(1);
    expect(auditBuffer.getStats().droppedCount).toBe(0);
    expect(await countTag('notdup')).toBe(0);

    // 恢复后必须真的落库：证明上面是"留在缓冲待重试"，不是"已被识别为已落库"
    AuditLog.insertMany = realInsertMany;
    await auditBuffer.flush();
    expect(await waitFor(async () => (await countTag('notdup')) === 2)).toBe(true);
  });

  test('部分成功后下一批必须从 DB 重取链尾（不重同步就会与已落库那条同前驱分叉）', async () => {
    // 真实 ordered:false 部分成功：第 1 条已落库（用真实驱动写入），
    // 整批调用仍失败 ⇒ advanceChainTail 不会执行，内存链尾停留在本批之前。
    // 下一批若不 resync 从 DB 重读，就会拿旧尾给第 2 条串链 → 与第 1 条同 prevHash 分叉。
    const spy = jest.spyOn(AuditLog, 'insertMany').mockImplementation(async (docs, opts) => {
      const [one] = await realInsertMany([docs[0]], opts);
      const e = new Error('simulated mid-batch failure');
      e.insertedDocs = [one];
      throw e;
    });
    for (const d of makeDocs('half', 2)) auditBuffer.push(d);
    await auditBuffer.flush();
    expect(auditBuffer.getStats().bufferLength).toBe(1); // 只回退未落库的那条
    const row0 = await AuditLog.findOne({ username: 'zzombie_half_0' }).lean();
    expect(row0).not.toBeNull();

    spy.mockRestore();
    await auditBuffer.flush();
    const row1 = await AuditLog.findOne({ username: 'zzombie_half_1' }).lean();
    expect(row1).not.toBeNull();
    // 承重断言：第 2 条必须接在已落库的第 1 条之后
    expect(row1.prevHash).toBe(row0.hash);
    expect(await countTag('half')).toBe(2);
  });

  test('链尾重同步按 _id 近似最新记录：_id 必须在 flush 里分配而不是 push 里', async () => {
    // 这条钉住"_id 预分配位置"的理由，而不是只写在注释里。
    // 时序：A 先入缓冲（不 flush）→ 直写记录 B 落库 → flush 把 A 接在 B 之后。
    // 链顺序是 B→A；若 A 在 push 时就拿到 _id，则 A._id < B._id，
    // getChainTail 的 `sort({_id:-1})` 会挑到 B（已被接走的旧尾）→ 下一批分叉，
    // 凭空造出 chain_break。flush 内分配则 A._id > B._id，重同步挑到真尾。
    const { resyncChainTail } = require('../utils/auditChain');

    const [docA] = makeDocs('order', 1);
    auditBuffer.push(docA); // 只在缓冲里，此刻还没落库也没串链

    const B = await AuditLog.create({
      action: 'user_login',
      category: 'auth',
      username: 'zzombie_orderB',
      ip: '10.9.9.9',
      success: true,
    });

    await auditBuffer.flush(); // A 在此串链：prevHash 应等于 B.hash
    const rowA = await AuditLog.findOne({ username: 'zzombie_order_0' }).lean();
    expect(rowA).not.toBeNull();
    expect(rowA.prevHash).toBe(B.hash);

    // 强制重同步（模拟链锁超时后的自愈），再落一条：必须接在真尾 A 之后。
    // _id 显式清空：否则会带上 A 的 _id 撞唯一键（本用例要的是"新记录"）。
    resyncChainTail();
    auditBuffer.push({ ...docA, _id: undefined, username: 'zzombie_order_1' });
    await auditBuffer.flush();
    const rowC = await AuditLog.findOne({ username: 'zzombie_order_1' }).lean();
    expect(rowC.prevHash).toBe(rowA.hash);

    // 前提复核：本用例的判据成立依赖 A._id 晚于 B._id（push 期分配会反过来）
    expect(String(rowA._id) > String(B._id)).toBe(true);
  });

  function walLines(tag) {
    let content = '';
    try {
      content = fs.readFileSync(auditBuffer.getWalPath(), 'utf8');
    } catch (_) {
      return 0;
    }
    return content.split('\n').filter((l) => l.includes(`zzombie_${tag}_`)).length;
  }
});
