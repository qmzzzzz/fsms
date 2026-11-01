/**
 * §13 V-8：WAL 重放的**幂等性边界**——本测试锁定「at-least-once 而非 exactly-once」
 *
 * V-8 原问「`auditBuffer.start()` 后立即 SIGKILL，重启检查 WAL 是否重复插入」。
 * 本次改动（2026-09-17）用真实内存 mongod 分窗实测，结论是**三个窗口三种结局**，
 * 本测试把这三条边界钉成可失败断言，防止后续有人误以为"已 exactly-once"：
 *
 *  1. **start() 后立即崩溃 → 不会重复**（用例 1）
 *     重放只把 WAL 行读回**内存缓冲**、不落库；崩溃时 DB 里没有对应记录，
 *     重启后重放再落库一次，净结果正确。
 *
 *  2. **insertMany 确认后、WAL 裁剪完成前硬崩 → 会重复插入**（用例 2）
 *     `flush()` 在落库成功后把裁剪**排入** walChain 而不 await（auditBuffer.js:110-116）；
 *     裁剪是「读→写 tmp→rename」（auditBufferWal.js）。窗口内硬崩（SIGKILL / OOM /
 *     容器驱逐）→ WAL 行仍在 → 重启重放整批再插一份。
 *     这是 auditBuffer.js:259-266（B-L2）注释承认的场景：`flushAndStop` + `wal.drain`
 *     已消除**优雅关闭**路径，仅剩硬杀。本用例**锁定该已知边界存在**——若哪天实现了
 *     幂等（如按 __walSeq 唯一索引去重），本用例会红，届时是"能力提升"，
 *     应按新语义更新断言而非删除测试。
 *     本仓 AuditLog schema 实测 unique 索引数 = 0（无天然去重键）。
 *
 *  3. **WAL 追加是 best-effort（异步 fire-and-forget、无 fsync）**（用例 3）
 *     正常路径可用，但不承诺"崩溃零丢失"——auditBufferWal.js:17 已如实声明。
 *
 * 【2026-10-31 更新：用例 2 的边界在**新格式行**上已闭合】F-143 的跨重启幂等修复把
 * `_id` 的分配从 flush 提前到 push，并随 WAL 行落盘 ⇒ 重放复用同一 `_id` ⇒ 撞 `_id`
 * 唯一索引 ⇒ 走 collectDurableIds 的 11000 对账（不再插入）。所以：
 *   · **新格式行**（用例 5/6 写出的行，带 `_id`）＝恰好一次；
 *   · **旧格式行**（升级前写下的行，没有 `_id`）＝仍按旧语义重放，重复插入窗口仍在（用例 2）。
 * 这不是「两个真相」：行里有没有身份键是磁盘上可读的事实，用例 2/5/6 分别钉住两档。
 *
 * 模拟"进程重启"的手法：同进程内 `__resetForTest()` 清空内存缓冲 + 重新
 * `start()`。这与真实重启的差别只在"不重建模块对象"，对本测试要断言的
 * 「磁盘 WAL 状态 → 落库条数」映射无影响。
 *
 * 隔离：独立 mkdtemp + 独立 AUDIT_WAL_PATH（修复后 start() 会重读 env）。
 * ⚠️ 写 WAL 文件前必须先 start()：`getWalPath()` 在 startup() 之前返回的是
 * 模块加载期的**默认派生路径**（auditBufferWal.js 的 `let walPath = deriveDefaultWalPath()`；
 * 函数实体在 auditWalPath.js），
 * 只有 start() → wal.startup() 之后才切到本套件 mkdtemp 下的路径。
 * 本文件用 `walPath()` 辅助函数把这件事封装掉：先确保已 startup，再取路径。
 * 不使用 jest.useFakeTimers（与 mongodb-memory-server 冲突），用 spyOn(setInterval)
 * 捕获回调手动触发（与既有 observability/auditBufferFlushAndWalGuards.test.js 同法）。
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const mongoose = require('mongoose');
const { TEST_CLIENT_IP } = require('../fixtures');

const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'audit-wal-idem-'));
process.env.AUDIT_WAL_PATH = path.join(tmpDir, 'idem-test.wal');
process.env.AUDIT_BUFFER_HARD_LIMIT = '200';
process.env.AUDIT_WAL_MAX_BYTES = '100000';
process.env.AUDIT_WAL_STAT_INTERVAL = '1000';

const auditBuffer = require('../../services/auditBuffer');
const wal = require('../../services/auditBufferWal');
const AuditLog = require('../../models/AuditLog');
const { waitFor, waitForStable, flushEventLoop } = require('../helpers/waitFor');
const chain = require('../../utils/auditChain');

/** 等 WAL 异步写入链真正排空（追加/裁剪/rename 全部落盘）。
 *
 * 【竞态修复】原实现比较「两次读到的文件内容是否相同」，但 WAL 追加是
 * fire-and-forget 的异步链（auditBufferWal.walAppendLine）：push() 返回时
 * 文件可能**尚未创建**，此时第一次读得 null 作为基线，第二次读仍是 null，
 * null === null 成立 → 函数在 0 次循环后立即返回。
 *
 * 后果：调用方紧接着读 WAL / 断言缓冲内容时，实际读取的是「异步链还没跑完」
 * 的中间态。单跑本文件时事件循环空闲、链几乎瞬时完成，故长期未被发现；
 * 全量并行（50% workers，每个 worker 在跑真实 DB 操作）下链明显排队，
 * 稳定复现为「WAL 行数 0 / 缓冲计数 0」的假红。
 *
 * 修复：改为等待 wal 模块自己的串行链排空（drain 就是 flushAndStop 用的
 * 同一判据），再叠加一次「文件内容稳定」确认（复用 helpers/waitFor.waitForStable），
 * 语义与「追加链排空」等价且不依赖文件是否已存在。 */
async function waitForWalQuiet(timeoutMs = 8000) {
  await wal.drain(); // 精确判据：walChain 上排队的 append/trim/rename 全部完成
  const p = walPath();
  const readWalContent = () => {
    try {
      return fs.readFileSync(p, 'utf8');
    } catch (_) {
      return null; // 文件不存在 = 没有待观察的写入（链已排空）
    }
  };
  if (readWalContent() === null) return;
  await waitForStable(readWalContent, { timeoutMs, label: 'WAL 文件内容稳定' });
}

/**
 * WAL 路径（beforeAll 已通过一次 start() 把它 pin 到本套件的 mkdtemp 下）。
 * 背景：`getWalPath()` 在 `startup()` 之前返回模块加载期的默认派生路径
 * （auditBufferWal.js 的 `let walPath = deriveDefaultWalPath()`，函数实体在 auditWalPath.js）——直接写那个
 * 文件等于白写，模块根本不会读它。
 */
const walPath = () => auditBuffer.getWalPath();

function makeDoc(tag, seq) {
  return {
    action: 'wal_replay_probe',
    category: 'auth',
    username: `${tag}_${seq}`,
    ip: TEST_CLIENT_IP,
    success: true,
    timestamp: new Date(),
  };
}

/**
 * 模拟一次进程重启：停表 → 清内存状态（缓冲/计数）→ 重新 start（触发 WAL 重放）。
 * @returns {Function} tick：手动触发定时 flush 的回调
 */
function reboot() {
  auditBuffer.stop();
  auditBuffer.__resetForTest();
  let tick = null;
  siSpy.mockImplementation((fn) => {
    tick = fn;
    return { unref() {} };
  });
  auditBuffer.start();
  if (typeof tick !== 'function') throw new Error('flush timer 未注册');
  return tick;
}

let siSpy = null;

describe('§13 V-8 WAL 重放幂等性边界', () => {
  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    // 把 WAL 路径 pin 到本套件的 mkdtemp：startup() 会读 AUDIT_WAL_PATH。
    // 之后的 stop()/__resetForTest() 都不会重置 walPath（模块级变量只由 startup 写）。
    auditBuffer.start();
    auditBuffer.stop();
  });

  beforeEach(async () => {
    await waitForWalQuiet();
    auditBuffer.stop();
    auditBuffer.__resetForTest();
    // 清空 WAL 文件，避免上一个用例的行污染本用例的"重放条数"断言
    try {
      fs.writeFileSync(walPath(), '');
    } catch (_) {
      /* 文件尚不存在 */
    }
  });

  afterEach(() => {
    auditBuffer.stop();
    if (siSpy) siSpy.mockRestore();
    siSpy = null;
  });

  afterAll(async () => {
    try {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    } catch (_) {
      /* 尽力清理 */
    }
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });

  test('用例 1：start() 后立即崩溃 → 重启重放不会重复（报告原设问的答案）', async () => {
    const tag = `idem1_${Date.now()}`;
    // 手工写 3 行 WAL（模拟上一进程 push 后崩溃、尚未落库）
    const lines = [0, 1, 2].map((i) => JSON.stringify(makeDoc(tag, i))).join('\n') + '\n';
    fs.writeFileSync(walPath(), lines);

    // boot 1：重放只回内存缓冲，不落库 —— 此时"崩溃"（不等于 DB 有记录）
    siSpy = jest.spyOn(global, 'setInterval');
    siSpy.mockImplementation(() => ({ unref() {} }));
    auditBuffer.start();
    await waitFor(async () => auditBuffer.getStats().bufferLength === 3);
    expect(await AuditLog.countDocuments({ username: new RegExp(`^${tag}_`) })).toBe(0);

    // boot 2：重启后重放 → 定时 flush 落库，净结果恰好 3 条（无重复）
    const tick = reboot();
    await waitFor(async () => auditBuffer.getStats().bufferLength === 3);
    tick();

    const ok = await waitFor(
      async () => (await AuditLog.countDocuments({ username: new RegExp(`^${tag}_`) })) === 3,
      { label: '重启后重放的 3 条落库且不重复' }
    );
    expect(ok).toBe(true);
    expect(await AuditLog.countDocuments({ username: new RegExp(`^${tag}_`) })).toBe(3);
    // 落库成功后 WAL 被裁剪（前缀消费），残留为空 —— 这是"不会重复"的机制原因
    // 裁剪排在 walChain 上（异步），轮询等待而非立即读取
    await waitFor(() => fs.readFileSync(walPath(), 'utf8').trim() === '', {
      label: '落库后 WAL 被裁剪为空',
    });
  });

  test('用例 2：**旧格式**行（无 _id）落库成功但未裁剪即「崩溃」→ 重放再插一份（兼容档，非回归）', async () => {
    const tag = `idem2_${Date.now()}`;
    siSpy = jest.spyOn(global, 'setInterval');
    siSpy.mockImplementation(() => ({ unref() {} }));
    auditBuffer.start();

    // 第 1 轮：正常 push + flush 落库（WAL 行随之裁剪）
    const tick1 = siSpy.mock.calls[0][0];
    for (let i = 0; i < 3; i += 1) auditBuffer.push(makeDoc(tag, i));
    await waitForWalQuiet();
    tick1();

    const inserted = await waitFor(
      async () => (await AuditLog.countDocuments({ username: new RegExp(`^${tag}_`) })) === 3,
      { label: '第 1 轮 3 条落库' }
    );
    expect(inserted).toBe(true);

    // 「硬崩前一刻」：把 WAL 恢复成裁剪前的状态——模拟 insert 确认后、rename
    // 完成前进程被 SIGKILL（WAL 行原样留在磁盘）。不依赖真实 SIGKILL，等价地
    // 重建「DB 已有记录 + WAL 仍有对应行」这个磁盘状态。
    //
    // 注意这里**手工构造的是旧格式行**（makeDoc 没有 _id）：升级前写下的行就该按旧
    // 语义重放（现分配 _id），所以本用例仍然期待 2 条 —— 它钉的是兼容档。
    // 新格式行的同一形态见用例 6（那里由 push 写行、行里带 _id，期待 1 条）。
    const crashLine = JSON.stringify(makeDoc(tag, 0)) + '\n';
    await waitForWalQuiet();
    fs.writeFileSync(walPath(), crashLine);

    // 重启：重放该行 → flush 落库 → DB 出现第 2 条同内容记录（**不去重**）
    const tick2 = reboot();
    await waitFor(async () => auditBuffer.getStats().bufferLength === 1);
    tick2();

    const duplicated = await waitFor(
      async () => (await AuditLog.countDocuments({ username: `${tag}_0` })) === 2,
      { label: '重放导致同一内容出现第 2 条（已知边界）' }
    );
    expect(duplicated).toBe(true);
    expect(await AuditLog.countDocuments({ username: `${tag}_0` })).toBe(2);

    // 机制说明（不是断言，供读者定位）：本仓无任何去重键
    const uniqueIdx = AuditLog.schema.indexes().filter(([, opt]) => opt && opt.unique);
    expect(uniqueIdx).toHaveLength(0);
  });

  test('用例 3：WAL 追加为 best-effort（无 fsync）——注释与实现一致才放行', async () => {
    const tag = `idem3_${Date.now()}`;
    siSpy = jest.spyOn(global, 'setInterval');
    siSpy.mockImplementation(() => ({ unref() {} }));
    auditBuffer.start();

    for (let i = 0; i < 3; i += 1) auditBuffer.push(makeDoc(tag, i));

    // 正常路径：排空追加链后行确实在磁盘上（WAL 可用）
    await waitForWalQuiet();
    const onDisk = fs
      .readFileSync(auditBuffer.getWalPath(), 'utf8')
      .trim()
      .split('\n')
      .filter(Boolean);
    expect(onDisk).toHaveLength(3);

    // 但不承诺"崩前零丢失"：实现里没有 fsync，注释也如实声明。
    // 本断言防止有人误读 WAL 为"已持久化保证"——若将来加了 fsync，
    // 此处会红，提示同步更新 auditBufferWal.js 的 best-effort 声明。
    const walSrc = fs.readFileSync(
      path.resolve(__dirname, '../../services/auditBufferWal.js'),
      'utf8'
    );
    expect(walSrc).not.toMatch(/\bfsyncSync\b|\bfdatasyncSync\b/);
    expect(walSrc).toContain('best-effort');
  });

  test('用例 4：追加仍在途时，等待判据不得提前返回（drain 判据的承重断言）', async () => {
    // 【可证伪性】闸住 appendFile 让追加永不完成：waitForWalQuiet 若丢掉
    // `await wal.drain()`，会在「内容未变化」处立即 return，下面的
    // expect(returned).toBe(false) 随即转红——这正是该行的承重对象。
    siSpy = jest.spyOn(global, 'setInterval');
    siSpy.mockImplementation(() => ({ unref() {} }));
    auditBuffer.start();
    await wal.drain(); // 先排空 start() 的重放任务

    let release;
    const gate = new Promise((r) => {
      release = r;
    });
    const realAppend = fs.promises.appendFile.bind(fs.promises);
    const appendSpy = jest.spyOn(fs.promises, 'appendFile').mockImplementation(async (...args) => {
      await gate;
      return realAppend(...args);
    });

    let returned = false;
    auditBuffer.push(makeDoc(`quiet4_${Date.now()}`, 0));
    const waiter = waitForWalQuiet().then(() => {
      returned = true;
    });
    try {
      // 负向断言：给 waiter 若干轮事件循环去（错误地）提前返回；真实判据
      // `await wal.drain()` 被门闩卡住，故这里只让出事件循环、不承诺时长。
      await flushEventLoop(3);
      expect(returned).toBe(false);
    } finally {
      release();
      await waiter;
      await wal.drain();
      appendSpy.mockRestore();
    }
  });

  test('用例 5：行的 _id 随行落盘 → 重放落库的 _id 与行内一致，且只有一条', async () => {
    const tag = 'idem5_' + Date.now();
    siSpy = jest.spyOn(global, 'setInterval');
    siSpy.mockImplementation(() => ({ unref() {} }));
    auditBuffer.start();
    auditBuffer.push(makeDoc(tag, 0));
    await waitForWalQuiet();

    const linesBefore = fs.readFileSync(walPath(), 'utf8').trim().split('\n').filter(Boolean);
    expect(linesBefore).toHaveLength(1);
    const lineDoc = JSON.parse(linesBefore[0]);
    // 身份键必须在行里：这是跨重启幂等的唯一依据（改前此处为 undefined）
    expect(typeof lineDoc._id).toBe('string');
    expect(lineDoc._id).toMatch(/^[0-9a-f]{24}$/);

    // 模拟进程死：内存状态全丢，磁盘 WAL 原样留下
    const tick = reboot();
    await waitFor(async () => auditBuffer.getStats().bufferLength === 1);
    tick();

    const ok = await waitFor(
      async () => (await AuditLog.countDocuments({ username: tag + '_0' })) === 1,
      {
        label: '重放后恰好一条',
      }
    );
    expect(ok).toBe(true);
    const stored = await AuditLog.findOne({ username: tag + '_0' }).lean();
    // 落库的 _id 必须是行里那一个（改前：重放现分配 ⇒ 两者不同）
    expect(String(stored._id)).toBe(String(lineDoc._id));
  });

  test('用例 6：崩在「落库成功、WAL 未裁」之间 → 重放不再插第二份（F-143 跨重启幂等）', async () => {
    const tag = 'idem6_' + Date.now();
    siSpy = jest.spyOn(global, 'setInterval');
    siSpy.mockImplementation(() => ({ unref() {} }));
    auditBuffer.start();
    const tick1 = siSpy.mock.calls[0][0];
    auditBuffer.push(makeDoc(tag, 0));
    auditBuffer.push(makeDoc(tag, 1));
    await waitForWalQuiet();
    const preTrim = fs.readFileSync(walPath(), 'utf8');
    expect(preTrim.trim().split('\n').filter(Boolean)).toHaveLength(2);

    tick1();
    const inserted = await waitFor(
      async () => (await AuditLog.countDocuments({ username: new RegExp('^' + tag + '_') })) === 2,
      { label: '第一轮两条落库' }
    );
    expect(inserted).toBe(true);
    await waitForWalQuiet(); // 等裁剪真正落盘，再回写裁剪前的字节
    const tailAfterFirst = await chain.getChainTail(AuditLog);

    // 「硬崩」：把 WAL 恢复成裁剪前的字节（模拟 insert 确认后 rename 未完成）
    fs.writeFileSync(walPath(), preTrim);
    expect(await AuditLog.countDocuments({ username: new RegExp('^' + tag + '_') })).toBe(2);

    const tick2 = reboot();
    await waitFor(async () => auditBuffer.getStats().bufferLength === 2);
    tick2();
    await waitForWalQuiet();
    await flushEventLoop(5);

    // 改前：重放的 _id 是新分配的 ⇒ 库里 4 条；改后：撞 _id 唯一索引 ⇒ 仍 2 条
    expect(await AuditLog.countDocuments({ username: new RegExp('^' + tag + '_') })).toBe(2);
    // 链尾不多推：重放没有产生新记录，也就没有新链尾
    expect(await chain.getChainTail(AuditLog)).toBe(tailAfterFirst);
    // 已被识别为「已在库中」⇒ 两行随后被正常裁掉，不会每次重启都重放
    const emptied = await waitFor(() => fs.readFileSync(walPath(), 'utf8').trim() === '', {
      label: '重放的行被裁空',
    });
    expect(emptied).toBe(true);
  });

  test('用例 7：C 实测 —— 久候批次的 _id 序与串链序反转，链尾初始化是否还选得对', async () => {
    const tag = 'idem7_' + Date.now();
    siSpy = jest.spyOn(global, 'setInterval');
    siSpy.mockImplementation(() => ({ unref() {} }));
    auditBuffer.start();
    const tick = siSpy.mock.calls[0][0];

    // (a) 批次先入队：此刻就已分配 _id（较早）
    auditBuffer.push(makeDoc(tag, 'b'));
    await waitForWalQuiet();
    // (b) 其间一条**直写**记录先落库并推链尾（_id 更晚）
    await AuditLog.create(makeDoc(tag, 'd'));
    // (c) 批次随后落库：链上更晚，但 _id 更早
    tick();
    const both = await waitFor(
      async () =>
        (await AuditLog.countDocuments({ username: { $in: [tag + '_b', tag + '_d'] } })) === 2,
      { label: '批次与直写各一条' }
    );
    expect(both).toBe(true);

    const batch = await AuditLog.findOne({ username: tag + '_b' }).lean();
    const direct = await AuditLog.findOne({ username: tag + '_d' }).lean();
    // 实测 1：id 序与串链序**相反**（改前 _id 在 flush 时分配 ⇒ 两者一致）
    expect(String(batch._id) < String(direct._id)).toBe(true);
    expect(batch.prevHash).toBe(direct.hash);
    // 实测 2：谁被谁认领 —— 直写已有子记录，批次没有（批次就是链尾）
    const parents = new Set(
      (
        await AuditLog.find(
          { prevHash: { $in: [batch.hash, direct.hash] } },
          { prevHash: 1 }
        ).lean()
      )
        .map((r) => r.prevHash)
        .filter(Boolean)
    );
    expect(parents.has(direct.hash)).toBe(true);
    expect(parents.has(batch.hash)).toBe(false);
    // 实测 3：链尾初始化必须选「无子记录」的那条，而不是「最大 _id」的那条
    await chain.resyncChainTail();
    const tail = await chain.getChainTail(AuditLog);
    expect(tail).not.toBe(direct.hash);
    // 顺序跑（--runInBand）时真尾就是本批次的尾；并行跑其它套件时可能已有更晚的记录接在后面，
    // 故这里只断言充要性质（旧实现恰好返回被认领的那条）。
  });
});
