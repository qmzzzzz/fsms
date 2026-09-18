/**
 * §13 V-8：WAL 重放的**幂等性边界**——本测试锁定「at-least-once 而非 exactly-once」
 *
 * V-8 原问「`auditBuffer.start()` 后立即 SIGKILL，重启检查 WAL 是否重复插入」。
 * 本轮（2026-09-17）用真实内存 mongod 分窗实测，结论是**三个窗口三种结局**，
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
 * 模拟"进程重启"的手法：同进程内 `__resetForTest()` 清空内存缓冲 + 重新
 * `start()`。这与真实重启的差别只在"不重建模块对象"，对本测试要断言的
 * 「磁盘 WAL 状态 → 落库条数」映射无影响。
 *
 * 隔离：独立 mkdtemp + 独立 AUDIT_WAL_PATH（T-1 修复后 start() 会重读 env）。
 * ⚠️ 写 WAL 文件前必须先 start()：`getWalPath()` 在 startup() 之前返回的是
 * 模块加载期的**默认派生路径**（auditBufferWal.js 的 `let walPath = deriveDefaultWalPath()`），
 * 只有 start() → wal.startup() 之后才切到本套件 mkdtemp 下的路径。
 * 本文件用 `walPath()` 辅助函数把这件事封装掉：先确保已 startup，再取路径。
 * 不使用 jest.useFakeTimers（与 mongodb-memory-server 冲突），用 spyOn(setInterval)
 * 捕获回调手动触发（与既有 auditBufferGap.test.js 同法）。
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

/** 轮询等待真实完成条件 */
async function waitFor(cond, timeoutMs = 8000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await cond()) return true;
    await new Promise((r) => setTimeout(r, 25));
  }
  return false;
}

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
 * 同一判据），再叠加一次「文件内容稳定」确认，语义与「追加链排空」等价且
 * 不依赖文件是否已存在。 */
async function waitForWalQuiet(timeoutMs = 8000) {
  await wal.drain(); // 精确判据：walChain 上排队的 append/trim/rename 全部完成
  const p = walPath();
  let last = null;
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    let cur;
    try {
      cur = fs.readFileSync(p, 'utf8');
    } catch (_) {
      return; // 文件不存在 = 没有待观察的写入（链已排空），无需继续等
    }
    if (cur === last) return; // 内容不再变化
    last = cur;
    await new Promise((r) => setTimeout(r, 25));
  }
}

/**
 * WAL 路径（beforeAll 已通过一次 start() 把它 pin 到本套件的 mkdtemp 下）。
 * 背景：`getWalPath()` 在 `startup()` 之前返回模块加载期的默认派生路径
 * （auditBufferWal.js 的 `let walPath = deriveDefaultWalPath()`）——直接写那个
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
      async () => (await AuditLog.countDocuments({ username: new RegExp(`^${tag}_`) })) === 3
    );
    expect(ok).toBe(true);
    expect(await AuditLog.countDocuments({ username: new RegExp(`^${tag}_`) })).toBe(3);
    // 落库成功后 WAL 被裁剪（前缀消费），残留为空 —— 这是"不会重复"的机制原因
    // 裁剪排在 walChain 上（异步），轮询等待而非立即读取
    const trimmed = await waitFor(() => fs.readFileSync(walPath(), 'utf8').trim() === '');
    expect(trimmed).toBe(true);
  });

  test('用例 2：落库成功但 WAL 未裁剪即「崩溃」→ 重放整批再插一份（已知边界，非回归）', async () => {
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
      async () => (await AuditLog.countDocuments({ username: new RegExp(`^${tag}_`) })) === 3
    );
    expect(inserted).toBe(true);

    // 「硬崩前一刻」：把 WAL 恢复成裁剪前的状态——模拟 insert 确认后、rename
    // 完成前进程被 SIGKILL（WAL 行原样留在磁盘）。不依赖真实 SIGKILL，等价地
    // 重建「DB 已有记录 + WAL 仍有对应行」这个磁盘状态。
    const crashLine = JSON.stringify(makeDoc(tag, 0)) + '\n';
    await waitForWalQuiet();
    fs.writeFileSync(walPath(), crashLine);

    // 重启：重放该行 → flush 落库 → DB 出现第 2 条同内容记录（**不去重**）
    const tick2 = reboot();
    await waitFor(async () => auditBuffer.getStats().bufferLength === 1);
    tick2();

    const duplicated = await waitFor(
      async () => (await AuditLog.countDocuments({ username: `${tag}_0` })) === 2
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
      await new Promise((r) => setTimeout(r, 150));
      expect(returned).toBe(false);
    } finally {
      release();
      await waiter;
      await wal.drain();
      appendSpy.mockRestore();
    }
  });
});
