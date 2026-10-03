'use strict';

/**
 * F-96：数据库抖动不得把合法审计当"毒文档"删掉
 *
 * 缺陷（台账 §4.2 [复]）：`auditBuffer.flush()` 的丢弃判据是**全局连败计数**
 * （`consecutiveFailures >= 5`），与批次内容完全无关。Mongo 主从切换/重启/网络抖动
 * 只要横跨 5 轮 flush（约 10 秒），第 5 轮那批**完全合法**的审计就会被
 * `wal.discardBySeqs()` 按 `__walSeq` 移出主 WAL 并归档到 `.discarded`，永不再回灌
 * ⇒ 一次抖动换一条永久缺失的合规记录，而日志把归因写成"毒文档"。
 *
 * 修法（同批一起提交的两处前提变更见文件末尾说明）：
 *   · 只有**能从错误里 positively 认出内容级失败**（服务端逐条拒绝 / 文档校验失败）才计次；
 *   · 计次按**文档**而不是按批次 ⇒ 第 5 轮被 flush 出去的无辜文档不替别人买单；
 *   · 基础设施类错误与未知形状一律保守处理：保留缓冲与 WAL、继续重试、error 级告警；
 *   · 丢弃时只丢达到阈值的那些文档，同批其余留在缓冲。
 *
 * 分类器的判据来自实测错误形状（`MongooseServerSelectionError` / `code`、`writeErrors`
 * 均为 undefined），本文件第一条用例就是那张真值表的自证 —— 驱动升级改了错误形状时，
 * 会先红在这里，而不是悄悄把"抖动删审计"的口子重新打开。
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const mongoose = require('mongoose');

const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'auditbuf-outage-'));
process.env.AUDIT_WAL_PATH = path.join(tmpDir, 'outage.wal');
process.env.AUDIT_WAL_MAX_BYTES = '100000';
process.env.AUDIT_BUFFER_HARD_LIMIT = '200';

const auditBuffer = require('../../services/auditBuffer');
const { isContentAttributableFailure } = require('../../utils/mongoFailureAttribution');
const wal = require('../../services/auditBufferWal');
const AuditLog = require('../../models/AuditLog');
const { TEST_CLIENT_IP } = require('../fixtures');
const { contentLevelWriteError } = require('../helpers/contentLevelWriteError');

const MAX_RETRY = 5; // 与 auditBuffer.MAX_BATCH_RETRY 同值（改动阈值时这里会红，属期望行为）

const infraError = () => {
  const e = new Error('connection was reset');
  e.name = 'MongoNetworkError';
  return e;
};
const stepDownError = () => {
  // F-183：类名原先写的 MongoNotPrimaryError 在 driver 6 里不存在（那是 3/4 时代的类名，
  // 现在同一种情形叫 MongoStalePrimaryError，或干脆是 MongoServerError + code 10107）。
  // 名字编出来不影响本用例的结论——判据对**任何**它不认识的名字都返回 false（保守分支），
  // 所以"名字是否真实"这件事已经挪到 mongoFailureAttribution.test.js 的派生门禁去钉。
  const e = new Error('NotPrimary');
  e.name = 'MongoStalePrimaryError';
  e.codeName = 'NotPrimary';
  e.code = 10107;
  return e;
};
const outageError = () =>
  Object.assign(new Error('connect ECONNREFUSED 127.0.0.1:1'), {
    name: 'MongooseServerSelectionError',
  });

function makeDoc(tag) {
  return {
    action: 'login',
    category: 'auth',
    username: `outage_${tag}`,
    userId: new mongoose.Types.ObjectId(),
    ip: TEST_CLIENT_IP,
    result: 'success',
    riskLevel: 'low',
    timestamp: new Date(),
  };
}

async function flushRounds(times) {
  for (let i = 0; i < times; i += 1) await auditBuffer.flush();
}

describe('审计缓冲：不可归因于内容的失败一律不丢审计（F-96）', () => {
  let insertSpy;
  let discardSpy;
  let intervalSpy;

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) await mongoose.connect(process.env.MONGODB_URI);
  });

  // 两个清理各自吞错：共用一个 try 时，第一次 rmSync 抛错（Windows 上文件仍被追加句柄
  // 占用会 EBUSY）会让 '.discarded' 那一行根本不执行，清理静默缺一半。
  // 注：这不是 seed 31337 那条红的成因（实测红因见下方 wal.drain() 的注释），
  // 但它是同一族"清理静默失败"的地雷，顺手拆掉。
  const rmQuiet = (p) => {
    try {
      fs.rmSync(p, { force: true });
    } catch (_) {
      /* 文件可能不存在，或被句柄占用 */
    }
  };

  beforeEach(() => {
    auditBuffer.__resetForTest();
    rmQuiet(process.env.AUDIT_WAL_PATH);
    rmQuiet(process.env.AUDIT_WAL_PATH + '.discarded');
    // 定时器换成捕获不执行：轮数必须由用例里的 flushRounds 决定，
    // 否则后台 tick 会往 outageFailures / 计次里加不确定的轮次（本仓的时序地雷）
    intervalSpy = jest.spyOn(global, 'setInterval').mockImplementation(() => ({ unref() {} }));
    discardSpy = jest.spyOn(wal, 'discardBySeqs'); // 不替换实现：归档要真的发生，才断言得了'只挪走该挪的那些行'
    insertSpy = jest.spyOn(AuditLog, 'insertMany').mockImplementation(() => Promise.resolve());
    // WAL 只在 startup() 之后启用（walEnabled 门控），而 __walSeq 只有落 WAL 才有
    auditBuffer.start();
  });

  afterEach(async () => {
    auditBuffer.stop();
    insertSpy.mockRestore();
    discardSpy.mockRestore();
    intervalSpy.mockRestore();
    await AuditLog.deleteMany({ username: /^outage_/ }).catch(() => {});
  });

  afterAll(async () => {
    auditBuffer.__resetForTest();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  test('前提自证：分类器真值表（含实测的三种基础设施错误形状与内容级形状）', () => {
    expect(isContentAttributableFailure(outageError())).toBe(false); // 实测形状：MongooseServerSelectionError、无 code/writeErrors
    expect(isContentAttributableFailure(infraError())).toBe(false);
    expect(isContentAttributableFailure(stepDownError())).toBe(false);
    expect(isContentAttributableFailure(new Error('未知形状'))).toBe(false); // 认不出来 ⇒ 保守按基础设施处理
    expect(isContentAttributableFailure(contentLevelWriteError(1))).toBe(true);
    // F-183：原先这里断言 `{ name: 'BulkSaveValidationError' }` ⇒ true，而驱动/Mongoose 里
    // 根本没有这个类名——判据对"内容表里的名字"才返回 true，编一个名字恰好在那张表里才算数。
    // 换成真实存在的 Mongoose 校验类名，名字真实性由派生门禁统一核。
    expect(isContentAttributableFailure({ name: 'MongooseBulkWriteError' })).toBe(true);
    expect(isContentAttributableFailure({ name: 'MongoBulkWriteError', writeErrors: [] })).toBe(
      false
    ); // 载体类名自身不算证据（实测：w>1 打在单节点上就是这个形状）
    expect(
      isContentAttributableFailure({
        message: 'x',
        code: 121,
        codeName: 'DocumentValidationFailure',
      })
    ).toBe(true);
  });

  test('基础设施抖动 10 轮：零丢弃、缓冲与 WAL 全留、不叫 discardBySeqs', async () => {
    insertSpy.mockRejectedValue(outageError());
    auditBuffer.push(makeDoc('a'));
    auditBuffer.push(makeDoc('b'));
    auditBuffer.push(makeDoc('c'));
    await flushRounds(10);
    await wal.drain();

    const stats = auditBuffer.getStats();
    expect({ dropped: stats.droppedCount, buffered: stats.bufferLength }).toEqual({
      dropped: 0,
      buffered: 3,
    });
    expect(stats.outageFailures).toBe(10);
    expect(discardSpy).not.toHaveBeenCalled();
    const walText = fs.readFileSync(process.env.AUDIT_WAL_PATH, 'utf8');
    expect(walText.split('\n').filter(Boolean).length).toBeGreaterThanOrEqual(3);
    expect(fs.existsSync(process.env.AUDIT_WAL_PATH + '.discarded')).toBe(false);
  });

  test('恢复后自动落库：抖动期间的记录一条不少地进库，outageFailures 归零', async () => {
    insertSpy.mockRejectedValue(outageError());
    auditBuffer.push(makeDoc('r1'));
    auditBuffer.push(makeDoc('r2'));
    await flushRounds(3);
    expect(await AuditLog.countDocuments({ username: /^outage_r/ })).toBe(0);

    insertSpy.mockRestore(); // 交回真实 insertMany：这条用例断言的是真的落库，不是 mock 返回成功
    await auditBuffer.flush();
    await wal.drain();

    expect(await AuditLog.countDocuments({ username: /^outage_r/ })).toBe(2);
    const stats = auditBuffer.getStats();
    expect(stats.outageFailures).toBe(0);
    expect(stats.droppedCount).toBe(0);
    expect(stats.bufferLength).toBe(0);
  });

  test('内容级失败仍会收敛：同一条文档连续 5 次被服务端拒绝才丢，且只丢它', async () => {
    insertSpy.mockRejectedValue(contentLevelWriteError(1));
    auditBuffer.push(makeDoc('poison'));
    await flushRounds(MAX_RETRY - 1);
    expect(auditBuffer.getStats().droppedCount).toBe(0); // 还没到阈值 ⇒ 一条都不能丢

    await auditBuffer.flush();
    // 必须等 WAL 写入链排空：discardBySeqs 的 `.discarded` 追加是排在 wal 内部写链里的，
    // 不等就会在下一条用例的 beforeEach 清完文件之后才落地 —— 实测 seed 31337 下
    // 本用例被排到"基础设施抖动 10 轮"之前时，那 10 轮里凭空多出 .discarded（F-112 同族，
    // 但传递介质是"未 await 的写链"而不是库状态）。同文件"按文档计次"用例已有这一句。
    await wal.drain();
    const stats = auditBuffer.getStats();
    expect(stats.droppedCount).toBe(1);
    expect(stats.bufferLength).toBe(0);
    expect(discardSpy).toHaveBeenCalledTimes(1);
  });

  test('按文档计次（这条正是"全局连败"与"逐文档计次"的分水岭）', async () => {
    insertSpy.mockRejectedValue(contentLevelWriteError(1));
    auditBuffer.push(makeDoc('old'));
    await flushRounds(3); // old 计 3 次
    auditBuffer.push(makeDoc('fresh')); // 后来的文档此刻 0 次
    await flushRounds(2); // 再 2 轮：old 到 5 次被丢，fresh 只有 2 次
    await wal.drain();

    const stats = auditBuffer.getStats();
    expect(stats.droppedCount).toBe(1);
    expect(stats.bufferLength).toBe(1);
    const buffered = stats.bufferLength;
    expect(buffered).toBe(1);
    expect(discardSpy).toHaveBeenCalledTimes(1);
    // fresh 的 WAL 行必须还在主 WAL 里（被误伤的话就是全局计数回归了）
    const walText = fs.readFileSync(process.env.AUDIT_WAL_PATH, 'utf8');
    expect(walText).toContain('outage_fresh');
    const discarded = fs.readFileSync(process.env.AUDIT_WAL_PATH + '.discarded', 'utf8');
    expect(discarded).toContain('outage_old');
    expect(discarded).not.toContain('outage_fresh');
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
