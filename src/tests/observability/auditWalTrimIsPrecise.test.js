'use strict';

/**
 * F-97：WAL 裁剪必须按 `__walSeq` 精确匹配，不得按"文件前 N 行"
 *
 * 缺陷（台账 §4.2 [复]、§7-2 的第二半，级别同 F-96：会造成审计永久缺失）：
 * `flush()` 落库成功后原先调 `wal.trimLines(docs.length)`，其实现是
 * 「读文件 → 丢弃前 N 行 → 原子替换」。这套账只有在**本批文档的 WAL 行恰好是文件最前
 * N 行**时才正确，而代码里至少三条路径会先在这 N 行之前/之间制造空洞：
 *   1) WAL 未启用的窗口期入缓冲的文档（auditBuffer.start 竞态注释自己承认过）没有行；
 *   2) `walAppendLine` 的 appendFile 失败只 warn，文档照样进缓冲 ⇒ 缺行；
 *   3) 毒批 `discardBySeqs` 从文件**中间**移走行；
 *   4) 部分成功（ordered:false）时已落库子集的行留在原地，永不回收 ⇒ 前缀里堆死行。
 * 出现空洞后，每次裁剪都在删"排在后面的、尚未落库记录"的行——那些记录的内存副本还在，
 * 但**崩溃恢复能力已经没了**：进程一崩就永久缺失，而 droppedCount 完全不计。
 * 旧告警（"WAL 行数(n)少于待裁剪(m)"）也抓不住：有更新行垫在后面时 n>=m 恒成立，**恒不触发**。
 *
 * 本文件两条用例分别钉住"不吃别人的行"与"自己的死行要回收"，都是行为断言。
 *
 * 前提说明：两条用例都直接驱动 `auditBuffer.flush()`（不外靠定时器轮数），
 * 且读取 WAL 前先 `await wal.drain()` —— WAL 的写是排在串行链上的异步操作
 * （本仓时序地雷，见 ledger §8）。
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const mongoose = require('mongoose');

const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'auditwal-precise-'));
process.env.AUDIT_WAL_PATH = path.join(tmpDir, 'precise.wal');
process.env.AUDIT_WAL_MAX_BYTES = '1000000';
process.env.AUDIT_BUFFER_HARD_LIMIT = '200';

const auditBuffer = require('../../services/auditBuffer');
const wal = require('../../services/auditBufferWal');
const AuditLog = require('../../models/AuditLog');
const { TEST_CLIENT_IP } = require('../fixtures');
const { contentLevelWriteError } = require('../helpers/contentLevelWriteError');

function makeDoc(tag) {
  return {
    action: 'login',
    category: 'auth',
    username: `precise_${tag}`,
    userId: new mongoose.Types.ObjectId(),
    ip: TEST_CLIENT_IP,
    result: 'success',
    riskLevel: 'low',
    timestamp: new Date(),
  };
}

/** WAL 里当前留着的行的 username 集合（按内容识别，不按行序） */
async function walTags() {
  await wal.drain();
  const lines = await wal.readLines();
  return lines
    .map((l) => {
      try {
        return JSON.parse(l).username;
      } catch {
        return '<损坏行>';
      }
    })
    .filter(Boolean);
}

describe('审计 WAL 精确裁剪：只裁自己已落库的行（F-97）', () => {
  let insertSpy;
  let intervalSpy;
  let appendSpy;

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) await mongoose.connect(process.env.MONGODB_URI);
  });

  beforeEach(() => {
    auditBuffer.__resetForTest();
    fs.rmSync(process.env.AUDIT_WAL_PATH, { force: true });
    fs.rmSync(process.env.AUDIT_WAL_PATH + '.discarded', { force: true });
    // 轮次由用例显式驱动，后台 tick 不得掺进来
    intervalSpy = jest.spyOn(global, 'setInterval').mockImplementation(() => ({ unref() {} }));
    insertSpy = jest.spyOn(AuditLog, 'insertMany').mockImplementation(() => Promise.resolve());
    auditBuffer.start(); // WAL 启用（__walSeq 只有在启用时才分配）
  });

  afterEach(async () => {
    auditBuffer.stop();
    insertSpy.mockRestore();
    intervalSpy.mockRestore();
    if (appendSpy) appendSpy.mockRestore();
    await AuditLog.deleteMany({ username: /^precise_/ }).catch(() => {});
  });

  afterAll(async () => {
    auditBuffer.__resetForTest();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  test('批次里有文档缺 WAL 行（追加失败）时，裁剪不得吃掉排在后面的未落库记录', async () => {
    // 空洞成因取真实的一条：walAppendLine 的 appendFile 失败只 warn，文档仍进缓冲
    const realAppend = fs.promises.appendFile.bind(fs.promises);
    appendSpy = jest
      .spyOn(fs.promises, 'appendFile')
      .mockImplementation((p, payload, enc) =>
        String(payload).includes('precise_hole')
          ? Promise.reject(new Error('ENOSPC: no space left on device'))
          : realAppend(p, payload, enc)
      );

    auditBuffer.push(makeDoc('hole')); // 行没写成 ⇒ 本批少一行
    auditBuffer.push(makeDoc('b'));

    // flush 同步取走批次（splice 在首个 await 之前），此时再 push 的文档排在批次之后，
    // 其 WAL 行会被追加到文件尾部 ⇒ 正是"前 N 行"判据会越界吃到的那种行
    const running = auditBuffer.flush();
    auditBuffer.push(makeDoc('pending')); // C：本轮不落库，只在缓冲里等下一轮
    await running;

    expect(await AuditLog.countDocuments({ username: 'precise_pending' })).toBe(0);
    // 断言的是**行为**：C 的取证行必须还在（它尚未落库，那是崩溃后唯一的残留）
    expect(await walTags()).toContain('precise_pending');
  });

  test('部分成功时已落库子集的行要回收，且不误伤同批未落库文档的行', async () => {
    const poison = contentLevelWriteError(1);
    // ordered:false 的真实形状：确认写入的在 err.insertedDocs，被拒的在 err.writeErrors[1]
    let batch;
    insertSpy.mockImplementation((docs) => {
      batch = docs;
      const err = poison;
      err.insertedDocs = [docs[0]];
      return Promise.reject(err);
    });

    auditBuffer.push(makeDoc('stored'));
    auditBuffer.push(makeDoc('rejected'));
    await auditBuffer.flush();
    await wal.drain();

    // 死行（已落库）不该继续占着 WAL：它既是噪声，也是下一次裁剪的错位来源
    // 前提自证：两条文档确实在**同一批**里送进 insertMany（否则"同批子集"不成立）
    expect(batch).toHaveLength(2);
    const tags = await walTags();
    expect(tags).toContain('precise_rejected'); // 未落库的必须留着重试
    expect(tags).not.toContain('precise_stored'); // 已落库的必须裁掉
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
