'use strict';

/**
 * F-101：优雅关闭不得把"未排空"报成"已清空"
 *
 * 缺陷（台账 §4.2 [报]，本轮实测坐实）：`flushAndStop()` 原先就是
 * 「await flush(); await wal.drain(); stop()」三行。而 `flush()` 的第一行是
 * `if (flushing || buffer.length === 0) return;` ⇒ **只要关停时恰有一轮定时 flush 在途**
 * （2s 一轮，这是常见时序而不是边角），`await flush()` 立即 resolve 且什么都没做，
 * 函数照常走完，`index.js` 那句 `logger.info('审计日志缓冲已清空')` 就打了出去。
 * 更糟的是紧接着在途那轮失败会把整批 unshift 回缓冲 —— 此时定时器已 clear、
 * WAL 已 disable，这批记录只剩内存副本，进程退出即永久丢失，
 * 而日志里那条"已清空"成了它不存在过的**反向证据**。
 *
 * 七条用例分别钉两侧：
 *  ① 在途 flush 会失败但 DB 随后恢复 ⇒ 关停必须等它、再把它重试的记录刷干净，
 *    并如实返回 `drained:true`（记录**真的在库里**，不是看标志位猜的）；
 *  ② DB 一直不可用 ⇒ 关停必须有界返回、如实报 `drained:false` + 剩余条数，
 *    绝不假装排空（也不能无限等，否则这一步本身变成部署卡死的原因）；
 *  ③ 缓冲本来就空 ⇒ 立刻返回，不为"排空"白等一个预算；
 *  ④ 在途那一批跑到预算耗尽仍未结束（DB 挂住）⇒ 它此刻既不在缓冲也未落库，
 *    只靠 `flush()` 维护的 `inFlightCount` 才能被算进 residual。
 *    这条专门防"只声明计数、却没有在 splice 处记账"的半成品实现——
 *    本轮我就先写过这么一版，①照样绿、谎话照样说。
 *  ⑤（F-103）调用方从关停链总预算里只剩 1ms ⇒ 必须在那儿收手。本模块默认愿意等
 *    2000ms，但那 2000ms 只有在"整条关停链还剩 2000ms"时才成立；无视外部上限就会
 *    让 30s 的部署窗口被前面的步骤吃光后仍在这里等满 ⇒ 进程在 flush 中途被 SIGKILL。
 *    实测：把 `Math.min(FLUSH_DRAIN_BUDGET_MS, hardCeilingMs)` 写成
 *    `FLUSH_DRAIN_BUDGET_MS` 后，①–④ 全绿、⑤ 耗时从 5ms 变 2014ms 而红。
 *
 * ②的预算 `AUDIT_FLUSH_DRAIN_BUDGET_MS` 默认 2000ms（模块加载期读取，故本套件
 * 用默认值，实测耗时应明显小于"预算 + 宽松余量"）。
 *
 * ⑥（F-143）钉的是**排空失败之后的收尾**：批次在 `stop()` 之后才落库成功时，
 * 成功路径原先写着 `if (wal.isEnabled()) wal.trimBySeqs(...)` —— 关停已经
 * `wal.disable()`，于是这一批**确认在库里**的行永远留在 WAL 文件里。留下的代价
 * 不是"文件难看点"：重启后 `start()` 会把它重放进缓冲，而重放文档的 `_id` 是
 * 下一轮 `flush()` 新分配的（WAL 行写于 `push()`，那时还没有 `_id`）——
 * 幂等重放靠的是同一批对象引用存活 `_id`，跨重启不成立 ⇒ **每重启一次就把这个
 * 已存在的批次再插一份**。本仓自己在 `index.js` 的关停注释里就把同类时序写成
 * "重启重放把已落库批次重复插入（B-L2）"，判据一致。
 * 实测：把 `:290` 的 `wal.isEnabled()` 去掉前，①–⑤ 全绿、⑥ 红（行还在）。
 * ⑦ 钉同一函数的第二处闸门（部分成功子集 `storedSeqs`）：只放开一处 = 半个缺陷，
 * 单独把 `:324` 改回 `wal.isEnabled() && storedSeqs.size > 0` 时 ①–⑥ 全绿、⑦ 红。
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const mongoose = require('mongoose');

const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'auditbuf-shutdown-'));
process.env.AUDIT_WAL_PATH = path.join(tmpDir, 'shutdown.wal');
process.env.AUDIT_WAL_MAX_BYTES = '1000000';

const auditBuffer = require('../../services/auditBuffer');
const wal = require('../../services/auditBufferWal');
const AuditLog = require('../../models/AuditLog');
const { TEST_CLIENT_IP } = require('../fixtures');
const { contentLevelWriteError } = require('../helpers/contentLevelWriteError');

function makeDoc(tag) {
  return {
    action: 'login',
    category: 'auth',
    username: `shutdown_${tag}`,
    userId: new mongoose.Types.ObjectId(),
    ip: TEST_CLIENT_IP,
    result: 'success',
    riskLevel: 'low',
    timestamp: new Date(),
  };
}

/** WAL 里当前留着的行的 username 集合（按内容识别，不按行序；先排在串行链上的写落定） */
async function walUsernames() {
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

const realInsertMany = AuditLog.insertMany.bind(AuditLog);

describe('审计缓冲的关停排空（F-101）', () => {
  let insertSpy;
  let intervalSpy;

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) await mongoose.connect(process.env.MONGODB_URI);
  });

  beforeEach(() => {
    auditBuffer.__resetForTest();
    fs.rmSync(process.env.AUDIT_WAL_PATH, { force: true });
    // 轮次/关停全部由用例显式驱动，后台 tick 不得掺进来
    intervalSpy = jest.spyOn(global, 'setInterval').mockImplementation(() => ({ unref() {} }));
  });

  afterEach(async () => {
    auditBuffer.stop();
    auditBuffer.__resetForTest();
    insertSpy.mockRestore();
    intervalSpy.mockRestore();
    await AuditLog.deleteMany({ username: /^shutdown_/ }).catch(() => {});
  });

  afterAll(async () => {
    auditBuffer.__resetForTest();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  test('① 关停时恰有一轮 flush 在途且它失败：必须等它、重试并真的排空（旧实现当场报"已清空"）', async () => {
    let first = true;
    insertSpy = jest.spyOn(AuditLog, 'insertMany').mockImplementation((docs, opts) => {
      if (first) {
        first = false;
        return new Promise((_, reject) =>
          setTimeout(() => reject(new Error('connection was reset')), 40)
        );
      }
      return realInsertMany(docs, opts);
    });

    auditBuffer.start();
    auditBuffer.push(makeDoc('inflight'));

    // 制造"在途"：flush() 同步 splice 并把 flushing 置真，这里**不 await** 它
    const inflight = auditBuffer.flush();
    // 关停与它并发——这正是旧实现说谎的那条时序
    const result = await auditBuffer.flushAndStop();
    await inflight.catch(() => {});

    expect(result).toEqual({ drained: true, residual: 0 });
    // 断言的是行为而不是返回值：记录确实落库了
    expect(await AuditLog.countDocuments({ username: 'shutdown_inflight' })).toBe(1);
    // 正向对照：这条时序里 WAL 还没 disable，裁剪照常发生 ⇒ 证明下面的 ⑥ 不是
    // "helper 读不到行"造成的假红（helper 读不到行时这里也会红）。
    expect(await walUsernames()).not.toContain('shutdown_inflight');
  });

  test('② DB 一直不可用：有界返回、如实报未排空，一条都不许被"报成已落库"', async () => {
    insertSpy = jest.spyOn(AuditLog, 'insertMany').mockImplementation(() => {
      const e = new Error('connection was reset');
      e.name = 'MongoNetworkError';
      return Promise.reject(e);
    });

    auditBuffer.start();
    auditBuffer.push(makeDoc('keep1'));
    auditBuffer.push(makeDoc('keep2'));

    const started = Date.now();
    const { drained, residual } = await auditBuffer.flushAndStop();
    const elapsed = Date.now() - started;

    expect(drained).toBe(false);
    expect(residual).toBe(2); // 两条都还在，一条都没被静默吞掉
    // 预算 2000ms：必须远小于"每次都等满超时"，也不许无限挂住关停
    expect(elapsed).toBeLessThan(5000);
  });

  test('③ 缓冲本来就空：立刻 drained:true，不为"排空"白等一个预算', async () => {
    insertSpy = jest.spyOn(AuditLog, 'insertMany').mockImplementation(() => Promise.resolve([]));
    auditBuffer.start();

    const started = Date.now();
    const result = await auditBuffer.flushAndStop();

    expect(result).toEqual({ drained: true, residual: 0 });
    expect(Date.now() - started).toBeLessThan(1500);
  });

  test('④ 在途批次跑到预算耗尽仍未结束：residual 必须算上"不在缓冲里"的那一批', async () => {
    // 2400ms > 排空预算 2000ms ⇒ flushAndStop 等到超时、在途那轮仍在跑。
    // 这批文档此刻既不在 buffer（splice 已取走）也没落库，只有 `inFlightCount` 知道它们存在。
    let rejectInsert;
    const hang = new Promise((_, reject) => {
      rejectInsert = () =>
        reject(Object.assign(new Error('connection was reset'), { name: 'MongoNetworkError' }));
    });
    const hangTimer = setTimeout(rejectInsert, 2400);
    if (hangTimer.unref) hangTimer.unref();
    insertSpy = jest.spyOn(AuditLog, 'insertMany').mockImplementation(() => hang);

    auditBuffer.start();
    auditBuffer.push(makeDoc('zombie'));
    const inflight = auditBuffer.flush();

    const started = Date.now();
    const { drained, residual } = await auditBuffer.flushAndStop();
    const elapsed = Date.now() - started;

    expect(drained).toBe(false);
    expect(residual).toBe(1); // 少了 inFlightCount 记账，这里会变成 0 ⇒ 又是一句"已排空"
    expect(elapsed).toBeGreaterThanOrEqual(1900); // 确实等满了预算，不是提前放弃
    expect(elapsed).toBeLessThan(4000);

    // 等在途那轮 settle（它的批次会 unshift 回缓冲），否则残留会串到下一个用例
    await inflight.catch(() => {});
    expect(auditBuffer.getStats().bufferLength).toBe(1);
  });

  test('⑤ 调用方给出更小的外部上限（F-103 总预算）：必须在上限处收手并如实报未排空', async () => {
    insertSpy = jest
      .spyOn(AuditLog, 'insertMany')
      .mockImplementation(() =>
        Promise.reject(
          Object.assign(new Error('connection was reset'), { name: 'MongoNetworkError' })
        )
      );

    auditBuffer.start();
    auditBuffer.push(makeDoc('ceil1'));
    auditBuffer.push(makeDoc('ceil2'));

    // 本模块默认愿意等 2000ms，但关停链只剩 1ms ⇒ 取较小值。忽略这个参数的实现会等满 2s。
    const started = Date.now();
    const { drained, residual } = await auditBuffer.flushAndStop(1);
    const elapsed = Date.now() - started;

    expect(drained).toBe(false);
    expect(residual).toBe(2);
    expect(elapsed).toBeLessThan(1000);
    // 收手不等于丢掉：两条还在缓冲里，WAL 行也在磁盘上，重启后由 start() 重放
    expect(auditBuffer.getStats().bufferLength).toBe(2);
  });

  test('⑥ 批次在 stop() 之后才落库成功：它的 WAL 行必须回收（F-143，否则每次重启重复插入一份已存在的审计）', async () => {
    // 真实时序：DB 慢到排空预算用尽（这里用外部上限 1ms 复现），但那一轮 insertMany
    // 其实**成功**了——只是成功得比 deadline 晚。
    let release;
    const hold = new Promise((resolve) => {
      release = resolve;
    });
    insertSpy = jest
      .spyOn(AuditLog, 'insertMany')
      .mockImplementation((docs, opts) => hold.then(() => realInsertMany(docs, opts)));

    auditBuffer.start();
    auditBuffer.push(makeDoc('late'));
    const inflight = auditBuffer.flush();

    const { drained, residual } = await auditBuffer.flushAndStop(1);
    expect(drained).toBe(false);
    expect(residual).toBe(1);
    // 前提自证：这一批的取证行此刻确实还在文件里（未落库时留着是对的）
    expect(await walUsernames()).toContain('shutdown_late');

    release([]);
    await inflight;

    // 记录确实在库里
    expect(await AuditLog.countDocuments({ username: 'shutdown_late' })).toBe(1);
    // 那么它的 WAL 行就必须消失：留着 = 下次 start() 重放进缓冲，而重放文档的 _id
    // 是下一轮 flush 新分配的（WAL 行写于 push，那时还没有 _id）⇒ 幂等性跨重启不成立，
    // 这个已经存在的批次会被再插一份。原先的 `wal.isEnabled()` 闸门在这里为假
    // （stop() 已 disable）⇒ 裁剪被跳过，实测本行红。
    expect(await walUsernames()).not.toContain('shutdown_late');
  });

  test('⑦ 部分成功发生在 stop() 之后：已落库子集的行要回收，未落库的子集要留着重试（F-143 第二处闸门）', async () => {
    // ⑥ 钉的是"整批成功"那条裁剪，这一条钉"部分成功"那条（`storedSeqs`）。
    // 两处原先共用同一个 `wal.isEnabled()` 闸门，去掉一处仍留着另一处 = 半个缺陷。
    let release;
    const hold = new Promise((resolve) => {
      release = resolve;
    });
    insertSpy = jest.spyOn(AuditLog, 'insertMany').mockImplementation((docs) =>
      hold.then(() => {
        const err = contentLevelWriteError(1); // ordered:false 的真实形状：0 写入、1 被内容拒
        err.insertedDocs = [docs[0]];
        return Promise.reject(err);
      })
    );

    auditBuffer.start();
    auditBuffer.push(makeDoc('p_stored'));
    auditBuffer.push(makeDoc('p_rejected'));
    const inflight = auditBuffer.flush();

    const { drained } = await auditBuffer.flushAndStop(1);
    expect(drained).toBe(false); // 关停时这批还没 settle

    release();
    await inflight.catch(() => {});

    const tags = await walUsernames();
    expect(tags).not.toContain('shutdown_p_stored'); // 已确认在库里 ⇒ 留着就是下次重启的重复插入
    expect(tags).toContain('shutdown_p_rejected'); // 未落库 ⇒ 回收它就是审计永久缺失
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
