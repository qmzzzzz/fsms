'use strict';

/**
 * F-104：审计导出的 writeLine 只监听 `drain` ⇒ 客户端中断时整个导出**永久挂住**
 *
 * 缺陷（`src/services/auditExportService.js:65-69`）：
 * ```js
 * const writeLine = (line) => new Promise((resolve) => {
 *   if (res.write(line)) return resolve();
 *   res.once('drain', resolve);        // ← 唯一的出口
 * });
 * ```
 * 客户端关标签页 / 前端 abort() 时，`res.write()` 返回 false 而 `drain` **永不再来**
 * ⇒ 这个 Promise 永不 settle ⇒ `await cursor.eachAsync(...)` 卡在那一步：
 * 路由函数既不返回也不抛错，`auditController.js:60-72` 的 catch 出口（`logger.error`
 * + `markResponseAbortedByError` + `res.end()`）永远走不到。后果不只是"一个挂住的请求"：
 * 服务端游标不关、一次 5 万条量级的导出对着死连接一直占着资源，而且**这条敏感导出
 * 在审计里什么痕迹都不留**（响应收尾的审计包装器根本没被执行）。
 *
 * 实测依据（探针，本地 node 直跑，不依赖本仓代码）：客户端 destroy 之后
 * `drains` 计数纹丝不动（3 → 3，即 parked 的 drain 等待再也没被满足），
 * 而 `res` 上真正到来了两个信号：**写回调收到 error**（cbErrs 0 → 1）与 **`close` 事件**。
 * 现在这两个信号一个都没被观察。
 * ⇒ 三条用例分别按这三个终止信号各钉一条，第四条钉"别把监听器漏成一堆"。
 *
 * 用例 ③（正常 drain 路径）在当前实现下**本来就是绿的**，它是对照组：
 * 修完必须仍然绿，否则说明我把背压处理改坏了。
 */

const { EventEmitter } = require('events');
const mongoose = require('mongoose');

const auditExportService = require('../../services/auditExportService');
const AuditLog = require('../../models/AuditLog');
const { TEST_CLIENT_IP } = require('../fixtures');

const USER = 'abort_probe_user';

/**
 * 造一个"会中断的响应流"。
 * @param {object} signals 哪些终止信号会到来（对应探针实测到的那几种）
 */
function makeRes(signals) {
  const res = new EventEmitter();
  res.setHeader = () => {};
  const state = { writeCalls: 0, drainEmits: 0 };
  res.state = state;
  res.write = (line, cb) => {
    state.writeCalls += 1;
    if (state.writeCalls === 1 && signals.afterFirstWrite) signals.afterFirstWrite(res, cb);
    // 永远报背压：不这样就无法把"只等 drain"的实现逼进挂死状态
    return false;
  };
  return res;
}

/** 挂起判定：p 在 ms 内 settle 返回 'resolved'/'rejected'，否则返回 'hang'。 */
function settleWithin(p, ms) {
  return Promise.race([
    p.then(
      () => 'resolved',
      () => 'rejected'
    ),
    new Promise((resolve) => {
      const t = setTimeout(() => resolve('hang'), ms);
      t.unref();
    }),
  ]);
}

function makeDoc(seq, prefix = USER) {
  return {
    action: 'login',
    category: 'auth',
    username: `${prefix}_${seq}`,
    userId: new mongoose.Types.ObjectId(),
    ip: TEST_CLIENT_IP,
    result: 'success',
    riskLevel: 'low',
    timestamp: new Date(2026, 8, 20, 10, 0, seq),
    hash: `hash_${seq}`,
  };
}

describe('审计导出在中断的连接上必须收手（F-104）', () => {
  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) await mongoose.connect(process.env.MONGODB_URI);
    await AuditLog.deleteMany({ username: new RegExp(`^${USER}_`) }, { bypassAppendOnly: true });
    await AuditLog.insertMany([makeDoc(1), makeDoc(2)]);
  });

  afterAll(async () => {
    await AuditLog.deleteMany({ username: new RegExp(`^${USER}`) }, { bypassAppendOnly: true });
  });

  // 精确点名两条，不用前缀正则：用例 ⑤ 会往同一集合里塞 60 条同前缀的 bulk 文档，
  // 而 `--randomize` 下它可能先于本组执行（顺序不能影响判定）。
  const query = { username: { $in: [`${USER}_1`, `${USER}_2`] } };

  // F-107：本组①–③ 都靠"write() 恒返回 false"把实现逼进背压窗口，
  // 可真实导出里单行约 200 B、远小于 16 KB highWaterMark ⇒ write() 几乎恒为 true，
  // **逐行**挂的 close/error 监听器在绝大多数行压根没挂上。
  // 这条就是钉那一侧：没有任何背压、只有断连，导出也必须收手。
  test('⑥ write() 恒返回 true（无背压）而连接中途断开：导出仍必须以错误收手', async () => {
    const res = new EventEmitter();
    res.setHeader = () => {};
    const state = { writeCalls: 0 };
    res.write = () => {
      state.writeCalls += 1;
      // 第 1 行"写成功"之后连接才断：信号只能落在下一次写的起点上
      if (state.writeCalls === 1) process.nextTick(() => res.emit('close'));
      return true;
    };

    await expect(auditExportService.streamAuditExport(query, res)).rejects.toThrow(/中途断开/);
    // 关键：不得继续把剩下的行写进已死的 socket
    expect(state.writeCalls).toBe(1);
  });

  test('① 客户端消失后只来 `close`（永不 drain）：导出必须以错误收手，而不是挂住', async () => {
    const res = makeRes({
      afterFirstWrite: (r) => {
        setTimeout(() => r.emit('close'), 10).unref();
      },
    });

    const verdict = await settleWithin(auditExportService.streamAuditExport(query, res), 800);

    expect(verdict).toBe('rejected');
    // 收手 = 不再往下写：第二行根本没尝试过
    expect(res.state.writeCalls).toBe(1);
  });

  test('② 只有写回调报错（`close` 还没到）：同样必须收手', async () => {
    const res = makeRes({
      afterFirstWrite: (r, cb) => {
        setTimeout(() => {
          const err = new Error('write ECONNRESET');
          err.code = 'ECONNRESET';
          cb(err);
        }, 10).unref();
      },
    });

    const verdict = await settleWithin(auditExportService.streamAuditExport(query, res), 800);

    expect(verdict).toBe('rejected');
    expect(res.state.writeCalls).toBe(1);
  });

  test('③ `error` 事件也是终止信号：不得继续等 drain', async () => {
    const res = makeRes({
      afterFirstWrite: (r) => {
        setTimeout(() => r.emit('error', new Error('socket hang up')), 10).unref();
      },
    });

    const verdict = await settleWithin(auditExportService.streamAuditExport(query, res), 800);

    expect(verdict).toBe('rejected');
  });

  test('④ 对照：真有 drain 时两行都要写完并正常 resolve（修完不得改坏背压路径）', async () => {
    const res = new EventEmitter();
    res.setHeader = () => {};
    let writeCalls = 0;
    res.write = (line, cb) => {
      writeCalls += 1;
      // 模拟健康的背压循环：下一拍 drain
      setTimeout(() => {
        if (cb) cb(null);
        res.emit('drain');
      }, 0).unref();
      return false;
    };

    const counters = await auditExportService.streamAuditExport(query, res);

    expect(counters.recordCount).toBe(2);
    expect(writeCalls).toBe(2);
  });

  test('⑤ 每一行都要收掉自己的监听器：持续背压下也不得攒出一堆 drain/close', async () => {
    const BULK = 60;
    const BULK_PREFIX = `${USER}_bulk`;
    const bulkDocs = Array.from({ length: BULK }, (_, i) => makeDoc(i, BULK_PREFIX));
    await AuditLog.insertMany(bulkDocs);

    const res = new EventEmitter();
    res.setMaxListeners(500); // 泄漏时让它安静地涨，由断言判定，不靠 MaxListeners 警告
    res.setHeader = () => {};
    let parked = false;
    res.write = () => {
      if (parked) return true;
      parked = true;
      setTimeout(() => {
        parked = false;
        res.emit('drain');
      }, 0).unref();
      return false;
    };

    const counters = await auditExportService.streamAuditExport(
      { username: new RegExp(`^${BULK_PREFIX}_`) },
      res
    );
    expect(counters.recordCount).toBe(BULK);

    // 每个事件上最多只留一份"当前这一行"的等待者；残留 ⇒ 结算时没摘监听器
    expect(res.listenerCount('drain')).toBeLessThanOrEqual(1);
    expect(res.listenerCount('close')).toBeLessThanOrEqual(1);
    expect(res.listenerCount('error')).toBeLessThanOrEqual(1);

    await AuditLog.deleteMany(
      { username: new RegExp(`^${BULK_PREFIX}_`) },
      { bypassAppendOnly: true }
    );
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
