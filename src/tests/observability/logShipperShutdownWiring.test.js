'use strict';

/**
 * F-186：SIEM 转发缓冲的排空必须**真的接在关停链上**
 *
 * 【缺陷】`HttpShipperTransport.close()`（P3-31 + F-98：按批排空、有界退出、如实报剩余
 * 行数）在生产里**没有任何调用点** ⇒ 关停时缓冲里最多 `BUFFER_CAP` 行日志一行都不送达
 * SIEM，而且**无声**（丢的恰恰是"为什么要关闭 / 为什么崩"那几行）。F-98 那三条用例全绿，
 * 测的却是一个没人调用的方法——⑤⑥ 钉"接上了"，⑦⑧ 钉"接上的是对的东西"。
 *
 * 【机制：本文件初版在这里写错过，两支独立探针实测后纠正】
 * 初版断言"`Logger.end()` 只对各 transport 调 `end()`，而 `close()` 挂在 'unpipe' 上，
 * 所以 end() 够不到 close()"。推断**错在只读到 winston 那一层就收尾**：
 *   `_final()` 调 `transport.end()`（winston/lib/winston/logger.js:350-361）
 *   → transport 发 'finish'
 *   → readable-stream 的 pipe 收尾 `onfinish` → `src.unpipe(dest)`
 *     （readable-stream/lib/_stream_readable.js:656-670，注释原文
 *      "Both close and finish should trigger unpipe, but only once."）
 *   → winston-transport 的 `once('unpipe')` → `close()`（modern.js:40-54）。
 * 实测：closeCalled=1、unpipes=1、finishes=1、25/25 送达。⇒ 台账里对侧 F-98 那句
 * "logger.end() 确实会走到 close()"**是对的**，我先前那句"读源码否证"才是要撤回的。
 * 但缺陷判定不变，因为两条各自独立的理由：
 *   (a) end() 只**触发**不**等待**：同一夹具（25 行、每批 40ms 网络延迟）end() 之后立刻
 *       process.exit() 只送达 5/25，等 100ms 送达 15/25，200ms 才全量——能不能送到取决于
 *       end() 之后进程还活多久，而且没有任何一处报"这一轮丢了几行"；
 *   (b) F-187 删掉了生产里唯一的 end() 调用点（end() 之后再打任意一条日志都同步抛
 *       ERR_STREAM_WRITE_AFTER_END，对落盘零收益）⇒ 今天的树上 'unpipe' 永不发生。
 * 所以准确的表述是：close() 过去只被"顺带且不等待"地触发，现在由关停链**显式 await、
 * 有预算、如实报数**。⑦ 钉 (a)，⑧ 钉 (b)。
 *
 * 【本文件各用例的分工】
 *   ① 排空确实发生：5 行分 3 批全送达 + 定时器被摘（`timer === null` 是 close() 的
 *      可观察副作用，`_flush` 不碰它）；
 *   ② 预算钳制是真的：同一夹具，allowMs=30 ⇒ 'over-budget' 且缓冲没清空；
 *      allowMs=5000 ⇒ 'drained' 且全送达（N0，证明 ① 的送达能力不是被竞速路径伪造的）；
 *   ③ 未启用转发是常态：无 shipper transport ⇒ 'no-shipper'，不抛错；
 *      且**不会**去关别人的 close()（instanceof 精确性——否则会误关文件 transport）；
 *   ④ 排空异常 ⇒ 'failed'（不 unhandledRejection、不静默）；
 *   ⑤ 优雅关闭那一步源码（代码视图）确实调用排空 helper 一次，并用"把调用注释掉"的反例
 *      证明这条闸不被注释骗过（同 F-145 的口径）；
 *   ⑥ 两条崩溃链也各自接了（F-186b：只有优雅关闭有＝台账 L 项只修一半），且 tag 对得上；
 *   ⑦ 行为面（探针实测的用例化）：`logger.end()` **确实**触发 close()（可达性＝对侧的观测），
 *      但不等它 ⇒ 后端稍慢时一条都没送达；只有显式 await 排空才全量；
 *   ⑧ 门禁面：生产源码（注释遮蔽后的代码视图，全仓非测试 js）里 `logger.end(` 出现 0 次
 *      ⇒ 这个显式排空是 close() 的唯一触发点；注入一处真调用 ⇒ 计数 1（证明闸不是空转）。
 *
 * 【F-186b】台账 §L 项「异常路径不 flush 日志转发缓冲」原本只被半修：优雅关闭接了排空，
 * `uncaughtException` / `unhandledRejection` 仍是 `auditBuffer.flush()` + 1 s 后 exit。
 * 崩溃那一刻的日志最需要进 SIEM（"为什么崩"的证据就在最后几行里），所以现在三条退出
 * 路径共用同一个 helper（`bestEffortDrain`）与同一套结果口径；下面第二个 describe
 * 钉的是"结果口径"本身，①–④ 钉的是"排空能力"。
 */

// 构造期起的 interval 捕获不执行：本套件要测的是"由关停排空"，
// 不是"由定时器等到排空"（周期取 600 s，本来就等不到；这里 mock 是为了不留真定时器）
const intervalSpy = jest.spyOn(global, 'setInterval').mockImplementation(() => ({
  unref: jest.fn(),
}));

const fs = require('fs');
const path = require('path');

const { HttpShipperTransport } = require('../../utils/logShipper');
const { drainShippingBuffer, bestEffortDrain } = require('../../utils/loggerFlush');

const REPO_ROOT = path.join(__dirname, '..', '..', '..');

afterAll(() => intervalSpy.mockRestore());

function makeTransport(overrides = {}) {
  return new HttpShipperTransport({
    url: 'http://127.0.0.1:59999/logs',
    batchSize: 2,
    intervalMs: 600000,
    timeoutMs: 300,
    ...overrides,
  });
}

/** 与 utils/loggerFlush.js 的判定同源的"是不是我们的 transport"探针 */
function hasShipper(t) {
  return t instanceof HttpShipperTransport;
}

/**
 * 与 shutdownBudgetContract.test.js 的 F-145 同一口径：判定只跑"只剩代码"的视图，
 * 否则在注释里写一句调用就能把"删掉这一步"骗绿。
 */
function jsCodeOnly(src) {
  return src
    .replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, ' '))
    .split('\n')
    .filter((l) => !/^\s*\/\//.test(l))
    .map((l) => l.replace(/\/\/[^\n]*/g, ' '))
    .join('\n');
}

const readIndex = () => fs.readFileSync(path.join(REPO_ROOT, 'src/index.js'), 'utf8');
const countCalls = (text) => (text.match(/bestEffortDrain\(/g) || []).length;

describe('关停链排空 SIEM 转发缓冲（F-186）', () => {
  let errSpy;
  beforeEach(() => {
    errSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
  });
  afterEach(() => errSpy.mockRestore());

  test('① 后端可用：close() 被 await，全部批次送达且定时器被摘', async () => {
    const t = makeTransport();
    const sent = [];
    t._post = async (batch) => {
      sent.push([...batch]);
    };
    for (let i = 0; i < 5; i += 1) t.buffer.push(`line-${i}`);
    expect(t.timer).not.toBeNull(); // 前提：构造期确实起了定时器

    await expect(drainShippingBuffer({ logger: { transports: [t] } })).resolves.toBe('drained');

    expect(sent.flat()).toEqual(['line-0', 'line-1', 'line-2', 'line-3', 'line-4']);
    expect(sent).toHaveLength(3); // 2+2+1：排空，不是"恰好一批装得下"
    expect(t.buffer).toHaveLength(0);
    expect(t.timer).toBeNull(); // 只有 close() 会摘掉它 ⇒ 被调用的确实是 close()
    expect(errSpy).not.toHaveBeenCalled();
  });

  test('② 关停预算：给不够就如实报 over-budget（且一行都没送达），给够则 drained', async () => {
    // —— 预算不足的臂：_post 卡在门闩上，30 ms 的额度必然先到期
    const slow = makeTransport();
    const sent = [];
    let release;
    const gate = new Promise((resolve) => {
      release = resolve;
    });
    slow._post = async (batch) => {
      await gate;
      sent.push([...batch]);
    };
    for (let i = 0; i < 4; i += 1) slow.buffer.push(`s${i}`);

    await expect(
      drainShippingBuffer({ logger: { transports: [slow] }, allowMs: 30 })
    ).resolves.toBe('over-budget');
    // 判据用"送达"而不是"缓冲长度"：_flush 先 splice 出本批再 await _post
    // （logShipper.js:212-214），所以在途那批此刻已经不在缓冲里了。
    expect(sent).toHaveLength(0);

    // 收尾：放行那次被放弃的排空，证明放弃不留半成品状态（也避免跨用例悬挂）
    release();
    for (let i = 0; i < 60 && sent.flat().length < 4; i += 1) {
      await new Promise((r) => setTimeout(r, 20));
    }
    expect(sent.flat()).toEqual(['s0', 's1', 's2', 's3']);

    // —— N0 控制臂：同一夹具、同一调用形状，只是额度给够 ⇒ 必须 drained 且全送达。
    //    没有这条，② 的 'over-budget' 可能来自"排空本身坏了"而不是预算钳制。
    const fast = makeTransport();
    const sentFast = [];
    fast._post = async (batch) => {
      sentFast.push([...batch]);
    };
    for (let i = 0; i < 4; i += 1) fast.buffer.push(`f${i}`);
    await expect(
      drainShippingBuffer({ logger: { transports: [fast] }, allowMs: 5000 })
    ).resolves.toBe('drained');
    expect(sentFast.flat()).toEqual(['f0', 'f1', 'f2', 'f3']);
  });

  test('③ 未启用转发：返回 no-shipper，且绝不误关别的 transport', async () => {
    expect(hasShipper(makeTransport())).toBe(true); // 前提：instanceof 判据成立

    let closed = 0;
    const other = {
      close: async () => {
        closed += 1;
      },
    }; // 形状相同但不是 shipper
    await expect(drainShippingBuffer({ logger: { transports: [other] } })).resolves.toBe(
      'no-shipper'
    );
    expect(closed).toBe(0); // 盲关 close() 会把文件 transport 一起关掉

    // transports 缺失/为空都不能抛（生产默认没有 LOG_SHIPPING_URL）
    await expect(drainShippingBuffer({ logger: {} })).resolves.toBe('no-shipper');
    await expect(drainShippingBuffer({ logger: { transports: [] } })).resolves.toBe('no-shipper');
  });

  test('④ close() 抛错 ⇒ failed，且不留 unhandledRejection', async () => {
    const t = makeTransport();
    t.close = async () => {
      throw new Error('shipper 内部炸了');
    };
    await expect(drainShippingBuffer({ logger: { transports: [t] }, allowMs: 5000 })).resolves.toBe(
      'failed'
    );
    expect(errSpy.mock.calls.map((c) => c.join(' ')).join('\n')).toContain('排空失败');
  });

  test('⑤ 关停链源码确实接了这一步（代码视图，注释骗不过）', () => {
    const regionOf = (view) => {
      const from = view.indexOf('const gracefulShutdown');
      const to = view.indexOf('const startServer');
      expect(from).toBeGreaterThan(-1);
      expect(to).toBeGreaterThan(from);
      return view.slice(from, to);
    };

    const raw = readIndex();
    expect(countCalls(regionOf(jsCodeOnly(raw)))).toBe(1);

    // 反例：把调用注释掉（文本视图里字样还在 ⇒ 纯文本闸会被骗绿；代码视图归零 ⇒ 抓住）
    const unwired = raw.replace('await bestEffortDrain({', 'await /* bestEffortDrain( */ 不接线({');
    expect(unwired).not.toBe(raw);
    expect(countCalls(regionOf(unwired))).toBe(1);
    expect(countCalls(regionOf(jsCodeOnly(unwired)))).toBe(0);

    // 预算口径：这一步向链尾剩余额度领时间（不越 F-103 总预算）
    const codeRegion = regionOf(jsCodeOnly(raw));
    expect(codeRegion).toMatch(/bestEffortDrain\(\{[\s\S]{0,120}?stepAllowMs\(0\)/);
    // 可达性：调用必须挂在 runStep 的清理步骤里，而不是"写在链上但没人走到的分支"
    expect(codeRegion).toMatch(/runStep\([\s\S]{0,160}?await bestEffortDrain\(/);
  });

  test('⑥ 两条崩溃链也各自接了排空（F-186b：只有优雅关闭有＝台账 L 项只修一半）', () => {
    const codeView = jsCodeOnly(readIndex());
    // 1（优雅关闭）+ 2（uncaughtException / unhandledRejection）
    expect(countCalls(codeView)).toBe(3);

    const handlerSlice = (tag) => {
      const from = codeView.indexOf(`process.on('${tag}'`);
      expect(from).toBeGreaterThan(-1);
      const next = codeView.indexOf('process.on(', from + 12);
      return codeView.slice(from, next > -1 ? next : codeView.length);
    };
    for (const tag of ['uncaughtException', 'unhandledRejection']) {
      // tag 必须对得上：只保证"调用了"会让复制粘贴的两个 handler 共用一个 tag，
      // 崩溃时看不出是哪条链报的。
      expect(handlerSlice(tag)).toMatch(
        new RegExp(`bestEffortDrain\\(\\{[^)]*tag:\\s*'${tag}'`),
        `${tag} 的崩溃链没接排空（或 tag 写错）`
      );
    }

    // 反例：注释掉其中一条 ⇒ 代码视图 3→2，而文本视图仍是 3（字样还在括号还在，
    // 只是被包进块注释里）——这正是"纯文本闸会被骗绿"的那个形状。
    const half = readIndex().replace(
      ".then(() => bestEffortDrain({ allowMs: CRASH_DRAIN_BUDGET_MS, tag: 'uncaughtException' }))",
      '.then(() => /* bestEffortDrain( */ undefined)'
    );
    expect(half).not.toBe(readIndex());
    expect(countCalls(jsCodeOnly(half))).toBe(2);
    expect(countCalls(half)).toBe(3);
  });

  test('⑦ logger.end() 触发 close() 却不等它 ⇒ 单靠 end() 不保证送达（探针实测的用例化）', async () => {
    const winston = require('winston');
    const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
    const t = makeTransport({ batchSize: 5 });
    const sent = [];
    let inFlight = 0;
    let release;
    const gate = new Promise((r) => {
      release = r;
    });
    t._post = async (batch) => {
      inFlight += batch.length; // 在途：已 splice 出缓冲、还没送达
      await gate;
      inFlight -= batch.length;
      sent.push([...batch]);
    };
    let closeCalls = 0;
    const realClose = t.close.bind(t);
    t.close = async (...a) => {
      closeCalls += 1;
      return realClose(...a);
    };
    const logger = winston.createLogger({ level: 'info', transports: [t] });
    const accounted = () => t.buffer.length + inFlight + sent.flat().length;

    try {
      for (let i = 0; i < 12; i += 1) logger.info(`e${i}`);
      // 行是异步流过 pipe-chain 的：先等 12 行全部到达 transport 侧，
      // 否则下面测的是"根本没东西可排"，closeCalls 与 sent 都不成立。
      for (let i = 0; i < 100 && accounted() < 12; i += 1) await sleep(10);
      expect(accounted()).toBe(12); // 前提自证（缓冲 + 在途 + 已送达 = 写入总数）

      logger.end();
      for (let i = 0; i < 100 && closeCalls === 0; i += 1) await sleep(10);

      // 可达性：end() 经 'finish' → pipe 收尾的 'unpipe' 确实调到了 close()（对侧 F-98 的观测）
      expect(closeCalls).toBe(1);
      // 不等待：_post 还被门闩卡着 ⇒ 一条都没送达。真实关停里这就是"看运气"——
      // end() 之后进程多活 200ms 就全送，立刻 exit 就只剩 5/25，而且无人报数。
      expect(sent).toHaveLength(0);
      expect(accounted()).toBe(12);
      // 顺带实测的另一面：'unpipe' 会把 transport 从 logger 上摘掉 ⇒ "事后补排空"连对象都
      // 找不到（drainShippingBuffer 只能按 transports 认人）。排空必须显式接在关停链里。
      expect(logger.transports).toHaveLength(0);

      release();
      await expect(
        drainShippingBuffer({ logger: { transports: [t] }, allowMs: 5000 })
      ).resolves.toBe('drained');
      // 送达的是序列化后的行（①–④ 直接往 buffer 里塞裸字符串，绕过了这一步；
      // 这里从 logger.info 灌进去，所以按 payload 比对，不比字节）
      const got = sent
        .flat()
        .map((l) => JSON.parse(l).message)
        .sort();
      expect(got).toEqual(Array.from({ length: 12 }, (_, i) => `e${i}`).sort());
      expect(closeCalls).toBe(2); // 显式排空＝第二次 close()；两次并发排空不丢行也不重复（上面的多重集比对）
    } finally {
      release();
    }
  });

  test('⑧ 生产源码零 logger.end() 调用点（F-187 不变量）⇒ 显式排空是 close() 的唯一触发', () => {
    const files = [];
    const walk = (dir) => {
      for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
        const p = path.join(dir, entry.name);
        if (entry.isDirectory()) {
          if (entry.name !== 'tests') walk(p);
        } else if (entry.name.endsWith('.js')) files.push(p);
      }
    };
    walk(path.join(REPO_ROOT, 'src'));
    expect(files.length).toBeGreaterThan(50); // 前提：真的扫了整个 src，不是走了个空目录

    const count = (text) => (text.match(/\blogger\.end\s*\(/g) || []).length;
    const codeView = files.map((f) => jsCodeOnly(fs.readFileSync(f, 'utf8'))).join('\n');
    expect(count(codeView)).toBe(0);

    // 反例一：注入一处真调用 ⇒ 代码视图 +1（证明这条闸看得见 token，不是在数空气）
    const raw = readIndex();
    const textBase = count(raw); // 生产文件自己的注释里就写着 logger.end()，故文本视图本就不为 0
    const injected = raw.replace(
      'return exitAfterFlush(0',
      'logger.end();\n  return exitAfterFlush(0'
    );
    expect(injected).not.toBe(raw);
    expect(count(jsCodeOnly(raw))).toBe(0);
    expect(count(jsCodeOnly(injected))).toBe(1);
    // 反例二：同样的字样只出现在注释里 ⇒ 文本视图 +1 而代码视图仍是 0（F-145 口径的另一半）
    const commented = raw.replace(
      'return exitAfterFlush(0',
      '// logger.end(\n  return exitAfterFlush(0'
    );
    expect(count(commented)).toBe(textBase + 1);
    expect(count(jsCodeOnly(commented))).toBe(0);
  });
});

describe('bestEffortDrain 的结果口径（F-186b）', () => {
  let errSpy;
  beforeEach(() => {
    errSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
  });
  afterEach(() => errSpy.mockRestore());

  const makeLogger = (t) => ({
    transports: [t],
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
  });

  /** 卡住的 transport：_post 永不 resolve ⇒ 只能靠 allowMs 到期 */
  function stuckTransport() {
    const t = makeTransport();
    t._post = () => new Promise(() => {});
    for (let i = 0; i < 3; i += 1) t.buffer.push(`x${i}`);
    return t;
  }

  test('ⓐ 预算不足 ⇒ warn 里带真实额度数字，且返回 over-budget', async () => {
    const logger = makeLogger(stuckTransport());
    await expect(bestEffortDrain({ logger, allowMs: 20, tag: '优雅关闭' })).resolves.toBe(
      'over-budget'
    );
    expect(logger.warn.mock.calls.flat().join(' ')).toContain('未在 20ms 内排空');
    expect(logger.info).not.toHaveBeenCalled();
    expect(logger.error).not.toHaveBeenCalled();
  });

  test('ⓑ 成功：reportDrained 才写 info；崩溃路径（默认）保持静默', async () => {
    const mk = () => {
      const t = makeTransport();
      t._post = async () => {};
      t.buffer.push('a');
      return t;
    };
    const quiet = makeLogger(mk());
    await expect(bestEffortDrain({ logger: quiet, allowMs: 5000 })).resolves.toBe('drained');
    expect(quiet.info).not.toHaveBeenCalled();
    expect(quiet.warn).not.toHaveBeenCalled();

    const loud = makeLogger(mk());
    await expect(
      bestEffortDrain({ logger: loud, allowMs: 5000, tag: '优雅关闭', reportDrained: true })
    ).resolves.toBe('drained');
    expect(loud.info.mock.calls.flat().join(' ')).toContain('优雅关闭：SIEM 日志转发缓冲已排空');
  });

  test('ⓒ 未启用转发 ⇒ 静默 no-shipper（生产默认形态，不得每次关停一条日志）', async () => {
    const logger = makeLogger({ close: async () => {} });
    await expect(bestEffortDrain({ logger, allowMs: 5000, reportDrained: true })).resolves.toBe(
      'no-shipper'
    );
    expect(logger.info).not.toHaveBeenCalled();
    expect(logger.warn).not.toHaveBeenCalled();
    expect(logger.error).not.toHaveBeenCalled();
  });

  test('ⓓ 报结果用的 logger 自己抛 ⇒ 不 reject，退回 stderr（F-187 的抛点是日志语句本身）', async () => {
    const t = stuckTransport();
    const logger = {
      transports: [t],
      warn: () => {
        throw new Error('ERR_STREAM_WRITE_AFTER_END');
      },
    };
    await expect(bestEffortDrain({ logger, allowMs: 20, tag: 'uncaughtException' })).resolves.toBe(
      'over-budget'
    );
    const logged = errSpy.mock.calls.map((c) => c.join(' ')).join('\n');
    expect(logged).toContain('未在 20ms 内排空');
    expect(logged).toContain('ERR_STREAM_WRITE_AFTER_END');
  });

  test('ⓔ 连 logger 都取不到 ⇒ 兜住成 failed，绝不把异常抛回崩溃链', async () => {
    const opts = { allowMs: 5000, tag: 'unhandledRejection' };
    Object.defineProperty(opts, 'logger', {
      get() {
        throw new Error('模块加载失败');
      },
    });
    await expect(bestEffortDrain(opts)).resolves.toBe('failed');
    expect(errSpy.mock.calls.map((c) => c.join(' ')).join('\n')).toContain('模块加载失败');
  });
});
