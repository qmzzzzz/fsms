/**
 * 审计 WAL 大小硬上限测试（报告 R-6）
 *
 * 背景：WAL 行仅在 flush 落库成功后前缀裁剪，DB 长时间不可用且高流量时
 * WAL 持续增长（磁盘写放大）。现增加 AUDIT_WAL_MAX_BYTES 硬上限：
 * 超限丢弃最旧一半行并告警（walDroppedLines 计数可观测）。
 *
 * 2026-09-25 追加（F-146）：同一对 catch 上的**计数口径**也要钉住——
 * `walAppendFailures` 只表示"这一行没落盘"，上限裁剪自己的失败（stat/writeFile/rename）
 * 不得混进来。此前两处失败汇在同一个 catch 里，面板上分不清"磁盘写不进"和"裁剪抽查出错"；
 * 而"抽查出错"会被报成"取证记录没落盘"，是一次假告警（合规口径上同样有害）。
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const { TEST_CLIENT_IP } = require('../fixtures');
const logger = require('../../utils/logger');

describe('审计 WAL 大小硬上限（R-6）', () => {
  let tmpDir;
  let defaultWalPath;
  let auditBuffer;
  let wal;

  beforeAll(() => {
    // AUDIT_WAL_PATH 在模块加载时求值，必须先于 require 设置；
    // getWalMaxBytes / getWalStatInterval 运行期读 env，注入小阈值
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'audit-wal-cap-'));
    process.env.AUDIT_WAL_PATH = path.join(tmpDir, 'test-audit.wal');
    defaultWalPath = process.env.AUDIT_WAL_PATH;
    process.env.AUDIT_WAL_MAX_BYTES = '200';
    // B-I1：stat 节流默认每 32 次追加抽查一次——本套件只 push 10 条，
    // 注入 1 恢复逐条检查，使上限裁剪在套件内可见
    process.env.AUDIT_WAL_STAT_INTERVAL = '1';
    auditBuffer = require('../../services/auditBuffer');
    wal = require('../../services/auditBufferWal');
  });

  afterEach(() => {
    // 上面两个新用例各自桩掉 fs.promises 的一个方法；不还原会顺着 require 缓存
    // 漏给后面的用例（本仓 jest 全量跑时同一模块实例贯穿整个套件）。
    jest.restoreAllMocks();
    // 换过文件的用例把路径还给默认值：AUDIT_WAL_PATH 是运行期读的，不还原的话
    // 随机顺序下排在本文件第一个用例就会写到别人的文件里。
    process.env.AUDIT_WAL_PATH = defaultWalPath;
    auditBuffer.stop();
  });

  afterAll(() => {
    auditBuffer.stop();
    try {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    } catch (_) {
      /* 忽略 */
    }
  });

  test('WAL 超限后丢弃最旧行且文件不再无界增长', async () => {
    auditBuffer.__resetForTest();
    auditBuffer.start(); // 开启 walEnabled

    // 上限 200 字节、单行实测 116~117 字节（见下），10 行远超上限 ⇒ enforceWalLimit 多次触发
    for (let i = 0; i < 10; i++) {
      auditBuffer.push({
        action: 'wal_cap_test',
        category: 'auth',
        ip: TEST_CLIENT_IP,
        success: true,
        seq: i,
      });
    }

    // enforcement 在 walChain 上异步执行：轮询等待丢弃计数器推进
    const deadline = Date.now() + 5000;
    while (auditBuffer.getStats().walDroppedLines === 0 && Date.now() < deadline) {
      // walChain 链式任务在微任务/IO 后推进，让出事件循环
      await new Promise((r) => setTimeout(r, 50));
    }
    // 必须排干整条链再量：轮询只等到"第一次丢弃"，此时后面几次追加还排在 walChain 上。
    // 实测（2026-09-26 全量并行跑）：stat 抓到过链中途的 348 字节，而同一条用例单独跑
    // 4/4 绿 ⇒ 那次红是判据在测"还没落盘的写入"，不是上限语义变了。
    // 排干后残留 1 行；文件字节数随 `__walSeq` 计数器位数在 116~117 之间浮动（实测两种都出现过），
    // walDroppedLines 在同 worker 内为 5~9（用例随机顺序 + 追加计数不对齐）⇒ 这些都是交错量，
    // 不能钉；能钉的只有"排干之后文件必然仍在上界之内"。
    await wal.drain();

    const stats = auditBuffer.getStats();
    expect(stats.walDroppedLines).toBeGreaterThan(0);

    // 文件存在且受控（保留一半语义下允许上限 + 单行容差）。
    // 不放宽这条界：320 一字未动，"丢弃最旧一半行"的产品语义也没动（那是 R-6 有意为之）。
    // 余量从 203 字节起（实测残留 1 行、116~117 字节），且来自上一行的 drain 而不是把界放大——
    // 链没排干时同一个 stat 抓到过 348，那才是原来 phantom-red 的来源。
    const size = fs.statSync(process.env.AUDIT_WAL_PATH).size;
    expect(size).toBeLessThanOrEqual(200 + 120);

    // 残留行均为合法 JSON（丢弃按整行进行，不产生残缺行）
    const lines = fs.readFileSync(process.env.AUDIT_WAL_PATH, 'utf8').split('\n').filter(Boolean);
    expect(lines.length).toBeGreaterThan(0);
    for (const line of lines) {
      expect(() => JSON.parse(line)).not.toThrow();
    }
  });

  test('getStats 暴露 walDroppedLines（合规可观测）', () => {
    // 顺序无关（自包含）：walEnabled 由 start() 开启、stop() 关闭。原用例依赖
    // 前一用例先调用过 start()，随机顺序下本用例先跑时实得 false。
    // 这里显式走「关 → 开」两个方向，不再依赖任何前序用例。
    auditBuffer.stop();
    expect(auditBuffer.getStats().walEnabled).toBe(false);
    auditBuffer.start();
    const stats = auditBuffer.getStats();
    expect(stats).toHaveProperty('walDroppedLines');
    expect(stats.walEnabled).toBe(true);
  });

  test('appendFile 失败逐条计入 walAppendFailures，且内存副本仍在（计数≠已丢）', async () => {
    // 独占 WAL 文件：wal.startup 每次 start() 重读 AUDIT_WAL_PATH，换名即换文件。
    // 实测：与前面用例共用同一个 wal 文件时，这里的计数是 4 而不是 2（用例顺序随机 ⇒
    // 是否踩到取决于前面有没有人先跑过），"2 次 push ⇒ 2 次失败"这个前提就不成立了。
    auditBuffer.stop();
    await wal.drain(); // 上一用例的链上操作打的是旧路径，先排干再换文件
    auditBuffer.__resetForTest();
    process.env.AUDIT_WAL_PATH = path.join(tmpDir, 'append-fail.wal');
    auditBuffer.start();
    const warnSpy = jest.spyOn(logger, 'warn').mockImplementation(() => {});
    jest.spyOn(fs.promises, 'appendFile').mockImplementation(async () => {
      throw new Error('ENOSPC: no space left on device');
    });

    for (let i = 0; i < 2; i++) {
      auditBuffer.push({
        action: 'wal_append_fail',
        category: 'auth',
        ip: TEST_CLIENT_IP,
        success: true,
        seq: i,
      });
    }
    await wal.drain();

    const stats = auditBuffer.getStats();
    expect(stats.walAppendFailures).toBe(2);
    // 崩溃保护层失效 ≠ 记录已丢：文档还在缓冲里，落库成功就无损
    expect(stats.bufferLength).toBe(2);
    const logged = warnSpy.mock.calls.map((c) => c.join(' ')).join('\n');
    expect(logged).toContain('审计 WAL 追加失败');
    expect(logged).toContain('ENOSPC');
    // 留痕带**累计**数：单条日志只说本次，运维要能看出这个进程已经写不进多少次
    expect(logged).toContain('累计 2 次');
  });

  test('口径隔离：上限裁剪自己的失败不得计成"追加失败"', async () => {
    auditBuffer.stop();
    await wal.drain();
    auditBuffer.__resetForTest();
    process.env.AUDIT_WAL_PATH = path.join(tmpDir, 'trim-fail.wal'); // 同上：独占文件，顺序无关
    auditBuffer.start();
    const warnSpy = jest.spyOn(logger, 'warn').mockImplementation(() => {});
    // errSpy 必须在 push 之前就位：裁剪回写失败发生在下面这个循环里，事后才装
    // 探针的话 loggedErr 恒空，那条 toContain 就成了永远绿的假断言。
    const errSpy = jest.spyOn(logger, 'error').mockImplementation(() => {});
    // 追加链路正常（行确实落盘），只打断裁剪最后那步原子替换
    jest.spyOn(fs.promises, 'rename').mockImplementation(async () => {
      throw new Error('EACCES: permission denied, rename');
    });

    // 本套件 MAX_BYTES=200、STAT_INTERVAL=1：每追加一条就抽查一次，几行即越限进入裁剪分支
    for (let i = 0; i < 5; i++) {
      auditBuffer.push({
        action: 'wal_trim_fail',
        category: 'auth',
        ip: TEST_CLIENT_IP,
        success: true,
        seq: i,
      });
    }
    await wal.drain();

    const stats = auditBuffer.getStats();
    expect(stats.walDroppedLines).toBe(0); // 裁剪没走到"已丢弃"那一步
    expect(stats.walAppendFailures).toBe(0);
    // F-217：裁剪侧现在有自己的计数，且失败就地记成 error 级"超限裁剪回写失败"，
    // 不再冒泡成那句口径更宽的"追加链后续操作失败"。两个计数不串这条性质，
    // 由下面 walTrimFailures>0 与上面 walAppendFailures===0 同时成立来表达。
    expect(stats.walTrimFailures).toBeGreaterThan(0);
    const logged = warnSpy.mock.calls.map((c) => c.join(' ')).join('\n');
    const loggedErr = errSpy.mock.calls.map((c) => c.join(' ')).join('\n');
    expect(logged + '\n' + loggedErr).toContain('超限裁剪回写失败');
    expect(logged).not.toContain('审计 WAL 追加失败');
    expect(loggedErr).not.toContain('审计 WAL 追加失败');
    // 计数与留痕一一对应：本用例只驱动"回写失败"这一条裁剪路径，所以两者必须相等。
    // 只断言 toBeGreaterThan(0) 时，一次残留的旧计数就能让它永远绿（本文件开头的
    // __resetForTest 确实清了零，但那条前提在别处，不该由这条断言的命运来间接证明）。
    const trimErrLines = loggedErr.split('\n').filter((l) => l.includes('超限裁剪回写失败'));
    expect(trimErrLines.length).toBe(stats.walTrimFailures);
    expect(stats.walTrimFailures).toBeGreaterThan(0);
    errSpy.mockRestore();
  });
});
