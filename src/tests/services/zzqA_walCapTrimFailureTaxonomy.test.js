/**
 * 审计 WAL 上限裁剪的失败分类（F-217 判据的闭环）
 *
 * 为什么单独立一个文件：`walTrimFailures` 这个计数在面板上有了位置之后，
 * 它覆盖的三条"该裁没裁成"路径必须各自有用例，否则计数退化回"只有一条路径会动的计数器"。
 * 本轮覆盖率读数直接点出了缺口：拆分后的 `auditWalCap.js` 未命中行是 112-113，
 * 正是「stat 刚成功、内容却读不回」那条（`readWalRecords()` 返回 null）。
 *
 * 三条路径的**后果同、成因不同**，所以判据必须能分辨：
 *   ① `fs.promises.stat` 抛非 ENOENT ⇒ warn「审计 WAL 大小检查失败」
 *      —— 这条已由 src/tests/observability/auditBufferFlushAndWalGuards.test.js 的
 *         stat_err 用例覆盖（注入 interval=1），本文件不重复装桩，只在下面注释里点名归属；
 *   ② stat 成功但 `readWalRecords()` 读不回（文件被并发删掉 / EACCES / EIO）⇒ error
 *      「审计 WAL 已超限但读不回内容」 ← **本文件补的就是这条**；
 *   ③ `atomicReplaceWal` 抛错 ⇒ error「审计 WAL 超限裁剪回写失败」
 *      —— 由 src/tests/services/auditWalCap.test.js 的口径隔离用例覆盖（含
 *         `trimErrLines.length === walTrimFailures` 的一一对应判据）。
 *
 * 还钉住一条**刻意不计**的分支（`records.length < 2`：单行超限没有"一半"可弃，
 * 留给外部取证）。不钉住它，"每条裁剪路径都计数"这句话就成了假的；钉住它，
 * 将来有人把那条 return 改成计数时这里会红 —— 那是有意变更，需要连着注释一起改。
 *
 * 判据形状（三条用例共用）：`walTrimFailures` 必须与"该路径自己的留痕行数"**一一对应**，
 * 而不是 toBeGreaterThan(0)。后者一次残留的旧计数就能永远满足（同 F-217 在对面文件里
 * 立的那条）。另外三条都断言 `walAppendFailures === 0`：F-146 立的"裁剪侧失败不得
 * 报成追加失败"这条口径隔离，正是靠"这里裁剪失败了而追加计数没动"来表达。
 *
 * 顺序无关：每条用例独占自己的 wal 文件（`AUDIT_WAL_PATH` 是运行期读的，换名即换文件），
 * 探针在每条用例末尾还原，计数在每条用例开头清零。
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const { TEST_CLIENT_IP } = require('../fixtures');
const logger = require('../../utils/logger');

const MAX_BYTES = 200;
// 逐条抽查：本文件的判据是"一次裁剪 = 一次留痕"，节流会让对账变成区间量
const STAT_INTERVAL = '1';
// 本文件写过的全部 env（还原清单，见 afterAll）
const WAL_ENV_KEYS = ['AUDIT_WAL_PATH', 'AUDIT_WAL_MAX_BYTES', 'AUDIT_WAL_STAT_INTERVAL'];

describe('审计 WAL 上限裁剪：三类"该裁没裁成"各自计数、各自留痕、且不串追加账目', () => {
  let tmpDir;
  let walEnvSnapshot;
  let auditBuffer;
  let wal;

  beforeAll(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'audit-wal-trim-tax-'));
    // 快照必须在**改之前**取。原实现先写 AUDIT_WAL_PATH、再 `defaultWalPath =
    // process.env.AUDIT_WAL_PATH`，取到的是自己刚写进去的值 ⇒ afterEach 的"还原"
    // 是空操作，三条 env（含指向已删临时目录的路径）泄漏给同一 worker 的后续套件
    // （jest worker 不重置 process.env）。
    walEnvSnapshot = Object.fromEntries(WAL_ENV_KEYS.map((k) => [k, process.env[k]]));
    process.env.AUDIT_WAL_PATH = path.join(tmpDir, 'tax-audit.wal');
    process.env.AUDIT_WAL_MAX_BYTES = String(MAX_BYTES);
    process.env.AUDIT_WAL_STAT_INTERVAL = STAT_INTERVAL;
    auditBuffer = require('../../services/auditBuffer');
    wal = require('../../services/auditBufferWal');
  });

  afterEach(() => {
    jest.restoreAllMocks();
    auditBuffer.stop();
  });

  afterAll(() => {
    auditBuffer.stop();
    // 还原只放 afterAll，不放用例尾部：断言失败会跳过函数体尾部语句。
    // `process.env.X = undefined` 会写入字符串 'undefined' ⇒ 原本未设置的键必须 delete。
    for (const k of WAL_ENV_KEYS) {
      if (walEnvSnapshot[k] === undefined) delete process.env[k];
      else process.env[k] = walEnvSnapshot[k];
    }
    try {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    } catch (_) {
      /* 临时目录由系统回收 */
    }
  });

  /**
   * 装桩 → 追加 appends 条 → 排干 walChain（drain 串在同一条链尾部，await 它即等到
   * 每一次抽查做完）→ 还桩 → 返回账目与两类日志文本。
   * 探针必须在 drain **之前**保持存活：链是异步的，早还桩会让被测路径拿到好端端的 readFile。
   */
  async function drive(caseFile, install, appends) {
    auditBuffer.stop();
    await wal.drain();
    auditBuffer.__resetForTest();
    process.env.AUDIT_WAL_PATH = path.join(tmpDir, caseFile);
    auditBuffer.start();
    const warnSpy = jest.spyOn(logger, 'warn').mockImplementation(() => {});
    const errSpy = jest.spyOn(logger, 'error').mockImplementation(() => {});
    install();
    for (let i = 0; i < appends; i++) {
      auditBuffer.push({
        action: 'wal_trim_tax',
        category: 'auth',
        ip: TEST_CLIENT_IP,
        success: true,
        seq: i,
      });
    }
    await wal.drain();
    jest.restoreAllMocks();
    return {
      stats: auditBuffer.getStats(),
      warn: warnSpy.mock.calls.map((c) => c.join(' ')).join('\n'),
      err: errSpy.mock.calls.map((c) => c.join(' ')).join('\n'),
    };
  }

  const countLines = (text, needle) => text.split('\n').filter((l) => l.includes(needle)).length;

  // stat 谎报体积：让"已越过硬上限"这个前提成立，而不去真写满 200 字节的磁盘文件。
  // 只桩 stat 不影响 readFile，所以这是"读得回来"的对照形态（用例②的对照臂）。
  const installFatStat = () => {
    jest.spyOn(fs.promises, 'stat').mockImplementation(async () => ({ size: MAX_BYTES * 1000 }));
  };

  test('② 超限却读不回内容：计入 walTrimFailures 且落一条 error（此前零行为覆盖）', async () => {
    const { stats, err, warn } = await drive(
      'read-gone.wal',
      () => {
        installFatStat();
        jest.spyOn(fs.promises, 'readFile').mockImplementation(async () => {
          throw Object.assign(new Error('ENOENT: no such file or directory, open'), {
            code: 'ENOENT',
          });
        });
      },
      4
    );

    const phrase = '审计 WAL 已超限但读不回内容';
    expect(stats.walTrimFailures).toBeGreaterThan(0);
    // 一一对应：不是"有失败就有计数"，而是"每一次失败都留下它自己的那行字"
    expect(countLines(err, phrase)).toBe(stats.walTrimFailures);
    // 三条路径各有自己的措辞：混用会让运维看不出是磁盘、权限还是并发删
    expect(err).not.toContain('超限裁剪回写失败');
    // 读不回内容 ⇒ 一行都没弃：面板上"丢弃 N 行"必须继续只表示真的丢了
    expect(stats.walDroppedLines).toBe(0);
    expect(stats.walAppendFailures).toBe(0);
    expect(warn).not.toContain('审计 WAL 追加失败');
  });

  test('② 的对照臂：同样谎报体积但读得回来 ⇒ 只计 walDroppedLines，一条 trimFailure 都不许有', async () => {
    const { stats, err } = await drive('read-ok.wal', installFatStat, 4);

    // 没有这条对照，上一条的"读不回内容 ⇒ 计数"就可能只是"任何抽查都计数"的假象
    expect(stats.walTrimFailures).toBe(0);
    expect(stats.walDroppedLines).toBeGreaterThan(0);
    expect(err).not.toContain('审计 WAL 已超限但读不回内容');
    expect(err).toContain('已丢弃最旧');
    expect(stats.walAppendFailures).toBe(0);
  });

  test('刻意不计：单行超限没有"一半"可弃 ⇒ 两个计数都不动，且不打 error', async () => {
    const { stats, err } = await drive(
      'single-line.wal',
      () => {
        installFatStat();
        // 只放一行：records.length < 2 直接 return（auditWalCap.js 的"留给外部取证"分支）
      },
      1
    );

    expect(stats.walDroppedLines).toBe(0);
    expect(stats.walTrimFailures).toBe(0);
    expect(err).not.toContain('审计 WAL 已超限但读不回内容');
    expect(err).not.toContain('已丢弃最旧');
  });
});
