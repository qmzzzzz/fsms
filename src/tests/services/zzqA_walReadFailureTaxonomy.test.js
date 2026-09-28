/**
 * 审计 WAL「读不回文件」与「本来就没有行」的分辨（Lane X #2 的落地闭环）
 *
 * 缺陷本体：`readWalRecords()` 对 ENOENT 与 EACCES/EIO/ESTALE 一律 `return null`，
 * 而 `removeWalLinesBySeqs()` 把 `!wal` 和 `records.length === 0` 折成同一个 `return 0`。
 * 于是「一批刚确认落库的行没裁掉」（后果：行留在原地，重启按 WAL 语义把已落库的记录
 * 再插一份）与「确实没有行要裁」（后果：无）在日志、面板、计数上完全同形。
 * 同一个 null 还让 `readWalLines()`（启动重放唯一入口）把「读不回」当成「WAL 是空的」，
 * 整轮重放静默跳过，连 `审计 WAL 重放 N 条遗留记录` 那行 info 都不打。
 *
 * 与既有账目的分工（不重复装桩）：
 *   - 上限侧的「stat 刚成功、内容却读不回」由 zzqA_walCapTrimFailureTaxonomy.test.js
 *     的用例②钉住（计入 `walTrimFailures` + 那条 error 措辞），本文件不碰 cap；
 *   - 本文件钉**回收侧**与**重放侧**两处此前零覆盖的静默 `return`。
 *
 * 判据形状：正向臂断言"那一行 error 恰好一条 + 点名序号数与 errno"，并断言
 * `walDroppedLines`/`walDiscardedLines` 纹丝不动——读失败一行都没删掉，把这两个计数
 * 抬起来就是撒谎（F-146 立的"裁剪侧失败不得报成已丢弃"口径）。
 *
 * 可证伪性（改动前的旧代码会怎么红）：
 *   ①③ 旧代码在两处都不打 error ⇒ error 行数为 0，正向臂直接红；
 *   ②④ 是**反向臂**：旧代码同样不打 error，所以它们单独跑永远绿。它们的作用是把①③
 *      钉成"只在读失败时报"——否则有人把分辨改成"凡是 0 命中就报错"，正常路径就会被
 *      刷成一堆假告警而这两条用例仍绿。⑤ 是正向对照，防止①退化成"凡是裁剪都报错"。
 *
 * 顺序无关：每条用例独占一个 wal 文件（`AUDIT_WAL_PATH` 运行期读取，换名即换文件），
 * 计数在每条用例开头随 `__resetForTest()` 归零，env 在 afterAll 还原。
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const { TEST_CLIENT_IP } = require('../fixtures');
const logger = require('../../utils/logger');

const WAL_ENV_KEYS = ['AUDIT_WAL_PATH', 'AUDIT_WAL_MAX_BYTES', 'AUDIT_WAL_STAT_INTERVAL'];

const TRIM_PHRASE = '落库回收读不回文件';
const REPLAY_PHRASE = '启动重放读不回文件';

describe('审计 WAL 读取失败：与「没有行要裁」分家，各自留一条 error 且不动丢弃计数', () => {
  let tmpDir;
  let walEnvSnapshot;
  let auditBuffer;
  let wal;

  beforeAll(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'audit-wal-readfail-'));
    walEnvSnapshot = Object.fromEntries(WAL_ENV_KEYS.map((k) => [k, process.env[k]]));
    process.env.AUDIT_WAL_PATH = path.join(tmpDir, 'readfail.wal');
    auditBuffer = require('../../services/auditBuffer');
    wal = require('../../services/auditBufferWal');
  });

  afterEach(() => {
    jest.restoreAllMocks();
    auditBuffer.stop();
  });

  afterAll(() => {
    auditBuffer.stop();
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
   * 装桩与探针必须在 `start()` **之前**就位：启动重放就发生在那一次调用里。
   * 探针也必须在 act 与 drain 期间存活，还桩只能排在取完日志之后。
   */
  async function run(caseFile, install, act) {
    auditBuffer.stop();
    await wal.drain();
    auditBuffer.__resetForTest();
    process.env.AUDIT_WAL_PATH = path.join(tmpDir, caseFile);
    const warnSpy = jest.spyOn(logger, 'warn').mockImplementation(() => {});
    const errSpy = jest.spyOn(logger, 'error').mockImplementation(() => {});
    const infoSpy = jest.spyOn(logger, 'info').mockImplementation(() => {});
    if (install) install();
    auditBuffer.start();
    if (act) await act();
    await wal.drain();
    const out = {
      stats: auditBuffer.getStats(),
      warn: warnSpy.mock.calls.map((c) => c.join(' ')).join('\n'),
      err: errSpy.mock.calls.map((c) => c.join(' ')).join('\n'),
      info: infoSpy.mock.calls.map((c) => c.join(' ')).join('\n'),
    };
    jest.restoreAllMocks();
    return out;
  }

  /** 只对 WAL 文件本身抛错：`.discarded` 归档与 logs 目录下其它读取一律放行 */
  const failWalRead = (code, message) => {
    const real = fs.promises.readFile;
    jest.spyOn(fs.promises, 'readFile').mockImplementation(async (p, ...rest) => {
      if (String(p).endsWith('.wal')) throw Object.assign(new Error(message), { code });
      return real(p, ...rest);
    });
  };

  /** 走生产追加路径真写两行，序号由模块自己分配 */
  async function appendTwoLines() {
    for (let i = 0; i < 2; i++) {
      auditBuffer.push({
        action: 'wal_readfail_tax',
        category: 'auth',
        ip: TEST_CLIENT_IP,
        success: true,
        seq: i,
      });
    }
    await wal.drain();
  }

  const seqsOf = (lines) =>
    new Set(
      lines
        .map((l) => {
          try {
            return JSON.parse(l).__walSeq;
          } catch (_) {
            return null;
          }
        })
        .filter(Boolean)
    );

  const countLines = (text, needle) => text.split('\n').filter((l) => l.includes(needle)).length;

  test('① 回收侧读不回（EACCES）：一条 error 点名序号数，且两个"已丢弃"计数都不动', async () => {
    const { stats, err } = await run(
      'trim-eacces.wal',
      () => failWalRead('EACCES', 'permission denied, open'),
      () => wal.trimBySeqs(new Set(['r-x-1', 'r-x-2']))
    );

    expect(countLines(err, TRIM_PHRASE)).toBe(1);
    expect(err).toContain('2 个序号本轮 0 命中');
    expect(err).toContain('EACCES');
    // 读失败 ⇒ 一行都没删。这两个计数抬起来就是谎报"取证已丢失"
    expect(stats.walDroppedLines).toBe(0);
    expect(stats.walDiscardedLines).toBe(0);
  });

  test('② 文件确实不存在（ENOENT）：两处都不许报——这是①③的反向臂', async () => {
    const { err, warn } = await run(
      'missing.wal',
      () => failWalRead('ENOENT', 'no such file or directory, open'),
      () => wal.trimBySeqs(new Set(['r-x-3']))
    );

    // 「没有文件」是正常态（WAL 从未启用 / 已被排空删掉），对它报错就是刷假告警
    expect(err).not.toContain(TRIM_PHRASE);
    expect(err).not.toContain(REPLAY_PHRASE);
    expect(warn).not.toContain('审计 WAL 读取失败');
  });

  test('③ 重放侧读不回（EIO）：一条 error 说清"本轮不重放"，且不打印"重放 N 条"的假象', async () => {
    const { err, info } = await run('replay-eio.wal', () => failWalRead('EIO', 'i/o error, open'));

    expect(countLines(err, REPLAY_PHRASE)).toBe(1);
    expect(err).toContain('EIO');
    // 旧代码这里既不打 error、也不打 info ⇒ 运维读到的是"没有待重放的记录"
    expect(info).not.toContain('审计 WAL 重放');
  });

  test('④ 反向臂：文件读得回来但序号不命中 ⇒ 0 命中却一条 error 都不许有', async () => {
    const { stats, err } = await run('no-match.wal', null, async () => {
      await appendTwoLines();
      // 序号刻意不匹配：这是"真的没有行要裁"，与①的"读不回"必须不同形
      wal.trimBySeqs(new Set(['no-such-run-9-1']));
    });

    expect(err).not.toContain(TRIM_PHRASE);
    expect(stats.walDiscardedLines).toBe(0);
    expect(stats.walDroppedLines).toBe(0);
  });

  test('⑤ 正向对照：序号命中时照常裁掉、error 静默（证明①不是"凡是裁剪都报错"）', async () => {
    let removedSeqs = new Set();
    const { stats, err } = await run('happy.wal', null, async () => {
      await appendTwoLines();
      removedSeqs = seqsOf(await wal.readLines());
      expect(removedSeqs.size).toBe(2);
      wal.trimBySeqs(removedSeqs);
    });

    expect(err).not.toContain(TRIM_PHRASE);
    expect(await wal.readLines()).toHaveLength(0);
    expect(stats.walDiscardedLines).toBe(0);
  });
});
