/**
 * 审计 WAL 里"解析不出文档的行"必须可见、可计、不得静默重复
 *
 * 缺陷：
 * `stampReplaySeqs` 对损坏行走 `catch { doc = null }` 后原样保留——保留是对的
 * （不猜内容、也不因一行坏而丢掉后续行），但坏行**没有 `__walSeq`**，
 * 而裁剪按序号匹配 ⇒ 这些行永远不会被裁掉；同时它们也不进缓冲、不重放。
 * 实测后果：种 4 行（含 `{"module":"broken","action":` 与 `12345`）后，
 * 启动日志只有孤零零一句"审计 WAL 重放 2 条遗留记录"，
 * `getStats()` 里 `walDroppedLines` / `walDiscardedLines` 全为 0——
 * 合规出口对"WAL 里有多少取证永远进不了库"完全失明，且每次重启都原地重读一遍。
 *
 * 同一个根因（行尾换行缺失）的另一面：文件尾缺 `\n` 时，下一次 append 会把新记录
 * 拼在残行之后，两条记录同时变成坏行。`walAppendLine` 只补自己那段行尾，
 * 管不到已经存在的残尾，因此在启动重放处补一次（并告警成因）。
 *
 * 2026-09-25 追加两条不变式（F-147 与"测量法本身"的修正）：
 *   ③ 补号必须**真的回写到文件**——内存里有序号而文件里没有，等于这批行落库后
 *      按序号裁不掉，下次重启会被重放成同一事件的第二个副本（_id 每次新分配）＋
 *      哈希链分叉；回写失败本身必须有计数（walRewriteFailures），原先它只汇进
 *      一句 `启动重放失败` 的 warn，与"读文件失败"共用一行日志、无指标可事后核对。
 *   ④ "无事可做"的判据必须是**没发起写**，不能是"文件字节没变"：`rewriteInChain`
 *      落的就是 `join('\n') + '\n'`，与完整文件逐字节相同 ⇒ 把整条回写删掉，
 *      原先那条"不重写"的用例照样绿（实测见 deliverables/AGENT工作总账与待办-2026-09-21.md）。
 */

const fs = require('fs');
const os = require('os');
const path = require('path');

describe('审计 WAL 损坏行的可观测性与文件尾自愈', () => {
  let tmpDir;
  let walPath;
  let auditBuffer;
  let wal;
  let logger;
  let errorSpy;
  let warnSpy;

  const writeWal = (text) => fs.writeFileSync(walPath, text, 'utf8');
  const readWal = () => fs.readFileSync(walPath, 'utf8');
  /** 物理行（不含空行），并顺手断言行尾完整 */
  const walLines = () => readWal().split('\n').filter(Boolean);

  /** 一轮"启动→重放→排干→停止"，模拟进程的一次开机 */
  const bootOnce = async () => {
    auditBuffer.start();
    await wal.drain();
    auditBuffer.stop();
  };

  const loggedText = (calls) => calls.map((c) => c.join(' ')).join('\n');

  beforeAll(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'audit-wal-corrupt-'));
    walPath = path.join(tmpDir, 'test-audit.wal');
    process.env.AUDIT_WAL_PATH = walPath;
    delete process.env.AUDIT_WAL_MAX_BYTES; // 本套件不测容量上限
    delete process.env.AUDIT_WAL_STAT_INTERVAL;
    auditBuffer = require('../../services/auditBuffer');
    wal = require('../../services/auditBufferWal');
    logger = require('../../utils/logger');
  });

  beforeEach(() => {
    errorSpy = jest.spyOn(logger, 'error').mockImplementation(() => {});
    warnSpy = jest.spyOn(logger, 'warn').mockImplementation(() => {});
    auditBuffer.stop();
    auditBuffer.__resetForTest();
  });

  afterEach(() => {
    jest.restoreAllMocks();
    auditBuffer.stop();
    try {
      fs.rmSync(walPath, { force: true });
      fs.rmSync(`${walPath}.tmp`, { force: true });
    } catch (_) {
      /* 忽略 */
    }
  });

  afterAll(() => {
    auditBuffer.stop();
    try {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    } catch (_) {
      /* 忽略 */
    }
  });

  test('坏行计数并进合规指标：walCorruptLines 存在且随坏行推进', async () => {
    // 第 1 行合法但缺 __walSeq（会被补序号）；第 2 行 JSON 截断；第 3 行解析成数字
    writeWal('{"action":"ok","seq":1}\n{"module":"broken","action":\n12345\n');

    await bootOnce();

    const stats = auditBuffer.getStats();
    expect(stats).toHaveProperty('walCorruptLines');
    expect(stats.walCorruptLines).toBe(2);
    // 合法行照常重放：缓冲里只有它一条
    expect(stats.bufferLength).toBe(1);
  });

  test('坏行有 error 级留痕，且写清"不重放、裁不掉、每次重启重读"三个后果', async () => {
    writeWal('{"action":"ok","seq":1}\nnope-not-json\n');

    await bootOnce();

    const logged = loggedText(errorSpy.mock.calls);
    expect(logged).toContain('解析不出取证文档');
    expect(logged).toContain('有 1 行');
    // 本轮数之外还要带**累计**数：运维要看的是"这个文件一共坏了多少行"，
    // 只有本轮数会在下一次开机后把历史盖掉。
    expect(logged).toContain('累计 1 行');
    expect(logged).toContain('永远不会被裁剪');
    expect(logged).toContain(walPath);
  });

  test('不猜内容：坏行原件保留在 WAL 里（既不删也不改写）', async () => {
    writeWal('{"action":"ok","seq":1}\n{"module":"broken","action":\n');

    await bootOnce();

    expect(walLines()).toContainEqual('{"module":"broken","action":');
  });

  test('对照：全部行合法时计数为 0，也不产生 error 噪声', async () => {
    writeWal('{"action":"a","seq":1}\n{"action":"b","seq":2}\n');

    await bootOnce();

    expect(auditBuffer.getStats().walCorruptLines).toBe(0);
    expect(auditBuffer.getStats().bufferLength).toBe(2);
    expect(loggedText(errorSpy.mock.calls)).not.toContain('解析不出取证文档');
  });

  test('累计口径（与 walDroppedLines 一致）：两次开机各 1 行坏 ⇒ 计数为 2', async () => {
    writeWal('{"action":"a","seq":1}\nbad-line-1\n');
    await bootOnce();
    expect(auditBuffer.getStats().walCorruptLines).toBe(1);

    writeWal('{"action":"b","seq":2}\nbad-line-2\n');
    await bootOnce();
    expect(auditBuffer.getStats().walCorruptLines).toBe(2);
  });

  test('文件尾缺行尾换行 → 启动重放补齐并告警（不补则下一条记录被拼进残行）', async () => {
    // 两行都已带 __walSeq：补序号这条臂不会触发整体重写，只剩"补行尾"这一条理由
    writeWal('{"action":"a","seq":1,"__walSeq":"r-1"}\n{"action":"b","seq":2,"__walSeq":"r-2"}');
    expect(readWal().endsWith('\n')).toBe(false);

    await bootOnce();

    expect(readWal().endsWith('\n')).toBe(true);
    expect(walLines()).toHaveLength(2);
    expect(loggedText(warnSpy.mock.calls)).toContain('缺少行尾换行');
    // 已有序号不被重新分配：重放的两条都在缓冲里，且没有产生坏行
    expect(auditBuffer.getStats().bufferLength).toBe(2);
    expect(auditBuffer.getStats().walCorruptLines).toBe(0);
  });

  test('补齐是幂等的：第二次开机不再重复告警、不再重写', async () => {
    writeWal('{"action":"a","seq":1,"__walSeq":"r-1"}');
    await bootOnce();
    expect(loggedText(warnSpy.mock.calls)).toContain('缺少行尾换行');

    auditBuffer.__resetForTest();
    warnSpy.mockClear();
    await bootOnce();

    expect(loggedText(warnSpy.mock.calls)).not.toContain('缺少行尾换行');
    expect(readWal().endsWith('\n')).toBe(true);
    expect(walLines()).toHaveLength(1);
  });

  test('补齐之后新记录独占一行：逐行 JSON.parse 全部通过（端到端后果）', async () => {
    writeWal('{"action":"a","seq":1,"__walSeq":"r-1"}\n{"action":"b","seq":2,"__walSeq":"r-2"}');

    await bootOnce(); // 补行尾
    auditBuffer.start(); // 重新开启写入，push 才会落 WAL
    auditBuffer.push({ action: 'after_repair', category: 'auth', seq: 99 });
    await wal.drain();
    auditBuffer.stop();

    const lines = walLines();
    expect(lines).toHaveLength(3);
    for (const line of lines) {
      expect(() => JSON.parse(line)).not.toThrow();
      expect(typeof JSON.parse(line)).toBe('object');
    }
    expect(JSON.parse(lines[2]).action).toBe('after_repair');
  });

  test('补号真的回写到了文件里（内存有序号 ≠ 下次重启不再重复插入）', async () => {
    // 这条钉的是回写的**存在**：只看 getStats/bufferLength 的用例在"回写被摘掉"时
    // 照样绿——文档照样进缓冲、序号照样在内存里，缺陷要到下次开机才显形（重复插入）。
    writeWal('{"action":"a","seq":1}\n');

    await bootOnce();

    const lines = walLines();
    expect(lines).toHaveLength(1);
    expect(JSON.parse(lines[0]).__walSeq).toBeTruthy();
    // 反向对照：回写成功时不得污染失败计数（否则 walRewriteFailures 恒 >0，
    // 面板上"这次回写失败过"就成了没有信息量的常量）
    expect(auditBuffer.getStats().walRewriteFailures).toBe(0);
  });

  test('回写失败：walRewriteFailures 推进 + error 级留痕，且不打断这次重放', async () => {
    writeWal('{"action":"a","seq":1}\n'); // 缺 __walSeq ⇒ 必走整体回写
    jest
      .spyOn(fs.promises, 'writeFile')
      .mockImplementation(async () =>
        Promise.reject(
          Object.assign(new Error('ENOSPC: no space left on device'), { code: 'ENOSPC' })
        )
      );

    await bootOnce();

    const stats = auditBuffer.getStats();
    expect(stats.walRewriteFailures).toBe(1);
    const logged = loggedText(errorSpy.mock.calls);
    expect(logged).toContain('重放补号回写失败');
    expect(logged).toContain('累计 1 次'); // 与本轮数并列：下一台机器上还要能看出累计规模
    expect(logged).toContain(walPath);
    // 级别不得下调：这条的后果（下次重启重复插一份 + 链分叉）要靠 error 级留痕被捞到
    expect(loggedText(warnSpy.mock.calls)).not.toContain('重放补号回写失败');
    // 不得反噬这次重放：记录仍在缓冲里（把它丢掉才是真的缺），落库/裁剪照常
    expect(stats.bufferLength).toBe(1);
    // 失败在 stampReplaySeqs 内部就地消化：外层那句含糊的"启动重放失败"不该再出现
    expect(loggedText(warnSpy.mock.calls)).not.toContain('启动重放失败');
  });

  test('本来完整（尾行带换行）时不发起任何写，也不告警', async () => {
    const body = '{"action":"a","seq":1,"__walSeq":"r-1"}\n';
    writeWal(body);
    // 判据是"没发起写"，不是"文件字节没变"：rewriteInChain 写的正是 join('\n')+'\n'，
    // 与这里的 body 逐字节相同 ⇒ 只比字节的旧写法抓不到"整条回写被删掉"，
    // 而那恰好是本用例想防的方向（无事可做时多余的重写会重排/覆写别人的行）。
    const writeSpy = jest.spyOn(fs.promises, 'writeFile'); // 不替换实现，只记调用
    const renameSpy = jest.spyOn(fs.promises, 'rename');
    await bootOnce();

    expect(writeSpy).not.toHaveBeenCalled();
    expect(renameSpy).not.toHaveBeenCalled();
    expect(readWal()).toBe(body);
    expect(loggedText(warnSpy.mock.calls)).not.toContain('缺少行尾换行');
  });
});
