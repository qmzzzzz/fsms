/**
 * 取证 WAL（P2）：追加 → 精确裁剪 → 超限丢弃的容量语义
 *
 * 被测对象：services/forensicCaptureWal.js。
 *
 * 与审计 WAL 的分工（任务书 §1.3）：审计 WAL 承诺"审计记录不可丢"，取证 WAL 是
 * 尽力而为的增强证据——超过 FORENSIC_WAL_CAP_BYTES 时丢最旧一半并归档到 .discarded，
 * 丢弃必须**计数可见**（walDroppedLines），永不静默。本文件锁定这三件事：
 *  ① 落库后的行按 __walSeq 精确移除（不能错杀未落库行——那是取证缺口的第二种来源）；
 *  ② 超限只丢最旧一半、归档而不是删除、计数在 stats 里读得到；
 *  ③ 损坏行不猜内容：计数并跳过，不把乱码当记录重放。
 */

const fs = require('fs');
const os = require('os');
const path = require('path');

const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'forensic-wal-'));
process.env.FORENSIC_WAL_CAP_BYTES = '4096';
process.env.FORENSIC_WAL_STAT_INTERVAL = '1';
const wal = require('../../services/forensicCaptureWal');

const readWal = () => {
  try {
    return fs.readFileSync(wal.getWalPath(), 'utf8');
  } catch {
    return null;
  }
};

describe('取证 WAL：追加/裁剪/容量退让', () => {
  beforeAll(() => {
    wal.startup(path.join(tmpDir, 't.wal'));
  });

  beforeEach(async () => {
    await wal.drain();
    fs.rmSync(wal.getWalPath(), { force: true });
    fs.rmSync(wal.getWalPath() + '.discarded', { force: true });
    wal.resetCounters();
    wal.startup(path.join(tmpDir, 't.wal'));
  });

  afterAll(async () => {
    await wal.drain();
    wal.disable();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  test('追加后可整行读回；未启用时不写文件（不产生空文件副作用）', async () => {
    wal.appendLine(JSON.stringify({ __walSeq: 'r-1', ip: '203.0.113.7' }));
    await wal.drain();
    expect(readWal()).toContain('"__walSeq":"r-1"');

    wal.disable();
    const before = readWal();
    wal.appendLine(JSON.stringify({ __walSeq: 'r-2' }));
    await wal.drain();
    expect(readWal()).toBe(before); // 关闭态追加是 no-op（不写、不报错）
    wal.startup(path.join(tmpDir, 't.wal'));
  });

  test('按 __walSeq 精确裁剪：只移除命中行，未命中行原样保留（含损坏行）', async () => {
    wal.appendLine(JSON.stringify({ __walSeq: 'r-1' }));
    wal.appendLine('{corrupt-line'); // 解析失败的行：seq 判 null ⇒ 必须保留（不猜、不误删）
    wal.appendLine(JSON.stringify({ __walSeq: 'r-2' }));
    wal.appendLine(JSON.stringify({ __walSeq: 'r-3' }));
    await wal.drain();

    wal.trimBySeqs(['r-2']);
    await wal.drain();
    const after = readWal();
    expect(after).not.toContain('"__walSeq":"r-2"');
    expect(after).toContain('"__walSeq":"r-1"');
    expect(after).toContain('"__walSeq":"r-3"');
    expect(after).toContain('{corrupt-line');
  });

  test('超限丢弃：丢最旧一半、归档到 .discarded、walDroppedLines 计数可见', async () => {
    const filler = 'x'.repeat(400);
    for (let i = 1; i <= 12; i += 1) {
      wal.appendLine(JSON.stringify({ __walSeq: 'cap-' + i, filler }));
    }
    await wal.drain();
    const stats = wal.getStats();
    expect(stats.walDroppedLines).toBeGreaterThan(0); // 不许静默丢
    const archive = fs.readFileSync(wal.getWalPath() + '.discarded', 'utf8');
    expect(archive).toContain('"__walSeq":"cap-1"'); // 最旧的进了归档（可取证核查）
    const kept = readWal();
    expect(kept).not.toContain('"__walSeq":"cap-1"');
    expect(kept).toContain('"__walSeq":"cap-12"'); // 最新的必须还在
  });

  test('损坏行：重放时计数并跳过，绝不把解析不出的内容当记录', async () => {
    const p = wal.getWalPath();
    fs.writeFileSync(p, '{"__walSeq":"ok-1"}\nnot-json\n[]\n', { encoding: 'utf8', mode: 0o600 });
    const docs = await wal.readLines();
    expect(docs.map((d) => d.__walSeq)).toEqual(['ok-1']);
    expect(wal.getStats().walCorruptLines).toBe(2);
  });
});
