/**
 * P2b 清单哈希锚定（T3，§2.4）：每批 flush 追加一行 manifest，每日一条审计事件，
 * 复核脚本对「删一条 / 改一条 / 丢一批」三种篡改形态必须判红。
 *
 * 为什么清单必须存在：`recordHash` 只保证**单条**记录不被改；整批/整条被删掉时，
 * 库里每一条自己都是自洽的，没有任何东西会说"这里曾经有一条"。清单把"批次"这件事
 * 变成可核算的：count/firstSeq/lastSeq 给出应有多少条、从哪到哪，
 * chainHash 把批次按顺序串起来（改中间任意一条 ⇒ 其后所有 chainHash 全变）。
 *
 * 【本清单能做到与不能做到，如实记录】
 *  · 能：发现单条删除（count/seq 缺口）、单条篡改（chainHash 断链）、整批丢失（两日之间
 *    chainHash 接不上）；每日审计事件把当天的末条 chainHash 钉进审计链，于是
 *    "连清单文件一起改"要多改一处、且那处在不可改写的链上。
 *  · 不能：manifest 与 Mongo 同主权边界。能同时改库**与** manifest 文件**与**审计链的人
 *    仍可重写一切（审计链自身也要 HMAC 密钥）。清单的价值来自把三者拆成三个动作、
 *    把"可疑"变成"必须同时伪造三处"，不是"防得住"。
 *  · 不能：manifest 落盘失败时的记录不受保护——本模块只计数并告警（fail-visible），
 *    不重试、不阻塞落库（取证是尽力而为的增强证据，不能反过来卡业务）。
 */

'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');

const {
  MANIFEST_VERSION,
  MANIFEST_DIR,
  batchEntryOf,
  appendBatch,
  readManifest,
  verifyManifest,
  resetManifestState,
  getManifestStats,
  writeDailyAnchor,
  dateKeyOf,
} = require('../../services/forensicManifest');

const tmpdir = () => fs.mkdtempSync(path.join(os.tmpdir(), 'fc-manifest-'));

describe('清单批次链：每批一行、chainHash 串起来', () => {
  beforeEach(() => resetManifestState());

  test('同一批的 recordHash 顺序拼接后哈希稳定：同内容同序 ⇒ 同 chainHash（可复算）', () => {
    const g = 'genesis-';
    const hashes = ['a'.repeat(64), 'b'.repeat(64), 'c'.repeat(64)];
    const e1 = batchEntryOf({
      prevChainHash: g,
      recordHashes: hashes,
      firstSeq: 's1',
      lastSeq: 's3',
    });
    const e2 = batchEntryOf({
      prevChainHash: g,
      recordHashes: hashes.slice(),
      firstSeq: 's1',
      lastSeq: 's3',
    });
    expect(e1.chainHash).toBe(e2.chainHash);
    // 顺序参与哈希：换序即变（否则"调换两条"不可见）
    // ⚠ 下面每条都必须**只改一个变量**：首版没传 firstSeq/lastSeq，于是"换序"那条的哈希差异
    // 其实来自 null ≠ 's1'，顺序敏感性根本没被测到（变异 M1 存活时才发现）。
    const same = { prevChainHash: g, firstSeq: 's1', lastSeq: 's3' };
    const reordered = batchEntryOf({ ...same, recordHashes: [hashes[1], hashes[0], hashes[2]] });
    expect(reordered.chainHash).not.toBe(e1.chainHash);
    // 少一条参与哈希：删中间一条即变（count 会跟着变，但 hashesDigest 也必须变——
    // 否则"改一条"这类篡改在 count 打平的情况下仍能自洽）
    const fewer = batchEntryOf({ ...same, recordHashes: [hashes[0], hashes[2]] });
    expect(fewer.hashesDigest).not.toBe(e1.hashesDigest);
    expect(fewer.chainHash).not.toBe(e1.chainHash);
    // 只改 hashesDigest 一项（count/seq 全同）也必须变：这条是 M1 的专杀
    expect(reordered.chainHash).not.toBe(e1.chainHash);
    expect(reordered.count).toBe(e1.count); // 前提自证：count 相同，差异只可能来自顺序
    // 前序链参与哈希：换 genesis 即变（否则批次可被整段搬迁到别的链上）
    const otherPrev = batchEntryOf({ ...same, prevChainHash: 'genesis-x' });
    expect(otherPrev.chainHash).not.toBe(e1.chainHash);
  });

  test('追加两批：第二行 prevChainHash 必须等于第一行 chainHash（链是串起来的）', async () => {
    const dir = tmpdir();
    await appendBatch({ dir, recordHashes: ['1'.repeat(64)], firstSeq: 'a-1', lastSeq: 'a-1' });
    await appendBatch({ dir, recordHashes: ['2'.repeat(64)], firstSeq: 'a-2', lastSeq: 'a-2' });
    const { entries } = readManifest({ dir, date: new Date() });
    expect(entries).toHaveLength(2);
    expect(entries[0].prevChainHash).toBe('genesis');
    expect(entries[1].prevChainHash).toBe(entries[0].chainHash);
    expect(entries[1].chainHash).not.toBe(entries[0].chainHash);
  });

  test('按业务日分文件：跨日写成两个文件，各自 genesis 起链（当日文件自洽）', async () => {
    const dir = tmpdir();
    // 业务日 = Asia/Shanghai：UTC 15:59 = 北京 23:59（10-31），UTC 16:01 = 北京 00:01（11-01）
    const d1 = new Date(Date.UTC(2026, 9, 31, 15, 59, 0));
    const d2 = new Date(Date.UTC(2026, 9, 31, 16, 1, 0));
    await appendBatch({ dir, recordHashes: ['1'.repeat(64)], now: d1 });
    await appendBatch({ dir, recordHashes: ['2'.repeat(64)], now: d2 });
    expect(
      fs
        .readdirSync(dir)
        .filter((f) => f.endsWith('.jsonl'))
        .sort()
    ).toEqual(['2026-10-31.jsonl', '2026-11-01.jsonl']);
    const second = readManifest({ dir, date: d2 });
    expect(second.entries).toHaveLength(1);
    expect(second.entries[0].prevChainHash).toBe('genesis');
  });
});

describe('复核：三种篡改形态必须判红（这是本题的验收线）', () => {
  beforeEach(() => resetManifestState());

  const seed = async (dir, batches) => {
    let seq = 0;
    for (const hashes of batches) {
      seq += 1;
      await appendBatch({
        dir,
        recordHashes: hashes,
        firstSeq: `r-${seq}`,
        lastSeq: `r-${seq}`,
        now: new Date(Date.UTC(2026, 9, 31, 12, 0, 0)),
      });
    }
  };
  const linesOf = (dir) =>
    fs.readFileSync(path.join(dir, '2026-10-31.jsonl'), 'utf8').split('\n').filter(Boolean);

  test('删一条（删掉中间那个批次行）⇒ 断链必须判红，且指出断在哪一行', async () => {
    const dir = tmpdir();
    await seed(dir, [['a'.repeat(64)], ['b'.repeat(64)], ['c'.repeat(64)]]);
    const lines = linesOf(dir);
    fs.writeFileSync(path.join(dir, '2026-10-31.jsonl'), [lines[0], lines[2]].join('\n') + '\n');
    const v = verifyManifest({ dir, date: new Date(Date.UTC(2026, 9, 31)) });
    expect(v.ok).toBe(false);
    expect(v.problems.map((p) => p.type)).toContain('chain_broken');
    // 断链点必须落到被删那一行之后的那条（第 2 行），不是含糊的"有问题"
    expect(v.problems.find((p) => p.type === 'chain_broken').line).toBe(2);
  });

  test('改一条（改写某批的 count/seq 而 chainHash 不变）⇒ 必须判红', async () => {
    const dir = tmpdir();
    await seed(dir, [['a'.repeat(64)], ['b'.repeat(64)]]);
    const lines = linesOf(dir).map((l) => JSON.parse(l));
    lines[0].count = 99; // 声称有 99 条，但 chainHash 是 1 条算出来的
    fs.writeFileSync(
      path.join(dir, '2026-10-31.jsonl'),
      lines.map((l) => JSON.stringify(l)).join('\n') + '\n'
    );
    const v = verifyManifest({ dir, date: new Date(Date.UTC(2026, 9, 31)) });
    expect(v.ok).toBe(false);
    expect(v.problems.map((p) => p.type)).toContain('hash_mismatch');
    expect(v.problems.find((p) => p.type === 'hash_mismatch').line).toBe(1);
  });

  test('丢一批（最后一行整行被删）⇒ 必须判红（尾部截断不能因为"链自洽"就放过）', async () => {
    const dir = tmpdir();
    await seed(dir, [['a'.repeat(64)], ['b'.repeat(64)], ['c'.repeat(64)]]);
    const lines = linesOf(dir);
    fs.writeFileSync(path.join(dir, '2026-10-31.jsonl'), lines.slice(0, 2).join('\n') + '\n');
    const v = verifyManifest({
      dir,
      date: new Date(Date.UTC(2026, 9, 31)),
      expectedLastSeq: 'r-3',
    });
    expect(v.ok).toBe(false);
    expect(v.problems.map((p) => p.type)).toContain('tail_truncated');
  });

  test('原样不动 ⇒ 必须判绿（否则上面三条只是"恒红"）', async () => {
    const dir = tmpdir();
    await seed(dir, [['a'.repeat(64)], ['b'.repeat(64)]]);
    const v = verifyManifest({ dir, date: new Date(Date.UTC(2026, 9, 31)) });
    expect(v).toEqual({
      ok: true,
      problems: [],
      count: 2,
      lastChainHash: expect.any(String),
      lastSeq: 'r-2',
    });
  });

  test('坏行（解析不出）⇒ 判红并点名行号，绝不当作不存在', async () => {
    const dir = tmpdir();
    await seed(dir, [['a'.repeat(64)]]);
    fs.appendFileSync(path.join(dir, '2026-10-31.jsonl'), '{not json}\n');
    const v = verifyManifest({ dir, date: new Date(Date.UTC(2026, 9, 31)) });
    expect(v.ok).toBe(false);
    expect(v.problems.map((p) => p.type)).toContain('unparsable_line');
  });
});

describe('落盘失败必须 fail-visible（不得静默丢批次）', () => {
  beforeEach(() => resetManifestState());

  test('目录不可写 ⇒ 不抛、计 writeFailures，且 stats 里看得见', async () => {
    // 用"父路径是文件"制造必然的 ENOTDIR：比权限位更可靠（Windows 上 chmod 不生效）
    const dir = path.join(tmpdir(), 'not-a-dir');
    fs.writeFileSync(dir, 'x');
    const r = await appendBatch({ dir, recordHashes: ['a'.repeat(64)] });
    expect(r.written).toBe(false);
    expect(getManifestStats().writeFailures).toBe(1);
    // 平台差异：Linux 报 ENOTDIR，Windows 报 EEXIST——判据是"失败可见"，不是"失败原因长什么样"
    expect(getManifestStats().lastError).toMatch(
      /ENOTDIR|ENOENT|EEXIST|not a directory|already exists/i
    );
  });

  test('空批次不写行（不产生"0 条"噪声行，也不推进链）', async () => {
    const dir = tmpdir();
    const r = await appendBatch({ dir, recordHashes: [] });
    expect(r.written).toBe(false);
    expect(fs.readdirSync(dir)).toEqual([]);
  });
});

describe('每日锚点写进审计链（尾部截断的唯一外部判据）', () => {
  beforeEach(() => resetManifestState());

  /** 桩模型：记录收到的文档，供断言"锚点里到底写了什么" */
  const stub = () => {
    const seen = [];
    return {
      seen,
      create: async (doc) => {
        seen.push(doc);
        return doc;
      },
    };
  };
  const day = new Date(Date.UTC(2026, 9, 31));

  test('锚点带 dateKey / batches / lastSeq / lastChainHash / ok，自查通过记 low', async () => {
    const dir = tmpdir();
    await appendBatch({
      dir,
      recordHashes: ['a'.repeat(64)],
      firstSeq: 'r-1',
      lastSeq: 'r-1',
      now: new Date(Date.UTC(2026, 9, 31, 8, 0, 0)),
    });
    const m = stub();
    const r = await writeDailyAnchor({ dir, date: day, model: m });
    expect(r.written).toBe(true);
    expect(m.seen).toHaveLength(1);
    expect(m.seen[0].action).toBe('forensic_capture_manifest');
    expect(m.seen[0].category).toBe('security');
    // 锚点字段就是复核方需要的全部：日期、批数、末条 seq 与 chainHash
    expect(m.seen[0].body).toMatchObject({
      dateKey: '2026-10-31',
      batches: 1,
      lastSeq: 'r-1',
      lastChainHash: expect.any(String),
      ok: true,
    });
    // 自查通过 ⇒ low；不通过 ⇒ 必须 high（"验了但没验成"不许记成绿记录）
    expect(m.seen[0].riskLevel).toBe('low');
  });

  test('清单自查不通过（删中间批次 ⇒ 断链）⇒ 锚点记 high，且问题类型进 body', async () => {
    const dir = tmpdir();
    for (const h of ['a', 'b', 'c']) {
      await appendBatch({
        dir,
        recordHashes: [h.repeat(64)],
        now: new Date(Date.UTC(2026, 9, 31, 8, 0, 0)),
      });
    }
    const file = path.join(dir, '2026-10-31.jsonl');
    const lines = fs.readFileSync(file, 'utf8').split('\n').filter(Boolean);
    fs.writeFileSync(file, [lines[0], lines[2]].join('\n') + '\n'); // 删中间 ⇒ 断链
    const m = stub();
    await writeDailyAnchor({ dir, date: day, model: m });
    expect(m.seen[0].riskLevel).toBe('high');
    expect(m.seen[0].body.ok).toBe(false);
    expect(m.seen[0].body.problems.join(' ')).toContain('chain_broken');
  });

  test('能力边界自证：只删尾行、不带外部期望值时，清单**自己查不出来**（所以必须有审计锚点）', async () => {
    const dir = tmpdir();
    for (const h of ['a', 'b']) {
      await appendBatch({
        dir,
        recordHashes: [h.repeat(64)],
        now: new Date(Date.UTC(2026, 9, 31, 8, 0, 0)),
      });
    }
    const file = path.join(dir, '2026-10-31.jsonl');
    const lines = fs.readFileSync(file, 'utf8').split('\n').filter(Boolean);
    fs.writeFileSync(file, lines[0] + '\n'); // 删尾：链仍然自洽
    expect(verifyManifest({ dir, date: day }).ok).toBe(true); // ← 这条限制是真的，不掩饰
    // 只有把前一天锚点记下的 expectedLastSeq 传进来才判得出
    const v = verifyManifest({ dir, date: day, expectedLastSeq: 'r-2' });
    expect(v.ok).toBe(false);
    expect(v.problems.map((p) => p.type)).toContain('tail_truncated');
  });

  test('锚点写入失败不抛，但计 anchorFailures（定时任务不能因写不进而崩）', async () => {
    const dir = tmpdir();
    // 必须先有清单文件：没有文件是 empty_day（不锚、不算失败），走不到审计写入这条分支
    await appendBatch({ dir, recordHashes: ['a'.repeat(64)], now: day });
    const m = {
      create: async () => {
        throw new Error('audit down');
      },
    };
    const r = await writeDailyAnchor({ dir, date: day, model: m });
    expect(r.written).toBe(false);
    expect(r.reason).toBe('anchor_write_failed');
    expect(getManifestStats().anchorFailures).toBe(1);
  });
});

describe('边界与特殊情况（用户追问"考虑了吗"后补测的实测缺口）', () => {
  beforeEach(() => resetManifestState());
  const day = new Date(Date.UTC(2026, 9, 31));

  test('【缺陷1】空清单不得判绿：文件存在但一行都没有 ⇒ 必须报 empty_manifest', async () => {
    // 实测缺口：删掉唯一一行后文件仍在，verifyManifest 返回 ok:true/count:0——
    // 「把当天全部批次抹掉」这种最彻底的篡改，反而被判成"干净"。
    const dir = tmpdir();
    await appendBatch({
      dir,
      recordHashes: ['a'.repeat(64)],
      firstSeq: 'r-1',
      lastSeq: 'r-1',
      now: day,
    });
    fs.writeFileSync(path.join(dir, '2026-10-31.jsonl'), '');
    const v = verifyManifest({ dir, date: day });
    expect(v.ok).toBe(false);
    expect(v.problems.map((p) => p.type)).toContain('empty_manifest');
  });

  test('【缺陷1b】run 中途的非空清单不受影响：有行且自洽必须仍判绿', async () => {
    const dir = tmpdir();
    await appendBatch({
      dir,
      recordHashes: ['a'.repeat(64)],
      firstSeq: 'r-1',
      lastSeq: 'r-1',
      now: day,
    });
    expect(verifyManifest({ dir, date: day }).ok).toBe(true);
  });

  test('【缺陷2】空锚点不得污染当天：当天还没有批次时不写锚点，等有数据再锚', async () => {
    // 实测缺口：跨日 00:05 的首个 tick 会写一条 batches:0/ok:false 的锚点并把
    // lastAnchorDateKey 置为当天 ⇒ 当天真实批次（10:00 产生）从此永远不被锚定。
    const dir = tmpdir();
    const m = {
      seen: [],
      create: async (d) => {
        m.seen.push(d);
        return d;
      },
    };
    const r1 = await writeDailyAnchor({ dir, date: day, model: m });
    expect(r1.written).toBe(false);
    expect(r1.reason).toBe('empty_day'); // 不写 = 不锁定
    expect(m.seen).toHaveLength(0);
    // 当天后来产生批次 ⇒ 此时才锚，且锚点带真实批数
    await appendBatch({
      dir,
      recordHashes: ['a'.repeat(64)],
      firstSeq: 'r-1',
      lastSeq: 'r-1',
      now: day,
    });
    const r2 = await writeDailyAnchor({ dir, date: day, model: m });
    expect(r2.written).toBe(true);
    expect(m.seen[0].body.batches).toBe(1);
  });

  test('【缺陷3】命名按业务时区（Asia/Shanghai）而不是 UTC：北京 11-01 00:30 必须落 11-01 文件', async () => {
    // 实测缺口：原实现用 toISOString().slice(0,10)，北京 00:00–08:00 产生的批次会落到
    // 「昨天」的文件里，与仓内 businessDateParts 的业务日口径分叉（仓里已有单一声明）。
    const dir = tmpdir();
    const beijingNextDayEarly = new Date('2026-10-31T16:30:00Z'); // 北京 11-01 00:30
    await appendBatch({
      dir,
      recordHashes: ['a'.repeat(64)],
      firstSeq: 'r-1',
      lastSeq: 'r-1',
      now: beijingNextDayEarly,
    });
    const files = fs.readdirSync(dir).filter((f) => f.endsWith('.jsonl'));
    expect(files).toEqual(['2026-11-01.jsonl']);
    // 反向对照：同一实时刻在 UTC 口径下是 10-31，证明这条判据真的按业务时区走
    expect(beijingNextDayEarly.toISOString().slice(0, 10)).toBe('2026-10-31');
    expect(dateKeyOf(beijingNextDayEarly)).toBe('2026-11-01');
  });

  test('【缺陷3b】跨业务日边界：北京 23:59 与次日 00:01 分属两个文件', async () => {
    const dir = tmpdir();
    await appendBatch({
      dir,
      recordHashes: ['a'.repeat(64)],
      now: new Date('2026-10-31T15:59:00Z'),
    }); // 北京 23:59
    await appendBatch({
      dir,
      recordHashes: ['b'.repeat(64)],
      now: new Date('2026-10-31T16:01:00Z'),
    }); // 北京 00:01
    expect(
      fs
        .readdirSync(dir)
        .filter((f) => f.endsWith('.jsonl'))
        .sort()
    ).toEqual(['2026-10-31.jsonl', '2026-11-01.jsonl']);
  });

  test('【缺陷4】并发追加必须串行：多个 flush 同时写不得把链写成多条 genesis', async () => {
    // 实测缺口：首版 appendBatch 是"读末行 → 算 → append"的读-改-写，并发时全部读到 genesis，
    // 写出三条以 genesis 为父的行 ⇒ verifyManifest 把自己写的合法数据报成 chain_broken（假红）。
    const dir = tmpdir();
    await Promise.all(
      ['a', 'b', 'c', 'd', 'e'].map((h) =>
        appendBatch({ dir, recordHashes: [h.repeat(64)], now: day })
      )
    );
    const v = verifyManifest({ dir, date: day });
    expect(v.problems).toEqual([]);
    expect(v.count).toBe(5);
  });

  test('【边界】坏行夹在中间：后续行仍须逐条校验，不能整份放弃', async () => {
    const dir = tmpdir();
    for (const h of ['a', 'b', 'c']) {
      await appendBatch({
        dir,
        recordHashes: [h.repeat(64)],
        firstSeq: 'r',
        lastSeq: 'r',
        now: day,
      });
    }
    const file = path.join(dir, '2026-10-31.jsonl');
    const lines = fs.readFileSync(file, 'utf8').split('\n').filter(Boolean);
    fs.writeFileSync(file, [lines[0], '{BROKEN', lines[2]].join('\n') + '\n');
    const v = verifyManifest({ dir, date: day });
    expect(v.problems.map((p) => p.type)).toEqual(
      expect.arrayContaining(['unparsable_line', 'chain_broken'])
    );
    expect(v.count).toBe(2); // 第 1、3 行仍被读进来（不因坏行整份放弃）
  });
});

describe('常量与路径：冻结接口', () => {
  test('MANIFEST_VERSION 与目录常量可用（下游 T5/T7 要按同一路径复核）', () => {
    expect(MANIFEST_VERSION).toBe(1);
    expect(typeof MANIFEST_DIR).toBe('string');
    expect(MANIFEST_DIR.endsWith(path.join('logs', 'forensic-manifest'))).toBe(true);
  });
});
