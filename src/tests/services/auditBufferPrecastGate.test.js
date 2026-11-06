/**
 * 批量审计写路径的「预铸造闸」：串链（算哈希）之前先把每条文档对到 schema 上。
 *
 * 【被测的两条同源缺口】同源＝铸造发生在算哈希之后，都出在 auditBuffer.flush 的批量路径
 * （逐条路径 AuditLog.create 先铸造后算哈希，两侧天然同源，不受影响）：
 *
 *  ① 静默丢文档 ⇒ 永久链洞。insertMany({ordered:false}) 对 mongoose 层校验失败的文档是
 *    「resolve 但不返回」：不抛错、不进 writeErrors、零告警，而它的下一条的 prevHash 已经
 *    指向这条从未落库的记录 ⇒ 核验端报 chain_break 假篡改，且永远修不掉（真被改也照样红，
 *    唯一"补救"是整库重签＝销毁取证价值）。它的 WAL 行还照样被本批裁剪吃掉 ⇒ 崩溃重放这层
 *    保险一起没了，`.discarded` 取证文件里也查不到它，droppedCount 还不计。
 *  ② 被哈希的形态 ≠ 落库的形态。schema 里任何改写值的 set/类型转换都让这条记录永久
 *    hash_mismatch（同样是假篡改 + 自身保护静默失效）。utils/auditChain.js 的
 *    PAYLOAD_SCHEMA_DEFAULTS 与 method 降级闸是这一类的两处**镜像补丁**——每新增一个改写器
 *    就得人记得再补一处，漏一次即永久红。本闸从源头消掉整族：将来新写的 setter 无需再镜像。
 *
 * 【判据为什么要收窄到"自己那批"】同一次运行里有别的套件往共享集合并发写审计，
 * 全窗计数等于对"此刻还剩谁"下结论；故一律 verifyAuditChain({filter:{action: 唯一串}})。
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const mongoose = require('mongoose');

const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'audit-precast-'));
process.env.AUDIT_WAL_PATH = path.join(tmpDir, 'precast-test.wal');
process.env.AUDIT_WAL_MAX_BYTES = '100000';
process.env.AUDIT_WAL_STAT_INTERVAL = '1000';

// flush 单轮批次上限在**模块加载时**读定（与 BUFFER_HARD_LIMIT 同法，错配只告警一次），
// 因此必须在 require 之前设值；写在用例体内对已加载的模块毫无作用。
process.env.AUDIT_FLUSH_BATCH_SIZE = '120';
const auditBuffer = require('../../services/auditBuffer');
const wal = require('../../services/auditBufferWal');
const auditDocs = require('../../services/auditBufferDocs');
const AuditLog = require('../../models/AuditLog');
const logger = require('../../utils/logger');
const { verifyAuditChain } = require('../../services/auditChainVerify');
const chain = require('../../utils/auditChain');

const STAMP = `${Date.now()}`.slice(-7);
const ACTION = (name) => `b72_${name}_${STAMP}`;

/** action/category/username 是仅有的三个 required；其余按需覆盖 */
const doc = (action, o) => ({
  action,
  category: 'auth',
  username: `u_${STAMP}`,
  ip: '127.0.0.1',
  path: '/api/auth/login',
  statusCode: 200,
  success: true,
  ...o,
});

const readFile = (p) => {
  try {
    return fs.readFileSync(p, 'utf8');
  } catch (_) {
    return '';
  }
};

/** 按核验口径复算：落库文档自身的内容哈希必须与库里存的一致 */
const recompute = async (id) => {
  const { canonicalPayload, computeHash } = chain;
  const stored = await AuditLog.findById(id).lean();
  return computeHash(
    stored.prevHash,
    canonicalPayload(stored, stored.hashVersion || chain.CURRENT_PAYLOAD_VERSION)
  );
};

/**
 * 带标签的等值断言：变异自检要按"红得对因"判臂（failureContains），
 * 裸 toBe(64 位哈希) 的失败文本里只有两串十六进制，无法区分"链洞"与"形态分叉"两族缺陷。
 */
const same = (label, actual, expected) =>
  expect({ [label]: actual }).toEqual({ [label]: expected });

/**
 * 【本机 I/O 拒绝 vs 闸的行为】Windows 上 `rename(tmp → wal)` 可能返回
 * `EPERM: operation not permitted`：目标文件被杀软/索引器（或上一句 unlink 的延迟删除）
 * 短暂占住时，MoveFileExW(REPLACE_EXISTING) 就给 ACCESS_DENIED。实测（本机，同一棵树）：
 * 并行全量跑 1 次命中；隔离单跑 5 次命中 1 次（约 20%，且**同一份字节**其余 4 次全绿）。
 * 它与预铸造闸无关，而裁剪/追加失败在本仓是**可存活**的——重放按 `__walSeq` 幂等
 * （见 `auditWalReplayIdempotency`），失败也已各自计数（`walAppendFailures`、
 * `noteTrimFailure` ⇒ `walTrimFailures`），所以"这条用例随机红"不是我们要的性质。
 *
 * 豁免只认「`审计 WAL …失败：EPERM`」这一形状（WAL 层 + 错误码必须是 EPERM）。
 * 判据的牙由文件末的「豁免集精确性」用例钉住：任何其它告警文案（含闸自己那几条）
 * 都必须**不**被匹配——把正则放宽成 `/^审计/` 之类，那条用例立刻红。
 */
/**
 * 与预铸造闸无关的启动期噪声：ACL 权限收紧（services/auditWalPermissions）。
 *
 * 本机（Windows 且进程环境里没有 USERNAME）收紧必然失败，于是 start() 期间会有
 * 一条 warn + 一条 error；CI（Linux）上收紧成功、根本不产生这两条。它们出现在
 * errSpy/warnSpy 里时，「恰好 1 条」「一条都没有」这两条判据会被环境决定，
 * 而测的又不是本闸。该子系统的行为由 src/tests/services/auditWalPermissionHardening
 * 与 auditWalPathIsolation 单独钉住，这里按文案逐字筛掉，判据只对着本闸自己的文案。
 */
const ENV_ACL_NOISE = /^审计 WAL (?:目录|文件)权限未能收紧（|^无法确定当前用户名，跳过 ACL 收紧：/;

/** 取某个 spy 收到的、不属于环境噪声的文案 */
const scopedMessages = (spy) =>
  spy.mock.calls.map((c) => String(c[0])).filter((m) => !ENV_ACL_NOISE.test(m));

test('ENV_ACL_NOISE 只命中启动期 ACL 两条文案（放宽容不得）', () => {
  // 豁免集自身也要有反证：把它写宽成 /审计 WAL|无法确定当前用户名/ 时，本闸自己的
  // 警告会被一起吞掉，而所有断言仍是绿的。正样本取自 auditWalPermissions 的两条实测文案，
  // 负样本取自本文件的 MUST_STAY_RED_* 与「权限已收紧」的正常路径。
  const positives = [
    '审计 WAL 目录权限未能收紧（/opt/fsms/logs）：ACE 主体 1 条，可疑 0 条',
    '审计 WAL 文件权限未能收紧（/opt/fsms/logs/audit-buffer.wal）：chmod 失败',
    '无法确定当前用户名，跳过 ACL 收紧：/opt/fsms/logs',
  ];
  for (const m of positives) expect({ m, hit: ENV_ACL_NOISE.test(m) }).toEqual({ m, hit: true });
  const negatives = [
    '审计缓冲超过硬上限，已丢弃最早的一条',
    '审计 WAL 追加失败，本条审计未落盘',
    '审计 WAL 权限已收紧（/opt/fsms/logs）',
    '审计 WAL 启动重放失败：读取失败',
  ];
  for (const m of negatives) expect({ m, hit: ENV_ACL_NOISE.test(m) }).toEqual({ m, hit: false });
  // 自指断言：scopedMessages 真的接在这个正则上（否则上面的精确性只是对着一个死常量）。
  const spy = { mock: { calls: [[positives[0]], [negatives[0]]] } };
  expect(scopedMessages(spy)).toEqual([negatives[0]]);
});

const OS_WAL_EPERM = /^审计 WAL [^：]*：EPERM\b/;

/** 闸/落库链上必须恒红的告警文案（逐字取自 src/services/auditBuffer.js，用例里回查） */
const MUST_STAY_RED_WARN_TEXTS = [
  '审计日志哈希链计算失败，批次将无哈希落库：',
  '审计日志批量落库失败（',
  '条已全部存在于库中（上一轮超时后的延迟落库），',
  '审计日志落库触发异常：',
  '收尾 flush 失败：',
  '审计日志定时落库异常：',
];

/** 不许豁免的那一类样本（即使文案里出现 EPERM 字样也必须照红） */
const MUST_STAY_RED_SAMPLES = [
  '审计 WAL 裁剪失败：ENOENT: no such file or directory',
  '审计 WAL 已归档 3 行毒批取证行并从主 WAL 移除（重启重放不再重复处理）',
  '预铸造闸拒绝 1 条：EPERM 假装是系统错误',
  '审计日志批量落库失败（4 条，连续第 1 次）：EPERM: 假装是系统错误',
];

describe('批量审计写路径：串链前的预铸造闸', () => {
  let errSpy;
  let warnSpy;

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
  });

  beforeEach(async () => {
    await wal.drain();
    auditBuffer.__resetForTest();
    auditBuffer.stop();
    for (const f of [auditBuffer.getWalPath(), `${auditBuffer.getWalPath()}.discarded`]) {
      try {
        fs.unlinkSync(f);
      } catch (_) {
        /* 首轮无文件 */
      }
    }
    errSpy = jest.spyOn(logger, 'error').mockImplementation(() => {});
    warnSpy = jest.spyOn(logger, 'warn').mockImplementation(() => {});
    auditBuffer.start();
  });

  afterEach(async () => {
    await auditBuffer.flushAndStop();
    auditBuffer.stop();
    errSpy.mockRestore();
    warnSpy.mockRestore();
  });

  afterAll(async () => {
    try {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    } catch (_) {
      /* ignore */
    }
    if (mongoose.connection.readyState !== 0) await mongoose.connection.close();
    // 本文件在 require 前设的上限不能泄给同一 worker 里的后续文件（testMatch 顺序不定）
    delete process.env.AUDIT_FLUSH_BATCH_SIZE;
  });

  test('① 批次中间一条不合 schema：不留链洞、行有归档、丢失量可见', async () => {
    const action = ACTION('hole');
    // 中间那条 category 不在枚举内 ⇒ 旧写法下 insertMany 静默少返回一条
    auditBuffer.push(doc(action, { username: `a_ok1_${STAMP}` }));
    auditBuffer.push(doc(action, { category: 'bogus-cat', username: `a_bad_${STAMP}` }));
    auditBuffer.push(doc(action, { username: `a_ok2_${STAMP}` }));
    await auditBuffer.flush();
    await wal.drain();

    const landed = await AuditLog.find({ action }).sort({ _id: 1 }).lean();
    expect(landed.map((d) => d.username)).toEqual([`a_ok1_${STAMP}`, `a_ok2_${STAMP}`]);
    // 旧实现这里最要命的一步：第二条的 prevHash 指向从未落库的那条 ⇒ 永久 chain_break
    same('后继prevHash指回未落库记录', landed[1].prevHash, landed[0].hash);
    const report = await verifyAuditChain(AuditLog, { filter: { action }, maxRecords: 20 });
    expect(report.total).toBe(2);
    expect(report.byType.chain_break).toBe(0);
    expect(report.breaks).toBe(0);

    // 静默丢弃在合规上等同篡改：必须计入累计丢失并 error 级告警
    expect(auditBuffer.getStats().droppedCount).toBe(1);
    const precastErrors = scopedMessages(errSpy);
    expect(precastErrors).toHaveLength(1);
    expect(precastErrors[0]).toMatch(/bogus-cat|category/);
    // 取证顺序：被拒那条的 WAL 行既不在主文件（不会被崩溃重放再插一遍），也已在归档里
    expect(readFile(auditBuffer.getWalPath())).not.toContain('a_bad_');
    expect(readFile(`${auditBuffer.getWalPath()}.discarded`)).toContain('a_bad_');
    expect(auditBuffer.getStats().bufferLength).toBe(0);
  });

  test('① 反证：闸门若跳过预检，同一条记录就真的会被静默丢弃', async () => {
    // 这条钉的是「闸的判据与被闸的机制同源」：不经过 auditBuffer，直接把不合 schema 的
    // 文档送进真实 insertMany，必须看到「resolve 而不落库」——否则上一条的丢弃记账
    // 就是在防一个不存在的现象，本批的全部理由随之塌掉。
    const action = ACTION('proof');
    const ids = [1, 2, 3].map(() => new mongoose.Types.ObjectId());
    const batch = [
      { ...doc(action, { username: `p1_${STAMP}` }), _id: ids[0] },
      { ...doc(action, { username: `p2_${STAMP}` }), category: 'bogus-cat', _id: ids[1] },
      { ...doc(action, { username: `p3_${STAMP}` }), _id: ids[2] },
    ];
    const res = await AuditLog.insertMany(batch, { ordered: false });
    expect(res.length).toBe(2);
    expect(await AuditLog.countDocuments({ action })).toBe(2);
    expect(await AuditLog.exists({ _id: ids[1] })).toBeFalsy();
  });

  test('② 落库形态回写：会改值的载荷逐条都能复算出自己的哈希', async () => {
    const action = ACTION('cast');
    const variants = [
      ['statusCode 数字串', { statusCode: '200' }],
      ['success 数字', { success: 1 }],
      ['success 字符串', { success: 'false' }],
      ['userId 大写十六进制', { userId: '64F000000000000000000001' }],
      ['riskFactors 裸字符串', { riskFactors: 'x' }],
      ['duration 小数串', { duration: '12.7' }],
      ['timestamp 毫秒数', { timestamp: 1777000000123 }],
      ['method 枚举外动词', { method: 'TRACE' }],
      ['params 为 null', { params: null }],
    ];
    for (const [name, o] of variants) {
      auditBuffer.push(doc(action, { username: `c_${name}_${STAMP}`, ...o }));
    }
    await auditBuffer.flush();
    await wal.drain();

    const landed = await AuditLog.find({ action }).lean();
    expect(landed.length).toBe(variants.length);
    // 逐条按核验口径复算：旧写法下这 9 个形态里多个会变红
    for (const d of landed) same('落库形态重算哈希', await recompute(d._id), d.hash);
    const report = await verifyAuditChain(AuditLog, { filter: { action }, maxRecords: 20 });
    expect(report.breaks).toBe(0);
    // 枚举外动词的落库形态仍是「不记 method」（闸只对齐两侧，不改变既有语义）
    const trace = landed.find((d) => d.username.startsWith(`c_method 枚举外动词_`));
    expect(trace.method).toBeUndefined();
    expect(auditBuffer.getStats().droppedCount).toBe(0);
  });

  test('反向对照：全合法批次既不丢也不告警（闸不许过拒）', async () => {
    const action = ACTION('clean');
    for (let i = 0; i < 4; i += 1) {
      auditBuffer.push(doc(action, { username: `k${i}_${STAMP}` }));
    }
    await auditBuffer.flush();
    await wal.drain();
    expect(await AuditLog.countDocuments({ action })).toBe(4);
    expect(auditBuffer.getStats().droppedCount).toBe(0);
    expect(scopedMessages(errSpy)).toEqual([]);
    // 逐条按形状筛，不按"这条用例不该有告警"下结论：见文件头 OS_WAL_EPERM 的实测豁免理由
    const unexpectedWarns = scopedMessages(warnSpy).filter((m) => !OS_WAL_EPERM.test(m));
    expect(unexpectedWarns).toEqual([]);
    expect(readFile(`${auditBuffer.getWalPath()}.discarded`)).toBe('');
  });

  test('整批都被拒时不得送 insertMany（空批抛错会被读成一次莫须有的落库故障）', async () => {
    const spy = jest.spyOn(AuditLog, 'insertMany');
    auditBuffer.push(doc(ACTION('allbad'), { category: 'bogus-cat', username: `z1_${STAMP}` }));
    auditBuffer.push(doc(ACTION('allbad'), { username: '' }));
    await auditBuffer.flush();
    await wal.drain();
    expect(spy).not.toHaveBeenCalled();
    expect(auditBuffer.getStats().bufferLength).toBe(0);
    expect(auditBuffer.getStats().droppedCount).toBe(2);
    spy.mockRestore();
  });

  test('与主文件的接缝：被拒文档按 _id 交回缓冲撤回、逐文档计次一并清掉', () => {
    // precastBatch 不持有缓冲与计数器，丢弃记账全靠 sink 反向调用。这条用例钉的是
    // "协议形状"：删掉任何一路（retract / clearStrike / addDropped）都会在这里变红，
    // 而在集成路径上它们是 0 命中的对账（正常批次根本不在缓冲里），集成用例看不见。
    const calls = [];
    const sink = {
      addDropped: (n) => {
        calls.push(['addDropped', n]);
        return n;
      },
      retract: (ids) => calls.push(['retract', [...ids].sort()]),
      clearStrike: (d) => calls.push(['clearStrike', String(d._id)]),
    };
    const bad = {
      ...doc(ACTION('sink'), { category: 'bogus-cat' }),
      _id: new mongoose.Types.ObjectId(),
    };
    const good = {
      ...doc(ACTION('sink'), { username: `s_ok_${STAMP}` }),
      _id: new mongoose.Types.ObjectId(),
    };

    const accepted = auditDocs.precastBatch([bad, good], sink);
    expect(accepted.map((d) => String(d._id))).toEqual([String(good._id)]);
    expect(calls).toEqual([
      ['retract', [String(bad._id)]],
      ['clearStrike', String(bad._id)],
      ['addDropped', 1],
    ]);

    // 全通过的批次不得产生任何记账（否则"过拒"会以另一种形态漏出来）
    calls.length = 0;
    expect(auditDocs.precastBatch([good], sink)).toEqual([good]);
    expect(calls).toEqual([]);
  });

  test('回写范围必须严格等于当前版本的载荷字段清单', () => {
    // 少回写一个字段＝留一处分叉（②），多回写＝对非载荷字段做无谓的写放大。
    // 版本 bump 而清单没导出时 PRECAST_FIELDS 会回落 V4 ⇒ 这条以红逼人对齐。
    const exported = chain[`PAYLOAD_FIELDS_V${chain.CURRENT_PAYLOAD_VERSION}`];
    expect(exported).toBeTruthy();
    expect(auditDocs.PRECAST_FIELDS).toBe(exported);
    expect(auditDocs.PRECAST_FIELDS).toContain('username');
  });

  test('豁免集精确性：OS 级 EPERM 豁免只认 WAL 那一族形状，闸自己的告警一律不免', () => {
    // 「反向对照」用例把 warnSpy 恒空换成了按形状筛，这条负责证明那条收窄没有把牙拔掉：
    // 把 OS_WAL_EPERM 放宽（例如改成 /^审计/）⇒ 下面第 3 组断言立刻红。
    const readSrc = (p) => fs.readFileSync(path.join(__dirname, '../../services', p), 'utf8');
    const bufferSrc = readSrc('auditBuffer.js');
    const walSrc = readSrc('auditBufferWal.js');

    // 1) 豁免确实命中现场实测到的那两条（原文照抄，含 libuv 的报错前缀）
    expect(
      OS_WAL_EPERM.test(
        "审计 WAL 裁剪失败：EPERM: operation not permitted, rename 'a.wal.tmp' -> 'a.wal'"
      )
    ).toBe(true);
    expect(
      OS_WAL_EPERM.test(
        '审计 WAL 追加失败（累计 1 次）：EPERM: operation not permitted——本条只有内存态'
      )
    ).toBe(true);
    // 被豁免的这两条文案必须还在产品码里（改名 ⇒ 豁免集就该缩小，这里以红逼人对账）
    expect(walSrc).toContain('审计 WAL 裁剪失败：');
    expect(walSrc).toContain('审计 WAL 追加失败（累计');

    // 2) 闸/落库链上的告警文案：逐字在产品码里，且**不**被豁免
    for (const text of MUST_STAY_RED_WARN_TEXTS) {
      expect({ text, inSource: bufferSrc.includes(text) }).toEqual({ text, inSource: true });
      expect(OS_WAL_EPERM.test(text)).toBe(false);
    }

    // 3) 反例样本：出现 EPERM 字样也不许免（非 WAL 前缀 / 非 EPERM 码 / 无冒号形状）
    for (const text of MUST_STAY_RED_SAMPLES) expect(OS_WAL_EPERM.test(text)).toBe(false);

    // 4) 自指：那条筛除必须**真的**接在这个正则上。把 `.filter(...)` 改成常量 false
    //    （或直接删掉那行断言）会让「反向对照」对告警变成空判，而 1)~3) 全都不会响。
    //    针脚自己拼出来，否则本行就含一份针脚文本、计数恒 1（第一版就踩了这个坑）。
    const needle = ['!OS_WAL_EPERM', '.test(m)'].join('');
    const self = fs.readFileSync(path.join(__dirname, path.basename(__filename)), 'utf8');
    expect(self.split(needle).length - 1).toBe(1);
  });
  test('预检拒收文案不得先于归档事实：discard 只是移交队列，不写「已归档/已移除」', () => {
    // 第十一轮 D7：wal.discardBySeqs 是 fire-and-forget（返回 undefined，归档排在 wal 链上）。
    // 文案原先写「已归档到 … 并从主文件移除」——完成时措辞先于事实：调用返回时归档
    // 可能还没发生、也可能随后失败。这条用例把"此刻只是移交队列"钉在案发时刻。
    const discardSpy = jest.spyOn(wal, 'discardBySeqs').mockReturnValue(undefined);
    errSpy.mockClear();
    try {
      const bad = {
        ...doc(ACTION('claim'), { category: 'bogus-cat' }),
        _id: new mongoose.Types.ObjectId(),
        __walSeq: `zzq-claim-${STAMP}`,
      };
      const sink = { addDropped: () => 1, retract: () => {}, clearStrike: () => {} };
      expect(auditDocs.precastBatch([bad], sink)).toEqual([]);
      expect(discardSpy).toHaveBeenCalledTimes(1);
      const msg = scopedMessages(errSpy).find((m) => m.includes('预铸造中被拒'));
      expect(msg).toBeTruthy();
      // 归档尚未落定 ⇒ 完成时措辞一律不允许
      expect(msg).not.toMatch(/已归档/);
      expect(msg).not.toMatch(/并从主文件移除/);
      // 只允许「移交队列」这一档
      expect(msg).toMatch(/移交归档队列/);
    } finally {
      discardSpy.mockRestore();
    }
  });
});

describe('A7：flush 单轮批次上限（splice 截断，余量留待下一轮）', () => {
  // 批次上限改为每次 flush 现读（模块加载读定会被随机序下先 require 的套件钉死），
  // 本 describe 的上限值因此必须**自管**：文件级 :33 的设置在上方 describe 的
  // afterAll（:193 防泄漏清理）里已被删除，不能依赖。
  beforeAll(() => {
    process.env.AUDIT_FLUSH_BATCH_SIZE = '120';
    // 链僵尸冻结是 worker 级跨文件状态（auditBufferZombie 类套件 freeze 后不随套件
    // 复位）：冻结窗口内本用例的 flush 被 isChainFrozen 整体跳过 ⇒ insertMany spy
    // 收空数组（seed 31337 实测 [100] 变 []）。A7 量的是 splice 截断，必须解冻。
    require('../../utils/auditChainFence').reset();
  });
  afterAll(() => {
    delete process.env.AUDIT_FLUSH_BATCH_SIZE;
  });

  const pushN = (n) => {
    for (let i = 0; i < n; i += 1) {
      auditBuffer.push(doc(`b7cap_${STAMP}`, { path: `/cap/${i}` }));
    }
  };

  test('push 250 条、上限 120 ⇒ insertMany 依次收到 100(自动触发,不足上限)/120/30', async () => {
    const insertSpy = jest.spyOn(AuditLog, 'insertMany').mockImplementation(async (docs) => docs);
    try {
      pushN(250);
      // push 循环是同步的：第 100 条触发的自动 flush 在循环里只跑了同步前缀
      //（splice 100 条后让出），其余推入不会再次触发。等它收尾后再看余量。
      await auditBuffer.__waitForFlushIdle();
      const lengths = () => insertSpy.mock.calls.map((c) => c[0].length);
      expect(lengths()).toEqual([100]); // 自动轮：缓冲只有 100 条，上限未绑定
      expect(auditBuffer.getStats().bufferLength).toBe(150);

      await auditBuffer.flush(); // 上限绑定：只取 120
      expect(lengths()).toEqual([100, 120]);
      expect(auditBuffer.getStats().bufferLength).toBe(30);

      await auditBuffer.flush(); // 余量取尽
      expect(lengths()).toEqual([100, 120, 30]);
      expect(auditBuffer.getStats().bufferLength).toBe(0);
    } finally {
      insertSpy.mockRestore();
    }
  });
});
