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
    expect(errSpy).toHaveBeenCalledTimes(1);
    expect(String(errSpy.mock.calls[0][0])).toMatch(/bogus-cat|category/);
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
    expect(errSpy).not.toHaveBeenCalled();
    // 逐条按形状筛，不按"这条用例不该有告警"下结论：见文件头 OS_WAL_EPERM 的实测豁免理由
    const unexpectedWarns = warnSpy.mock.calls
      .map((c) => String(c[0]))
      .filter((m) => !OS_WAL_EPERM.test(m));
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
});
