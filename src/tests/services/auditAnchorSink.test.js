/**
 * 审计检查点**外部锚定**：传输（ship / fetch）与双向比对
 *
 * 被测的不变式（每一条都对应一条真实的攻击路径）：
 *  1. 改链 → 删本地检查点文件 → 重新 create：旧实现判 PASS，外锚比对必须判
 *     `anchor_missing_local`。这是本功能存在的唯一理由，用「本地只剩新锚点、外部
 *     还有三条旧锚点」的现场钉住。
 *  2. 只截断检查点文件末尾（不动 Mongo）：同样必须被发现。
 *  3. 外部副本被改写：判 `anchor_signature_invalid`，且**不得**因「验不过就跳过」
 *     而退化成「无失配」。
 *  4. 外部存储为空：判 `no_external_anchors`，不得当成「比对通过」。
 *  5. 本地有、外部无：只记 pending（刚 create 还没 ship 是正常态），不判红。
 *  6. ship 只发存储里还没有的（幂等）；本地有一条验不过签名时**整体拒绝外发**，
 *     否则会往 append-only / WORM 存储里推入不可删除的伪造锚点。
 *  7. 外部存储读不出来（非 JSON / 形状不对 / HTTP 错误）与「存储里确实没东西」必须
 *     分开编码——前者判「判据不可用」，后者才是 no_external_anchors。
 *
 * http sink 的用例起**真实**本地 server 做对端（理由同 httpPostJsonDeadline.test.js：
 * mock 只能验证「我以为的调用序列」，真实 server 才能验证真的发出了什么）。
 */

'use strict';

const fs = require('fs');
const http = require('http');
const os = require('os');
const path = require('path');

const {
  CHECKPOINT_VERSION,
  compareAnchors,
  createCheckpoint,
  signCheckpoint,
  verifyCheckpoints,
} = require('../../services/auditChainCheckpoint');
const {
  SINK_ENV,
  ALLOWLIST_ENV,
  ALLOW_PRIVATE_ENV,
  resolveSink,
  readAnchorStore,
  shipCheckpoints,
} = require('../../services/auditAnchorSink');

const SECRET = 'anchor-test-secret';

/** 造一条签名有效的检查点记录（签名口径与被测模块同源，不分叉）。 */
function mkRecord(seq, overrides = {}) {
  const record = {
    version: CHECKPOINT_VERSION,
    createdAt: new Date(Date.UTC(2026, 9, 20, seq, 0, 0)).toISOString(),
    headId: String(seq).padStart(24, '0'),
    headHash: `hash-${seq}`,
    headHmac: `hmac-${seq}`,
    recordCount: seq,
    ...overrides,
  };
  record.signature = signCheckpoint(record, SECRET);
  return record;
}

const entryOf = (record, line) => ({ line, record });

/** 假 AuditLog：只实现本模块实际调用的两种查询，不把 Mongo 行为当被测对象。 */
function fakeModel(docs) {
  const state = docs.map((doc) => ({ ...doc }));
  const resultOf = (query) => {
    if (query.hash && query.hash.$ne === null) {
      const hashed = state.filter((doc) => doc.hash != null);
      return hashed.length ? { ...hashed[hashed.length - 1] } : null;
    }
    // 按 hash 值直查：链尾初始化（utils/auditChainTail）先取尾 hash，再据此取头部文档。
    // 少了这一支，链尾会被判成 null ⇒ 检查点退化成「空链锚点」（实测算出 headHash:null 的假现场）。
    if (typeof query.hash === 'string') {
      const hit = state.find((doc) => doc.hash === query.hash);
      return hit ? { ...hit } : null;
    }
    if (query._id !== undefined) {
      const hit = state.find((doc) => String(doc._id) === String(query._id));
      return hit ? { ...hit } : null;
    }
    return null;
  };
  return {
    state,
    findOne: jest.fn((query) => {
      const result = resultOf(query);
      const chain = { sort: () => chain, lean: async () => result };
      return chain;
    }),
    countDocuments: jest.fn(async (query) => {
      if (query && query._id && query._id.$lte !== undefined) {
        return state.filter((doc) => String(doc._id) <= String(query._id.$lte)).length;
      }
      // 生产口径：recordCount 只数「带哈希」的记录（hash:{$ne:null}），不是集合总数。
      // 假模型若按总数回答，一旦现场混入无哈希行，计数判据就会在测试里假绿。
      if (query && query.hash && query.hash.$ne === null) {
        return state.filter((doc) => doc.hash != null).length;
      }
      return state.length;
    }),
  };
}

describe('auditAnchorSink.resolveSink', () => {
  const savedSink = process.env[SINK_ENV];
  const savedAllow = process.env[ALLOWLIST_ENV];
  const savedAllowPrivate = process.env[ALLOW_PRIVATE_ENV];

  afterEach(() => {
    if (savedSink === undefined) delete process.env[SINK_ENV];
    else process.env[SINK_ENV] = savedSink;
    if (savedAllow === undefined) delete process.env[ALLOWLIST_ENV];
    else process.env[ALLOWLIST_ENV] = savedAllow;
    if (savedAllowPrivate === undefined) delete process.env[ALLOW_PRIVATE_ENV];
    else process.env[ALLOW_PRIVATE_ENV] = savedAllowPrivate;
  });

  test('file: 前缀解析为绝对路径，且不带告警', () => {
    const sink = resolveSink('file:./anchors/store.jsonl');
    expect(sink.kind).toBe('file');
    expect(sink.path).toBe(path.resolve(process.cwd(), './anchors/store.jsonl'));
    expect(sink.warnings).toEqual([]);
  });

  test('file: 后为空、URL 无法解析、协议非 http(s) 各有独立编码', () => {
    expect(resolveSink('file:')).toMatchObject({ kind: null, reason: 'file_path_empty' });
    expect(resolveSink('://nope')).toMatchObject({ kind: null, reason: 'url_unparsable' });
    expect(resolveSink('ftp://anchor.internal/x')).toMatchObject({
      kind: null,
      reason: 'protocol_not_allowed',
    });
  });

  test('主机白名单配了就校验：不在名单内拒绝，在名单内放行且无告警', () => {
    process.env[ALLOWLIST_ENV] = 'anchor.internal, other.example';
    expect(resolveSink('https://evil.example/anchors')).toMatchObject({
      kind: null,
      reason: 'host_not_allowlisted',
    });
    const ok = resolveSink('https://anchor.internal:9000/anchors');
    expect(ok).toMatchObject({ kind: 'http', host: 'anchor.internal' });
    expect(ok.warnings).toEqual([]);
  });

  test('白名单未配置 → 拒绝（fail-closed），不再"放行 + 一条警告"', () => {
    // 口径变更（2026-10-31，审计一-4）：原实现放行 + 一条 warning，理由是
    // "AUDIT_ANCHOR_SINK 与 MONGODB_URI 同级信任"。这条理由挡不住真实失效：
    // 改错的域名会把**签名有效的检查点**（链头 hash + 计数 + 签名）持续发给陌生人，
    // 而 cron 的 warning 没人看。现在未配白名单即拒绝。
    delete process.env[ALLOWLIST_ENV];
    expect(resolveSink('https://anchor.internal/anchors')).toMatchObject({
      kind: null,
      reason: 'allowlist_not_configured',
      host: 'anchor.internal',
    });
  });

  test('私网/回环/链路本地与歧义 IPv4 默认拒绝（即使已在白名单里也一样）', () => {
    // 白名单是"允许发给谁"，私网闸是"这类地址本身不接受"：两道判据独立成立，
    // 白名单里写上私网地址不等于放行（要放行走 AUDIT_ANCHOR_ALLOW_PRIVATE_HOSTS）。
    process.env[ALLOWLIST_ENV] = '127.0.0.1,169.254.169.254,10.0.0.7,::1,anchor.internal';
    for (const raw of [
      'http://127.0.0.1:9000/anchors',
      'https://169.254.169.254/latest/meta-data',
      'http://10.0.0.7/anchors',
      'http://[::1]/anchors',
      // 歧义形态：OS 当 127.0.0.1 连，但严格解析判不出私网 ⇒ 一并拒绝
      'http://127.1/anchors',
      'http://2130706433/anchors',
    ]) {
      expect(resolveSink(raw)).toMatchObject({
        kind: null,
        reason: 'host_private_not_allowed',
      });
    }
    // 反面对照：同一份白名单里的公网主机照常放行（判据不是"一律拒绝"）
    expect(resolveSink('https://anchor.internal/anchors')).toMatchObject({
      kind: 'http',
      host: 'anchor.internal',
    });
  });

  test('AUDIT_ANCHOR_ALLOW_PRIVATE_HOSTS 可显式放行内网目标（主机名 / IP / 网段）', () => {
    process.env[ALLOWLIST_ENV] = 'siem.internal,192.168.5.9';
    expect(resolveSink('http://192.168.5.9/anchors')).toMatchObject({
      kind: null,
      reason: 'host_private_not_allowed',
    });
    process.env[ALLOW_PRIVATE_ENV] = '192.168.5.9';
    expect(resolveSink('http://192.168.5.9/anchors')).toMatchObject({ kind: 'http' });
    // 网段形态走 ipMatchesEntry（与 IP 名单同一把尺）
    process.env[ALLOW_PRIVATE_ENV] = '192.168.5.0/24';
    expect(resolveSink('http://192.168.5.9/anchors')).toMatchObject({ kind: 'http' });
    // 主机名形态：精确匹配
    process.env[ALLOW_PRIVATE_ENV] = 'siem.internal';
    expect(resolveSink('http://siem.internal/logs')).toMatchObject({ kind: 'http' });
    // 放行只针对声明的那个目标，别的私网地址仍然拒绝
    expect(resolveSink('http://10.1.2.3/anchors')).toMatchObject({
      kind: null,
      reason: 'host_private_not_allowed',
    });
  });

  test('未配置（参数与环境变量都没有）→ not_configured', () => {
    delete process.env[SINK_ENV];
    expect(resolveSink()).toMatchObject({ kind: null, reason: 'not_configured' });
    expect(resolveSink('   ')).toMatchObject({ kind: null, reason: 'not_configured' });
  });
});

describe('compareAnchors（双向比对）', () => {
  test('本地与外部完全一致 ⇒ 无错误、无 pending', () => {
    const records = [mkRecord(1), mkRecord(2)];
    const result = compareAnchors({
      localEntries: records.map((r, i) => entryOf(r, i + 1)),
      externalAnchors: records,
      secret: SECRET,
    });
    expect(result.errors).toEqual([]);
    expect(result.pending).toEqual([]);
    expect(result.externalValid).toHaveLength(2);
  });

  test('【核心】删本地文件后重新 create：外部旧锚点在本地缺失 ⇒ 逐条 anchor_missing_local', () => {
    // 攻击现场：外部已锚定 seq 1..3；攻击者改链后删文件，create 出一条全新锚点
    const external = [mkRecord(1), mkRecord(2), mkRecord(3)];
    const reAnchored = mkRecord(4, { headHash: 'hash-4-tampered' });

    const result = compareAnchors({
      localEntries: [entryOf(reAnchored, 1)],
      externalAnchors: external,
      secret: SECRET,
    });

    expect(result.errors.map((e) => e.type)).toEqual([
      'anchor_missing_local',
      'anchor_missing_local',
      'anchor_missing_local',
    ]);
    // 本地这条新锚点还没外发 ⇒ pending，而不是错误
    expect(result.pending).toEqual([
      expect.objectContaining({ line: 1, headId: reAnchored.headId }),
    ]);
  });

  test('只截断检查点文件末尾（Mongo 未动）同样被发现', () => {
    const records = [mkRecord(1), mkRecord(2), mkRecord(3)];
    const result = compareAnchors({
      localEntries: records.slice(0, 2).map((r, i) => entryOf(r, i + 1)),
      externalAnchors: records,
      secret: SECRET,
    });
    expect(result.errors).toEqual([expect.objectContaining({ type: 'anchor_missing_local' })]);
    expect(result.errors[0].message).toContain(records[2].headId);
  });

  test('外部副本被改写 ⇒ anchor_signature_invalid，不得静默跳过', () => {
    const records = [mkRecord(1), mkRecord(2)];
    const tampered = { ...records[1], recordCount: 1 }; // 改字段但不重签

    const result = compareAnchors({
      localEntries: records.map((r, i) => entryOf(r, i + 1)),
      externalAnchors: [records[0], tampered],
      secret: SECRET,
    });

    expect(result.errors).toEqual([expect.objectContaining({ type: 'anchor_signature_invalid' })]);
    // 被改的那条不参与「已锚定」判定
    expect(result.externalValid).toHaveLength(1);
  });

  test('外部锚点版本不支持 ⇒ anchor_version_unsupported', () => {
    const record = mkRecord(1, { version: 999 });
    const result = compareAnchors({
      localEntries: [entryOf(mkRecord(1), 1)],
      externalAnchors: [record],
      secret: SECRET,
    });
    expect(result.errors).toEqual([
      expect.objectContaining({ type: 'anchor_version_unsupported' }),
    ]);
  });

  test('外部存储为空 ⇒ no_external_anchors（不是「无失配」）', () => {
    const result = compareAnchors({
      localEntries: [entryOf(mkRecord(1), 1)],
      externalAnchors: [],
      secret: SECRET,
    });
    expect(result.errors).toEqual([expect.objectContaining({ type: 'no_external_anchors' })]);
  });

  test('外部记录形状不可识别（不是对象 / 缺 signature）⇒ anchor_signature_invalid', () => {
    const result = compareAnchors({
      localEntries: [entryOf(mkRecord(1), 1)],
      externalAnchors: [null, { version: CHECKPOINT_VERSION }],
      secret: SECRET,
    });
    expect(result.errors).toEqual([
      expect.objectContaining({ type: 'anchor_signature_invalid' }),
      expect.objectContaining({ type: 'anchor_signature_invalid' }),
    ]);
  });

  test('本地验签不过的行不重复计入 pending（同一处篡改只报一次）', () => {
    const good = mkRecord(1);
    const bad = { ...mkRecord(2), headHash: 'rewritten' }; // 签名失配
    const result = compareAnchors({
      localEntries: [entryOf(good, 1), entryOf(bad, 2)],
      externalAnchors: [good],
      secret: SECRET,
    });
    expect(result.errors).toEqual([]);
    expect(result.pending).toEqual([]);
  });
});

describe('compareAnchors · D8：外部回滚与「还没发」必须分开（2026-10-31）', () => {
  test('① 正常落后：外锚停在更早的水位 ⇒ 仍记 pending，不得判红', () => {
    const local = [mkRecord(1), mkRecord(2), mkRecord(3)];
    const result = compareAnchors({
      localEntries: local.map((r, i) => entryOf(r, i + 1)),
      externalAnchors: [mkRecord(1), mkRecord(2)],
      secret: SECRET,
    });
    expect(result.errors).toEqual([]);
    expect(result.pending).toEqual([expect.objectContaining({ line: 3, headId: local[2].headId })]);
  });

  test('② 外锚里已有更晚的锚点、本地更早的那条在外锚里缺失 ⇒ anchor_rollback（不得混进 pending）', () => {
    // 现场：本地 c1→c2→c3；外锚只剩 c1 与 c3。ship 是「按文件序把本地缺的一次性全推」，
    // c3 能进外锚就说明 c2 当时也在本地、也该一起进去 ⇒ c2 现在不在外锚只可能是被回退掉了。
    const c1 = mkRecord(1);
    const c2 = mkRecord(2);
    const c3 = mkRecord(3);
    const result = compareAnchors({
      localEntries: [c1, c2, c3].map((r, i) => entryOf(r, i + 1)),
      externalAnchors: [c1, c3],
      secret: SECRET,
    });
    expect(result.errors.map((e) => e.type)).toEqual(['anchor_rollback']);
    expect(result.errors[0]).toMatchObject({ line: 2 });
    expect(result.errors[0].message).toContain(c2.headId);
    expect(result.errors[0].message).toContain(c3.headId);
    expect(result.pending).toEqual([]);
  });

  test('③ 外锚整份被清空（present 但零条）⇒ 判错 no_external_anchors，不是 pending：空存储证明不了任何事', () => {
    // 判定理由：外锚这一路的全部价值是「外部有独立副本」。零条时既不能证明失配、也不能
    // 证明无失配；把它读成 pending 等于让「把外部副本清空」变成一种无成本的掩盖手段。
    const result = compareAnchors({
      localEntries: [entryOf(mkRecord(1), 1)],
      externalAnchors: [],
      secret: SECRET,
    });
    expect(result.errors.map((e) => e.type)).toEqual(['no_external_anchors']);
    expect(result.pending).toEqual([]);
  });
  test('②b 本地记录的 createdAt 是坏串 ⇒ 不判回滚、不抛：水位证不出「发过又被撤」', () => {
    // 同一现场（本地 c1→c2→c3，外锚只有 c1 与 c3），只把 c2 的 createdAt 换成不可解析的值。
    // 判据必须退到 pending 而不是猜成回滚：回滚的前提是「c2 早于外锚水位」，而坏串算不出先后。
    // 顺带钉住不抛：new Date(坏串).getTime() 得 NaN，NaN 参与比较恒 false，成本不能变成异常。
    const c1 = mkRecord(1);
    const c2 = { ...mkRecord(2), createdAt: 'not-a-date' };
    const c3 = mkRecord(3);
    // 坏串会破坏签名（签名覆盖 createdAt），改用「签名有效但时间不可解析」的构造：
    // 直接重签一次，保证本用例测的是水位判据，而不是签名闸先把它拦掉。
    c2.signature = signCheckpoint(c2, SECRET);
    const result = compareAnchors({
      localEntries: [c1, c2, c3].map((r, i) => entryOf(r, i + 1)),
      externalAnchors: [c1, c3],
      secret: SECRET,
    });
    expect(result.errors).toEqual([]);
    expect(result.pending).toEqual([expect.objectContaining({ line: 2, headId: c2.headId })]);
  });
});
describe('verifyCheckpoints 与 externalAnchors 的组合', () => {
  let dir;
  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'audit-anchor-'));
  });
  afterEach(() => {
    fs.rmSync(dir, { recursive: true, force: true });
  });
  const filePath = () => path.join(dir, 'checkpoints.jsonl');

  /** 用假模型建一个真检查点，返回它写出的记录。 */
  async function buildCheckpoint(docs, now) {
    const model = fakeModel(docs);
    const { record } = await createCheckpoint({
      model,
      filePath: filePath(),
      secret: SECRET,
      now,
    });
    return { model, record };
  }

  test('不传 externalAnchors ⇒ 结果里没有 anchors 键（旧契约逐字不变）', async () => {
    const { model } = await buildCheckpoint([
      { _id: '000000000000000000000010', hash: 'h1', hmac: 'm1' },
    ]);
    const result = await verifyCheckpoints({ model, filePath: filePath(), secret: SECRET });
    expect(result).toEqual({ ok: true, checked: 1, errors: [] });
    expect('anchors' in result).toBe(false);
  });

  test('本地与外部一致 ⇒ ok，并带 anchors 统计', async () => {
    const { model, record } = await buildCheckpoint([
      { _id: '000000000000000000000010', hash: 'h1', hmac: 'm1' },
    ]);
    const result = await verifyCheckpoints({
      model,
      filePath: filePath(),
      secret: SECRET,
      externalAnchors: [record],
    });
    expect(result).toEqual({
      ok: true,
      checked: 1,
      errors: [],
      anchors: { compared: 1, pending: 0, externalValid: 1 },
    });
  });

  test('【核心】检查点文件被删 + 外部仍有锚点 ⇒ 判 anchor_missing_local，不是 no_checkpoints', async () => {
    const external = [mkRecord(1), mkRecord(2)];
    const model = fakeModel([]);
    const result = await verifyCheckpoints({
      model,
      filePath: filePath(), // 文件不存在
      secret: SECRET,
      externalAnchors: external,
    });
    expect(result.ok).toBe(false);
    expect(result.errors.map((e) => e.type)).toEqual([
      'anchor_missing_local',
      'anchor_missing_local',
    ]);
    expect(result.errors.some((e) => e.type === 'no_checkpoints')).toBe(false);
  });

  test('外部为空且本地为空 ⇒ no_external_anchors + no_checkpoints 两条都在', async () => {
    const result = await verifyCheckpoints({
      model: fakeModel([]),
      filePath: filePath(),
      secret: SECRET,
      externalAnchors: [],
    });
    expect(result.errors.map((e) => e.type)).toEqual(['no_external_anchors', 'no_checkpoints']);
  });

  test('外部锚点全部验签不过 ⇒ 不因「验不过就跳过」而判通过', async () => {
    const { model, record } = await buildCheckpoint([
      { _id: '000000000000000000000010', hash: 'h1', hmac: 'm1' },
    ]);
    const result = await verifyCheckpoints({
      model,
      filePath: filePath(),
      secret: SECRET,
      externalAnchors: [{ ...record, recordCount: 99 }],
    });
    expect(result.ok).toBe(false);
    expect(result.errors).toEqual([
      expect.objectContaining({ type: 'anchor_signature_invalid' }),
      // 本地这条既没被外部确认、外部那条也没验过 ⇒ pending 1，但 pending 不是错误
    ]);
    expect(result.anchors).toMatchObject({ compared: 1, pending: 1, externalValid: 0 });
  });

  /**
   * 对照实验：**同一个**被篡改现场，跑两遍。
   *
   * 这是整个外锚功能唯一的正当性证明——不是「多了一个检查项」，而是
   * 「旧口径在这个现场判 PASS」。如果哪一天有人把 externalAnchors 那条分支删掉，
   * 上半段仍然绿，下半段才会红，红点直接指向缺失的能力。
   *
   * 现场：原链 A→B→C，检查点①锚在 C（计数 3）。攻击者把 B、C 删掉、改写 A 的内容、
   * 重算链，然后删掉检查点文件再跑一次 create，得到检查点②（锚在 A'，计数 1）。
   * 攻击全程不需要 HMAC_SECRET：签名由服务自己算。
   */
  test('【对照】删文件重新锚定：旧口径判 PASS，加外锚比对才判 anchor_missing_local', async () => {
    const model = fakeModel([
      { _id: '000000000000000000000010', hash: 'hash-a', hmac: 'hmac-a' },
      { _id: '000000000000000000000020', hash: 'hash-b', hmac: 'hmac-b' },
      { _id: '000000000000000000000030', hash: 'hash-c', hmac: 'hmac-c' },
    ]);
    const first = await createCheckpoint({
      model,
      filePath: filePath(),
      secret: SECRET,
      now: new Date('2026-10-20T00:00:00.000Z'),
    });
    expect(first.record).toMatchObject({ headHash: 'hash-c', recordCount: 3 });

    // —— 攻击：改链（删 B/C + 改写 A 的内容）并删掉检查点文件 ——
    model.state.length = 0;
    model.state.push({
      _id: '000000000000000000000010',
      hash: 'hash-a-rewritten',
      hmac: 'hmac-a2',
    });
    fs.rmSync(filePath());
    await createCheckpoint({
      model,
      filePath: filePath(),
      secret: SECRET,
      now: new Date('2026-10-20T06:00:00.000Z'),
    });

    // ① 旧口径（只看本地文件 + 当前库）：签名有效、头部一致、计数一致、链尾未倒退
    const blind = await verifyCheckpoints({ model, filePath: filePath(), secret: SECRET });
    expect(blind.ok).toBe(true);
    expect(blind.errors).toEqual([]);

    // ② 加外锚比对：检查点①还在外部存储里，本地已经没有了
    const anchored = await verifyCheckpoints({
      model,
      filePath: filePath(),
      secret: SECRET,
      externalAnchors: [first.record],
    });
    expect(anchored.ok).toBe(false);
    expect(anchored.errors.map((e) => e.type)).toEqual(['anchor_missing_local']);
    // 消息里带的是 headId（运维要拿它去库里查那条记录），不是 headHash
    expect(anchored.errors[0].message).toContain('000000000000000000000030');
  });
});

describe('shipCheckpoints（file sink）', () => {
  let dir;
  let localFile;
  let storeFile;

  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'audit-anchor-ship-'));
    localFile = path.join(dir, 'checkpoints.jsonl');
    storeFile = path.join(dir, 'anchors', 'store.jsonl');
  });
  afterEach(() => {
    fs.rmSync(dir, { recursive: true, force: true });
  });

  const writeLocal = (records) =>
    fs.writeFileSync(localFile, records.map((r) => `${JSON.stringify(r)}\n`).join(''));
  const readStore = () =>
    fs.existsSync(storeFile)
      ? fs
          .readFileSync(storeFile, 'utf8')
          .split('\n')
          .filter(Boolean)
          .map((line) => JSON.parse(line))
      : [];

  test('首次外发全部；二次外发 0 条（幂等，不重复追加）', async () => {
    const records = [mkRecord(1), mkRecord(2)];
    writeLocal(records);
    const sink = resolveSink(`file:${storeFile}`);

    const first = await shipCheckpoints({ filePath: localFile, sink, secret: SECRET });
    expect(first).toMatchObject({ ok: true, shipped: 2, alreadyAnchored: 0, pending: 0 });
    expect(readStore()).toHaveLength(2);

    const second = await shipCheckpoints({ filePath: localFile, sink, secret: SECRET });
    expect(second).toMatchObject({ ok: true, shipped: 0, alreadyAnchored: 2 });
    expect(readStore()).toHaveLength(2);
  });

  test('新增检查点只外发增量', async () => {
    const sink = resolveSink(`file:${storeFile}`);
    writeLocal([mkRecord(1), mkRecord(2)]);
    await shipCheckpoints({ filePath: localFile, sink, secret: SECRET });

    writeLocal([mkRecord(1), mkRecord(2), mkRecord(3)]);
    const result = await shipCheckpoints({ filePath: localFile, sink, secret: SECRET });
    expect(result).toMatchObject({ ok: true, shipped: 1, alreadyAnchored: 2 });
    expect(readStore()).toHaveLength(3);
  });

  test('本地有一条验签不过 ⇒ 整体拒绝外发，存储保持为空（防不可逆污染）', async () => {
    const good = mkRecord(1);
    const bad = { ...mkRecord(2), headHash: 'rewritten' };
    writeLocal([good, bad]);
    const sink = resolveSink(`file:${storeFile}`);

    const result = await shipCheckpoints({ filePath: localFile, sink, secret: SECRET });
    expect(result).toMatchObject({ ok: false, error: 'local_checkpoint_invalid', shipped: 0 });
    expect(result.invalid).toEqual([expect.objectContaining({ line: 2 })]);
    expect(result.pending).toBe(1);
    expect(fs.existsSync(storeFile)).toBe(false);
  });

  test('未配置 sink / 未配置密钥 ⇒ 各自独立编码，不静默成功', async () => {
    writeLocal([mkRecord(1)]);
    const notConfigured = await shipCheckpoints({
      filePath: localFile,
      sink: resolveSink(''),
      secret: SECRET,
    });
    expect(notConfigured).toMatchObject({ ok: false, error: 'sink_not_configured' });

    // 空 secret 会回落到 config.hmacSecret（与 createCheckpoint 同源），因此必须
    // 把配置也清空才是「真的没有密钥」——只传 '' 在这个环境里不算。
    const config = require('../../config');
    const original = config.hmacSecret;
    config.hmacSecret = '';
    try {
      const noSecret = await shipCheckpoints({
        filePath: localFile,
        sink: resolveSink(`file:${storeFile}`),
        secret: '',
      });
      expect(noSecret.ok).toBe(false);
      expect(noSecret.error).toBe('hmac_not_configured');
    } finally {
      config.hmacSecret = original;
    }
  });

  test('锚点存储里有坏行 ⇒ anchor_store_malformed（不跳过、不覆盖）', async () => {
    writeLocal([mkRecord(1)]);
    fs.mkdirSync(path.dirname(storeFile), { recursive: true });
    fs.writeFileSync(storeFile, '{not json}\n');

    const result = await shipCheckpoints({
      filePath: localFile,
      sink: resolveSink(`file:${storeFile}`),
      secret: SECRET,
    });
    expect(result).toMatchObject({ ok: false, error: 'anchor_store_malformed' });
  });

  test('file sink 存在但零条 ⇒ present:true + emptied:true（与「从未创建」分开）；ship 颜色不变但必须说出来', async () => {
    fs.mkdirSync(path.dirname(storeFile), { recursive: true });
    fs.writeFileSync(storeFile, '', 'utf8');
    const store = await readAnchorStore(resolveSink(`file:${storeFile}`));
    expect(store).toMatchObject({ ok: true, present: true, emptied: true, anchors: [] });

    // 对照：文件根本不存在时没有 emptied 概念（= 尚未创建，不是被清空）
    const missing = await readAnchorStore(resolveSink(`file:${path.join(dir, 'nope.jsonl')}`));
    expect(missing).toMatchObject({ ok: true, present: false, anchors: [] });
    expect(missing.emptied).toBeUndefined();

    writeLocal([mkRecord(1)]);
    const shipped = await shipCheckpoints({
      filePath: localFile,
      sink: resolveSink(`file:${storeFile}`),
      secret: SECRET,
    });
    // 判据颜色不变：清空不是外发失败，ship 仍会把本地全部锚点重新推入（append-only 可恢复）
    expect(shipped).toMatchObject({ ok: true, shipped: 1 });
    // 但它必须被大声说出来——否则「外部被清空」在 ship 侧也是静默的
    expect(shipped.warnings.join('\n')).toMatch(/被清空|存在但为空/);
  });
  test('本地没有任何检查点 ⇒ 成功但零条（不是错误，也不算外发成功过）', async () => {
    const result = await shipCheckpoints({
      filePath: localFile,
      sink: resolveSink(`file:${storeFile}`),
      secret: SECRET,
    });
    expect(result).toMatchObject({ ok: true, shipped: 0, alreadyAnchored: 0 });
  });
});

describe('shipCheckpoints / readAnchorStore（http sink）', () => {
  let server;
  let base;
  let store;
  let posts;
  let getStatus;
  let postStatus;
  let getBody;

  // 本组用**真实**本地 server 当对端（http://127.0.0.1:<port>）。2026-10-31 起
  // http sink 是两道硬闸（白名单必配 + 私网默认拒），故这里按运维的真实做法
  // 显式声明：白名单写上 127.0.0.1，并用 ALLOW_PRIVATE_HOSTS 放行回环地址。
  // 不这样声明的话，本组测的就不再是传输语义，而是被闸门挡在 resolveSink 之前
  // ——那正是下面「未配置白名单 ⇒ 拒绝」那条用例单独钉住的形态。
  const savedAllow = process.env[ALLOWLIST_ENV];
  const savedAllowPrivate = process.env[ALLOW_PRIVATE_ENV];

  beforeEach(() => {
    store = [];
    posts = [];
    getStatus = 200;
    postStatus = 200;
    getBody = null;
    process.env[ALLOWLIST_ENV] = '127.0.0.1';
    process.env[ALLOW_PRIVATE_ENV] = '127.0.0.1';
  });

  afterEach(async () => {
    if (savedAllow === undefined) delete process.env[ALLOWLIST_ENV];
    else process.env[ALLOWLIST_ENV] = savedAllow;
    if (savedAllowPrivate === undefined) delete process.env[ALLOW_PRIVATE_ENV];
    else process.env[ALLOW_PRIVATE_ENV] = savedAllowPrivate;
    if (server) {
      await new Promise((resolve) => server.close(resolve));
      server = null;
    }
  });

  const start = () =>
    new Promise((resolve) => {
      server = http.createServer((req, res) => {
        if (req.method === 'GET') {
          res.writeHead(getStatus, { 'Content-Type': 'application/json' });
          res.end(getBody === null ? JSON.stringify({ anchors: store }) : getBody);
          return;
        }
        const chunks = [];
        req.on('data', (c) => chunks.push(c));
        req.on('end', () => {
          const parsed = JSON.parse(Buffer.concat(chunks).toString('utf8'));
          posts.push(parsed);
          res.writeHead(postStatus, { 'Content-Type': 'application/json' });
          if (postStatus < 300) {
            store.push(...parsed.anchors);
            res.end(JSON.stringify({ accepted: parsed.anchors.length }));
          } else {
            res.end('{}');
          }
        });
      });
      server.listen(0, '127.0.0.1', () => {
        base = `http://127.0.0.1:${server.address().port}/anchors`;
        resolve();
      });
    });

  test('GET 空存储（200 {anchors:[]}）⇒ POST 全部锚点', async () => {
    await start();
    const records = [mkRecord(1), mkRecord(2)];
    const result = await shipCheckpoints({
      filePath: writeTemp(records),
      sink: resolveSink(base),
      secret: SECRET,
    });
    expect(result).toMatchObject({ ok: true, shipped: 2 });
    expect(posts).toHaveLength(1);
    expect(posts[0].anchors).toHaveLength(2);
    expect(posts[0].anchorVersion).toBe(1);
  });

  test('GET 404 ⇒ 视为存储尚未创建，POST 全部', async () => {
    getStatus = 404;
    await start();
    const result = await shipCheckpoints({
      filePath: writeTemp([mkRecord(1)]),
      sink: resolveSink(base),
      secret: SECRET,
    });
    expect(result).toMatchObject({ ok: true, shipped: 1 });
  });

  test('存储里已有锚点 ⇒ 只 POST 增量', async () => {
    const existing = [mkRecord(1), mkRecord(2)];
    store = [...existing];
    await start();
    const result = await shipCheckpoints({
      filePath: writeTemp([mkRecord(1), mkRecord(2), mkRecord(3)]),
      sink: resolveSink(base),
      secret: SECRET,
    });
    expect(result).toMatchObject({ ok: true, shipped: 1, alreadyAnchored: 2 });
    expect(posts[0].anchors).toHaveLength(1);
  });

  test('GET 返回看不懂的形状（{}）⇒ anchor_store_bad_shape，且一条都不 POST', async () => {
    getBody = '{}';
    await start();
    const result = await shipCheckpoints({
      filePath: writeTemp([mkRecord(1)]),
      sink: resolveSink(base),
      secret: SECRET,
    });
    expect(result).toMatchObject({ ok: false, error: 'anchor_store_bad_shape' });
    expect(posts).toEqual([]);
  });

  test('GET 返回非 JSON ⇒ anchor_store_not_json，不误判成空存储', async () => {
    getBody = '<html>oops</html>';
    await start();
    const store1 = await readAnchorStore(resolveSink(base));
    expect(store1).toMatchObject({ ok: false, error: 'anchor_store_not_json' });
  });

  test('GET 非 2xx ⇒ anchor_store_http_error（判据不可用，不能当空存储）', async () => {
    getStatus = 503;
    await start();
    const result = await readAnchorStore(resolveSink(base));
    expect(result).toMatchObject({ ok: false, error: 'anchor_store_http_error' });
  });

  test('POST 非 2xx ⇒ ok=false 且 pending 记为未外发条数', async () => {
    postStatus = 500;
    await start();
    const result = await shipCheckpoints({
      filePath: writeTemp([mkRecord(1), mkRecord(2)]),
      sink: resolveSink(base),
      secret: SECRET,
    });
    expect(result).toMatchObject({ ok: false, error: 'anchor_store_http_error', pending: 2 });
  });

  test('对端不可达 ⇒ anchor_store_unreachable（不抛异常）', async () => {
    const result = await readAnchorStore(resolveSink('http://127.0.0.1:1/anchors'), {
      timeoutMs: 300,
    });
    expect(result).toMatchObject({ ok: false, error: 'anchor_store_unreachable' });
    expect(result.anchors).toEqual([]);
  });
});

/** 给 http 用例造一个临时检查点文件（用完不清理也不影响断言，随进程结束消失）。 */
function writeTemp(records) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'audit-anchor-http-'));
  const file = path.join(dir, 'checkpoints.jsonl');
  fs.writeFileSync(file, records.map((r) => `${JSON.stringify(r)}\n`).join(''));
  return file;
}

describe('audit-chain-checkpoint CLI 新增参数', () => {
  const { parseArgs, COMMANDS } = require('../../../scripts/audit-chain-checkpoint');

  test('ship 子命令可用；旧参数解析结果不变（新键默认 undefined 被 toEqual 忽略）', () => {
    expect(COMMANDS).toEqual(['create', 'verify', 'ship']);
    expect(parseArgs(['create'])).toEqual({ command: 'create', filePath: undefined });
    expect(parseArgs(['verify', '--file=logs/x.jsonl'])).toEqual({
      command: 'verify',
      filePath: 'logs/x.jsonl',
    });
  });

  test('--ship / --anchors / --anchors=<sink> / --no-anchors 各自解析', () => {
    expect(parseArgs(['create', '--ship'])).toMatchObject({ command: 'create', ship: true });
    expect(parseArgs(['verify', '--anchors'])).toMatchObject({ anchors: true });
    expect(parseArgs(['verify', '--anchors=file:logs/a.jsonl'])).toMatchObject({
      anchors: 'file:logs/a.jsonl',
    });
    expect(parseArgs(['verify', '--no-anchors'])).toMatchObject({ anchorsDisabled: true });
  });

  test('参数放错子命令一律报错（被忽略会让运维误以为已外发/已比对）', () => {
    expect(() => parseArgs(['verify', '--ship'])).toThrow(/--ship 只能与 create/);
    expect(() => parseArgs(['create', '--anchors'])).toThrow(/只能与 verify/);
    expect(() => parseArgs(['ship', '--no-anchors'])).toThrow(/只能与 verify/);
    expect(() => parseArgs(['verify', '--anchors', '--no-anchors'])).toThrow(/不能同时使用/);
    expect(() => parseArgs(['verify', '--anchors='])).toThrow(/无法识别的参数/);
  });
});
