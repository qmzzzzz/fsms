/**
 * 审计链存量重签（resign-audit-chain-v3.js）的改写前预检
 *
 * 缺陷本体：该脚本按库内**现值**重算 hash，并且**重建整条 prevHash 链**。
 * 只具备数据库写权限的攻击者改内容时可以顺手把 hash/prevHash 全部重算自洽
 * （无密钥 SHA-256 谁都能算），链上唯一会红的一层是 hmac。于是照 Runbook
 * 跑一次 `--apply --yes` 之后：
 *   · 被改过的字段 → 重签后与哈希完全一致；
 *   · 被删掉的记录 → 后继的 prevHash 被重建，链接痕迹一起消失；
 *   · 事后 verify-audit-chain 对这份被洗过的库报「链完整」。
 * 即重签不是修复，是**给可能已被改写的库补签**。修复=改写前先跑一次与复核
 * 同源的全量核验（computeChainVerdict），判不了就不 --apply，越权须显式表态。
 *
 * 三条判据的分工（缺一条就留有假绿空间）：
 * 1. 纯函数真值表：四种「能不能宣称完整 × 是否 apply × 是否越权」的组合；
 * 2. 行为判据：篡改链（攻击者已把 hash/prevHash 重算自洽）必须被拒，
 *    且**所有文档一字未动**——只看退出码会被"先写后拒"骗过去；
 * 3. 反向对照：干净链的 --apply 必须真的改写成功（hashVersion 2→当前版本），
 *    否则"永远拒绝"也能让第 2 条全绿，而运维脚本也就此废掉。
 *
 * 环境陷阱与同族 hmac 预检用例一致：.env 里有 HMAC_SECRET/MONGODB_URI，
 * 子进程顶层 dotenv 会把 delete 掉的键补回来 ⇒ 显式赋值 + 删 HMAC_SECRET_FILE
 * （文件优先于环境变量）。
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const mongoose = require('mongoose');
const { spawnSync } = require('child_process');

const ROOT = path.resolve(__dirname, '../../..');
const SCRIPT = path.join(ROOT, 'scripts', 'resign-audit-chain-v3.js');
const NODE = process.execPath;

const KEY = 'aa'.repeat(32);
const ACTIONS = ['zzq_a1', 'zzq_a2', 'zzq_a3'];
// 时间戳必须落在 TTL 留存期内：auditlogs 的 {timestamp:-1} 索引按
// AUDIT_RETENTION_DAYS（默认 180 天，下限 90）过期清扫，写死的历史日期会被
// mongod 约 60s 一轮的 TTL sweep 删光（2026-11-07 CI 实证：snapshot 读到 []）。
// 本文件断言只比较前后快照相等、哈希由 TS 现算，不依赖具体日期，故取加载时刻。
const TS = new Date();
// 2026-11-04 起越权旗标必须携带变更单号（=值形态）：放行凭据无据 = 持钥者单方可灭迹，
// 单号连同预检计数写进 append-only 重签留痕（logs/audit-resign-log.jsonl，已 gitignore）。
const ALLOW_SUSPECT_TICKET = 'NW-TEST-1';

const {
  canonicalPayload,
  computeHash,
  CURRENT_PAYLOAD_VERSION,
} = require('../../utils/auditChain');
const hmacOf = (secret, hash) =>
  crypto.createHmac('sha256', secret).update(hash, 'utf8').digest('hex');

const URI = process.env.MONGODB_URI;
const DB_NAME = URI.split('/').pop().split('?')[0];

const { parseArgs, decidePrecheck } = require(SCRIPT);

const coll = () => mongoose.connection.collection('auditlogs');
const mine = () => ({ action: { $in: ACTIONS } });

/**
 * 造一条 v2 口径的链（hashVersion=2 是"待升级到当前版本"的真实形态，
 * 也让"有没有被改写"有一个可观测的标记：重签后应为 CURRENT_PAYLOAD_VERSION）。
 * tamper='selfconsistent' 模拟攻击者：改 action 后把 hash/prevHash 全部重算自洽，
 * 但 hmac 保持原值——他没有密钥。
 */
async function seedChain({ tamper } = {}) {
  await coll().deleteMany(mine());
  let prev = null;
  const rows = [];
  for (const action of ACTIONS) {
    const doc = {
      _id: new mongoose.Types.ObjectId(),
      timestamp: TS,
      action,
      category: 'security',
      hashVersion: 2,
    };
    doc.prevHash = prev;
    doc.hash = computeHash(prev, canonicalPayload(doc, 2));
    doc.hmac = hmacOf(KEY, doc.hash);
    prev = doc.hash;
    rows.push(doc);
  }
  if (tamper === 'selfconsistent') {
    // 改的是 v2 payload 覆盖内的字段（category）。选 description 是不成立的攻击：
    // v2 从未把它纳入哈希，改它本就不会让任何一层红（这正是升 v4 的理由）。
    rows[1].category = 'system';
    let p = rows[0].hash;
    for (let i = 1; i < rows.length; i += 1) {
      rows[i].prevHash = p;
      rows[i].hash = computeHash(p, canonicalPayload(rows[i], 2));
      p = rows[i].hash;
    }
  }
  await coll().insertMany(rows);
  return rows;
}

async function snapshot() {
  const rows = await coll()
    .find(mine(), {
      projection: {
        action: 1,
        category: 1,
        timestamp: 1,
        hash: 1,
        hmac: 1,
        prevHash: 1,
        hashVersion: 1,
      },
    })
    .sort({ _id: 1 })
    .toArray();
  return rows.map((r) => ({
    action: r.action,
    category: r.category,
    timestamp: r.timestamp,
    hash: r.hash,
    hmac: r.hmac,
    prevHash: r.prevHash,
    hashVersion: r.hashVersion,
  }));
}

function runScript({ apply, confirmYes = true, allowSuspect, extraArgs } = {}) {
  const env = {
    ...process.env,
    MONGODB_URI: URI,
    ALLOWED_SOURCE_DB: DB_NAME,
    HMAC_SECRET: KEY,
  };
  delete env.HMAC_SECRET_FILE;
  delete env.NEW_HMAC_SECRET;
  const argv = [];
  if (apply) argv.push('--apply');
  if (confirmYes) argv.push('--yes');
  // true = 带 =单号 的合法越权形态；'bare' = 裸旗标（2026-11-04 起按用法错误拒绝）
  if (allowSuspect === true) argv.push(`--allow-suspect-chain=${ALLOW_SUSPECT_TICKET}`);
  else if (allowSuspect === 'bare') argv.push('--allow-suspect-chain');
  if (extraArgs) argv.push(...extraArgs);
  const r = spawnSync(NODE, [SCRIPT, ...argv], {
    cwd: ROOT,
    encoding: 'utf8',
    timeout: 60000,
    env,
  });
  return { code: r.status, out: `${r.stdout || ''}${r.stderr || ''}` };
}

describe('resign-audit-chain-v3 的改写前预检', () => {
  beforeAll(async () => {
    await mongoose.connect(URI);
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      await coll().deleteMany(mine());
      await mongoose.disconnect();
    }
  });

  // ---- 判据 1：纯函数真值表 ----
  test.each([
    ['完整 + apply', { intact: true, apply: true, allow: false }, true],
    ['不完整 + apply + 无越权', { intact: false, apply: true, allow: false }, false],
    ['不完整 + apply + 越权标志', { intact: false, apply: true, allow: true }, true],
    ['不完整 + 演练（无 apply）', { intact: false, apply: false, allow: false }, true],
  ])('%s ⇒ proceed=%s', (_label, { intact, apply, allow }, expected) => {
    expect(
      decidePrecheck({
        verdict: { canAttestIntact: intact, reasons: ['r'] },
        apply,
        allowSuspect: allow,
      })
    ).toBe(expected);
  });

  test('前提自证：干净链在**没跑脚本**时确实能通过同源核验（否则拒绝来自夹具而不是预检）', async () => {
    await seedChain();
    const r = runScript();
    expect(r.out).toContain('断裂 0');
    expect(r.out).toContain('能否宣称完整：能');
    expect(r.code).toBe(0);
  });

  // ---- 判据 2：篡改必须被拒，且拒绝早于改写 ----
  test('攻击者把 hash/prevHash 重算自洽后 --apply ⇒ 拒绝，且一条都不改写', async () => {
    await seedChain({ tamper: 'selfconsistent' });
    const before = await snapshot();
    // 前提自证（这条决定整组用例有没有判别力）：篡改者的 hash 是**自洽**的——
    // 无密钥 SHA-256 他当然能重算，链接也接得回去；只有 hmac 打不开。
    // 所以"只看 breaks/hash 是否自洽"的判据必然放过这份库，而预检必须拦住。
    expect(computeHash(before[1].prevHash, canonicalPayload(before[1], 2))).toBe(before[1].hash);
    expect(hmacOf(KEY, before[1].hash)).not.toBe(before[1].hmac);
    expect(hmacOf(KEY, before[0].hash)).toBe(before[0].hmac);
    const r = runScript({ apply: true });
    expect(r.out).toContain('预检（改写前）');
    expect(r.out).toMatch(/hmac_mismatch|断裂 [1-9]/);
    expect(r.out).toContain('拒绝执行');
    expect(r.code).toBe(2);
    // 最关键：拒绝必须发生在任何改写之前（先写后拒等于没拒）
    expect(await snapshot()).toEqual(before);
  });

  test('演练模式：报出预检结论但退 0，且同样一字未动', async () => {
    await seedChain({ tamper: 'selfconsistent' });
    const before = await snapshot();
    const r = runScript({ apply: false });
    expect(r.code).toBe(0);
    expect(r.out).toContain('不能');
    expect(r.out).toContain('演练模式未改写任何记录');
    expect(await snapshot()).toEqual(before);
  });

  // ---- 判据 3：反向对照，预检不得退化成"永远拒绝" ----
  test('干净链 --apply --yes ⇒ 预检放行并真的升级到当前版本', async () => {
    await seedChain();
    const before = await snapshot();
    expect(before.every((d) => d.hashVersion === 2)).toBe(true);
    const r = runScript({ apply: true });
    expect(r.out).not.toContain('拒绝执行');
    expect(r.code).toBe(0);
    const after = await snapshot();
    // 钉住**当前**版本，不写死数字：升版忘了同步用例会红在这里，而不是红在一个看似对的旧数字上
    expect(after.every((d) => d.hashVersion === CURRENT_PAYLOAD_VERSION)).toBe(true);
    // 链尾被重建（当前口径下 hash 必然不同于 v2）
    expect(after[2].hash).not.toBe(before[2].hash);
  });

  // 判据 4（版本号有人守）：脚本产出的 hashVersion 必须是 CURRENT_PAYLOAD_VERSION，
  // 且脚本**自己不许写死版本数字**——写死就说明它没跟上常量，升版时不会有任何东西红。
  // 这条与上面两条的分工：上面测"跑出来的结果对不对"，这里测"脚本有没有把版本号变成常量"。
  test('resign 脚本按 CURRENT_PAYLOAD_VERSION 走，不写死版本数字', () => {
    const src = fs.readFileSync(SCRIPT, 'utf8');
    // 反向对照：写死一个与当前版本不同的数字必须被判红（把下面这条判据改成恒真，本用例仍绿但失去意义）
    const hardcoded = /(hashVersion\s*=\s*)(\d+)/g;
    const offenders = [];
    let m = hardcoded.exec(src);
    while (m) {
      offenders.push(Number(m[2]));
      m = hardcoded.exec(src);
    }
    expect(offenders).toEqual([]);
    // 正向：脚本必须从 auditChain 取常量，且真的用它算 hash 与落版本
    expect(src).toContain('CURRENT_PAYLOAD_VERSION');
    expect(src).toMatch(/canonicalPayload\(payload,\s*CURRENT_PAYLOAD_VERSION\)/);
    // 版本号本身仍由常量定义（不是本用例写死的 4/5），所以升版只需改 auditChainPayload.js
    expect(typeof CURRENT_PAYLOAD_VERSION).toBe('number');
  });

  test('反向对照：越权标志确实放行改写（否则"拒绝"可以是恒真的）', async () => {
    await seedChain({ tamper: 'selfconsistent' });
    const before = await snapshot();
    const r = runScript({ apply: true, allowSuspect: true });
    expect(r.out).toContain('越权放行');
    expect(r.code).toBe(0);
    const after = await snapshot();
    expect(after.every((d) => d.hashVersion === CURRENT_PAYLOAD_VERSION)).toBe(true);
    expect(after[1].hash).not.toBe(before[1].hash);
  });

  test('缺 --yes 时拒绝执行（二次确认闸不得因为新增预检而被绕过或前移）', async () => {
    await seedChain({ tamper: 'selfconsistent' });
    const before = await snapshot();
    const r = runScript({ apply: true, confirmYes: false });
    expect(r.code).toBe(2);
    expect(r.out).toContain('--yes');
    // 此时甚至还没连库，更不该有改写
    expect(await snapshot()).toEqual(before);
  });

  test('未知参数直接拒绝，不得静默当成"没传"而只跑演练还报成功', async () => {
    await seedChain();
    const before = await snapshot();
    const r = runScript({ apply: true, extraArgs: ['--aply'] });
    expect(r.code).toBe(2);
    expect(r.out).toContain('未知参数');
    expect(await snapshot()).toEqual(before);
  });

  test('裸旗标越权（不带变更单号）按用法错误拒绝——放行凭据无据不得静默成立', async () => {
    await seedChain({ tamper: 'selfconsistent' });
    const before = await snapshot();
    const r = runScript({ apply: true, allowSuspect: 'bare' });
    expect(r.code).toBe(2);
    expect(r.out).toContain('必须携带变更单号');
    // 拒绝发生在任何改写之前
    expect(await snapshot()).toEqual(before);
  });

  test('parseArgs：三个标志位各自独立生效', () => {
    expect(parseArgs(['node', 'x.js', '--apply'])).toEqual({
      apply: true,
      confirmYes: false,
      allowSuspect: false,
      suspectTicket: null,
    });
    expect(
      parseArgs(['node', 'x.js', '--yes', `--allow-suspect-chain=${ALLOW_SUSPECT_TICKET}`])
    ).toMatchObject({
      apply: false,
      confirmYes: true,
      allowSuspect: true,
      suspectTicket: ALLOW_SUSPECT_TICKET,
    });
  });
});
