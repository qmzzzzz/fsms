/**
 * 审计 hmac 轮换预检（resign-audit-hmac.js）：拒绝必须早于改写，且不许灭迹
 *
 * 缺陷本体：`hash` 是无密钥 SHA-256，所以只具备 DB 写权限的攻击者改内容时可以
 * 顺手把 hash 重算自洽——防篡改链上唯一会红的一层就是 hmac。原脚本
 * 「对不上新钥就一律重签」，于是运维照 Runbook 跑完 --apply 之后，
 * verify-audit-chain 会对一份被改过的库报「完整」，且原实现边扫边写
 * （拒绝判定即便存在，前面的批次也已经落库）。
 *
 * 判据设计（三条各有分工，缺一条就留有假绿空间）：
 * 1. 分类真值表（纯函数，含"对不上新钥"的两种成因必须分开这一格）；
 * 2. 行为判据：预检报告确实印了 ⇒ 拒绝来自预检而不是白名单/连不上库；
 *    并且**四条文档一字未动**（这才是"拒绝早于改写"，只看退出码会被
 *    "先写后拒"骗过去）；
 * 3. 反向对照：越权标志真能放行，否则"永远拒绝"也能让第 2 条全绿。
 *
 * 环境陷阱（都实测过）：本仓 .env 里有 HMAC_SECRET 与 MONGODB_URI，
 * 子进程顶层 dotenv 会把被 delete 掉的键补回来 ⇒ 造"缺当前密钥"必须显式
 * 置空串（dotenv 不覆盖已存在的 own 键），并同时 delete HMAC_SECRET_FILE，
 * 否则 secrets.hydrateSecretsFromFiles 会用文件内容把密钥恢复（文件优先于环境变量）。
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const mongoose = require('mongoose');
const { spawnSync } = require('child_process');

const ROOT = path.resolve(__dirname, '../../..');
const SCRIPT = path.join(ROOT, 'scripts', 'resign-audit-hmac.js');
const NODE = process.execPath;

const OLD_KEY = '11'.repeat(32);
const NEW_KEY = '22'.repeat(32);
const ATTACKER_KEY = '33'.repeat(32);

// 新密钥经文件给出：`--new-key` 已移除（写在 argv 上的密钥会进 /proc/<pid>/cmdline 与 shell 历史）。
// 本套件的判据里有"四条文档一字未动"这种逐字比对，argv 形态换了就得连带改夹具，
// 而夹具改错的失效方向是"脚本拿到空密钥"——那会走 unverifiable 分支，报的仍是拒绝，只是原因不同。
const KEY_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'fsms-hmac-resign-'));
const KEY_FILE = path.join(KEY_DIR, 'new_hmac');
fs.writeFileSync(KEY_FILE, `${NEW_KEY}\n`);

const hmacOf = (secret, hash) =>
  crypto.createHmac('sha256', secret).update(hash, 'utf8').digest('hex');

const URI = process.env.MONGODB_URI;
// setup.js 已按 worker+文件 分配独立库名，这里不再另起库，避免污染别的套件
// （完整性套件会在共享 auditlogs 上断言"零断裂"）。
const DB_NAME = URI.split('/').pop().split('?')[0];

const { classifyHmacState } = require(SCRIPT);

const HASHES = {
  clean: 'hash-signed-by-old-key',
  suspect: 'hash-tampered-then-recomputed',
  unsigned: 'hash-never-signed',
  already: 'hash-signed-by-new-key',
};

async function seedFixture() {
  const coll = mongoose.connection.collection('auditlogs');
  await coll.deleteMany({ hash: { $in: Object.values(HASHES) } });
  const docs = [
    { _id: new mongoose.Types.ObjectId(), hash: HASHES.clean, hmac: hmacOf(OLD_KEY, HASHES.clean) },
    {
      _id: new mongoose.Types.ObjectId(),
      hash: HASHES.suspect,
      hmac: hmacOf(ATTACKER_KEY, HASHES.suspect),
    },
    { _id: new mongoose.Types.ObjectId(), hash: HASHES.unsigned },
    {
      _id: new mongoose.Types.ObjectId(),
      hash: HASHES.already,
      hmac: hmacOf(NEW_KEY, HASHES.already),
    },
  ];
  await coll.insertMany(docs);
  return docs.reduce(
    (acc, d) => ({ ...acc, [path.basename(String(d.hash).replace('hash-', ''))]: d }),
    {}
  );
}

async function readBack() {
  const coll = mongoose.connection.collection('auditlogs');
  const rows = await coll
    .find({ hash: { $in: Object.values(HASHES) } }, { projection: { hash: 1, hmac: 1 } })
    .toArray();
  return rows.reduce((acc, r) => ({ ...acc, [r.hash]: r.hmac === undefined ? null : r.hmac }), {});
}

function runScript({ apply, allowSuspect, currentKey }) {
  const env = { ...process.env, MONGODB_URI: URI, ALLOWED_SOURCE_DB: DB_NAME };
  if (currentKey === undefined) {
    // 缺当前密钥：必须显式置空，delete 会被 .env 的 dotenv 注入补回来
    env.HMAC_SECRET = '';
    delete env.HMAC_SECRET_FILE;
  } else {
    env.HMAC_SECRET = currentKey;
    delete env.HMAC_SECRET_FILE; // 否则文件内容会覆盖上面的取值
  }
  delete env.NEW_HMAC_SECRET;
  const argv = ['--new-key-file', KEY_FILE];
  if (apply) argv.push('--apply', '--yes');
  if (allowSuspect) argv.push('--allow-suspect-hmac');
  const r = spawnSync(NODE, [SCRIPT, ...argv], {
    cwd: ROOT,
    encoding: 'utf8',
    timeout: 25000,
    env,
  });
  return { code: r.status, out: `${r.stdout || ''}${r.stderr || ''}` };
}

beforeAll(async () => {
  await mongoose.connect(URI);
});

afterAll(async () => {
  if (mongoose.connection.readyState !== 0) {
    await mongoose.connection
      .collection('auditlogs')
      .deleteMany({ hash: { $in: Object.values(HASHES) } });
    await mongoose.disconnect();
  }
  fs.rmSync(KEY_DIR, { recursive: true, force: true });
});

describe('hmac 轮换预检的分类判定（纯函数真值表）', () => {
  test('已是新钥签名优先于一切（幂等重跑不该被当成篡改）', () => {
    expect(
      classifyHmacState({
        hasHmac: true,
        matchesNewKey: true,
        hasCurrentKey: true,
        matchesCurrentKey: false,
      })
    ).toBe('already_signed');
  });

  test('"从没有过 hmac"与"当前钥解不开"必须分成两格', () => {
    expect(
      classifyHmacState({
        hasHmac: false,
        matchesNewKey: false,
        hasCurrentKey: true,
        matchesCurrentKey: false,
      })
    ).toBe('never_signed');
    expect(
      classifyHmacState({
        hasHmac: true,
        matchesNewKey: false,
        hasCurrentKey: true,
        matchesCurrentKey: false,
      })
    ).toBe('suspect');
    expect(
      classifyHmacState({
        hasHmac: true,
        matchesNewKey: false,
        hasCurrentKey: true,
        matchesCurrentKey: true,
      })
    ).toBe('clean');
  });

  test('拿不到当前密钥时是 unverifiable，不得混进 clean', () => {
    expect(
      classifyHmacState({
        hasHmac: true,
        matchesNewKey: false,
        hasCurrentKey: false,
        matchesCurrentKey: false,
      })
    ).toBe('unverifiable');
  });
});

describe('hmac 轮换预检的落库行为', () => {
  beforeEach(async () => {
    await seedFixture();
  });

  test('脚本可被 require 而不触发连库（否则单测一 import 就跑副作用）', () => {
    const r = spawnSync(
      NODE,
      [
        '-e',
        "require(process.argv[1]); process.exit(require('mongoose').connection.readyState)",
        SCRIPT,
      ],
      { cwd: ROOT, encoding: 'utf8', timeout: 20000 }
    );
    // readyState 0 = 没有任何连接：require 只取走判定函数
    expect(r.status).toBe(0);
  });

  test('演练模式：报出灭迹风险但仍退出 0，四条文档一字未动', async () => {
    const { code, out } = runScript({ apply: false, currentKey: OLD_KEY });
    expect(out).toContain('预检分类');
    expect(out).toContain('当前钥解不开（疑似被改） ：1');
    expect(code).toBe(0);
    const rows = await readBack();
    expect(rows[HASHES.clean]).toBe(hmacOf(OLD_KEY, HASHES.clean));
    expect(rows[HASHES.suspect]).toBe(hmacOf(ATTACKER_KEY, HASHES.suspect));
    expect(rows[HASHES.unsigned]).toBe(null);
  });

  test('--apply 无越权标志 ⇒ 拒绝，且拒绝发生在任何改写之前', async () => {
    const { code, out } = runScript({ apply: true, currentKey: OLD_KEY });
    expect(code).toBe(2);
    // 前提自证：预检报告已经印出来 ⇒ 这条红不是白名单/连不上库给的
    expect(out).toContain('预检分类');
    expect(out).toContain('拒绝执行');
    const rows = await readBack();
    expect(rows[HASHES.clean]).toBe(hmacOf(OLD_KEY, HASHES.clean));
    expect(rows[HASHES.suspect]).toBe(hmacOf(ATTACKER_KEY, HASHES.suspect));
    expect(rows[HASHES.unsigned]).toBe(null);
    expect(rows[HASHES.already]).toBe(hmacOf(NEW_KEY, HASHES.already));
  });

  test('缺当前密钥时同样拒绝：那种重签不构成完整性背书', async () => {
    const { code, out } = runScript({ apply: true, currentKey: undefined });
    expect(code).toBe(2);
    expect(out).toContain('无法预检');
    const rows = await readBack();
    expect(rows[HASHES.clean]).toBe(hmacOf(OLD_KEY, HASHES.clean));
    expect(rows[HASHES.unsigned]).toBe(null);
  });

  test('反向对照：显式越权后确实改写（否则上面几条"永远拒绝"也算绿）', async () => {
    const { code, out } = runScript({
      apply: true,
      allowSuspect: true,
      currentKey: OLD_KEY,
    });
    expect(code).toBe(0);
    expect(out).toContain('越权放行 1 条');
    const rows = await readBack();
    expect(rows[HASHES.clean]).toBe(hmacOf(NEW_KEY, HASHES.clean));
    expect(rows[HASHES.suspect]).toBe(hmacOf(NEW_KEY, HASHES.suspect));
    expect(rows[HASHES.unsigned]).toBe(hmacOf(NEW_KEY, HASHES.unsigned));
    // 已是新钥签名的那条不需要改写，值不变
    expect(rows[HASHES.already]).toBe(hmacOf(NEW_KEY, HASHES.already));
  });
});
