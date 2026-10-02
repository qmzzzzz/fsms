/**
 * 破坏性脚本的护栏**顺序**门禁：未获准就一个字节都不许碰目标库
 *
 * 背景：`scripts/destructiveGuard.js` 把"要不要放行"收敛成了单一声明，
 * 但没收敛"什么时候问"。三个脚本（migrate-mfa-secret / resign-audit-hmac /
 * fix-token-blacklist-index）原先是
 *   resolveMongoUri → **mongoose.connect** → 打印已连接 → assertApplyAllowed
 * 后果：
 *  - 一次"被护栏拒绝"的执行，仍然先向目标库（可能就是生产库）发起 TCP + 鉴权握手；
 *  - 库不可达时 Mongoose 默认重试 30s（实测：`--apply` 无白名单跑这两个脚本
 *    会一直卡到我 20~25s 的超时被 kill，exit 为 null），运维看到的是"脚本挂死"
 *    而不是"被 fail-closed 拦下"——正是护栏最该给出的信号。
 * 现在三个脚本都改成 resolveMongoUri → assertApplyAllowed → connect。
 *
 * 判据用"多快给出拒绝"而不是"输出了什么"，因为连接失败的信息随环境而变，
 * 而"拒绝必须发生在毫秒级、且不带任何连接痕迹"是顺序的直接后果。
 * 另附一条静态完备性不变量：任何直接操作集合的脚本都必须引入护栏，
 * 且正则本身有前提自证（防"正则写错⇒空集恒真"的假绿）。
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const ROOT = path.resolve(__dirname, '../..');
const SCRIPTS = path.join(ROOT, 'scripts');
const NODE = process.execPath;

// 一个必然连不上的库名：只要脚本真去 connect，就会卡在 serverSelection 重试里
const PROBE_ENV = {
  ...process.env,
  MONGODB_URI: 'mongodb://127.0.0.1:1/guard_probe_db',
  ALLOWED_SOURCE_DB: '', // 故意留空 ⇒ fail-closed 必须拒绝
};

const KEY64 = 'a1b2c3d4e5f60718293a4b5c6d7e8f90'.repeat(2);
// 新密钥经文件给出（`--new-key` 已移除：写在 argv 上的密钥会进 /proc/<pid>/cmdline 与 shell 历史）。
// 必须是**真文件且强度合格**：migrate-mfa-secret 的强度闸门排在护栏之前，给个空文件就会
// 以「拒绝迁移」退出 2，而本用例断言的是「拒绝执行」这句护栏话术——那时绿的是错的分支。
const KEY_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'fsms-guard-order-'));
const KEY_FILE = path.join(KEY_DIR, 'new_key');
fs.writeFileSync(KEY_FILE, `${KEY64}\n`);
const DESTRUCTIVE = [
  ['migrate-mfa-secret.js', ['--apply', '--new-key-file', KEY_FILE]],
  ['resign-audit-hmac.js', ['--apply', '--yes', '--new-key-file', KEY_FILE]],
  ['resign-audit-chain-v3.js', ['--apply', '--yes']],
  ['fix-token-blacklist-index.js', ['--apply', '--yes']],
  ['sync-audit-indexes.js', ['--apply', '--yes']],
  ['revoke-user-sessions.js', ['zznosuchuser', '--apply', '--yes']],
  // 破坏性最强的一个（清空 users/roles/permissions/auditlogs 四集合后回灌）原先
  // **不在本名单里**——§27.3(e)：强度与覆盖不匹配。它的开关是 --apply-source
  // （不是 --apply），且护栏前移后拒绝发生在 connect 之前，故不会建目录、不连库。
  ['run-rollback-drill.js', ['--apply-source', '--yes']],
];

describe('破坏性脚本：白名单校验必须先于数据库连接', () => {
  afterAll(() => {
    fs.rmSync(KEY_DIR, { recursive: true, force: true });
  });

  test.each(DESTRUCTIVE)('%s：--apply 且无白名单 ⇒ 秒级 exit 2 并给出拒绝原因', (file, args) => {
    const t0 = Date.now();
    const r = spawnSync(NODE, [path.join(SCRIPTS, file), ...args], {
      cwd: ROOT,
      encoding: 'utf8',
      timeout: 15000,
      env: PROBE_ENV,
    });
    const ms = Date.now() - t0;
    const out = `${r.stderr || ''}${r.stdout || ''}`;

    expect(out).toContain('拒绝执行');
    expect(r.status).toBe(2);
    // 顺序判据：连接一旦先发生，就是 30s 重试（这里给 8s 宽限，仍远小于超时）
    expect(ms).toBeLessThan(8000);
    // 不许留下任何"已经连上/在连"的痕迹。
    // `目标数据库` 是 run-rollback-drill.js 的等价连接痕迹（它只在 connect 成功后才打印）：
    // 只列 已连接/ECONNREFUSED/... 四个串时，它**不在白名单内 ⇒ 直接穿透**（§27.3(g)）。
    expect(out).not.toMatch(
      /已连接|ECONNREFUSED|ServerSelection|connection was closed|目标数据库/i
    );
  });

  test('前提自证：不加 --apply 时这些脚本确实会去连库（否则上面的"快"没有意义）', () => {
    // 反向对照：dry-run 没有 --apply ⇒ 护栏不该拦，脚本会真的去 connect ⇒
    // 在我给的不可达 URI 上卡住，被我的 4s 超时 kill（status 为 null）。
    // 若哪天有人把 dry-run 也改成"直接退出"，这条会红——那时才说明
    // 上面那组"毫秒级拒绝"失去了判别力，不能继续当门禁。
    const r = spawnSync(NODE, [path.join(SCRIPTS, 'sync-audit-indexes.js')], {
      cwd: ROOT,
      encoding: 'utf8',
      timeout: 4000,
      env: PROBE_ENV,
    });
    expect(r.status).toBeNull(); // 被 timeout 杀掉 = 它一直在尝试连接
    expect(`${r.stderr}${r.stdout}`).not.toContain('拒绝执行');
  });

  test('完备性：直接操作集合的脚本必须引入护栏，且护栏调用先于 connect', () => {
    const WRITE_SIG =
      /mongoose\.connection\.collection\(|\.(updateMany|deleteMany|insertMany|bulkWrite|dropIndex|createIndex|replaceOne|updateOne|deleteOne)\(/;
    const files = fs.readdirSync(SCRIPTS).filter((f) => f.endsWith('.js'));
    const offenders = [];
    let matched = 0;
    let connectSeen = 0;
    for (const f of files) {
      if (f === 'destructiveGuard.js') continue;
      const src = fs.readFileSync(path.join(SCRIPTS, f), 'utf8');
      if (!WRITE_SIG.test(src)) continue;
      matched += 1;
      if (!/require\(['"]\.\/destructiveGuard['"]\)/.test(src))
        offenders.push(`${f}（未引入护栏）`);

      // 顺序判据取"护栏调用 vs mongoose.connect 的源码位置"，而不是"护栏 vs 集合操作"：
      // 集合操作几乎都写在函数体内，源码位置不代表执行顺序（本次改动就被
      // resign-audit-chain-v3.js 顶过一次——它的 collection 句柄在函数内、第 55 行，
      // 却根本不可能在 connect 之前跑）。而"任何 connect 之前必须先问护栏"是充分可静态检查的。
      // 顺序判据取"**每一处**护栏调用 vs mongoose.connect 的源码位置"。
      // 只取"第一处"会漏：包装式护栏（本仓 run-rollback-drill.js 先定义
      // `assertSourceDbAllowed` 再在别处调用）会让"首次出现"落在**包装函数定义体内**，
      // 判据读到的是定义位置而不是真实调用位置 ⇒ 假绿（§27.3(f) 的表）。
      // 改成"任何一处护栏调用都不得晚于 connect"：定义体在前无害，
      // 真实调用落在 connect 之后 ⇒ 当场判红。同时把包装函数名纳入正则。
      const guardPositions = [...src.matchAll(/assert(?:ApplyAllowed|SourceDbAllowed)\s*\(/g)].map(
        (m) => m.index
      );
      const connectAt = src.search(/\bmongoose\.connect\s*\(/);
      if (connectAt >= 0) connectSeen += 1;
      if (
        connectAt >= 0 &&
        (guardPositions.length === 0 || guardPositions.some((pos) => pos > connectAt))
      ) {
        offenders.push(`${f}（护栏调用未先于 mongoose.connect）`);
      }
    }
    // 前提自证：两条正则都得真的抓到东西，否则空 offenders 只是判据失效的假绿
    expect(matched).toBeGreaterThanOrEqual(4);
    expect(connectSeen).toBeGreaterThanOrEqual(4);
    expect(offenders).toEqual([]);
  });
});
