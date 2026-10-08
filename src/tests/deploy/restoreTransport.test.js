/**
 * restore-mongo.sh 的两条传输路径（**生产默认是 docker**）
 *
 * 为什么值得一个专门闸：本仓所有真跑过 `restore-mongo.sh` 的用例都显式把传输设成
 * `local`（backupUriFile / backupEncryptionContract / infraParam…），而 README 与
 * deployment/backup-encryption.md 教的恰恰是默认那条——compose 里 mongo 只 `expose`，
 * 宿主机连不上，mongorestore 必须在容器内跑。也就是说**破坏性写入的默认路径**在修前
 * 从未被任何用例执行过：主机段改写的拒绝、`--drop` 的拼接、凭据在容器内即删、
 * 归档经 stdin 流向容器，全都不是被证过的事实。
 *
 * 三个设计要点：
 *   1. 桩 `docker` 把 argv 与 stdin 分别落到文件里 ⇒ 断言的是"真正送进容器的那条命令
 *      与那段字节流"，不是脚本里有没有某个字符串。
 *   2. "宿主机有没有落凭据文件"这条由**两个桩共用同一段探测代码**：local 分支必须探测到
 *      文件、docker 分支必须探测不到。同一把尺子量两格，探测器坏掉时不可能只让
 *      docker 那一格假绿。探测同时记下**路径与内容**——路径用来断言 trap 把文件删了
 *      （那时内容已经读不到），内容必须在桩还活着的时候抄出来。
 *   3. `--drop` 在两条分支各写一遍（local 拼数组、docker 拼远端命令字符串），
 *      所以两侧都要演"开了有、没开无"——这是防漂移，不是重复断言。
 */

'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync, execFileSync } = require('child_process');

const ROOT = path.resolve(__dirname, '../../..');
const SCRIPT = path.join(ROOT, 'scripts/restore-mongo.sh');
const DB = 'fire-safety';
const URI = `mongodb://fsms:Sup3r%21Secret@mongo:27017/${DB}?authSource=admin`;
// 口令里有**未转义的 @**：mongo_swap_host 会拒绝（两个读者对凭据/主机的分界读法相反），
// 用它演"改写被拒 ⇒ 一个字节都不该流向容器"。
const UNSWAPPABLE = 'mongodb://fsms:Sup3r!ca@99@mongo:27017/fire-safety?authSource=admin';
const ARCHIVE_BYTES = 'FAKE-GZIP-ARCHIVE-PAYLOAD-BYTES';

const sh = (p) => String(p).replace(/\\/g, '/');

/**
 * 两个桩共用的探测片段：工具被拉起的那一刻，宿主机上有没有**含明文凭据的配置文件**；
 * 有的话它写的是什么。内容必须在桩里抄出来——脚本退出前 trap 就把原文件删了，
 * 事后再读会拿到 ENOENT（这条实测踩过：断言写成"读 found[0]"直接把闸做成了假失败）。
 *
 * 探测按**内容结构**（首行是 `uri: ` ——mongorestore 配置文件唯一的形状，scripts/restore-mongo.sh
 * 用 printf 'uri: %s\n' 写它）而不是按文件名。原实现扫 `"$TMPDIR"/mongorestore-config.*`，
 * 于是"把模板改名成 fsms-restore-cred.XXXXXX 再引入同一份宿主明文口令"能整条绿灯穿过——
 * 按名字探测闸的是"祸害叫什么"，不是"祸害是什么"。判据里也不放口令字面量：
 * 夹具换口令就会让探测器瞎掉。
 * 残余盲区（诚实写明）：若回归把文件写到硬编码的 /tmp 而 TMPDIR 被改到别处，本探测看不到；
 * 桩里把 TMPDIR 指到本次临时目录正是为了让"脚本写的宿主文件"只有这一处落点。
 */
const HOSTCFG_PROBE = [
  ': > "$HOSTCFG_FILE"',
  ': > "$HOSTCFG_BODY_FILE"',
  'for f in "$TMPDIR"/*; do',
  '  [ -f "$f" ] || continue',
  '  head -n1 "$f" 2>/dev/null | grep -q \'^uri: \' || continue',
  '  printf \'%s\\n\' "$f" >> "$HOSTCFG_FILE"',
  '  cat "$f" >> "$HOSTCFG_BODY_FILE"',
  'done',
];

function makeWorkspace() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'restore-transport-'));
  const bin = path.join(dir, 'bin');
  fs.mkdirSync(bin);
  const backupDir = path.join(dir, 'backups');
  fs.mkdirSync(backupDir);

  const dockerStub = [
    '#!/usr/bin/env bash',
    'printf "%s\\n" "$@" > "$DOCKER_ARGV_FILE"',
    'cat > "$DOCKER_STDIN_FILE"',
    ...HOSTCFG_PROBE,
    'exit 0',
    '',
  ].join('\n');
  const mongorestoreStub = [
    '#!/usr/bin/env bash',
    'printf "%s\\n" "$@" > "$MONGORESTORE_ARGV_FILE"',
    ...HOSTCFG_PROBE,
    'exit 0',
    '',
  ].join('\n');
  fs.writeFileSync(path.join(bin, 'docker'), dockerStub, { mode: 0o755 });
  fs.writeFileSync(path.join(bin, 'mongorestore'), mongorestoreStub, { mode: 0o755 });
  fs.chmodSync(path.join(bin, 'docker'), 0o755);
  fs.chmodSync(path.join(bin, 'mongorestore'), 0o755);

  // 归档 + sidecar：恢复侧对**取回的原文件**先做 sha256 比对，缺 sidecar 直接硬失败，
  // 所以夹具必须自洽（与 backupUriFile.test.js 同一口径：用 sha256sum 生成）。
  const archive = path.join(backupDir, 'fire-safety-backup-t1.gz');
  fs.writeFileSync(archive, ARCHIVE_BYTES);
  execFileSync('bash', ['-c', `sha256sum '${sh(archive)}' > '${sh(archive)}.sha256'`], {
    cwd: ROOT,
    encoding: 'utf8',
  });

  // 桩自己的产物一律放在 TMPDIR 的**点目录**里：bash 的 `"$TMPDIR"/*` 不匹配点文件，
  // 于是 docker.stdin（首行就是 `uri: …`，那是流经 stdin 的正常内容，不是宿主泄露）
  // 不会被下面的内容探测误伤。探测器扫的必须是"脚本写的文件"，不能扫到自己的输出。
  const probeDir = path.join(dir, '.probe');
  fs.mkdirSync(probeDir);

  const files = {
    dockerArgv: path.join(probeDir, 'docker.argv'),
    dockerStdin: path.join(probeDir, 'docker.stdin'),
    mongorestoreArgv: path.join(probeDir, 'mongorestore.argv'),
    hostCfg: path.join(probeDir, 'hostcfg.txt'),
    hostCfgBody: path.join(probeDir, 'hostcfg.body'),
  };
  return { dir, bin, backupDir, archive, probeDir, files };
}

// 夹具文件路径 → 桩读取的环境变量名（探测器的接线集中在这里，避免两处拼写漂移）
const PROBE_ENV = {
  dockerArgv: 'DOCKER_ARGV_FILE',
  dockerStdin: 'DOCKER_STDIN_FILE',
  mongorestoreArgv: 'MONGORESTORE_ARGV_FILE',
  hostCfg: 'HOSTCFG_FILE',
  hostCfgBody: 'HOSTCFG_BODY_FILE',
};

function runRestore(work, env = {}) {
  const r = spawnSync('bash', [sh(SCRIPT), sh(work.archive)], {
    cwd: ROOT,
    // stdin 保持 pipe（非 tty）⇒ 走 RESTORE_CONFIRM 那条非交互确认口径
    encoding: 'utf8',
    timeout: 60000,
    env: {
      ...process.env,
      PATH: `${sh(work.bin)}${path.delimiter}${process.env.PATH}`,
      // 显式把 TMPDIR 指到本次的临时目录：桩里的凭据文件探测才既确定又不越界
      TMPDIR: sh(work.dir),
      MONGODB_URI: URI,
      RESTORE_CONFIRM: DB,
      ...Object.fromEntries(Object.entries(work.files).map(([k, v]) => [PROBE_ENV[k], sh(v)])),
      ...env,
    },
  });
  if (r.error) {
    throw new Error(`本机找不到 bash，本闸无法执行：${r.error.message}`);
  }
  const read = (p) => (fs.existsSync(p) ? fs.readFileSync(p, 'utf8') : '');
  return {
    code: r.status,
    out: `${r.stdout || ''}${r.stderr || ''}`,
    read,
    files: work.files,
  };
}

describe('restore-mongo.sh 传输路径（默认 docker：mongorestore 在容器内跑）', () => {
  let work;
  beforeEach(() => {
    work = makeWorkspace();
  });
  afterEach(() => {
    fs.rmSync(work.dir, { recursive: true, force: true });
  });

  test('docker 传输：uri 行与归档都经 stdin 流入容器，argv 上没有凭据', () => {
    const r = runRestore(work);
    expect(r.code).toBe(0);

    const argv = r.read(work.files.dockerArgv);
    expect(argv).toContain('compose');
    expect(argv).toMatch(/exec/);
    expect(argv).toMatch(/-T/);
    expect(argv).toContain('mongo'); // 服务名
    expect(argv).not.toContain('mongodb://');
    expect(argv).not.toContain('Sup3r');

    const stdin = r.read(work.files.dockerStdin);
    expect(stdin.startsWith('uri: mongodb://')).toBe(true);
    expect(stdin).toContain('127.0.0.1:27017'); // 主机段已换成容器内地址
    expect(stdin).not.toContain('@mongo:27017');
    expect(stdin).toContain(DB); // 库名保留
    expect(stdin).toContain('authSource=admin'); // 查询串保留
    // 归档确实跟着流进去了：stdin = 一行配置 + 原归档字节
    expect(stdin.endsWith(ARCHIVE_BYTES)).toBe(true);

    // 容器侧临时文件用完即删（凭据不能留在容器文件系统里）。
    // 原断言钉 `rm -f /tmp/.mongorestore.cfg /tmp/.mongorestore.archive`：脚本把这两条写死
    // 路径换成 mktemp（并发恢复会互相截断对方的文件）之后，它红的是"名字变了"，而这条臂要守的
    // 性质一条都没变——按名字探测的闸守的是祸害叫什么，这里改成按变量核对：
    //   ① mktemp 出来的每个变量都真的被写过（前提自证，否则下面的包含判断真空成立）
    //   ② 写入只允许落到变量，不许落写死路径（写死路径既不可预测、又对 ③ 隐形）
    //   ③ 每个被写过的文件都在退出路径的 rm -f 名单里
    const lines = argv.split('\n');
    expect(lines.indexOf('-c')).toBeGreaterThan(-1); // sh -c 的实参就是"真正在容器里跑的那条命令"
    const remote = lines.slice(lines.indexOf('-c') + 1).join('\n');
    const mktempVars = [...remote.matchAll(/(\w+)=\$\(?mktemp[^\n]*\)/g)].map((m) => m[1]);
    const writeVars = [...remote.matchAll(/(?:^|[;\s])>\s*"\$(\w+)"/g)].map((m) => m[1]);
    expect(mktempVars.length).toBeGreaterThan(0);
    expect([...mktempVars].sort()).toEqual([...writeVars].sort());
    const literalWrites = [...remote.matchAll(/(?:^|[;\s])>\s*(?!")[^;&\s][^\s;]*/g)].map((m) =>
      m[0].trim()
    );
    expect(literalWrites).toEqual([]);
    const cleanup = remote.match(/rc=\$\?;\s*rm -f ([^;]+);/);
    expect(cleanup).not.toBeNull(); // 退出路径上没有 rm ⇒ 凭据留在容器文件系统
    const removed = [...cleanup[1].matchAll(/"\$(\w+)"/g)].map((m) => m[1]);
    writeVars.forEach((v) => expect(removed).toContain(v));
    expect(argv).toMatch(/--gzip/);
  });

  test('docker 传输 ⇒ 宿主机不落任何含凭据的配置文件（修前会无条件写一份，而没人读它）', () => {
    const r = runRestore(work);
    expect(r.code).toBe(0);
    expect(r.read(work.files.hostCfg)).toBe('');
    expect(r.read(work.files.hostCfgBody)).toBe('');
    expect(fs.existsSync(work.files.hostCfg)).toBe(true); // 桩确实跑过并清点了
  });

  test('反向自证：local 传输用同一把尺子能探到凭据文件（上一条的空结果不是探测器坏了）', () => {
    const r = runRestore(work, { MONGO_RESTORE_TRANSPORT: 'local' });
    expect(r.code).toBe(0);
    const found = r.read(work.files.hostCfg).trim().split('\n').filter(Boolean);
    expect(found).toHaveLength(1);
    // 探测器抄出来的内容正是含口令的那一行 uri——它只在 local 分支才是必需的
    expect(r.read(work.files.hostCfgBody)).toMatch(/^uri: mongodb:\/\//);
    expect(r.read(work.files.hostCfgBody)).toContain(DB);
    // 收尾：trap 必须把原文件删掉（0600 只是缩小窗口，删除才是承诺）
    expect(fs.existsSync(found[0].replace(/\r$/, ''))).toBe(false);
  });

  test('local 传输：mongorestore 收到 --config/--archive/--gzip，主机段不被改写', () => {
    const r = runRestore(work, { MONGO_RESTORE_TRANSPORT: 'local' });
    expect(r.code).toBe(0);
    const argv = r.read(work.files.mongorestoreArgv);
    expect(argv).toMatch(/--config=/);
    expect(argv).toContain(`--archive=${sh(work.archive)}`);
    expect(argv).toMatch(/--gzip/);
    // 宿主机直连用的就是原主机名，不做容器地址改写
    expect(r.read(work.files.hostCfgBody)).toContain('@mongo:27017');
    expect(r.read(work.files.hostCfgBody)).not.toContain('127.0.0.1:27017');
  });

  // ---- --drop 门禁在两条分支必须同口径（各写一遍 ⇒ 会各自漂移）----

  test('--drop：默认不开 ⇒ 两条传输的实参里都没有它', () => {
    const docker = runRestore(work);
    expect(docker.code).toBe(0);
    expect(docker.read(work.files.dockerArgv)).not.toMatch(/--drop/);
    const local = runRestore(work, { MONGO_RESTORE_TRANSPORT: 'local' });
    expect(local.code).toBe(0);
    expect(local.read(work.files.mongorestoreArgv)).not.toMatch(/--drop/);
  });

  test('--drop：RESTORE_DROP=true ⇒ 两条传输的实参里都真的有它（缺一侧即门禁只在一台机器上成立）', () => {
    const docker = runRestore(work, { RESTORE_DROP: 'true' });
    expect(docker.code).toBe(0);
    expect(docker.read(work.files.dockerArgv)).toMatch(/--drop/);
    const local = runRestore(work, {
      MONGO_RESTORE_TRANSPORT: 'local',
      RESTORE_DROP: 'true',
    });
    expect(local.code).toBe(0);
    expect(local.read(work.files.mongorestoreArgv)).toMatch(/--drop/);
  });

  // ---- 主机段改写被拒：破坏性写入的一个字节都不许流出去 ----

  test('docker 传输：URI 无法改写 ⇒ 非零、stdin 一个字节都没送、归档原样未动', () => {
    const r = runRestore(work, { MONGODB_URI: UNSWAPPABLE });
    expect(r.code).not.toBe(0);
    expect(r.out).toMatch(/拒绝执行/);
    expect(fs.existsSync(work.files.dockerStdin)).toBe(false);
    expect(fs.existsSync(work.files.dockerArgv)).toBe(false);
    expect(fs.readFileSync(work.archive, 'utf8')).toBe(ARCHIVE_BYTES);
    // 拒绝信息不回显凭据字节（口令段以 `Sup3r` 起头，两种读法下都落在凭据侧）
    expect(r.out).not.toMatch(/Sup3r|mongodb:\/\//);
  });

  /**
   * 已实测到的**不对称**（不是断言"这样才对"，而是钉住现状并让它可见）：
   * 同一条含裸 `@` 的 URI，docker 分支硬拒，local 分支放行。
   *
   * 为什么方向不同：docker 分支必须知道"哪一段是主机"才能替换，两个读者（本仓 parity
   * 用的 JS 连接串包按**第一个** `@` 切凭据，Node 的 WHATWG `new URL` 按**最后一个** `@`
   * 定界 userinfo，实测对同一条串给出不同主机）一旦读法相反，替换本身就是猜，所以拒。
   * local 分支从不改写——它把 URI 原样经 0600 配置交给 mongorestore，歧义不是脚本引入的。
   *
   * 残余风险（本闸测不到，记下以免被读成"local 也没问题"）：横幅与 RESTORE_CONFIRM 核对的
   * 库名用最后一个 `@` 取段，两条读法在这个形态下给出的**库名相同**（`/` 之后就是库），
   * 所以确认门禁没有被绕过；但"实际拨号的主机"取决于 mongorestore 自己的解析器，
   * 而 Go 驱动本机没有二进制可比对（推断与 WHATWG 同侧）。若它其实与 JS 包同侧，
   * 现场看到的会是"连到主机段里那段谁都没写过的名字"——大概率是连不上而报错，
   * 不是静默恢复进另一台机器。**未测，不下结论**；是否把 docker 分支那条"第二个裸 `@`
   * 一律硬拒"也压到 local（备份侧同形）需要人来定：它会开始拒绝一批现在能跑的口令，
   * 已在待决清单里点名，不在这个用例里偷偷改语义。
   */
  test('钉住现状：同一含裸 @ 的 URI 在 local 分支是放行的（与 docker 的硬拒不对称，见注释）', () => {
    const r = runRestore(work, { MONGODB_URI: UNSWAPPABLE, MONGO_RESTORE_TRANSPORT: 'local' });
    expect(r.code).toBe(0);
    expect(r.read(work.files.mongorestoreArgv)).toMatch(/--config=/);
    // 原样交付：脚本没有碰主机段，所以配置里就是那条歧义串
    expect(r.read(work.files.hostCfgBody)).toContain('99@mongo:27017');
    // 门禁核对的库名不受两种读法影响（这串里库名在第一个 `/` 之后）
    expect(r.out).toMatch(/目标库名 : fire-safety/);
  });
});

/**
 * 变异台账（2026-10-03，第 1 组"容器侧清理"臂改判据后重测）
 *
 * 跑法：node tools/ledger.js scripts/restore-mongo.sh src/tests/deploy/restoreTransport.test.js \
 *        restore-cleanup-dropped="红:#1" restore-cleanup-cfg-only="红:#1" \
 *        restore-write-literal-path="红:#1" restore-mktemp-cfg-to-fixed="红:#1"
 *
 * 基线 8/8 绿；四条变异**预测与实测完全一致**，每次都只有 #1 红，恢复后逐字节相同。
 * 四条各自钉住这条臂的一个不同断口：退出路径没 rm / rm 少一个文件 / 写入绕过变量 /
 * mktemp 退回写死路径。
 *
 * 为什么改判据：这一臂原先钉的是 `rm -f /tmp/.mongorestore.cfg /tmp/.mongorestore.archive`
 * 字面量。脚本把两个容器侧路径换成 mktemp（并发恢复会互相截断对方的文件——那是真 bug，
 * 修得对）之后，这条断言红了，而红的原因是"祸害改了名字"，不是"祸害回来了"。
 * 这是第 8 族（按名字探测）在我自己门禁里的复发，记下以免下次又去改脚本迁就断言。
 *
 * 自纠：台账第一版里 restore-mktemp-cfg-to-fixed 施加失败（MUT-ABORT 命中 0 处）——
 * 正则里的 `(` 写成了捕获分组。判据是"MUT-ABORT 会响"而不是"我一次写对"，
 * 所以这类错误不会变成假绿；改用 `[(]`/`[)]` 后命中 1 处。
 */
