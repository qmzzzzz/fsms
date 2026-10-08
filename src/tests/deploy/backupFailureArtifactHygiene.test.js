/**
 * 备份的两个「顺序与残留」契约（2026-10-03）
 *
 * A. 加密门禁必须早于 mongodump。
 *    默认 `BACKUP_ENCRYPTION=gpg` 需要 gpg 二进制 + `BACKUP_GPG_RECIPIENT`。这两项判据
 *    原先写在归档**之后**的 `case` 里 ⇒ "没装 gpg / 忘配收件人"的部署会先花几分钟导出
 *    整个明文全量库（含人员 PII 与不可篡改审计集合），再在加密步失败退出；而 `set -e`
 *    直接带走脚本，加密分支里"写完就删明文"那行永远执行不到 ⇒ 每次失败都往 backups/
 *    多留一份明文归档。问不清"这次能不能加密"就不该开始导。
 * B. 未定稿的产物不得留在 backups/。
 *    失败产物与成功产物**同名**（fire-safety-backup-*.gz[.gpg][.sha256]），于是会被
 *    retention 清单、回滚演练与"最近一次备份"的报表挑中，真要恢复那天才发现是半截的。
 *    反方向同样成立：定稿（密文 + 校验和都在手且非空）之后一个都不能删——否则一次
 *    异地副本失败会把已到手的加密备份连带删掉，而"备份成功"的报表刚刚才算过它。
 *
 * 判据是真进程 + 桩工具（mongodump/gpg 经 PATH 注入），断言的是"目录里到底有什么文件、
 * 桩有没有被调用"，不是脚本源码里出现过哪个字符串。归档名带秒级时间戳，所以断言按
 * 后缀分类（明文/密文/校验和）而不是拼死一个文件名。
 * 反向自证有三处：A 用"补上收件人即放行"证明上一条的红来自门禁而不是夹具；
 * B 用"从脚本副本里删掉 FINALIZED 块（前世版）跑同一夹具"证明断言抓得住回退；
 * 异地失败那一臂证明定稿之后没有被过度清理。
 */

'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync, execFileSync } = require('child_process');

const ROOT = path.resolve(__dirname, '../../..');
const BACKUP = path.join(ROOT, 'scripts/backup-mongo.sh');
const CRYPTO = path.join(ROOT, 'scripts/backupCrypto.sh');

const DB = 'fire_safety';
const URI = `mongodb://fsms:ExplicitPw@127.0.0.1:27017/${DB}?authSource=admin`;
const RECIPIENT = 'ops@example.net';

const sh = (p) => String(p).replace(/\\/g, '/');

/** 按后缀把 backups/ 里的产物分三类：明文归档、加密归档、校验和 */
function classify(files) {
  return {
    plain: files.filter((f) => /\.gz$/.test(f)),
    enc: files.filter((f) => /\.gz\.gpg$/.test(f)),
    sha: files.filter((f) => /\.sha256$/.test(f)),
  };
}

function mkwork() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'backup-hygiene-'));
  const bin = path.join(dir, 'bin');
  fs.mkdirSync(bin);
  const tmp = path.join(dir, 'tmp');
  fs.mkdirSync(tmp);
  const log = path.join(dir, 'calls.log');
  const probe = path.join(dir, 'hostcfg.log');

  const write = (name, lines) => {
    const p = path.join(bin, name);
    fs.writeFileSync(p, `${lines.join('\n')}\n`, { mode: 0o755 });
    fs.chmodSync(p, 0o755);
  };

  // 宿主机凭据文件的**结构**探测（与 src/tests/deploy/restoreTransport.test.js 的
  // HOSTCFG_PROBE 同一口径）：按"首行是 `uri: `"识别，不按文件名——否则把 mktemp 模板
  // 改名成 fsms-cred.XXXXXX 就能整条绿灯穿过，而钉名字判的是"祸害叫什么"。
  // 探测必须发生在**工具被拉起的那一刻**：脚本退出前 trap 就把原文件删了，事后去读会
  // 拿到空目录，那条"没有凭据文件"就成了白给的。
  const PROBE = [
    ': > "$PROBE_OUT"',
    'for f in "$TMPDIR"/*; do',
    '  [ -f "$f" ] || continue',
    '  head -n1 "$f" 2>/dev/null | grep -q \'^uri: \' || continue',
    '  printf \'HOSTCFG %s\\n\' "$f" >> "$PROBE_OUT"',
    '  cat "$f" >> "$PROBE_OUT"',
    'done',
  ];

  write('mongodump', [
    '#!/usr/bin/env bash',
    'echo "TOOL $*" >> "$STUB_LOG"',
    ...PROBE,
    'for a in "$@"; do',
    '  case "$a" in',
    '    --config=*) cat "${a#--config=}" >> "$STUB_LOG" ;;',
    '    --archive=*) printf \'FAKE-ARCHIVE-BYTES\' > "${a#--archive=}" ;;',
    '  esac',
    'done',
    'exit 0',
  ]);
  // docker 桩：把 stdin 喝干（真实容器侧的 `cat > cfg` 就是这么拿到 uri 行的），
  // 再往 stdout 写归档字节（宿主把它重定向进 .gz）。它**不**执行容器侧命令——
  // 容器侧的形状由 src/tests/deploy/restoreRemoteHardening.test.js 用真执行的方式判。
  write('docker', [
    '#!/usr/bin/env bash',
    'echo "DOCKER $*" >> "$STUB_LOG"',
    'cat > /dev/null',
    ...PROBE,
    "printf 'STUB-ARCHIVE-BYTES'",
    'exit 0',
  ]);
  // stub gpg：成功时做 --output 的 src→dst 拷贝语义（带信封标记，证明数据真经过它）；
  // STUB_GPG_FAIL=1 模拟加密失败（真实形态：收件人公钥没导入、密钥环缺失）。
  write('gpg', [
    '#!/usr/bin/env bash',
    'echo "GPG $*" >> "$STUB_LOG"',
    'if [ "${STUB_GPG_FAIL:-0}" = 1 ]; then echo "stub gpg: encrypt failed" >&2; exit 2; fi',
    'out=""',
    'prev=""',
    'for a in "$@"; do',
    '  if [ "$prev" = "--output" ]; then out="$a"; fi',
    '  prev="$a"',
    'done',
    'src="${!#}"',
    '{ echo "STUB-GPG-ENVELOPE"; cat "$src"; } > "$out"',
  ]);
  write('offsite-fail', ['#!/usr/bin/env bash', 'exit 7']);
  // 成功侧的桩：把收到的参数与两个 export 一起记进日志，用于证明
  // "异地副本确实被执行了"（而不是只证明脚本没报错）。
  write('offsite-ok', [
    '#!/usr/bin/env bash',
    'echo "OFFSITE $* file=${BACKUP_FILE:-unset} sha=${BACKUP_SHA256:-unset}" >> "$STUB_LOG"',
    'exit 0',
  ]);

  return { dir, bin, tmp, log, probe, backupDir: path.join(dir, 'backups') };
}

function runBackup(work, script, env) {
  const r = spawnSync('bash', [sh(script || BACKUP), sh(work.backupDir)], {
    cwd: ROOT,
    encoding: 'utf8',
    timeout: 60000,
    env: {
      ...process.env,
      PATH: `${work.bin}${path.delimiter}${process.env.PATH}`,
      STUB_LOG: sh(work.log),
      // TMPDIR 收到本次临时目录：脚本写的宿主临时文件因此**只有这一处落点**，
      // 桩里的结构探测才有资格说"没看见"。不接 TMPDIR 的探针扫的是运气。
      TMPDIR: sh(work.tmp),
      PROBE_OUT: sh(work.probe),
      MONGODB_URI: URI,
      MONGODB_URI_FILE: '',
      MONGO_BACKUP_TRANSPORT: 'local',
      BACKUP_RETENTION_DAYS: '30',
      BACKUP_ENCRYPTION: 'gpg',
      BACKUP_GPG_RECIPIENT: RECIPIENT,
      ...env,
    },
  });
  if (r.error) {
    // 环境没有 bash ⇒ 红，不静默跳过（静默跳过等于把这层防护换成错觉）
    throw new Error(
      `本机找不到 bash（Git Bash / CI runner 都自带），本闸无法执行：${r.error.message}`
    );
  }
  const files = fs.existsSync(work.backupDir) ? fs.readdirSync(work.backupDir).sort() : [];
  return {
    code: r.status,
    out: `${r.stdout || ''}${r.stderr || ''}`,
    files,
    kinds: classify(files),
    calls: fs.existsSync(work.log) ? fs.readFileSync(work.log, 'utf8') : '',
    probe: fs.existsSync(work.probe) ? fs.readFileSync(work.probe, 'utf8') : null,
  };
}

describe('A：加密门禁必须早于 mongodump', () => {
  let work;
  beforeEach(() => {
    work = mkwork();
  });
  afterEach(() => {
    fs.rmSync(work.dir, { recursive: true, force: true });
  });

  test('缺 BACKUP_GPG_RECIPIENT ⇒ 非零、mongodump 一次都没被调用、备份目录根本没建', () => {
    const r = runBackup(work, null, { BACKUP_GPG_RECIPIENT: '' });
    expect(r.code).not.toBe(0);
    expect(r.out).toMatch(/BACKUP_GPG_RECIPIENT/);
    // 关键的不是"报了错"，而是**没有产出**：一条 mongodump 都没跑，连 backups/
    // 都还没创建 ⇒ 不存在任何一份明文全量库可被下一次演练挑中。
    expect(r.calls).toBe('');
    expect(fs.existsSync(work.backupDir)).toBe(false);
    expect(r.files).toEqual([]);
  });

  test('未知模式（BACKUP_ENCRYPTION=none）⇒ 同样早退，零归档', () => {
    const r = runBackup(work, null, { BACKUP_ENCRYPTION: 'none' });
    expect(r.code).not.toBe(0);
    expect(r.out).toMatch(/只能是 gpg 或 plaintext-acknowledged/);
    expect(r.calls).toBe('');
    expect(fs.existsSync(work.backupDir)).toBe(false);
  });

  test('前提自证：桩通道真的能带回 --config 内容（否则上面的"零调用"是白给的）', () => {
    const r = runBackup(work, null, {});
    expect(r.code).toBe(0);
    expect(r.calls).toContain('TOOL ');
    expect(r.calls).toContain(`uri: ${URI}`);
  });

  test('反向自证：门禁放行时产出密文 + 配对校验和，明文归档被删', () => {
    const r = runBackup(work, null, {});
    expect(r.code).toBe(0);
    expect(r.kinds.plain).toEqual([]);
    expect(r.kinds.enc).toHaveLength(1);
    expect(r.kinds.sha).toEqual([`${r.kinds.enc[0]}.sha256`]);
    expect(fs.readFileSync(path.join(work.backupDir, r.kinds.enc[0]), 'utf8')).toContain(
      'STUB-GPG-ENVELOPE'
    );
  });

  test('gpg 二进制缺失 ⇒ 共享实现在没有任何产物时就拒绝（PATH 收到不存在的目录）', () => {
    const r = spawnSync(
      'bash',
      [
        '-c',
        `PATH=${sh(path.join(ROOT, 'no-such-dir'))}; export PATH; ` +
          `. '${sh(CRYPTO)}'; if crypto_precheck_backup gpg; then echo ALLOWED; else echo REJECTED; fi`,
      ],
      { cwd: ROOT, encoding: 'utf8' }
    );
    const out = `${r.stdout}${r.stderr}`;
    expect(out).toContain('REJECTED');
    expect(out).toContain('gpg 不在 PATH');
    expect(out).not.toContain('ALLOWED');
  });
});

describe('B：失败现场与定稿之后的产物卫生', () => {
  let work;
  beforeEach(() => {
    work = mkwork();
  });
  afterEach(() => {
    fs.rmSync(work.dir, { recursive: true, force: true });
  });

  /**
   * 把 FINALIZED 清理块从脚本副本里删掉＝回到修前形态（与 backupUriFile.test.js 的
   * "前世版 mongoUri.sh" 同一手法）。缩进用反向引用锁死，否则会停在 for 循环里
   * 那层 `fi`，删出来的是语法错误的脚本，"残留明文"就演示不出来了。
   */
  function writeLegacy() {
    const src = fs.readFileSync(BACKUP, 'utf8');
    const stripped = src.replace(
      /^([ \t]*)if \[ "\$FINALIZED" -ne 1 \]; then[\s\S]*?\n\1fi[ \t]*\r?\n/m,
      ''
    );
    // 前提自证：删掉的确实是那块，而不是正则没命中导致"新旧两版同一份源码"
    expect(stripped).not.toBe(src);
    expect(stripped).not.toMatch(/\[ "\$FINALIZED" -ne 1 \]/);
    const legacy = path.join(work.dir, 'legacy');
    fs.mkdirSync(legacy, { recursive: true });
    for (const f of ['mongoUri.sh', 'backupCrypto.sh']) {
      fs.copyFileSync(path.join(ROOT, 'scripts', f), path.join(legacy, f));
    }
    const p = path.join(legacy, 'backup-mongo.sh');
    fs.writeFileSync(p, stripped);
    // 前世版必须仍然是**能解析**的脚本：否则它"退出非零"是语法错误的功劳，
    // 下面那条"残留明文归档"的对照就什么都没证明。
    expect(execFileSync('bash', ['-n', sh(p)], { encoding: 'utf8' })).toBe('');
    return p;
  }

  test('加密步失败 ⇒ 明文归档与半成品密文都不残留', () => {
    const r = runBackup(work, null, { STUB_GPG_FAIL: '1' });
    expect(r.code).not.toBe(0);
    expect(r.out).toMatch(/gpg 加密失败/);
    // mongodump 确实跑过（归档曾经存在），失败点在其后 ⇒ "目录为空"不是白给的
    expect(r.calls).toContain('TOOL ');
    expect(r.files).toEqual([]);
  });

  test('反向自证：删掉 FINALIZED 块的前世版在同一夹具下会留下明文全量归档', () => {
    const r = runBackup(work, writeLegacy(), { STUB_GPG_FAIL: '1' });
    expect(r.code).not.toBe(0);
    expect(r.out).toMatch(/gpg 加密失败/);
    // 修前形态：一份 0600（在非 077 umask 下甚至 0644）的全量库明文躺在 backups/，
    // 名字与成功产物同形，retention/演练清单都会把它当"有一次备份"。
    expect(r.kinds.plain).toHaveLength(1);
    expect(fs.readFileSync(path.join(work.backupDir, r.kinds.plain[0]), 'utf8')).toContain(
      'FAKE-ARCHIVE-BYTES'
    );
  });

  test('定稿后不过度清理：异地副本失败 ⇒ 密文与校验和仍在（本地副本是回滚抓手）', () => {
    const r = runBackup(work, null, { BACKUP_OFFSITE_CMD: `${sh(work.bin)}/offsite-fail` });
    expect(r.code).not.toBe(0);
    expect(r.out).toMatch(/异地副本命令失败/);
    expect(r.kinds.enc).toHaveLength(1);
    expect(r.kinds.sha).toEqual([`${r.kinds.enc[0]}.sha256`]);
    expect(r.kinds.plain).toEqual([]);
  });

  test('明文出口那一支同样要定稿：plaintext + 异地失败 ⇒ 归档与校验和仍在', () => {
    const r = runBackup(work, null, {
      BACKUP_ENCRYPTION: 'plaintext-acknowledged',
      BACKUP_OFFSITE_CMD: `${sh(work.bin)}/offsite-fail`,
    });
    expect(r.code).not.toBe(0);
    expect(r.out).toMatch(/异地副本命令失败/);
    expect(r.kinds.plain).toHaveLength(1);
    expect(r.kinds.sha).toEqual([`${r.kinds.plain[0]}.sha256`]);
  });

  // ── 异地副本的"空命令假成功"（2026-10-03 实测）─────────────────────────────
  // 旧判据是 `[ -n "$BACKUP_OFFSITE_CMD" ]`：一个只含空白的值**非空** ⇒ 进分支，
  // 而 `read -a` 切出 0 个词，`"${空数组[@]}"` 落在命令位置是**空命令**，
  // 实测 bash 5.3.9 返回 0。后果不是"报错看不见"，而是压根没有信号：
  // 异地副本一次都没执行，回显却是 `Offsite copy completed:`，连未配置那支的
  // Warning 都不打——cron 邮件里这是一次"有异地副本的成功备份"。
  test('BACKUP_OFFSITE_CMD 只含空白 ⇒ 判失败，且绝不打印"completed"（旧形态：零词空命令 rc=0）', () => {
    for (const blank of [' ', '   ', '\t ']) {
      const r = runBackup(work, null, { BACKUP_OFFSITE_CMD: blank });
      // 钉死成 1 而不是"非零"：null（spawn 失败）也满足 toBe(0) 的补集，那是另一种故事
      expect({ blank, code: r.code }).toEqual({ blank, code: 1 });
      expect(r.out).toMatch(/只含空白/);
      // 最关键的一条：不得出现成功回显（旧写法两条都给它）
      expect(r.out).not.toMatch(/Offsite copy completed/);
      // 未配置那支的 Warning 也不该串味：这不是"没配异地"，是配错了
      expect(r.out).not.toMatch(/未配置 BACKUP_OFFSITE_CMD/);
      expect(r.calls).not.toMatch(/OFFSITE /);
    }
  });

  test('反向自证：真异地命令确实被执行（否则上一条可能只是"异地一步恒失败"）', () => {
    const r = runBackup(work, null, { BACKUP_OFFSITE_CMD: `${sh(work.bin)}/offsite-ok` });
    expect(r.code).toBe(0);
    expect(r.out).toMatch(/Offsite copy completed/);
    // 桩真跑过，且拿到的是定稿后的最终路径（两个 export 仍在分支内）
    expect(r.calls).toMatch(/OFFSITE .*file=[^\s]+\.gz\.gpg sha=[^\s]+\.sha256/);
    expect(r.kinds.enc).toHaveLength(1);
  });

  test('未设置才走 Warning 那一支（不得被新分支吞成失败）', () => {
    const r = runBackup(work, null, { BACKUP_OFFSITE_CMD: '' });
    expect(r.code).toBe(0);
    expect(r.out).toMatch(/未配置 BACKUP_OFFSITE_CMD/);
    expect(r.out).not.toMatch(/Offsite copy completed/);
    expect(r.calls).not.toMatch(/OFFSITE /);
  });
});

// ── C：凭据落盘的分支 + 异地命令的"形状"（2026-10-04 审计复跑）────────────────
// C.1 宿主机那份含生产口令的临时配置文件，原先写在 `case` **之前**：docker 传输（默认那一条）
//     走的是"uri 行经 stdin 送进容器、容器侧落它自己的临时文件"，宿主这份从头到尾没有读者。
//     于是每次默认备份都在 /tmp 放一份 0600 的明文口令，一放就是整场导出的几分钟；而
//     SIGKILL / OOM / 断电时 trap 不执行，那份文件就永久留在磁盘上。恢复侧早就是
//     "建在 local 支里"的形状，这里是把备份侧对齐。
// C.2 `read -r -a … <<< "$VALUE"` 只吃**第一行**：多行值实际只跑第一行，而末尾的回显打印的是
//     整份配置——异地副本报表因此说谎（这与本文件 A/B 两段判的是同一族：把没做完说成做完了）。
//     含 `\r`（CRLF 写的 env 文件）更阴：最后一个参数带回车，rsync/scp 把它当路径的一部分，
//     复制到错的地方还报成功。尾随的换行/回车不算配置错误，剥掉尾部后再判形状。
describe('C：凭据只在真正需要它的分支落盘；异地命令一条都不许"半跑还说完成"', () => {
  let work;
  beforeEach(() => {
    work = mkwork();
  });
  afterEach(() => {
    fs.rmSync(work.dir, { recursive: true, force: true });
  });

  test('C.1 docker 传输：宿主机没有 `uri: ` 开头的文件（工具被拉起的那一刻取证）', () => {
    const r = runBackup(work, null, { MONGO_BACKUP_TRANSPORT: 'docker' });
    expect(r.code).toBe(0);
    expect(r.kinds.enc).toHaveLength(1);
    // 前提自证：备份确实走到了容器边界（桩 docker 真被调用），不是"根本没跑所以没文件"
    expect(r.calls).toMatch(/DOCKER .*exec -T mongo sh -c/);
    expect(r.probe).not.toBeNull();
    expect(r.probe).toBe('');
    // 口令也没从 stdin 之外的地方漏进日志：docker 支的 argv 上只该有服务名与 sh -c
    expect(r.calls).not.toMatch(/ExplicitPw/);
  });

  test('C.1 反向自证：同一条探测在 local 传输下**看得见**凭据文件（C.1 的空不是探测器坏了）', () => {
    const r = runBackup(work, null, { MONGO_BACKUP_TRANSPORT: 'local' });
    expect(r.code).toBe(0);
    const lines = r.probe.split('\n').filter((l) => l.startsWith('HOSTCFG '));
    expect(lines).toHaveLength(1);
    // 按内容而不是名字命中：模板名换成别的也一样会被这条抓到
    expect(r.probe).toMatch(/^uri: mongodb:\/\/fsms:ExplicitPw@/m);
  });

  test('C.2 多行 BACKUP_OFFSITE_CMD ⇒ 一条都不执行、不回显 completed、退 1', () => {
    const value = `${sh(work.bin)}/offsite-ok\n${sh(work.bin)}/offsite-fail`;
    const r = runBackup(work, null, { BACKUP_OFFSITE_CMD: value });
    expect(r.code).toBe(1);
    expect(r.out).toMatch(/含多行或回车/);
    expect(r.out).not.toMatch(/Offsite copy completed/);
    // 最关键：第一行也不许跑。跑了第一行再说"拒绝"，异地副本仍是半套，而运维不知道。
    expect(r.calls).not.toMatch(/OFFSITE /);
    // 定稿产物按设计保留（本地副本是回滚抓手），拒绝的是异地那一步
    expect(r.kinds.enc).toHaveLength(1);
  });

  test('C.2 值里含回车（CRLF env 文件的形态）⇒ 同样拒绝，而不是带着 \\r 去复制', () => {
    // 内部回车：`offsite-ok \r --flag`。旧写法会让最后一个参数带回车进 argv，
    // 复制到"看不见的错路径"还说成功；这里必须在执行前就停手。
    const r = runBackup(work, null, {
      BACKUP_OFFSITE_CMD: `${sh(work.bin)}/offsite-ok \r --flag`,
    });
    expect(r.code).toBe(1);
    expect(r.out).toMatch(/含多行或回车/);
    expect(r.calls).not.toMatch(/OFFSITE /);
  });

  test('C.2 反向自证：尾随换行的单行值照常执行，且回显写的是**被执行的那条**', () => {
    // 这条是 C.2 上两条的对照：剥尾部不等于拒绝执行。`$(...)` 取回的命令天然带尾换行，
    // 把它做成配置错误会把一个正常部署挡在门外。
    const one = `${sh(work.bin)}/offsite-ok`;
    const r = runBackup(work, null, { BACKUP_OFFSITE_CMD: `${one}\n` });
    expect(r.code).toBe(0);
    expect(r.calls).toMatch(/OFFSITE .*file=/);
    const echo = r.out.split('\n').find((l) => l.startsWith('Offsite copy completed:'));
    // 回显与真正执行的字符串逐字节相等（原始值里的尾换行不在里面）
    expect(echo).toBe(`Offsite copy completed: ${one}`);
  });

  /**
   * 前世版脚本（与 describe B 的 writeLegacy 同一手法）：把一处修复**还原成修前的形状**，
   * 再跑同一个夹具。这一对用例判的不是"新版对不对"，而是"断言抓不抓得住回退"——
   * C.1/C.2 那四条如果换了脚本副本照样绿，它们就是没有牙齿的装饰。
   */
  function legacy(transform, name) {
    const src = fs.readFileSync(BACKUP, 'utf8');
    const out = transform(src);
    // 前提自证：正则真的命中了（否则"新旧同一份源码"会让这条永远绿）
    expect(out).not.toBe(src);
    const dir = path.join(work.dir, name);
    fs.mkdirSync(dir, { recursive: true });
    for (const f of ['mongoUri.sh', 'backupCrypto.sh']) {
      fs.copyFileSync(path.join(ROOT, 'scripts', f), path.join(dir, f));
    }
    const p = path.join(dir, 'backup-mongo.sh');
    fs.writeFileSync(p, out);
    expect(execFileSync('bash', ['-n', sh(p)], { encoding: 'utf8' })).toBe('');
    return p;
  }

  test('C.1 前世版自证：把凭据文件挪回 `case` 之前 ⇒ docker 支也留下明文口令（断言有牙齿）', () => {
    const block =
      /([ \t]*)CONFIG_FILE=\$\(mktemp "\$\{TMPDIR:-\/tmp\}\/mongodump-config\.XXXXXX"\)[\s\S]*?printf 'uri: %s\\n' "\$MONGODB_URI" > "\$CONFIG_FILE"\r?\n/m;
    const m = fs.readFileSync(BACKUP, 'utf8').match(block);
    expect(m).not.toBeNull();
    const legacyScript = legacy((src) => {
      const one = src.match(block)[0];
      const stripped = src.replace(block, '');
      // 还原成"建在 case 之前"：缩进去掉，位置挪到 `umask 077` 那行之后
      return stripped.replace(/^umask 077\r?\n/m, `umask 077\n${one.replace(/^[ \t]+/gm, '')}\n`);
    }, 'legacy-cfg');
    const r = runBackup(work, legacyScript, { MONGO_BACKUP_TRANSPORT: 'docker' });
    // 修前形态：备份本身是**成功**的（这正是它危险的地方——没有任何失败信号）
    expect(r.code).toBe(0);
    expect(r.kinds.enc).toHaveLength(1);
    // 而宿主机多了一份没人读的明文口令文件
    expect(r.probe).toMatch(/^HOSTCFG /m);
    expect(r.probe).toMatch(/^uri: mongodb:\/\/fsms:ExplicitPw@/m);
  });

  test('C.2 前世版自证：删掉形状检查 ⇒ 多行值只跑第一行却宣布全部完成', () => {
    const legacyScript = legacy(
      (src) => src.replace(/^case "\$OFFSITE_VALUE" in[\s\S]*?^esac[ \t]*\r?\n/m, ''),
      'legacy-offsite'
    );
    const bin = sh(work.bin);
    const r = runBackup(work, legacyScript, {
      BACKUP_OFFSITE_CMD: `${bin}/offsite-ok\n${bin}/offsite-fail`,
    });
    // 修前形态：退 0，第一行跑了，第二行**静默消失**，还回显 completed
    expect(r.code).toBe(0);
    expect(r.calls).toMatch(/OFFSITE .*file=/);
    expect(r.out).toMatch(/Offsite copy completed/);
    // 现版对同一夹具的结果写在上面对照里（退 1 + 一条都不跑）——这里钉的是"两版确有差别"，
    // 万一有人把检查做成恒真，这条与 C.2 主用例不会同时绿。
    expect(r.out).not.toMatch(/含多行或回车/);
  });
});
