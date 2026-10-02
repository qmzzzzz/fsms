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
  const log = path.join(dir, 'calls.log');

  const write = (name, lines) => {
    const p = path.join(bin, name);
    fs.writeFileSync(p, `${lines.join('\n')}\n`, { mode: 0o755 });
    fs.chmodSync(p, 0o755);
  };

  write('mongodump', [
    '#!/usr/bin/env bash',
    'echo "TOOL $*" >> "$STUB_LOG"',
    'for a in "$@"; do',
    '  case "$a" in',
    '    --config=*) cat "${a#--config=}" >> "$STUB_LOG" ;;',
    '    --archive=*) printf \'FAKE-ARCHIVE-BYTES\' > "${a#--archive=}" ;;',
    '  esac',
    'done',
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

  return { dir, bin, log, backupDir: path.join(dir, 'backups') };
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
});
