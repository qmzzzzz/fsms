/**
 * MONGODB_URI_FILE → backup-mongo.sh / restore-mongo.sh
 * （scripts/mongoUri.sh 的 mongo_hydrate_uri，与 deployment/backup-encryption.md 的每日 cron）
 *
 * 为什么值得一个专门闸：`*_FILE` 约定的权威实现是 src/config/secrets.js 的
 * hydrateSecretsFromFiles()，它只在「require 到 src/config 的 Node 入口」里生效；
 * 备份/恢复是纯 shell，从来没接上。后果不是报错难懂，是**备份覆盖率静默归零**：
 * 手册让运维写 `MONGODB_URI_FILE=… ./scripts/backup-mongo.sh`，脚本只认 MONGODB_URI，
 * 于是每天定时退出码 1、一份归档都不产出，而失败只落在 cron 的 stderr 里。
 * 「有备份」因此在整整一个周期里是错觉，唯一暴露时刻是真正要恢复的那天。
 *
 * 判据全部是真进程 + 桩工具：断言的是"改写后的 URI 到底送到了 mongodump/mongorestore
 * 的 --config 文件里"，而不是脚本文本里有没有某个字符串。用例 2 是反向自证：
 * 用一份"只认 MONGODB_URI"的前世版 mongoUri.sh 跑同一组夹具，
 * 证明本闸的红绿确实由 hydrate 决定，而不是被别的东西凑出来的绿。
 */

'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync, execFileSync } = require('child_process');

const ROOT = path.resolve(__dirname, '../../..');
const BACKUP = path.join(ROOT, 'scripts/backup-mongo.sh');
const RESTORE = path.join(ROOT, 'scripts/restore-mongo.sh');

const DB = 'fire_safety';
const URI_FILE = `mongodb://fsms:FilePw%401@127.0.0.1:27017/${DB}?authSource=admin`;
const URI_EXPLICIT = `mongodb://fsms:ExplicitPw@127.0.0.1:27017/${DB}?authSource=admin`;

const sh = (p) => String(p).replace(/\\/g, '/');

function mkwork(prefix) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  const bin = path.join(dir, 'bin');
  fs.mkdirSync(bin);
  const log = path.join(dir, 'calls.log');

  const dumpStub = [
    '#!/usr/bin/env bash',
    'echo "TOOL $*" >> "$STUB_LOG"',
    'for a in "$@"; do',
    '  case "$a" in',
    '    --config=*) cat "${a#--config=}" >> "$STUB_LOG" ;;',
    // 只有备份侧需要桩"造出"归档；恢复侧的 --archive= 是**读**同一个路径，
    // 无差别覆写会让桩自己把夹具毁掉（本用例里是哈希已经算完才调用，
    // 但毁掉夹具的桩撑不住后续加进来的断言，所以按方向位区分）。
    '    --archive=*) if [ "${STUB_WRITES_ARCHIVE:-0}" = 1 ]; then',
    '      printf \'FAKE-ARCHIVE-BYTES\' > "${a#--archive=}"; fi ;;',
    '  esac',
    'done',
    'exit 0',
    '',
  ].join('\n');
  for (const name of ['mongodump', 'mongorestore']) {
    const p = path.join(bin, name);
    fs.writeFileSync(p, dumpStub, { mode: 0o755 });
    fs.chmodSync(p, 0o755);
  }
  return { dir, bin, log, backupDir: path.join(dir, 'backups') };
}

function runScript(script, args, work, env) {
  const r = spawnSync('bash', [sh(script), ...args.map(sh)], {
    cwd: ROOT,
    encoding: 'utf8',
    timeout: 60000,
    env: {
      ...process.env,
      PATH: `${work.bin}${path.delimiter}${process.env.PATH}`,
      STUB_LOG: sh(work.log),
      // 本文件只锁"连接串从哪来"，加密与异地副本由 backupEncryptionContract.test.js 覆盖
      BACKUP_ENCRYPTION: 'plaintext-acknowledged',
      MONGO_BACKUP_TRANSPORT: 'local',
      MONGO_RESTORE_TRANSPORT: 'local',
      RESTORE_CONFIRM: DB,
      BACKUP_RETENTION_DAYS: '30',
      STUB_WRITES_ARCHIVE: '1',
      ...env,
    },
  });
  if (r.error) {
    // 环境没有 bash ⇒ 红，不静默跳过（静默跳过等于把这层防护换成错觉）
    throw new Error(
      `本机找不到 bash（Git Bash / CI runner 都自带），本闸无法执行：${r.error.message}`
    );
  }
  const out = `${r.stdout || ''}${r.stderr || ''}`;
  const archives = fs.existsSync(work.backupDir)
    ? fs.readdirSync(work.backupDir).filter((f) => f.endsWith('.gz'))
    : [];
  return {
    code: r.status,
    out,
    archives,
    calls: fs.existsSync(work.log) ? fs.readFileSync(work.log, 'utf8') : '',
  };
}

const backup = (work, env) => runScript(BACKUP, [work.backupDir], work, env);
const restore = (work, env, archive) =>
  runScript(RESTORE, [archive || work.archive], work, { STUB_WRITES_ARCHIVE: '0', ...env });

/** 写一个 *_FILE 夹具；content 已是最终字节（换行/BOM 由用例自己控制） */
function secretFile(work, content) {
  const p = path.join(work.dir, 'mongodb_uri');
  fs.writeFileSync(p, content);
  return p;
}

/** 恢复侧需要一个「归档 + sidecar」都成立的夹具，否则死在完整性门禁、到不了 URI 检查 */
function makeArchive(work) {
  fs.mkdirSync(work.backupDir, { recursive: true });
  const archive = path.join(work.backupDir, 'fire-safety-backup-t1.gz');
  fs.writeFileSync(archive, 'ARCHIVE-BYTES-ORIGINAL');
  execFileSync('bash', ['-c', `sha256sum '${sh(archive)}' > '${sh(archive)}.sha256'`], {
    cwd: ROOT,
    encoding: 'utf8',
  });
  work.archive = archive;
  return archive;
}

describe('backup/restore 的 MONGODB_URI_FILE 接线（每日 cron 的默认形态）', () => {
  let work;
  beforeEach(() => {
    work = mkwork('backup-uri-');
  });
  afterEach(() => {
    fs.rmSync(work.dir, { recursive: true, force: true });
  });

  // ---- 前提自证：闸不是空转的 ----

  test('前提自证：两个来源都不给 ⇒ 非零、点名两种给法、零归档', () => {
    const r = backup(work, { MONGODB_URI: '', MONGODB_URI_FILE: '' });
    expect(r.code).not.toBe(0);
    expect(r.out).toMatch(/MONGODB_URI\b/);
    expect(r.out).toMatch(/MONGODB_URI_FILE/);
    expect(r.archives).toEqual([]);
  });

  test('前提自证：把 hydrate 换成前世版（只认 MONGODB_URI）⇒ 同一夹具必须红', () => {
    // 复制脚本到临时目录，并塞一份"只认明文"的 mongoUri.sh：脚本按 $(dirname $0) 找它。
    const legacy = path.join(work.dir, 'legacy');
    fs.mkdirSync(legacy);
    for (const f of ['backup-mongo.sh', 'backupCrypto.sh']) {
      fs.copyFileSync(path.join(ROOT, 'scripts', f), path.join(legacy, f));
    }
    fs.writeFileSync(
      path.join(legacy, 'mongoUri.sh'),
      [
        '# 前世版：只承认显式 MONGODB_URI，不看 *_FILE（修前行为）',
        'mongo_hydrate_uri() { [ -n "${MONGODB_URI:-}" ]; }',
        'mongo_swap_host() { printf "%s" "$1"; }',
        '',
      ].join('\n')
    );
    const file = secretFile(work, URI_FILE);
    const legacyScript = path.join(legacy, 'backup-mongo.sh');

    const bad = runScript(legacyScript, [work.backupDir], work, {
      MONGODB_URI: '',
      MONGODB_URI_FILE: file,
    });
    expect(bad.code).not.toBe(0);
    expect(bad.archives).toEqual([]);

    // 同一套夹具、同一份桩，只把连接串换成明文形态 ⇒ 必须放行。
    // 这一格证明上一格的红来自 *_FILE 不被识别，而不是路径/桩/权限出问题。
    const good = runScript(legacyScript, [work.backupDir], work, {
      MONGODB_URI: URI_EXPLICIT,
      MONGODB_URI_FILE: '',
    });
    expect(good.code).toBe(0);
    expect(good.archives).toHaveLength(1);
  });

  test('前提自证：桩通道真的能带回 --config 内容（否则下面的 URI 断言恒绿）', () => {
    const r = backup(work, { MONGODB_URI: URI_EXPLICIT, MONGODB_URI_FILE: '' });
    expect(r.code).toBe(0);
    expect(r.calls).toContain(`uri: ${URI_EXPLICIT}`);
  });

  // ---- 核心：运维手册的写法现在成立 ----

  test('只给 MONGODB_URI_FILE ⇒ 备份跑通，且文件里的连接串真的进了 mongodump 的 --config', () => {
    const file = secretFile(work, URI_FILE);
    const r = backup(work, { MONGODB_URI: '', MONGODB_URI_FILE: file });
    expect(r.code).toBe(0);
    expect(r.out).not.toMatch(/MONGODB_URI.*not set/);
    expect(r.calls).toContain(`uri: ${URI_FILE}`);
    expect(r.archives).toHaveLength(1);
  });

  test.each([
    ['generate-secrets.js 的形态（无尾换行）', URI_FILE],
    ['echo 写的（尾换行）', `${URI_FILE}\n`],
    ['Windows 记事本/CRLF（尾 CR + 空行）', `${URI_FILE}\r\n\r\n`],
    ['PowerShell Set-Content -Encoding UTF8（带 BOM）', `\uFEFF${URI_FILE}\n`],
  ])('密钥文件写法差异不影响：%s', (_label, content) => {
    const file = secretFile(work, content);
    const r = backup(work, { MONGODB_URI: '', MONGODB_URI_FILE: file });
    expect(r.code).toBe(0);
    // 断言的是"精确这一条"，不是"含 mongodb://"：换行/BOM/CR 若没被剥掉，
    // mongodump 会拿到一条尾巴坏掉的串，而备份照样退出 0。
    expect(r.calls).toContain(`uri: ${URI_FILE}\n`);
    expect(r.calls).not.toMatch(/uri: .*\r/);
  });

  test('恢复侧同一口径：只给 MONGODB_URI_FILE ⇒ mongorestore 被调用且目标库正确', () => {
    makeArchive(work);
    const file = secretFile(work, URI_FILE);
    const r = restore(work, { MONGODB_URI: '', MONGODB_URI_FILE: file });
    expect(r.code).toBe(0);
    expect(r.calls).toContain(`uri: ${URI_FILE}`);
    // RESTORE_CONFIRM 要等于目标库名才能过；它是在 hydrate 之后才比对的，
    // 所以"退出 0"本身就证明回填早于目标库确认（早于任何写库动作）。
    // 桩被真的调用过（不是"脚本自己退 0 但没跑工具"）
    expect(r.calls).toContain('TOOL ');
  });

  // ---- 取向：显式值优先（与 Node 侧相反，恢复目标必须可由命令行点名）----

  test('MONGODB_URI 与 MONGODB_URI_FILE 并存 ⇒ 用显式值、并告警', () => {
    const file = secretFile(work, URI_FILE);
    const r = backup(work, { MONGODB_URI: URI_EXPLICIT, MONGODB_URI_FILE: file });
    expect(r.code).toBe(0);
    expect(r.calls).toContain(`uri: ${URI_EXPLICIT}`);
    expect(r.calls).not.toContain(URI_FILE);
    expect(r.out).toMatch(/Warning/);
    expect(r.out).toMatch(/MONGODB_URI_FILE/);
  });

  // ---- 坏文件：必须硬失败且点名文件，绝不"回退到本地库"或"静默半条串" ----

  test.each([
    ['空文件', ''],
    ['两条非空行（取其一等于连一个没人知道的库）', `mongodb://a/1\nmongodb://b/2\n`],
    ['不是连接串', 'hunter2\n'],
    ['含空格（未转义的凭据）', 'mongodb://u:pa ss@h/db\n'],
    ['含控制字符', `mongodb://u:p\x01@h/db\n`],
  ])('坏密钥文件 ⇒ 拒绝：%s', (_label, content) => {
    const file = secretFile(work, content);
    const r = backup(work, { MONGODB_URI: '', MONGODB_URI_FILE: file });
    expect(r.code).not.toBe(0);
    expect(r.archives).toEqual([]);
    expect(r.calls).toBe(''); // 连工具都没被调用，不是"跑了但失败"
    // 断言的是脚本**原样回显**的那个路径串（不换成 / 形态：环境变量给它什么形态，
    // 报错就得是什么形态，运维照着报错去 ls 才找得到文件）。
    expect(r.out).toContain(file);
  });

  test('MONGODB_URI_FILE 指向不存在的路径 ⇒ 拒绝并点名文件', () => {
    const missing = path.join(work.dir, 'nope');
    const r = backup(work, { MONGODB_URI: '', MONGODB_URI_FILE: missing });
    expect(r.code).not.toBe(0);
    expect(r.archives).toEqual([]);
    expect(r.out).toContain(missing);
  });

  // ---- 凭据通道不回退（P2-27：连接串绝不上 argv）----

  test('hydrate 之后凭据仍不进 argv：文件里的串只出现在 --config 内容中', () => {
    const file = secretFile(work, URI_FILE);
    const r = backup(work, { MONGODB_URI: '', MONGODB_URI_FILE: file });
    expect(r.code).toBe(0);
    const argvLines = r.calls
      .split('\n')
      .filter((l) => l.startsWith('TOOL '))
      .join('\n');
    expect(argvLines).not.toContain('mongodb://');
    expect(argvLines).not.toContain('FilePw');
    expect(argvLines).toContain('--config=');
  });
});
