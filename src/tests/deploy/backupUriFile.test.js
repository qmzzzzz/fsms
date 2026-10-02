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

function baseEnv(work, env) {
  return {
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
  };
}

function collect(r, work) {
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

function runScript(script, args, work, env, opts = {}) {
  return collect(
    spawnSync('bash', [sh(script), ...args.map(sh)], {
      // opts.cwd：`MONGODB_URI_FILE=-c` 这类"文件名会被当成选项"的形态只能在
      // 该文件所在目录里复现，且不能把 `-c` 造进仓库目录
      cwd: opts.cwd || ROOT,
      encoding: 'utf8',
      timeout: 60000,
      env: baseEnv(work, env),
    }),
    work
  );
}

/**
 * 经 `bash -c` 起脚本，只为一种形态服务：**连接串里带真换行**。
 * 换行不能走 Node 的 env 块（Windows 上能否承载不可靠），而 `$'…\n…'` 由 bash 自己展开，
 * 与运维手滑敲出来的那个字节等价。脚本与目录也经 env 传进去，避免把含非 ASCII 的
 * 临时目录拼进命令串。
 */
function runBashC(cmd, work, env) {
  return collect(
    spawnSync('bash', ['-c', cmd], {
      cwd: ROOT,
      encoding: 'utf8',
      timeout: 60000,
      env: baseEnv(work, env),
    }),
    work
  );
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

  // ---- NUL / UTF-16（finding #26）----
  // `_body=$(cat -- "$_file")` 这一步 bash 就把 NUL 吃掉了（只在 stderr 留一行 warning，
  // 退出码仍是 0），于是后面四条判据看到的是**改写后的串**，不是文件里的字节。
  // 两条现实形态：UTF-16"另存为"整文件（每个 ASCII 后跟一个 00）⇒ 改写结果恰好仍是合法
  // 连接串，备份 rc=0；库名中间夹一个 NUL ⇒ 改写结果连的是**没人写过的库**。
  // 同族缺陷在 Node 侧的形态更糟（process.env 截断成首字符），见 deployScriptInvariants.test.js。

  test('UTF-16 另存的连接串文件 ⇒ 非零、点名文件、零归档', () => {
    const file = secretFile(work, Buffer.from(`${URI_FILE}\n`, 'utf16le'));
    const r = backup(work, { MONGODB_URI: '', MONGODB_URI_FILE: file });
    expect(r.code).not.toBe(0);
    expect(r.archives).toEqual([]);
    expect(r.out).toMatch(/NUL/);
    expect(r.out).toMatch(/UTF-16/);
    expect(r.out).toContain(file);
  });

  test('库名中间夹一个 NUL ⇒ 拒绝，而不是打进改写后的那个库', () => {
    // 去掉 NUL 后是 `…/fsmsx?authSource=admin`——形状完全合法，四条判据一条都拦不住，
    // 但运维在文件里写的是 `fsms` + 一个不可见字节。这类差异只会出现在恢复那天。
    const file = secretFile(
      work,
      Buffer.from(
        'mongodb://fsms:FilePw%401@127.0.0.1:27017/fsms\u0000x?authSource=admin\n',
        'utf8'
      )
    );
    const r = backup(work, { MONGODB_URI: '', MONGODB_URI_FILE: file });
    expect(r.code).not.toBe(0);
    expect(r.archives).toEqual([]);
    expect(r.calls).not.toMatch(/TOOL /);
    expect(r.out).toMatch(/NUL/);
  });

  test('反向自证：同一串去掉 NUL ⇒ 照常放行（判据没有退化成"拒绝一切"）', () => {
    const file = secretFile(
      work,
      'mongodb://fsms:FilePw%401@127.0.0.1:27017/fsmsx?authSource=admin\n'
    );
    const r = backup(work, { MONGODB_URI: '', MONGODB_URI_FILE: file });
    expect(r.code).toBe(0);
    expect(r.archives).toHaveLength(1);
    expect(r.calls).toMatch(/fsmsx/);
  });

  test('前提自证：删掉 NUL 闸 ⇒ 同一份 UTF-16 夹具 rc=0 并产出归档（红确实来自这道闸）', () => {
    // 机械删块 + 找不到就抛：上一轮踩过"变异没落地、用例对着未改动的文件保持绿"，
    // 所以这里不用 sed 行号，改成"按特征定位并显式断言定位成功"。
    const lines = fs.readFileSync(path.join(ROOT, 'scripts', 'mongoUri.sh'), 'utf8').split('\n');
    const from = lines.findIndex((l) => /tr -dc '\\000'/.test(l));
    if (from < 0) {
      throw new Error('夹具前提失效：mongoUri.sh 里找不到 NUL 闸的判据行，请同步本用例');
    }
    let to = from;
    while (to < lines.length && lines[to].trim() !== 'fi') to += 1;
    if (to >= lines.length) {
      throw new Error('夹具前提失效：NUL 闸的 if 没有配对的 fi 收尾');
    }
    const legacy = path.join(work.dir, 'legacy-nul');
    fs.mkdirSync(legacy);
    for (const f of ['backup-mongo.sh', 'backupCrypto.sh']) {
      fs.copyFileSync(path.join(ROOT, 'scripts', f), path.join(legacy, f));
    }
    fs.writeFileSync(
      path.join(legacy, 'mongoUri.sh'),
      [...lines.slice(0, from), ...lines.slice(to + 1)].join('\n')
    );

    const file = secretFile(work, Buffer.from(`${URI_FILE}\n`, 'utf16le'));
    const r = runScript(path.join(legacy, 'backup-mongo.sh'), [work.backupDir], work, {
      MONGODB_URI: '',
      MONGODB_URI_FILE: file,
    });
    expect(r.code).toBe(0);
    expect(r.archives).toHaveLength(1);
    // 而且送去 mongodump 的是"吃掉 NUL 之后"的串：与正确值字形相同，所以任何
    // 只比对文本的断言都看不出文件其实不是 UTF-8。
    expect(r.calls).toContain('fire_safety');
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

/**
 * 显式 MONGODB_URI 与密钥文件必须过同一道值校验（2026-10-03 审计 finding）。
 *
 * 修前的形状：mongo_hydrate_uri 里"显式值非空 ⇒ return 0"，四条内容判据
 * （单行、纯可打印 ASCII、scheme、非空）只加在文件分支上。于是换行走后门：
 *   MONGODB_URI=$'mongodb://…?authSource=admin\ndrop: true' ./scripts/restore-mongo.sh 归档
 * 退出码 0，配置文件的第二行变成 mongorestore 的 `drop: true`——
 * 「--drop 需显式 RESTORE_DROP=true」这道门禁被绕过，而横幅回显「删除既有 : false」，
 * 现场证据与实际行为相反。目标库名又是在 `?` 处截断出来的，确认令牌照样对得上。
 *
 * 同一批 finding 还有三条形态各异的漏检，一并钉在这里：
 *   · `MONGODB_URI_FILE=-c`：文件操作数没加 `--`，grep 把 `-c` 当选项、转去读调用方
 *     stdin，密钥文件自始至终没被打开，报错却说"内容不是连接串"（说的是没读过的字节）；
 *   · 口令里含未转义 `@`：`${URI_NO_CRED#*@}` 剥最短前缀，把口令尾巴留在"目标主机"里
 *     打进 stdout（cron 邮件与 CI 日志会收走）；
 *   · URI 不含库名：确认令牌退化成一句固定文案，而拒绝信息把这句原样回显——
 *     第二次运行照抄即可放行，恢复范围变成"归档里有什么就恢复什么"。
 */
describe('显式 MONGODB_URI 的内容校验与脱敏回显', () => {
  let work;
  beforeEach(() => {
    work = mkwork('backup-uri-hard-');
  });
  afterEach(() => {
    fs.rmSync(work.dir, { recursive: true, force: true });
  });

  const bashBackup = (uriExpr, extra = {}) =>
    runBashC(`MONGODB_URI=$'${uriExpr}' exec bash "$FS_S" "$FS_D"`, work, {
      FS_S: sh(BACKUP),
      FS_D: sh(work.backupDir),
      MONGODB_URI_FILE: '',
      ...extra,
    });

  test('显式值里的换行 ⇒ 拒绝，drop 不会被追加进配置文件（正向对照同通道放行）', () => {
    const r = bashBackup(`${URI_EXPLICIT}\\ndrop: true`);
    expect(r.code).not.toBe(0);
    expect(r.archives).toEqual([]);
    expect(r.out).toMatch(/换行|不可打印/);
    // 桩工具会把 --config 的内容 cat 回日志：修前这里就会出现 `drop: true` 一行
    expect(r.calls).not.toContain('drop: true');

    // 反向自证：同一命令、同一夹具，只是不带那个换行 ⇒ 必须绿。
    // 没有这一格，上面的红可能来自 bash -c 接线而不是判据本身。
    const ok = bashBackup(URI_EXPLICIT);
    expect(ok.code).toBe(0);
    expect(ok.archives).toHaveLength(1);
  });

  test('显式值不是连接串 ⇒ 同样拒绝（此前只验文件那条路）', () => {
    const r = bashBackup('postgres://fsms:pw@127.0.0.1:5432/fire_safety');
    expect(r.code).not.toBe(0);
    expect(r.archives).toEqual([]);
    expect(r.out).toMatch(/不是 mongodb/);
  });

  test('MONGODB_URI_FILE=-c ⇒ 打开的是那个文件，不是调用方的 stdin', () => {
    // `-c` 与密钥文件放在同一个目录里，并以该目录为 cwd：值就是字面量 `-c`，
    // 这正是"以 - 开头的路径被当成选项"的唯一可复现形状。
    fs.writeFileSync(path.join(work.dir, '-c'), URI_FILE);
    const r = runScript(
      BACKUP,
      [work.backupDir],
      work,
      { MONGODB_URI: '', MONGODB_URI_FILE: '-c' },
      {
        cwd: work.dir,
      }
    );
    expect(r.code).toBe(0);
    expect(r.calls).toContain(`uri: ${URI_FILE}`);
    expect(r.out).not.toMatch(/空文件/);
  });

  test('口令里含未转义 @ ⇒ 回显的主机段不含口令尾巴', () => {
    makeArchive(work);
    const uri = 'mongodb://fsms:Sup3r!ca@99@10.0.0.5:27017/fire_safety?authSource=admin';
    const r = restore(work, { MONGODB_URI: uri, MONGODB_URI_FILE: '' });
    expect(r.code).toBe(0);
    expect(r.out).toContain('目标主机 : 10.0.0.5:27017');
    expect(r.out).not.toContain('99@10.0.0.5');
    expect(r.out).not.toContain('Sup3r');
  });

  test('URI 不含库名 ⇒ 拒绝执行，抄不动确认门禁', () => {
    makeArchive(work);
    const uri = 'mongodb://fsms:pw@10.0.0.5:27017';
    // 修前：期望值就是被拒绝信息原样回显的那句固定文案，照抄一遍即可放行
    const asSentinel = restore(work, {
      MONGODB_URI: uri,
      MONGODB_URI_FILE: '',
      RESTORE_CONFIRM: '(未在 URI 中指定，将按归档内的库名恢复)',
    });
    expect(asSentinel.code).not.toBe(0);
    expect(asSentinel.out).toMatch(/未指定库名/);
    // 桩工具把每次调用都记进 log：这里必须一条都没有 ⇒ 真的没走到 mongorestore
    expect(asSentinel.calls).toBe('');

    // 补上库名 ⇒ 同一条链路必须放行（证明红来自"没有库名"，不是夹具或 transport）
    const withDb = restore(work, {
      MONGODB_URI: `${uri}/fire_safety`,
      MONGODB_URI_FILE: '',
      RESTORE_CONFIRM: DB,
    });
    expect(withDb.code).toBe(0);
    expect(withDb.calls).toContain('--config=');
  });

  test('SIGINT 打断备份 ⇒ 不得打印"备份成功"（trap 必须自己 exit）', () => {
    // 桩 mongodump 演示真工具的行为：先写出半截归档，收到 INT 也不死，1.2s 后正常退出 0。
    // 修前 `trap cleanup EXIT INT TERM` 只做清理不 exit ⇒ 脚本在信号之后继续往下跑，
    // 于是那份 5 字节的半截归档被打印成 "Backup completed successfully" 并补了 .sha256。
    //
    // 信号由**桩在半截归档落盘的那一刻**发给父进程，而不是外面挂一个 `sleep 0.4` 的定时器：
    // 并行跑套件时 mongodump 可能整段跑完都还没到 0.4s（也可能反过来），用例就退化成
    // "看机器快慢"的随机数——实测在本机 `src/tests/config src/tests/deploy` 同跑时确实漂了。
    // 让因果落在"归档已存在 ⇒ 立刻打断"上，红绿只取决于脚本自己的 trap 语义。
    fs.writeFileSync(
      path.join(work.bin, 'mongodump'),
      [
        '#!/usr/bin/env bash',
        'for a in "$@"; do case "$a" in --archive=*) out="${a#--archive=}";; esac; done',
        'printf "PARTIAL" > "$out"',
        'kill -INT "$PPID" 2>/dev/null || true',
        'trap "exit 0" INT',
        'sleep 1.2',
        'exit 0',
        '',
      ].join('\n'),
      { mode: 0o755 }
    );
    fs.chmodSync(path.join(work.bin, 'mongodump'), 0o755);

    const r = runBashC('exec bash "$FS_S" "$FS_D"', work, {
      FS_S: sh(BACKUP),
      FS_D: sh(work.backupDir),
      MONGODB_URI: URI_EXPLICIT,
      MONGODB_URI_FILE: '',
    });
    expect(r.out).not.toMatch(/Backup completed successfully/);
    expect(r.code).not.toBe(0);
    // 信号打断之后**目录里不能留东西**：桩已经写出半截归档，而它的名字与成功产物
    // 同形（fire-safety-backup-*.gz）——留着它，retention 清单与回滚演练就会把
    // 一次中断的运行当成"最近有一次备份"。cleanup 按定稿标志（FINALIZED）删除未定稿产物。
    expect(r.archives).toEqual([]);
  });
});
