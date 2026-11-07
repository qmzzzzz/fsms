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

/**
 * PATH 条目必须转成 `/d/…`：实测（2026-10-30）MSYS 把 `D:/…` 当成**不可解析的字面路径**，
 * 于是「把桩目录放进 PATH」会静默失效——命令照样落在 /usr/bin 的真工具上，
 * 用例便在「以为桩已生效」的假前提下变绿。`sh()` 只换反斜杠，故这里单列一个转换器。
 */
const posix = (p) =>
  String(p)
    .replace(/\\/g, '/')
    .replace(/^([A-Za-z]):\//, (_m, d) => `/${d.toLowerCase()}/`);

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

  test('调用方 IFS 污染（source 场景）+ 两向共谋 tr ⇒ od 逐字节目视仍拒 NUL（fail-closed）', () => {
    // audit-round6-odparser.md ②-2：mongoUri.sh 被 source 进调用方 shell，`for … in $var` 的
    // 切分随调用方 IFS 走。若 IFS=' '，od 输出的换行不再作分隔符、行尾 token 连换行粘成
    // `00\n`，`case 00)` 漏计；再配「数 NUL 的调用输出空、数非 NUL 的调用透传」的两向共谋
    // tr 桩，互补和式闭合 ⇒ 修复前 rc=0、含 NUL 文件被静默接受。修复：od 循环外局部固定
    // IFS（`_ifs_saved` 成对保存/恢复，restore-mongo 的 `IFS= read` 同款局部化纪律）。
    // 两向共谋 tr：`tr -dc '\000'`（数 NUL 的那条管道）输出空 ⇒ _file_nul=0；
    // `tr -cd '\001-\377'`（数非 NUL 的那条）原样透传 ⇒ _file_nonnull=总字节 ⇒ 和式闭合。
    // mkwork 已把 work/bin 放在 PATH 首位，桩在这里遮蔽真 tr；桩把每次调用记进 $STUB_LOG，
    // 用例末尾断言两条管道**都被桩接过** —— 否则真 tr 会让这条用例变成空转（假绿）。
    const trStub = path.join(work.bin, 'tr');
    fs.writeFileSync(
      trStub,
      [
        '#!/usr/bin/env bash',
        'echo "TR $*" >> "$STUB_LOG"',
        'case "$*" in',
        '  *001-377*) exec /usr/bin/cat ;;',
        '  *000*) exec /usr/bin/true ;;',
        '  *) exec /usr/bin/cat ;;',
        'esac',
        '',
      ].join('\n')
    );
    // chmod 与 mkwork 同款：Windows 上 writeFileSync 的 mode 不足以让 MSYS 认它是可执行体，
    // 缺这一句桩会被跳过、用例退化成对着真 tr 空转。
    fs.chmodSync(trStub, 0o755);
    const file = secretFile(
      work,
      Buffer.from('mongodb://a:1/h\u0000x', 'utf8') // 17 B：NUL 是 od 第一行的行尾 token（第 16 字节）
    );
    // PATH 必须在命令串里前置（MSYS 会把 /usr/bin:/mingw64/bin 重新前置，光靠 env 块的 PATH
    // 遮蔽不到 tr），且整条赋值要用双引号 —— PATH 里有含空格的目录，裸 $PATH 会在空格处断句。
    // 目录形态必须是 `/d/…`：`D:/…` 这种混合形态 MSYS 整段跳过，桩形同不存在（假绿）。
    const r = runBashC(
      [
        `PATH="${posix(work.bin)}:$PATH"; export PATH; IFS=' '; . "${posix(
          path.join(ROOT, 'scripts', 'mongoUri.sh')
        )}"`,
        `MONGODB_URI=''; MONGODB_URI_FILE='${posix(file)}'; mongo_hydrate_uri`,
      ].join('\n'),
      work,
      {}
    );
    expect(r.code).not.toBe(0);
    expect(r.out).toMatch(/NUL/);
    // 前提自证：桩确实遮蔽了真 tr，且 NUL 管道与非 NUL 管道都经过了它
    expect(r.calls).toMatch(/TR -dc \\000/);
    expect(r.calls).toMatch(/TR -cd \\001-\\377/);
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
    // 判据几经演进（NUL 计数 → 非 NUL 计数 → 互补计数和式 + NUL 直接计数 + od 逐字节目视），
    // NUL 的拒绝语义现在由**两条冗余臂**承载：直接计数臂与 od 逐字节目视臂（互为备份）。
    // 所以这里把两臂一起摘（探针证实：只摘一条时另一条仍拦住 UTF-16 夹具；两条都摘 ⇒
    // 「NUL 计数被吞 ⇒ 相等 ⇒ 放行」的原始缺陷链重新成立，rc=0 且值被静默改写）：
    // 锚点必须是 **if 行**而不是赋值行：赋值行后面先经过一串 case/其他 if（第四轮新增的
    // stat/-s/互补计数腿），用「第一个 fi」会删掉半截、留下悬空的 _file_nonnull 引用 ——
    // 那种静默错删正是这条用例自己要防的形态。锚点字面量必须与判据行**逐字节同形**，
    // 找不到就抛（判据变了 ⇒ 同步本用例），不许静默跳过。
    const armOf = (needle) => {
      const at = lines.findIndex((l) => l.includes(needle));
      if (at < 0) {
        throw new Error(`夹具前提失效：mongoUri.sh 里找不到判据行 ${needle}，请同步本用例`);
      }
      let end = at;
      while (end < lines.length && lines[end].trim() !== 'fi') end += 1;
      if (end >= lines.length) {
        throw new Error('夹具前提失效：判据 if 没有配对的 fi 收尾');
      }
      return [at, end];
    };
    const armA = armOf('if [ "$_file_nul" != 0 ]; then');
    const armB = armOf('if [ "$_od_nul" != 0 ]; then');
    const keep = lines.filter(
      (_, i) => !(i >= armA[0] && i <= armA[1]) && !(i >= armB[0] && i <= armB[1])
    );
    const legacy = path.join(work.dir, 'legacy-nul');
    fs.mkdirSync(legacy);
    for (const f of ['backup-mongo.sh', 'backupCrypto.sh']) {
      fs.copyFileSync(path.join(ROOT, 'scripts', f), path.join(legacy, f));
    }
    fs.writeFileSync(path.join(legacy, 'mongoUri.sh'), keep.join('\n'));

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

  // ---- 凭据通道不回退（连接串绝不上 argv）----

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

  /**
   * 工具缺失 ⇒ 必须失败关（A6，2026-10-30）。
   *
   * `mongo_validate_uri` 的「单行纯可打印 ASCII」判据由 `tr` 执行，而它的失败**是静默的**：
   * 命令替换得到空串，与「干净的值」不可分。修复前实测（本机，PATH 里没有 tr）：
   * 带真换行的连接串照样 rc=0 —— 换行会被写成 mongodump/mongorestore 配置文件的第二行，
   * 而配置里唯一由调用方决定的那一段正是它（见 scripts/mongoUri.sh 顶部 2026-10-03 的取证）。
   * 所以这里锁两件事：没有 tr 时**必须拒绝**，且拒绝理由要点名 tr（红不能由别的判据凑出来）。
   */
  describe('tr 不可用时 mongo_validate_uri 必须失败关（不是静默放行）', () => {
    const VALIDATE_LIB = path.join(ROOT, 'scripts/mongoUri.sh');
    const CLEAN = 'mongodb://fsms:pw@127.0.0.1:27017/fire_safety';

    /**
     * 起一个真 sh：先 source mongoUri.sh，再按需把 PATH 换成「只有桩工具」的目录。
     *
     * PATH 必须在 **shell 内部**设死：Git Bash / MSYS 启动时会把 /usr/bin:/mingw64/bin
     * 塞回 PATH（实测），从 Node 侧传一个不含 tr 的 env.PATH 删不掉 tr ——
     * 那样的用例会在「以为已移除」的假前提下变绿，等于没测。
     * 换行值同样在 shell 内部用 printf 生成：真换行经 Windows 命令行转交 bash 不可靠。
     */
    const callValidate = ({
      newline = false,
      stripPath = false,
      trStub = '',
      wcStub = '',
    } = {}) => {
      const payload = newline
        ? "printf 'mongodb://fsms:pw@127.0.0.1:27017/fire_safety\\ndrop:true'"
        : `printf '%s' '${CLEAN}'`;
      // stripPath：PATH 里只剩桩目录（工具真缺）；trStub/wcStub：桩目录 + 真工具（只遮一个）。
      // 两者都必须走 posix()：`D:/…` 形态的 PATH 条目 MSYS 解析不到（实测），
      // 那会让「桩已生效」这个前提静默失效 —— 判据照样落在 /usr/bin 的真工具上。
      const writeStub = (name, body) => {
        fs.writeFileSync(path.join(work.bin, name), body, { mode: 0o755 });
        try {
          fs.chmodSync(path.join(work.bin, name), 0o755);
        } catch (_) {
          /* Windows 上 mode 参数已足够 */
        }
      };
      if (trStub) {
        // 桩只遮 tr，其余工具（wc/grep/…）照常可用：这正是审计实测的形态 ——
        // 「工具在不在」通过，「判据这一次能不能执行」不通过。
        writeStub('tr', trStub);
      }
      // wcStub 走「路径里必需有桩目录」那一支：桩目录 + 真工具，与 trStub 同款。
      const useStubDir = Boolean(trStub || wcStub);
      const pathLine2 = stripPath
        ? `PATH='${posix(work.bin)}'; export PATH; `
        : useStubDir
          ? `PATH='${posix(work.bin)}:/usr/bin:/bin'; export PATH; `
          : '';
      if (wcStub) writeStub('wc', wcStub);
      // 末尾带上 tr/wc 的实际解析结果：桩是否真的生效必须被观测，否则「桩没进 PATH」会伪装成绿。
      const cmd = `_v=$(${payload}); . "$1"; ${pathLine2}mongo_validate_uri "$_v" MONGODB_URI; printf 'rc=%s' "$?"; printf 'tr=%s' "$(command -v tr 2>/dev/null)"; printf 'wc=%s' "$(command -v wc 2>/dev/null)"`;
      const r = spawnSync('bash', ['-c', cmd, '_', sh(VALIDATE_LIB)], {
        cwd: ROOT,
        encoding: 'utf8',
        timeout: 30000,
      });
      return { code: r.status, out: `${r.stdout || ''}${r.stderr || ''}` };
    };

    test('前提自证：tr 在位时判据是活的（干净值放行、换行值拒绝）', () => {
      expect(callValidate().out).toContain('rc=0');
      const nlValue = callValidate({ newline: true });
      expect(nlValue.out).toContain('rc=1');
      // 拒绝理由必须是「值里有越界字节」，不是别的判据顺手拒绝的
      expect(nlValue.out).toMatch(/换行或不可打印字符/);
    });

    test('没有 tr：带换行的值必须拒绝，且理由点名 tr（修复前实测 rc=0）', () => {
      const r = callValidate({ newline: true, stripPath: true });
      expect(r.out).toContain('rc=1');
      expect(r.out).toMatch(/字节计数不可用/);
    });

    test('没有 tr：干净值同样拒绝（无法校验即拒绝，宁静不能以放行为代价）', () => {
      const r = callValidate({ stripPath: true });
      expect(r.out).toContain('rc=1');
      expect(r.out).toMatch(/字节计数不可用/);
    });

    /**
     * 2026-10-30 第三轮审计的形态：探针证明的是「工具在不在」，判据要的是「这一次调用能不能执行」。
     * 只装一个「无 tr」的桩是不够的 —— 曾经的探针跑 `tr -d 'a'` 通过、判据跑 `tr -d '\\041-\\176'` 失败，
     * 于是 `$(…; printf '~')` 恰好等于 '~'，换行注入的连接串照样 rc=0。
     * 所以这里让桩**只在八进制区间集合这一形态上**失败（其余形态委托真 tr）：
     * 判据必须仍然拒绝，且理由必须指向「判不出来」，而不是变成放行。
     */
    test('tr 只在判据的那种形态上失败（八进制区间集合）⇒ 仍然拒绝（修复前实测 rc=0）', () => {
      const stub = [
        '#!/bin/sh',
        'case "$*" in *"041-"*) echo "tr: illegal set" >&2; exit 1 ;; esac',
        'exec /usr/bin/tr "$@"',
        '',
      ].join('\n');
      const r = callValidate({ newline: true, trStub: stub });
      expect(r.out).toMatch(/tr=\S*backup-uri-hard[^\s]*\/bin\/tr/); // 前提自证：桩确实被解析到了
      expect(r.out).toContain('rc=1');
      expect(r.out).toMatch(/字节计数不可用|换行或不可打印字符/);
    });

    /**
     * 第四轮审计（2026-10-30）把 fail-open 从 tr 这条腿搬到了 wc 这条腿：wc 退出 0、打印 0 时
     * 两个计数都是 0 ⇒ 相等 ⇒ 放行（实测：换行注入照样 rc=0）。两种新形态各配一条腿：
     *   · wc 静默 0 —— 由「`${#_uri}`（shell 内建）与字节数交叉」拦住；0 是合法数字，形状校验挡不住它。
     *   · tr 退化成 cat（能跑、退出 0、一个字节都不删）—— 由「同一形态的自检常量」拦住。
     * 每条都配前提自证（桩确实生效），否则「桩没进 PATH」会伪装成绿。
     */
    test('wc 从第二次调用起只打印 0 ⇒ 判据必须拒绝（形状校验挡不住 0，靠内建字符数交叉）', () => {
      const counter = path.join(work.bin, 'wc.count');
      fs.writeFileSync(counter, '0');
      const stub = [
        '#!/bin/sh',
        `c=$(cat '${posix(counter)}' 2>/dev/null || printf 0)`,
        'c=$((c + 1))',
        `printf '%s\\n' "$c" > '${posix(counter)}'`,
        '[ "$c" -gt 1 ] && { printf "0\\n"; exit 0; }',
        'exec /usr/bin/wc "$@"',
        '',
      ].join('\n');
      // 干净值：绝对值是 46，桩把它变成 0 —— 只有与 `\${#_uri}` 交叉才能发现。
      const r = callValidate({ wcStub: stub });
      expect(r.out).toMatch(/wc=\S*backup-uri-hard[^\s]*\/bin\/wc/); // 前提自证：桩确实被解析到了
      expect(r.out).toContain('rc=1');
      expect(r.out).toMatch(/字节数与字符数不符|字节计数不可用/);
    });

    test('tr 退化成 cat（退出 0、不删任何字节）⇒ 判据必须拒绝（互补计数之和 ≠ 总字节数）', () => {
      // 桩不过滤：允许集与禁止集两条管道都得到整串 ⇒ 两边之和 = 2×总数 ≠ 总数 ⇒ 判「检测不可用」。
      // 这条判据跑在**真实载荷**上，所以没有固定串可以被绕（固定串自检那一版正是栽在这里）。
      const r = callValidate({ trStub: '#!/bin/sh\nexec cat\n' });
      expect(r.out).toContain('rc=1');
      expect(r.out).toMatch(/tr 没有按判据过滤字节/);
    });

    test('tr 吃掉一切（退出 0、无输出）⇒ 判据必须拒绝（互补计数之和 = 0 ≠ 总字节数）', () => {
      // 这一条是「和式」那条腿存在的理由：吃掉一切时两个违禁/允许计数都是 0，
      // 「违禁字节数 == 0」会放行一个**已被工具毁掉**的值。
      // 桩只在判据形态（-cd）上吃掉一切，规范化管道（tr -d ' \t'）仍走真 tr ——
      // 否则连「把 wc 输出去掉空白」这一步都会被打断，用例测到的就不是这条腿了。
      const eat = [
        '#!/bin/sh',
        'case "$*" in *-cd*) /usr/bin/cat > /dev/null; exit 0 ;; esac',
        'exec /usr/bin/tr "$@"',
        '',
      ].join('\n');
      const r = callValidate({ trStub: eat });
      expect(r.out).toContain('rc=1');
      expect(r.out).toMatch(/tr 没有按判据过滤字节/);
    });

    test('内容相关退化的 tr（短输入正常、真实载荷透传）+ 换行载荷 ⇒ 必须拒绝（第四轮复攻的原始形态）', () => {
      // 审计实测：固定串自检只能证明「短输入」这一形态，工具对真实载荷退化为透传时旧版 rc=0。
      const scratch = posix(path.join(work.bin, 'tr.in'));
      const stub = [
        '#!/bin/sh',
        `_d='${scratch}'`,
        '/usr/bin/cat > "$_d"',
        'if [ "$(/usr/bin/wc -c < "$_d" | /usr/bin/tr -d " ")" -le 12 ]; then',
        '  exec /usr/bin/tr "$@" < "$_d"',
        'fi',
        'exec /usr/bin/cat < "$_d"',
        '',
      ].join('\n');
      const r = callValidate({ newline: true, trStub: stub });
      expect(r.out).toContain('rc=1');
      // 拒绝理由随桩保真度漂移（CI ubuntu /bin/sh=dash 下内容退化桩的透传行为
      // 与 Git Bash bash 不同）：只要是 fail-closed 拒绝（rc=1+拒绝放行），具体
      // 理由按兄弟用例同款口径放宽到"未能完成"族。
      expect(r.out).toMatch(/tr 没有按判据过滤字节|换行或不可打印字符|未能完成/);
    });
    test('前提自证：同一个桩下干净值也必须拒绝（判据不再是「碰巧有 tr」就算数）', () => {
      const stub = [
        '#!/bin/sh',
        'case "$*" in *"041-"*) echo "tr: illegal set" >&2; exit 1 ;; esac',
        'exec /usr/bin/tr "$@"',
        '',
      ].join('\n');
      const r = callValidate({ trStub: stub });
      expect(r.out).toMatch(/tr=\S*backup-uri-hard[^\s]*\/bin\/tr/); // 前提自证：桩确实被解析到了
      expect(r.out).toContain('rc=1');
      expect(r.out).toMatch(/字节计数不可用|换行或不可打印字符/);
    });
  });

  /**
   * 同族的第二条：NUL 判据的**正常值就是 0**，与「工具死了输出 0」不可分 ——
   * 这正是审计里那条「tr 只在 -dc '\000' 形态上失败 ⇒ UTF-16LE 密钥文件 rc=0」的成因。
   * 判据改成「非 NUL 字节数 == 总字节数」之后，形态失败会让左边变成 0，与右边不等 ⇒ 拒绝。
   */
  describe('tr 只在 NUL 判据的形态上失败 ⇒ mongo_hydrate_uri 仍必须拒绝 UTF-16 文件', () => {
    // 第四轮起新增 stubs：{ tr, wc, stat, grep } 逐名覆盖；**先清掉上一轮留下的同名桩**，
    // 否则「上一条用例的桩还挂着」会让下一条在错误前提下变绿。
    const callHydrate = ({ trStub = '', stubs = {}, clean = false } = {}) => {
      const file = path.join(work.dir, clean ? 'secret-clean.txt' : 'secret-utf16.txt');
      // clean：干净的 UTF-8 单行文件（行数判据那类用例要用它，否则会在 NUL 闸就红、测不到目标腿）。
      fs.writeFileSync(file, clean ? `${URI_FILE}\n` : Buffer.from(`${URI_FILE}\n`, 'utf16le'));
      if (trStub) stubs = { ...stubs, tr: trStub };
      for (const name of ['tr', 'wc', 'stat', 'grep']) {
        const stubPath = path.join(work.bin, name);
        if (fs.existsSync(stubPath)) fs.rmSync(stubPath, { force: true });
      }
      for (const [name, body] of Object.entries(stubs)) {
        fs.writeFileSync(path.join(work.bin, name), body, { mode: 0o755 });
        try {
          fs.chmodSync(path.join(work.bin, name), 0o755);
        } catch (_) {
          /* Windows 上 mode 参数已足够 */
        }
      }
      const cmd = `PATH='${posix(work.bin)}:/usr/bin:/bin'; export PATH; . "$1"; MONGODB_URI='' MONGODB_URI_FILE="$2"; mongo_hydrate_uri; printf 'rc=%s' "$?"`;
      const r = spawnSync(
        'bash',
        ['-c', cmd, '_', sh(path.join(ROOT, 'scripts/mongoUri.sh')), sh(file)],
        {
          cwd: ROOT,
          encoding: 'utf8',
          timeout: 30000,
        }
      );
      return { code: r.status, out: `${r.stdout || ''}${r.stderr || ''}` };
    };

    test('反向对照：真 tr 下同一份 UTF-16 夹具必须拒绝（红不能来自夹具本身）', () => {
      const r = callHydrate();
      expect(r.out).toContain('rc=1');
      expect(r.out).toMatch(/含 NUL 字节/);
    });

    test('桩只在「非 NUL 计数」那一形态上失败 ⇒ 仍然拒绝（修复前实测 rc=0、值被静默改写）', () => {
      const stub = [
        '#!/bin/sh',
        'case "$*" in *"001-"*) echo "tr: illegal set" >&2; exit 1 ;; esac',
        'exec /usr/bin/tr "$@"',
        '',
      ].join('\n');

      const r = callHydrate({ trStub: stub });
      expect(r.out).toContain('rc=1');
      expect(r.out).toMatch(/含 NUL 字节|字节检查未能完成/);
    });

    /**
     * 第四轮审计（2026-10-30）在 hydrate 侧也踩到了同一族的三条腿：
     *   · wc 静默 0 ⇒ 两个计数都是 0 ⇒ 相等 ⇒ UTF-16 文件被吃成值；由 stat 交叉拦住；
     *   · stat 本身不可用 ⇒ 「能不能检测」这件事必须先答，答不出来就拒；
     *   · tr 退化成 cat ⇒ 自检常量对不上；
     *   · wc 与 stat 同时说 0 而文件非空 ⇒ 由 shell 内建 `[ -s ]` 的自相矛盾拦住；
     *   · grep -c 静默空输出 ⇒ 行数判据取假分支被跳过（两行密钥文件只取第一行）⇒ 形状校验拦住。
     */
    test('wc 一律打印 0（stat 是真的）⇒ 必须拒绝：绝不按「检测不到」继续', () => {
      // 桩让每一次 wc 都说 0（这正是第四轮审计造的形态）：0 是合法数字，形状校验拦不住，
      // 靠 stat 的独立长度交叉拦下（它排在互补计数之前，所以理由必须是「两者不一致」）。
      const r = callHydrate({ stubs: { wc: '#!/bin/sh\nprintf "0\\n"\n' } });
      expect(r.out).toContain('rc=1');
      expect(r.out).toMatch(/两者不一致/);
    });

    test('stat 不可用 ⇒ 必须拒绝（不能拿「工具在不在」当「这一次判得出来」）', () => {
      const r = callHydrate({ stubs: { stat: '#!/bin/sh\nexit 1\n' } });
      expect(r.out).toContain('rc=1');
      expect(r.out).toMatch(/stat 不可用/);
    });

    test('tr 退化成 cat ⇒ 必须拒绝（互补计数之和 ≠ 总字节数）', () => {
      const r = callHydrate({ stubs: { tr: '#!/bin/sh\nexec cat\n' } });
      expect(r.out).toContain('rc=1');
      expect(r.out).toMatch(/tr 没有按判据过滤字节/);
    });

    test('tr 吃掉一切（退出 0、无输出）⇒ 必须拒绝（不是「没有 NUL」）', () => {
      // 判据是「NUL 字节数 == 0」，工具吃掉一切时它同样是 0 —— 只有互补计数之和那条腿看得见。
      const eat = [
        '#!/bin/sh',
        'case "$*" in *-cd*) /usr/bin/cat > /dev/null; exit 0 ;; esac',
        'exec /usr/bin/tr "$@"',
        '',
      ].join('\n');
      const r = callHydrate({ stubs: { tr: eat }, clean: true });
      expect(r.out).toContain('rc=1');
      expect(r.out).toMatch(/tr 没有按判据过滤字节/);
    });

    test('内容相关退化的 tr（短输入正常、真实文件透传）+ UTF-16 文件 ⇒ 必须拒绝（第四轮复攻的原始形态）', () => {
      // 审计实测：那一版能把 UTF-16 密钥文件吃成「字形相同」的连接串并 rc=0。
      const scratch = posix(path.join(work.bin, 'tr.in'));
      const stub = [
        '#!/bin/sh',
        `_d='${scratch}'`,
        '/usr/bin/cat > "$_d"',
        'if [ "$(/usr/bin/wc -c < "$_d" | /usr/bin/tr -d " ")" -le 12 ]; then',
        '  exec /usr/bin/tr "$@" < "$_d"',
        'fi',
        'exec /usr/bin/cat < "$_d"',
        '',
      ].join('\n');
      const r = callHydrate({ stubs: { tr: stub } });
      expect(r.out).toContain('rc=1');
      // 同上：dash 桩保真度漂移 ⇒ 放宽到"未能完成"族（兄弟用例 ：851 同款口径）
      expect(r.out).toMatch(/tr 没有按判据过滤字节|含 NUL 字节|字节检查未能完成/);
    });

    test('wc 与 stat 同时说 0、而文件非空 ⇒ 由内建 `[ -s ]` 的自相矛盾拦住', () => {
      const r = callHydrate({
        stubs: { wc: '#!/bin/sh\nprintf "0\\n"\n', stat: '#!/bin/sh\nprintf "0\\n"\n' },
      });
      expect(r.out).toContain('rc=1');
      expect(r.out).toMatch(/计数为 0 但文件非空/);
    });

    test('grep -c 静默空输出（退出 0）⇒ 行数判据必须判「不可用」而不是被跳过', () => {
      const grepStub = [
        '#!/bin/sh',
        'case "$*" in *"-c"*) exit 0 ;; esac',
        'exec /usr/bin/grep "$@"',
        '',
      ].join('\n');
      const r = callHydrate({ stubs: { grep: grepStub }, clean: true });
      expect(r.out).toContain('rc=1');
      expect(r.out).toMatch(/行数判据不可用/);
    });
  });
});
