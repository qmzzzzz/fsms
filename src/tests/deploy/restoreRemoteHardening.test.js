/**
 * restore-mongo.sh 的 docker 传输：容器侧命令真的被执行一次（2026-10-04 审计复跑）
 *
 * 【为什么单开一个文件】既有的 docker 传输门禁（`src/tests/deploy/restoreTransport.test.js`）
 * 把 `docker` 桩成"记录 argv 与 stdin 就退出"——那是对的粒度，它判的是凭据不落宿主盘、
 * `--drop` 两侧一致。代价是**容器里那段 `sh -c "$REMOTE_CMD"` 从来没被执行过**，
 * 于是它的三条缺陷谁都不判：
 *   ① 容器侧两个临时文件写死名字（`/tmp/.mongorestore.cfg`、`/tmp/.mongorestore.archive`）：
 *      并发运行时后到的 `cat >` 会把前一份归档截断成自己的，"恢复"变成对半截别人的备份动手；
 *      写死的名字还能被容器内同 uid 的进程预先创建（`cat >` 原样跟随已存在的路径），
 *      于是恢复动作变成往 mongod 的数据文件里覆写字节；被 SIGKILL 的 run 会把含生产口令的
 *      cfg 留在容器 /tmp 里，名字可预测。
 *   ② `read` / `printf` / `cat` 三个写入步一句返回码都不判：管道断在宿主 `cat` 之前时，
 *      远端 `cat > arch` 依然是**成功**的（它拿到的是 EOF），mongorestore 于是对着一份
 *      0 字节归档工作并返回 0，脚本打印 "Restore completed successfully"——
 *      一次什么都没恢复的恢复演练就此记账为成功。备份侧早就写着"归档为 0 字节不是一次有效备份"。
 *   ③ 上面两条都没有失败信号，所以只有**把容器侧命令真跑一遍**的门禁才判得动。
 *
 * 本文件的 `docker` 桩不满足于记录：它把 `-c` 后面那段命令交回给 bash 执行，
 * stdin/stdout 沿用真实管道，容器内的 `mongorestore` 由 PATH 上的桩充当。
 * 因此下面所有断言都是"桩有没有被调用、拿到的是什么路径、canary 文件有没有被动过"，
 * 没有一条是 `expect(src).toMatch(…)` 的字符串匹配。
 *
 * 【前世版自证】每条正向断言都配一份"把脚本副本还原成修前形态"的对照：
 * 如果断言换了脚本副本仍然绿，它就是没有牙齿的装饰。
 */

'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync, execFileSync } = require('child_process');

const ROOT = path.resolve(__dirname, '../../..');
const RESTORE = path.join(ROOT, 'scripts/restore-mongo.sh');

const DB = 'fire_safety';
const URI = `mongodb://restore_user:Sup3rPw@127.0.0.1:27017/${DB}?authSource=admin`;
const PAYLOAD = 'FAKE-GZIP-ARCHIVE-PAYLOAD-BYTES';

// 修前形态写死的两个容器侧名字。canary 必须占**这两个**名字：本文件里所有"预测名字"
// 相关的断言，意义都建立在名字与脚本字面量一致上，下面有一条用例专门核对这一点。
const CANARY_CFG = '/tmp/.mongorestore.cfg';
const CANARY_ARCH = '/tmp/.mongorestore.archive';

/**
 * 修前形态的容器侧命令，逐字节抄自 `git show 2bebd20:scripts/restore-mongo.sh` 的
 * REMOTE_CMD（本文件用 `sh -c "$REMOTE_CMD"` 的原始字面量，不重新组织措辞）。
 *
 * 抄写时最容易丢的是 `\$_uri_line` 里那个反斜杠。丢了之后它变成宿主端的
 * `"$_uri_line"`——`_uri_line` 在宿主脚本里从未赋值，`set -u` 让脚本在**拼这条命令**
 * 时就非零退出，前世版用例于是以"脚本根本没跑到容器"的形式失败：那既不能证明固定名
 * 会被覆写，也不能证明 0 字节归档会被收下，整条自证退化成一条假绿（实测踩过，rc=1）。
 */
const LEGACY_RE =
  [
    'REMOTE_CMD="umask 077; IFS= read -r _uri_line; printf \'%s\\n\' \\"\\$_uri_line\\" > /tmp/.mongorestore.cfg;',
    'cat > /tmp/.mongorestore.archive;',
    'mongorestore --config=/tmp/.mongorestore.cfg --archive=/tmp/.mongorestore.archive --gzip ${DROP_ARG};',
    'rc=\\$?; rm -f /tmp/.mongorestore.cfg /tmp/.mongorestore.archive; exit \\$rc"',
  ].join('\n') + '\n';

const sh = (p) => String(p).replace(/\\/g, '/');

/** 在 MSYS/Linux 的 /tmp 里做事（容器侧路径写的是字面量 /tmp，跨环境只能同样用 bash 操作） */
const inTmp = (script, ...args) =>
  execFileSync('bash', ['-c', script, 'bash', ...args], {
    cwd: ROOT,
    encoding: 'utf8',
  });

/**
 * 读 /tmp 里的路径，不存在时返回哨兵而不是让 execFileSync 抛。
 * 修前形态在收尾时 `rm -f` 了那几个固定名，"被删掉"和"被改写"同样说明 canary 没保住；
 * 少了这个包装，前世版那一条会先以"cat 抛错"的形式失败，看不出是谁把文件弄没的。
 * 用 spawnSync 而不是 try/catch 包住 execFileSync：后者抛错时会把 `cat` 的 stderr
 * 原样喷到 jest 输出里，一屏 "No such file or directory" 正是让人学会忽略告警的写法。
 */
const readTmp = (p) => {
  const r = spawnSync('bash', ['-c', 'cat "$1" 2>/dev/null || printf "<MISSING>"', 'bash', p], {
    cwd: ROOT,
    encoding: 'utf8',
  });
  return r.stdout;
};

/** 预置两个 canary：占住的正是修前脚本写死的那两个名字（名字必须与脚本里的字面量一致） */
const plantCanaries = () =>
  inTmp('printf CANARY-CFG > "$1"; printf CANARY-ARCH > "$2"', CANARY_CFG, CANARY_ARCH);

const dropCanaries = () => inTmp('rm -f "$1" "$2"', CANARY_CFG, CANARY_ARCH);

function mkwork() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'restore-remote-'));
  const bin = path.join(dir, 'bin');
  fs.mkdirSync(bin);
  const backupDir = path.join(dir, 'backups');
  fs.mkdirSync(backupDir);
  const log = path.join(dir, 'calls.log');

  const write = (name, lines) => {
    const p = path.join(bin, name);
    fs.writeFileSync(p, `${lines.join('\n')}\n`, { mode: 0o755 });
    fs.chmodSync(p, 0o755);
  };

  // docker 桩：找到 `-c` 后面那个参数（就是脚本拼出来的容器侧命令），交回 bash 真执行。
  // stdin/stdout 不动手脚：宿主那侧 `printf uri; cat archive | … > 归档` 的管道形状原样保留。
  write('docker', [
    '#!/usr/bin/env bash',
    'echo "DOCKER $*" >> "$STUB_LOG"',
    'remote=""',
    'prev=""',
    'for a in "$@"; do',
    '  if [ "$prev" = "-c" ]; then remote="$a"; fi',
    '  prev="$a"',
    'done',
    '[ -n "$remote" ] || { echo "stub docker: 没有 sh -c 的远端命令" >&2; exit 9; }',
    'exec bash -c "$remote"',
  ]);
  // 容器内的 mongorestore：记下**自己拿到的参数**与归档内容，再成功退出。
  // 内容抄出来是因为远端在 mongorestore 之后就把临时文件删了，事后无从复核。
  write('mongorestore', [
    '#!/usr/bin/env bash',
    'echo "RESTORE $*" >> "$STUB_LOG"',
    'for a in "$@"; do',
    '  case "$a" in',
    '    --archive=*) echo "ARCHIVE-BODY: $(cat "${a#--archive=}")" >> "$STUB_LOG" ;;',
    '    --config=*)  echo "CONFIG-BODY: $(cat "${a#--config=}")" >> "$STUB_LOG" ;;',
    '  esac',
    'done',
    'exit 0',
  ]);

  const archive = path.join(backupDir, 'fire-safety-backup-t1.gz');
  fs.writeFileSync(archive, PAYLOAD);
  return { dir, bin, log, backupDir, archive };
}

function runRestore(work, script, env, target = work.archive) {
  const r = spawnSync('bash', [sh(script || RESTORE), sh(target)], {
    cwd: ROOT,
    encoding: 'utf8',
    timeout: 60000,
    env: {
      ...process.env,
      PATH: `${work.bin}${path.delimiter}${process.env.PATH}`,
      STUB_LOG: sh(work.log),
      MONGO_RESTORE_TRANSPORT: 'docker',
      MONGODB_URI: URI,
      RESTORE_CONFIRM: DB,
      ...env,
    },
  });
  if (r.error) {
    throw new Error(`本机找不到 bash，本闸无法执行：${r.error.message}`);
  }
  return {
    code: r.status,
    out: `${r.stdout || ''}${r.stderr || ''}`,
    calls: fs.existsSync(work.log) ? fs.readFileSync(work.log, 'utf8') : '',
  };
}

/** 与 scripts/backupCrypto.sh 的 crypto_checksum 同一形态：真 sha256sum 写 sidecar */
const sign = (target) => inTmp(`sha256sum "$1" > "$1.sha256"`, sh(target));

/** 从桩日志里取 mongorestore 实际收到的容器侧路径 */
function pathsIn(calls) {
  const grab = (flag) =>
    [...calls.matchAll(new RegExp(`RESTORE .*${flag}=([^ ]+)`, 'g'))].map((m) => m[1]);
  return { cfg: grab('--config'), arch: grab('--archive') };
}

describe('restore-mongo.sh 容器侧：路径不可预测、写入有返回码、空归档不算恢复', () => {
  let work;
  beforeEach(() => {
    work = mkwork();
    sign(work.archive);
  });
  afterEach(() => {
    fs.rmSync(work.dir, { recursive: true, force: true });
  });

  test('前提自证：docker 桩确实把容器侧命令跑起来了（mongorestore 拿到 uri 行与归档字节）', () => {
    const r = runRestore(work);
    expect(r.code).toBe(0);
    expect(r.calls).toMatch(/DOCKER .*exec -T mongo sh -c/);
    expect(r.calls).toMatch(/RESTORE --config=/);
    // 这两条是本文件所有断言的地基：容器侧命令没被执行的话，下面每一条都是白给的绿
    expect(r.calls).toContain(
      `CONFIG-BODY: uri: mongodb://restore_user:Sup3rPw@127.0.0.1:27017/${DB}`
    );
    expect(r.calls).toContain(`ARCHIVE-BODY: ${PAYLOAD}`);
  });

  test('① 容器侧两个路径都是 mktemp 产物，且不等于那两个写死的名字', () => {
    const r = runRestore(work);
    expect(r.code).toBe(0);
    const { cfg, arch } = pathsIn(r.calls);
    expect(cfg).toHaveLength(1);
    expect(arch).toHaveLength(1);
    expect(cfg[0]).not.toBe('/tmp/.mongorestore.cfg');
    expect(arch[0]).not.toBe('/tmp/.mongorestore.archive');
    expect(cfg[0]).toMatch(/\.mongorestore-cfg\.[A-Za-z0-9]{6}$/);
    expect(arch[0]).toMatch(/\.mongorestore-arc\.[A-Za-z0-9]{6}$/);
  });

  test('① 两次运行的路径互不相同（固定名在并发下会互相截断归档）', () => {
    const a = runRestore(work);
    fs.rmSync(work.log);
    const b = runRestore(work);
    expect(a.code).toBe(0);
    expect(b.code).toBe(0);
    const pa = pathsIn(a.calls);
    const pb = pathsIn(b.calls);
    expect(pa.cfg).not.toEqual(pb.cfg);
    expect(pa.arch).not.toEqual(pb.arch);
  });

  test('① 写在预测名字上的 canary 文件一动不动（不再跟随预创建路径）', () => {
    // 修前形态：`cat > /tmp/.mongorestore.cfg` 会原样写入（并跟随同名符号链接），
    // 所以"预先占住这个名字"是一条真实可利用的路径。canary 用 bash 建，因为它在 /tmp 里。
    plantCanaries();
    try {
      const r = runRestore(work);
      expect(r.code).toBe(0);
      expect(readTmp(CANARY_CFG)).toBe('CANARY-CFG');
      expect(readTmp(CANARY_ARCH)).toBe('CANARY-ARCH');
      // 反面自证：canary 之所以能证明"不跟随预创建路径"，前提是它占的名字**就是**
      // 修前脚本写死的那两个。名字哪天漂了，这条会静默变成"什么都没判"的绿。
      expect(LEGACY_RE).toContain(CANARY_CFG);
      expect(LEGACY_RE).toContain(CANARY_ARCH);
    } finally {
      dropCanaries();
    }
  });

  test('②③ 0 字节归档（sidecar 也配得上）⇒ 非零退出，mongorestore 一次都不被调用', () => {
    // 这是最阴的一种：宿主 `cat` 拿不到内容但**成功**（EOF），远端 cat > arch 也成功，
    // 于是一份空文件走完整条链路，脚本打印 "Restore completed successfully"。
    // 备份侧早就规定"归档为 0 字节不是一次有效备份"，恢复侧收下它等于把没做过的事记成做过。
    const empty = path.join(work.backupDir, 'fire-safety-backup-empty.gz');
    fs.writeFileSync(empty, '');
    sign(empty);
    const r = runRestore(work, null, {}, empty);
    expect(r.out).toMatch(/0 字节/);
    expect(r.code).not.toBe(0);
    expect(r.out).not.toMatch(/Restore completed successfully/);
    // 关键：不是"报了个错"，而是**根本没碰 mongorestore**
    expect(r.calls).not.toMatch(/RESTORE --config=/);
  });

  test('② 空 stdin（宿主连 uri 行都没送出去）⇒ 远端在读这一步就停手', () => {
    // 单独驱动远端命令：把 REMOTE_CMD 从脚本里抠出来喂 /dev/null，判的是"read 的返回码
    // 有没有被检查"。这条不依赖真实 docker，也不依赖宿主那半条管道。
    const src = fs.readFileSync(RESTORE, 'utf8');
    const m = src.match(/REMOTE_CMD="([\s\S]*?)"\n/);
    expect(m).not.toBeNull();
    // 只还原 `\"` 与 `\$` 两种转义：`%s\n` 里的那个反斜杠必须原样留着（printf 的格式串
    // 要靠它输出换行），把它替成真换行等于改了被测脚本的语义。
    const remote = m[1].replace(/\\"/g, '"').replace(/\\\$/g, '$');
    const before = inTmp('ls /tmp/.mongorestore-cfg.* /tmp/.mongorestore-arc.* 2>/dev/null | sort');
    const r = spawnSync('bash', ['-c', remote], {
      cwd: ROOT,
      encoding: 'utf8',
      input: '',
      env: {
        ...process.env,
        STUB_LOG: sh(work.log),
        PATH: `${work.bin}${path.delimiter}${process.env.PATH}`,
      },
    });
    expect(r.status).not.toBe(0);
    expect(fs.existsSync(work.log) ? fs.readFileSync(work.log, 'utf8') : '').not.toMatch(
      /RESTORE --config=/
    );
    // 停手时不能把 mktemp 的文件留在容器 /tmp：那是含凭据的落点。
    // 比"目录里一个都没有"强的是**增量**——并行跑的别的用例可能正留着文件。
    const after = inTmp('ls /tmp/.mongorestore-cfg.* /tmp/.mongorestore-arc.* 2>/dev/null | sort');
    expect(after).toBe(before);
  });

  test('前世版自证：固定名 + 不判返回码的版本会让上面几条全线翻转', () => {
    const src = fs.readFileSync(RESTORE, 'utf8');
    // 用函数形式做替换：字符串形式会把 `$&`、`` $` ``、`$'` 当作特殊序列，
    // 而这段内容里全是 shell 的 `$`，不该让 String.replace 参与它的转义语义。
    const legacy = src.replace(/REMOTE_CMD="[\s\S]*?"\n/, () => LEGACY_RE);
    expect(legacy).not.toBe(src);
    expect(legacy).toContain(CANARY_CFG);
    expect(legacy).toContain(CANARY_ARCH);
    const dir = path.join(work.dir, 'legacy');
    fs.mkdirSync(dir, { recursive: true });
    for (const f of ['mongoUri.sh', 'backupCrypto.sh']) {
      fs.copyFileSync(path.join(ROOT, 'scripts', f), path.join(dir, f));
    }
    const p = path.join(dir, 'restore-mongo.sh');
    fs.writeFileSync(p, legacy);
    expect(execFileSync('bash', ['-n', sh(p)], { encoding: 'utf8' })).toBe('');

    plantCanaries();
    try {
      const r = runRestore(work, p);
      // 前提自证：抄回来的旧命令必须**跑得通**。若它在宿主就非零退出，下面所有"翻转"
      // 都成了"脚本挂了"的功劳，一条也证明不了（见 LEGACY_RE 上那段关于 `\$_uri_line` 的话）。
      expect(r.code).toBe(0);
      expect(r.out).toMatch(/Restore completed successfully/);
      // 修前形态 1：写死的名字被覆盖——"预创建同名文件"这条利用路径成立
      expect(r.calls).toMatch(/RESTORE --config=\/tmp\/\.mongorestore\.cfg/);
      expect(readTmp(CANARY_CFG)).not.toBe('CANARY-CFG');
      expect(readTmp(CANARY_ARCH)).not.toBe('CANARY-ARCH');

      // 修前形态 2：0 字节归档一路走到 mongorestore，还宣布恢复完成
      const empty = path.join(work.backupDir, 'legacy-empty.gz');
      fs.writeFileSync(empty, '');
      sign(empty);
      plantCanaries();
      fs.rmSync(work.log, { force: true });
      const re = runRestore(work, p, {}, empty);
      expect(re.code).toBe(0);
      expect(re.out).toMatch(/Restore completed successfully/);
      // 桩抄出来的归档内容是**空的**：canary 那 10 个字节被 `cat >` 截掉，
      // mongorestore 对着 0 字节返回 0，一次什么都没做的恢复就此被记成成功恢复。
      expect(re.calls).toMatch(/^ARCHIVE-BODY: *$/m);
    } finally {
      dropCanaries();
    }
  });
});
