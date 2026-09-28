/**
 * 备份步的执行位置与凭据通道（scripts/backup-mongo.sh）
 *
 * 为什么值得专门测：部署编排把"发布前先全量备份"当成回滚资格的前提，
 * 而 compose 里的 mongo 只 `expose` 不 `publish`，secrets/mongodb_uri 的主机名
 * 又是容器网内的服务名 —— 宿主机上直接 mongodump 必然连不上，
 * 于是**每一次真实发布都稳定死在备份步**（或者被 --skip-backup 绕过，
 * 顺带失去自动回滚能力）。这类缺陷在 CI 里看不见：CI 没有部署机，也没有 docker。
 *
 * 本文件用桩 docker/mongodump 把两条传输路径都跑成真进程：
 * 断言的是"命令到底在哪个环境执行、URI 被改写成了什么、凭据有没有落到 argv 上"，
 * 而不是脚本文本里有没有某个字符串。
 */

'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const ROOT = path.resolve(__dirname, '../../..');
const SCRIPT = path.join(ROOT, 'scripts/backup-mongo.sh');
const URI = 'mongodb://fsms:Sup3r%21Secret@mongo:27017/fire-safety?authSource=admin';
const FAKE_ARCHIVE_BYTES = Buffer.from('FAKE-GZIP-ARCHIVE-PAYLOAD');

function makeWorkspace() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'backup-transport-'));
  const bin = path.join(dir, 'bin');
  fs.mkdirSync(bin);
  const work = { dir, bin, backupDir: path.join(dir, 'backups') };

  // 桩 docker：把 argv 记下来，把 stdin（容器内配置文件）记下来，
  // 再往 stdout 写一段"归档字节"——归档经 stdout 流回宿主正是 docker 传输的设计点。
  const dockerStub = [
    '#!/usr/bin/env bash',
    'printf "%s\\n" "$@" > "$DOCKER_ARGV_FILE"',
    'cat > "$DOCKER_STDIN_FILE"',
    'printf "docker-stderr-noise\\n" >&2',
    // DOCKER_STUB_EXIT 让"命令跑挂了"这一格可被确定性复现：真 docker 的失败原因
    // 在 CI 与本机之间不可控，桩的退出码可控
    'if [ "${DOCKER_STUB_EXIT:-0}" != "0" ]; then exit "$DOCKER_STUB_EXIT"; fi',
    `printf '${FAKE_ARCHIVE_BYTES.toString()}'`,
    '',
  ].join('\n');
  const mongodumpStub = [
    '#!/usr/bin/env bash',
    'printf "%s\\n" "$@" > "$MONGODUMP_ARGV_FILE"',
    'for arg in "$@"; do',
    '  case "$arg" in',
    '    --config=*) cfg="${arg#--config=}"; cat "$cfg" > "$MONGODUMP_CFG_FILE";;',
    '    --archive=*) out="${arg#--archive=}"; printf \'MONGODUMP-LOCAL\' > "$out";;',
    '  esac',
    'done',
    'exit 0',
    '',
  ].join('\n');

  fs.writeFileSync(path.join(bin, 'docker'), dockerStub, { mode: 0o755 });
  fs.writeFileSync(path.join(bin, 'mongodump'), mongodumpStub, { mode: 0o755 });
  // Git Bash/Windows 下 mode 可能被忽略，显式 chmod 一次（Linux 上同样是必需的）
  fs.chmodSync(path.join(bin, 'docker'), 0o755);
  fs.chmodSync(path.join(bin, 'mongodump'), 0o755);
  return work;
}

function runBackup(work, env = {}) {
  const files = {
    DOCKER_ARGV_FILE: path.join(work.dir, 'docker.argv'),
    DOCKER_STDIN_FILE: path.join(work.dir, 'docker.stdin'),
    MONGODUMP_ARGV_FILE: path.join(work.dir, 'mongodump.argv'),
    MONGODUMP_CFG_FILE: path.join(work.dir, 'mongodump.cfg'),
  };
  const r = spawnSync('bash', [SCRIPT, work.backupDir], {
    cwd: ROOT,
    encoding: 'utf8',
    env: {
      ...process.env,
      PATH: `${work.bin}${path.delimiter}${process.env.PATH}`,
      BACKUP_RETENTION_DAYS: '30',
      MONGODB_URI: URI,
      ...files,
      ...env,
    },
  });
  const read = (p) => (fs.existsSync(p) ? fs.readFileSync(p, 'utf8') : '');
  return { code: r.status, out: `${r.stdout || ''}${r.stderr || ''}`, files, read };
}

const archivesOf = (work) =>
  fs.existsSync(work.backupDir)
    ? fs.readdirSync(work.backupDir).filter((f) => f.endsWith('.gz'))
    : [];

describe('backup-mongo.sh 传输路径', () => {
  test('docker 传输（默认）：mongodump 在容器内跑，归档从 stdout 流回宿主文件', () => {
    const work = makeWorkspace();
    const r = runBackup(work);
    expect(r.code).toBe(0);

    const argv = r.read(r.files.DOCKER_ARGV_FILE);
    expect(argv).toContain('compose');
    expect(argv).toMatch(/exec/);
    expect(argv).toMatch(/-T/);
    expect(argv).toContain('mongo'); // 服务名
    expect(argv).not.toContain('mongodb://'); // 凭据不在 argv 上（P2-27）

    const cfg = r.read(r.files.DOCKER_STDIN_FILE);
    expect(cfg).toContain('uri: mongodb://');
    expect(cfg).toContain('127.0.0.1:27017'); // 主机段已换成容器内地址
    expect(cfg).not.toContain('@mongo:27017');
    expect(cfg).toContain('fire-safety'); // 库名保留
    expect(cfg).toContain('authSource=admin'); // 查询参数保留

    const archives = archivesOf(work);
    expect(archives).toHaveLength(1);
    const bytes = fs.readFileSync(path.join(work.backupDir, archives[0]));
    expect(bytes.toString()).toBe(FAKE_ARCHIVE_BYTES.toString());

    // 宿主机不该再有第二次直连执行
    expect(r.read(r.files.MONGODUMP_ARGV_FILE)).toBe('');
  });

  test('COMPOSE_FILE 被透传给 docker compose（否则 exec 会命中同名另一个项目）', () => {
    const work = makeWorkspace();
    const composeFile = path.join(work.dir, 'docker-compose.yml');
    fs.writeFileSync(composeFile, 'services: {}\n', 'utf8');
    const r = runBackup(work, { COMPOSE_FILE: composeFile });
    expect(r.code).toBe(0);
    const argv = r.read(r.files.DOCKER_ARGV_FILE);
    expect(argv).toContain('-f');
    expect(argv).toContain(composeFile);
  });

  test('local 传输：宿主机 mongodump 用 --config 读凭据，URI 不出现在 argv', () => {
    const work = makeWorkspace();
    const r = runBackup(work, { MONGO_BACKUP_TRANSPORT: 'local' });
    expect(r.code).toBe(0);
    expect(r.read(r.files.DOCKER_ARGV_FILE)).toBe(''); // 没走 docker

    const argv = r.read(r.files.MONGODUMP_ARGV_FILE);
    expect(argv).toContain('--config=');
    expect(argv).toContain('--gzip');
    expect(argv).not.toContain('Sup3r'); // 口令不在命令行
    expect(argv).not.toContain('mongodb://');

    const cfg = r.read(r.files.MONGODUMP_CFG_FILE);
    expect(cfg).toContain('uri: mongodb://');
    expect(cfg).toContain('@mongo:27017'); // local 模式不改写主机（宿主可达时才用）
  });

  test('传输值写错 ⇒ 非零退出，且不产生任何归档（不得"看起来成功了"）', () => {
    const work = makeWorkspace();
    const r = runBackup(work, { MONGO_BACKUP_TRANSPORT: 'podman' });
    expect(r.code).not.toBe(0);
    expect(r.out).toMatch(/MONGO_BACKUP_TRANSPORT/);
    expect(archivesOf(work)).toEqual([]);
  });

  test('备份命令非零退出 ⇒ 整体失败且不留归档（"有文件但没备成"是最坏形态）', () => {
    const work = makeWorkspace();
    const r = runBackup(work, { DOCKER_STUB_EXIT: '1' });
    expect(r.code).not.toBe(0);
    expect(archivesOf(work)).toEqual([]);
  });

  test('归档为 0 字节 ⇒ 判失败（mongodump 退出码 0 不等于备份成功）', () => {
    const work = makeWorkspace();
    // 覆写 docker 桩：成功退出但 stdout 什么都不写
    fs.writeFileSync(
      path.join(work.bin, 'docker'),
      [
        '#!/usr/bin/env bash',
        'printf "%s\\n" "$@" > "$DOCKER_ARGV_FILE"',
        'cat > /dev/null',
        'exit 0',
        '',
      ].join('\n'),
      { mode: 0o755 }
    );
    fs.chmodSync(path.join(work.bin, 'docker'), 0o755);
    const r = runBackup(work);
    expect(r.code).not.toBe(0);
    expect(r.out).toMatch(/0 字节|不是一次有效备份/);
  });

  test('容器内配置文件用完即删：脚本里的清理语句是硬要求（凭据不能留在容器 fs）', () => {
    const source = fs.readFileSync(SCRIPT, 'utf8');
    // 这一条确实是文本断言（它测的是脚本自己），保留的理由：清理动作发生在容器内，
    // 桩 docker 无法证明"真 mongodump 跑完后文件被删"，只能锁住意图不被删改。
    expect(source).toMatch(/rm -f "\$cfg"/);
  });
});
