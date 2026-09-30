/**
 * scripts/backup-mongo.sh 的行为回归
 *
 * 为什么必须"真跑"而不是扫源码：既有 `src/tests/middleware/infraParamRateLimitFailClosed.test.js`
 * 对这两个 shell 脚本的全部覆盖是 readScript + 正则（文本契约）。它能证明
 * "字面量还在文件里"，证明不了：
 *   - `|| true` 正在吞掉一次真实的清理失败；
 *   - mongodump 退出 0 但归档是 0 字节时脚本会不会报成功（会——这就是"看起来有备份"）；
 *   - 同一分钟内两次备份会不会互相覆盖（会，--archive 是覆盖写）；
 *   - 清理是否**真的**在删过期文件（|| true 下即使一条都没删也全绿）。
 * 本次改动四条全部由这些用例兜住。
 *
 * 做法：往 PATH 前面插一个 stub `mongodump`，把它的完整 argv 记到日志，
 * 并按 STUB_MODE 决定归档写成什么形态。被测脚本不知道命令被接管。
 * 平台前提：需要 POSIX bash（CI 是 ubuntu；本机走 Git Bash）。探测不到时
 * 整组用例显式跳过并打印原因——不静默算通过。
 */

'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const ROOT = path.resolve(__dirname, '../..');
const SCRIPT = path.join(ROOT, 'scripts', 'backup-mongo.sh');

function findBash() {
  for (const c of ['/bin/bash', 'bash', 'C:/Program Files/Git/bin/bash.exe']) {
    const r = spawnSync(c, ['--version'], { encoding: 'utf8' });
    if (!r.error && r.status === 0) return c;
  }
  return null;
}
const BASH = findBash();
if (!BASH)
  console.warn('[跳过] 未找到 bash：backup-mongo.sh 的行为用例在本平台无法执行（CI ubuntu 会跑）');

const group = BASH ? describe : describe.skip;

const STUB = `#!/bin/bash
echo "$@" >> "$STUB_LOG"
ARCH=""
for a in "$@"; do
  case "$a" in --archive=*) ARCH="\${a#--archive=}";; esac
done
case "$STUB_MODE" in
  ok)    printf 'GZIPBYTES-GZIPBYTES-GZIPBYTES' > "$ARCH" ;;
  empty) : > "$ARCH" ;;
  noop)  exit 0 ;;
esac
exit 0
`;

const tracked = [];
afterAll(() => {
  for (const d of tracked) fs.rmSync(d, { recursive: true, force: true });
});

/** 一次隔离演练：stub PATH + 命令日志 + 临时备份目录 */
function stage(mode) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bakscript-'));
  tracked.push(dir);
  const bin = path.join(dir, 'bin');
  fs.mkdirSync(bin);
  const stubPath = path.join(bin, 'mongodump');
  fs.writeFileSync(stubPath, STUB, { mode: 0o755 });
  try {
    fs.chmodSync(stubPath, 0o755);
  } catch (_) {
    /* Windows 上是空操作，MSYS 由 mode 参数处理 */
  }
  const backups = path.join(dir, 'backups');
  return {
    dir,
    backups,
    log: path.join(dir, 'argv.log'),
    mode: mode || 'ok',
  };
}

function run(st, { retention, uri = 'mongodb://user:sup3rs3cr3t@db:27017/fire_safety_db' } = {}) {
  const env = {
    ...process.env,
    PATH: `${path.join(st.dir, 'bin')}${path.delimiter}${process.env.PATH}`,
    STUB_LOG: st.log,
    STUB_MODE: st.mode,
    // 本文件测的是"宿主机直接跑 mongodump"这条路径的全部判据（凭据只经 --config、
    // 归档非空、同名拒覆盖、过期清理…），因此显式声明传输方式：
    // 脚本的默认值现在是 docker（部署机上 mongo 只 expose 不 publish，宿主直连必挂），
    // 不写这一行的话下面的 mongodump 桩根本不会被调用，7 条用例会一起变红。
    // docker 传输那一支由 src/tests/deploy/backupTransport.test.js 覆盖。
    MONGO_BACKUP_TRANSPORT: 'local',
    // 本文件测的是门禁/保留期判据，不是加密（P1-①）——显式走明文确认出口，
    // 使归档产物保持在 ARCHIVE_PATH 原位供下方 archives 断言；默认 gpg 路径
    // 由 src/tests/deploy/backupEncryptionContract.test.js 覆盖。
    BACKUP_ENCRYPTION: 'plaintext-acknowledged',
    // 让 stub 写文件时用 POSIX 路径（Windows 上 fs 侧仍认这个路径）
    TMPDIR: st.dir,
  };
  if (uri) env.MONGODB_URI = uri;
  else delete env.MONGODB_URI; // 必须显式删：jest 引导链会给进程注入 MONGODB_URI，
  // 只"不设置"等于继承真值，用例测的就不是"缺失"这一支了（实测踩过）
  if (retention !== undefined) env.BACKUP_RETENTION_DAYS = retention;
  const r = spawnSync(BASH, [SCRIPT, st.backups], { env, encoding: 'utf8' });
  const argvLog = fs.existsSync(st.log) ? fs.readFileSync(st.log, 'utf8') : '';
  return {
    code: r.status,
    out: (r.stdout || '') + (r.stderr || ''),
    argv: argvLog.split(/\r?\n/).filter(Boolean),
    // 只数归档本体（.gz）：P1-① 后 backups/ 还会有 .sha256 校验和——
    // 各用例断言的是"归档份量"，把校验和算进去会每个数字都 +1 而红一遍
    archives: fs.existsSync(st.backups)
      ? fs.readdirSync(st.backups).filter((f) => f.endsWith('.gz'))
      : [],
  };
}

group('backup-mongo.sh 真跑行为', () => {
  test('缺 MONGODB_URI 即拒绝，且不留下备份目录之外的动作', () => {
    const st = stage('ok');
    const r = run(st, { uri: '' });
    expect(r.code).toBe(1);
    expect(r.out).toContain('MONGODB_URI');
    expect(r.argv.length).toBe(0); // 没调用过 mongodump
  });

  test('BACKUP_RETENTION_DAYS 非法 ⇒ 在调用 mongodump 之前就拒绝（旧写法会一路跑完并吞错）', () => {
    const st = stage('ok');
    const r = run(st, { retention: '30d' });
    expect(r.code).toBe(1);
    expect(r.out).toContain('BACKUP_RETENTION_DAYS');
    expect(r.out).toContain('正整数');
    // 关键顺序断言：拒绝必须早于任何对外调用，否则"校验"只是事后解释
    expect(r.argv.length).toBe(0);
    expect(r.out).not.toContain('Backup completed');
  });

  test('0 / 负数 / 非数字 / 纯空白都拒绝（等价于立刻删光全部备份或让清理静默失效）', () => {
    for (const bad of ['0', '-5', 'abc', ' ', '30d', '1e3']) {
      const st = stage('ok');
      const r = run(st, { retention: bad });
      expect({ bad, code: r.code, named: r.out.includes('BACKUP_RETENTION_DAYS') }).toEqual({
        bad,
        code: 1,
        named: true,
      });
      expect(r.argv.length).toBe(0); // 一律早于任何对外调用
    }
  });

  test('留空 = 未配置，按默认 30 走（这是文档化语义，不是被吞掉的错误）', () => {
    // 与上一条区分开：`${BACKUP_RETENTION_DAYS:-30}` 只在**未设置或空串**时取默认，
    // 所以空串合法、空格非法。混为一谈会把"运维忘填"和"运维填错"当成同一件事。
    const st = stage('ok');
    const r = run(st, { retention: '' });
    expect(r.code).toBe(0);
    expect(r.out).toContain('Pruning backups older than 30 days');
  });

  test('正常路径：只经 --config 传凭据、归档非空、凭据文件用完即删', () => {
    const st = stage('ok');
    const r = run(st, { retention: '30' });
    expect({ code: r.code, out: r.out.slice(-120) }).toMatchObject({ code: 0 });
    expect(r.out).toContain('Backup completed successfully');
    // 归档存在且**非空**（这条就是"确认备份文件非空"从人工步骤变成代码判据）
    expect(r.archives.length).toBe(1);
    const archive = path.join(st.backups, r.archives[0]);
    expect(fs.statSync(archive).size).toBeGreaterThan(0);
    expect(r.out).toMatch(/\(\d+ bytes\)/);

    // 凭据不上命令行
    expect(r.argv.length).toBe(1);
    expect(r.argv[0]).toContain('--config=');
    expect(r.argv[0]).not.toContain('sup3rs3cr3t');
    expect(r.argv[0]).not.toMatch(/--uri=/);
    // 凭据文件被 trap 清理：从 argv 里取出的路径跑完后必须不存在
    const cfg = /--config=(\S+)/.exec(r.argv[0])[1];
    expect(fs.existsSync(cfg)).toBe(false);
  });

  test('mongodump 退出 0 但没写出归档 ⇒ 判失败（"看起来成功"的备份最危险）', () => {
    const st = stage('noop');
    const r = run(st);
    expect(r.code).toBe(1);
    expect(r.out).toContain('归档不存在');
    expect(r.out).not.toContain('Backup completed successfully');
  });

  test('归档写成 0 字节 ⇒ 判失败且不报"完成"', () => {
    const st = stage('empty');
    const r = run(st);
    expect(r.code).toBe(1);
    expect(r.out).toContain('0 字节');
    expect(r.out).not.toContain('Backup size:');
  });

  test('目标归档已存在 ⇒ 拒绝覆盖（时间戳同名时不得静默吃掉上一份）', () => {
    const st = stage('ok');
    fs.mkdirSync(st.backups, { recursive: true });
    // 造一个必被本次时间戳命中的名字：先跑一次拿到真实文件名，再放回去当障碍
    const first = run(st);
    expect(first.code).toBe(0);
    expect(first.archives.length).toBe(1);
    // 同一秒内重复执行才会撞名——直接手工制造该状态（把归档改名为"下一次"的名字不可控，
    // 这里改用更强断言：把已存在的归档保留，再跑一次；若时间戳只到分钟，两次会同名 ⇒ 拒绝）
    const second = run(st);
    // 两次运行通常跨秒 ⇒ 第二次成功并新增一份；无论哪种，都不得**减少**已有备份
    expect(second.archives.length + 0).toBeGreaterThanOrEqual(1);
    expect(second.archives.length).toBeGreaterThanOrEqual(first.archives.length);
    if (second.code === 1) {
      expect(second.out).toContain('拒绝覆盖');
      expect(second.archives).toEqual(first.archives); // 拒绝时原文件仍在
    }
    // 反向自证：时间戳必须细到秒，否则同一分钟内的两次备份必然同名
    const names = fs
      .readdirSync(st.backups)
      .filter((f) => /^fire-safety-backup-.*\.gz$/.test(f))
      .map((f) => /^fire-safety-backup-(\d{8})-(\d{6})\.gz$/.exec(f)[2])
      .filter((t) => t.length === 6); // HHMMSS
    expect(names.length).toBeGreaterThanOrEqual(1);
  });

  test('同名归档存在时拒绝覆盖，且**不再调用** mongodump（用 stub date 制造确定性同名）', () => {
    // 光靠真实时间撞不进同一秒，故把 date 也接管掉：文件名完全可预测，
    // 于是"第二次运行必须拒绝"与"拒绝时不得已经覆盖写"都能确定性地断言。
    const st = stage('ok');
    const dateStub = path.join(st.dir, 'bin', 'date');
    fs.writeFileSync(dateStub, '#!/bin/bash\necho "20260101-120000"\n', { mode: 0o755 });
    try {
      fs.chmodSync(dateStub, 0o755);
    } catch (_) {
      /* see note on mongodump stub */
    }
    const first = run(st);
    expect(first.code).toBe(0);
    expect(first.archives).toEqual(['fire-safety-backup-20260101-120000.gz']);
    expect(first.argv.length).toBe(1);

    const second = run(st);
    expect(second.code).toBe(1);
    expect(second.out).toContain('拒绝覆盖');
    // 关键：拒绝必须发生在 mongodump 之前——否则"拒绝"只是事后通知，归档已被覆盖写坏
    expect(second.argv.length).toBe(1);
    expect(fs.statSync(path.join(st.backups, first.archives[0])).size).toBeGreaterThan(0);
  });

  test('过期备份真的被删除（|| true 版本即使一条没删也全绿）', () => {
    const st = stage('ok');
    fs.mkdirSync(st.backups, { recursive: true });
    const old = path.join(st.backups, 'fire-safety-backup-20200101-000000.gz');
    fs.writeFileSync(old, 'OLD');
    const stale = Date.now() - 100 * 24 * 3600 * 1000;
    fs.utimesSync(old, new Date(stale), new Date(stale));
    const keep = path.join(st.backups, 'fire-safety-backup-20990101-000000.gz');
    fs.writeFileSync(keep, 'NEW');

    const r = run(st, { retention: '30' });
    expect(r.code).toBe(0);
    expect(r.out).toContain('Pruning backups older than 30 days');
    expect(fs.existsSync(old)).toBe(false); // 100 天前的被清掉
    expect(fs.existsSync(keep)).toBe(true); // 30 天内的必须留下
    // 本次新产物也在
    expect(r.archives.length).toBeGreaterThanOrEqual(1);
  });
});
