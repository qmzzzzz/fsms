/**
 * 备份加密契约（P1-①，2026-09-30）
 *
 * deliverables/安全缺口核查-2026-09-30.md P1-①：备份归档（全量业务库，含 PII
 * 与审计集合）此前明文落盘、无校验和、无异地副本。修复后的契约：
 *   - 默认 gpg 非对称加密（BACKUP_ENCRYPTION=gpg）：备份宿主机只放公钥，
 *     私钥托管异地；唯一明文出口是 BACKUP_ENCRYPTION=plaintext-acknowledged，
 *     取值本身就是一句确认词；
 *   - 产物三件套：归档（.gz.gpg）+ 校验和（.sha256）+ 异地副本命令
 *     （BACKUP_OFFSITE_CMD，argv 解析不经 shell 展开，失败即整体失败）；
 *   - restore 按**后缀**识别 .gz.gpg 并自动解密（私钥侧），旧 .gz 原样支持。
 *
 * 判据分两层：
 *  - 结构层：脚本必须 source 共享实现（backupCrypto.sh）、必须声明默认加密、
 *    清理模式必须覆盖加密产物与校验和（漏掉校验和 = backups/ 单向膨胀）；
 *  - 行为层：用 **stub gpg**（PATH 注入，src→dst 的拷贝语义）真跑
 *    backupCrypto.sh 的 encrypt/checksum/decrypt 全链——验证文件落地位置、
 *    明文归档删除、校验和内容这些管道事实，而不是"源码里出现过某字符串"。
 *    真实 gpg 的密钥生成在 CI 上是熵池抽奖，不入门禁；gpg 调用形态由结构
 *    断言钉住（--batch --yes --output/--encrypt/--recipient 逐项在场）。
 */
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync, spawnSync } = require('child_process');

const ROOT = path.resolve(__dirname, '../../..');
const CRYPTO = path.join(ROOT, 'scripts/backupCrypto.sh');
const BACKUP = path.join(ROOT, 'scripts/backup-mongo.sh');
const RESTORE = path.join(ROOT, 'scripts/restore-mongo.sh');

const read = (p) => fs.readFileSync(p, 'utf8');

describe('备份加密契约（P1-①）', () => {
  test('三个脚本都能被 bash 解析（语法错误只会在真正要备份/恢复时才暴露）', () => {
    for (const p of [CRYPTO, BACKUP, RESTORE]) {
      expect(execFileSync('bash', ['-n', p], { encoding: 'utf8' })).toBe('');
    }
  });

  test('备份侧：加密是默认路径，明文出口必须显式确认词', () => {
    const src = read(BACKUP);
    // 可执行的一行 source（注释行不算数——纯文本判据拦不住"删掉调用"）
    expect(src).toMatch(/^[ \t]*\.[ \t]*".*backupCrypto\.sh.*$/m);
    // 默认值就是 gpg：忘配加密 = 硬失败，而不是静默明文
    expect(src).toContain('BACKUP_ENCRYPTION=${BACKUP_ENCRYPTION:-gpg}');
    // 明文出口必须逐字确认；裸 "none"/"off" 一律非法（case 分支只认这两个值）
    expect(src).toContain('plaintext-acknowledged)');
    expect(src).not.toMatch(/BACKUP_ENCRYPTION=\\?\$?\{?[^}\n]*none/);
    // gpg 调用形态（共享实现里逐项在场）：非交互 + 输出 + 收件人
    const crypto = read(CRYPTO);
    expect(crypto).toContain('--batch --yes');
    expect(crypto).toContain('--encrypt --recipient');
    expect(crypto).toContain('BACKUP_GPG_RECIPIENT');
    // 明文归档必须在加密成功后删除（留着 = 缺口原样存在）
    expect(src).toMatch(/rm -f "\$ARCHIVE_PATH"/);
  });

  test('清理模式覆盖 .gz / .gz.gpg / .sha256 三种产物（漏一种 = 单向膨胀）', () => {
    const src = read(BACKUP);
    expect(src).toContain('fire-safety-backup-*.gz"');
    expect(src).toContain('fire-safety-backup-*.gz.gpg');
    expect(src).toContain('fire-safety-backup-*.sha256');
  });

  test('备份侧：umask 077 必须覆盖整个产物写入窗口（还原点只能落在 cleanup 里）', () => {
    // 为什么是位置判据而不是"跑一遍看权限位"：Git Bash/MSYS 下 NTFS 不承载 POSIX
    // 权限位，chmod/umask 都是空操作、stat 恒报 644（该文件自己的注释已记录），
    // 本机跑出来的模式没有信息量。这条闸钉的是"收紧的作用域"这一事实本身。
    // 修复前实测：umask 在凭据临时文件建好后立刻还原，于是 mongodump 的归档
    // （全量业务库明文）与随后的 .gpg/.sha256 都落在调用方 umask 022 上 = 0644。
    const src = read(BACKUP);
    const restrict = src.search(/^[ \t]*umask 077$/m);
    const dump = src.indexOf('mongodump --config=');
    const encrypt = src.indexOf('crypto_encrypt ');
    expect(restrict).toBeGreaterThan(-1);
    expect(dump).toBeGreaterThan(-1);
    expect(encrypt).toBeGreaterThan(-1);
    expect(restrict).toBeLessThan(dump); // 收紧必须早于第一次产物写入

    const cleanupMatch = src.match(/cleanup\(\)\s*\{[\s\S]*?\n\}/);
    expect(cleanupMatch).not.toBeNull();
    // 还原语句必须在 cleanup 体内（trap EXIT INT TERM ⇒ 任何退出路径都还原）
    expect(cleanupMatch[0]).toMatch(/umask "\$OLD_UMASK"/);
    // 且**只**在那里：cleanup 之外再出现一次还原，就是提前放开作用域
    expect(src.replace(cleanupMatch[0], '')).not.toMatch(/umask "\$OLD_UMASK"/);
  });

  test('异地副本：BACKUP_OFFSITE_CMD 以 argv 解析执行，不经 shell 展开', () => {
    const src = read(BACKUP);
    expect(src).toContain('read -r -a OFFSITE_ARGS');
    // 注入面收口的反证：不得出现 bash -c / sh -c 执行该值的形态
    expect(src).not.toMatch(/bash -c "\$BACKUP_OFFSITE_CMD"|sh -c "\$BACKUP_OFFSITE_CMD"/);
    expect(src).toMatch(/if ! "\$\{OFFSITE_ARGS\[@\]}"/);
  });

  test('恢复侧：按后缀识别加密归档并解密，明文旧归档原样支持', () => {
    const src = read(RESTORE);
    expect(src).toMatch(/^[ \t]*\.[ \t]*".*backupCrypto\.sh.*$/m);
    expect(src).toContain('*.gz.gpg)');
    expect(src).toContain('*.gz)');
    // 解密产物是 0600 临时文件且进 trap 清理（凭据级字段同款纪律）
    expect(src).toMatch(/mongorestore-decrypted\./);
    expect(src.indexOf('DECRYPTED_FILE=""')).toBeGreaterThan(-1);
    expect(src).toMatch(/rm -f "\$DECRYPTED_FILE"/);
  });

  describe('backupCrypto.sh 行为链（stub gpg，真跑文件管道）', () => {
    let tmpDir;
    let stubDir;

    const runCrypto = (script, env = {}) => {
      const stdout = execFileSync('bash', ['-c', script], {
        encoding: 'utf8',
        cwd: ROOT,
        env: { ...process.env, ...env },
      });
      return stdout.trim();
    };

    beforeEach(() => {
      tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'backup-crypto-'));
      stubDir = path.join(tmpDir, 'bin');
      fs.mkdirSync(stubDir);
      // stub gpg：把 --output 语义做成 src→dst 拷贝（含一个可辨识的标记行，
      // 证明数据真的经过了"gpg"而不是原样引用同一文件）
      fs.writeFileSync(
        path.join(stubDir, 'gpg'),
        [
          '#!/bin/bash',
          'out=""',
          'prev=""',
          'for a in "$@"; do',
          '  if [ "$prev" = "--output" ]; then out="$a"; fi',
          '  prev="$a"',
          'done',
          'src="${!#}"',
          '{ echo "STUB-GPG-ENVELOPE"; cat "$src"; } > "$out"',
          '',
        ].join('\n'),
        { mode: 0o755 }
      );
      fs.writeFileSync(path.join(tmpDir, 'archive.gz'), 'PLAINTEXT-ARCHIVE-BYTES');
    });

    afterEach(() => {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    });

    test('encrypt → checksum → 明文归档删除 → decrypt 还原内容，全链成立', () => {
      const src = path.join(tmpDir, 'archive.gz');
      const enc = path.join(tmpDir, 'archive.gz.gpg');
      const dec = path.join(tmpDir, 'restored.gz');
      const script = [
        `. '${CRYPTO.replace(/\\/g, '/')}'`,
        `export BACKUP_GPG_RECIPIENT='ops@example.net'`,
        `crypto_encrypt '${src}' '${enc}'`,
        `crypto_checksum '${enc}'`,
        `rm -f '${src}'`,
        `crypto_decrypt '${enc}' '${dec}'`,
        `echo "rc=$?"`,
      ].join('; ');
      const out = runCrypto(script, { PATH: `${stubDir}${path.delimiter}${process.env.PATH}` });
      expect(out).toBe('rc=0');
      // 加密产物：经过 stub gpg 的信封 + 原始字节；校验和在且指向加密产物
      expect(fs.readFileSync(enc, 'utf8')).toContain('STUB-GPG-ENVELOPE');
      expect(fs.readFileSync(enc, 'utf8')).toContain('PLAINTEXT-ARCHIVE-BYTES');
      const checksum = fs.readFileSync(`${enc}.sha256`, 'utf8');
      // Git Bash 的 sha256sum 在 Windows 上走二进制模式（hash *C:\path），
      // 且路径含反斜杠时哈希前会带一个 \ 转义指示符；Linux 是 hash  path。
      // 三种形态的哈希位（64 个 hex）与文件名都在，转义/分隔符不进断言。
      expect(checksum).toMatch(/^\\?[0-9a-f]{64}[ *]/);
      expect(checksum).toContain('archive.gz.gpg');
      // 明文归档已被调用方删除；解密产物还原出原始字节
      expect(fs.existsSync(src)).toBe(false);
      expect(fs.readFileSync(dec, 'utf8')).toContain('PLAINTEXT-ARCHIVE-BYTES');
    });

    test('缺 BACKUP_GPG_RECIPIENT ⇒ 加密拒绝（不产出半成品）', () => {
      const src = path.join(tmpDir, 'archive.gz');
      const enc = path.join(tmpDir, 'archive.gz.gpg');
      const script = [
        `. '${CRYPTO.replace(/\\/g, '/')}'`,
        `unset BACKUP_GPG_RECIPIENT`,
        `if crypto_encrypt '${src}' '${enc}'; then echo BAD-OK; else echo REJECTED; fi`,
        `ls '${enc}' 2>/dev/null || echo NO-ARTIFACT`,
      ].join('; ');
      const out = runCrypto(script);
      expect(out).toContain('REJECTED');
      expect(out).toContain('NO-ARTIFACT');
    });
  });
});

/**
 * 恢复侧的 sha256 门禁（2026-10-01）
 *
 * 上面那条既有用例断言的是校验和**被产出**；本组断言它**被消费**。
 * 此前全仓没有任何一处读 .sha256：备份侧写了，恢复侧不验 ⇒
 * 异地取回的归档哪怕传错文件、被截断、被替换，也照样进 mongorestore，
 * 而"先 sha256sum --check"只写在 deployment/backup-encryption.md 里。
 *
 * 为什么用 stub mongorestore 真跑脚本（而不是文本断言）：这条防线的全部价值在于
 * "验不过就不写库"，而"写库"是一个副作用。文本断言只能证明代码里出现过 sha256，
 * 证不了 mongorestore 真的没被执行——恰恰是被截断归档最容易被半写进库的形态。
 *
 * 反向自证（用例 6）：本仓比的是**哈希值**而不是 `sha256sum --check`。
 * sidecar 里记的是备份宿主机上的路径字符串，异地副本改名/换目录后 --check 会报
 * no such file —— 用 `--check` 实现的"看似更严格"的版本会在用例 6 红。
 */
describe('restore-mongo.sh 的完整性门禁：验不过就不许写库', () => {
  let tmpDir;
  let stubDir;
  let stubLog;
  let archive;

  const sh = (p) => p.replace(/\\/g, '/');

  const runRestore = (env = {}, script = RESTORE) =>
    spawnSync('bash', [sh(script), sh(archive)], {
      cwd: ROOT,
      encoding: 'utf8',
      timeout: 60000,
      env: {
        ...process.env,
        PATH: `${stubDir}${path.delimiter}${process.env.PATH}`,
        // local 传输 + 非交互确认：与 CI/cron 恢复同一分支
        MONGO_RESTORE_TRANSPORT: 'local',
        MONGODB_URI: 'mongodb://restore_user:pw@127.0.0.1:27017/fire_safety?authSource=admin',
        RESTORE_CONFIRM: 'fire_safety',
        STUB_LOG: sh(stubLog),
        ...env,
      },
    });

  /** 用真实 sha256sum 写 sidecar（与 backupCrypto.sh 的 crypto_checksum 同一形态） */
  const writeChecksum = (target = archive) =>
    execFileSync('bash', ['-c', `sha256sum '${sh(target)}' > '${sh(target)}.sha256'`], {
      cwd: ROOT,
      encoding: 'utf8',
    });

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'restore-checksum-'));
    stubDir = path.join(tmpDir, 'bin');
    fs.mkdirSync(stubDir);
    stubLog = path.join(tmpDir, 'mongorestore.calls');
    fs.writeFileSync(
      path.join(stubDir, 'mongorestore'),
      ['#!/bin/bash', 'echo "STUB-MONGORESTORE $*" >> "$STUB_LOG"', 'exit 0', ''].join('\n'),
      { mode: 0o755 }
    );
    archive = path.join(tmpDir, 'fire-safety-backup-t1.gz');
    fs.writeFileSync(archive, 'ARCHIVE-BYTES- ORIGINAL');
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  test('1 校验通过 ⇒ 放行到 mongorestore（stub 真的被调用）', () => {
    writeChecksum();
    const r = runRestore();
    expect(r.status).toBe(0);
    expect(r.stdout).toContain('完整性校验通过');
    expect(r.stdout).toContain('Restore completed successfully');
    const calls = fs.readFileSync(stubLog, 'utf8');
    expect(calls).toContain('STUB-MONGORESTORE');
    expect(calls).toContain('--archive=');
  });

  test('2 归档被篡改（字节变了、sidecar 仍是旧的）⇒ 终止且 mongorestore 一次都不执行', () => {
    writeChecksum();
    fs.writeFileSync(archive, 'ARCHIVE-BYTES- TRUNCATED/TAMPERED');
    const r = runRestore();
    expect(r.status).not.toBe(0);
    expect(r.stderr).toContain('完整性校验失败');
    expect(r.stderr).toContain('已终止恢复');
    expect(r.stdout).not.toContain('Restore completed successfully');
    // 关键断言：不是"报了错"，而是**根本没有写库**
    expect(fs.existsSync(stubLog)).toBe(false);
  });

  test('3 缺 sidecar ⇒ 硬失败（不得静默放行），且点名显式出口', () => {
    const r = runRestore();
    expect(r.status).not.toBe(0);
    expect(r.stderr).toContain('缺少校验和文件');
    expect(r.stderr).toContain('RESTORE_SKIP_CHECKSUM');
    expect(fs.existsSync(stubLog)).toBe(false);
  });

  test('4 正向对照：RESTORE_SKIP_CHECKSUM=true 放行，但警告必须可见', () => {
    const r = runRestore({ RESTORE_SKIP_CHECKSUM: 'true' });
    expect(r.status).toBe(0);
    expect(r.stderr).toContain('未经任何完整性证明');
    expect(fs.existsSync(stubLog)).toBe(true);
  });

  test('5 sidecar 解析不出 64 位十六进制 ⇒ 失败而不是"当作匹配"', () => {
    fs.writeFileSync(`${archive}.sha256`, 'not-a-hash  fire-safety-backup-t1.gz\n');
    const r = runRestore();
    expect(r.status).not.toBe(0);
    expect(r.stderr).toContain('解析不出 sha256');
    expect(fs.existsSync(stubLog)).toBe(false);
  });

  test('6 异地副本改名/换目录后仍能验（比哈希值，不是 sha256sum --check 的路径耦合）', () => {
    const offsiteDir = path.join(tmpDir, 'offsite');
    fs.mkdirSync(offsiteDir);
    const offsite = path.join(offsiteDir, 't1-copy-renamed.gz');
    fs.copyFileSync(archive, offsite);
    writeChecksum(); // sidecar 里记的是**原名**的路径字符串
    fs.copyFileSync(`${archive}.sha256`, `${offsite}.sha256`);
    // 让 sidecar 内记录的路径失效：这正是 --check 形态会在异地恢复当天报错的原因
    fs.rmSync(archive);
    archive = offsite;
    const r = runRestore();
    expect(r.status).toBe(0);
    expect(r.stdout).toContain('完整性校验通过');
    expect(fs.existsSync(stubLog)).toBe(true);
  });

  // ── 7~9：RESTORE_SKIP_CHECKSUM 的作用域（2026-10-04 审计复跑）──────────────────
  // 旧实现把 `[ "$RESTORE_SKIP_CHECKSUM" = true ]` 写在**整段最前面**，于是它连
  // "sidecar 在、哈希对不上"一起跳过：这个开关的原意是"恢复一份本来就没有校验和的老归档"，
  // 落地却成了"已知损坏/被替换的归档也可以直接写进生产库"。两种情况差着一个量级——
  // 前者缺的是**证据**，后者手里是**反证**。
  test('7 归档被篡改 + RESTORE_SKIP_CHECKSUM=true ⇒ 仍然硬失败，一次都不写库', () => {
    writeChecksum();
    fs.writeFileSync(archive, 'ARCHIVE-BYTES- TAMPERED AFTER CHECKSUM');
    const r = runRestore({ RESTORE_SKIP_CHECKSUM: 'true' });
    expect(r.status).not.toBe(0);
    expect(r.stderr).toContain('完整性校验失败');
    // 点名开关不管这件事：否则运维的下一步是去查别的脚本，或者手工绕过校验直接 mongorestore
    expect(r.stderr).toMatch(/只放行「没有 \.sha256」/);
    expect(r.stderr).not.toMatch(/未经任何完整性证明/);
    expect(fs.existsSync(stubLog)).toBe(false);
    expect(r.stdout).not.toContain('Restore completed successfully');
  });

  test('8 缺 sidecar + SKIP=true 的警告必须说清"缺的是哪一样"（措辞不得漂回通用跳过）', () => {
    // 这一条钉的是文案的作用域：警告如果写成"未经任何完整性证明"这种通用说法，
    // 它与第 7 条的"对不上也放行"在文档上就没区别了，下一个改代码的人会照着模糊文案漂。
    const r = runRestore({ RESTORE_SKIP_CHECKSUM: 'true' });
    expect(r.status).toBe(0);
    expect(r.stderr).toMatch(/缺少 \.sha256/);
    expect(fs.existsSync(stubLog)).toBe(true);
  });

  test('9 前世版自证：把开关判据挪回整段最前面 ⇒ 篡改 + SKIP=true 真的写库（断言有牙齿）', () => {
    const src = fs.readFileSync(RESTORE, 'utf8');
    const legacy = src.replace(
      /^CHECKSUM_FILE="\$BACKUP_FILE\.sha256"\r?\nif \[ ! -f "\$CHECKSUM_FILE" \]; then[\s\S]*?\nelse\r?\n/m,
      'CHECKSUM_FILE="$BACKUP_FILE.sha256"\n' +
        'if [ "${RESTORE_SKIP_CHECKSUM:-false}" = "true" ]; then\n' +
        '  echo "（前世版形态）跳过整段校验" >&2\n' +
        'elif [ ! -f "$CHECKSUM_FILE" ]; then\n' +
        '  echo "Error: 缺少校验和文件：$CHECKSUM_FILE" >&2\n' +
        '  exit 1\n' +
        'else\n'
    );
    // 前提自证：命中替换的是"开关判在整段最前面"那一层——缺 sidecar 的那条新分支文案
    // 必须已经不在（mismatch 分支两版共用，所以不能拿它当判据）。
    expect(legacy).not.toBe(src);
    expect(legacy).toMatch(/前世版形态/);
    expect(legacy).not.toMatch(/本次恢复的归档缺少 \.sha256/);
    const dir = path.join(tmpDir, 'legacy-checksum');
    fs.mkdirSync(dir, { recursive: true });
    for (const f of ['mongoUri.sh', 'backupCrypto.sh']) {
      fs.copyFileSync(path.join(ROOT, 'scripts', f), path.join(dir, f));
    }
    const p = path.join(dir, 'restore-mongo.sh');
    fs.writeFileSync(p, legacy);
    expect(execFileSync('bash', ['-n', sh(p)], { encoding: 'utf8' })).toBe('');

    writeChecksum();
    fs.writeFileSync(archive, 'ARCHIVE-BYTES- TAMPERED AFTER CHECKSUM');
    const r = runRestore({ RESTORE_SKIP_CHECKSUM: 'true' }, p);
    // 修前形态：退 0 且 mongorestore 被调用——这就是第 7 条要拦住的那次写库
    expect(r.status).toBe(0);
    expect(fs.existsSync(stubLog)).toBe(true);
    expect(r.stdout).toContain('Restore completed successfully');
  });
});
