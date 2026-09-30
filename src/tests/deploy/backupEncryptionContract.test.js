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
const { execFileSync } = require('child_process');

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
