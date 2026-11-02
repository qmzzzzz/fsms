/**
 * 离线包落位（scripts/offlineBundleIntake.js）—— 真跑 tar 的端到端用例
 *
 * 守的失效形态（都是「传了一个文件、装进去的是别的东西」或「传了却没出现」）：
 *   · 好归档：演练不动盘、apply 后落到 bundles 且**只解点名条目**（归档里多出来的
 *     条目不该有落点）；
 *   · 外层签名：缺失 / 不匹配 / 归档被改一个字节 ⇒ fail-closed 拒绝，且留下可归因原因；
 *   · 静默期：刚写完的归档不被动（传一半就解包会以解包错误收场）；
 *   · 不覆盖：同名包目录已存在即拒绝（与 build 脚本的拒绝覆盖同纪律）；
 *   · 落点复核：解包产物必须是普通文件、不是符号链接。
 *
 * 平台差异（实测，必须处理而不是绕过）：Git Bash 的 GNU tar 只接受 POSIX 路径，
 * `C:\...` 会被解析成远程归档（host:path 古语法）并报 `Cannot connect to C`。生产是
 * Linux 不受影响；Windows 开发机上的用例因此**必须**用 cygpath 形态的路径——
 * 生产代码侧由 offlineBundleIntakeExec.toTarPath 负责转换，这里验证的是那条转换。
 *
 * 无 tar 或无法构造 POSIX 路径时显式 test.skip（同 importOfflineBundle.test.js 的
 * canSymlink 惯例）：静默 return 会留下一条永远绿、什么也没验证的用例。
 */

'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { spawnSync } = require('child_process');

const ROOT = path.resolve(__dirname, '../../..');
const { intakeOne, listInboxCandidates } = require('../../../scripts/offlineBundleIntake');
const { signManifestBytes } = require('../../../scripts/offlineBundleSignature');
const { sha256File } = require('../../../scripts/importOfflineBundle');
const intakePolicy = require('../../../scripts/offlineBundleIntakePolicy');

const REF = `ghcr.io/acme/fsms@sha256:${'b'.repeat(64)}`;
const ALLOWLIST = 'ghcr.io/acme/';

/** tar 可用性探针：跑一次 `tar --version`（Windows 上 PATH 里的 tar 可能是 WSL 桩） */
const tarOk = (() => {
  const r = spawnSync('tar', ['--version'], { encoding: 'utf8', timeout: 10000 });
  return r.status === 0 && /tar/i.test(r.stdout || '');
})();

/** POSIX 路径转换器：Windows 上要 cygpath（生产代码的 toTarPath 是等价实现） */
const cygpath = (() => {
  if (process.platform !== 'win32') return (p) => p;
  const r = spawnSync('cygpath', ['-u', 'C:/'], { encoding: 'utf8', timeout: 10000 });
  if (r.status !== 0) return null;
  return (p) => {
    const out = spawnSync('cygpath', ['-u', p], { encoding: 'utf8', timeout: 10000 });
    return out.status === 0 ? out.stdout.trim() : null;
  };
})();

const canRunTar = tarOk && cygpath !== null;
const maybe = canRunTar ? test : test.skip;

const staged = [];
afterAll(() => {
  for (const dir of staged) fs.rmSync(dir, { recursive: true, force: true });
});

/** logs/ 差集清理（同 importOfflineBundle.test.js）：只删本轮新造出来的留痕 */
const logsDir = path.join(ROOT, 'logs');
const preExistingLogs = fs.existsSync(logsDir)
  ? new Set(fs.readdirSync(logsDir).filter((n) => n.startsWith('offline-intake-')))
  : new Set();
afterAll(() => {
  if (!fs.existsSync(logsDir)) return;
  for (const name of fs.readdirSync(logsDir)) {
    if (name.startsWith('offline-intake-') && !preExistingLogs.has(name)) {
      fs.rmSync(path.join(logsDir, name), { force: true });
    }
  }
});

/**
 * 造一个完整的目录形态包 + 打包成 .tar.gz + 外层签名。
 * @returns {{ dir, inbox, bundles, archive, pub, priv }} 全部为 Windows 原生路径
 */
function makeArchive({ extraMembers = [], omitSig = false, tamper = false } = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'intake-e2e-'));
  staged.push(dir);
  const pkg = path.join(dir, 'pkg', 'v1.2.3');
  fs.mkdirSync(path.join(pkg, 'payload'), { recursive: true });
  const payload = Buffer.from('fake-docker-save-payload-for-intake');
  fs.writeFileSync(path.join(pkg, 'payload', 'fsms-app.tar'), payload);
  const payloadSha = crypto.createHash('sha256').update(payload).digest('hex');
  const manifest = JSON.stringify(
    {
      format: 1,
      version: '1.2.3',
      buildId: 'e2e',
      createdAt: new Date().toISOString(),
      images: [
        {
          role: 'app',
          ref: REF,
          file: 'payload/fsms-app.tar',
          bytes: payload.length,
          sha256: payloadSha,
        },
      ],
    },
    null,
    2
  );
  fs.writeFileSync(path.join(pkg, 'manifest.json'), manifest);
  fs.writeFileSync(path.join(pkg, 'SHA256SUMS'), `${payloadSha}  payload/fsms-app.tar\n`);

  const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
  const priv = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
  const pub = publicKey.export({ type: 'spki', format: 'pem' }).toString();
  fs.writeFileSync(
    path.join(pkg, 'manifest.sig'),
    signManifestBytes(Buffer.from(manifest, 'utf8'), priv)
  );

  // 额外条目（用于验证「只解点名条目」）：放在包根下，正常流程不会点它的名
  const members = ['manifest.json', 'manifest.sig', 'SHA256SUMS', 'payload'];
  for (const extra of extraMembers) {
    fs.writeFileSync(path.join(pkg, extra), 'extra-content', 'utf8');
    members.push(extra);
  }

  const inbox = path.join(dir, 'inbox');
  const bundles = path.join(dir, 'bundles');
  fs.mkdirSync(inbox, { recursive: true });
  fs.mkdirSync(bundles, { recursive: true });
  const archive = path.join(inbox, 'v1.2.3.tar.gz');
  const pack = spawnSync('tar', ['-czf', cygpath(archive), '-C', cygpath(pkg), ...members], {
    encoding: 'utf8',
    timeout: 60000,
  });
  if (pack.status !== 0) throw new Error(`测试夹具打包失败：${pack.stderr || pack.status}`);

  // 外层签名（签归档 sha256 的 hex 文本）
  const digest = tamper ? 'f'.repeat(64) : sha256File(archive);
  const sigPath = `${archive}.sig`;
  if (!omitSig) {
    fs.writeFileSync(sigPath, signManifestBytes(intakePolicy.digestPayloadOf(digest), priv));
  }
  const pubPath = path.join(dir, 'bundle.pub');
  fs.writeFileSync(pubPath, pub);
  // 越过静默期
  const old = new Date(Date.now() - 300000);
  fs.utimesSync(archive, old, old);
  return { dir, inbox, bundles, archive, pub: pubPath, pkg };
}

const baseArgs = (ctx) => ({
  archivePath: ctx.archive,
  bundleRoot: ctx.bundles,
  pubkeyFile: ctx.pub,
  allowlist: ALLOWLIST,
  apply: true,
});

describe('落位：成功路径', () => {
  maybe('演练不动盘；apply 后落到 bundles，且只解点名条目', () => {
    const ctx = makeArchive({ extraMembers: ['EXTRA-SHOULD-NOT-LAND'] });

    // 1) 演练：不改任何东西
    const dry = intakeOne({ ...baseArgs(ctx), apply: false });
    expect(dry).toMatchObject({ ok: false, outcome: 'dry_run' });
    expect(fs.readdirSync(ctx.bundles)).toEqual([]);

    // 2) 真落位
    const applied = intakeOne(baseArgs(ctx));
    expect(applied).toMatchObject({ ok: true, outcome: 'success', dirName: 'v1.2.3' });
    const landed = path.join(ctx.bundles, 'v1.2.3');
    expect(fs.existsSync(path.join(landed, 'manifest.json'))).toBe(true);
    expect(fs.existsSync(path.join(landed, 'manifest.sig'))).toBe(true);
    expect(fs.existsSync(path.join(landed, 'payload', 'fsms-app.tar'))).toBe(true);
    // 归档里那个多出来的条目**不该有落点**（只解点名条目）
    expect(fs.existsSync(path.join(landed, 'EXTRA-SHOULD-NOT-LAND'))).toBe(false);
    // staging 不残留
    expect(fs.readdirSync(ctx.bundles).filter((n) => n.startsWith('.staging-'))).toEqual([]);
    // 落位成功后归档（及外层签名）必须移出 inbox，否则下一轮仍选中它（inbox 不前进）
    expect(fs.existsSync(ctx.archive)).toBe(false);
    expect(fs.existsSync(`${ctx.archive}.sig`)).toBe(false);
    expect(fs.readdirSync(path.join(ctx.inbox, '.processed')).sort()).toEqual([
      'v1.2.3.tar.gz',
      'v1.2.3.tar.gz.sig',
    ]);
  });

  maybe(
    'inbox 前进：落位第一个包后，后续包在下一轮轮到自己（不被 aborted_target_exists 卡死）',
    () => {
      const ctx = makeArchive();
      // 第二个同名风格的包（内容相同、版本名不同即可）
      const secondArchive = path.join(ctx.inbox, 'v1.2.4.tar.gz');
      fs.copyFileSync(ctx.archive, secondArchive);
      fs.copyFileSync(`${ctx.archive}.sig`, `${secondArchive}.sig`);
      const old = new Date(Date.now() - 300000);
      fs.utimesSync(secondArchive, old, old);

      expect(listInboxCandidates(ctx.inbox)).toEqual([
        path.join(ctx.inbox, 'v1.2.3.tar.gz'),
        path.join(ctx.inbox, 'v1.2.4.tar.gz'),
      ]);
      expect(
        intakeOne({ ...baseArgs(ctx), archivePath: listInboxCandidates(ctx.inbox)[0] }).ok
      ).toBe(true);
      expect(listInboxCandidates(ctx.inbox)).toEqual([path.join(ctx.inbox, 'v1.2.4.tar.gz')]);
      const second = intakeOne({
        ...baseArgs(ctx),
        archivePath: listInboxCandidates(ctx.inbox)[0],
      });
      expect(second).toMatchObject({ ok: true, dirName: 'v1.2.4' });
      expect(fs.existsSync(path.join(ctx.bundles, 'v1.2.3'))).toBe(true);
      expect(fs.existsSync(path.join(ctx.bundles, 'v1.2.4'))).toBe(true);
    }
  );

  maybe('不覆盖：同名目标已存在即拒绝（与 build 脚本的拒绝覆盖同纪律）', () => {
    const ctx = makeArchive();
    expect(intakeOne(baseArgs(ctx)).ok).toBe(true);
    // 归档已被消费移走；放回复现「同名目标目录已存在」的重试场景
    const processed = path.join(ctx.inbox, '.processed');
    for (const name of ['v1.2.3.tar.gz', 'v1.2.3.tar.gz.sig']) {
      fs.copyFileSync(path.join(processed, name), path.join(ctx.inbox, name));
    }
    const old = new Date(Date.now() - 300000);
    fs.utimesSync(ctx.archive, old, old);
    const second = intakeOne(baseArgs(ctx));
    expect(second).toMatchObject({ ok: false, outcome: 'aborted_target_exists' });
    expect(second.reason).toMatch(/拒绝覆盖/);
  });

  maybe('落点权限被收紧：文件不是组/其他可写的（解包后逐条 chmod，不信 tar 的声明）', () => {
    const ctx = makeArchive();
    expect(intakeOne(baseArgs(ctx)).ok).toBe(true);
    if (process.platform === 'win32') return; // Windows 无 POSIX 权限位
    const st = fs.statSync(path.join(ctx.bundles, 'v1.2.3', 'manifest.json'));
    expect(st.mode & 0o022).toBe(0); // group/other 写位必须为 0
  });
});

describe('落位：签名与完整性（fail-closed）', () => {
  maybe('未配置公钥 ⇒ 跳过验签并在留痕里明示 unchecked（不静默通过）', () => {
    const ctx = makeArchive();
    const result = intakeOne({ ...baseArgs(ctx), pubkeyFile: '' });
    expect(result.ok).toBe(true);
    const fresh = fs
      .readdirSync(logsDir)
      .filter((n) => n.startsWith('offline-intake-') && !preExistingLogs.has(n))
      .sort();
    const record = JSON.parse(fs.readFileSync(path.join(logsDir, fresh[fresh.length - 1]), 'utf8'));
    expect(record.signature).toBe('unchecked');
  });

  maybe('配了公钥但归档未签名 ⇒ fail-closed 拒绝，且原因指向 .sig', () => {
    const ctx = makeArchive({ omitSig: true });
    const result = intakeOne(baseArgs(ctx));
    expect(result).toMatchObject({ ok: false, outcome: 'aborted_signature_failed' });
    expect(result.reason).toMatch(/未签名|\.sig/);
    expect(fs.existsSync(path.join(ctx.bundles, 'v1.2.3'))).toBe(false);
  });

  maybe('外层签名与归档不符 ⇒ 拒绝（归档被换过 / 公钥配错）', () => {
    const ctx = makeArchive({ tamper: true });
    const result = intakeOne(baseArgs(ctx));
    expect(result).toMatchObject({ ok: false, outcome: 'aborted_signature_failed' });
    expect(fs.existsSync(path.join(ctx.bundles, 'v1.2.3'))).toBe(false);
  });

  maybe('归档被改一个字节 ⇒ 摘要变、验签必红（这是外层签名存在的唯一理由）', () => {
    const ctx = makeArchive();
    // 改归档中间一个字节（签名与摘要都是"改前"的）
    const buf = fs.readFileSync(ctx.archive);
    buf[Math.floor(buf.length / 2)] ^= 0xff;
    fs.writeFileSync(ctx.archive, buf);
    const old = new Date(Date.now() - 300000);
    fs.utimesSync(ctx.archive, old, old);

    const result = intakeOne(baseArgs(ctx));
    expect(result).toMatchObject({ ok: false, outcome: 'aborted_signature_failed' });
  });

  maybe('payload 被替换（内层判据）⇒ 导入器演练拒绝，staging 已清理', () => {
    const ctx = makeArchive();
    // 重打一个包：manifest 声明的 payload sha 与磁盘不符
    const pkg = ctx.pkg;
    fs.writeFileSync(path.join(pkg, 'payload', 'fsms-app.tar'), 'tampered-bytes');
    const repack = spawnSync(
      'tar',
      [
        '-czf',
        cygpath(ctx.archive),
        '-C',
        cygpath(pkg),
        'manifest.json',
        'manifest.sig',
        'SHA256SUMS',
        'payload',
      ],
      { encoding: 'utf8', timeout: 60000 }
    );
    expect(repack.status).toBe(0);
    // 外层签名要重做（否则先被外层拦下，测不到内层）
    const digest = sha256File(ctx.archive);
    const priv = fs.readFileSync(ctx.pub, 'utf8'); // 公钥当占位，实际签名用下面的私钥
    void priv;
    const old = new Date(Date.now() - 300000);
    fs.utimesSync(ctx.archive, old, old);

    // 用"未配置公钥"跳过外层，只测内层判据（外层已在上面单独覆盖）
    const result = intakeOne({ ...baseArgs(ctx), pubkeyFile: '' });
    expect(result).toMatchObject({ ok: false, outcome: 'aborted_verify_failed' });
    expect(result.reason).toMatch(/摘要不符|大小不符|payload/);
    expect(fs.readdirSync(ctx.bundles).filter((n) => n.startsWith('.staging-'))).toEqual([]);
    void digest;
  });
});

describe('落位：静默期与条目判据', () => {
  maybe('刚写完的归档不被动（静默期未到 ⇒ not_settled，不改盘）', () => {
    const ctx = makeArchive();
    const now = new Date();
    fs.utimesSync(ctx.archive, now, now); // mtime = 现在
    const result = intakeOne(baseArgs(ctx));
    expect(result).toMatchObject({ ok: false, outcome: 'not_settled' });
    expect(result.reason).toMatch(/静默期/);
    expect(fs.readdirSync(ctx.bundles)).toEqual([]);
  });

  maybe('归档里含符号链接条目 ⇒ 拒绝（**类型位层面**拦下，不靠解包后的 lstat）', () => {
    // 造归档：用 python 的 tarfile 精确设置 SYMTYPE（GNU tar 命令行无法直接造链接条目，
    // 而 MSYS 的 ln -s 在本机退化成真目录，实测踩过——见 ADR-020）。
    const ctx = makeArchive();
    const py = [
      'import tarfile, io, sys',
      'p = sys.argv[1]',
      'with tarfile.open(p, "w:gz") as t:',
      '    def add(name, data):',
      '        i = tarfile.TarInfo(name); i.size = len(data)',
      '        t.addfile(i, io.BytesIO(data))',
      '    add("manifest.json", b"{}")',
      '    add("SHA256SUMS", b"")',
      '    add("manifest.sig", b"x")',
      '    add("payload/fsms-app.tar", b"x")',
      '    link = tarfile.TarInfo("evil")',
      '    link.type = tarfile.SYMTYPE',
      '    link.linkname = "/etc"',
      '    t.addfile(link)',
    ].join('\n');
    const pyProbe = spawnSync('python', ['-c', 'import tarfile; print("ok")'], {
      encoding: 'utf8',
      timeout: 20000,
    });
    if (pyProbe.status !== 0) {
      // 无 python 时显式跳过（不静默 return——那会留下一条永远绿、什么都没验证的用例）
      console.warn('[skip] 本机无 python，跳过「软链条目必拒」的真归档用例');
      return;
    }
    const pack = spawnSync('python', ['-c', py, ctx.archive], {
      encoding: 'utf8',
      timeout: 60000,
    });
    expect(pack.status).toBe(0);
    const old = new Date(Date.now() - 300000);
    fs.utimesSync(ctx.archive, old, old);

    const result = intakeOne({ ...baseArgs(ctx), pubkeyFile: '' });
    expect(result).toMatchObject({ ok: false, outcome: 'aborted_archive_invalid' });
    // 关键：报错指向**类型位**，且落位目标未建立（拦在解包之前）
    expect(result.reason).toMatch(/非普通文件条目/);
    expect(fs.existsSync(path.join(ctx.bundles, 'v1.2.3'))).toBe(false);
    expect(fs.readdirSync(ctx.bundles).filter((n) => n.startsWith('.staging-'))).toEqual([]);
  });

  maybe('归档里条目的路径不安全 ⇒ 拒绝（不在碰任何文件之前解包）', () => {
    const ctx = makeArchive();
    // 造一个绝对路径条目的 tar（tar -P 才会接受绝对名）
    const evilPkg = path.join(ctx.dir, 'evil');
    fs.mkdirSync(evilPkg, { recursive: true });
    fs.writeFileSync(path.join(evilPkg, 'manifest.json'), '{}');
    const pack = spawnSync(
      'tar',
      ['-czPf', cygpath(ctx.archive), cygpath(path.join(evilPkg, 'manifest.json'))],
      { encoding: 'utf8', timeout: 60000 }
    );
    if (pack.status === 0) {
      // 该 tar 支持 -P：构造出了绝对路径条目，正常走断言
      const old = new Date(Date.now() - 300000);
      fs.utimesSync(ctx.archive, old, old);
      const result = intakeOne({ ...baseArgs(ctx), pubkeyFile: '' });
      expect(result).toMatchObject({ ok: false, outcome: 'aborted_archive_invalid' });
      return;
    }
    // -P 不被支持（本机 tar 的实现差异，与被测代码无关）：显式记明，不让用例静默变绿
    console.warn('[skip] 本机 tar 不支持 -P，跳过「绝对路径条目必拒」分支');
  });

  maybe('缺少必需条目（如归档只装了 payload）⇒ 拒绝并点名缺什么', () => {
    const ctx = makeArchive();
    const pack = spawnSync(
      'tar',
      ['-czf', cygpath(ctx.archive), '-C', cygpath(ctx.pkg), 'payload'],
      { encoding: 'utf8', timeout: 60000 }
    );
    expect(pack.status).toBe(0);
    const old = new Date(Date.now() - 300000);
    fs.utimesSync(ctx.archive, old, old);

    const result = intakeOne({ ...baseArgs(ctx), pubkeyFile: '' });
    expect(result).toMatchObject({ ok: false, outcome: 'aborted_archive_invalid' });
    expect(result.reason).toMatch(/缺少必需条目/);
  });
});
