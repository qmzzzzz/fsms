/**
 * 离线包导入器（scripts/importOfflineBundle.js）——「装进来的到底是哪一版」
 *
 * 这条链上真正昂贵的失误不是「导入失败」，而是**导入报成功、装进去的是另一版**：
 * 离线侧没有 registry 可以对质，唯一能证明版本的只有「manifest 自称」与「实际字节」
 * 之间那几次比对。所以本套件的用例全部围绕一个问题：哪一步被跳过之后，
 * 一个被替换/被截断的包会被报告成「导入成功」。
 *
 * 三组主张：
 *   · 用法错误必须在**产生任何副作用之前**以退出码 2 拒绝，且 stdout 一个字节都不留
 *     （本仓既有口径：ops 脚本的手误不得退化成「照常执行」）；
 *   · 校验必须**先于** docker load —— 一个坏的包若先被 load，拒绝之前它已经写进本地
 *     docker 了（占盘、并与上一版抢同一个 repo 名）；
 *   · 白名单在离线侧同样是 fail-closed，且离线不是 tag 的逃生通道。
 *
 * 全部用子进程实测：本套件不依赖 docker（开发机没有可用的 docker 守护进程），
 * 因此凡「本该在碰 docker 之前失败」的用例，都以「进程在 load 步之前退出」为判据。
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { spawnSync } = require('child_process');

const ROOT = path.resolve(__dirname, '../../..');
const SCRIPT = path.join(ROOT, 'scripts/importOfflineBundle.js');
const NODE = process.execPath;

/** 合法引用：digest 钉扎，且落在用例统一使用的白名单前缀内 */
const DIGEST = 'sha256:' + 'a'.repeat(64);
const REF = 'ghcr.io/qmzzzzz/fsms@' + DIGEST;
const ALLOWLIST = 'ghcr.io/qmzzzzz/';

const run = (args) =>
  spawnSync(NODE, [SCRIPT, ...args], { cwd: ROOT, encoding: 'utf8', timeout: 60000 });

/**
 * Windows 非开发者模式下建符号链接会 EPERM。这条判据（拒绝软链 payload）必须被**真正跑到**，
 * 否则「测试通过」只是因为用例自己跳过了——故显式降级为 skip，而不是在用例体里静默 return
 * （静默 return 会留下一条永远绿的用例，而它一条判据都没验证）。
 */
const canSymlink = (() => {
  const probe = fs.mkdtempSync(path.join(os.tmpdir(), 'symlink-probe-'));
  try {
    const t = path.join(probe, 't');
    fs.writeFileSync(t, 'x');
    fs.symlinkSync(t, path.join(probe, 'l'));
    return true;
  } catch (_) {
    return false;
  } finally {
    fs.rmSync(probe, { recursive: true, force: true });
  }
})();

const kept = [];
const mkdtemp = (label) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bundle-' + label + '-'));
  kept.push(dir);
  return dir;
};

/**
 * 导入器在失败路径上会往仓库 logs/ 写一份 0600 留痕（这是刻意的取证面）。
 * 用例只清掉**本轮自己造出来的**那几条：按文件名差集删，避免误删真实留痕。
 */
const logsDir = path.join(ROOT, 'logs');
const preExistingLogs = fs.existsSync(logsDir)
  ? new Set(fs.readdirSync(logsDir).filter((n) => n.startsWith('offline-import-')))
  : new Set();

afterAll(() => {
  for (const dir of kept) fs.rmSync(dir, { recursive: true, force: true });
  if (!fs.existsSync(logsDir)) return;
  for (const name of fs.readdirSync(logsDir)) {
    if (name.startsWith('offline-import-') && !preExistingLogs.has(name)) {
      fs.rmSync(path.join(logsDir, name), { force: true });
    }
  }
});

/**
 * 造一个包。payload 与 manifest 默认互相自洽——各用例只破坏自己关心的那一项，
 * 否则「拒绝」可能来自另一条判据，用例就失去了指向性。
 */
const makeBundle = (over = {}) => {
  const dir = mkdtemp('case');
  fs.mkdirSync(path.join(dir, 'payload'), { recursive: true });
  const bytes = over.payloadBytes || Buffer.from('fake docker save payload');
  fs.writeFileSync(path.join(dir, 'payload', 'fsms-app.tar'), bytes);
  const sha256 = over.sha256 || crypto.createHash('sha256').update(bytes).digest('hex');
  const manifest = {
    format: 1,
    version: '1.2.3',
    buildId: 'ci-20261101',
    createdAt: '2026-11-01T00:00:00.000Z',
    images: [
      Object.assign(
        {
          role: 'app',
          ref: REF,
          file: 'payload/fsms-app.tar',
          bytes: over.declaredBytes === undefined ? bytes.length : over.declaredBytes,
          sha256,
        },
        over.image || {}
      ),
    ],
  };
  fs.writeFileSync(path.join(dir, 'manifest.json'), JSON.stringify(manifest, null, 2));
  return dir;
};

describe('用法错误：在产生任何副作用之前以退出码 2 拒绝', () => {
  test('未知参数：点名该 token，且 stdout 一个字节都不留', () => {
    const r = run(['--bundle-rootz', '/x']);
    expect(r.status).toBe(2);
    expect(r.stdout).toBe('');
    expect(r.stderr).toContain('--bundle-rootz');
  });

  test('拼错时给出可照抄的写法（少一个字母是最常见的误输）', () => {
    const r = run(['--bundl', '/x']);
    expect(r.status).toBe(2);
    expect(r.stderr).toContain('--bundle');
  });

  test('缺少 --bundle：拒绝，而不是回退到某个默认目录去找包', () => {
    const r = run([]);
    expect(r.status).toBe(2);
    expect(r.stdout).toBe('');
    expect(r.stderr).toContain('缺少 --bundle');
  });
});

describe('离线不是绕开 digest 钉扎与白名单的通道', () => {
  test('空白名单 = 全拒（把包拷进目录不等于能装任意代码）', () => {
    const dir = makeBundle();
    const r = run(['--bundle', dir, '--allowlist', '']);
    expect(r.status).toBe(1);
    expect(r.stderr).toContain('白名单为空');
  });

  test('白名单外的仓库被拒', () => {
    const dir = makeBundle();
    const r = run(['--bundle', dir, '--allowlist', 'ghcr.io/someoneelse/']);
    expect(r.status).toBe(1);
    expect(r.stderr).toContain('不在白名单');
  });

  test('包内引用是 tag 形态：必须拒绝（离线包不得成为 tag 的逃生通道）', () => {
    const dir = makeBundle({ image: { ref: 'ghcr.io/qmzzzzz/fsms:v1.2.3' } });
    const r = run(['--bundle', dir, '--allowlist', ALLOWLIST]);
    expect(r.status).toBe(1);
    expect(r.stderr).toContain('digest 钉扎');
  });

  test('manifest 缺 sha256：拒绝，而不是「没有摘要就跳过校验」', () => {
    const dir = makeBundle();
    const raw = JSON.parse(fs.readFileSync(path.join(dir, 'manifest.json'), 'utf8'));
    delete raw.images[0].sha256;
    fs.writeFileSync(path.join(dir, 'manifest.json'), JSON.stringify(raw));
    const r = run(['--bundle', dir, '--allowlist', ALLOWLIST]);
    expect(r.status).toBe(1);
    expect(r.stderr).toContain('sha256');
  });

  test('包格式版本不符：硬失败，不做「尽力而为」的兼容', () => {
    const dir = makeBundle();
    const raw = JSON.parse(fs.readFileSync(path.join(dir, 'manifest.json'), 'utf8'));
    raw.format = 2;
    fs.writeFileSync(path.join(dir, 'manifest.json'), JSON.stringify(raw));
    const r = run(['--bundle', dir, '--allowlist', ALLOWLIST]);
    expect(r.status).toBe(1);
    expect(r.stderr).toContain('不支持的包格式版本');
  });
});

describe('包形态与位置', () => {
  test('传 .tar 而不是解压目录：拒绝并说明不自己解包的理由', () => {
    const file = path.join(os.tmpdir(), 'bundle-not-a-dir.tar');
    fs.writeFileSync(file, 'x');
    const r = run(['--bundle', file, '--allowlist', ALLOWLIST]);
    expect(r.status).toBe(1);
    expect(r.stderr).toContain('已解压的目录');
  });

  test('--bundle-root 之外的包：拒绝（代理调用时把包目录钉在允许的根之下）', () => {
    const dir = makeBundle();
    const r = run([
      '--bundle',
      dir,
      '--allowlist',
      ALLOWLIST,
      '--bundle-root',
      path.join(dir, 'sub'),
    ]);
    expect(r.status).toBe(1);
    expect(r.stderr).toContain('不在允许的根目录之下');
  });

  test('缺 manifest.json：拒绝', () => {
    const dir = mkdtemp('nomanifest');
    const r = run(['--bundle', dir, '--allowlist', ALLOWLIST]);
    expect(r.status).toBe(1);
    expect(r.stderr).toContain('manifest.json');
  });
});

describe('默认演练：不带 --apply 不碰 docker', () => {
  test('缺省即演练，退出码 2（与 scripts/hotUpgrade.js 同语义）', () => {
    const dir = makeBundle();
    const r = run(['--bundle', dir, '--allowlist', ALLOWLIST]);
    expect(r.status).toBe(2);
    expect(r.stdout).toContain('演练模式');
  });

  test('显式 --dry-run 演练并退出 0（CI 里「只验证不执行」需要一个成功信号）', () => {
    const dir = makeBundle();
    const r = run(['--bundle', dir, '--allowlist', ALLOWLIST, '--dry-run']);
    expect(r.status).toBe(0);
    expect(r.stdout).toContain('演练模式');
  });
});

describe('校验必须先于 docker load（否则坏包在被拒绝前已写进本地 docker）', () => {
  test('payload 字节数不符：在 load 之前中止', () => {
    const dir = makeBundle({ declaredBytes: 1 });
    const r = run(['--bundle', dir, '--allowlist', ALLOWLIST, '--apply']);
    expect(r.status).toBe(1);
    expect(r.stderr).toContain('大小不符');
    expect(r.stderr).toContain('尚未改动本机 docker');
  });

  test('payload 摘要不符（大小相同）：在 load 之前中止，且报「摘要不符」而非别的症状', () => {
    const dir = makeBundle({ sha256: 'b'.repeat(64) });
    const r = run(['--bundle', dir, '--allowlist', ALLOWLIST, '--apply']);
    expect(r.status).toBe(1);
    expect(r.stderr).toContain('摘要不符');
    expect(r.stderr).toContain('尚未改动本机 docker');
  });

  test('payload 缺失：在 load 之前中止', () => {
    const dir = makeBundle();
    fs.rmSync(path.join(dir, 'payload', 'fsms-app.tar'));
    const r = run(['--bundle', dir, '--allowlist', ALLOWLIST, '--apply']);
    expect(r.status).toBe(1);
    expect(r.stderr).toContain('尚未改动本机 docker');
  });

  (canSymlink ? test : test.skip)(
    'payload 是符号链接：拒绝（链接指向的可以是包外任意文件）',
    () => {
      const dir = makeBundle();
      const target = path.join(dir, 'payload', 'fsms-app.tar');
      fs.rmSync(target);
      fs.writeFileSync(path.join(dir, 'real.tar'), 'payload');
      fs.symlinkSync(path.join(dir, 'real.tar'), target);
      const r = run(['--bundle', dir, '--allowlist', ALLOWLIST, '--apply']);
      expect(r.status).toBe(1);
      expect(r.stderr).toContain('符号链接');
      expect(r.stderr).toContain('尚未改动本机 docker');
    }
  );
});
