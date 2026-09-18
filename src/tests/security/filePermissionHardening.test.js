/**
 * M-05 回归：密钥载体权限必须**实际收紧**并可复核
 *
 * 缺陷历史：
 *   - 原实现用 chmod(0600) 收紧 secrets/ 与初始密码文件。这在 NTFS 上是**空操作**，
 *     文件继续继承父目录 ACL（实测默认含 BUILTIN\Users 可读、沙箱/Users 组可写），
 *     而调用方日志仍打印「权限 600」——用户以为受保护，实际裸奔。
 *   - 第一轮修复只**打印** icacls 命令让用户手动执行。实践中多数人不会做，
 *     等于把安全语义降级为建议。
 *
 * 本轮修复：改为实际执行 + 回读校验（utils/filePermission.js）。
 *
 * 本测试的判定哲学：**假阴性最危险**。一个「权限没收紧」被校验判为「已收紧」，
 * 比完全没有校验更糟——它给出虚假保证。因此校验必须
 *   (a) 对未收紧的路径返回 tightened=false，
 *   (b) 解析不出 ACE 时 fail-closed（判未收紧），
 *   (c) 覆盖「组账户」这一类，而非枚举已知组名。
 */
const fs = require('fs');
const os = require('os');
const path = require('path');

const { hardenPath, verifyHardened, isWindows } = require(
  path.resolve(__dirname, '../../utils/filePermission')
);

/** 建一个隔离临时目录，用完删除（不触碰工作区） */
function withTempDir(fn) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'm05-'));
  try {
    return fn(dir);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

/**
 * 调 icacls 的薄封装：不抛异常，把退出码与 stderr 交回调用方断言。
 * 用 execFileSync 直接传参数数组（不经 shell），路径含空格/中文也不会被拆散。
 */
function execIcacls(args) {
  const { spawnSync } = require('child_process');
  const r = spawnSync('icacls', args, { encoding: 'utf8', windowsHide: true });
  return { status: r.status, stdout: r.stdout || '', stderr: r.stderr || '' };
}

describe('M-05 文件权限收紧与复核', () => {
  it('hardenPath 对不存在的路径返回 ok=false，不抛异常（best-effort 契约）', () => {
    const r = hardenPath(path.join(os.tmpdir(), 'definitely-missing-' + process.pid));
    expect(r.ok).toBe(false);
    expect(r.detail).toContain('不存在');
  });

  it('verifyHardened 对不存在的路径 fail-closed（判未收紧）', () => {
    const r = verifyHardened(path.join(os.tmpdir(), 'definitely-missing-' + process.pid));
    expect(r.tightened).toBe(false);
  });

  if (isWindows) {
    it('含组账户 ACE 的目录必须被判为「未收紧」——这是校验的基本正确性', () => {
      // 【本轮改造：删掉 if 跳过，改为确定性构造前置条件】
      // 原用例依赖「宿主临时目录默认 ACL 必然宽松」这一**环境假设**，
      // 并为此写了一个 `if (before.tightened) { console.warn(...); return; }` 的
      // 跳过分支——在被加固过的宿主上，这条断言会被静默跳过，用例报绿但**什么都没验**。
      //
      // 现在不依赖默认 ACL：显式授予 Everyone（S-1-1-0）可读权限，
      // 使「存在组账户 ACE」成为本用例自己造出来的既成事实。
      // 用 SID 而非本地化名称（Everyone / Users 在不同语言 Windows 上名称不同）。
      withTempDir((dir) => {
        const r = execIcacls([dir, '/grant', '*S-1-1-0:(OI)(CI)(RX)']);
        expect({ rc: r.status, stderr: r.stderr }).toMatchObject({ rc: 0 });

        const before = verifyHardened(dir);
        expect({ tightened: before.tightened, evidence: before.evidence }).toMatchObject({
          tightened: false,
        });
        expect(before.evidence).toMatch(/可疑/);
      });
    });

    it('hardenPath 能移除组账户 ACE（收紧后同一目录转为已收紧）', () => {
      // 与上一条构成闭环：先造出「未收紧」，再用 hardenPath 收紧，
      // 断言确实转成「已收紧」——否则硬化的实际效果无从验证。
      withTempDir((dir) => {
        execIcacls([dir, '/grant', '*S-1-1-0:(OI)(CI)(RX)']);
        expect(verifyHardened(dir).tightened).toBe(false);

        const r = hardenPath(dir, { isDir: true });
        expect(r.ok).toBe(true);
        expect(verifyHardened(dir).tightened).toBe(true);
      });
    });

    it('hardenPath 后 verifyHardened 必须判为已收紧（收紧 → 复核闭环）', () => {
      withTempDir((dir) => {
        const r = hardenPath(dir, { isDir: true });
        expect(r.ok).toBe(true);
        const after = verifyHardened(dir);
        expect(after.tightened).toBe(true);
      });
    });

    it('文件级收紧同样生效（初始密码文件走的是这条路径）', () => {
      withTempDir((dir) => {
        const f = path.join(dir, '.admin-initial-password');
        fs.writeFileSync(f, 'username: admin\npassword: x\n');
        const r = hardenPath(f);
        expect(r.ok).toBe(true);
        expect(verifyHardened(f).tightened).toBe(true);
      });
    });

    it('收紧后原始 icacls 输出中不再出现组账户 ACE（含显式授予的）', () => {
      // 【本轮修正：标题与断言对齐】
      // 原用例标题写「不再含组账户 ACE」，断言却只查「不含 (I) 继承标记」——
      // 二者不等价：显式授予的 Everyone ACE 不带 (I)，在「只切继承、不重置显式 ACE」
      // 的实现下会存活，而该用例照样报绿（实测：把 /reset 移除后，此用例仍绿）。
      // 现按标题真正的语义取证，前置条件由本用例自己构造：
      // 先显式授予 Everyone(S-1-1-0)，再收紧，断言原始 icacls 文本里 Everyone 确实消失。
      // 不经过 verifyHardened 的解析层，是对该解析层的交叉验证。
      withTempDir((dir) => {
        const g = execIcacls([dir, '/grant', '*S-1-1-0:(OI)(CI)(RX)']);
        expect({ rc: g.status, stderr: g.stderr }).toMatchObject({ rc: 0 });
        hardenPath(dir, { isDir: true });
        const r = execIcacls([dir]);
        expect({ rc: r.status, stderr: r.stderr }).toMatchObject({ rc: 0 });
        // Everyone 在中文/英文 Windows 的 icacls 输出里均显示为英文名（实测）；
        // 再加 SID 形式兜底，防个别环境按 SID 呈现。
        expect(r.stdout).not.toMatch(/Everyone/i);
        expect(r.stdout).not.toMatch(/S-1-1-0/);
      });
    });
  } else {
    it('POSIX：chmod 0700 后 mode 必须精确匹配（不依赖回溯校验的宽松判断）', () => {
      withTempDir((dir) => {
        hardenPath(dir, { isDir: true });
        expect(fs.statSync(dir).mode & 0o777).toBe(0o700);
        expect(verifyHardened(dir).tightened).toBe(true);
      });
    });

    it('POSIX：widened 后必须判为未收紧（防止校验恒真）', () => {
      withTempDir((dir) => {
        hardenPath(dir, { isDir: true });
        fs.chmodSync(dir, 0o755);
        expect(verifyHardened(dir).tightened).toBe(false);
      });
    });
  }
});

/**
 * 【本轮改造：源码 grep → 真实执行】
 *
 * 原 describe 对两个调用方做正则 grep（断言源码里出现 `hardenPath(` / `verifyHardened(`）。
 * 它拦不住真正的回归，因为「调用被写进源码」与「调用真的生效」是两件事：
 *   - 把调用挪进 `if (false)` / 永不满足的分支 → grep 照样命中；
 *   - 调用后忽略返回值、不给 log 回调、或参数传错（如漏 isDir）→ grep 照样命中；
 *   - 注释里写一行 `hardenPath(dir)` → grep 照样命中。
 *
 * 现直接**运行 generate-secrets.js**（它有 --out，是可端到端驱动的真实入口），
 * 跑完检查产物目录的权限是否**真的被收紧**（复用 verifyHardened，即运维复核用的同一函数）。
 * 这正是「伪修复」与「真收紧」的分界线：脚本若退化为只打印命令，
 * 生成的目录会保持继承 ACL，verifyHardened 判未收紧 → 本用例转红。
 *
 * initData.js 一侧不再重复：它的「落盘 + 收紧 + 复核」闭环已由
 * src/tests/security/initDataPasswordHardening.test.js 用真实行为覆盖
 * （断言 verifyHardened(pwdFile).tightened === true），此处保留 grep 只会是冗余弱证据。
 */
describe('M-05 调用点真的收紧（运行脚本，检查产物权限）', () => {
  const { execFileSync } = require('child_process');
  const SCRIPT = path.resolve(__dirname, '../../../scripts/generate-secrets.js');
  const NODE = process.execPath;

  it('generate-secrets.js 跑完后，输出目录权限确实被收紧（非「只提示不执行」）', () => {
    withTempDir((dir) => {
      const out = path.join(dir, 'secrets-out');
      const stdout = execFileSync(NODE, [SCRIPT, '--out', out], {
        encoding: 'utf8',
        cwd: path.resolve(__dirname, '../../..'),
      });

      // 密钥确实写出来了（防止「脚本报错退出但用例仍绿」）
      expect(fs.existsSync(path.join(out, 'jwt_secret'))).toBe(true);
      expect(fs.existsSync(path.join(out, 'hmac_secret'))).toBe(true);

      // 关键断言：权限真的被收紧（与运维复核用的是同一个函数）
      const check = verifyHardened(out);
      expect({ tightened: check.tightened, evidence: check.evidence }).toMatchObject({
        tightened: true,
      });

      // 脚本必须如实汇报收敛结果，而不是静默通过
      expect(stdout).toContain('权限已收紧并复核通过');
    });
  });

  it('目录内的密钥文件本身也被逐个收紧（不只是目录）', () => {
    // 原实现只收紧了目录，未对目录内已写入的文件显式收紧——
    // 在「文件先建、目录后收紧」且未走 /T 递归的平台上，文件会保持宽松 ACL。
    // 本用例锁死「逐个文件也收紧」这一行为。
    withTempDir((dir) => {
      const out = path.join(dir, 'secrets-out');
      execFileSync(NODE, [SCRIPT, '--out', out], {
        encoding: 'utf8',
        cwd: path.resolve(__dirname, '../../..'),
      });

      for (const name of ['jwt_secret', 'aes_secret_key', 'admin_initial_password']) {
        const f = path.join(out, name);
        expect({ name, tightened: verifyHardened(f).tightened }).toMatchObject({
          name,
          tightened: true,
        });
      }
    });
  });
});
