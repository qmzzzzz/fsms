'use strict';

/**
 * Windows 上**文件**的 ACL 收紧漏了 /reset ⇒ 显式授予的组 ACE 存活，
 * 而 hardenPath 照旧返回 ok:true（目录分支已修，文件分支没修）
 *
 * `utils/filePermission.js` 第 77-82 行的注释把危害说得很清楚：
 *   `icacls <path> /inheritance:r /grant:r <user>:F` 只移除**继承来的** ACE，
 *   显式授予的 Everyone/Users 会存活；而函数返回 ok:true ⇒ "已收紧"是假阴性。
 * 那个 /reset 却包在 `if (isDir)` 里 —— 文件路径走不到。
 *
 * 谁受影响：两个真实调用点都收紧文件。
 *   - `scripts/generate-secrets.js:135` 逐个收紧密钥文件；
 *   - `src/services/initData.js:733` 收紧初始密码文件（这条路径**不**先重置父目录，
 *     所以没有"目录 /T 递归重置"顺带兜底）。
 * 而 `icacls` 的现实语义下，"文件带显式 ACE"并不罕见：从别处拷贝/解压来的密钥文件、
 * 备份恢复出来的文件、或管理员手工 grant 过的文件。
 *
 * 取证方式与 `filePermissionHardening.test.js` 里那条目录用例同型：
 * 真跑 icacls，直接看原始输出里 Everyone/S-1-1-0 是否消失——
 * **不经过 verifyHardened 的解析层**（否则是在用被测代码验证被测代码）。
 */

const fs = require('fs');
const os = require('os');
const path = require('path');

const { hardenPath, verifyHardened, isWindows } = require('../utils/filePermission');

function execIcacls(args) {
  const { spawnSync } = require('child_process');
  const r = spawnSync('icacls', args, { encoding: 'utf8', windowsHide: true });
  return { status: r.status, stdout: r.stdout || '', stderr: r.stderr || '' };
}

const withTempFile = (fn) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'f87-'));
  const file = path.join(dir, 'app.key');
  fs.writeFileSync(file, 'secret-material\n');
  try {
    return fn(file);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
};

(isWindows ? describe : describe.skip)('zzqoder F-87 文件级 ACL 收紧必须清除显式 ACE', () => {
  test('前置：能真跑 icacls（否则后面的断言全是在测空气）', () => {
    const r = execIcacls(['/?']);
    expect(r.status === null || r.status === 0 || typeof r.stdout === 'string').toBe(true);
    expect(r.stdout.length + r.stderr.length).toBeGreaterThan(0);
  });

  test('显式授予 Everyone 的文件，收紧后 Everyone 必须从 ACL 里消失', () => {
    withTempFile((file) => {
      const granted = execIcacls([file, '/grant', '*S-1-1-0:(R)']);
      expect(granted.status).toBe(0);
      // 前提自证：授予确实生效了（否则"消失"可能是根本没出现过）
      const before = execIcacls([file]);
      expect(before.stdout + before.stderr).toMatch(/Everyone|S-1-1-0/);

      const res = hardenPath(file);
      expect(res.ok).toBe(true);

      const after = execIcacls([file]);
      expect(after.stdout).not.toMatch(/Everyone/i);
      expect(after.stdout).not.toMatch(/S-1-1-0/);
    });
  });

  test('复核层也必须判"未收紧"（假阴性是本模块最危险的失效形态）', () => {
    withTempFile((file) => {
      execIcacls([file, '/grant', '*S-1-1-0:(R)']);
      hardenPath(file);
      expect(verifyHardened(file).tightened).toBe(true);
    });
  });

  test('反向保护：收紧后当前用户仍可读写（不许把密钥文件锁死）', () => {
    withTempFile((file) => {
      execIcacls([file, '/grant', '*S-1-1-0:(R)']);
      hardenPath(file);
      expect(() => fs.writeFileSync(file, 'rewritten\n')).not.toThrow();
      expect(fs.readFileSync(file, 'utf8')).toBe('rewritten\n');
    });
  });
});
