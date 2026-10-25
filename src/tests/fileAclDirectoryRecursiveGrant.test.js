'use strict';

/**
 * Windows 上目录级 ACL 收紧曾把子文件 DACL 清空（实测 EPERM）。
 *
 * 原实现给 `/grant:r` 也带了 `/T`，于是 `(OI)(CI)F` 这条**继承专用** ACE 被直接写进
 * 每个子文件；它对文件自身不生效 ⇒ 子文件没有任何有效 ACE，连所有者都打不开。
 * 受害面不限于 WAL：目录里只要还有日志/密钥子文件，一次“收紧”就会把它们全部锁死。
 *
 * 修复判据：`/reset /T` 负责递归清除显式 ACE，`/grant:r` 只在目录上授予、由子文件继承。
 * 本用例真跑 icacls 并**实际读回子文件**——只查 ACL 文本会漏掉“ACE 在但不可用”的形态。
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const { hardenPath, verifyHardened, isWindows } = require('../utils/filePermission');

const execIcacls = (args) => {
  const r = spawnSync('icacls', args, { encoding: 'utf8', windowsHide: true });
  return { status: r.status, stdout: r.stdout || '', stderr: r.stderr || '' };
};

(isWindows ? describe : describe.skip)('目录级 ACL 收紧不得清空子文件 DACL', () => {
  test('递归 reset 后子文件仍可读写，且显式 Everyone ACE 被清除', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dirperm-'));
    const child = path.join(dir, 'child.log');
    fs.writeFileSync(child, 'before\n');
    try {
      expect(execIcacls([child, '/grant', '*S-1-1-0:(R)']).status).toBe(0);

      const res = hardenPath(dir, { isDir: true });
      expect(res.ok).toBe(true);

      // 这一句就是本用例的核心：修复前这里 EPERM
      expect(fs.readFileSync(child, 'utf8')).toBe('before\n');
      expect(() => fs.writeFileSync(child, 'after\n')).not.toThrow();

      const acl = execIcacls([child]);
      expect(acl.stdout).not.toMatch(/Everyone/i);
      expect(acl.stdout).not.toMatch(/S-1-1-0/);
      expect(verifyHardened(child).tightened).toBe(true);
      expect(verifyHardened(dir).tightened).toBe(true);
    } finally {
      try {
        execIcacls([dir, '/reset', '/T', '/C']);
      } catch {
        /* 清理失败不影响断言结果 */
      }
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
