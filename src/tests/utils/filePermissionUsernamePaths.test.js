/**
 * filePermission 的用户名解析与 icacls 提示渲染分支。
 *
 * currentUsername 的四条取值臂（USERNAME / USER / os.userInfo / 全失败）与
 * show() 对含空格参数加引号的分支，此前从未被计数（branches 90.9% < 92%）。
 * icacls 执行失败用注入的 execFileSync 触发，不打真实 ACL。
 */
jest.mock('child_process', () => {
  const real = jest.requireActual('child_process');
  const state = { impl: null };
  const execFileSync = (...args) => (state.impl ? state.impl(...args) : real.execFileSync(...args));
  execFileSync.__setImpl = (impl) => {
    state.impl = impl;
  };
  return { ...real, execFileSync };
});

const os = require('os');
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');
const { hardenPath, currentUsername, isWindows } = require('../../utils/filePermission');

const ENV_KEYS = ['USERNAME', 'USER'];

describe('currentUsername 的取值臂', () => {
  const saved = {};
  beforeAll(() => {
    for (const k of ENV_KEYS) saved[k] = process.env[k];
  });
  afterAll(() => {
    for (const k of ENV_KEYS) {
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k];
    }
  });

  test('USERNAME 优先于 USER', () => {
    process.env.USERNAME = 'alice';
    process.env.USER = 'bob';
    expect(currentUsername()).toBe('alice');
  });

  test('只有 USER 时用 USER', () => {
    delete process.env.USERNAME;
    process.env.USER = 'bob';
    expect(currentUsername()).toBe('bob');
  });

  test('两者皆缺时回落 os.userInfo().username', () => {
    delete process.env.USERNAME;
    delete process.env.USER;
    const spy = jest.spyOn(os, 'userInfo').mockReturnValue({ username: 'carol' });
    expect(currentUsername()).toBe('carol');
    spy.mockRestore();
  });

  test('userInfo 返回空名继续落到空串（fail-closed）', () => {
    delete process.env.USERNAME;
    delete process.env.USER;
    const spy = jest.spyOn(os, 'userInfo').mockReturnValue({ username: '' });
    expect(currentUsername()).toBe('');
    spy.mockRestore();
  });

  test('userInfo 抛错（无 passwd 条目）也落到空串', () => {
    delete process.env.USERNAME;
    delete process.env.USER;
    const spy = jest.spyOn(os, 'userInfo').mockImplementation(() => {
      throw new Error('no passwd entry');
    });
    expect(currentUsername()).toBe('');
    spy.mockRestore();
  });
});

describe('hardenPath 的提示渲染', () => {
  test('含空格的路径在失败提示里被加引号（可直接粘贴）', () => {
    if (!isWindows) return;
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'fsms acl space '));
    try {
      execFileSync.__setImpl(() => {
        throw new Error('注入的 icacls 失败');
      });
      const logs = [];
      const result = hardenPath(dir, { isDir: true, recursive: true, log: (m) => logs.push(m) });
      expect(result.ok).toBe(false);
      expect(result.detail).toBe('注入的 icacls 失败');
      const hint = logs.find((m) => m.includes('请手动执行'));
      expect(hint).toContain('icacls "' + dir + '"');
      expect(hint).toContain('/reset');
      expect(hint).toContain('/inheritance:r');
    } finally {
      execFileSync.__setImpl(null);
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
