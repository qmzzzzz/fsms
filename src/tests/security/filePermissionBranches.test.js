/**
 * M-05 补漏：filePermission.js 的失败路径与跨平台分支覆盖
 *
 * 为什么这些分支必须被覆盖：本模块是 M-05 的信任根——「密钥载体权限已收紧」
 * 这一结论的唯一来源。它的**失败路径**恰恰是安全语义的关键处：
 *   - icacls 执行失败 → 必须 ok=false 并打印可操作命令（否则用户以为已收紧）；
 *   - 用户名缺失 → 必须跳过而非盲目执行（否则可能授予了错误的账户）；
 *   - icacls 读不出结果 → 必须 fail-closed 判「未收紧」（否则未收紧被当成已收紧）。
 * 这些分支此前全部未被任何测试触达（覆盖率实测 67.34% 行 / 68.42% 分支，
 * 未覆盖集合正是 45-51、58-59、69-72、103-105、115 行）。
 *
 * 平台分支的触发方式：模块的 isWindows 是**加载期常量**，只有临时改写
 * process.platform 并 isolateModules 重新 require 才能走到另一条分支。
 * 所有子进程调用均被 spy 拦截，不会真实执行 icacls/chmod 之外的动作。
 */
const fs = require('fs');
const os = require('os');
const path = require('path');
const cp = require('child_process');

const MODULE = '../../utils/filePermission';

/** 在指定平台上重新加载模块（spoof 仅在 require 期间生效） */
function loadOn(platform) {
  const desc = Object.getOwnPropertyDescriptor(process, 'platform');
  let mod;
  Object.defineProperty(process, 'platform', { value: platform, configurable: true });
  try {
    jest.isolateModules(() => {
      mod = require(MODULE);
    });
  } finally {
    Object.defineProperty(process, 'platform', desc);
  }
  return mod;
}

function withTempDir(fn) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'm05b-'));
  try {
    return fn(dir);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

describe('M-05 补漏：filePermission 失败路径', () => {
  it('icacls 执行失败 → ok=false 且打印可操作的手动命令（不得静默）', () => {
    withTempDir((dir) => {
      const spy = jest.spyOn(cp, 'execFileSync').mockImplementation(() => {
        throw new Error('icacls-boom');
      });
      const mod = loadOn('win32');
      const logs = [];
      let r;
      try {
        r = mod.hardenPath(dir, { isDir: true, log: (m) => logs.push(m) });
      } finally {
        spy.mockRestore();
      }
      expect(r.ok).toBe(false);
      expect(r.method).toBe('icacls');
      expect(r.detail).toContain('icacls-boom');
      // 告警必须含「怎么做」，只报错不给出路等于把问题留给用户猜
      expect(logs.join('\n')).toContain('请手动执行');
      expect(logs.join('\n')).toContain('/inheritance:r');
    });
  });

  it('无法确定用户名 → 跳过收紧而非盲目执行，且不调用 icacls', () => {
    withTempDir((dir) => {
      const savedUser = process.env.USERNAME;
      const savedUser2 = process.env.USER;
      const spy = jest.spyOn(cp, 'execFileSync');
      const mod = loadOn('win32');
      const logs = [];
      let r;
      try {
        delete process.env.USERNAME;
        delete process.env.USER;
        r = mod.hardenPath(dir, { isDir: true, log: (m) => logs.push(m) });
      } finally {
        if (savedUser === undefined) delete process.env.USERNAME;
        else process.env.USERNAME = savedUser;
        if (savedUser2 === undefined) delete process.env.USER;
        else process.env.USER = savedUser2;
        spy.mockRestore();
      }
      expect(r.ok).toBe(false);
      expect(r.detail).toBe('USERNAME 未定义');
      expect(logs.join('\n')).toContain('跳过 ACL 收紧');
      // 关键：未确定用户名时**不得**执行 icacls（否则可能把 ACL 授予错误账户）
      expect(spy).not.toHaveBeenCalled();
    });
  });

  it('POSIX：hardenPath 走 chmod 路径（目录 0700 / 文件 0600）', () => {
    withTempDir((dir) => {
      const mod = loadOn('linux');
      const rDir = mod.hardenPath(dir, { isDir: true });
      expect(rDir.ok).toBe(true);
      expect(rDir.method).toBe('chmod');
      expect(rDir.detail).toContain('0700');

      const file = path.join(dir, 'secret.key');
      fs.writeFileSync(file, 'x');
      const rFile = mod.hardenPath(file, { isDir: false });
      expect(rFile.method).toBe('chmod');
      expect(rFile.detail).toContain('0600');
    });
  });

  it('POSIX：chmod 抛错时 ok=false 且不抛异常（best-effort 契约）', () => {
    withTempDir((dir) => {
      const spy = jest.spyOn(fs, 'chmodSync').mockImplementation(() => {
        throw new Error('chmod-boom');
      });
      const mod = loadOn('linux');
      const logs = [];
      let r;
      try {
        r = mod.hardenPath(dir, { isDir: true, log: (m) => logs.push(m) });
      } finally {
        spy.mockRestore();
      }
      expect(r.ok).toBe(false);
      expect(r.method).toBe('chmod');
      expect(logs.join('\n')).toContain('chmod 失败');
    });
  });

  it('POSIX：verifyHardened 按 mode 精确判定（与宿主真实 mode 一致）', () => {
    withTempDir((dir) => {
      const mod = loadOn('linux');
      fs.chmodSync(dir, 0o700);
      const actual = fs.statSync(dir).mode & 0o777;
      const r = mod.verifyHardened(dir);
      // 期望值由**实际读到的 mode** 推导：POSIX 上 chmod 生效 → true；
      // 在 Windows 宿主上 chmod 是空操作（mode 恒为 0o666）→ false。
      // 这样同一断言在两种宿主上都有意义，而不是被硬编码为某一平台的结果。
      expect(r.tightened).toBe(actual === 0o700);
      expect(r.evidence).toMatch(/mode=[0-7]+（期望 700）/);
    });
  });

  it('verifyHardened：icacls 读取失败 → fail-closed 判未收紧', () => {
    withTempDir((dir) => {
      const spy = jest.spyOn(cp, 'execFileSync').mockImplementation(() => {
        throw new Error('read-boom');
      });
      const mod = loadOn('win32');
      let r;
      try {
        r = mod.verifyHardened(dir);
      } finally {
        spy.mockRestore();
      }
      expect(r.tightened).toBe(false);
      expect(r.evidence).toContain('icacls 读取失败');
    });
  });

  it('verifyHardened：icacls 输出解析不出任何主体 → fail-closed（假阴性最危险）', () => {
    withTempDir((dir) => {
      const spy = jest.spyOn(cp, 'execFileSync').mockReturnValue('');
      const mod = loadOn('win32');
      let r;
      try {
        r = mod.verifyHardened(dir);
      } finally {
        spy.mockRestore();
      }
      expect(r.tightened).toBe(false);
      expect(r.evidence).toContain('未能解析出任何 ACE 主体');
    });
  });

  it('verifyHardened：能识别组账户 ACE（未收紧的典型 icacls 输出）', () => {
    withTempDir((dir) => {
      // 取真实 icacls 输出的形态：主体与权限之间用 ':' 分隔，行首含路径
      const fakeOut = [
        dir + ' BUILTIN\\Users:(I)(RX)',
        '        BUILTIN\\Administrators:(I)(F)',
        '        NT AUTHORITY\\SYSTEM:(I)(F)',
        '        CodexSandboxUsers:(I)(M)',
      ].join('\r\n');
      const spy = jest.spyOn(cp, 'execFileSync').mockReturnValue(fakeOut);
      const mod = loadOn('win32');
      let r;
      try {
        r = mod.verifyHardened(dir);
      } finally {
        spy.mockRestore();
      }
      expect(r.tightened).toBe(false);
      // 三类都应被识别：Users、Administrators、sandbox 前缀组
      expect(r.evidence).toMatch(/可疑 3 条|可疑 4 条/);
    });
  });

  it('icacls 失败提示中的权限串随文件/目录变化（文件用 F，目录用 (OI)(CI)F）', () => {
    withTempDir((dir) => {
      const spy = jest.spyOn(cp, 'execFileSync').mockImplementation(() => {
        throw new Error('boom');
      });
      const mod = loadOn('win32');
      const logs = [];
      const file = path.join(dir, 'x.key');
      fs.writeFileSync(file, 'k'); // 必须先存在，否则 hardenPath 提前返回（不存在的路径不触发 icacls）
      let r;
      try {
        r = mod.hardenPath(file, { isDir: false, log: (m) => logs.push(m) });
      } finally {
        spy.mockRestore();
      }
      expect(r.ok).toBe(false);
      // 文件级提示不得带继承标志（(OI)(CI) 只对目录有意义）
      expect(logs.join('\n')).toMatch(/grant:r "%USERNAME%:F"/);
      expect(logs.join('\n')).not.toContain('(OI)(CI)F');
    });
  });

  it('POSIX：verifyHardened 对文件按 0600 判定（目录另一分支）', () => {
    withTempDir((dir) => {
      const mod = loadOn('linux');
      const file = path.join(dir, 'secret.key');
      fs.writeFileSync(file, 'x');
      fs.chmodSync(file, 0o600);
      const actual = fs.statSync(file).mode & 0o777;
      const r = mod.verifyHardened(file);
      expect(r.tightened).toBe(actual === 0o600);
      expect(r.evidence).toMatch(/（期望 600）/);
    });
  });

  it('不传 log 回调时不崩溃（默认空实现）', () => {
    withTempDir((dir) => {
      const spy = jest.spyOn(cp, 'execFileSync').mockImplementation(() => {
        throw new Error('boom');
      });
      const mod = loadOn('win32');
      let r;
      try {
        r = mod.hardenPath(dir, { isDir: true });
      } finally {
        spy.mockRestore();
      }
      expect(r.ok).toBe(false);
    });
  });
});
