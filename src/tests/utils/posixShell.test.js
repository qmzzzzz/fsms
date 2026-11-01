'use strict';

/**
 * 测试用 POSIX shell 解析（src/tests/helpers/posixShell.js）的行为判据
 *
 * 判据必须是**行为**而不是"文件在不在"——本仓踩过的坑正是「存在但跑不通」：Windows 上
 * C:\Windows\system32\bash.exe 是 WSL 启动桩，没装发行版时它存在、退出码非 0、什么也不执行。
 * 于是三道判据：
 *  ① 正向：解析出的 shell 真的具备 shell 语义（算术 / 管道 / stderr / 退出码透传）；
 *  ② 反向对照：拿"存在、可执行、但没有 -c 语义"的可执行文件（node 本体）当候选，探针必须
 *     判否——否则本模块就退化成"能起进程就算可用"，WSL 桩那类候选会一路放行；
 *  ③ fail-closed：显式指定 FSMS_TEST_SHELL 却不可用时必须抛错，不许静默换一个 shell 顶上
 *     （"以为在真跑"是本仓最忌讳的失效形态）。
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const {
  SHELL_OVERRIDE_ENV,
  SHELL_SOURCE_ENV,
  probeShell,
  resolveShell,
  ensureShellOnPath,
} = require('../helpers/posixShell');

const resolved = resolveShell();

/** 环境对象里 PATH 键的实际拼写（Windows 上常是 Path） */
function pathKeyOf(env) {
  return Object.keys(env).find((k) => k.toUpperCase() === 'PATH') || 'PATH';
}

/** 用解析出的 shell 跑一段脚本，返回退出码与两个流 */
function runWith(shell, script, env = process.env) {
  const r = spawnSync(shell.cmd, ['-c', script], {
    encoding: 'utf8',
    env,
    windowsHide: true,
    timeout: 20000,
  });
  return { status: r.status, stdout: String(r.stdout || ''), stderr: String(r.stderr || '') };
}

describe('测试用 POSIX shell 解析', () => {
  test('反向对照：没有 -c 语义的可执行文件必须被判否（探针不是"能起进程就算过"）', () => {
    // node 本体：文件存在、能执行、退出码 0，但 -c 不是它的选项 ⇒ 拿不回探针标记
    expect(probeShell(process.execPath)).toBe(false);
  });

  test('反向对照：会把参数原样回显的可执行文件必须被判否（echo.exe 形态的假阳性）', () => {
    // 实测形态：MSYS 的 `echo.exe` 拿到 `-c printf '%s' FSMS_POSIX_SHELL_OK` 会把整串参数打出来，
    // stdout 里于是**包含**标记，而它根本不是 shell。旧判据用 includes ⇒ 判真，
    // 探针退化成「能起进程就算可用」。这里用 node 跑一个只回显 argv 的桩，跨平台复现同一形态。
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'echo-like-'));
    try {
      const stub = path.join(dir, 'echo-like.js');
      fs.writeFileSync(stub, "process.stdout.write(process.argv.slice(2).join(' '));\n");
      expect(probeShell(process.execPath, [stub])).toBe(false);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  test('前提自证：探针对真 shell 判真；本机确实没有可用 shell 时如实记录，不假装通过', () => {
    if (!resolved) {
      console.warn(
        '[posixShell] 本机没有可用的 POSIX shell：shell 族门禁将整族红，属环境缺失而非代码缺陷。'
      );
      expect(resolved).toBeNull();
      return;
    }
    expect(probeShell(resolved.cmd)).toBe(true);
    expect(['override', 'git-bash', 'path', 'posix']).toContain(resolved.source);
  });

  test('正向：解析出的 shell 具备 shell 语义（算术 / 管道 / stderr / 退出码）', () => {
    if (!resolved) return;
    const r = runWith(
      resolved,
      "printf '%s' \"$((6*7))\"; printf 'a' | tr a b; printf 'E' >&2; exit 7"
    );
    expect(r.stdout).toBe('42b');
    expect(r.stderr).toBe('E');
    expect(r.status).toBe(7);
  });

  test('fail-closed：显式指定的 shell 不可用必须抛错，不许静默回退到别的 shell', () => {
    expect(() => resolveShell({ [SHELL_OVERRIDE_ENV]: 'C:/definitely/not/a/bash.exe' })).toThrow(
      /FSMS_TEST_SHELL/
    );
    // 存在且可执行、但没有 -c 语义 ⇒ 同样必须抛错（只看"文件在不在"是本判据的失效形态）
    expect(() => resolveShell({ [SHELL_OVERRIDE_ENV]: process.execPath })).toThrow(
      /FSMS_TEST_SHELL/
    );
  });

  test('幂等：ensureShellOnPath 重复调用不重复插 PATH，且把来源落进环境变量', () => {
    if (!resolved) return;
    const env = { ...process.env };
    const key = pathKeyOf(env);
    const first = ensureShellOnPath(env);
    const pathAfterFirst = env[key];
    const second = ensureShellOnPath(env);

    expect(second.cmd).toBe(first.cmd);
    expect(env[key]).toBe(pathAfterFirst);
    expect(env[SHELL_OVERRIDE_ENV]).toBe(first.cmd);
    expect(env[SHELL_SOURCE_ENV]).toBe(first.source);
    if (first.dir) {
      const hits = String(env[key])
        .split(require('path').delimiter)
        .filter((d) => d === first.dir);
      expect(hits).toHaveLength(1);
      expect(String(env[key]).split(require('path').delimiter)[0]).toBe(first.dir);
    }
  });

  test('端到端：本进程里裸命令 bash 已经命中可用 shell（既有用例不改一行也能跑）', () => {
    if (!resolved) return;
    const r = spawnSync('bash', ['-c', "printf '%s' shell-ok"], {
      encoding: 'utf8',
      timeout: 20000,
      windowsHide: true,
    });
    expect(String(r.stdout || '')).toBe('shell-ok');
    expect(r.status).toBe(0);
  });
});
