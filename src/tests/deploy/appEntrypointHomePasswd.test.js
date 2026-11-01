/**
 * 入口脚本「按 nodejs 重设 HOME」的去外部命令化（第十二轮 D8）
 *
 * 缺陷形态（本仓反复修的那一族）：`nodejs_home=$(grep '^nodejs:' /etc/passwd | cut -d: -f6)`。
 * 管道里两个外部命令，任一缺失或被 PATH 上的同名桩顶替时——
 *   · 命令替换只留空串，`set -e` **不会**触发（管道退出码取最后一个命令，cut 对空输入照样 0）；
 *   · 于是 HOME 保持 /root，EACCES 推迟到某个要写缓存的工具上，日志里一个字都没有；
 *   · 且「grep 失败」与「真的没有 nodejs 用户」在返回值上不可区分。
 *
 * 判据分三层，缺一层这个修复就可能是"看起来修了"：
 *  ① 行为级：真跑抽出来的函数体，喂三份夹具（有 nodejs 行 / 没有 / home 为空）；
 *  ② 「无外部命令」：PATH 里根本没有 grep/cut、以及桩 grep 返回 0 但输出空，都必须照常得到 home；
 *  ③ 文本级：脚本里不再出现 grep/cut（防改回去），且保留 `export HOME="$nodejs_home"` 形状。
 */
'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const { resolveShell } = require('../helpers/posixShell');
const { toPosixPath } = require('../helpers/stubPath');

const ROOT = path.resolve(__dirname, '../../..');
const ENTRYPOINT = path.join(ROOT, 'docker', 'app-entrypoint.sh');
const BASH = (resolveShell() || { cmd: null }).cmd;
const group = BASH ? describe : describe.skip;

if (!BASH && process.env.CI) {
  // 与 appEntrypointQueuePermFallback.test.js 同口径：CI 上探不到 POSIX shell 即为探测失效 ⇒ 红
  describe('app-entrypoint HOME 用例的平台前提（CI 上缺 POSIX shell）', () => {
    test('resolveShell 必须解析到可用的 POSIX shell', () => {
      expect(BASH).toBeTruthy();
    });
  });
}

/** 脚本源码去掉整行注释：注释里会出现 grep/cut 的对照文本，不能参与"禁止"判定 */
const codeOnly = (src) =>
  src
    .split(/\r?\n/)
    .filter((l) => !/^\s*#/.test(l))
    .join('\n');

/**
 * 抽出 set_nodejs_home 整段（声明 + 函数体 + 收尾 }），从脚本原文取，不另抄一份。
 * 必须是**整段**：只取函数体注入会得到 "set_nodejs_home: command not found"，
 * 于是「没有 nodejs 行必须非零退出」等用例会被命令缺失假绿——判据测的就不是被测实现了。
 */
function extractHomeFn() {
  const src = fs.readFileSync(ENTRYPOINT, 'utf8');
  const m = /^set_nodejs_home\(\) \{\n[\s\S]*?^\}/m.exec(src);
  expect(m).toBeTruthy();
  return m[0];
}

/** 夹具：root 行必须在，用来证明不会误取 root 的 home */
const ROOT_LINE = 'root:x:0:0:root:/root:/bin/sh';
const withNodejs = [ROOT_LINE, 'nodejs:x:1001:1001:nodejs:/home/nodejs:/sbin/nologin', ''].join(
  '\n'
);
const withoutNodejs = [ROOT_LINE, 'app:x:1002:1002:app:/home/app:/bin/sh', ''].join('\n');
const emptyHome = [ROOT_LINE, 'nodejs:x:1001:1001:nodejs::/sbin/nologin', ''].join('\n');

/**
 * 跑一遍抽出来的函数。
 * @param {string} fixtureText /etc/passwd 的替身内容
 * @param {{noExternal?:boolean, stubGrep?:boolean}} opts
 *   noExternal：子 shell 的 PATH 只有一个空目录（grep/cut 都不存在）
 *   stubGrep：PATH 最前面放一个"返回 0 但输出空"的 grep 桩（模拟被同名桩顶替）
 * @returns {{status:number|null, out:string}}
 */
function runHome(fixtureText, opts = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'entrypoint-home-'));
  try {
    // 必须用 toPosixPath：把 C:\\… 直接换成 C:/… 在 MSYS 的 PATH 里**不是**可执行目录，
    // 桩会被静默忽略（实测：stub 已 chmod 755 也照样命中 /usr/bin/grep）。
    // 这条坑记录在 helpers/stubPath.js 顶部，本文件复用同一份实现而不是自己写一个。
    const posix = toPosixPath;
    const passwd = path.join(dir, 'passwd');
    fs.writeFileSync(passwd, fixtureText, 'utf8');
    const emptyDir = path.join(dir, 'empty-path');
    fs.mkdirSync(emptyDir, { recursive: true });
    // 函数里读的是字面量 /etc/passwd：替换成夹具路径（只在测试的这份副本上替换）
    const fn = extractHomeFn().replace(/\/etc\/passwd/g, '"$PASSWD_FILE"');
    const prelude = [];
    if (opts.noExternal) prelude.push(`PATH=${posix(emptyDir)}; export PATH;`);
    if (opts.stubGrep) {
      const stubDir = path.join(dir, 'stub-bin');
      fs.mkdirSync(stubDir, { recursive: true });
      const stub = path.join(stubDir, 'grep');
      // 返回 0 且什么都不输出：正是"被 PATH 上的同名桩顶替"的形态
      fs.writeFileSync(stub, '#!/bin/sh\nexit 0\n', { mode: 0o755 });
      try {
        fs.chmodSync(stub, 0o755);
      } catch (_) {
        /* Windows 上 chmod 是空操作，靠 shebang + MSYS 语义 */
      }
      prelude.push(`PATH=${posix(stubDir)}:"$PATH"; export PATH;`);
    }
    const script = [
      'set -eu',
      `PASSWD_FILE=${posix(passwd)}`,
      ...prelude,
      fn,
      'HOME=/root',
      'export HOME',
      'set_nodejs_home',
      'printf \'HOME=%s\\n\' "$HOME"',
      'printf \'USER=%s\\n\' "$USER"',
      'printf \'LOGNAME=%s\\n\' "$LOGNAME"',
    ].join('\n');
    const r = spawnSync(BASH, ['-c', script], { encoding: 'utf8', timeout: 30000 });
    return { status: r.status, out: String(r.stdout || '') + String(r.stderr || '') };
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

group('docker/app-entrypoint.sh：HOME 重设不依赖任何外部命令', () => {
  test('前提自证：抽出的是完整函数段（声明 + 体 + 收尾），且含 HOME 重设', () => {
    const fn = extractHomeFn();
    expect(fn.startsWith('set_nodejs_home() {')).toBe(true);
    expect(fn.trimEnd().endsWith('}')).toBe(true);
    expect(fn).toMatch(/nodejs_home/);
    expect(fn).toMatch(/export HOME="\$nodejs_home"/);
    // 抽取真的能跟着实现走：把实现换成写死的赋值，这段断言就会失配（证明不是写死文本）
    expect(fn).toMatch(/\/etc\/passwd/);
  });

  test('有 nodejs 行 ⇒ HOME 取其 home（root 行不得被误取）', () => {
    const r = runHome(withNodejs);
    expect(r.out).toContain('HOME=/home/nodejs');
    expect(r.out).toContain('USER=nodejs');
    expect(r.out).toContain('LOGNAME=nodejs');
    expect(r.out).not.toContain('HOME=/root');
    expect(r.status).toBe(0);
  });

  test('没有 nodejs 行 ⇒ 明确报错并退出（fail-closed，不得留 /root 的 HOME）', () => {
    const r = runHome(withoutNodejs);
    expect(r.status).not.toBe(0);
    expect(r.out).toMatch(/nodejs/);
    expect(r.out).toMatch(/home/i);
    expect(r.out).not.toContain('HOME=/root');
  });

  test('nodejs 行 home 为空 ⇒ 同上（空 HOME 与没有 home 是同一种失败）', () => {
    const r = runHome(emptyHome);
    expect(r.status).not.toBe(0);
    expect(r.out).not.toContain('HOME=/root');
  });

  test('PATH 里没有 grep/cut ⇒ 照常解析出 home（旧实现此处静默拿空串）', () => {
    const r = runHome(withNodejs, { noExternal: true });
    expect(r.out).toContain('HOME=/home/nodejs');
    expect(r.status).toBe(0);
  });

  test('桩 grep 返回 0 但输出空 ⇒ 照常解析出 home（被同名桩顶替不得改变结论）', () => {
    const r = runHome(withNodejs, { stubGrep: true });
    expect(r.out).toContain('HOME=/home/nodejs');
    expect(r.status).toBe(0);
  });

  test('文本级：脚本代码里不再出现 grep / cut，且用 IFS=: read 读 passwd', () => {
    const code = codeOnly(fs.readFileSync(ENTRYPOINT, 'utf8'));
    // 自指先证：剥离注释真的生效（注释里本就该能写 grep/cut 做对照说明）
    expect(code).not.toMatch(/^\s*#/m);
    expect(code).not.toMatch(/\bgrep\b/);
    expect(code).not.toMatch(/\bcut\b/);
    expect(code).toMatch(/IFS=: read/);
    // 旧形状的形状断言保留：新的实现里 export HOME 仍在
    expect(code).toMatch(/export HOME="\$nodejs_home"/);
    expect(code).toMatch(/export USER=nodejs/);
    expect(code).toMatch(/export LOGNAME=nodejs/);
  });
});
