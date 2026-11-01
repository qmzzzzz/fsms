'use strict';

/**
 * CI 的 mongod 预置步骤：失败必须**中止这一步**，不许"绿着往环境里写空值"
 *
 * 缺陷形态（本机实测）：run 体写成
 *   `echo "MONGOMS_SYSTEM_BINARY=$(node scripts/provision-mongod.js)" >> "$GITHUB_ENV"`
 * 这一行的退出码取 `echo` 自己的——命令替换失败对 `bash -e` 不可见。于是 provision 报错时：
 *   ① 步骤仍然是绿的；② 写进 `$GITHUB_ENV` 的是 `MONGOMS_SYSTEM_BINARY=`（空串）。
 * 而 mongodb-memory-server 的 MongoBinary 把空串当"未设置"，回落到自己下载一个**未经仓库
 * SHA-256 锚**的 mongod（globalSetup 为兼容镜像源还关掉了 checkMD5）——那份锚于是被静默
 * 穿透，且所有门禁都是绿的：最需要它说话的场景里它不说话。
 *
 * 判据不扫文本，而是**把这一步的脚本体抽出来真跑**（与 workflowShellSyntax 的取值方式同源）：
 *   · 桩 node 失败 ⇒ 步骤必须非零退出，且一个 MONGOMS_SYSTEM_BINARY 行都不许写进 $GITHUB_ENV；
 *   · 桩 node 成功 ⇒ 步骤零退出并写入路径（正向对照：证明抽取 + 执行不是空转）；
 *   · 前世版自证：把旧写法喂给同一夹具 ⇒ 0 退出并写下空值，证明本闸确实抓得住这个坑。
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const { resolveShell } = require('../helpers/posixShell');
const { stubPathPreamble, toPosixPath } = require('../helpers/stubPath');

const ROOT = path.resolve(__dirname, '../../..');
const CI = path.join(ROOT, '.github', 'workflows', 'ci.yml');
const STEP_NAME = 'Provision SHA-256 pinned mongod';

const BASH = (resolveShell() || { cmd: null }).cmd;
const group = BASH ? describe : describe.skip;

if (!BASH && process.env.CI) {
  // 同 imageDigestGate.test.js:80-89 的口径：CI ubuntu 必有 bash，探不到即为探测失效 ⇒ 红。
  describe('ci.yml 预置步骤的平台前提（CI 上缺 POSIX shell）', () => {
    test('CI 上 resolveShell 必须解析到可用的 POSIX shell，否则本文件全部覆盖都是假的', () => {
      expect(BASH).toBeTruthy();
    });
  });
}
if (!BASH) {
  console.warn('[跳过] 未找到可用的 POSIX shell：ci.yml 预置步骤的失败传播判据无法执行（CI 会跑）');
}

/** 抽出名为 STEP_NAME 的每个步骤的 run 体（块标量与单行两种写法） */
function extractStepRuns(yaml, stepName) {
  const escaped = stepName.replace(/[.*+?^$|\\[\]()]/g, '\\$&');
  const nameRe = new RegExp('^\\s*-\\s*name:\\s*' + escaped + '\\s*$');
  const lines = yaml.split(/\r?\n/);
  const out = [];
  for (let i = 0; i < lines.length; i++) {
    if (!nameRe.test(lines[i])) continue;
    for (let j = i + 1; j < lines.length; j++) {
      if (/^\s*-\s*name:/.test(lines[j])) break;
      const m = /^(\s*)run:\s*(.*)$/.exec(lines[j]);
      if (!m) continue;
      const indent = m[1].length;
      const rest = m[2].trim();
      if (/^[|>]/.test(rest)) {
        const body = [];
        for (let k = j + 1; k < lines.length; k++) {
          if (lines[k].trim() === '') {
            body.push('');
            continue;
          }
          if (lines[k].search(/\S/) <= indent) break;
          body.push(lines[k]);
        }
        const first = body.find((l) => l.trim() !== '');
        const base = first ? first.search(/\S/) : indent + 2;
        out.push(body.map((l) => l.slice(base)).join('\n'));
      } else {
        out.push(rest.replace(/^(['"])([\s\S]*)\1$/, '$2'));
      }
      break;
    }
  }
  return out;
}

const bodies = extractStepRuns(fs.readFileSync(CI, 'utf8'), STEP_NAME);

/**
 * 在隔离目录里真跑一段「步骤体」：PATH 最前面是桩 node（MSYS 会前置自己的目录，故必须在
 * 子 shell 内收口，见 helpers/stubPath.js），$GITHUB_ENV 指向本次临时文件。
 * 用 bash -e 起进程：GitHub Actions 的默认 shell 就是 bash -e，少了这个 -e 判据会宽于
 * 真实运行环境——而"宽于真实环境"正是这条缺陷赖以隐藏的条件。
 */
function runStepBody(body, opts) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ci-provision-'));
  try {
    const bin = path.join(dir, 'bin');
    fs.mkdirSync(bin);
    fs.writeFileSync(
      path.join(bin, 'node'),
      '#!/bin/bash\necho ' + opts.nodeOut + '\nexit ' + opts.nodeExit + '\n',
      { mode: 0o755 }
    );
    const envFile = path.join(dir, 'github_env');
    fs.writeFileSync(envFile, '');
    const r = spawnSync(BASH, ['-e', '-c', stubPathPreamble(bin) + body], {
      encoding: 'utf8',
      env: { ...process.env, GITHUB_ENV: toPosixPath(envFile) },
      // 超时兜底（A6/S3）：卡住的步骤要红在断言上，而不是把整条流水线拖到超时。
      timeout: 30000,
    });
    return {
      status: r.status,
      out: String(r.stdout || '') + String(r.stderr || ''),
      written: fs.readFileSync(envFile, 'utf8'),
    };
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

group('CI 的 mongod 预置步骤：provision 失败必须让步骤红', () => {
  test('前提自证：两个 job 都真的拿这一步锚定二进制（抽取与夹具不是空转）', () => {
    expect(bodies.length).toBeGreaterThanOrEqual(2);
    for (const b of bodies) {
      expect(b).toContain('scripts/provision-mongod.js');
      expect(b).toContain('MONGOMS_SYSTEM_BINARY=');
      expect(b).toContain('$GITHUB_ENV');
    }
  });

  test('正向对照：provision 成功 ⇒ 步骤零退出，且把二进制路径写进 $GITHUB_ENV', () => {
    for (const b of bodies) {
      const r = runStepBody(b, { nodeExit: 0, nodeOut: '/opt/mongod-8.0.34' });
      expect({ status: r.status, written: r.written.trim() }).toEqual({
        status: 0,
        written: 'MONGOMS_SYSTEM_BINARY=/opt/mongod-8.0.34',
      });
    }
  });

  test('判据：provision 失败 ⇒ 非零退出，且空值一个字节都不许进环境', () => {
    for (const b of bodies) {
      const r = runStepBody(b, { nodeExit: 3, nodeOut: '' });
      expect(r.status).not.toBe(0);
      // 空串是这条缺陷真正的祸首：MongoBinary 把它当"未设置"⇒ 回落到未校验下载
      expect(r.written).not.toMatch(/MONGOMS_SYSTEM_BINARY=/);
    }
  });

  /**
   * 「exit 0 但输出空」——2026-10-30 第二轮审计的缺陷 3：
   * 步骤里的 `test -n "$MONGOD"` 此前没有任何判据（删掉它整族仍绿）。
   * 而这正是本步骤自述的头号危害形态：provision 不报错、但什么都没打印（例如脚本提前 return、
   * 或 node 把路径打到了 stderr），于是写进 $GITHUB_ENV 的是空值，MongoBinary 把它当「未设置」
   * 回落到**未经仓库 SHA-256 锚**的下载 —— 锚被静默穿透，而所有门禁都是绿的。
   */
  test('判据：provision 退出 0 但输出空 ⇒ 步骤必须红，且不许写下空值', () => {
    for (const b of bodies) {
      const r = runStepBody(b, { nodeExit: 0, nodeOut: '' });
      expect(r.status).not.toBe(0);
      expect(r.written).not.toMatch(/MONGOMS_SYSTEM_BINARY=/);
    }
  });

  test('前世版自证：去掉 test -n 后「exit 0 + 空输出」绿着写下空值（本闸抓得住它）', () => {
    // 从抽取到的真实步骤体里把那一行判据删掉，其余一字不改 —— 反例必须来自同一份源码，
    // 否则测的是我抄的副本。
    const stripped = bodies.map((b) => b.replace(/^\s*test -n "\$MONGOD"\s*$/m, ''));
    for (const [i, b] of stripped.entries()) {
      expect({ i, changed: b !== bodies[i] }).toEqual({ i, changed: true });
      const r = runStepBody(b, { nodeExit: 0, nodeOut: '' });
      expect(r.status).toBe(0);
      expect(r.written).toMatch(/^MONGOMS_SYSTEM_BINARY=\s*$/m);
    }
  });

  test('前世版自证：旧的 echo "$(…)" 在同一夹具下绿着写下空值（本闸抓得住它）', () => {
    const legacy =
      'echo "MONGOMS_SYSTEM_BINARY=$(node scripts/provision-mongod.js)" >> "$GITHUB_ENV"';
    const r = runStepBody(legacy, { nodeExit: 3, nodeOut: '' });
    expect(r.status).toBe(0);
    expect(r.written).toMatch(/^MONGOMS_SYSTEM_BINARY=\s*$/m);
  });
});
