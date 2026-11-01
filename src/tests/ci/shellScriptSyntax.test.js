/**
 * 仓库 shell 脚本的**语法闸**（A6/S4，2026-10-30）
 *
 * 为什么值得一个门禁：`docker/app-entrypoint.sh` 的 shebang 是 `#!/bin/sh`，容器里由 dash 执行；
 * 它一旦有语法错误，后果不是"某个用例红"，而是**容器起不来**——而那要等到下一次部署或热升级才发现。
 * 仓库此前只有 workflow 的 `run:` 块有 `bash -n` 闸（workflowShellSyntax.test.js），
 * 脚本本体一个语法判据都没有：改坏一个 `if`/`fi` 全靠人眼。
 *
 * 判据口径：
 *   1. 每份**已入库**的 `*.sh` 都必须有 shebang，且 shebang 只能是 sh / bash 家族；
 *   2. 用 shebang **指定的那个解释器**跑 `-n`（语法解析，不执行）：`#!/bin/sh` 用 `sh -n`，
 *      `#!/bin/bash`（含 `env bash`）用 `bash -n`。这一条是本闸的重点——
 *      拿 bash 去检查一份要跑在 dash 下的脚本，会把 bash 专有语法当成"合法"；
 *   3. 同一套判据必须能**判否**：临时造一份有语法错误的脚本，同一条路径必须报红。
 *
 * 反向自证（③）用的是与真实判据**同一个** checkScript()，避免"自证的是一套逻辑、产品用的是另一套"。
 */

'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const ROOT = path.resolve(__dirname, '../../..');

/** 只取已入库的文件：未跟踪的草稿/探针不该决定门禁红绿（仓根下另有 work/ 之类的临时目录） */
function trackedShellScripts() {
  const r = spawnSync('git', ['ls-files', '*.sh'], { cwd: ROOT, encoding: 'utf8', timeout: 20000 });
  if (r.status !== 0) {
    throw new Error(
      `夹具前提失效：git ls-files 未能列出 *.sh（status=${r.status}）：${r.stderr || ''}`
    );
  }
  return String(r.stdout || '')
    .split(/\r?\n/)
    .filter(Boolean);
}

/**
 * 按 shebang 选解释器。返回 null 表示"这份文件的 shebang 不在本闸约定的范围内"。
 * @param {string} text
 * @returns {{interpreter: string, args: string[]} | null}
 */
function interpreterFor(text) {
  const first = String(text).split(/\r?\n/, 1)[0];
  const m = /^#!\s*(\S+)(?:\s+(\S+))?/.exec(first);
  if (!m) return null;
  const bin = m[1];
  const arg = m[2] || '';
  const name = path.basename(bin);
  if (name === 'sh' || name === 'dash') return { interpreter: 'sh', args: [] };
  if (name === 'bash') return { interpreter: 'bash', args: [] };
  if (name === 'env') {
    const envName = path.basename(arg);
    if (envName === 'sh' || envName === 'dash') return { interpreter: 'sh', args: [] };
    if (envName === 'bash') return { interpreter: 'bash', args: [] };
  }
  return null;
}

/**
 * 语法检查一份脚本。**真实判据与反向自证共用这一条路径。**
 * @returns {{ok: boolean, interpreter: string, detail: string}}
 */
function checkScript(absPath) {
  const text = fs.readFileSync(absPath, 'utf8');
  const picked = interpreterFor(text);
  if (!picked) {
    return {
      ok: false,
      interpreter: '(no shebang)',
      detail: '缺少 shebang，或 shebang 不在 sh/bash 家族内',
    };
  }
  const r = spawnSync(picked.interpreter, [...picked.args, '-n', absPath], {
    cwd: ROOT,
    encoding: 'utf8',
    timeout: 20000,
  });
  if (r.error) {
    return {
      ok: false,
      interpreter: picked.interpreter,
      detail: `解释器未能启动：${r.error.message}`,
    };
  }
  const detail = `${r.stdout || ''}${r.stderr || ''}`.trim();
  return { ok: r.status === 0, interpreter: picked.interpreter, detail };
}

describe('仓库 shell 脚本语法闸（sh -n / bash -n，按 shebang 选解释器）', () => {
  test('前提自证：清单非空、且点名的那几份关键脚本都在里面', () => {
    const files = trackedShellScripts();
    expect(files.length).toBeGreaterThanOrEqual(7);
    for (const must of [
      'docker/app-entrypoint.sh',
      'scripts/mongoUri.sh',
      'scripts/capture-image-digests.sh',
      'scripts/backup-mongo.sh',
      'scripts/restore-mongo.sh',
    ]) {
      expect(files).toContain(must);
    }
  });

  test('反向自证：同一套判据对一份语法错误的脚本必须报红（否则下面的绿是白给的）', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'shellsyntax-'));
    try {
      const broken = path.join(dir, 'broken.sh');
      // 一份"少一个 fi"的真脚本：`if` 开了没有收尾
      fs.writeFileSync(broken, '#!/bin/sh\nif [ 1 -eq 1 ]; then\n  echo yes\n', 'utf8');
      const r = checkScript(broken);
      expect(r.interpreter).toBe('sh');
      expect(r.ok).toBe(false);
      expect(r.detail).not.toBe('');

      // 正向：同一目录里一份**语法正确**的脚本必须过（证明上面那条红的是语法而非路径/权限）
      const fine = path.join(dir, 'fine.sh');
      fs.writeFileSync(fine, '#!/bin/sh\nif [ 1 -eq 1 ]; then\n  echo yes\nfi\n', 'utf8');
      expect(checkScript(fine).ok).toBe(true);

      // shebang 不认识时必须判否，而不是"跳过"（静默跳过等于没有闸）
      const noShebang = path.join(dir, 'plain.sh');
      fs.writeFileSync(noShebang, 'echo hi\n', 'utf8');
      expect(checkScript(noShebang).ok).toBe(false);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  test('每份已入库的 .sh 都能通过其 shebang 指定的解释器的 -n 检查', () => {
    const bad = [];
    for (const rel of trackedShellScripts()) {
      const r = checkScript(path.join(ROOT, rel));
      if (!r.ok) bad.push(`${rel} [${r.interpreter}] ${r.detail}`.trim());
    }
    expect(bad).toEqual([]);
  });

  test('docker/app-entrypoint.sh 必须按 sh（dash 语义）检查，不许被 bash 顶替', () => {
    const text = fs.readFileSync(path.join(ROOT, 'docker/app-entrypoint.sh'), 'utf8');
    expect(interpreterFor(text)).toEqual({ interpreter: 'sh', args: [] });
  });
});
