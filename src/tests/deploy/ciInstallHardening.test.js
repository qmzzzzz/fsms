/**
 * CI 安装期供应链硬化回归（2026-10-24 审计 P2）
 *
 * 锁住三条结构性不变量：
 *   1. 策略闸（安装脚本登记册 + 锁文件完整性锚）必须在**任何 `npm ci` 之前**完成，
 *      且所有会安装依赖的作业都直接 needs 它；
 *   2. CI 里的每一次 `npm ci` 都必须带 `--ignore-scripts`——安装期零脚本执行；
 *   3. test / e2e 的内存 Mongo 来自仓库内 SHA-256 锚定的预置二进制，
 *      版本必须与 globalSetup 的 MONGO_VERSION 一致。
 *
 * 第 3 条尤其容易腐化：把 provisioning 步骤删掉后，测试仍会通过——只是悄悄
 * 回退到 postinstall 下载（同一 host 的 MD5，且 globalSetup 已关掉校验）。
 * 因此这里对「锚定表 ↔ globalSetup ↔ workflow」三方做静态对账。
 */

const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..', '..', '..');
const CI = fs.readFileSync(path.join(ROOT, '.github/workflows/ci.yml'), 'utf8');
const TABLE = JSON.parse(
  fs.readFileSync(path.join(ROOT, 'deployment/mongod-artifacts.json'), 'utf8')
);
const PROVISION = require(path.join(ROOT, 'scripts/provision-mongod.js'));

/** 剥掉整行注释与行尾注释，避免「只写在注释里」被当成证据 */
const stripComments = (text) =>
  text
    .split(/\r?\n/)
    .filter((line) => !/^\s*#/.test(line))
    .map((line) => line.replace(/\s+#(?![^'"]*').*$/, ''))
    .join('\n');

const CODE = stripComments(CI);

/** 取 job 块（从 `  <name>:` 到下个顶层 job） */
function jobBlock(name) {
  const start = CODE.indexOf(`\n  ${name}:`);
  if (start < 0) throw new Error(`未找到 job：${name}`);
  const rest = CODE.slice(start + 1);
  const next = rest.slice(1).search(/\n {2}[a-zA-Z0-9_-]+:/);
  return next < 0 ? rest : rest.slice(0, next + 1);
}

const jobNames = () =>
  [...CODE.matchAll(/^ {2}([a-zA-Z0-9_-]+):$/gm)].map((m) => m[1]).filter((n) => n !== 'on');

describe('CI 安装期供应链硬化', () => {
  test('工作流级关闭 scarf 遥测（漏加 --ignore-scripts 时的第二道保险）', () => {
    expect(CODE).toMatch(/^\s*SCARF_ANALYTICS:\s*'false'$/m);
  });

  test('dependency-policy 存在，只做锁文件判定，且不安装依赖', () => {
    const block = jobBlock('dependency-policy');
    expect(block).toContain('scripts/check-prod-install-scripts.js --all');
    expect(block).toContain('scripts/check-lockfile-integrity.js --verify');
    expect(block).not.toMatch(/npm\s+(ci|install)\b/);
  });

  test('所有安装依赖的作业都直接 needs dependency-policy', () => {
    const installers = jobNames().filter((j) => /\bnpm\s+(ci|install)\b/.test(jobBlock(j)));
    // 前提自证：确实找到了安装作业（找到空集会让本条恒真）
    expect(installers.length).toBeGreaterThanOrEqual(4);
    for (const job of installers) {
      const block = jobBlock(job);
      expect({ job, needs: /needs:\s*dependency-policy/.test(block) }).toEqual({
        job,
        needs: true,
      });
    }
  });

  test('CI 里每一次 npm ci（含 --prefix）都带 --ignore-scripts', () => {
    const lines = CODE.split('\n')
      .map((l) => l.trim())
      .filter((l) => /\bnpm\s+(--prefix\s+\S+\s+)?ci\b/.test(l));
    expect(lines.length).toBeGreaterThanOrEqual(4);
    expect(lines.filter((l) => !l.includes('--ignore-scripts'))).toEqual([]);
  });

  test('test 与 e2e 作业用锚定预置的 mongod（而不是安装期下载）', () => {
    for (const job of ['test', 'e2e']) {
      const block = jobBlock(job);
      expect({ job, provisioned: block.includes('scripts/provision-mongod.js') }).toEqual({
        job,
        provisioned: true,
      });
      expect({ job, env: block.includes('MONGOMS_SYSTEM_BINARY=') }).toEqual({
        job,
        env: true,
      });
    }
  });

  test('锚定表：版本与 globalSetup 的 MONGO_VERSION 一致，SHA-256 形状合法', () => {
    const setup = fs.readFileSync(path.join(ROOT, 'src/tests/globalSetup.js'), 'utf8');
    const version = /const MONGO_VERSION = '([^']+)'/.exec(setup)[1];
    expect(TABLE.artifacts.length).toBeGreaterThan(0);
    for (const a of TABLE.artifacts) {
      expect(a.version).toBe(version);
      expect(a.url).toMatch(/^https:\/\//);
      expect(a.url).toContain(a.version);
      expect(a.sha256).toMatch(/^[0-9a-f]{64}$/);
      expect(a.binary).toMatch(/bin\/mongod$/);
    }
    // 前提自证：CI 实际使用的平台必须在表里（否则 job 会在运行时 exit 2）
    expect(
      TABLE.artifacts.some(
        (a) => a.platform === 'linux' && a.arch === 'x64' && a.distro === 'ubuntu2404'
      )
    ).toBe(true);
  });
});

describe('CI 供应链门禁的其余接线（2026-10-24 审计 P3）', () => {
  test('web-admin 完整树（含 dev）与后端同口径走允许清单', () => {
    const block = jobBlock('security-audit');
    // 恰好两处全树 --json 审计（后端 + web-admin）；漏掉任一，dev 树又回到门禁之外
    expect([...block.matchAll(/npm audit --audit-level=moderate --json/g)]).toHaveLength(2);
    expect(block).toContain('node scripts/check-audit-allowlist.js --report .audit-all.json');
    expect(block).toContain('node ../scripts/check-audit-allowlist.js --report .audit-all.json');
    // 反向对照：全树审计不得退回 --omit=dev（那正是原缺口）
    expect(block).not.toMatch(/npm audit[^\n]*--omit=dev[^\n]*--json/);
  });

  test('PR 上构建镜像但不推送（Dockerfile 写坏在合并前暴露）', () => {
    const block = jobBlock('container-build');
    expect(block).toMatch(/if:\s*github\.event_name\s*==\s*'pull_request'/);
    expect(block).toMatch(/needs:\s*dependency-policy/);
    expect(block).toMatch(/^\s*push:\s*false$/m);
    expect(block).not.toMatch(/^\s*push:\s*true$/m);
    // 只构建不推送 ⇒ 不应接触任何仓库密钥
    expect(block).not.toContain('secrets.');
    // 动作必须钉到不可变 commit SHA（与仓库其余动作同口径）
    const uses = [...block.matchAll(/uses:\s*(\S+)/g)].map((m) => m[1]);
    expect(uses.length).toBeGreaterThanOrEqual(2);
    for (const u of uses) expect(u).toMatch(/@[0-9a-f]{40}$/);
    expect(uses.some((u) => u.startsWith('docker/build-push-action@'))).toBe(true);
  });
});

describe('mongod 锚定解析：可证伪且 fail-closed', () => {
  test('Ubuntu 版本映射（24.04 → ubuntu2404，22.04 → ubuntu2204）', () => {
    const rel = (v) => `ID=ubuntu\nVERSION_ID="${v}"\n`;
    expect(PROVISION.distroFromOsRelease(rel('24.04'))).toBe('ubuntu2404');
    expect(PROVISION.distroFromOsRelease(rel('22.04'))).toBe('ubuntu2204');
  });

  test('非 Ubuntu / 畸形版本返回 null（调用方据此 fail-closed）', () => {
    expect(PROVISION.distroFromOsRelease('ID=debian\nVERSION_ID="12"\n')).toBeNull();
    expect(PROVISION.distroFromOsRelease('ID=ubuntu\nVERSION_ID="24"\n')).toBeNull();
    expect(PROVISION.distroFromOsRelease('')).toBeNull();
  });

  test('非 Linux 平台不进入锚定路径（本地开发保持默认行为）', () => {
    expect(PROVISION.detectTarget('win32', 'x64', 'ID=ubuntu\nVERSION_ID="24.04"\n')).toBeNull();
    expect(PROVISION.detectTarget('darwin', 'arm64', '')).toBeNull();
  });

  test('findArtifact 对未登记平台返回 null，而不是回退到无校验下载', () => {
    const target = PROVISION.detectTarget('linux', 'x64', 'ID=ubuntu\nVERSION_ID="24.04"\n');
    expect(PROVISION.findArtifact(TABLE, target)).not.toBeNull();
    expect(
      PROVISION.findArtifact(TABLE, { platform: 'linux', arch: 'x64', distro: 'alpine' })
    ).toBeNull();
    expect(PROVISION.findArtifact(TABLE, null)).toBeNull();
  });
});
