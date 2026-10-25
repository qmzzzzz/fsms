/**
 * CODEOWNERS 覆盖回归（2026-10-24 审计 P3）
 *
 * 缺口形状：仓库此前没有 CODEOWNERS，于是「改一个门禁脚本的判据」「往允许清单里
 * 塞一条豁免」「改 lockfile 的 integrity」与普通业务改动在评审流程里**没有区别**。
 * 本文件把三类高爆炸半径路径钉成必须被覆盖的清单；删掉对应模式、或把文件写成
 * 空壳，都会直接红。
 *
 * 能力边界：CODEOWNERS 只负责请求评审，真正阻断合并要靠分支保护的
 * "Require review from Code Owners"。这里断言的是**文件内容覆盖**，不是分支保护。
 */

const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..', '..', '..');
const FILE = path.join(ROOT, '.github', 'CODEOWNERS');

const LINES = fs
  .readFileSync(FILE, 'utf8')
  .split(/\r?\n/)
  .map((l) => l.trim())
  .filter((l) => l && !l.startsWith('#'));

/** 解析成 {pattern, owner}；形如 `[pattern...] owner`，owner 必须是 @handle */
const RULES = LINES.map((line) => {
  const parts = line.split(/\s+/);
  return { pattern: parts[0], owner: parts[parts.length - 1] };
});

/** 最小 glob：支持行首 `/` 锚定、`*`（不跨 `/`）、目录尾 `/`（匹配其下全部） */
function matches(pattern, file) {
  const anchored = pattern.startsWith('/');
  const body = anchored ? pattern.slice(1) : pattern;
  const dir = body.endsWith('/');
  const re = body
    .replace(/\/$/, '')
    .split('/')
    .map((seg) => seg.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '[^/]*'))
    .join('/');
  return new RegExp(`${anchored ? '^' : '(^|/)'}${re}${dir ? '/' : '(?=/|$)'}`).test(file);
}

const covered = (file) => RULES.some((r) => matches(r.pattern, file));

describe('CODEOWNERS 覆盖高爆炸半径路径', () => {
  test('文件存在、有规则、每条规则都指向具体 @handle', () => {
    expect(RULES.length).toBeGreaterThanOrEqual(8);
    for (const r of RULES) {
      expect(r.pattern).toMatch(/^\//);
      expect(r.owner).toMatch(/^@[A-Za-z0-9][A-Za-z0-9-]*$/);
      // 团队占位符不算所有者：它们不会真的请求到任何人
      expect(r.owner).not.toMatch(/^@(your-org|org|team|owner)$/i);
    }
  });

  test.each([
    '.github/workflows/ci.yml',
    '.github/workflows/deploy.yml',
    '.github/dependabot.yml',
    'deployment/audit-allowlist.json',
    'deployment/lockfile-anchor.json',
    'deployment/mongod-artifacts.json',
    'deployment/ip2region-checksum.json',
    'eslint.ratchet.json',
    'scripts/check-audit-allowlist.js',
    'scripts/check-lockfile-integrity.js',
    'scripts/check-prod-install-scripts.js',
    'scripts/provision-mongod.js',
    'scripts/update-ip2region.js',
    'package-lock.json',
    'web-admin/package-lock.json',
    'Dockerfile',
    'docker-compose.yml',
  ])('%s 必须有 owner', (file) => {
    expect({ file, covered: covered(file) }).toEqual({ file, covered: true });
  });

  test('可证伪：普通业务文件与不存在的路径不应被规则误伤', () => {
    expect(covered('src/index.js')).toBe(false);
    expect(covered('web-admin/src/main.js')).toBe(false);
    expect(covered('README.md')).toBe(false);
  });
});
