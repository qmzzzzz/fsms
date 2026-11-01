/**
 * 离线包扫描（scripts/offlineBundleScan.js，宿主代理心跳侧）
 *
 * 守的失效形态：
 *   · 好包的摘要字段映射正确（ref/version/createdAt…）——前端下拉直接吃这份数据；
 *   · 坏 manifest / 白名单外 → 进 invalid 且错误可读，**绝不**混进 available；
 *   · 隐藏目录与文件条目跳过（半截解压、临时文件不是包）；
 *   · 目录不存在 = 未启用离线通道（不是错误）；目录读不出（指向文件等）= error 折进
 *     结果且**不 throw**——离线通道坏了不许炸掉代理这一轮、不许让在线升级变红；
 *   · 数量封顶：塞满畸形包的目录不能把心跳文件撑成 DoS 载体。
 *
 * 用真实临时目录（仓库惯例）：目录形状本身是被验证的对象，不 mock 文件系统。
 * 全部用例不依赖 docker——扫描层只读 manifest，不算 payload 哈希。
 */
'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');

const {
  scanBundles,
  MAX_AVAILABLE,
  MAX_INVALID,
  MAX_SCAN_ENTRIES,
} = require('../../../scripts/offlineBundleScan');

const ALLOWLIST = ['ghcr.io/acme/'];
const DIGEST = `sha256:${'b'.repeat(64)}`;
const REF = `ghcr.io/acme/fsms@${DIGEST}`;

const manifestOf = (overrides = {}) => ({
  format: 1,
  version: '1.2.3',
  buildId: 'ci-42',
  createdAt: '2026-11-01T00:00:00Z',
  images: [
    {
      role: 'app',
      ref: REF,
      file: 'payload/fsms-app.tar',
      bytes: 1024,
      sha256: 'a'.repeat(64),
      ...overrides,
    },
  ],
});

function makeRoot() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'fsms-bundles-'));
}

/**
 * 在临时根下建一个包目录。
 * 写死一个与被测模块同语义的边界断言：目录名必须落在临时根之内（本文件全部用
 * 字面量目录名，这条断言守的是测试自身的笔误，同时呼应「包目录名不许逃逸」的判据）。
 */
function writeBundle(root, name, manifest) {
  const base = path.resolve(root);
  const dir = path.resolve(base, name);
  if (dir !== base && !dir.startsWith(base + path.sep)) {
    throw new Error(`测试用例错误：目录名「${name}」逃逸出临时根（allowed base: ${base}）`);
  }
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, 'manifest.json'), JSON.stringify(manifest, null, 2), 'utf8');
  return dir;
}

describe('扫描：可用包', () => {
  test('好包出现在 available，字段逐项映射（前端下拉直接吃这份数据）', () => {
    const root = makeRoot();
    writeBundle(root, 'v1.2.3', manifestOf());
    const result = scanBundles({ bundlesDir: root, allowlist: ALLOWLIST });
    expect(result.error).toBe('');
    expect(result.available).toHaveLength(1);
    expect(result.available[0]).toEqual({
      dirName: 'v1.2.3',
      ref: REF,
      digest: DIGEST,
      repository: 'ghcr.io/acme/fsms',
      version: '1.2.3',
      buildId: 'ci-42',
      createdAt: '2026-11-01T00:00:00Z',
    });
    expect(result.invalid).toEqual([]);
  });

  test('多个好包都列出；隐藏目录与文件条目跳过（半截解压/临时文件不是包）', () => {
    const root = makeRoot();
    writeBundle(root, 'v1.2.3', manifestOf());
    writeBundle(root, 'v1.2.4', manifestOf({ ref: `ghcr.io/acme/fsms@sha256:${'c'.repeat(64)}` }));
    writeBundle(root, '.tmp-partial', manifestOf());
    fs.writeFileSync(path.join(root, 'notes.txt'), 'not a bundle', 'utf8');
    const result = scanBundles({ bundlesDir: root, allowlist: ALLOWLIST });
    expect(result.available.map((b) => b.dirName).sort()).toEqual(['v1.2.3', 'v1.2.4']);
  });
});

describe('扫描：坏包与边界', () => {
  test('缺 sha256 的 manifest ⇒ invalid，available 不受污染', () => {
    const root = makeRoot();
    const bad = manifestOf();
    delete bad.images[0].sha256;
    writeBundle(root, 'broken', bad);
    writeBundle(root, 'good', manifestOf());
    const result = scanBundles({ bundlesDir: root, allowlist: ALLOWLIST });
    expect(result.available.map((b) => b.dirName)).toEqual(['good']);
    expect(result.invalid).toHaveLength(1);
    expect(result.invalid[0].dirName).toBe('broken');
    expect(result.invalid[0].error).toMatch(/sha256/);
  });

  test('白名单外的包 ⇒ invalid（离线不是白名单逃生通道）；空白名单 = 全拒', () => {
    const root = makeRoot();
    writeBundle(root, 'outside', manifestOf({ ref: `ghcr.io/evil/fsms@${DIGEST}` }));
    expect(scanBundles({ bundlesDir: root, allowlist: ALLOWLIST }).invalid).toHaveLength(1);
    const all = scanBundles({ bundlesDir: root, allowlist: [] });
    expect(all.available).toEqual([]);
    expect(all.invalid).toHaveLength(1);
  });

  test('tag 引用的包 ⇒ invalid（离线同样不接受浮动 tag）', () => {
    const root = makeRoot();
    writeBundle(root, 'tagged', manifestOf({ ref: 'ghcr.io/acme/fsms:v1.2.3' }));
    const result = scanBundles({ bundlesDir: root, allowlist: ALLOWLIST });
    expect(result.available).toEqual([]);
    expect(result.invalid[0].error).toMatch(/digest|钉扎/);
  });

  test('目录不存在 = 未启用离线通道：空结果、无 error、不 throw', () => {
    const result = scanBundles({
      bundlesDir: path.join(makeRoot(), 'nope'),
      allowlist: ALLOWLIST,
    });
    expect(result).toEqual({ available: [], invalid: [], error: '' });
  });

  test('bundlesDir 为空配置 = 同上（离线通道未配置不是异常）', () => {
    expect(scanBundles({ bundlesDir: '', allowlist: ALLOWLIST })).toEqual({
      available: [],
      invalid: [],
      error: '',
    });
  });

  test('bundlesDir 指向文件 ⇒ error 折进结果（fail-soft：不许炸掉代理这一轮）', () => {
    const root = makeRoot();
    const filePath = path.join(root, 'not-a-dir');
    fs.writeFileSync(filePath, 'x', 'utf8');
    const result = scanBundles({ bundlesDir: filePath, allowlist: ALLOWLIST });
    expect(result.available).toEqual([]);
    expect(result.error).toMatch(/不可读/);
  });

  test('条目数超过扫描上限 ⇒ 拒绝整扫并提示清理（防目录被滥用拖慢心跳）', () => {
    const root = makeRoot();
    for (let i = 0; i < MAX_SCAN_ENTRIES + 1; i += 1) {
      fs.mkdirSync(path.join(root, `b${i}`), { recursive: true });
    }
    const result = scanBundles({ bundlesDir: root, allowlist: ALLOWLIST });
    expect(result.available).toEqual([]);
    expect(result.error).toMatch(/超过扫描上限/);
  });

  test('available/invalid 各自封顶（心跳文件不能被畸形包撑大）', () => {
    const root = makeRoot();
    const broken = manifestOf();
    delete broken.images[0].sha256;
    for (let i = 0; i < MAX_INVALID + 3; i += 1) {
      writeBundle(root, `bad${i}`, broken);
    }
    for (let i = 0; i < MAX_AVAILABLE + 3; i += 1) {
      writeBundle(root, `good${i}`, manifestOf());
    }
    const result = scanBundles({ bundlesDir: root, allowlist: ALLOWLIST });
    expect(result.available).toHaveLength(MAX_AVAILABLE);
    expect(result.invalid).toHaveLength(MAX_INVALID);
  });
});
