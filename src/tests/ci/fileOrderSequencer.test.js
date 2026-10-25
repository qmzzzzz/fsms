/**
 * 文件级乱序门禁的自测。
 *
 * 背景：Jest 的 `--randomize` 只打乱单个文件内的用例顺序，文件顺序始终是
 * 默认值。CI 的顺序无关步骤曾据此声称覆盖「文件/用例的执行次序」，实际
 * 只覆盖了用例这一半——文件 A 的模块级/外部状态污染文件 B 的耦合不会被
 * 任何 seed 命中。本文件钉住三件事：
 *   1. sequencer 的默认行为不变（未设 JEST_FILE_SEED 时走 Jest 默认顺序）；
 *   2. 同一 seed 可复现，且排列不等于默认顺序；
 *   3. jest.config.js 与 ci.yml 真的把文件级 seed 接上了。
 */

const fs = require('fs');
const path = require('path');
const Sequencer = require('../testSequencer');

const ROOT = path.join(__dirname, '..', '..', '..');
const readRoot = (rel) => fs.readFileSync(path.join(ROOT, rel), 'utf8');

// 默认 sequencer 在无计时缓存时按文件大小降序排列；用可控的 hasteFS 伪造这一维度
const fakeTests = (sizes) =>
  sizes.map((size, index) => ({
    path: `/repo/src/tests/fake-${index}.test.js`,
    context: {
      config: { cache: false },
      hasteFS: { getSize: () => size },
    },
  }));

const seedEnv = Sequencer.FILE_SEED_ENV;

describe('文件级乱序 sequencer', () => {
  const originalSeed = process.env[seedEnv];

  afterEach(() => {
    if (originalSeed === undefined) delete process.env[seedEnv];
    else process.env[seedEnv] = originalSeed;
  });

  test('未设置 seed 时完全沿用 Jest 默认顺序', () => {
    delete process.env[seedEnv];
    const seq = new Sequencer({});
    const order = seq.sort(fakeTests([10, 30, 20])).map((test) => test.path);

    expect(order).toEqual([
      '/repo/src/tests/fake-1.test.js',
      '/repo/src/tests/fake-2.test.js',
      '/repo/src/tests/fake-0.test.js',
    ]);
  });

  test('同一 seed 可复现，且不同于默认顺序', () => {
    const sizes = Array.from({ length: 24 }, (_, index) => 100 - index * 3);
    // CI 自身就带 JEST_FILE_SEED；不先清掉的话「默认顺序」会按同一个 seed 洗一遍，
    // 与 first 恒等——这条判据在 seed=20260917 的那一轮里正是这样变红的。
    delete process.env[seedEnv];
    const defaultOrder = new Sequencer({}).sort(fakeTests(sizes)).map((test) => test.path);

    process.env[seedEnv] = '20260917';
    const first = new Sequencer({}).sort(fakeTests(sizes)).map((test) => test.path);
    const again = new Sequencer({}).sort(fakeTests(sizes)).map((test) => test.path);

    expect(first).toEqual(again);
    expect(first).not.toEqual(defaultOrder);
    // 打乱不是丢弃：集合必须完全一致
    expect([...first].sort()).toEqual([...defaultOrder].sort());
  });

  test('不同 seed 给出不同排列', () => {
    const sizes = Array.from({ length: 24 }, (_, index) => 100 - index * 3);
    process.env[seedEnv] = '31337';
    const a = new Sequencer({}).sort(fakeTests(sizes)).map((test) => test.path);
    process.env[seedEnv] = '777001';
    const b = new Sequencer({}).sort(fakeTests(sizes)).map((test) => test.path);

    expect(a).not.toEqual(b);
  });

  test('jest.config.js 接上自定义 sequencer', () => {
    expect(readRoot('jest.config.js')).toMatch(
      /testSequencer:\s*'<rootDir>\/src\/tests\/testSequencer\.js'/
    );
  });

  test('CI 的每个 seed 同时驱动文件级与用例级乱序', () => {
    const ci = readRoot('.github/workflows/ci.yml');
    expect(ci).toMatch(/for seed in [\d\s]+; do/);
    expect(ci).toMatch(/JEST_FILE_SEED="\$seed" npx jest --randomize --seed="\$seed"/);
  });
});
