/**
 * UTF-8 门禁的扫描边界（F-05，2026-10-17）
 *
 * 缺陷本体：`scripts/check-utf8.js` 的跳过集合是**精确名** `['node_modules','dist',
 * '.git','coverage']`。本仓同时存在 `web-admin/dist-debug`（`--mode development` 产物）、
 * `dist-optimized`，以及手工跑覆盖率留下的 `coverage-<tag>`——一个都不匹配精确名，
 * 于是**构建产物被当成源码扫**：生成一次 debug bundle 后 `npm run check:utf8` 就红，
 * 报错行指向 `dist-debug/assets/router-<hash>.js`，而源码一个字符没变。
 *
 * 修法：改成前缀判据 `^(node_modules|\.git|dist($|-)|coverage($|-))`。
 * 本套件钉三件事：① 三种产物变体都跳过；② 同前缀的**源码目录**不被误跳
 * （`distribution`/`distance`）；③ 端到端走一遍真实 walk，确认产物里的乱码
 * 不再影响扫描集——只断言正则等于没测"它到底有没有被用上"。
 */
'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');

const { isSkippedDirName, walk, roots } = require('../../../scripts/check-utf8');

describe('F-05 生成物目录必须跳过', () => {
  test.each([
    ['dist', '基础产物目录'],
    ['dist-debug', '--mode development 的产物'],
    ['dist-optimized', '优化产物'],
    ['coverage', '覆盖率'],
    ['coverage-zzmfa', '手工跑覆盖率时的带 tag 目录'],
    ['node_modules', '依赖'],
    ['.git', '版本库元数据'],
  ])('%s（%s）跳过', (name) => {
    expect(isSkippedDirName(name)).toBe(true);
  });

  test.each([
    ['.gitignore', '根目录文本文件，不是 .git 目录'],
    ['.gitattributes', '同上'],
    ['.gitleaksignore', '同上'],
  ])('%s（%s）不被误跳', (name, why) => {
    // 回归面：`\.git` 曾无右边界，把这三个文件一并吞掉。编码门禁没受影响（rootFiles
    // 走直接 push），但任何基于 walk 的扫描都看不见它们——F-14 的引用台账因此在
    // `.gitignore` 那条「取回方式见 deliverables/…」上瞎了一次，直到有人对着
    // 「台账里明明登记了、却说没人引用」的红讯去查才暴露。
    expect({ name, why: Boolean(why) }).toEqual({ name, why: true });
    expect(isSkippedDirName(name)).toBe(false);
  });

  test.each(['distribution', 'distance', 'dist-tool', 'src', 'docs', 'web-admin'])(
    '同前缀的源码目录不被误跳：%s',
    (name) => {
      // `dist-tool` 是「产物族」的合法成员，故意跳过；这里只钉**非产物**的相似名。
      if (name === 'dist-tool') return;
      expect(isSkippedDirName(name)).toBe(false);
    }
  );
});

describe('F-05 端到端：产物里的乱码不进扫描集', () => {
  let tmp;
  beforeEach(() => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'utf8scope-'));
  });
  afterEach(() => {
    fs.rmSync(tmp, { recursive: true, force: true });
  });

  test('dist-debug 下的 U+FFFD 文件不被收集，src 下的正常文件被收集', () => {
    fs.mkdirSync(path.join(tmp, 'dist-debug', 'assets'), { recursive: true });
    // 这就是审计现场：构建产物里有一个 U+FFFD（Vite 打包时的替换字符）
    fs.writeFileSync(path.join(tmp, 'dist-debug', 'assets', 'router-abc.js'), 'const x="\uFFFD";');
    fs.mkdirSync(path.join(tmp, 'src'));
    fs.writeFileSync(path.join(tmp, 'src', 'ok.js'), 'const a = 1;\n');

    const out = [];
    walk(tmp, out);

    expect(out).toEqual([path.join(tmp, 'src', 'ok.js')]);
  });

  test('coverage-<tag> 同样不进扫描集（覆盖率报告里有大量 HTML/JS）', () => {
    fs.mkdirSync(path.join(tmp, 'coverage-zzmfa'));
    fs.writeFileSync(path.join(tmp, 'coverage-zzmfa', 'index.html'), '<p>\uFFFD</p>');
    const out = [];
    walk(tmp, out);
    expect(out).toEqual([]);
  });
});

describe('F-05 扫描根清单仍然有效（跳过规则不得把扫描面吃掉）', () => {
  test('web-admin 仍是扫描根（跳过的是它下面的产物子目录，不是它本身）', () => {
    // 反方向的守卫：把 web-admin 整个跳掉也能让 check:utf8 变绿，
    // 但那是"门禁没看东西"，与 F-05 要修的"看错了东西"是两种失效。
    expect(roots.some((r) => r.endsWith('web-admin'))).toBe(true);
  });
});

describe('F-05 并发：遍历期间消失的条目按「没看见」处理，悬空条目必须报红，其余错误一律上抛', () => {
  let tmp;
  beforeEach(() => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'utf8race-'));
  });
  afterEach(() => {
    jest.restoreAllMocks();
    fs.rmSync(tmp, { recursive: true, force: true });
  });

  /**
   * 复现现场（2026-10-31 全量并行实测）：
   * `src/tests/security/gateSelfTest.test.js` 在仓库根下 `mkdtempSync('.lint-ratchet-selftest-')`
   * 造夹具、用完即删；`src/tests/docs/deliverablesReferenceIndex.test.js` 同时在本 walk 里
   * 走全仓。readdir 拿到名字、stat 之前目录已被删 ⇒ 整个套件 `Test suite failed to run:
   * ENOENT … stat '.lint-ratchet-selftest-D0Y6cO'`。编码内容一个字节没变，这是假红。
   *
   * 这些用例用 monkey-patch 精确复刻时序（真并发不可等待），而不是去跑两个套件碰运气。
   *
   * 第十一轮补牙（依据 work/audit-round10-walk-migration.md §1b）：原三条用例对
   * stat/readdir 的 ENOENT 与 stat 的 EACCES 有牙，但两处无人设防——
   *   a) ENOTDIR 的处置：把 ENOTDIR 从「消失」集合里拿掉，三条用例全绿；
   *   b) readdir 腿的非 ENOENT 上抛：反例只 mock 了 statSync，readdir 腿整体吞掉也全绿。
   * 第十一轮同时立一条新判据（§1c）：**瞬时消失跳过、持续缺失必须报红**——
   * stat/readdir 报 ENOENT 后再用 lstat 复核一次：lstat 成功 ⇒ 名字还在（悬空链接/目录联接，
   * 目标已被删）⇒ 抛 DANGLING_ENTRIES；lstat 也 ENOENT ⇒ 真被删 ⇒ 跳过。
   */
  test('stat 阶段 ENOENT 且 lstat 复核也 ENOENT（真被删）：跳过该条，其余文件照常收集（不抛）', () => {
    fs.writeFileSync(path.join(tmp, 'keep.js'), 'const a = 1;\n');
    fs.writeFileSync(path.join(tmp, 'vanish.js'), 'const b = 2;\n');
    const realStat = fs.statSync;
    const realLstat = fs.lstatSync;
    jest.spyOn(fs, 'statSync').mockImplementation((target, ...rest) => {
      if (String(target).endsWith('vanish.js')) {
        const err = new Error(`ENOENT: no such file or directory, stat '${target}'`);
        err.code = 'ENOENT';
        throw err;
      }
      return realStat(target, ...rest);
    });
    jest.spyOn(fs, 'lstatSync').mockImplementation((target, ...rest) => {
      if (String(target).endsWith('vanish.js')) {
        const err = new Error(`ENOENT: no such file or directory, lstat '${target}'`);
        err.code = 'ENOENT';
        throw err;
      }
      return realLstat(target, ...rest);
    });
    const out = [];
    expect(() => walk(tmp, out)).not.toThrow();
    expect(out).toEqual([path.join(tmp, 'keep.js')]);
  });

  test('readdir 阶段 ENOENT 且 lstat 复核也 ENOENT（真被删）：整个目录按空处理（不抛）', () => {
    const realLstat = fs.lstatSync;
    jest.spyOn(fs, 'readdirSync').mockImplementation(() => {
      const err = new Error('ENOENT: no such file or directory, scandir');
      err.code = 'ENOENT';
      throw err;
    });
    jest.spyOn(fs, 'lstatSync').mockImplementation((target, ...rest) => {
      if (String(target) === tmp) {
        const err = new Error(`ENOENT: no such file or directory, lstat '${target}'`);
        err.code = 'ENOENT';
        throw err;
      }
      return realLstat(target, ...rest);
    });
    const out = [];
    expect(() => walk(tmp, out)).not.toThrow();
    expect(out).toEqual([]);
  });

  test('悬空条目（stat 报 ENOENT 但 lstat 成功＝名字还在）必须抛 DANGLING_ENTRIES，不得当成竞态跳过', () => {
    fs.writeFileSync(path.join(tmp, 'keep.js'), 'const a = 1;\n');
    fs.writeFileSync(path.join(tmp, 'dangling.js'), 'const b = 2;\n');
    const realStat = fs.statSync;
    jest.spyOn(fs, 'statSync').mockImplementation((target, ...rest) => {
      if (String(target).endsWith('dangling.js')) {
        const err = new Error(`ENOENT: no such file or directory, stat '${target}'`);
        err.code = 'ENOENT';
        throw err;
      }
      return realStat(target, ...rest);
    });
    // lstat 不跟随链接：目标被删掉时它照样成功——这正是「名字还在、目标不可达」的证据。
    // 这里不 mock lstatSync，用真实的 lstat 走一遍，避免把判据钉在桩上。
    const out = [];
    expect(() => walk(tmp, out)).toThrow(/DANGLING_ENTRIES[\s\S]*dangling\.js/);
  });

  test('悬空目录联接（readdir 报 ENOENT 但目录仍在）同样必须抛 DANGLING_ENTRIES', () => {
    jest.spyOn(fs, 'readdirSync').mockImplementation(() => {
      const err = new Error('ENOENT: no such file or directory, scandir');
      err.code = 'ENOENT';
      throw err;
    });
    // tmp 真实存在 ⇒ lstat 成功 ⇒ 「名字还在」：读不到不等于不见了。
    const out = [];
    expect(() => walk(tmp, out)).toThrow(/DANGLING_ENTRIES/);
  });

  test('readdir 阶段 EACCES 也必须上抛——与 stat 腿同一条判据，不得只守一条腿', () => {
    jest.spyOn(fs, 'readdirSync').mockImplementation(() => {
      const err = new Error('EACCES: permission denied, scandir');
      err.code = 'EACCES';
      throw err;
    });
    const out = [];
    expect(() => walk(tmp, out)).toThrow(/EACCES/);
  });

  test('stat 阶段 ENOTDIR：跳过该条（目录被换成文件的瞬间态），其余文件照常收集（不抛）', () => {
    fs.writeFileSync(path.join(tmp, 'keep.js'), 'const a = 1;\n');
    fs.writeFileSync(path.join(tmp, 'flip.js'), 'const b = 2;\n');
    const realStat = fs.statSync;
    jest.spyOn(fs, 'statSync').mockImplementation((target, ...rest) => {
      if (String(target).endsWith('flip.js')) {
        const err = new Error(`ENOTDIR: not a directory, stat '${target}'`);
        err.code = 'ENOTDIR';
        throw err;
      }
      return realStat(target, ...rest);
    });
    const out = [];
    expect(() => walk(tmp, out)).not.toThrow();
    expect(out).toEqual([path.join(tmp, 'keep.js')]);
  });

  test('readdir 阶段 ENOTDIR：整个目录按空处理（组件被换走），不抛', () => {
    jest.spyOn(fs, 'readdirSync').mockImplementation(() => {
      const err = new Error('ENOTDIR: not a directory, scandir');
      err.code = 'ENOTDIR';
      throw err;
    });
    const out = [];
    expect(() => walk(tmp, out)).not.toThrow();
    expect(out).toEqual([]);
  });

  test('反例：stat 的 EACCES 仍然上抛——不得把「看不见」当成「没问题」', () => {
    fs.writeFileSync(path.join(tmp, 'locked.js'), 'const c = 3;\n');
    jest.spyOn(fs, 'statSync').mockImplementation(() => {
      const err = new Error('EACCES: permission denied, stat');
      err.code = 'EACCES';
      throw err;
    });
    const out = [];
    expect(() => walk(tmp, out)).toThrow(/EACCES/);
  });

  test('边界：lstat 复核自己抛 EACCES ⇒ 照旧上抛（复核不可用不得变成「跳过」）', () => {
    fs.writeFileSync(path.join(tmp, 'x.js'), 'const a = 1;\n');
    const realStat = fs.statSync;
    const realLstat = fs.lstatSync;
    jest.spyOn(fs, 'statSync').mockImplementation((target, ...rest) => {
      if (String(target).endsWith('x.js')) {
        const err = new Error(`ENOENT: no such file or directory, stat '${target}'`);
        err.code = 'ENOENT';
        throw err;
      }
      return realStat(target, ...rest);
    });
    jest.spyOn(fs, 'lstatSync').mockImplementation((target, ...rest) => {
      if (String(target).endsWith('x.js')) {
        const err = new Error(`EACCES: permission denied, lstat '${target}'`);
        err.code = 'EACCES';
        throw err;
      }
      return realLstat(target, ...rest);
    });
    const out = [];
    expect(() => walk(tmp, out)).toThrow(/EACCES/);
  });

  test('边界：lstat 复核抛 ENOTDIR（非 ENOENT）同样上抛，只有 ENOENT 才允许当「真被删」', () => {
    fs.writeFileSync(path.join(tmp, 'y.js'), 'const a = 1;\n');
    const realStat = fs.statSync;
    const realLstat = fs.lstatSync;
    jest.spyOn(fs, 'statSync').mockImplementation((target, ...rest) => {
      if (String(target).endsWith('y.js')) {
        const err = new Error(`ENOENT: no such file or directory, stat '${target}'`);
        err.code = 'ENOENT';
        throw err;
      }
      return realStat(target, ...rest);
    });
    jest.spyOn(fs, 'lstatSync').mockImplementation((target, ...rest) => {
      if (String(target).endsWith('y.js')) {
        const err = new Error(`ENOTDIR: not a directory, lstat '${target}'`);
        err.code = 'ENOTDIR';
        throw err;
      }
      return realLstat(target, ...rest);
    });
    const out = [];
    expect(() => walk(tmp, out)).toThrow(/ENOTDIR/);
  });
});
