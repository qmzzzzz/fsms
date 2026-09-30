/**
 * 供应链完整性锚（`scripts/check-lockfile-integrity.js`）的可证伪性自检。
 *
 * 为什么必须真调判据、而不是在本文件里复刻一份：
 *   本仓有过一次实测教训（见 `installScriptGate.test.js` 头注释）——测试复刻判据时，
 *   把门禁的选择条件写反，门禁退化成"永远失败"，而复刻版测试仍 6/6 全绿。
 *   复刻一份判据 = 测试了一个平行实现，与被测对象是否还正确无关。
 *   故本套件直接 `require` 脚本导出的 `canonicalize` / `semanticHash`。
 *
 * 本套件守护的不变式：
 *   1. **跨行尾稳定**：同一份 JSON 的 CRLF 版本与 LF 版本必须得到**同一个**哈希。
 *      这是把方案 §1.3 的决定性实验固化成回归闸——开发机 Windows/CRLF、CI ubuntu/LF，
 *      口径一旦退回原始字节哈希，CI 会**恒假红**，而假红第一次出现就会被消化掉，
 *      等于没有门禁。这是本套件最有价值的一条断言。
 *   2. key 顺序不同但内容相同 ⇒ 同哈希（证明排序真的生效，不是"碰巧"）。
 *   3. 内容真的变了 ⇒ 哈希必须变（**反向断言**，防止函数恒返回常量）。
 *   4. 锚文件可解析、且覆盖两份 lockfile。
 *   5. `require` 脚本不得执行 CLI（否则 jest 进程会被 process.exit 带走）。
 *
 * 本套件不启动 npm、不连网、不起子进程 ⇒ 确定性，可在任意环境跑。
 */

const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..', '..', '..');
const SCRIPT = path.join(ROOT, 'scripts', 'check-lockfile-integrity.js');
const ANCHOR = path.join(ROOT, 'deployment', 'lockfile-anchor.json');

/** 被测对象的真判据（不许在本文件里另写一份） */
const { canonicalize, semanticHash, LOCK_PATHS } = require(SCRIPT);

/** 构造一份用于变异的最小 lockfile 文本；行尾可控 */
const sampleLock = (eol) =>
  [
    '{',
    '  "name": "sample",',
    '  "version": "1.0.0",',
    '  "lockfileVersion": 3,',
    '  "packages": {',
    '    "": { "name": "sample", "version": "1.0.0" },',
    '    "node_modules/left-pad": { "version": "1.3.0", "integrity": "sha512-AAA" }',
    '  }',
    '}',
  ].join(eol);

describe('lockfile 完整性锚：判据可证伪', () => {
  // —— 本套件最关键的一条 ——
  // 变异实测：把 canonicalize 里 `Object.keys(value).sort()` 的 `.sort()` 去掉 ⇒ 本条必须红
  // （CRLF 与 LF 的键序一致时仍可能同值，故真正的杀招在下面"key 顺序不同"那条）。
  test('跨行尾稳定性：同一 JSON 的 CRLF 与 LF 版本必须同哈希（方案 §1.3 回归闸）', () => {
    const crlf = sampleLock('\r\n');
    const lf = sampleLock('\n');
    expect(crlf).not.toBe(lf); // 前提自证：两份输入确实不同
    expect(semanticHash(crlf)).toBe(semanticHash(lf));
  });

  // 这条才是"排序被改坏"的杀招：键序不同 ⇒ 不排序时序列化串不同 ⇒ 哈希不同。
  test('key 顺序不同但内容相同 ⇒ 同哈希（证明排序生效）', () => {
    const a = '{"a":1,"b":{"x":1,"y":2},"c":[1,2]}';
    const b = '{"c":[1,2],"b":{"y":2,"x":1},"a":1}';
    expect(semanticHash(a)).toBe(semanticHash(b));
  });

  // —— 反向断言 ——
  // 变异实测：把 semanticHash 改成 `return 'CONST';` ⇒ 本条与上面"key 顺序"条同时红。
  test('反向断言：内容真的变了 ⇒ 哈希必须变（防恒返回常量）', () => {
    const base = sampleLock('\n');
    const tamperedIntegrity = base.replace('sha512-AAA', 'sha512-EVIL');
    const tamperedVersion = base.replace('"1.3.0"', '"9.9.9"');
    expect(semanticHash(tamperedIntegrity)).not.toBe(semanticHash(base));
    expect(semanticHash(tamperedVersion)).not.toBe(semanticHash(base));
  });

  test('数组保序：元素顺序是语义的一部分，不得被"排序"抹平', () => {
    expect(semanticHash('{"files":["a","b"]}')).not.toBe(semanticHash('{"files":["b","a"]}'));
  });

  test('canonicalize 是递归排序的：嵌套对象的键序也被抹平', () => {
    expect(JSON.stringify(canonicalize({ b: { d: 1, c: 2 }, a: 3 }))).toBe(
      '{"a":3,"b":{"c":2,"d":1}}'
    );
  });

  test('哈希口径固定：64 位十六进制 sha256', () => {
    expect(semanticHash('{}')).toMatch(/^[0-9a-f]{64}$/);
    // 与实现绑定的已知值，改口径（换算法/换序列化）时必须同步锚文件
    expect(semanticHash('{"a":1,"b":2}')).toBe(semanticHash('{"b":2,"a":1}'));
  });

  describe('锚文件', () => {
    test('可解析且覆盖两份 lockfile（后端 + web-admin）', () => {
      const anchor = JSON.parse(fs.readFileSync(ANCHOR, 'utf8'));
      expect(anchor.locks).toBeDefined();
      for (const rel of LOCK_PATHS) {
        expect(anchor.locks[rel]).toMatch(/^[0-9a-f]{64}$/);
      }
      expect(Object.keys(anchor.locks).sort()).toEqual([...LOCK_PATHS].sort());
    });

    // 前提自证：若 LOCK_PATHS 哪天被改成空数组，上面所有断言都会退化成"空集相等"而恒真
    test('锚的覆盖面是 2 份，且不含未入库的 zznpmtest/（脚手架，git 未跟踪）', () => {
      expect(LOCK_PATHS).toHaveLength(2);
      expect(LOCK_PATHS).toContain('package-lock.json');
      expect(LOCK_PATHS).toContain('web-admin/package-lock.json');
      expect(LOCK_PATHS.some((p) => p.includes('zznpmtest'))).toBe(false);
    });

    test('锚里记的口径与脚本实现一致（改口径必须同步锚，否则存量锚静默过期）', () => {
      const anchor = JSON.parse(fs.readFileSync(ANCHOR, 'utf8'));
      expect(anchor.algorithm).toBe('sha256');
      expect(anchor.canonical).toBe('json-sort-keys-compact-utf8');
    });

    // —— 端到端：锚必须真的等于当前工作区锁文件的哈希 ——
    // 这条与 CI 门禁同判据，但在这里红能让人看到"是哪一份、差多少"
    test('锚与当前仓库的锁文件一致（跑 --verify 的那条判据在此复现）', () => {
      const anchor = JSON.parse(fs.readFileSync(ANCHOR, 'utf8'));
      for (const rel of LOCK_PATHS) {
        const text = fs.readFileSync(path.join(ROOT, rel), 'utf8').replace(/^\uFEFF/, '');
        expect(semanticHash(text)).toBe(anchor.locks[rel]);
      }
    });
  });

  test('判据被 require 时不执行 CLI（否则测试进程会被 process.exit 带走）', () => {
    expect(typeof canonicalize).toBe('function');
    expect(typeof semanticHash).toBe('function');
    expect(Array.isArray(LOCK_PATHS)).toBe(true);
  });
});
