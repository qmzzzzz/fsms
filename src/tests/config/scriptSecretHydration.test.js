/**
 * 独立脚本的密钥回填不变量（2026-10-03 审计线）
 *
 * 背景：`src/config/secrets.js` 支持 Docker/K8s 的 `<NAME>_FILE` 约定（密钥以文件挂载，
 * 启动期回填 process.env，避免密钥出现在 `docker inspect` / `compose config` / 子进程继承里）。
 * 但**只有 require 到 src/config 的入口会自动回填**，而运维手边的独立脚本大多是
 * `require('dotenv').config()` + 直读 `process.env.MONGODB_URI`。
 *
 * 为什么"看 require 图里有没有 src/config"不足以判绿（本轮实测）：
 *   `scripts/verify-audit-chain.js` 的静态依赖图**确实**通向 src/config
 *   （auditChainVerify → utils/auditChain → 函数体内 `require('../config')`），
 *   但那是**懒 require**——脚本在 main() 里读 env 时它根本还没执行。
 *   动态探测（只给 MONGODB_URI_FILE、不给 MONGODB_URI，目标端口 1）的结论：
 *     verify-audit-chain / revoke-user-sessions / run-rollback-drill /
 *     sync-audit-indexes / perf/explain-spotcheck ⇒ 读到空串，开局报错退出；
 *     fix-token-blacklist-index ⇒ 更隐蔽，resolveMongoUri 静默回退本地默认库，
 *       打印「已连接：127.0.0.1:27017/fire_safety_db」，运维以为在动生产；
 *     resign-audit-chain-v3 ⇒ 正常（它显式调了 hydrate，作为探测方法学的正向对照）。
 *   后果落在文档化的运维步骤上：`deployment/secret-rotation.md` 的轮换第 0/4/5 步都要求
 *   `node scripts/verify-audit-chain.js` 退出码 0，在 *_FILE 部署里这一步**做不到**。
 *
 * 判据因此取"每个入口自己显式 hydrate"，而不是"依赖图上有人 hydrate 过"：
 * 显式一行既 grep 得到，也不随依赖图重构失效。豁免必须带证据，不能预先占位。
 */

const fs = require('fs');
const path = require('path');
const { FILE_BACKED_SECRETS } = require('../../config/secrets');

const ROOT = path.resolve(__dirname, '../../..');
const SCRIPTS = path.join(ROOT, 'scripts');

/** 读点：`process.env.NAME` 或 `process.env['NAME']`，且不是赋值左侧（`===` 仍算读） */
const readPattern = (name) =>
  new RegExp(
    String.raw`(?:process\.env\.${name}\b|process\.env\[['"]${name}['"]\])(?!\s*=(?!=))`,
    'g'
  );

/** 写点：`process.env.NAME = …`（压测/探针入口给自己造临时值用的就是它） */
const writePattern = (name) =>
  new RegExp(String.raw`(?:process\.env\.${name}\b|process\.env\[['"]${name}['"]\])\s*=(?!=)`, 'g');

/** 共享护栏的引入点：它代读 MONGODB_URI，所以调用方也算读取者 */
const GUARD_REQUIRE = /require\(['"]\.{1,2}\/destructiveGuard['"]\)/g;

/** 一次扫描给出所有读点（直读 + 经护栏代读），按源码位置排序 */
function readsOf(src) {
  const reads = [];
  for (const name of FILE_BACKED_SECRETS) {
    for (const m of src.matchAll(readPattern(name))) reads.push({ name, at: m.index });
  }
  for (const m of src.matchAll(GUARD_REQUIRE))
    reads.push({ name: 'MONGODB_URI', at: m.index, via: 'destructiveGuard' });
  return reads;
}

/** 递归列出 scripts 下所有 JS 入口（跳过 node_modules） */
function listScripts(dir) {
  const out = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (entry.name === 'node_modules') continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) out.push(...listScripts(full));
    else if (/\.js$|\.cjs$/.test(entry.name)) out.push(full);
  }
  return out.sort();
}

/**
 * 纯函数：给定源码返回违规说明，无违规返回 null。
 * 抽成纯函数是为了能被"合成源码"直接攻击——见「判据可被攻击」用例。
 *
 * 读取有两条通道，只钉第一条会漏：
 *   ① 直读 `process.env.NAME`；
 *   ② 经共享护栏 `./destructiveGuard` 的 `resolveMongoUri()` 代读 MONGODB_URI。
 *      `fix-token-blacklist-index.js` 只有这一条通道，删掉它的 hydrate 时①判据闭嘴，
 *      闸会绿——而运维侧的表现是"静默回退本地库"。所以护栏调用点也按读点计。
 *
 * @param {string} src
 * @returns {string|null}
 */
function findHydrationOffender(src) {
  const reads = readsOf(src);
  if (reads.length === 0) return null;

  const hydrateAt = src.search(/hydrateSecretsFromFiles\s*\(/);
  if (hydrateAt === -1) {
    const names = [...new Set(reads.map((r) => r.name))].join(', ');
    return `读取文件型密钥 ${names}，但整个文件没有调用 hydrateSecretsFromFiles()`;
  }
  const first = reads.reduce((a, b) => (a.at <= b.at ? a : b));
  if (first.at < hydrateAt)
    return `首次读取 ${first.name} 发生在 hydrate 之前（读点 ${first.at} < hydrate ${hydrateAt}）`;
  return null;
}

/**
 * 豁免一：自带临时密钥/临时库的探针入口。
 * 它们跑的是内存 Mongo 与随机密钥，不需要文件型注入，但**确实读**这些 env，所以显式登记。
 * 登记的代价是必须拿出证据：每个被读到的名字都得能在同一文件里找到赋值处，
 * 删掉赋值守卫时闸门就报错，而不是让豁免悄悄生效。
 * 刻意**不**比较读写位置：这类文件读点在函数体内、赋值在 main 里，
 * 源码位置不代表执行顺序（本仓 destructiveGuardOrder.test.js 已为这个口径踩过一次）。
 */
const SELF_SEEDED = ['audit-probes/ws-session-bypass.cjs'];

/**
 * 豁免二：被同族脚本 require 的共享模块——不是进程入口，无权决定何时 hydrate，
 * 责任在各入口。下面用"确实被 ≥4 个入口 require"自证它真的是库，
 * 而不是一张没人认领的豁免条。
 */
const LIBRARIES = ['destructiveGuard.js'];

describe('独立脚本必须先 hydrate 文件型密钥再读 env', () => {
  const files = listScripts(SCRIPTS);
  const rel = (f) => path.relative(SCRIPTS, f).replace(/\\/g, '/');

  const analyzed = files.map((f) => {
    const src = fs.readFileSync(f, 'utf8');
    const readNames = [...new Set(readsOf(src).map((r) => r.name))];
    return {
      file: rel(f),
      src,
      readNames,
      offender: findHydrationOffender(src),
    };
  });

  const readers = analyzed.filter((a) => a.readNames.length > 0);
  const readerFiles = readers.map((r) => r.file);

  test('判据前提自证：扫描真的覆盖到了脚本，读点判据不是空转', () => {
    // 任一条归零都说明路径/正则写错了，此时的"全绿"只是判据失效的假绿
    expect(files.length).toBeGreaterThanOrEqual(15);
    expect(readers.length).toBeGreaterThanOrEqual(8);
    expect(readerFiles).toEqual(expect.arrayContaining(['verify-audit-chain.js']));
  });

  test('每个读取文件型密钥的入口都显式 hydrate，且早于首次读取', () => {
    const offenders = readers
      .filter((a) => !SELF_SEEDED.includes(a.file) && !LIBRARIES.includes(a.file))
      .filter((a) => a.offender !== null)
      .map((a) => `  ${a.file}：${a.offender}`);
    expect(offenders).toEqual([]);
  });

  test('豁免一成立的前提：自带临时值，且逐个名字都能找到赋值处', () => {
    const unjustified = [];
    for (const name of SELF_SEEDED) {
      const a = analyzed.find((x) => x.file === name);
      if (!a || a.readNames.length === 0) {
        unjustified.push(`  ${name}：已不读取任何文件型密钥（豁免条要一起删）`);
        continue;
      }
      for (const secret of a.readNames) {
        if (!writePattern(secret).test(a.src))
          unjustified.push(`  ${name}：读 ${secret} 却没有任何赋值处（豁免不成立）`);
      }
    }
    expect(unjustified).toEqual([]);
  });

  test('豁免二成立的前提：共享模块确实被入口 require', () => {
    const orphan = LIBRARIES.filter((name) => !readerFiles.includes(name)).map(
      (name) => `  ${name}：已不读取文件型密钥（豁免条要一起删）`
    );
    expect(orphan).toEqual([]);
    const consumers = readers.filter(
      (a) => !LIBRARIES.includes(a.file) && a.src.includes("require('./destructiveGuard')")
    );
    expect(consumers.length).toBeGreaterThanOrEqual(4);
  });

  test('判据可被攻击：缺 hydrate / hydrate 太晚 / 依赖图里有 config 都不能蒙混过关', () => {
    const reading = `require('dotenv').config();\nconst uri = process.env.MONGODB_URI;\n`;
    // ① 完全没有 hydrate——即使依赖图通向 src/config（懒 require）也照样判红
    expect(findHydrationOffender(`${reading}require('../src/config');`)).toContain(
      '没有调用 hydrateSecretsFromFiles'
    );
    // ② hydrate 写在读点之后：容器里读到的仍是空串
    expect(
      findHydrationOffender(`${reading}require('../src/config/secrets').hydrateSecretsFromFiles();`)
    ).toContain('发生在 hydrate 之前');
    // ③ 正确顺序必须放行（否则上面的判红可能只是"永远判红"）
    const good =
      "require('dotenv').config();\n" +
      "require('../src/config/secrets').hydrateSecretsFromFiles();\n" +
      'const uri = process.env.MONGODB_URI;\n';
    expect(findHydrationOffender(good)).toBeNull();
    // ④ 赋值不是读取：只写不读的脚本不该被拉进来说话
    expect(findHydrationOffender(`process.env.JWT_SECRET = 'x';\n`)).toBeNull();
    expect(findHydrationOffender(`process.env['AES_SECRET_KEY'] = 'x';\n`)).toBeNull();
    // ⑤ 比较（===）仍是读取，不能被"排除赋值"的规则误放走
    expect(findHydrationOffender(`if (process.env.HMAC_SECRET === '') {}\n`)).toContain(
      '没有调用 hydrateSecretsFromFiles'
    );
    // ⑥ 前缀同名的变量不得误伤（判据按整词边界走）
    expect(findHydrationOffender(`const x = process.env.JWT_SECRET_V2;\n`)).toBeNull();
  });

  test('只写不读的压测/演练入口不得预先占住豁免位', () => {
    // 这三个入口自己造临时库与随机密钥，今天**不读**文件型密钥，所以不在任何豁免名单里。
    // 哪天有人给它们加一行读取，上面那条闸就会红，届时才需要显式登记并补证据——
    // 豁免只能被证据换来的，不能预先囤。
    for (const f of ['e2e-smoke.js', 'load-test.js', 'production-drill.js']) {
      const a = analyzed.find((x) => x.file === f);
      expect(a).toBeDefined();
      expect(a.readNames).toEqual([]);
      expect(SELF_SEEDED).not.toContain(f);
      expect(LIBRARIES).not.toContain(f);
    }
  });

  test('反向对照：本轮修掉的六个脚本确实各读各 hydrate', () => {
    const fixed = [
      'verify-audit-chain.js',
      'revoke-user-sessions.js',
      'run-rollback-drill.js',
      'sync-audit-indexes.js',
      'fix-token-blacklist-index.js',
      'perf/explain-spotcheck.js',
    ];
    for (const f of fixed) {
      const a = analyzed.find((x) => x.file === f);
      if (!a) throw new Error(`脚本 ${f} 未被扫描到（路径变了要同步改这条）`);
      expect(a.readNames).toContain('MONGODB_URI');
      expect(a.offender).toBeNull();
    }
  });

  test('verify-audit-chain 的 hmac 层确实依赖文件型密钥（轮换文档要求退出码 0 的前提）', () => {
    const a = analyzed.find((x) => x.file === 'verify-audit-chain.js');
    if (!a) throw new Error('verify-audit-chain.js 未被扫描到');
    expect(a.readNames).toContain('MONGODB_URI');
    // 链校验的 hmac 密钥取自 config.hmacSecret；把它和 MONGODB_URI 一起钉住，
    // 避免有人把 hydrate 当成"可有可无的装饰"删掉。
    const auditChainSrc = fs.readFileSync(path.join(ROOT, 'src/utils/auditChain.js'), 'utf8');
    expect(auditChainSrc).toContain("require('../config').hmacSecret");
  });
});
