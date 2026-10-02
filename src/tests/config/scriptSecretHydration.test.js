/**
 * 独立入口的密钥回填不变量（2026-10-03 审计线）
 *
 * 背景：`src/config/secrets.js` 支持 Docker/K8s 的 `<NAME>_FILE` 约定（密钥以文件挂载，
 * 启动期回填 process.env，避免密钥出现在 `docker inspect` / `compose config` / 子进程继承里）。
 * 但**只有 require 到 src/config 的入口会自动回填**，而运维手边的入口大多是
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
 *   同一族的第三个入口是 `npm run validate`（src/config/validate.js，它连 dotenv 都不走）：
 *   实测四条「JWT_SECRET 必须设置为至少 32 字符」的**假错**，而 secret-rotation.md:156
 *   正是拿这一步当"轮换后配置自洽"的证据。
 *
 * 判据因此取"每个入口自己显式 hydrate（或在其之前 require src/config）"，
 * 而不是"依赖图上有人 hydrate 过"：显式一行既 grep 得到，也不随依赖图重构失效。
 * 豁免必须带证据，不能预先占位。
 *
 * 扫描范围三处取并集，每处各由一条前提自证钉住：`scripts/**`、根目录 `*.js`/`*.cjs`
 * （`migrate-mongo up` 这类"以命令名调 CLI、CLI 再加载同目录 config"的入口）、
 * 以及 package.json 里 `node <file>` 形态的 npm 入口。
 * 后两处都从仓库自身推导而不是写死清单（新增入口自动进闸，
 * 与 compose `:?` 清单闸同一口径）。
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

/**
 * 解构读点：`const { MONGODB_URI } = process.env` / `const { MONGODB_URI: alias } = …`
 * 这是同一读法的第三种书写形态；漏了它，用解构的文件会被判"不读密钥"而**静默豁免**——
 * 那是最坏的一种漏判（闸不响，容器里读到空串）。
 */
const destructurePattern = (name) =>
  new RegExp(`\\{[^}]*\\b${name}\\b[^}]*\\}\\s*=\\s*process\\.env`, 'g');

/** 别名读点：`const env = process.env` 之后的 `env.NAME` */
const aliasPattern = (alias, name) => new RegExp(`\\b${alias}\\.${name}\\b(?!\\s*=(?!=))`, 'g');

/** 别名声明本身 */
const ALIAS_DECLARE = /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*process\.env\b/g;

/**
 * 动态键读点：`process.env[someVar]`（既非字面量也非赋值）。
 * 静态无法判定它读到的是哪个密钥，所以按"可能是读取"处理——多算一个读点最多让入口
 * 早点显式 hydrate（无害），少算一个则是静默漏判。
 */
const DYNAMIC_READ = /process\.env\[\s*(?!['"])[^\]]+\](?!\s*=(?!=))/g;

/**
 * 共享护栏的引入点：它代读 MONGODB_URI，所以调用方也算读取者。
 * 口径刻意宽松到「require( 之后、右括号之前出现 destructiveGuard」：
 * 曾经写成 `require\((['"])\.{1,2}\/destructiveGuard\1\)`，于是
 * `require('./destructiveGuard.js')`（带扩展名）和
 * `require(path.join(__dirname, 'destructiveGuard'))`（动态拼路径）都不命中，
 * 而 `fix-token-blacklist-index.js` 唯一的读取通道就是它——漏判的表现不是报错，
 * 是运维看到一个"已连接：127.0.0.1:27017/fire_safety_db"然后动了本地库。
 * 宽松方向的代价只有多算一个读点（入口早点 hydrate，无害）。
 */
const GUARD_CONSUMER = /require\s*\([^)]*destructiveGuard/;
const GUARD_REQUIRE = new RegExp(GUARD_CONSUMER.source, 'g');

/**
 * 回填来源两处算：① 显式 `hydrateSecretsFromFiles()`；
 * ② 顶层 `require('<...>/config')`——src/config/index.js 在 require 时就 hydrate，
 * 所以这条依赖是**真的**（前提：它在首次读取之前；懒在函数体内的不算，
 * 而本文件既只看当前文件的文本，函数体内 require 的位置天然落在读取之后或压根匹配不到）。
 */
const HYDRATE_SOURCE =
  /hydrateSecretsFromFiles\s*\(|require\(\s*['"][^'"]*\/config(\/index)?['"]\s*\)/;

/**
 * 递归深度：给定已剥注释的代码，返回某位置处于第几层括号内。
 * 字符串/模板内容整体跳过（里面的 `{` 不是代码块起点）。模板里的 `${expr}`
 * 一并跳过——效果只会把读取算得"更深一层"，方向上保守（见豁免三的前提）。
 */
function depthAt(code, at) {
  let depth = 0;
  let i = 0;
  while (i < at && i < code.length) {
    const c = code[i];
    if (c === "'" || c === '"' || c === '`') {
      i += 1;
      while (i < code.length) {
        if (code[i] === '\\') {
          i += 2;
          continue;
        }
        if (code[i] === c) {
          i += 1;
          break;
        }
        i += 1;
      }
      continue;
    }
    if (c === '{' || c === '[' || c === '(') depth += 1;
    else if (c === '}' || c === ']' || c === ')') depth -= 1;
    i += 1;
  }
  return depth;
}

/** 模块顶层（第 0 层）的读取：require 的那一刻就执行，稍后 hydrate 救不回来 */
function topLevelReads(code) {
  return readsOf(code).filter((r) => depthAt(code, r.at) === 0);
}

/**
 * 豁免三：既是库、又是进程入口的文件。
 * `src/config/validate.js` 被 app.js / index.js / websocketService.js require，
 * 同时 `npm run validate` 直接执行它。把 hydrate 写在文件顶部确实能满足位置判据，
 * 但代价是 require 期覆写调用方的 process.env——本轮实测就是这么做了一次，
 * 连带打红 5 个配置套件（src/tests/setup.js 给每个 worker 预置了四把 *_FILE 临时副本，
 * 「先设 env、后 require」的夹具被回填悄悄改回测试密钥）。
 * 库不该在 require 期动全局环境，所以改成按**执行形状**判：入口支
 * （`if (require.main === module)`）里先回填、再调用校验函数。
 *
 * 豁免的前提必须可执行地成立，否则这就是一张空白条：
 * 该文件不得有任何模块顶层读取。前提一破，「豁免三的前提」用例即红，
 * 逼着改法回到正题（顶层 hydrate，同时让库不再被依赖"调用方设 env"）。
 */
const CLI_ENTRY_BLOCKS = ['src/config/validate.js'];

/** 纯函数：入口支的回填判据。抽出来是为了能被合成源码直接攻击。 */
function findCliEntryOffender(code) {
  const block = /if\s*\(\s*require\.main\s*===\s*module\s*\)\s*\{([\s\S]*?)\n\}/.exec(code);
  if (!block) return '没有 `if (require.main === module)` 入口支，无从判断进程入口何时回填';
  const body = block[1];
  const hydrateAt = body.search(/hydrateSecretsFromFiles\s*\(/);
  if (hydrateAt === -1) return '入口支里没有 hydrateSecretsFromFiles()';
  const callAt = body.search(/validateConfig\s*\(/);
  if (callAt !== -1 && hydrateAt > callAt) return '入口支里 hydrate 晚于 validateConfig() 调用';
  return null;
}

/**
 * 剥掉注释，只留代码——本仓铁律「注释不执行，不能当证据」。
 * 不剥的后果（本轮审计实测）：把 hydrate 的调用删掉、只留一句
 * 「// 这里需要 hydrateSecretsFromFiles()」，文本扫描看到的和真调用一模一样，闸绿而容器空读。
 * 逐字符走并跟踪引号状态是必须的：`'mongodb://127.0.0.1:27017/db'` 里的 `//`
 * 不是注释起点，按行粗暴截断会把连接串和它同行的读取一起吃掉。
 *
 * 已知边界（如实说明，不假装解决）：正则字面量里**未转义**的 `//`
 * （如空正则 `//`）会被误当注释起点。本仓入口里没有这种写法；真撞上表现为多报红
 * 而非漏报，属于可接受的失效方向。
 */
function stripComments(src) {
  let out = '';
  let i = 0;
  const n = src.length;
  while (i < n) {
    const c = src[i];
    const two = src.slice(i, i + 2);
    if (c === "'" || c === '"' || c === '`') {
      out += c;
      i += 1;
      while (i < n) {
        if (src[i] === '\\') {
          out += src[i] + (src[i + 1] ?? '');
          i += 2;
          continue;
        }
        out += src[i];
        if (src[i] === c) {
          i += 1;
          break;
        }
        i += 1;
      }
      continue;
    }
    if (two === '//') {
      while (i < n && src[i] !== '\n') i += 1;
      continue;
    }
    if (two === '/*') {
      i += 2;
      while (i < n && src.slice(i, i + 2) !== '*/') i += 1;
      i += 2;
      continue;
    }
    out += c;
    i += 1;
  }
  return out;
}

/** 一次扫描给出所有读点（直读 / 解构 / 别名 / 动态键 / 经护栏代读），按源码位置排序 */
function readsOf(code) {
  const reads = [];
  const aliases = [...code.matchAll(ALIAS_DECLARE)].map((m) => m[1]);
  for (const name of FILE_BACKED_SECRETS) {
    for (const m of code.matchAll(readPattern(name))) reads.push({ name, at: m.index });
    for (const m of code.matchAll(destructurePattern(name)))
      reads.push({ name, at: m.index, via: 'destructure' });
    for (const alias of aliases) {
      if (alias === 'process') continue;
      for (const m of code.matchAll(aliasPattern(alias, name)))
        reads.push({ name, at: m.index, via: `alias:${alias}` });
    }
  }
  for (const m of code.matchAll(GUARD_REQUIRE))
    reads.push({ name: 'MONGODB_URI', at: m.index, via: 'destructiveGuard' });
  for (const m of code.matchAll(DYNAMIC_READ))
    reads.push({ name: '(动态键)', at: m.index, via: 'computed' });
  return reads;
}

/**
 * 纯函数：给定源码返回违规说明，无违规返回 null。
 * 抽成纯函数是为了能被"合成源码"直接攻击——见「判据可被攻击」用例。
 *
 * 读取有五条通道，只钉第一条会漏（本轮审计逐条实测出来的漏判形态）：
 *   ① 直读 `process.env.NAME`；
 *   ② 解构 `const { NAME } = process.env`；
 *   ③ 别名 `const env = process.env; env.NAME`；
 *   ④ 动态键 `process.env[k]`（静态判不了，按"可能是读"计）；
 *   ⑤ 经共享护栏 `destructiveGuard` 的 `resolveMongoUri()` 代读 MONGODB_URI。
 * hydrate 一律在**剥掉注释之后**的文本上找，读点同基（位置才可比）。
 *
 * @param {string} src 原始源码
 * @returns {string|null}
 */
function findHydrationOffender(src) {
  const code = stripComments(src);
  const reads = readsOf(code);
  if (reads.length === 0) return null;

  const hydrateAt = code.search(HYDRATE_SOURCE);
  if (hydrateAt === -1) {
    const names = [...new Set(reads.map((r) => r.name))].join(', ');
    return `读取文件型密钥 ${names}，但整个文件没有调用 hydrateSecretsFromFiles()`;
  }
  const first = reads.reduce((a, b) => (a.at <= b.at ? a : b));
  if (first.at < hydrateAt)
    return `首次读取 ${first.name} 发生在 hydrate 之前（读点 ${first.at} < hydrate ${hydrateAt}）`;
  return null;
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
 * 根目录下的进程入口配置（`eslint.config.js` / `jest.config.js` / `migrate-mongo-config.js` …）。
 * 为什么单独取一层：`migrate-mongo up`（package.json 里的 npm 入口）是以**裸命令名**调 CLI 的，
 * `node <file>` 那条匹配规则看不见它，而 CLI 自己会把同目录的 `migrate-mongo-config.js`
 * 当模块加载——那个文件里就有 `resolveMongoUri()`，是真正的独立入口。
 * 上一轮修复给它补的 hydrate 因此一直站在闸外：删掉那行不会有任何测试变红。
 * 这里不按文件名白名单（写死清单会随依赖 CLI 变化失效），而是整层纳入；
 * 不是读取者的文件自然判不出违规，成本只是多读几个文件。
 */
function listRootEntries() {
  return fs
    .readdirSync(ROOT, { withFileTypes: true })
    .filter((e) => e.isFile() && /\.js$|\.cjs$/.test(e.name))
    .map((e) => path.join(ROOT, e.name))
    .sort();
}

/**
 * package.json 里 `node <file>` 形态的 npm 入口（运维手边真实会敲的命令）。
 * 不写死清单：新增一条 npm 入口自动进闸。`src/config/validate.js` 就是靠这条
 * 从"没人想到要扫"变成"必须扫"的——它既不在 scripts/ 下，也没有 dotenv。
 */
function listNpmEntries() {
  const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));
  const out = new Set();
  for (const cmd of Object.values(pkg.scripts || {})) {
    for (const m of String(cmd).matchAll(/node\s+([\w./\\-]+\.(?:js|cjs|mjs))/g)) {
      const full = path.join(ROOT, m[1].replace(/\\/g, '/'));
      if (fs.existsSync(full)) out.add(full);
    }
  }
  return [...out].sort();
}

/**
 * 豁免一：自带临时密钥/临时库的探针入口。
 * 它们跑的是内存 Mongo 与随机密钥，不需要文件型注入，但**确实读**这些 env，所以显式登记。
 * 登记的代价是必须拿出证据：每个被读到的名字都得能在同一文件里找到赋值处，
 * 删掉赋值守卫时闸门就报错，而不是让豁免悄悄生效。
 * 刻意**不**比较读写位置：这类文件读点在函数体内、赋值在 main 里，
 * 源码位置不代表执行顺序（本仓 destructiveGuardOrder.test.js 已为这个口径踩过一次）。
 * 同样不解决的还有"hydrate 写在从未调用的函数里"——那是文本位置判据的原理性上限，
 * 抵住它的是动态探测，不是这条闸。
 */
const SELF_SEEDED = ['scripts/audit-probes/ws-session-bypass.cjs'];

/**
 * 豁免二：被同族脚本 require 的共享模块——不是进程入口，无权决定何时 hydrate，
 * 责任在各入口。下面用"确实被 ≥4 个入口 require"自证它真的是库，
 * 而不是一张没人认领的豁免条。
 */
const LIBRARIES = ['scripts/destructiveGuard.js'];

describe('入口脚本必须先 hydrate 文件型密钥再读 env', () => {
  const files = [
    ...new Set([...listScripts(SCRIPTS), ...listRootEntries(), ...listNpmEntries()]),
  ].sort();
  const rel = (f) => path.relative(ROOT, f).replace(/\\/g, '/');

  const analyzed = files.map((f) => {
    const src = fs.readFileSync(f, 'utf8');
    const code = stripComments(src);
    const readNames = [
      ...new Set(
        readsOf(code)
          .map((r) => r.name)
          .filter((n) => n !== '(动态键)')
      ),
    ];
    return {
      file: rel(f),
      src,
      code,
      readNames,
      hasDynamicRead: readsOf(code).some((r) => r.name === '(动态键)'),
      offender: CLI_ENTRY_BLOCKS.includes(rel(f))
        ? findCliEntryOffender(code)
        : findHydrationOffender(src),
    };
  });

  const readers = analyzed.filter((a) => a.readNames.length > 0 || a.hasDynamicRead);
  const readerFiles = readers.map((r) => r.file);

  test('判据前提自证：扫描真的覆盖到脚本、根入口与 npm 入口，读点判据不是空转', () => {
    // 任一条归零都说明路径/正则写错了，此时的"全绿"只是判据失效的假绿
    expect(files.length).toBeGreaterThanOrEqual(24);
    expect(readerFiles).toEqual(expect.arrayContaining(['scripts/verify-audit-chain.js']));
    // npm 入口这条通道单独自证：package.json 推导失败时这里会归零
    const npmOnly = files.map(rel).filter((f) => f.startsWith('src/'));
    expect(npmOnly).toEqual(expect.arrayContaining(['src/config/validate.js', 'src/index.js']));
    // 根目录入口这条通道单独自证：它靠 listRootEntries 而不是 package.json
    expect(readerFiles).toContain('migrate-mongo-config.js');
    expect(readers.length).toBeGreaterThanOrEqual(10);
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
        if (!writePattern(secret).test(a.code))
          unjustified.push(`  ${name}：读 ${secret} 却没有任何赋值处（豁免不成立）`);
      }
      // 动态键读点无法逐名取证：豁免必须能说清"它自己种了什么"，否则不认
      if (a.hasDynamicRead && !ALIAS_DECLARE.test(a.code))
        unjustified.push(`  ${name}：有 process.env[变量] 读取却给不出逐个名字的赋值证据`);
    }
    expect(unjustified).toEqual([]);
  });

  test('豁免二成立的前提：共享模块确实被入口 require', () => {
    const orphan = LIBRARIES.filter((name) => !readerFiles.includes(name)).map(
      (name) => `  ${name}：已不读取文件型密钥（豁免条要一起删）`
    );
    expect(orphan).toEqual([]);
    const consumers = readers.filter(
      (a) => !LIBRARIES.includes(a.file) && GUARD_CONSUMER.test(a.code)
    );
    expect(consumers.length).toBeGreaterThanOrEqual(4);
  });

  test('判据可被攻击（一）：缺 hydrate / hydrate 太晚 / 依赖图里有 config 都不能蒙混', () => {
    const reading = `require('dotenv').config();\nconst uri = process.env.MONGODB_URI;\n`;
    // ① 压根没有回填来源
    expect(findHydrationOffender(reading)).toContain('没有调用 hydrateSecretsFromFiles');
    // ② 有 src/config 依赖、但 require 写在读取之后 ⇒ 照样判红。
    //    这正是六个脚本当初的形态：依赖图通向 config，可那是函数体内的懒 require，
    //    读 env 时它一行都还没执行。"图里有 config"不是证据，位置才是。
    expect(findHydrationOffender(`${reading}require('../src/config');`)).toContain(
      '发生在 hydrate 之前'
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
    // ④ 顶层 require src/config 也算回填来源（config/index.js 在 require 期就 hydrate）
    expect(
      findHydrationOffender("require('./config');\nconst uri = process.env.MONGODB_URI;\n")
    ).toBeNull();
    // ⑤ 赋值不是读取：只写不读的脚本不该被拉进来说话
    expect(findHydrationOffender(`process.env.JWT_SECRET = 'x';\n`)).toBeNull();
    expect(findHydrationOffender(`process.env['AES_SECRET_KEY'] = 'x';\n`)).toBeNull();
    // ⑥ 比较（===）仍是读取，不能被"排除赋值"的规则误放走
    expect(findHydrationOffender(`if (process.env.HMAC_SECRET === '') {}\n`)).toContain(
      '没有调用 hydrateSecretsFromFiles'
    );
    // ⑦ 前缀同名的变量不得误伤（判据按整词边界走）
    expect(findHydrationOffender(`const x = process.env.JWT_SECRET_V2;\n`)).toBeNull();
  });

  test('判据可被攻击（二）：注释里的 hydrate 不算证据', () => {
    // 本轮审计实测的漏判形态：删掉真调用、留一句注释提到它
    const commentOnly =
      "require('dotenv').config();\n" +
      '// 这里需要 require(../src/config/secrets).hydrateSecretsFromFiles(); 否则读到空串\n' +
      'const uri = process.env.MONGODB_URI;\n';
    expect(findHydrationOffender(commentOnly)).toContain('没有调用 hydrateSecretsFromFiles');
    // 行尾追加注释同样不算
    const trailing =
      "require('dotenv').config();\n" +
      'const uri = process.env.MONGODB_URI; // hydrateSecretsFromFiles() 已在别处做过\n';
    expect(findHydrationOffender(trailing)).toContain('没有调用 hydrateSecretsFromFiles');
    // 块注释同理
    const blocked = '/* hydrateSecretsFromFiles(); */\nconst u = process.env.REDIS_URL;\n';
    expect(findHydrationOffender(blocked)).toContain('没有调用 hydrateSecretsFromFiles');
    // 反面：注释剥离不能把字符串里的 // 当注释起点（连接串里的 // 是内容）
    const uri = "const uri = 'mongodb://127.0.0.1:27017/db';\n";
    expect(stripComments(uri)).toBe(uri);
    expect(stripComments('hydrateSecretsFromFiles(); // 真正的调用在上一行\n')).toContain(
      'hydrateSecretsFromFiles();'
    );
  });

  test('判据可被攻击（三）：解构与别名两种读法不得静默豁免', () => {
    // 漏了这两种，用它们的文件会被判"不读密钥"⇒ 整条闸对该文件永久失明
    expect(
      findHydrationOffender('const { MONGODB_URI } = process.env;\nfoo(MONGODB_URI);\n')
    ).toContain('没有调用 hydrateSecretsFromFiles');
    expect(
      findHydrationOffender('const { HMAC_SECRET: hs, REDIS_URL } = process.env;\n')
    ).toContain('没有调用 hydrateSecretsFromFiles');
    expect(
      findHydrationOffender('const env = process.env;\nconst u = env.MONGODB_URI;\n')
    ).toContain('没有调用 hydrateSecretsFromFiles');
    // 解构/别名读取 + 正确 hydrate ⇒ 放行（证明上面不是靠"永远判红"混过去的）
    expect(
      findHydrationOffender(
        "require('./secrets').hydrateSecretsFromFiles();\nconst { MONGODB_URI } = process.env;\n"
      )
    ).toBeNull();
    // 动态键读点按"可能是读取"计，同样要求 hydrate
    expect(findHydrationOffender('for (const k of NAMES) use(process.env[k]);\n')).toContain(
      '没有调用 hydrateSecretsFromFiles'
    );
    // 而 process.env[k] = v 是赋值，不算读取
    expect(findHydrationOffender('for (const k of NAMES) process.env[k] = v;\n')).toBeNull();
  });

  test('护栏代读通道认得带扩展名与 path.join 的写法', () => {
    // GUARD_REQUIRE 曾是 `require\(['"]\.{1,2}\/destructiveGuard['"]\)`：
    // `require('./destructiveGuard.js')` 与 `require(path.join(__dirname,'destructiveGuard'))`
    // 都不命中 ⇒ fix-token-blacklist-index 那个"静默回退本地库"的缺陷类别可以再次溜过。
    for (const form of [
      "require('./destructiveGuard')",
      "require('./destructiveGuard.js')",
      'require("./destructiveGuard.js")',
      "require(path.join(__dirname, 'destructiveGuard'))",
      "require('../scripts/destructiveGuard')",
    ]) {
      const src = `${form};\nconnectDB();\n`;
      expect({ form, verdict: findHydrationOffender(src) }).toMatchObject({
        form,
        verdict: expect.stringContaining('没有调用 hydrateSecretsFromFiles'),
      });
    }
    // 反向：加了 hydrate 的同一形态必须放行
    expect(
      findHydrationOffender(
        "require('../src/config/secrets').hydrateSecretsFromFiles();\nrequire('./destructiveGuard.js');\n"
      )
    ).toBeNull();
  });

  test('只写不读的压测/演练入口不得预先占住豁免位', () => {
    // 这三个入口自己造临时库与随机密钥，今天**不读**文件型密钥，所以不在任何豁免名单里。
    // 哪天有人给它们加一行读取，上面那条闸就会红，届时才需要显式登记并补证据——
    // 豁免只能被证据换来的，不能预先囤。
    for (const f of [
      'scripts/e2e-smoke.js',
      'scripts/load-test.js',
      'scripts/production-drill.js',
    ]) {
      const a = analyzed.find((x) => x.file === f);
      expect(a).toBeDefined();
      expect(a.readNames).toEqual([]);
      expect(a.hasDynamicRead).toBe(false);
      expect(SELF_SEEDED).not.toContain(f);
      expect(LIBRARIES).not.toContain(f);
      expect(CLI_ENTRY_BLOCKS).not.toContain(f);
    }
  });

  test('反向对照：本轮修掉的六个脚本确实各读各 hydrate', () => {
    const fixed = [
      'scripts/verify-audit-chain.js',
      'scripts/revoke-user-sessions.js',
      'scripts/run-rollback-drill.js',
      'scripts/sync-audit-indexes.js',
      'scripts/fix-token-blacklist-index.js',
      'scripts/perf/explain-spotcheck.js',
    ];
    for (const f of fixed) {
      const a = analyzed.find((x) => x.file === f);
      if (!a) throw new Error(`脚本 ${f} 未被扫描到（路径变了要同步改这条）`);
      expect(a.readNames).toContain('MONGODB_URI');
      expect(a.offender).toBeNull();
      // 减法自证：把它的 hydrate 调用擦掉，闸必须点名这个文件。
      // 少了这一步，"全绿"可能只是因为读点判据根本没看见它（fix-token-blacklist-index
      // 上一轮就是这么溜过去的：它唯一的读取通道是护栏代读，而当时的正则不认那条）。
      const stripped = a.code.replace(/hydrateSecretsFromFiles\s*\(\s*\)/, '');
      expect(stripped).not.toBe(a.code);
      expect({ file: f, verdict: findHydrationOffender(stripped) }).toMatchObject({
        file: f,
        verdict: expect.stringContaining('hydrate'),
      });
    }
  });

  test('npm run validate 的入口支回填后才校验（否则报四条假弱密钥）', () => {
    // 这条单独钉，因为它的失效形态最误导：不是"读不到密钥"，而是"密钥看起来弱"。
    // 实测：只给 *_FILE 时 `node src/config/validate.js` 报
    //   JWT_SECRET / JWT_REFRESH_SECRET / AES_SECRET_KEY / HMAC_SECRET 四条
    //   「必须设置为至少 32 字符的强随机值」，退出码 1；
    //   用 -r 预加载先 hydrate ⇒ 四条全部消失（余下三条是 REDIS_URL/TRUST_PROXY_HOPS/
    //   TLS 终结形态，与回填无关）。deployment/secret-rotation.md:156 正是拿这步当证据。
    const a = analyzed.find((x) => x.file === 'src/config/validate.js');
    if (!a) throw new Error('src/config/validate.js 未进入扫描（npm 入口通道失效？）');
    expect(a.readNames).toEqual(
      expect.arrayContaining(['JWT_SECRET', 'JWT_REFRESH_SECRET', 'AES_SECRET_KEY', 'HMAC_SECRET'])
    );
    expect(a.offender).toBeNull();
  });

  test('豁免三成立的前提：validate.js 没有模块顶层读取', () => {
    // 位置判据在这里被换成入口支判据，换来的是"库不在 require 期覆写调用方的 env"。
    // 这笔交易只在**所有读取都在函数体内**时才成立：一旦有人把读取提到第 0 层，
    // require 的那一刻就读了，而 hydrate 要等到进程入口支——前提破了这条就红。
    for (const f of CLI_ENTRY_BLOCKS) {
      const a = analyzed.find((x) => x.file === f);
      if (!a) throw new Error(`${f} 未进入扫描，豁免条成了空白条`);
      expect({ f, topReads: topLevelReads(a.code).map((r) => r.name) }).toMatchObject({
        f,
        topReads: [],
      });
    }
    // 前提判据自己也得有牙：合成一份"顶层读取"的同族文件，必须被它点名
    expect(topLevelReads('const u = process.env.JWT_SECRET;\n')).toHaveLength(1);
    expect(topLevelReads('function main() {\n  const u = process.env.JWT_SECRET;\n}\n')).toEqual(
      []
    );
  });

  test('判据可被攻击（四）：入口支缺 hydrate / 顺序颠倒 / 没有入口支都判红', () => {
    const ok =
      "const { validateConfig } = require('./x');\n" +
      'function validateConfig() { return process.env.JWT_SECRET; }\n' +
      'if (require.main === module) {\n' +
      "  require('./secrets').hydrateSecretsFromFiles();\n" +
      '  validateConfig();\n' +
      '}\n';
    expect(findCliEntryOffender(ok)).toBeNull();
    // ① 入口支里没回填：*_FILE 部署下四条假弱密钥照旧
    expect(
      findCliEntryOffender(ok.replace("  require('./secrets').hydrateSecretsFromFiles();\n", ''))
    ).toContain('没有 hydrateSecretsFromFiles');
    // ② 顺序颠倒：先校验后回填，读到的仍是 undefined
    const reversed = ok.replace(
      /hydrateSecretsFromFiles\(\);\s*validateConfig\(\);/,
      'validateConfig();\n  hydrateSecretsFromFiles();'
    );
    expect(findCliEntryOffender(reversed)).toContain('晚于 validateConfig() 调用');
    // ③ 整个入口支没了（比如改成顶层 hydrate，也就是本轮被打回的那个方案）：
    //    判据不知道进程入口何时回填，必须报红而不是沉默
    expect(
      findCliEntryOffender(
        "require('./secrets').hydrateSecretsFromFiles();\nfunction f() { return process.env.JWT_SECRET; }\n"
      )
    ).toContain('没有 `if (require.main === module)` 入口支');
    // ④ 真文件做减法：擦掉 validate.js 入口支里的 hydrate，闸必须点名它
    const a = analyzed.find((x) => x.file === 'src/config/validate.js');
    const stripped = a.code.replace(
      /require\(['"]\.\/secrets['"]\)\.hydrateSecretsFromFiles\(\);/,
      ''
    );
    expect(stripped).not.toBe(a.code);
    expect(findCliEntryOffender(stripped)).toContain('没有 hydrateSecretsFromFiles');
  });

  test('migrate-mongo-config.js 在闸内：删掉它的 hydrate 必须判红', () => {
    // 它是 `npm run migrate:up` 真正加载的入口，却既不在 scripts/ 下，也不是 `node <file>` 形态。
    // 只断言"它被扫到了"不够——那靠的是它**碰巧**被 require 护栏。这里用同一份源码做减法：
    // 把 hydrate 那行去掉，闸必须点名它（否则这轮补的覆盖面依然可以是哑的）。
    const a = analyzed.find((x) => x.file === 'migrate-mongo-config.js');
    if (!a) throw new Error('migrate-mongo-config.js 未进入扫描（根入口通道失效？）');
    expect(a.readNames).toContain('MONGODB_URI');
    expect(a.offender).toBeNull();
    const withoutHydrate = a.code.replace(
      /require\(['"]\.\/src\/config\/secrets['"]\)\.hydrateSecretsFromFiles\(\);/,
      ''
    );
    expect(withoutHydrate).not.toBe(a.code); // 减法必须真的动了，否则这条断言是空的
    expect(findHydrationOffender(withoutHydrate)).toContain('没有调用 hydrateSecretsFromFiles');
  });

  test('verify-audit-chain 的 hmac 层确实依赖文件型密钥（轮换文档要求退出码 0 的前提）', () => {
    const a = analyzed.find((x) => x.file === 'scripts/verify-audit-chain.js');
    if (!a) throw new Error('verify-audit-chain.js 未被扫描到');
    expect(a.readNames).toContain('MONGODB_URI');
    // 链校验的 hmac 密钥取自 config.hmacSecret；把它和 MONGODB_URI 一起钉住，
    // 避免有人把 hydrate 当成"可有可无的装饰"删掉。
    const auditChainSrc = fs.readFileSync(path.join(ROOT, 'src/utils/auditChain.js'), 'utf8');
    expect(auditChainSrc).toContain("require('../config').hmacSecret");
  });
});
