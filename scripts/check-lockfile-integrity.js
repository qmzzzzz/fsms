/**
 * 供应链完整性锚：lockfile 的 **semantic 哈希**比对（CI 门禁：`npm run check:lockfile`）
 *
 * 缺口形状：本仓的供应链检测面（`npm audit` / Dependabot / CodeQL / gitleaks /
 * install-script 门禁）全部回答同一个问题——「这个包有没有已知 CVE」。于是
 * **lockfile 被静默篡改**这件事没有任何自动检测：
 *   - PR 里夹带改一个 `integrity` 字段（版本号合法、无 CVE、audit 全绿）；
 *   - 本地误跑一次 `npm install`，分辨率被重写后顺手提交；
 *   - CI 缓存污染导致 `npm ci` 得到的树与仓库里那份锁文件不是一回事。
 * `dependency-review.yml` 只比对「新引入的依赖有无漏洞」，**不校验锁文件与上次是否一致**，
 * 所以上面三种现状全靠 code review 的人眼。
 *
 * 本锚把这三种变成显式不变量：把「上次人工拍板时锁文件长什么样」固化成一份哈希，
 * 写进版本库（`deployment/lockfile-anchor.json`），任何改动都会在 diff 里现形。
 *
 * ── 哈希口径为什么必须是 semantic 而不是原始字节 ──
 * 开发机是 Windows/CRLF 工作区，CI 是 ubuntu-latest/LF checkout，`.gitattributes`
 * 对 `package-lock.json` 无规则（走 `core.autocrlf` 默认行为）。实测（2026-09-30）：
 *   raw 原始字节哈希：CRLF 与 LF **漂移** ✗
 *   LF 归一化       ：稳定，但只是一种绕开；
 *   semantic        ：稳定 ✓（本文件采用）
 * 用 raw 口径的后果不是「偶尔红」，而是**在 CI 上恒假红**——而假红第一次出现就会被
 * `continue-on-error` 或「先注释掉」消化掉，等于没有门禁。这正是本仓「不要假定整个仓
 * 行尾统一」那条纪律的直接应用。
 *
 * ── 锚的覆盖面 = 2 份 lockfile ──
 *   package-lock.json              （后端）
 *   web-admin/package-lock.json    （前端）
 * **刻意不纳入 `zznpmtest/package-lock.json`**：它是会话期脚手架，已被
 * `.gitignore:106-110` 登记、`git ls-files zznpmtest/` 为 0 ⇒ 未入库，锚无从比对
 * （并入只会让新克隆恒红）。
 *
 * ── overrides 固化（2026-11-18）──
 * npm 不把 `overrides` 写进 lockfile 根块，只把结果烘焙进解析树——于是
 * 「改了 overrides 却没重新 install」或「动了锁文件却没同步 overrides」
 * 现有门禁全都看不见。verify() 在哈希比对之外追加一条判据：overrides
 * 声明的每个包，其 lockfile 解析版本必须满足声明范围（当前判据覆盖
 * `^X.Y.Z` 形态；超出形态按失败处理，不许静默放过）。
 *
 * ── 能力边界（如实声明，勿夸大）──
 *   ✓ 能挡：PR 夹带改 lockfile、本地误 `npm install` 改分辨率、CI 缓存污染、
 *           锚被静默改（锚文件本身在 git 里，改动必留 diff）
 *   ✗ 挡不了：**上游包本身被投毒**——lockfile 未变、`integrity` 未变，只是那个版本的
 *           代码本身是恶意的。这一类只有 SBOM + 来源证明 + CVE 面能挡。
 *   ✗ **它不是 SBOM**：不提供组件清单/许可证/来源证明。别把「有了完整性锚」误当成
 *           「有了 SBOM」。
 *
 * ── fail-closed ──
 * 锁文件缺失、JSON 解析失败、锚文件缺失/无对应条目 ⇒ 一律判 1。对齐
 * `check-utf8.js` 的「扫了 0 个文件不能算通过」纪律：**没比对成**不等于**比对通过**。
 *
 * 用法：
 *   node scripts/check-lockfile-integrity.js --verify   （默认；CI 用，不一致即 exit 1）
 *   node scripts/check-lockfile-integrity.js --update   （人工拍板后重写锚文件，必须显式指定）
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const ANCHOR_FILE = path.resolve(ROOT, 'deployment/lockfile-anchor.json');
const PACKAGE_FILE = path.resolve(ROOT, 'package.json');
const ROOT_LOCK = path.resolve(ROOT, 'package-lock.json');

// 锚覆盖的锁文件（相对仓库根，用 `/` 以保证跨平台一致）
const LOCK_PATHS = ['package-lock.json', 'web-admin/package-lock.json'];

// 与 semanticHash 的实现绑定；写入锚文件，将来改口径时能一眼看出存量锚过期了
const ALGORITHM = 'sha256';
const CANONICAL = 'json-sort-keys-compact-utf8';

/**
 * 递归规整：对象 key 排序、数组保序、其余原样。
 * 纯函数：不读文件、不打印、不退出（测试直接调它）。
 *
 * 数组**必须保序**——`package-lock.json` 的 `packages` 是对象、但 `dependencies`
 * 内部多处是对象；真正要紧的是「语义相同的两份 JSON 必然得到同一串」，而数组顺序
 * 本身就是语义（`files: ["a","b"]` 与 `["b","a"]` 不是同一份声明），所以只对 key 排序。
 *
 * @param {*} value JSON.parse 的结果
 * @returns {*} 规整后的结构
 */
function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === 'object') {
    const out = {};
    for (const k of Object.keys(value).sort()) out[k] = canonicalize(value[k]);
    return out;
  }
  return value;
}

/**
 * 语义哈希 = SHA-256(UTF-8(紧凑序列化(排序后结构)))。纯函数。
 *
 * 输入是**文本**而不是解析后的对象，是为了让「解析失败」这件事由调用方按 fail-closed
 * 处理，而不是在这里吞掉（`JSON.parse` 抛错时上游必须判 1，不能把它当成一个哈希）。
 *
 * @param {string} text lockfile 文本（行尾 CRLF/LF 均可，本口径不敏感）
 * @returns {string} 64 位十六进制 SHA-256
 */
function semanticHash(text) {
  const canon = canonicalize(JSON.parse(text));
  return crypto.createHash(ALGORITHM).update(JSON.stringify(canon), 'utf8').digest('hex');
}

/**
 * 逐份计算锁文件的语义哈希。
 * @returns {Record<string,string>} 相对路径 → 哈希（缺失/解析失败直接抛，由 main 判 1）
 */
function computeHashes() {
  const locks = {};
  for (const rel of LOCK_PATHS) {
    const abs = path.resolve(ROOT, rel);
    // 读为 utf8：JSON 规范下锁文件是 UTF-8；BOM 由 JSON.parse 后的排序规整吸收不了，
    // 故在此显式剥掉（npm 自己写的锁文件不带 BOM，但编辑器"另存为"可能加）
    const text = fs.readFileSync(abs, 'utf8').replace(/^\uFEFF/, '');
    locks[rel] = semanticHash(text);
  }
  return locks;
}

/** 读取锚文件；不存在或不可解析时返回 null（调用方判 1） */
function readAnchor() {
  try {
    return JSON.parse(fs.readFileSync(ANCHOR_FILE, 'utf8'));
  } catch {
    return null;
  }
}

function writeAnchor(locks) {
  const anchor = {
    note:
      'lockfile 的 semantic 哈希锚（sha256(json-sort-keys-compact-utf8)）。' +
      '变更依赖后必须跑 node scripts/check-lockfile-integrity.js --update，' +
      '并由人复核 diff——本文件在 git 里，任何改动都会留下可追溯的记录。',
    algorithm: ALGORITHM,
    canonical: CANONICAL,
    locks,
  };
  fs.writeFileSync(ANCHOR_FILE, JSON.stringify(anchor, null, 2) + '\n', 'utf8');
}

/** 逐份比对；返回不一致清单（含期望值/实际值/路径，供运维定位） */
function diffHashes(expected, actual) {
  const mismatches = [];
  for (const rel of LOCK_PATHS) {
    const exp = expected ? expected[rel] : undefined;
    const act = actual[rel];
    // 锚里缺这一条同样算不一致——否则往锚里删一行就能静默关掉一份 lockfile 的检测
    if (exp !== act) mismatches.push({ rel, expected: exp, actual: act });
  }
  return mismatches;
}

/**
 * 最小 caret 语义判定：仅支持 `^X.Y.Z` 形态（当前 overrides 只用了这一种）。
 * 返回 null 表示「形态超出本判据、无法判定」，调用方按 fail-closed 处理。
 * npm caret 语义：^X.y.z 限定主版本；^0.y.z 限定次版本；^0.0.z 限定补丁位。
 *
 * @param {string} version lockfile 里的解析版本（如 "11.1.1"）
 * @param {string} range overrides 声明的范围（如 "^11.1.1"）
 * @returns {boolean|null} true=满足 / false=不满足 / null=无法判定
 */
function caretSatisfies(version, range) {
  const rangeM = /^\^(\d+)\.(\d+)\.(\d+)$/.exec(String(range).trim());
  const verM = /^(\d+)\.(\d+)\.(\d+)(?:[-+][\w.+-]*)?$/.exec(String(version).trim());
  if (!rangeM || !verM) return null;
  const r = rangeM.slice(1).map(Number);
  const v = verM.slice(1).map(Number);
  const cmp = (a, b) => a[0] - b[0] || a[1] - b[1] || a[2] - b[2];
  const upper = r[0] > 0 ? [r[0] + 1, 0, 0] : r[1] > 0 ? [0, r[1] + 1, 0] : [0, 0, r[2] + 1];
  return cmp(v, r) >= 0 && cmp(v, upper) < 0;
}

/**
 * overrides 固化校验：package.json 声明的 overrides（如 uuid ^11.1.1）必须与
 * lockfile 的实际解析版本一致。返回失败清单（空数组 = 通过）。
 *
 * fail-closed：overrides 声明了某包但锁文件解析不到 ⇒ 失败（依赖已移除时应
 * 同步删 overrides）；范围/版本形态超出本判据 ⇒ 失败并要求人工扩展判据，
 * 不许静默放过——「没校验成」不等于「校验通过」。
 *
 * @returns {string[]} 失败描述清单
 */
function checkOverrides() {
  let pkg;
  try {
    pkg = JSON.parse(fs.readFileSync(PACKAGE_FILE, 'utf8').replace(/^\uFEFF/, ''));
  } catch (e) {
    return [`package.json 不可读/不可解析：${String(e.message).slice(0, 120)}`];
  }
  const overrides = pkg && pkg.overrides;
  if (!overrides || typeof overrides !== 'object' || Array.isArray(overrides)) return [];
  let lock;
  try {
    lock = JSON.parse(fs.readFileSync(ROOT_LOCK, 'utf8').replace(/^\uFEFF/, ''));
  } catch (e) {
    return [`package-lock.json 不可读/不可解析：${String(e.message).slice(0, 120)}`];
  }
  const failures = [];
  for (const [name, range] of Object.entries(overrides)) {
    if (typeof range !== 'string') {
      failures.push(`overrides.${name}：嵌套/键语法范围本判据不支持，请人工核对并扩展判据`);
      continue;
    }
    const resolved = lock.packages && lock.packages[`node_modules/${name}`];
    if (!resolved || !resolved.version) {
      failures.push(
        `overrides.${name}：声明 ${range}，但 lockfile 无该包的解析条目（依赖已移除？请同步 overrides）`
      );
      continue;
    }
    const ok = caretSatisfies(resolved.version, range);
    if (ok === null) {
      failures.push(
        `overrides.${name}：范围 ${range} 或解析版本 ${resolved.version} 超出本判据支持的 ^X.Y.Z 形态，请人工核对`
      );
    } else if (!ok) {
      failures.push(`overrides.${name}：声明 ${range}，但 lockfile 解析为 ${resolved.version}`);
    }
  }
  return failures;
}

/** @returns {number} 退出码（0=一致 / 1=不一致或环境不可信） */
function verify() {
  let actual;
  try {
    actual = computeHashes();
  } catch (e) {
    console.error(`LOCKFILE_UNREADABLE：${String(e.message).slice(0, 200)}`);
    console.error('锁文件缺失或 JSON 解析失败时不能判为通过（fail-closed）');
    return 1;
  }

  const anchor = readAnchor();
  if (!anchor) {
    console.error(`ANCHOR_MISSING_OR_INVALID：${path.relative(ROOT, ANCHOR_FILE)}`);
    console.error('锚文件不存在/不可解析 ⇒ 没有比对对象，不能判为通过（fail-closed）');
    return 1;
  }

  const overrideFailures = checkOverrides();
  const mismatches = diffHashes(anchor.locks, actual);
  if (mismatches.length === 0 && overrideFailures.length === 0) {
    console.log(
      `LOCKFILE_ANCHOR_OK（比对 ${LOCK_PATHS.length} 份：${LOCK_PATHS.join(', ')}；overrides 校验通过）`
    );
    return 0;
  }

  if (overrideFailures.length > 0) {
    console.error('OVERRIDES_MISMATCH：package.json overrides 与 lockfile 解析版本不一致。');
    for (const f of overrideFailures) console.error(`  ${f}`);
    console.error('overrides 是烘焙进锁文件解析树的硬约束，改动必须与 lockfile 同步提交。');
    console.error('');
  }
  if (mismatches.length > 0) {
    console.error('LOCKFILE_ANCHOR_MISMATCH：锁文件与锚不一致——依赖树被改动过。');
    for (const m of mismatches) {
      console.error(`  文件：${m.rel}`);
      console.error(
        `    期望（锚，algorithm=${anchor.algorithm} canonical=${anchor.canonical}）：`
      );
      console.error(`      ${m.expected === undefined ? '(锚中缺失此条目)' : m.expected}`);
      console.error(`    实际（当前工作区）：`);
      console.error(`      ${m.actual}`);
    }
    console.error('');
  }
  console.error('若这是**有意的**依赖变更：先人工复核 `git diff` 的锁文件内容（重点看');
  console.error('integrity / resolved / 新增包），确认无夹带后跑：');
  console.error('  node scripts/check-lockfile-integrity.js --update');
  console.error('并把 deployment/lockfile-anchor.json 的改动一并提交受评审。');
  return 1;
}

/** @returns {number} 退出码（0=已重写 / 1=环境不可信） */
function update() {
  let locks;
  try {
    locks = computeHashes();
  } catch (e) {
    console.error(`LOCKFILE_UNREADABLE：${String(e.message).slice(0, 200)}`);
    return 1;
  }
  const before = readAnchor();
  writeAnchor(locks);
  for (const rel of LOCK_PATHS) {
    const was = before && before.locks ? before.locks[rel] : undefined;
    const changed = was !== locks[rel];
    console.log(`${changed ? '已更新' : '未变化'}  ${rel}  ${locks[rel]}`);
  }
  console.log(`锚文件已写入：${path.relative(ROOT, ANCHOR_FILE)}`);
  return 0;
}

function main() {
  const arg = process.argv[2];
  if (arg === undefined || arg === '--verify') return process.exit(verify());
  if (arg === '--update') return process.exit(update());
  console.error(`未知参数：${arg}（支持 --verify / --update）`);
  process.exit(2);
}

// 作为脚本执行时才跑 CLI；被 require 时只暴露纯函数（测试直接调，不许复刻判据——
// 本仓已有过一次教训：测试复刻判据导致可证伪性为零，判据写反测试仍全绿）。
if (require.main === module) main();

module.exports = {
  canonicalize,
  semanticHash,
  caretSatisfies,
  checkOverrides,
  LOCK_PATHS,
  ANCHOR_FILE,
  ALGORITHM,
  CANONICAL,
};
