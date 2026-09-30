/**
 * P2-⑫ 供应链门禁：安装脚本必须**显式登记**——生产树零容忍，dev 树逐个评审。
 *
 * 为什么比 `npm ci --ignore-scripts` 更进一步：ignore-scripts 让安装跳过脚本，
 * 但**没有人在看**——今天加一个新依赖、它带了个 install 脚本，安装照样成功、
 * 脚本照样在开发机上跑（本地不会带 --ignore-scripts），门禁形同虚设。
 * 本检查把「哪些包带安装脚本」变成显式不变量，并按依赖树分两档：
 *   - **生产树命中即红**（lockfile 中非 dev 的条目）：必须逐个评审后登记到
 *     PROD_INSTALL_SCRIPT_ALLOWLIST（并写明理由）。Dockerfile 的 runtime 阶段与
 *     `npm ci --omit=dev --ignore-scripts` 之所以安全，正是**由这一档来保证**——
 *     它保证「忽略脚本后的生产闭包里根本没有脚本需要忽略」。
 *   - **dev 树命中亦红**（lockfile 中 dev:true 的条目）：devDeps 里的安装脚本会在
 *     开发机、CI 的 test/e2e 作业上执行（那里刻意不加 --ignore-scripts，因为测试
 *     需要 mongod），属真实供应链风险面，必须登记到 DEV_INSTALL_SCRIPT_ALLOWLIST
 *     并写明「它装了什么、为什么可接受」。
 *
 * 判据来源：**package-lock.json 的 `packages` 段**，而不是扫 node_modules 目录，也不是
 * `npm ls --json`——后者的每个节点**只有 version/resolved/dependencies，不含 scripts**
 * （实测 1317 个节点 0 个带 scripts），无法据此判定，而目录扫描又会把残留在
 * node_modules 里、根本不在锁文件中的孤儿目录算成命中。锁文件是 `npm ci` 的事实来源，
 * 且其 `hasInstallScript` 由 npm 在写入时离线标定：
 *   - 与平台无关（fsevents 的 os:["darwin"] 在 Linux CI 上装不上，但在锁里仍有标记）；
 *   - `dev:true` 精确标出「省略 devDependencies 时这一条会被排除」。
 * 注意：`@scarf/scarf` 在锁里**不是 dev**（经 swagger-ui-express → swagger-ui-dist 传递引入），
 * 因此它属生产树——说它「是 dev」是错的，本检查按锁文件的真实标记判定。
 *
 * 用法（CI security-audit 作业，两次调用）：
 *   node scripts/check-prod-install-scripts.js --omit=dev
 *   node scripts/check-prod-install-scripts.js --scan
 * 默认（无标志）等价于 --omit=dev，便于人工按直觉运行。
 *
 * 本文件刻意保持精短：本仓有 max-lines 棘轮，文件体积不得超过基线。
 */

const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const LOCKFILE = path.resolve(ROOT, 'package-lock.json');

/** 评审后确需保留安装脚本的生产依赖，登记于此并写明理由。
 *  @scarf/scarf：经 swagger-ui-express → swagger-ui-dist → @scarf/scarf 传递引入
 *  （锁文件中**无 dev 标记**，故属生产树）。其 postinstall 是遥测上报（向 scarf.sh
 *  发送匿名安装计数），不产出运行期所需文件；`npm ci --omit=dev --ignore-scripts`
 *  跳过它不影响功能。之所以登记而非删除：它是 swagger-ui-dist 的硬依赖，
 *  无法在不弃用 swagger 文档页面前提下移除。供应链残余面已由「CI 一律
 *  --ignore-scripts + 本登记册显式表态」双重覆盖（runtime 镜像不会真的执行它）。
 */
const PROD_INSTALL_SCRIPT_ALLOWLIST = ['@scarf/scarf'];

/**
 * dev 树安装脚本登记册。键=包名，值=「它做了什么、为什么可接受」。
 * 新增一行都必须在评审中给出理由——这正是本档要的效果：让「devDeps 里的安装脚本」
 * 从「静默存在」变成「显式表态」。
 */
const DEV_INSTALL_SCRIPT_ALLOWLIST = {
  'mongodb-memory-server':
    'postinstall 预下载 mongod 二进制；失败时 process.exit(0) 不阻断安装（postinstallHelper.js:36），' +
    '缺它则下载延迟到 jest worker 首次 create 时才发生（见 ci.yml 的 --forceExit 注释所述竞态）',
  fsevents:
    'optional 且 os:["darwin"]——仅 macOS 安装；其 install 脚本编译/选取文件系统观察原生绑定。' +
    '在 Linux CI 与 linux 镜像上根本不会被安装，属平台性噪音而非可利用面。',
};

/** `node_modules/@scope/name` / `node_modules/name` / `node_modules/a/node_modules/name` → 包名 */
function lockPathToPkgName(p) {
  const marker = p.lastIndexOf('node_modules/');
  if (marker < 0) return null;
  const rest = p.slice(marker + 'node_modules/'.length);
  // scoped 包是 `@scope/name`（只可能是最后一段名字带 scope），非 scoped 是单段
  return rest.includes('/') ? rest.slice(0, rest.indexOf('/')) + '/' + rest.split('/')[1] : rest;
}

/**
 * 从锁文件取所有带安装脚本的条目（按包名去重——同一包可能有多个安装位置，如
 * `node_modules/fsevents` 与 `node_modules/playwright/node_modules/fsevents`）。
 * @returns {{name:string, dev:boolean, optional:boolean, os:string[]|undefined}[]}
 */
function collectFromLockfile(lock) {
  const packages = (lock || {}).packages || {};
  const found = new Map();
  for (const [p, meta] of Object.entries(packages)) {
    if (!meta || !meta.hasInstallScript) continue;
    const name = lockPathToPkgName(p);
    if (!name || found.has(name)) continue;
    found.set(name, { name, dev: !!meta.dev, optional: !!meta.optional, os: meta.os });
  }
  return [...found.values()];
}

/**
 * 判定核心（纯函数：不读 argv、不调 process.exit、不打印）。
 *
 * 抽出来的**唯一理由**是可证伪性：原实现把「读锁文件 → 筛选 → 退出码」全写在一个
 * run() 里并在顶层 main()，导致测试无法调用它——只能**复刻**一份判据（实测后果：
 * 把筛选条件 `omitDev ? !e.dev : e.dev` 写反，门禁本身退化成"永远失败"，
 * 而复刻版测试 6/6 全绿，这道闸的可证伪性为零）。现在测试真调本函数，
 * 改坏判据必然让测试红。
 *
 * @param {object} lock package-lock.json 的解析结果（注入以便测试构造变异样本）
 * @param {boolean} omitDev true=生产树（非 dev 条目）；false=dev 树
 * @returns {{all: Array, offenders: Array, allowlist: string[]}}
 */
function evaluate(lock, omitDev) {
  const entries = collectFromLockfile(lock);
  const all = entries.filter((e) => (omitDev ? !e.dev : e.dev));
  const allowlist = omitDev
    ? PROD_INSTALL_SCRIPT_ALLOWLIST
    : Object.keys(DEV_INSTALL_SCRIPT_ALLOWLIST);
  return { all, offenders: all.filter((f) => !allowlist.includes(f.name)), allowlist };
}

/** @returns {number} 退出码（0=通过 / 1=未登记命中） */
function run(omitDev) {
  const mode = omitDev ? '生产树（--omit=dev）' : 'dev 树（--scan：含 devDependencies）';
  let lock;
  try {
    lock = JSON.parse(fs.readFileSync(LOCKFILE, 'utf8'));
  } catch (e) {
    console.error(`Error: 无法读取/解析 package-lock.json：${String(e.message).slice(0, 200)}`);
    return 1;
  }
  const { all, offenders, allowlist } = evaluate(lock, omitDev);

  console.log(`[${mode}] 锁文件中带安装脚本的依赖（含已登记）：`);
  if (all.length === 0) console.log('  （无）');
  all.forEach((f) =>
    console.log(
      `  ${f.name}${f.optional ? `（optional${f.os ? '，仅 ' + f.os.join('/') : ''}）` : ''}`
    )
  );

  if (offenders.length > 0) {
    console.error(`\n未登记的${omitDev ? '生产' : 'dev'}依赖安装脚本（fail-closed）：`);
    offenders.forEach((f) => console.error(`  ${f.name}`));
    const register = omitDev ? 'PROD_INSTALL_SCRIPT_ALLOWLIST' : 'DEV_INSTALL_SCRIPT_ALLOWLIST';
    console.error(`\n若确需保留：把包名加入 scripts/check-prod-install-scripts.js 的`);
    console.error(`${register} 并写明理由，随提交评审。`);
    return 1;
  }
  console.log(`\n✅ ${mode}安装脚本检查通过（未登记命中 0，白名单 ${allowlist.length}）`);
  return 0;
}

function main() {
  const arg = process.argv[2];
  if (arg === '--scan') return process.exit(run(false));
  if (arg === undefined || arg === '--omit=dev') return process.exit(run(true));
  console.error(`未知参数：${arg}（支持 --omit=dev / --scan）`);
  process.exit(2);
}

// 作为脚本执行时才跑 CLI；被 require 时只暴露判据（测试用 evaluate +
// collectFromLockfile 构造变异样本，不必复刻逻辑——见 evaluate 的说明）。
if (require.main === module) main();

module.exports = {
  evaluate,
  collectFromLockfile,
  lockPathToPkgName,
  PROD_INSTALL_SCRIPT_ALLOWLIST,
  DEV_INSTALL_SCRIPT_ALLOWLIST,
};
