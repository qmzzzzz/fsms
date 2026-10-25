/**
 * 供应链门禁：安装脚本必须**显式登记**——生产树零容忍，dev 树逐个评审。
 *
 * 为什么比 `npm ci --ignore-scripts` 更进一步：ignore-scripts 让安装跳过脚本，
 * 但**没有人在看**——今天加一个新依赖、它带了个 install 脚本，安装照样成功、
 * 脚本照样在开发机上跑（本地不会带 --ignore-scripts），门禁形同虚设。
 * 本检查把「哪些包带安装脚本」变成显式不变量，并按依赖树分两档：
 *   - **生产树命中即红**（lockfile 中非 dev 的条目）：必须逐个评审后登记。
 *   - **dev 树命中亦红**（lockfile 中 dev:true 的条目）：devDeps 里的安装脚本会在
 *     开发机与任何未加 --ignore-scripts 的安装上执行，属真实供应链风险面。
 *
 * ── 登记键必须钉到「版本 + integrity」而不是包名 ──
 * 早期实现只按包名登记，后果是**未来任何版本自动获得豁免**：上游把同一个包名
 * 推到 2.0.0 并塞进新的 install 脚本时，门禁仍然是绿的。现在每条登记都必须写明
 * `version` 与 `integrity`，锁文件里对应条目的两者必须逐字一致；版本升级或
 * tarball 被换掉都会让门禁转红，迫使评审重新表态。
 *
 * ── 覆盖面 = 两份 lockfile ──
 *   package-lock.json              （后端）
 *   web-admin/package-lock.json    （前端）
 * 此前只扫根锁文件，web-admin 的安装脚本完全不可见。
 *
 * ── CI 用法（依赖安装**之前**的独立作业）──
 *   node scripts/check-prod-install-scripts.js --all
 * `--all` 只读两份锁文件、不碰 node_modules、不拉起 npm ⇒ 可以在任何安装动作
 * 之前跑；CI 的 dependency-policy 作业正是这样接线的。
 *
 * 判据来源：**package-lock.json 的 `packages` 段**，而不是扫 node_modules 目录，也不是
 * `npm ls --json`——后者的每个节点只有 version/resolved/dependencies，不含 scripts。
 * 锁文件的 `hasInstallScript` 由 npm 在写入时离线标定，与平台无关且精确标出 dev 标记。
 *
 * 本文件刻意保持精短：本仓有 max-lines 棘轮，文件体积不得超过基线。
 */

const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const LOCKFILES = [
  { rel: 'package-lock.json', label: 'backend' },
  { rel: 'web-admin/package-lock.json', label: 'web-admin' },
];

/**
 * 生产树安装脚本登记册。每条都必须带 version 与 integrity，理由写在 reason。
 * @scarf/scarf：经 swagger-ui-express → swagger-ui-dist 传递引入（锁文件中无 dev 标记）。
 * 其 postinstall 是遥测上报（向 scarf.sh 发送匿名安装计数），不产出运行期所需文件；
 * runtime 镜像与 CI 均以 --ignore-scripts 跳过它。登记而非删除：它是 swagger-ui-dist
 * 的硬依赖，无法在不弃用 swagger 文档页面前提下移除。
 */
const PROD_INSTALL_SCRIPT_ALLOWLIST = [
  {
    name: '@scarf/scarf',
    version: '1.4.0',
    integrity:
      'sha512-xxeapPiUXdZAE3che6f3xogoJPeZgig6omHEy1rIY5WVsB3H2BHNnZH+gHG6x91SCWyQCzWGsuL2Hh3ClO5/qQ==',
    reason: 'swagger-ui-dist 的传递依赖；postinstall 仅遥测，CI/镜像均 --ignore-scripts',
  },
];

/**
 * dev 树安装脚本登记册。键=包名，值=`version`/`integrity`/`reason`。
 * 新增一行都必须在评审中给出理由——这正是本档要的效果：让「devDeps 里的安装脚本」
 * 从「静默存在」变成「显式表态」。CI 现已全部 `npm ci --ignore-scripts`，
 * 这些脚本只在本地开发机执行；登记仍保留，作为「树里有哪些脚本」的显式清单。
 */
const DEV_INSTALL_SCRIPT_ALLOWLIST = [
  {
    name: 'mongodb-memory-server',
    version: '11.3.0',
    integrity:
      'sha512-8ZCDrraqKqmAikoeKuEq+16jeWdVKwjtEAuMxxeQctHiGSGYt17W9LmoRzV1Nwnz7owyxwDKMhow4IVkNYYRKw==',
    reason:
      'postinstall 预下载 mongod 二进制；CI 改为 --ignore-scripts + 仓库内 SHA-256 锚定的预置二进制',
  },
  {
    name: 'fsevents',
    version: '2.3.3',
    integrity:
      'sha512-5xoDfX+fL7faATnagmWPpbFtwh/R77WmMMqqHGS65C3vvB0YHrgF+B1YmZ3441tMj5n63k0212XNoJwzlhffQw==',
    reason: 'optional 且 os:["darwin"]——仅 macOS 安装；Linux CI 与镜像上不会安装',
  },
  {
    name: '@parcel/watcher',
    version: '2.6.0',
    integrity:
      'sha512-7FNeNl8NCE7aINx7WXiKQrPYZWC/hvrTsmk6zmxbI7LTXE7hVek/n8AfVgpe2y82zl3w0HvCHN0bVKMBoJcC0w==',
    reason: 'install 脚本在预编译产物缺失时构建文件监视原生绑定；仅 Jest 文件监视，CI 已忽略脚本',
  },
  {
    name: 'unrs-resolver',
    version: '1.12.2',
    integrity:
      'sha512-dmlRxBJJayXjqTwC+JtF1HhJmgf3ftQ3YejFcZrf4+KKtJv0qDsK1pjqaaVjG7wJ5NJ6UVP1OqRMQ71Z4C3rxQ==',
    reason:
      'postinstall 在预编译绑定缺失时下载 native binding；CI 已忽略脚本，平台绑定由 optionalDependencies 提供',
  },
];

/** `node_modules/@scope/name` / `node_modules/name` / `node_modules/a/node_modules/name` → 包名 */
function lockPathToPkgName(p) {
  const marker = p.lastIndexOf('node_modules/');
  if (marker < 0) return null;
  const rest = p.slice(marker + 'node_modules/'.length);
  // scoped 包是 `@scope/name`（只可能是最后一段名字带 scope），非 scoped 是单段
  return rest.includes('/') ? rest.slice(0, rest.indexOf('/')) + '/' + rest.split('/')[1] : rest;
}

/**
 * 从锁文件取所有带安装脚本的条目。
 * 去重键是 `name@version#integrity` 而不是包名：同一包名的两个版本（或同一版本
 * 换过 tarball）必须分别可见，否则门禁只会看到其中一个，另一个静默通过。
 * @returns {{name:string, version:string, integrity:string|null, dev:boolean,
 *            optional:boolean, os:string[]|undefined}[]}
 */
function collectFromLockfile(lock) {
  const packages = (lock || {}).packages || {};
  const found = new Map();
  for (const [p, meta] of Object.entries(packages)) {
    if (!meta || !meta.hasInstallScript) continue;
    const name = lockPathToPkgName(p);
    if (!name) continue;
    const integrity = meta.integrity || null;
    const key = `${name}@${meta.version}#${integrity || ''}`;
    if (found.has(key)) continue;
    found.set(key, {
      name,
      version: meta.version,
      integrity,
      dev: !!meta.dev,
      optional: !!meta.optional,
      os: meta.os,
    });
  }
  return [...found.values()];
}

/** 登记项与锁文件条目必须 name/version/integrity 三者全等；缺 integrity 一律不匹配 */
function isRegistered(entry, allowlist) {
  return allowlist.some(
    (a) =>
      a.name === entry.name &&
      a.version === entry.version &&
      typeof a.integrity === 'string' &&
      a.integrity === entry.integrity
  );
}

/**
 * 判定核心（纯函数：不读 argv、不调 process.exit、不打印）。
 *
 * 抽出来的**唯一理由**是可证伪性：原实现把「读锁文件 → 筛选 → 退出码」全写在一个
 * run() 里并在顶层 main()，导致测试无法调用它——只能**复刻**一份判据（实测后果：
 * 把筛选条件写反，门禁退化成"永远失败"，而复刻版测试全绿）。
 *
 * @param {object} lock package-lock.json 的解析结果（注入以便测试构造变异样本）
 * @param {boolean} omitDev true=生产树（非 dev 条目）；false=dev 树
 * @returns {{all: Array, offenders: Array, allowlist: Array}}
 */
function evaluate(lock, omitDev) {
  const entries = collectFromLockfile(lock);
  const all = entries.filter((e) => (omitDev ? !e.dev : e.dev));
  const allowlist = omitDev ? PROD_INSTALL_SCRIPT_ALLOWLIST : DEV_INSTALL_SCRIPT_ALLOWLIST;
  return { all, offenders: all.filter((e) => !isRegistered(e, allowlist)), allowlist };
}

/** 单份锁文件 × 单棵树的人类可读标签 */
function labelOf(mode, omitDev) {
  return `${mode} / ${omitDev ? '生产树（--omit=dev）' : 'dev 树（含 devDependencies）'}`;
}

/** 跑一份锁文件的一棵树；返回 true=通过 */
function checkOne(lockFile, lock, omitDev) {
  const { all, offenders, allowlist } = evaluate(lock, omitDev);
  const label = labelOf(lockFile.label, omitDev);

  console.log(`[${label}] 带安装脚本的依赖（含已登记）：`);
  if (all.length === 0) console.log('  （无）');
  all.forEach((f) =>
    console.log(
      `  ${f.name}@${f.version}${f.optional ? `（optional${f.os ? '，仅 ' + f.os.join('/') : ''}）` : ''}`
    )
  );

  if (offenders.length > 0) {
    console.error(`\n[${label}] 未登记的依赖安装脚本（fail-closed）：`);
    offenders.forEach((f) =>
      console.error(`  ${f.name}@${f.version}${f.integrity ? '' : '（缺 integrity，无法锚定）'}`)
    );
    const register = omitDev ? 'PROD_INSTALL_SCRIPT_ALLOWLIST' : 'DEV_INSTALL_SCRIPT_ALLOWLIST';
    console.error(
      `\n若确需保留：把 name/version/integrity 加入 scripts/check-prod-install-scripts.js`
    );
    console.error(`的 ${register} 并写明理由，随提交评审。`);
    return false;
  }
  console.log(`✅ ${label}安装脚本检查通过（未登记命中 0，白名单 ${allowlist.length}）\n`);
  return true;
}

function readLock(rel) {
  return JSON.parse(fs.readFileSync(path.resolve(ROOT, rel), 'utf8'));
}

/** @returns {number} 退出码（0=通过 / 1=未登记命中 / 2=用法或 IO 错误） */
function run(opts) {
  const files = opts.all
    ? LOCKFILES
    : [{ rel: opts.lockfile, label: path.basename(opts.lockfile) }];
  let ok = true;
  for (const file of files) {
    let lock;
    try {
      lock = readLock(file.rel);
    } catch (e) {
      console.error(`Error: 无法读取/解析 ${file.rel}：${String(e.message).slice(0, 200)}`);
      return 2;
    }
    // --omit=dev 只查生产树；--scan 只查 dev 树；--all 两棵树都查
    const modes = opts.all ? [true, false] : [opts.omitDev];
    for (const omitDev of modes) ok = checkOne(file, lock, omitDev) && ok;
  }
  return ok ? 0 : 1;
}

function parseArgs(argv) {
  const opts = { all: false, omitDev: true, lockfile: 'package-lock.json' };
  for (const arg of argv) {
    if (arg === '--all') opts.all = true;
    else if (arg === '--scan') opts.omitDev = false;
    else if (arg === '--omit=dev') opts.omitDev = true;
    else if (arg.startsWith('--lockfile=')) opts.lockfile = arg.slice('--lockfile='.length);
    else
      return { error: `未知参数：${arg}（支持 --all / --omit=dev / --scan / --lockfile=<path>）` };
  }
  return opts;
}

function main() {
  const opts = parseArgs(process.argv.slice(2));
  if (opts.error) {
    console.error(opts.error);
    process.exit(2);
  }
  process.exit(run(opts));
}

// 作为脚本执行时才跑 CLI；被 require 时只暴露判据（测试用 evaluate +
// collectFromLockfile 构造变异样本，不必复刻逻辑——见 evaluate 的说明）。
if (require.main === module) main();

module.exports = {
  evaluate,
  collectFromLockfile,
  lockPathToPkgName,
  isRegistered,
  PROD_INSTALL_SCRIPT_ALLOWLIST,
  DEV_INSTALL_SCRIPT_ALLOWLIST,
};
