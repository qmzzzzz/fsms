/**
 * P2-⑫ 供应链门禁：生产依赖树禁止任何 install/preinstall/postinstall 脚本
 *
 * 为什么比 `npm ci --ignore-scripts` 更进一步：ignore-scripts 让安装跳过脚本，
 * 但**没有人在看**——今天加一个新依赖、它带了个 install 脚本，安装照样成功、
 * 脚本照样在开发机上跑（本地不会带 --ignore-scripts），门禁形同虚设。
 * 本检查把「生产依赖树不得有安装脚本」变成显式不变量：
 *   - 新增带 install 脚本的生产依赖 ⇒ CI 红，必须逐个评审后登记到
 *     PROD_INSTALL_SCRIPT_ALLOWLIST（并写明理由），与 P2-27/门禁接线测试同风格；
 *   - 现状：生产树零命中（@scarf/scarf 的 install 是遥测上报、mongodb-memory-server
 *     的 postinstall 只在 dev 树），所以白名单默认为空。
 * 用法：node scripts/check-prod-install-scripts.js（CI security-audit 作业执行）
 */

const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const NODE_MODULES = path.resolve(ROOT, 'node_modules');

/** 评审后确需保留安装脚本的生产依赖，登记于此并写明理由（默认为空） */
const PROD_INSTALL_SCRIPT_ALLOWLIST = [];

/** 目录边界校验：解析后的目标必须仍落在 node_modules 内（含包名即边界，越界即抛） */
function safeJoin(base, name) {
  const target = path.resolve(base, name);
  if (target !== base && !target.startsWith(base + path.sep)) {
    throw new Error(`路径越界被拒绝：${name}`);
  }
  return target;
}

function checkPackage(pkgDir, name, found) {
  let pkg;
  try {
    pkg = JSON.parse(fs.readFileSync(safeJoin(pkgDir, 'package.json'), 'utf8'));
  } catch {
    return;
  }
  const scripts = pkg.scripts || {};
  const hook = ['preinstall', 'install', 'postinstall'].find((k) => scripts[k]);
  if (hook) found.push({ name, hook, script: String(scripts[hook]).slice(0, 120) });
}

function collectInstallScripts(base) {
  const found = [];
  let entries = [];
  try {
    entries = fs.readdirSync(base, { withFileTypes: true });
  } catch {
    return found; // node_modules 不存在时由调用方报错
  }
  for (const entry of entries) {
    if (!entry.isDirectory() || entry.name.startsWith('.')) continue;
    const pkgDir = safeJoin(base, entry.name);
    if (entry.name.startsWith('@')) {
      // scoped 包：递归一层
      let scoped = [];
      try {
        scoped = fs.readdirSync(pkgDir, { withFileTypes: true });
      } catch {
        continue;
      }
      for (const sub of scoped) {
        if (!sub.isDirectory()) continue;
        checkPackage(safeJoin(pkgDir, sub.name), `${entry.name}/${sub.name}`, found);
      }
      continue;
    }
    checkPackage(pkgDir, entry.name, found);
  }
  return found;
}

function main() {
  if (!fs.existsSync(NODE_MODULES)) {
    console.error('Error: node_modules 不存在——本检查必须在 npm ci 之后运行');
    process.exit(1);
  }
  const all = collectInstallScripts(NODE_MODULES);
  const offenders = all.filter((f) => !PROD_INSTALL_SCRIPT_ALLOWLIST.includes(f.name));

  if (all.length > 0) {
    console.log('依赖树中的安装脚本（含已登记）：');
    all.forEach((f) => console.log(`  ${f.name} [${f.hook}] ${f.script}`));
  } else {
    console.log('依赖树中没有任何安装脚本。');
  }

  if (offenders.length > 0) {
    console.error('\n未登记的生产依赖安装脚本（fail-closed）：');
    offenders.forEach((f) => console.error(`  ${f.name} [${f.hook}] ${f.script}`));
    console.error('\n若确需保留：把包名加入 scripts/check-prod-install-scripts.js 的');
    console.error('PROD_INSTALL_SCRIPT_ALLOWLIST 并写明理由，随提交评审。');
    process.exit(1);
  }
  console.log(
    `\n✅ 生产依赖树安装脚本检查通过（未登记命中 0，白名单 ${PROD_INSTALL_SCRIPT_ALLOWLIST.length}）`
  );
}

main();
