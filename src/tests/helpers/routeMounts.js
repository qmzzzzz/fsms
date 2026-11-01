/**
 * 路由挂载前缀解析（两个闸门共用一份取数，第 17 轮 F-06）
 *
 * 为什么要抽出来：审计白名单的对账有两处闸门——`tests/utils/auditMeta` 抓「新增路由忘补白名单」，
 * `tests/constants/auditActionReachability` 抓「白名单里永不产生的条目」。两处各自手写前缀规则时，
 * 它们**不是同一个事实**（第 26 轮 F-201 的教训）：auditMeta 那份写的是
 * `api/${file.replace('Routes.js','').replace('security','security')}`——第二个 replace 是空操作，
 * 说明它是靠"文件名恰好等于挂载段"的巧合在工作。本轮 `routes/forensicRoutes.js` 挂在
 * `/api/security/forensic` 下，巧合破了：
 *   · auditMeta 用错前缀派生，凭空造出 forensic_trace 这类**根本不存在的 action**；
 *   · 可达性闸按 app.js 前缀扫不到该文件，把真实存在的 security_forensic_* 判成"永不产生"。
 * 两个闸门对同一份代码给出两个互相矛盾的结论，而**两边都全绿是不可能的**——这正是并置取数的意义。
 *
 * 解析口径与边界（如实声明）：
 *  1. 顶层前缀 = app.js 里 `app.use('<前缀>', <变量>)`；
 *  2. 嵌套前缀 = 路由文件里 `router.use('<子路径>', <同文件 require 进来的变量>)`，前缀 = 父 + 子；
 *  3. **解析不出来就抛**：父前缀缺失、同一子路由被多处挂载（本工具只表达单一前缀）都必须显式失败。
 *     静默返回 undefined 会让调用方跳过该文件，于是"少扫一个文件"看起来和"该文件没有路由"一模一样。
 */
const fs = require('fs');
const path = require('path');

const SRC_DIR = path.resolve(__dirname, '../..');
const ROUTES_DIR = path.join(SRC_DIR, 'routes');

/** app.js 的顶层挂载前缀，键是变量名（与 app.use 的第二个实参同名） */
function readMounts(appSrcPath = path.join(SRC_DIR, 'app.js')) {
  const src = fs.readFileSync(appSrcPath, 'utf8');
  const mounts = {};
  for (const m of src.matchAll(/app\.use\(\s*'([^']+)',\s*(\w+)/g)) mounts[m[2]] = m[1];
  return mounts;
}

/** 路由文件里的嵌套挂载，键是被挂载的子路由文件名（不含 .js） */
function readNestedMounts() {
  const out = {};
  for (const file of fs.readdirSync(ROUTES_DIR)) {
    if (!file.endsWith('.js')) continue;
    const src = fs.readFileSync(path.join(ROUTES_DIR, file), 'utf8');
    const vars = new Map();
    for (const m of src.matchAll(/const\s+(\w+)\s*=\s*require\('\.\/([\w.-]+)'\)/g)) {
      vars.set(m[1], m[2]);
    }
    for (const m of src.matchAll(/router\.use\(\s*'([^']+)'\s*,\s*(\w+)\s*\)/g)) {
      const target = vars.get(m[2]);
      if (!target) continue;
      (out[target] = out[target] || []).push({ parent: file.replace(/\.js$/, ''), sub: m[1] });
    }
  }
  return out;
}

/** 单个路由文件的完整挂载前缀；解析不出来时抛（不返回 undefined） */
function makePrefixOf(mounts, nested) {
  return (name) => {
    if (mounts[name]) return mounts[name];
    const via = nested[name];
    if (!via || via.length === 0) {
      throw new Error(
        `${name} 在 app.js 与嵌套挂载里都找不到前缀：解析失败必须显式失败，不能当作"没有路由"`
      );
    }
    if (via.length > 1) {
      throw new Error(
        `${name} 被多处嵌套挂载（${via.map((v) => v.parent + v.sub).join(', ')}）：本工具只表达单一前缀`
      );
    }
    const parentPrefix = mounts[via[0].parent];
    if (!parentPrefix) {
      throw new Error(
        `${name} 的父路由 ${via[0].parent} 没有 app.js 挂载前缀：再拼下去会静默丢一层`
      );
    }
    return (parentPrefix.replace(/\/+$/, '') + via[0].sub).replace(/\/+/g, '/');
  };
}

module.exports = { SRC_DIR, ROUTES_DIR, readMounts, readNestedMounts, makePrefixOf };
