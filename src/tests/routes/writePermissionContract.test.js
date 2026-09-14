/**
 * 写接口权限契约测试（评价报告 #23）
 *
 * 契约：src/routes/*.js 中所有写路由（POST/PUT/DELETE/PATCH）必须显式挂
 * 权限中间件（checkPermission / checkViewSensitivePermission），
 * 或在同一路由块内以 `PERMISSION-EXEMPT: <理由>` 注释声明豁免
 * （公共端点 / 操作对象恒为调用者本人的端点）。
 *
 * 目的：前端权限仅为 UI 层（报告 #23），安全边界依赖后端逐接口鉴权；
 * 本测试把「新增写路由漏挂权限中间件」变成 CI 必失败项——
 * 修复方式二选一：补 checkPermission(...)，或显式声明豁免理由。
 *
 * 实现：静态扫描路由源码。相比运行时遍历 app._router 栈，
 * 静态扫描能在标记缺失时直接指出文件与路由，且不受挂载顺序影响。
 */

const fs = require('fs');
const path = require('path');

const ROUTES_DIR = path.join(__dirname, '../../routes');

/**
 * 从 router.<method>( 起截取路由块源码。
 * 块边界 = 下一个顶层 router. 声明或文件末尾——不用 `\n);` 收尾判断，
 * 因为部分路由是「单行声明 + 多行 handler 体」写法（如 wellKnownRoutes），
 * `\n);` 会落到 handler 体内或之后，块归属错乱。
 * 豁免标记（PERMISSION-EXEMPT）约定放在路由收尾 `});` 之后的下一行，
 * 位于本块与下一块之间，按此边界归属正确。
 */
const extractRouteBlocks = (source) => {
  const blocks = [];
  const re = /router\.(post|put|delete|patch)\s*\(/g;
  let match;
  while ((match = re.exec(source)) !== null) {
    const start = match.index;
    const next = source.indexOf('\nrouter.', start + 1);
    const end = next === -1 ? source.length : next;
    blocks.push({
      method: match[1].toUpperCase(),
      source: source.slice(start, end),
    });
  }
  return blocks;
};

const routeOf = (blockSource) => {
  const m = blockSource.match(/['"`](\/[^'"`]*)/);
  return m ? m[1] : '(未解析路径)';
};

describe('写接口权限契约（#23：后端逐接口鉴权是安全边界）', () => {
  const routeFiles = fs
    .readdirSync(ROUTES_DIR)
    .filter((f) => f.endsWith('.js') && f !== 'index.js')
    .sort();

  test('路由目录存在且非空（防扫描路径漂移导致假绿）', () => {
    expect(routeFiles.length).toBeGreaterThan(3);
  });

  test('每个写路由都挂权限中间件，或显式声明 PERMISSION-EXEMPT 理由', () => {
    const violations = [];
    let writeRouteCount = 0;

    for (const file of routeFiles) {
      const source = fs.readFileSync(path.join(ROUTES_DIR, file), 'utf8');
      for (const block of extractRouteBlocks(source)) {
        writeRouteCount += 1;
        const hasPermissionMiddleware =
          /checkPermission\s*\(/.test(block.source) ||
          /checkViewSensitivePermission/.test(block.source);
        const hasExemptMarker = /PERMISSION-EXEMPT:\s*\S/.test(block.source);
        if (!hasPermissionMiddleware && !hasExemptMarker) {
          violations.push(`${file} ${block.method} ${routeOf(block.source)}`);
        }
      }
    }

    // 阈值防假绿：当前写路由规模（含豁免）显著大于该值时说明扫描漏了
    expect(writeRouteCount).toBeGreaterThan(20);

    expect(violations).toEqual([]);
  });

  test('豁免标记必须给出理由（防止注释流于形式）', () => {
    const emptyMarkers = [];
    for (const file of routeFiles) {
      const source = fs.readFileSync(path.join(ROUTES_DIR, file), 'utf8');
      const re = /PERMISSION-EXEMPT:\s*(\S*)/g;
      let m;
      while ((m = re.exec(source)) !== null) {
        if (!m[1]) emptyMarkers.push(file);
      }
    }
    expect(emptyMarkers).toEqual([]);
  });
});
