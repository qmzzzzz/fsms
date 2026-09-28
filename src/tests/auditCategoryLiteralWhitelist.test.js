'use strict';

/**
 * 审计分类白名单：源码里手写的 `category: '<字面量>'` 必须都在模型 enum 内
 *
 * 危害（不是"筛选不出来"，而是"记录根本没落库"）：
 * `models/AuditLog.js` 的 `category` 是带 enum 的字段，而落库走
 * `auditBuffer` 的 `insertMany({ ordered: false })` —— 一条 ValidationError
 * 只丢掉它自己那一条，既不抛错也不告警。schema 第 22-27 行的注释把这个后果写得很清楚：
 * "缺少某个值时，该分类的审计记录会被静默丢弃（既不入库也不告警），造成审计盲区"。
 *
 * 已有的半边：`utils/auditMeta.test.js:80` 钉住了 `ROUTE_CATEGORY_MAP` 的取值全集 ⊆ enum
 * （中间件自动派生的那条路径）。
 * 缺的半边：**开发者手写的** `AuditLog.record({category: 'xxx'})` /
 * `AuditLog.create({category: 'xxx'})` —— 新增一个业务域时最容易走这条，
 * 而且写错之后表现是"日志看起来发了、库里没有"，排查成本极高。本文件补这半边的门禁。
 *
 * 扫描口径：`src/`（不含测试）、`scripts/`、`migrations/` 里的 `category: '<字面量>'`。
 * 实测当前 40 处全部是审计用途（auth/security/system/user），
 * 因此这里不做"仅审计写入点"的精细过滤——那需要区分 `action: 'created'` 这类
 * WebSocket 载荷与真实审计行，误判面比现在的收益大。
 * 若将来某个非审计模型也用了 `category` 字段而被本用例挡住，正确处置是把扫描范围
 * 收窄到审计写入相关目录，并在技术文档里说明，而不是删掉这条断言。
 */

const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '../..');
const SCAN_DIRS = ['src', 'scripts', 'migrations'];

const AUDIT_CATEGORY_LITERAL = /category:\s*'([A-Za-z_][A-Za-z0-9_-]*)'/g;

/**
 * 剥注释，只留代码视图。
 * 不剥的话文档里写的 `category: 'xxx'` 示例会被算成真实写入点
 * ——本仓已经两次因为"文本断言在含注释的原文上做"得到假绿/假红。
 * 块注释按等长空白替换（保住行号），行注释整行截掉（前面的 `:` 让 URL 不误伤）。
 */
function stripComments(text) {
  return text
    .replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, ' '))
    .replace(/(^|[^:])\/\/[^\n]*/g, '$1');
}

const isTestFile = (name) => /\.test\.(js|cjs)$/.test(name);

/** 从真实源码树里取出所有 `category: '<字面量>'`，返回 Map(字面量 -> 出现位置) */
function collectCategoryLiterals(dirs) {
  const found = new Map();
  const walk = (dir) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        // 测试目录里的夹具不是生产写入点（按名字判，别拿整条路径找分隔符——
        // 目录自身的路径结尾没有分隔符，那样写会漏排除整个 tests 目录）
        if (entry.name === 'tests' || entry.name === '__tests__') continue;
        walk(full);
      } else if (/\.(js|cjs)$/.test(entry.name) && !isTestFile(entry.name)) {
        const src = stripComments(fs.readFileSync(full, 'utf8'));
        for (const m of src.matchAll(AUDIT_CATEGORY_LITERAL)) {
          if (!found.has(m[1])) found.set(m[1], []);
          found.get(m[1]).push(path.relative(ROOT, full));
        }
      }
    }
  };
  for (const d of dirs) {
    const abs = path.join(ROOT, d);
    if (fs.existsSync(abs)) walk(abs);
  }
  return found;
}

describe('zzqoder 手写 category 字面量必须在审计分类白名单内', () => {
  const { AUDIT_CATEGORIES } = require('../constants/audit');
  const found = collectCategoryLiterals(SCAN_DIRS);
  const total = [...found.values()].reduce((n, list) => n + list.length, 0);

  test('取数有效：扫到足量真实 category 字面量（防扫描逻辑坏掉后空集恒绿）', () => {
    expect(total).toBeGreaterThanOrEqual(30);
  });

  test('扫描范围干净：本文件的示例与任何 .test.js 都不该被算进来', () => {
    const files = new Set([...found.values()].flat());
    expect([...files].some((f) => f.includes('zzqoder_auditCategoryLiteralWhitelist'))).toBe(false);
    expect([...files].some((f) => f.includes('.test.'))).toBe(false);
  });

  test('每一处都在 enum 内（不在就是静默丢行的审计盲区）', () => {
    const whitelist = new Set(AUDIT_CATEGORIES);
    const violations = [...found.entries()]
      .filter(([code]) => !whitelist.has(code))
      .map(([code, files]) => `${code} ← ${[...new Set(files)].join(', ')}`);
    expect(violations).toEqual([]);
  });

  test('反向前提：提取器真的能报出脏值（不是"当前恰好干净"的假绿）', () => {
    // 用同一段正则处理一段合成源码：如果提取器本身坏了，这条会先红，
    // 上面两条的"通过"才有意义。
    const dirty = collectFromText(`
      AuditLog.record({ action: 'x', category: 'auth' });
      AuditLog.create({ action: 'y', category: 'notification' });
      AuditLog.record({ action: 'z', category: 'zz_bogus' });
    `);
    expect([...dirty].sort()).toEqual(['auth', 'notification', 'zz_bogus']);
    const whitelist = new Set(AUDIT_CATEGORIES);
    expect([...dirty].filter((c) => !whitelist.has(c)).sort()).toEqual([
      'notification',
      'zz_bogus',
    ]);
  });

  test('提取器不把变量/模板串当字面量（防误报把门禁变成噪音）', () => {
    const ok = collectFromText(`
      AuditLog.record({ category: CATEGORY_X });
      AuditLog.record({ category: \`\${mod}:audit\` });
      AuditLog.record({ category: 'security' });
    `);
    expect([...ok]).toEqual(['security']);
  });

  function collectFromText(text) {
    const out = new Set();
    for (const m of text.matchAll(AUDIT_CATEGORY_LITERAL)) out.add(m[1]);
    return out;
  }
});
