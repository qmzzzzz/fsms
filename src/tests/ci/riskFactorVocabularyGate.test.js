/**
 * 风险因素词表闸：后端写入的风险码集合必须与前端翻译登记集一致。
 *
 * 为什么需要它：riskFactors 存机器码，客户界面靠 web-admin/src/i18n/auditRiskFactors.js
 * 翻译成「标签 + 悬浮解释」。后端新增一个码而前端没登记，客户看到的就是一将
 * full_range_cidr_attempt——不报错、不告警，只是静默退回机器码。这类漏登记
 * 在代码审阅里几乎不可见，故做成闸。
 *
 * 判定面：
 *   ① src 非测试源码里，凡 riskFactors 数组字面量中的引号小写 token，都必须
 *      在前端登记集里（否则红，并列出漏登记的码）；
 *   ② 前端登记集的每一项都必须在 src 里真实出现（防拼写错误产生死条目，
 *      也防把「只在读查询里出现」的幽灵码当成真码登记）；
 *   ③ 动态拼出来的码族（如 `chain_stage_` + stage）不要求逐个登记，但前缀
 *      必须在翻译模块里有对应的前缀族实现——否则同样是一整族裸机器码
 *      （本闸的第一版就是在这里放过了 chain_stage_*，被客户界面反向打脸）；
 *   ④ 三侧扫描均非空（防扫描器自己坏了变成永真）。
 *
 * 扫描器只认两类被证明可靠的排除，逐条成文：
 *   - 读查询过滤器 `riskFactors: { $in: [...] }` 是查询不是写入，整块跳过；
 *   - 数组里 `!== 'x'` / `=== 'x'` 这类比较运算符的操作数不是风险码。
 * 不做整行/整文件豁免。
 */
const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..', '..', '..');
const SRC = path.join(ROOT, 'src');
const FRONTEND = path.join(ROOT, 'web-admin', 'src', 'i18n', 'auditRiskFactors.js');

const SKIP_DIRS = new Set(['tests', 'node_modules']);

function walk(dir, out = []) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (!SKIP_DIRS.has(entry.name)) walk(full, out);
    } else if (entry.name.endsWith('.js')) {
      out.push(full);
    }
  }
  return out;
}

/** 取从 open 处的 [ 开始到配对 ] 为止的整块（支持嵌套与换行）。 */
function bracketBlock(text, open) {
  let depth = 0;
  for (let i = open; i < text.length; i += 1) {
    if (text[i] === '[') depth += 1;
    else if (text[i] === ']') {
      depth -= 1;
      if (depth === 0) return text.slice(open, i + 1);
    }
  }
  return '';
}

/**
 * 扫 src：返回 code（完整风险码 → 站点）与 prefix（动态码族前缀，如 chain_stage_）。
 */
function scan() {
  const codes = new Map();
  const prefixes = new Set();
  const tokens = /\x27([a-z][a-z0-9_]{2,})\x27/g;
  const collect = (block, file) => {
    for (const m of block.matchAll(tokens)) {
      const before = block.slice(Math.max(0, m.index - 6), m.index);
      if (/[!=]==?\s*$/.test(before)) continue; // 比较运算符的操作数不是风险码
      if (m[1].endsWith('_')) {
        prefixes.add(m[1]);
        continue;
      }
      for (const t of block.matchAll(/`([a-z][a-z0-9_]+_)\$\{/g)) prefixes.add(t[1]);
      if (!codes.has(m[1])) codes.set(m[1], path.relative(ROOT, file));
    }
  };
  for (const file of walk(SRC)) {
    const text = fs.readFileSync(file, 'utf8');
    let idx = text.indexOf('riskFactors');
    while (idx >= 0) {
      const open = text.indexOf('[', idx);
      const para = text.indexOf('\n\n', idx);
      const near = open > 0 && open - idx < 160 && (para < 0 || open < para);
      if (near && !text.slice(idx, open).includes('$in')) {
        collect(bracketBlock(text, open), file);
      }
      for (const m of text.slice(idx, idx + 200).matchAll(/riskFactors\.push\(([^)]*)\)/g)) {
        collect(m[1], file);
      }
      idx = text.indexOf('riskFactors', idx + 1);
    }
  }
  return { codes, prefixes };
}

const discoverCodes = () => scan().codes;

/** 前端登记集：只认 REGISTRY 顶层键（两空格缩进 + 冒号 + 花括号）。 */
function registeredCodes() {
  const text = fs.readFileSync(FRONTEND, 'utf8');
  const codes = [];
  for (const m of text.matchAll(/^ {2}([a-z][a-z0-9_]+): \{$/gm)) codes.push(m[1]);
  return new Set(codes);
}

describe('风险因素词表闸：后端码集 ≡ 前端登记集', () => {
  test('两侧扫描均非空（扫描器自证未失效）', () => {
    expect(discoverCodes().size).toBeGreaterThan(20);
    expect(registeredCodes().size).toBeGreaterThan(20);
  });

  test('后端每个风险码都已在前端登记（漏登记 → 客户看到机器码）', () => {
    const registered = registeredCodes();
    const missing = [...discoverCodes()]
      .filter(([code]) => !registered.has(code))
      .map(([code, site]) => code + ' @ ' + site);
    expect(missing).toEqual([]);
  });

  test('后端每个动态码族都有前缀族实现（否则整族裸机器码）', () => {
    const text = fs.readFileSync(FRONTEND, 'utf8');
    const unhandled = [...scan().prefixes].filter((prefix) => !text.includes("'" + prefix + "'"));
    expect(unhandled).toEqual([]);
    // 反方向对照：前缀集合必须真的非空，否则这条断言会变成永远通过
    expect(scan().prefixes.size).toBeGreaterThan(0);
  });

  test('前端每个登记项都在后端真实写入（防死条目与幽灵码）', () => {
    const discovered = discoverCodes();
    const dead = [...registeredCodes()].filter((code) => !discovered.has(code));
    expect(dead).toEqual([]);
  });
});
