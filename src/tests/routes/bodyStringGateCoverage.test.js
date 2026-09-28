'use strict';

/**
 * 「非字符串闸门」的覆盖面清点（静态，不起应用）
 *
 * 逐条 E2E 只能证明抽到的点，证明不了这一类收干净了。这里把闸门判据本身
 * 固化成测试：任何 `body()` 链只要
 *   · 带 `.trim()`/`.isLength()`（会被 stringify 绕过的两类），且
 *   · 链内没有任何形状拒绝型校验（isString/isEmail/isIn/isMongoId/…），且
 *   · 紧挨着的前一行不是 `mustBeString('<同一字段>', …)`
 * 就是漏网，直接失败并把漏网位置打印出来。
 *
 * 这条断言同时是后续新增路由的护栏：新加一条自由文本链而没配闸门，
 * CI 就会指名道姓地拒绝，而不是等到脏数据落库。
 */

const fs = require('fs');
const path = require('path');

const ROUTES = path.resolve(__dirname, '../../routes');

/** 会把 `String(value)` 之后的值判掉的校验器（有它就不会静默落库） */
const SHAPE_REJECTING =
  /\.(isString|isEmail|isInt|isFloat|isMongoId|isISO8601|isBoolean|isIn|matches|isURL|isBase64|isNumeric)\(/;

/**
 * 豁免：链上没有 sanitizer、且首个校验器就把非字符串判掉的字段。
 * `body('password').custom(validatePasswordStrength)` 里 custom 拿到的是**原值**
 * （只有标准校验器才 stringify），`utils/helpers.js` 的
 * `validatePasswordStrength` 首行即 `typeof password !== 'string' ⇒ 拒绝`，
 * 所以再加一道闸门只会多一句重复文案。
 */
const EXEMPT = new Set(['userRoutes.js:password']);

const esc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/** 一条链的文本：locator 行 + 后续不属于别的 locator 的行 */
const chainOf = (lines, idx) => {
  const parts = [lines[idx]];
  for (let j = idx + 1; j < lines.length; j += 1) {
    if (/\b(body|param|query)\(\s*'/.test(lines[j]) || /^\s*\]\s*[;,]?\s*$/.test(lines[j])) break;
    parts.push(lines[j]);
  }
  return parts.join(' ');
};

const gateLineFor = (line) => /^\s*mustBeString\(\s*'([^']+)'\s*,/.exec(line.trim());

describe('body 链的字符串闸门覆盖面', () => {
  const collectOffenders = () => {
    const offenders = [];
    for (const file of fs
      .readdirSync(ROUTES)
      .filter((f) => f.endsWith('.js'))
      .sort()) {
      const lines = fs.readFileSync(path.join(ROUTES, file), 'utf8').split(/\r?\n/);
      lines.forEach((line, i) => {
        const m = /^\s*body\(\s*'([^']+)'\s*\)/.exec(line);
        if (!m) return;
        const field = m[1];
        if (EXEMPT.has(`${file}:${field}`)) return;
        const chain = chainOf(lines, i);
        if (!/\.isLength\(|\.trim\(\)/.test(chain)) return;
        if (SHAPE_REJECTING.test(chain)) return;
        const prev = i > 0 ? gateLineFor(lines[i - 1]) : null;
        if (prev && prev[1] === field) return;
        offenders.push(`${file}:${i + 1}  body('${field}')`);
      });
    }
    return offenders;
  };

  test('没有任何 body 链可以在没有闸门时放行非字符串', () => {
    const offenders = collectOffenders();
    expect(offenders.join('\n')).toBe('');
  });

  test('清点确实扫到了内容（防止判据本身失效导致零命中假绿）', () => {
    // 断言"扫描器在工作"：至少要有 50 条链带着闸门通过检查。
    // 没有这条反向对照，上面那条断言可以在判据整体失配（改坏正则、
    // 目录读空）时空洞地绿着。
    let gated = 0;
    for (const file of fs.readdirSync(ROUTES).filter((f) => f.endsWith('.js'))) {
      const lines = fs.readFileSync(path.join(ROUTES, file), 'utf8').split(/\r?\n/);
      lines.forEach((line) => {
        if (gateLineFor(line)) gated += 1;
      });
    }
    expect(gated).toBeGreaterThanOrEqual(50);
  });

  test('每个豁免项都必须自带豁免理由：链上无 sanitizer 且有 custom 校验', () => {
    // 豁免表是这套判据唯一的"人工放行"入口，必须自身可证伪：
    // 无 `.trim()` ⇒ 没有把对象写回 req.body 的 sanitizer；
    // 有 `.custom()` ⇒ 首个校验器拿到的是原值，非字符串在 custom 里就被判掉。
    // 两条任一不成立（或字段已改名/已删）都算非法豁免，防止"为了让 CI 绿
    // 而往集合里塞一个字段名"。
    const unjustified = [];
    for (const entry of EXEMPT) {
      const [file, field] = entry.split(':');
      const file_ = path.join(ROUTES, file);
      if (!fs.existsSync(file_)) {
        unjustified.push(`${entry}：文件不存在`);
        continue;
      }
      const lines = fs.readFileSync(file_, 'utf8').split(/\r?\n/);
      const idx = lines.findIndex((l) =>
        new RegExp(`^\\s*body\\(\\s*'${esc(field)}'\\s*\\)`).test(l)
      );
      if (idx === -1) {
        unjustified.push(`${entry}：已找不到该字段的 body 链`);
        continue;
      }
      const chain = chainOf(lines, idx);
      if (/\.trim\(\)/.test(chain)) unjustified.push(`${entry}：链上有 sanitizer，豁免不成立`);
      if (!/\.custom\(/.test(chain)) unjustified.push(`${entry}：链上没有承接类型判断的 custom`);
    }
    expect(unjustified.join('\n')).toBe('');
  });

  test('每个闸门都紧挨着它保护的 body 链（不存在孤儿闸门）', () => {
    // 每个 mustBeString 的下一行必须是同名字段的 body 链：
    // 字段改名后留下的孤儿闸门会让上面那条清点误判成"已覆盖"。
    const orphans = [];
    for (const file of fs.readdirSync(ROUTES).filter((f) => f.endsWith('.js'))) {
      const lines = fs.readFileSync(path.join(ROUTES, file), 'utf8').split(/\r?\n/);
      lines.forEach((line, i) => {
        const g = gateLineFor(line);
        if (!g) return;
        const next = lines[i + 1] || '';
        if (
          !new RegExp(
            `^\\s*body\\(\\s*'${g[1].replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}'\\s*\\)`
          ).test(next)
        ) {
          orphans.push(`${file}:${i + 1}  mustBeString('${g[1]}') 后面不是同名字段的 body 链`);
        }
      });
    }
    expect(orphans.join('\n')).toBe('');
  });
});
