'use strict';

/**
 * （2026-09-19）：ipRange 的规则条数上限不得静默截断
 *
 * 原 `parseRules` 用 `splitRules(text).slice(0, MAX_RULE_COUNT)` 直接把第 201 条起丢掉，
 * 而且丢的是**数组尾部**——被丢的完全可能是排除项。排除项消失 = 放行，
 * 与本模块文件头自己写的失败方向原则（"只有规则确实为空才可放行"）正相反。
 * 现状下 validateRules / isIPAllowed 各自有更早的同款检查，所以这条是"直接调用方兜底 +
 * 同一份文本两条路径结论必须一致"，不是线上可利用缺陷（已按只读复核确认后修）。
 */

const {
  parseRules,
  validateRules,
  isIPAllowed,
  MAX_RULE_COUNT,
} = require('../../src/utils/ipRange');

/** 造 n 条互不相同的允许项（去重后仍在），可选把首条换成能覆盖 1.1.1.1 的宽网段 */
const fillerAllows = (n, { coverClient = false } = {}) => {
  const list = [];
  if (coverClient) list.push('1.0.0.0/8');
  for (let i = 0; list.length < n; i += 1) list.push(`10.${Math.floor(i / 256)}.${i % 256}.0/24`);
  return list;
};

const CLIENT = '1.1.1.1';

describe('zzqoder IP 规则上限不静默截断', () => {
  test('超过上限的文本整体判不可信，而不是解析前 200 条', () => {
    const r = parseRules(fillerAllows(MAX_RULE_COUNT + 1).join(','));
    expect(r.allows).toEqual([]);
    expect(r.denies).toEqual([]);
    expect(r.invalid).toHaveLength(1);
    expect(r.invalid[0]).toContain(`上限 ${MAX_RULE_COUNT}`);
    expect(r.invalid[0]).toContain(`${MAX_RULE_COUNT + 1} 条`);
  });

  test('负向对照：未超限的文本仍然正常解析（否则上面那条断言是恒绿的空集）', () => {
    const r = parseRules(fillerAllows(10).join(','));
    expect(r.invalid).toEqual([]);
    expect(r.allows).toHaveLength(10);
    expect(r.denies).toEqual([]);
  });

  test('第 201 条是排除项的超限文本必须被拒（不得因"截断后继续"而放行）', () => {
    const rules = fillerAllows(MAX_RULE_COUNT, { coverClient: true });
    rules.push(`!${CLIENT}`);
    const text = rules.join(',');

    // 旧实现若只被 parseRules 的调用方绕过（例如有人直接拿 parseRules 判），
    // 允许项 200 条正常解析、第 201 条排除项被 slice 掉
    //   → 1.1.1.1 命中 1.0.0.0/8 → allowed:true。这就是"排除项静默失效"。
    expect(rules.length).toBe(MAX_RULE_COUNT + 1);
    expect(rules[0]).toBe('1.0.0.0/8');
    // 前提自证：这条文本确实会让 parseRules 走新护栏，而不是"恰好没有允许项"
    expect(parseRules(text).allows).toEqual([]);

    const verdict = isIPAllowed(CLIENT, text);
    expect(verdict.allowed).toBe(false);
    // 实测：CLI 侧走的是 isIPAllowed 自己那条更早的同款检查（too_many_rules），
    // parseRules 的新护栏是给直接调用方兜底的（上一条用例已单独钉住）。
    // 这里要钉的是"两条路径必须同向拒绝"，而不是哪一个标签先命中。
    expect(verdict.reason).toBe('too_many_rules');
  });

  test('边界：正好等于上限时每一条都算数，尾部的排除项必须生效', () => {
    const rules = fillerAllows(MAX_RULE_COUNT - 1, { coverClient: true });
    rules.push(`!${CLIENT}`);
    expect(rules.length).toBe(MAX_RULE_COUNT);
    const verdict = isIPAllowed(CLIENT, rules.join(','));
    expect(verdict.allowed).toBe(false);
    expect(verdict.reason).toBe('denied');
    expect(verdict.matchedRule).toBe(`!${CLIENT}`);
  });

  test('边界：正好等于上限的纯允许项仍能正常放行（判据没有把可用配置一起打死）', () => {
    const rules = fillerAllows(MAX_RULE_COUNT, { coverClient: true });
    const verdict = isIPAllowed(CLIENT, rules.join(','));
    expect(verdict.allowed).toBe(true);
    expect(verdict.reason).toBe('allowed');
    expect(verdict.matchedRule).toBe('1.0.0.0/8');
  });

  test('两条路径对同一份文本的结论必须一致：validateRules 说不合法 ⇒ isIPAllowed 必不放行', () => {
    const cases = [
      fillerAllows(MAX_RULE_COUNT + 1).join(','), // 超量
      `10.0.0.0/24, !10.0.0.0/33, ${fillerAllows(3).join(',')}`, // 含非法片段
      '999.999.999.999', // 完全不可解析
      fillerAllows(5, { coverClient: true }).join(','), // 合法对照组（客户端确实落在允许范围内）
    ];
    let sawInvalidCase = 0;
    for (const text of cases) {
      const { valid } = validateRules(text);
      const { allowed } = isIPAllowed(CLIENT, text);
      if (!valid) sawInvalidCase += 1;
      if (!valid) expect(allowed).toBe(false);
      else expect(allowed).toBe(true);
    }
    // 前提自证：前三条确实被判不可信，否则这个"一致性"是同义反复
    expect(sawInvalidCase).toBe(3);
  });

  test('上限常量的语义仍然是"解析条数"而不是"文本长度"（长文本另有独立护栏）', () => {
    const atCap = fillerAllows(MAX_RULE_COUNT).join(',');
    expect(atCap.length).toBeLessThan(8192);
    expect(parseRules(atCap).invalid).toEqual([]);
    // 文本超长由 MAX_TEXT_LENGTH 分支负责，与条数无关
    expect(validateRules('1.1.1.1,'.repeat(2000)).valid).toBe(false);
  });
});
