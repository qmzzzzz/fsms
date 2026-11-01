'use strict';

/**
 * 封段拒绝原因的**三向对账**闸。
 *
 * 缺陷形状（第 19 轮实测）：同一个枚举曾有六份副本，彼此无对账——
 *   后端产出字面量 11 个 / OpenAPI 描述 5 个 / errorCodes 注释 7 个 / ADR 8 个 /
 *   前端 BAN_REFUSAL_KEYS 10 个 / 前端回归用例 7 个。
 * 实测差集是「只在代码: [live_traffic_inside, typed_confirmation_required, union_covers_family]
 * | 只在 docs: [whitelist_covers]」。后果不是"文档不好看"：第三方照 OpenAPI 实现分支时会
 * 精确漏掉 typed_confirmation_required —— 唯一一个"再点一次就能自救"的原因，于是他们的
 * 用户被拒后无法自救，而我们的回归用例全绿（用例只枚举了 7 个码里的子集）。
 *
 * 逃逸原因（为什么以前没人发现）：
 *   ① emittedErrorCodeCoverage 对账的是 ERROR_CODES 的**键**，不是键内部那个 reason 枚举；
 *   ② check-openapi-drift 只对账"生成器↔产物"，生成器里手抄的 5 个照样自洽；
 *   ③ documentationDrift 只查篇数。
 *   三把闸都在枚举的外面，没有一把伸进枚举内部。
 *
 * 本闸的四条腿（每条都必须能单独变红）：
 *   #1 产出方闭合：ipPoolBan 的 return 值只取自常量表（没有新字面量）。
 *   #2 响应侧覆盖：每个码都能在 errorCodes 的注册表里找到归宿（reason 字段名被文档化）。
 *   #3 前端映射：BAN_REFUSAL_KEYS 的键集 == 常量键集（双向，多/少都红）。
 *   #4 对外文档：openapi.json 的描述逐码出现（不是抽查，是逐个）。
 * 另有 #5：i18n 两个语种对每个映射键都有文案（漏文案 = 界面暴露英文键名）。
 */

const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '../../..');
const read = (rel) => fs.readFileSync(path.join(ROOT, rel), 'utf8');

const {
  REFUSAL_REASON_KEYS,
  REFUSAL_TEXT,
  CODES,
  isTicketReason,
} = require('../../constants/banRefusalReason');

/** 从源码里取出「前端拒绝原因映射」的键集 */
const frontendKeys = () => {
  const src = read('web-admin/src/views/ForensicTraceView.vue');
  const start = src.indexOf('const BAN_REFUSAL_KEYS = {');
  expect(start).toBeGreaterThan(-1);
  const end = src.indexOf('}', start);
  const block = src.slice(start, end);
  return [...block.matchAll(/^\s{2}([a-z_]+):/gm)].map((m) => m[1]).sort();
};

describe('封段拒绝原因：单一事实来源的三向对账', () => {
  test('#1 产出方只从常量表取码：ipPoolBan 里没有裸写的原因字面量', () => {
    const src = read('src/services/ipPoolBan.js');
    // 判据不能靠"字面量的外形"（第一版按 xxx_cidr 形态匹配，漏掉了 full_range_cidr——
    // 它并不以 _cidr 结尾，于是真缺陷照绿）。改成**拿常量表逐个去源码里找**：
    // 任何一个已知码以单/双引号字面量出现在产出方，就是副本复发。
    const bare = REFUSAL_REASON_KEYS.filter(
      (code) => src.includes("'" + code + "'") || src.includes('"' + code + '"')
    );
    expect(bare).toEqual([]);
    // 且必须真的从常量表取（否则 #1 会在"整文件删掉 return"的情况下也绿）
    expect(src).toMatch(/require\(['"]\.\.\/constants\/banRefusalReason['"]\)/);
    expect(src).toMatch(/CODES\./);
  });

  test('#2 每个码都在 errorCodes 注册表里有归宿（响应体 reason 字段名被文档化）', () => {
    const src = read('src/utils/errorCodes.js');
    // 两个对外码都要指向常量表，而不是手抄枚举
    for (const code of ['FORENSIC_POOL_BAN_REFUSED', 'IP_SEGMENT_WRITE_REFUSED']) {
      expect(src).toMatch(new RegExp(code + ':\\s*\\{'));
    }
    expect(src).toContain('constants/banRefusalReason');
    // 注释里不许再出现手抄枚举（"a / b / c" 形态）
    expect(src).not.toMatch(/errors\.reason（[a-z_]+ \//);
  });

  test('#3 前端映射键集与常量键集双向相等（漏一个界面就暴露英文枚举）', () => {
    expect(frontendKeys()).toEqual([...REFUSAL_REASON_KEYS].sort());
  });

  test('#4 对外 OpenAPI 产物逐码出现，不是抽查', () => {
    const spec = read('src/docs/openapi.json');
    for (const code of REFUSAL_REASON_KEYS) {
      expect({ code, present: spec.includes(code) }).toEqual({ code, present: true });
    }
  });

  test('#5 两个语种对每个前端文案键都有值（漏文案 = 界面显示点分键名）', () => {
    const keys = frontendKeys();
    const vue = read('web-admin/src/views/ForensicTraceView.vue');
    const start = vue.indexOf('const BAN_REFUSAL_KEYS = {');
    const block = vue.slice(start, vue.indexOf('}', start));
    const i18nKeys = [...block.matchAll(/'(forensic\.[A-Za-z]+)'/g)].map((m) => m[1]);
    expect(i18nKeys.length).toBe(keys.length);
    for (const locale of ['zh-CN', 'en-US']) {
      const src = read('web-admin/src/i18n/locales/' + locale + '.js');
      for (const key of i18nKeys) {
        const leaf = key.split('.')[1];
        expect({ locale, leaf, present: new RegExp('^\\s*' + leaf + ':', 'm').test(src) }).toEqual({
          locale,
          leaf,
          present: true,
        });
      }
    }
  });

  test('#5b 票据类与判据类的前端处置必须不同：票据类走"重新发起"，判据类走"提示后停手"', () => {
    // 单表合并后 ticket 标记是**唯一**保留分档语义的地方，它必须真的接到前端分支上：
    //   · 票据类（unknown_token / token_expired）⇒ 重新发起封禁流程；
    //   · 判据类 ⇒ 只提示原因、停手（换台机器重试也没用）。
    // 若这一档被吞并（全部 ticket:true 或全部 false），前端就会对判据类原因反复弹"重新发起"，
    // 把用户送进死循环——这正是 ADR-018 ③ 说的"让人多走一步，不是重来一遍"的反面。
    // 判据：前端那段"票据失效 ⇒ 作废本地票、退回第一步"的分支，**逐码枚举的恰好是整档**。
    // 只查"某个码出现在文件里"是假判据（码也在映射表里出现，删掉分支照样绿）；这里把该分支
    // 的码清单抠出来与 ticket 档双向比对——少一个（票据类被判据类吞并）或多一个（判据类被
    // 当成票据、用户被推进死循环）都必须红。
    const vue = read('web-admin/src/views/ForensicTraceView.vue');
    const branchAt = vue.indexOf("if (reason === '");
    expect(branchAt).toBeGreaterThan(-1);
    // 取到该 if 的右花括号为止；只收**比较位置**的码（reason === 'x'），把分支体里的
    // banStage.value = 'request' 这类同段字面量排除掉——否则判据会被无关赋值喂出假红。
    const branch = vue.slice(branchAt, vue.indexOf('}', branchAt));
    const branched = [...branch.matchAll(/reason === '([a-z_]+)'/g)].map((m) => m[1]).sort();
    expect(branched).toEqual(REFUSAL_REASON_KEYS.filter((k) => isTicketReason(k)).sort());
    // 两档都要非空，且互不重叠（判据类必须至少有一个：否则"提示后停手"分支成了死代码）
    const ban = REFUSAL_REASON_KEYS.filter((k) => !isTicketReason(k));
    const ticket = REFUSAL_REASON_KEYS.filter((k) => isTicketReason(k));
    expect(ticket.length).toBeGreaterThan(0);
    expect(ban.length).toBeGreaterThan(0);
    expect(ban.filter((k) => ticket.includes(k))).toEqual([]);
  });

  test('#6 两档分类不重叠且并集等于全量（票据类与判据类不许互相吞并）', () => {
    const ban = REFUSAL_REASON_KEYS.filter((k) => !isTicketReason(k));
    const ticket = REFUSAL_REASON_KEYS.filter((k) => isTicketReason(k));
    // 两档都不能为空（全归成一档 = 前端失去"重新发起 vs 提示后停手"的区分）
    expect(ban.length).toBeGreaterThan(0);
    expect(ticket.length).toBeGreaterThan(0);
    expect(ban.filter((k) => ticket.includes(k))).toEqual([]);
    expect([...ban, ...ticket].sort()).toEqual([...REFUSAL_REASON_KEYS].sort());
    // 三个导出视图必须逐码同集：文案表、码常量表、原因表
    expect(Object.keys(REFUSAL_TEXT).sort()).toEqual([...REFUSAL_REASON_KEYS].sort());
    expect(Object.keys(CODES).sort()).toEqual([...REFUSAL_REASON_KEYS].sort());
    // CODES 必须是"码→码自身"，否则产出方 return CODES.x 会返回说明文案
    for (const code of REFUSAL_REASON_KEYS) expect(CODES[code]).toBe(code);
    // 每个码都要有非空说明（对外文档逐码生成，空说明会印出"code（）"）
    for (const code of REFUSAL_REASON_KEYS) expect(REFUSAL_TEXT[code].length).toBeGreaterThan(0);
  });
});
