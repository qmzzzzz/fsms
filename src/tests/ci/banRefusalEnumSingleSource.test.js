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
const {
  ENDPOINT_OF_FILE,
  REFUSAL_ERROR_CODES,
  collectEmitFiles,
  endpoints,
  endpointDocViolations,
  strictFourXxGaps,
} = require('./helpers/refusalDocContract');

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

  test('#1b 反向：产出方不许自造表外码——抽出所有 reason 字面量，必须都能在表内找到', () => {
    // 第 20 轮实测：旧 #1 是**单向**的（拿表内码去源码里找），于是 ipPoolBan:174 的
    // `reason: 'no_candidates'` 这种表外码永远不会被查到。反向断言补上另一半：
    // 产出方出现的每个 reason 字面量都必须来自这张表（或者是 null=「没有原因」）。
    const src = read('src/services/ipPoolBan.js');
    const literals = [...src.matchAll(/reason:\s*(['"])([a-z_]+)\1/g)].map((m) => m[2]);
    // 抽取器自检：合成一条表外码必须被抽出来，否则「抽不到」与「不存在」无法区分（假绿）
    expect(
      [..."reason: 'no_candidates';".matchAll(/reason:\s*(['"])([a-z_]+)\1/g)].map((m) => m[2])
    ).toEqual(['no_candidates']);
    const outside = literals.filter((code) => !REFUSAL_REASON_KEYS.includes(code));
    expect({ literals, outside }).toEqual({ literals: [], outside: [] });
    // CODES.x 引用同样必须都在表内：拼错键名会返回 undefined（拒绝原因变成 undefined）
    const referenced = [...src.matchAll(/CODES\.([a-z_]+)/g)].map((m) => m[1]);
    expect(referenced.length).toBeGreaterThan(5);
    expect(referenced.filter((code) => !REFUSAL_REASON_KEYS.includes(code))).toEqual([]);
  });

  test('#2 每个码都在 errorCodes 注册表里有归宿（响应体 reason 字段名被文档化）', () => {
    const src = read('src/utils/errorCodes.js');
    // 两个对外码都要指向常量表，而不是手抄枚举
    for (const code of ['FORENSIC_POOL_BAN_REFUSED', 'IP_SEGMENT_WRITE_REFUSED']) {
      expect(src).toMatch(new RegExp(code + ':\\s*\\{'));
    }
    expect(src).toContain('constants/banRefusalReason');
    // 消费者（含前端 api.js）不许抄枚举：一个字面码都不该出现，抄一次就会漂移一次
    // （第 20 轮实测：web-admin/src/utils/api.js:282-284 手抄 7 码、漏 3 码，而 #2 只扫了后端）
    for (const rel of ['src/utils/errorCodes.js', 'web-admin/src/utils/api.js']) {
      const consumer = read(rel);
      const copied = REFUSAL_REASON_KEYS.filter((code) => consumer.includes(code));
      expect({ rel, copied }).toEqual({ rel, copied: [] });
    }
  });

  test('#3 前端映射键集与常量键集双向相等（漏一个界面就暴露英文枚举）', () => {
    expect(frontendKeys()).toEqual([...REFUSAL_REASON_KEYS].sort());
  });

  test('#4 每个真的会抛拒绝码的端点，其自身描述必须写明 errors.reason（端点级，不是整份文档）', () => {
    // 旧判据是 spec.includes(code)：同一个码出现在**无关端点**的长描述里就能让 ip-list
    // 的通用 400 文案蒙混过关（第 22 轮实测，见 work/audit-round22-h4-refusal-reason.md §6）。
    // 新判据把范围钉到「这个端点自己的描述」= 操作描述 + 它自己的 4xx 描述。
    const spec = JSON.parse(read('src/docs/openapi.json'));
    const violations = endpointDocViolations(spec);
    expect(violations).toEqual([]);
    // 严格档（第 23 轮 lead 拍板）：只认 4xx 描述**本身**，不接受"靠操作描述兜底"。
    // 松档放过的形状是"操作描述提了 errors.reason、400 描述却仍是通用文案"——照文档实现
    // 错误分支的第三方只会读到 400 那一行。pool-ban/confirm 曾是唯一缺口，现已写实。
    expect(strictFourXxGaps(spec)).toEqual([]);
    // 端点清单不许手抄：清单的锚是「源码里真的 codeError(res,'<码>') 的文件」，双向相等。
    const emitting = collectEmitFiles();
    expect(emitting).toEqual(Object.keys(ENDPOINT_OF_FILE).sort());
    // 静态一致性：清单里每个文件的拒绝码必须真的能从该文件里抽出来（否则清单随实现漂移）
    for (const rel of emitting) {
      const src = read(rel);
      const codes = REFUSAL_ERROR_CODES.filter((c) => src.includes("'" + c + "'"));
      expect({ rel, codes }).toEqual({ rel, codes: expect.arrayContaining([expect.any(String)]) });
    }
    // 反空转：判据作用域必须真的覆盖到端点自己的 400（不是只扫到别的端点）
    expect(endpoints().length).toBe(3);
    for (const ep of endpoints()) {
      const op = spec.paths[ep.path] && spec.paths[ep.path][ep.method];
      const body = JSON.stringify(op && op.responses && op.responses['400']);
      expect({ path: ep.path, has400: Boolean(body) }).toEqual({ path: ep.path, has400: true });
    }
  });

  test('#4b 变异自证：把 ip-list 400 描述回退成通用文案 ⇒ 本判据红，而旧 #4（整份 includes）仍绿', () => {
    // 判据"有牙"必须当场证明，不能靠报告口头声明。这里在内存里做一次最小变异：
    // 只改 ip-list POST 的 400 描述（回到 lead 修前的通用文案），其余产物不动。
    const specText = read('src/docs/openapi.json');
    const spec = JSON.parse(specText);
    spec.paths['/api/security/ip-list'].post.responses['400'].description = 'IP 已在白名单中';
    const mutatedText = JSON.stringify(spec);
    // 新判据：必须红，且指认的正是被变异的那个端点
    expect(endpointDocViolations(spec).map((v) => v.method + ' ' + v.path)).toEqual([
      'post /api/security/ip-list',
    ]);
    // 旧判据（逐码 includes）：在**同一份变异产物**上仍然全绿 —— 这就是它漏报 defect 的机理
    const oldJudgeMisses = REFUSAL_REASON_KEYS.filter((code) => !mutatedText.includes(code));
    expect(oldJudgeMisses).toEqual([]);
    // 且变异本身没把码从产物里抹掉（否则上一条的"仍绿"是拿"码全没了"骗来的）
    expect(specText).toContain('no_rescue_path');
  });

  test('#4c 严格档有牙：4xx 描述退回通用文案（操作描述仍提 errors.reason）⇒ 严格档红、松档绿', () => {
    // 这一条钉的是「为什么需要严格档」：松档认"操作描述 ∪ 4xx 描述"，于是
    // 400 那行写回通用文案时，只要操作描述里留一句 errors.reason 就照样绿。
    // 照文档实现错误分支的第三方只会读 400 那一行，所以这是真实漏报面。
    const spec = JSON.parse(read('src/docs/openapi.json'));
    const op = spec.paths['/api/security/forensic/pool-ban/confirm'].post;
    const before = op.responses['400'].description;
    op.responses['400'].description = '票据无效或已过期';
    // 松档：操作描述里仍有 errors.reason ⇒ 绿（漏报机理）
    expect(endpointDocViolations(spec)).toEqual([]);
    expect(op.description).toContain('errors.reason');
    // 严格档：必须红，且正好点名这一个端点
    expect(strictFourXxGaps(spec)).toEqual(['POST /api/security/forensic/pool-ban/confirm']);
    // 复原断言：当前产物本身（未变异）在严格档下无缺口，否则上面的红是"本来就是红的"
    expect(strictFourXxGaps(JSON.parse(read('src/docs/openapi.json')))).toEqual([]);
    expect(before).toContain('errors.reason');
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
