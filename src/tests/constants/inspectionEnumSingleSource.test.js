/**
 * 巡检域取值清单的单一来源对账（F-150）
 *
 * 口径照并行会话的 alarmEnumSingleSource.test.js（F-142）：常量 ↔ 模型 schema enum ↔
 * 路由 isIn 校验器 ↔ docs/generate.js ↔ **已提交产物** src/docs/openapi.json 五端对账。
 * 本轮把巡检域四组此前共有 15 处手写副本的清单收进 constants/inspection.js
 * （inspectionType 6 值 / status 5 值 / result 3 值 / reviewResult 2 值），
 * severity 那一组由 F-149 的 zzqoder_riskLevelSingleSource.test.js 钉，这里顺手一起对账。
 *
 * 为什么必须钉**产物**而不是只钉生成器：openapiSync 的 L-24 深比对保证的是"生成器 == 产物"，
 * 两边共用同一份手抄清单时它当然绿——F-142 的记录里就出现过产物落后于生成器。
 * 生成器 == 常量由下面的引用点计数钉，产物 == 常量由本文件钉，两端接上才闭环。
 *
 * 本域实测到的漂移（不是假想风险，是整改前的现状）：
 *   1. **文档比运行时窄**：GET /api/inspections 的 status 文档枚举只有 4 档、独缺 overdue，
 *      而 overdue 是调度器（deviceReminder）真实写入、看板（reportDashboardService）真实统计、
 *      InspectionService 特意留在"可开始/可提交"集合里的一档。
 *      ⇒ 照文档写的调用方筛不出**超期巡检**，而"超期"是巡检里唯一带时效危害的状态。
 *      文档比运行时**宽**会表现为 400（容易发现），比运行时**窄**表现为"筛出来是空"（很难发现）。
 *   2. **文档比运行时宽**：inspectionType 查询参数原先只写 type: string，路由却 isIn(...) 六个值
 *      ⇒ 契约宣称任意字符串都行，实际传别的得到 400。
 */
const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '../../..');
const read = (p) => fs.readFileSync(path.join(ROOT, p), 'utf8');

/**
 * 代码视图：去掉**整行注释**（口径同 F-128 与 F-142，理由也一样：
 * 常量文件与本文件里对旧写法的引用若算进对账，红起来只能改文案，等于把用例绑在文案上）
 */
const codeOnly = (src) =>
  src
    .split('\n')
    .filter((line) => !/^\s*(\/\/|\*|\/\*)/.test(line))
    .join('\n');

/** 展平视图：整行注释与行尾注释都去掉后压掉换行/缩进（多行形态的字面量副本也要能被抓到） */
const flatCode = (src) =>
  codeOnly(src)
    .replace(/\/\/[^\n]*/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();

const isInCount = (src, name) =>
  (codeOnly(src).match(new RegExp(`isIn\\(${name}\\)`, 'g')) || []).length;

const {
  INSPECTION_FINDING_SEVERITIES,
  INSPECTION_TYPES,
  INSPECTION_STATUSES,
  INSPECTION_RESULTS,
  INSPECTION_REVIEW_RESULTS,
} = require('../../constants/inspection');
const Inspection = require('../../models/Inspection');
const spec = require('../../docs/openapi.json');

const REWRITTEN = [
  'src/models/Inspection.js',
  'src/routes/inspectionRoutes.js',
  'src/services/InspectionService.js',
  'src/docs/generate.js',
];

describe('Inspection 的五组 enum 就是 constants/inspection.js', () => {
  test('inspectionType / status / result / reviewResult / findings.severity 逐组等于常量', () => {
    expect(Inspection.schema.path('inspectionType').enumValues).toEqual(INSPECTION_TYPES);
    expect(Inspection.schema.path('status').enumValues).toEqual(INSPECTION_STATUSES);
    expect(Inspection.schema.path('result').enumValues).toEqual(INSPECTION_RESULTS);
    expect(Inspection.schema.path('reviewResult').enumValues).toEqual(INSPECTION_REVIEW_RESULTS);
    expect(Inspection.schema.path('findings').schema.path('severity').enumValues).toEqual(
      INSPECTION_FINDING_SEVERITIES
    );
  });

  test('模型写的是引用而不是同内容副本（内容 equal 证明不了同源）', () => {
    const src = codeOnly(read('src/models/Inspection.js'));
    for (const name of [
      'INSPECTION_TYPES',
      'INSPECTION_STATUSES',
      'INSPECTION_RESULTS',
      'INSPECTION_REVIEW_RESULTS',
      'INSPECTION_FINDING_SEVERITIES',
    ]) {
      expect(src).toContain(`enum: ${name},`);
    }
  });

  test('status 的 default 落在清单内、inspectionType 仍必填（漂出清单不该被 schema 放过）', () => {
    const def = Inspection.schema.path('status').defaultValue;
    expect(INSPECTION_STATUSES).toContain(def);
    expect(Inspection.schema.path('inspectionType').isRequired).toBe(true);
  });
});

describe('引用点数量对账：原副本位置必须都已改成引用', () => {
  // 期望数量 = 重接线前 grep 实测的处数（3 个 body/query 的 inspectionType 是分开计的），不是凭印象
  const ROUTE_SITES = [
    ['INSPECTION_STATUSES', 1],
    ['INSPECTION_TYPES', 3],
    ['INSPECTION_RESULTS', 1],
    ['INSPECTION_REVIEW_RESULTS', 1],
    ['INSPECTION_FINDING_SEVERITIES', 1],
  ];
  for (const [name, n] of ROUTE_SITES) {
    test(`inspectionRoutes.js 里 isIn(${name}) 恰好 ${n} 处`, () => {
      expect(isInCount(read('src/routes/inspectionRoutes.js'), name)).toBe(n);
    });
  }

  test('服务层的审核闸门引用常量（闸门与白名单各写一遍是 F-137 那一族）', () => {
    const src = codeOnly(read('src/services/InspectionService.js'));
    expect((src.match(/INSPECTION_REVIEW_RESULTS\.includes\(/g) || []).length).toBe(1);
    // 判据自证：把引用改回字面量 includes，本条计数必须归 0（否则计数是空跑的）
    const laundered = src.replace(
      'INSPECTION_REVIEW_RESULTS.includes',
      "['approved', 'rejected'].includes"
    );
    expect((laundered.match(/INSPECTION_REVIEW_RESULTS\.includes\(/g) || []).length).toBe(0);
  });

  test('生成器 5 处 enum 写的是引用而不是副本（逐组计处数，防止只改一处）', () => {
    const src = codeOnly(read('src/docs/generate.js'));
    const enumCount = (name) => (src.match(new RegExp(`enum: ${name}\\b`, 'g')) || []).length;
    expect({
      TYPES: enumCount('INSPECTION_TYPES'),
      STATUSES: enumCount('INSPECTION_STATUSES'),
      RESULTS: enumCount('INSPECTION_RESULTS'),
      REVIEW: enumCount('INSPECTION_REVIEW_RESULTS'),
    }).toEqual({ TYPES: 2, STATUSES: 1, RESULTS: 1, REVIEW: 1 });
  });

  test('四个被改写的文件里不得再出现这四组值的字面量副本', () => {
    const LITERALS = [
      "'daily', 'weekly', 'monthly', 'quarterly', 'annual', 'special'",
      "'pending', 'in_progress', 'completed', 'overdue', 'cancelled'",
      "'normal', 'abnormal', 'partial'",
      "'approved', 'rejected'",
    ];
    // 正对照：常量文件本身必须含这四份完整清单，否则下面的 not.toContain 是空断言
    const constSrc = flatCode(read('src/constants/inspection.js'));
    for (const lit of LITERALS) expect(constSrc).toContain(lit);

    for (const file of REWRITTEN) {
      const src = flatCode(read(file));
      for (const lit of LITERALS) expect(src).not.toContain(lit);
    }
  });

  test('判据自证：把生成器的 status 引用改回字面量，上一条的副本检查必须报出来', () => {
    // 没有这条，"四个文件都干净"可能只是提取器压根抓不到多行/带注释的字面量
    const rel = 'src/docs/generate.js';
    const LIT = "'pending', 'in_progress', 'completed', 'overdue', 'cancelled'";
    const src = flatCode(read(rel));
    // 前提：这处确实是引用写法（replace 空转的话自检就没有意义）
    expect(src).toContain('enum: INSPECTION_STATUSES');
    const patched = src.replace('enum: INSPECTION_STATUSES', `enum: [${LIT}]`);
    expect(patched).not.toContain('enum: INSPECTION_STATUSES');
    expect(patched).toContain(LIT);
  });
});

describe('已提交产物的文档枚举 = 常量（钉对外交付的那一份）', () => {
  const queryEnum = (p, method, name) => {
    const item = spec.paths[p][method].parameters.find((q) => q.name === name);
    return item && item.schema ? item.schema.enum : undefined;
  };
  const bodyEnum = (p, method, name) =>
    spec.paths[p][method].requestBody.content['application/json'].schema.properties[name].enum;

  test('GET /api/inspections 的 status/inspectionType 文档枚举逐项等于常量', () => {
    // 用对象包一层：红灯时输出直接写着是哪个参数漂了（裸 toEqual 只给两个数组）
    expect({ status: queryEnum('/api/inspections', 'get', 'status') }).toEqual({
      status: INSPECTION_STATUSES,
    });
    expect({ inspectionType: queryEnum('/api/inspections', 'get', 'inspectionType') }).toEqual({
      inspectionType: INSPECTION_TYPES,
    });
  });

  test('文档的 status 枚举必须含 overdue（F-150 那条漂移的定点回归）', () => {
    const doc = queryEnum('/api/inspections', 'get', 'status');
    expect(doc).toContain('overdue');
    // 运行时接受而文档不列的取值 = 0 个（"文档比运行时窄"的通用表述，加一档时这条会替人记住）
    const undocumented = INSPECTION_STATUSES.filter((s) => !doc.includes(s));
    expect({ undocumented }).toEqual({ undocumented: [] });
    // 反向：文档写了而运行时拒的取值也必须为 0（"比运行时宽"会表现为调用方拿到 400）
    const rejected = doc.filter((s) => !INSPECTION_STATUSES.includes(s));
    expect({ rejected }).toEqual({ rejected: [] });
  });

  test('requestBody 侧的三处枚举等于常量', () => {
    expect({ inspectionType: bodyEnum('/api/inspections', 'post', 'inspectionType') }).toEqual({
      inspectionType: INSPECTION_TYPES,
    });
    expect({ result: bodyEnum('/api/inspections/{id}/complete', 'put', 'result') }).toEqual({
      result: INSPECTION_RESULTS,
    });
    expect({
      reviewResult: bodyEnum('/api/inspections/{id}/review', 'put', 'reviewResult'),
    }).toEqual({
      reviewResult: INSPECTION_REVIEW_RESULTS,
    });
  });

  test('提取器不是空转：三处 body 与两处 query 都真的取到了数组', () => {
    for (const v of [
      queryEnum('/api/inspections', 'get', 'status'),
      queryEnum('/api/inspections', 'get', 'inspectionType'),
      bodyEnum('/api/inspections', 'post', 'inspectionType'),
      bodyEnum('/api/inspections/{id}/complete', 'put', 'result'),
      bodyEnum('/api/inspections/{id}/review', 'put', 'reviewResult'),
    ]) {
      expect(Array.isArray(v)).toBe(true);
    }
  });
});

/**
 * F-151：巡检状态的**档带**必须由全集派生，且消费方不得各写一份子集
 *
 * 这一组与上面五端对账钉的是同一件事的两半：清单收齐了，但"取哪几档"的判据还在各处手抄。
 * 实测到的三处子集副本（整改前）：
 *   - userService.releaseOpenAssignments：['pending','in_progress'] —— **漏了 overdue**，
 *     而调度器恰恰会把超期的开放计划改成 overdue ⇒ 删掉唯一执行人后这条计划开工/提交双双 409，
 *     cancel 又不卡执行人 ⇒ 唯一出路是把真做过的消防巡检登记成「已取消」（行为级回归见
 *     zzqoder_userDeleteCascade.test.js 的「超期(overdue)的巡检」用例，整改前它是红的）。
 *   - deviceReminder.markOverdueInspections 与 reportDashboardService 的超期统计各写一份
 *     ['pending','in_progress']：两边不同口径时，看板会统计出调度器永不改写的超期数（或漏计），
 *     而漏计在看面上显示为「没有超期」——一个静默的负结果。
 *   - InspectionService 的开工 ['pending','overdue'] 与提交 ['in_progress','overdue']。
 *
 * 判据是**划分**（终态 / 开放）而不是清单：给 INSPECTION_STATUSES 加一档时必须显式回答
 * "它是终态吗"，否则下面的划分用例当场红。这与 F-149 的三档展示桶同理——
 * 单纯扫字面量在"没人抄清单"时永远是绿的，抓不到"该抄而没抄"的那一类。
 */
describe('巡检状态档带：派生关系与消费方引用点', () => {
  const {
    INSPECTION_STATUSES,
    INSPECTION_TERMINAL_STATUSES,
    INSPECTION_OPEN_STATUSES,
    INSPECTION_OVERDUE_MARKABLE_STATUSES,
    INSPECTION_STARTABLE_STATUSES,
    INSPECTION_SUBMITTABLE_STATUSES,
  } = require('../../constants/inspection');

  const sorted = (a) => [...a].sort();

  /**
   * 标题原先写"加一档不归类就红"——**M1 实测是错的**：给 INSPECTION_STATUSES 追加
   * 'archived' 时派生式 `OPEN = STATUSES - TERMINAL` 把它自动吸收进 OPEN，本行照绿
   * （红的只有下面的"取值逐一钉住"和 F-150 那两条文档/产枚举行）。
   * 本行真正抓得到的是**档带越出全集**：M4 实测把 'archived' 只塞进 TERMINAL ⇒ 本行红。
   * 说清各自把守哪种漂移，比给一条用例起一个它兑现不了的名字重要。
   */
  test('终态 + 开放 = 全集，且不重不漏（档带越出全集就红，M4 实测）', () => {
    expect(INSPECTION_TERMINAL_STATUSES.length).toBeGreaterThan(0);
    const overlap = INSPECTION_TERMINAL_STATUSES.filter((s) =>
      INSPECTION_OPEN_STATUSES.includes(s)
    );
    expect({ overlap }).toEqual({ overlap: [] });
    const uncovered = INSPECTION_STATUSES.filter(
      (s) => !INSPECTION_TERMINAL_STATUSES.includes(s) && !INSPECTION_OPEN_STATUSES.includes(s)
    );
    expect({ uncovered }).toEqual({ uncovered: [] });
    const bogus = [...INSPECTION_TERMINAL_STATUSES, ...INSPECTION_OPEN_STATUSES].filter(
      (s) => !INSPECTION_STATUSES.includes(s)
    );
    expect({ bogus }).toEqual({ bogus: [] });
  });

  test('四条档带的取值逐一钉住（派生式漂了这里会说是哪条）', () => {
    expect({ OPEN: sorted(INSPECTION_OPEN_STATUSES) }).toEqual({
      OPEN: sorted(['pending', 'in_progress', 'overdue']),
    });
    expect({ MARKABLE: sorted(INSPECTION_OVERDUE_MARKABLE_STATUSES) }).toEqual({
      MARKABLE: sorted(['pending', 'in_progress']),
    });
    expect({ STARTABLE: sorted(INSPECTION_STARTABLE_STATUSES) }).toEqual({
      STARTABLE: sorted(['pending', 'overdue']),
    });
    expect({ SUBMITTABLE: sorted(INSPECTION_SUBMITTABLE_STATUSES) }).toEqual({
      SUBMITTABLE: sorted(['in_progress', 'overdue']),
    });
  });

  test('overdue 同时可开工且可提交：它是时间标记，不是工作流阶段', () => {
    // 少一边就退回 F-旧账里那两个故障：迟开工的只能 cancel / 干到一半超时的提交 409 丢结果
    expect(INSPECTION_STARTABLE_STATUSES).toContain('overdue');
    expect(INSPECTION_SUBMITTABLE_STATUSES).toContain('overdue');
  });

  test('可开工 ∪ 可提交 = 开放档位 = 级联必须释放的面（F-151 的核心不变量）', () => {
    const workable = sorted(
      new Set([...INSPECTION_STARTABLE_STATUSES, ...INSPECTION_SUBMITTABLE_STATUSES])
    );
    expect({ workable }).toEqual({ workable: sorted(INSPECTION_OPEN_STATUSES) });
  });

  test('四条档带都是全集的有序子序列（派生而非另起一份清单）', () => {
    const isOrderedSubsequence = (band) => {
      let i = 0;
      for (const s of INSPECTION_STATUSES) if (band[i] === s) i += 1;
      return i === band.length;
    };
    for (const band of [
      INSPECTION_OPEN_STATUSES,
      INSPECTION_OVERDUE_MARKABLE_STATUSES,
      INSPECTION_STARTABLE_STATUSES,
      INSPECTION_SUBMITTABLE_STATUSES,
    ]) {
      expect(isOrderedSubsequence(band)).toBe(true);
    }
    // 前提自证：这条判据不是空转——把某条档带反序就不再是有序子序列
    expect(isOrderedSubsequence(['overdue', 'pending'])).toBe(false);
  });

  /**
   * M6 实测出来的洞：把 `INSPECTION_OVERDUE_MARKABLE_STATUSES` 从派生式改回
   * `['pending', 'in_progress']`——也就是 F-151 之前那个**缺 overdue 的手抄副本**——
   * 上面所有取值/划分/引用行全部照绿，因为它今天的取值恰好等于派生结果。
   * 值相等证明不了同源（同一个教训在 F-149/F-150 用在模型侧，这里漏了常量侧）。
   * 所以补这一条：读常量文件的**写法**，要求档带由上一条派生，而不是各自写字面量。
   */
  test('四条档带在常量文件里必须是派生式写法（同值手抄＝把 F-151 放回原处）', () => {
    const src = flatCode(read('src/constants/inspection.js'));
    const declRhs = (text, name) => {
      const head = `const ${name} = `;
      const i = text.indexOf(head);
      expect({ name, found: i >= 0 }).toEqual({ name, found: true });
      const end = text.indexOf(';', i);
      return text.slice(i + head.length, end);
    };
    expect(declRhs(src, 'INSPECTION_OPEN_STATUSES')).toContain('INSPECTION_STATUSES.filter(');
    for (const name of [
      'INSPECTION_OVERDUE_MARKABLE_STATUSES',
      'INSPECTION_STARTABLE_STATUSES',
      'INSPECTION_SUBMITTABLE_STATUSES',
    ]) {
      const rhs = declRhs(src, name);
      // 展平视图里 `filter(` 与换行之间会留一个空格，所以只钉"引用了上一条 + 用 filter 切片"
      expect({ name, refersOpen: rhs.includes('INSPECTION_OPEN_STATUSES') }).toEqual({
        name,
        refersOpen: true,
      });
      expect({ name, filtered: rhs.includes('.filter(') }).toEqual({ name, filtered: true });
    }

    // 判据自证：在内存里做一次 M6 那种手抄洗白，上面的口径必须不再成立
    const laundered = src.replace(
      /const INSPECTION_OVERDUE_MARKABLE_STATUSES = [^;]*;/,
      "const INSPECTION_OVERDUE_MARKABLE_STATUSES = ['pending', 'in_progress'];"
    );
    expect(laundered).not.toBe(src); // 替换真的发生了，否则这条自证是空转
    expect(declRhs(laundered, 'INSPECTION_OVERDUE_MARKABLE_STATUSES')).not.toContain(
      'INSPECTION_OPEN_STATUSES'
    );
    expect(declRhs(laundered, 'INSPECTION_OVERDUE_MARKABLE_STATUSES')).toContain(
      "'pending', 'in_progress'"
    );
  });

  // ---- 消费方：写的是引用还是副本 ----
  const SITES = [
    ['src/services/userService.js', 'INSPECTION_OPEN_STATUSES', 1],
    // cancelInspection 原先是 `$nin: ['completed', 'cancelled']`——本域最后一处手抄的档位
    // 字面量，被下面那条副本禁令抓出来（正是它存在的意义）。改成 `$in: 开放档位` 后同闸。
    ['src/services/InspectionService.js', 'INSPECTION_OPEN_STATUSES', 1],
    ['src/services/deviceReminder.js', 'INSPECTION_OVERDUE_MARKABLE_STATUSES', 1],
    ['src/services/reportDashboardService.js', 'INSPECTION_OVERDUE_MARKABLE_STATUSES', 1],
    ['src/services/InspectionService.js', 'INSPECTION_STARTABLE_STATUSES', 1],
    ['src/services/InspectionService.js', 'INSPECTION_SUBMITTABLE_STATUSES', 1],
  ];
  const countQuerySite = (src, name) =>
    (src.match(new RegExp(`\\$in: ${name}\\b`, 'g')) || []).length;
  for (const [file, name, n] of SITES) {
    test(`${file} 里 ${name} 的查询面恰好 ${n} 处`, () => {
      const uses = countQuerySite(codeOnly(read(file)), name);
      expect({ file, name, uses }).toEqual({ file, name, uses: n });
    });
  }

  test('计数判据自身不空转：正对照样例数得出 1 处，反例数得出 0 处', () => {
    // 这一条是给上一条兜底的：初版把模式写成 `$in: NAME\b`（模板串里 `\$` 会先被解成 `$`，
    // 落到 RegExp 里就成了"行尾锚点 + in: …"），于是 6 行全部 0 命中。期望值是 1 才让
    // 坏判据当场响；一旦有人把期望改成 0 来"修绿"，坏判据就会永久静默，所以计数器本身钉一次。
    expect(countQuerySite('{ a: { $in: BAND } }', 'BAND')).toBe(1);
    expect(countQuerySite("{ a: { $nin: ['x', 'y'] } }", 'BAND')).toBe(0);
    expect(countQuerySite('{ a: { $in: BAND_X } }', 'BAND')).toBe(0); // \b 不被前缀名骗到
  });

  test('4 个消费文件里不得再出现这些档带的字面量副本', () => {
    const LITERALS = [
      "'pending', 'in_progress'",
      "'pending', 'overdue'",
      "'in_progress', 'overdue'",
      "'completed', 'cancelled'",
    ];
    // 正对照：常量文件本身必须写着终态那份字面量（档带由它派生），否则下面的禁令是空断言
    const constSrc = flatCode(read('src/constants/inspection.js'));
    expect(constSrc).toContain("'completed', 'cancelled'");

    for (const file of [
      'src/services/userService.js',
      'src/services/deviceReminder.js',
      'src/services/reportDashboardService.js',
      'src/services/InspectionService.js',
    ]) {
      const src = flatCode(read(file));
      for (const lit of LITERALS) expect(src).not.toContain(lit);
    }
  });

  test('判据自证：把引用改回同内容字面量，上面的禁令必须红', () => {
    // 反向补丁跑在内存里（不写盘）：不这么测一次，"引用点计数 + 副本禁令"可能只是恰好没抓到东西
    const file = 'src/services/userService.js';
    const original = flatCode(read(file));
    expect(original).toContain('$in: INSPECTION_OPEN_STATUSES }');
    const laundered = original.replace(
      '$in: INSPECTION_OPEN_STATUSES }',
      "$in: ['pending', 'in_progress', 'overdue'] }"
    );
    expect(laundered).not.toContain('$in: INSPECTION_OPEN_STATUSES }');
    for (const lit of ["'pending', 'in_progress'", "'in_progress', 'overdue'"]) {
      expect(laundered).toContain(lit);
    }
  });
});
