/**
 * 报警域取值清单的单一来源对账（F-142）
 *
 * 口径与 permissionStatusSingleSource.test.js（F-137/138/141）一致：
 * `ALARM_LEVELS` / `ALARM_TYPES` / `ALARM_STATUSES` 三组值此前共有 12 处字面量副本，
 * 分布在 models/FireAlarm.js 的 schema enum、routes/alarmRoutes.js 的 query 与 body
 * 校验器、docs/generate.js 的 query 参数与 requestBody 属性。
 *
 * 本文件额外钉三件邻居用例没覆盖的事：
 *   1. **已提交产物**（src/docs/openapi.json，对外实际交付的那份文档）的枚举也必须等于
 *      常量。生成器 == 产物由 openapiSync 的逐端点深比对钉，产物 == 运行时由这里钉，
 *      两端接上才闭环——实测这次整改过程中产物就落后于生成器（对方改了 generate.js
 *      未重跑生成器，openapiSync 当时是红的），说明这一环不是假想风险。
 *   2. 文档原先**比运行时宽**：GET /api/alarms 的 alarmType 查询参数在文档里没有 enum，
 *      而路由一直 isIn(...) 拒非法值 ⇒ 调用方照文档传 'smoking' 得到一个 400。
 *      接同一根线后一并补齐，这里把它钉住。
 *   3. (F-158) **F-142 的扫描本身漏了一组**：cause 的清单当时只写在 model 的 schema 里，
 *      路由校验器与文档生成器各抄一份字面量。本文件靠"三组常量"跑绿，对没进常量的
 *      第四组完全无感——这正是清单型门禁的固有盲区：它只能证明已接线的一致，
 *      证明不了"该接的都接了"。所以这里的 LITERALS 黑名单要按**字段**列全，
 *      而不是按常量名循环（后者会跟着漏掉的那份一起漏）。
 */
const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '../../..');
const read = (p) => fs.readFileSync(path.join(ROOT, p), 'utf8');

/**
 * 代码视图：去掉**整行注释**。对账"某处不该再有字面量副本"时必须先过这一层，
 * 否则本文件/常量文件里对旧写法的引用会让用例红——那种红改措辞就能消掉，
 * 等于把用例绑在文案上。行尾跟随注释保留。口径同 F-128 与 permission 套件。
 */
const codeOnly = (src) =>
  src
    .split('\n')
    .filter((line) => !/^\s*(\/\/|\*|\/\*)/.test(line))
    .join('\n');

const isInCount = (src, name) =>
  (codeOnly(src).match(new RegExp(`isIn\\(${name}\\)`, 'g')) || []).length;

/**
 * 展平视图：整行注释与行尾注释都去掉后再压掉换行/缩进。
 * 抓"字面量副本"必须过这一层：ALARM_TYPES 有 6 个值，副本既可能写成一行
 * （prettier 放得下）也可能写成多行带中文行尾注释（整改前的 model 就是这种）。
 * 只用 codeOnly 的话，多行形态永远匹配不上，正对照就会当场红。
 */
const flatCode = (src) =>
  codeOnly(src)
    .replace(/\/\/[^\n]*/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();

const {
  ALARM_LEVELS,
  ALARM_TYPES,
  ALARM_STATUSES,
  ALARM_CAUSES,
} = require('../../constants/alarm');
const FireAlarm = require('../../models/FireAlarm');
const spec = require('../../docs/openapi.json');

describe('FireAlarm 的四个 enum 就是 constants/alarm.js', () => {
  test('level / alarmType / status / cause 逐组等于常量（顺序也一致，顺序即文档展示序）', () => {
    expect(FireAlarm.schema.path('level').enumValues).toEqual(ALARM_LEVELS);
    expect(FireAlarm.schema.path('alarmType').enumValues).toEqual(ALARM_TYPES);
    expect(FireAlarm.schema.path('status').enumValues).toEqual(ALARM_STATUSES);
    // F-158：cause 是 F-142 当时漏扫的第四组——清单只在 model 里，路由与文档各抄一份
    expect(FireAlarm.schema.path('cause').enumValues).toEqual(ALARM_CAUSES);
  });

  test('model 写的是引用而不是同内容副本（内容 equal 证明不了同源）', () => {
    const src = codeOnly(read('src/models/FireAlarm.js'));
    expect(src).toContain('enum: ALARM_LEVELS,');
    expect(src).toContain('enum: ALARM_TYPES,');
    expect(src).toContain('enum: ALARM_STATUSES,');
    expect(src).toContain('enum: ALARM_CAUSES,');
  });

  test('有 default 的字段都落在各自清单内（防止漂出清单后仍被 schema 放过）', () => {
    const defaults = {
      level: FireAlarm.schema.path('level').defaultValue,
      status: FireAlarm.schema.path('status').defaultValue,
    };
    expect(ALARM_LEVELS).toContain(defaults.level);
    expect(ALARM_STATUSES).toContain(defaults.status);
    // alarmType 无 default：required + 校验器兜住，这里只钉 required 没被顺手去掉
    expect(FireAlarm.schema.path('alarmType').isRequired).toBe(true);
    // cause 也无 default（不填就是没填，不能凭空造出一个处置原因）
    expect(FireAlarm.schema.path('cause').defaultValue).toBeUndefined();
  });
});

describe('引用点数量对账：原副本位置必须都已改成引用', () => {
  // 期望数量 = 重接线前 grep 实测的处数，不是凭印象写的
  const ROUTE_SITES = [
    ['src/routes/alarmRoutes.js', 'ALARM_STATUSES', 1],
    ['src/routes/alarmRoutes.js', 'ALARM_LEVELS', 2],
    ['src/routes/alarmRoutes.js', 'ALARM_TYPES', 2],
    ['src/routes/alarmRoutes.js', 'ALARM_CAUSES', 1],
  ];
  for (const [file, name, n] of ROUTE_SITES) {
    test(`${file} 里 isIn(${name}) 恰好 ${n} 处`, () => {
      expect(isInCount(read(file), name)).toBe(n);
    });
  }

  test('生成器 6 处 enum 写的是引用而不是副本（逐组计处数，防止只改一处）', () => {
    const src = codeOnly(read('src/docs/generate.js'));
    const enumCount = (name) => (src.match(new RegExp(`enum: ${name}\\b`, 'g')) || []).length;
    expect({
      STATUSES: enumCount('ALARM_STATUSES'),
      LEVELS: enumCount('ALARM_LEVELS'),
      TYPES: enumCount('ALARM_TYPES'),
      CAUSES: enumCount('ALARM_CAUSES'),
    }).toEqual({
      STATUSES: 1,
      LEVELS: 2,
      TYPES: 2,
      CAUSES: 1,
    });
  });

  test('3 个被改写的文件里不得再出现这四组值的字面量副本（正对照见 constants/alarm.js）', () => {
    const LITERALS = [
      "'info', 'warning', 'critical', 'emergency'",
      "'smoke', 'temp_abnormal', 'manual_button', 'phone_report', 'patrol_find', 'other'",
      "'pending', 'processing', 'resolved', 'false_alarm', 'cancelled'",
      "'fire', 'false_alarm', 'equipment_fault', 'test', 'unknown'",
    ];
    // 正对照：常量文件本身必须含这四份完整清单，否则下面的 not.toContain 是空断言
    const constSrc = flatCode(read('src/constants/alarm.js'));
    for (const lit of LITERALS) expect(constSrc).toContain(lit);
    // 清单条数 == 导出的常量条数：新增一组常量却不加对应字面量黑名单，
    // 上面那条正对照会悄悄变弱（漏掉的那组永远没被要求"从副本改成引用"）。
    expect(LITERALS).toHaveLength(Object.keys(require('../../constants/alarm')).length);

    for (const file of [
      'src/models/FireAlarm.js',
      'src/routes/alarmRoutes.js',
      'src/docs/generate.js',
    ]) {
      const src = flatCode(read(file));
      for (const lit of LITERALS) expect(src).not.toContain(lit);
    }
  });
});

describe('已提交产物的文档枚举 = 常量（钉对外交付的那一份）', () => {
  const enumOf = (params, name) => {
    const item = params.find((q) => q.name === name);
    return item && item.schema ? item.schema.enum : undefined;
  };

  test('GET /api/alarms 的 status/level/alarmType 文档枚举逐项等于常量', () => {
    const params = spec.paths['/api/alarms'].get.parameters;
    // 用对象包一层：红灯时输出直接写着是哪个参数漂了（裸 toEqual 只给两个数组）
    expect({ status: enumOf(params, 'status') }).toEqual({ status: ALARM_STATUSES });
    expect({ level: enumOf(params, 'level') }).toEqual({ level: ALARM_LEVELS });
    expect({ alarmType: enumOf(params, 'alarmType') }).toEqual({ alarmType: ALARM_TYPES });
  });

  test('POST /api/alarms/report 的 requestBody 枚举逐项等于常量', () => {
    const props =
      spec.paths['/api/alarms/report'].post.requestBody.content['application/json'].schema
        .properties;
    expect({ alarmType: props.alarmType.enum }).toEqual({ alarmType: ALARM_TYPES });
    expect({ level: props.level.enum }).toEqual({ level: ALARM_LEVELS });
  });

  test('PUT /api/alarms/:id/resolve 的 cause 文档枚举逐项等于常量（F-158 新接线）', () => {
    const props =
      spec.paths['/api/alarms/{id}/resolve'].put.requestBody.content['application/json'].schema
        .properties;
    expect({ cause: props.cause.enum }).toEqual({ cause: ALARM_CAUSES });
  });
});
