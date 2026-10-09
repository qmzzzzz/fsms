/**
 * G8 弱口令**词干匹配器**可证伪性测试（2026-10-09）
 *
 * ## 这份文件守的是什么
 * 2026-10-09 之前，constants/breachedPasswords.js 是 40 条**口令字面量**，而归一化只做
 * 「末尾 ≥4 位数字收敛为 3 位」且**只作用于口令侧** —— 两侧口径不一致的直接后果是
 * 实测 **40 条里 24 条永远命中不了**（生产路径上黑名单比对排在长度/复杂度之后，
 * 8~11 位的条目先被长度规则拒掉；而「以 ≥4 位数字结尾」的条目永远不等于任何口令的
 * 归一化结果）。文件看着 40 条，**有效字典只有 16 个词干**。
 * 修复 = 表改为词干 + 归一化只保留一份（口令侧），两者不可能再漂移。
 *
 * ## 本文件的核心手法：逐条构造反例
 * 对表里**每一个**词干，构造一个「除黑名单外无懈可击」的口令（首字母大写 + 数字尾 +
 * 特殊字符），断言 `validatePasswordStrength` 以「泄露口令」文案拒绝它。
 * 只要有一条词干不可达（表里混入字面量、归一化被改坏、比对改回双侧），对应用例必红。
 * 这条不变量是**必要条件而非巧合**：归一化只删非字母数字与末尾数字、不重排字母，
 * 所以「口令的字母序列（小写）」必须等于「词干的字母序列」；而策略要求同时含大写与小写，
 * 故**词干至少要有 2 个字母**，否则没有任何通过策略的口令能归一化到它。
 *
 * ## 变异证据（实测 2026-10-09，harness：`deliverables/mutation-harness-breached-matcher.js`）
 * 做法是**改真源码 → `new Function` 装载 → 跑本文件里逐字相同的期望**（沿用
 * `installScriptGate.test.js` 的先例：复刻一份判定语义是无效的）。实测结果：
 *   M1 删 normalize 的 `.replace(/\d+$/, '')`        → **捕获**
 *   M2 删 normalize 的 `.replace(/[^a-z0-9]/g, '')`  → **捕获**
 *   M3 `has(stem)` 改 `has(password)`（不归一化）     → **捕获**
 *   M4 表内 `admin` 改回字面量 `admin@123`            → **捕获**
 *   M5 删 `stem.length > 0 &&`                       → **实测仍漏网**：表内无空串，
 *      `has('')` 本就为 false，该分支当前不可达，属防御性冗余。
 *      **不据此宣称设防**；harness 每次复测 M5，若哪天真被捕获会翻红，届时把这里改成「已设防」。
 * harness 另有**基线自检**（未变异时必须全部满足），它当场揪出过本文件作者写错的一条谓词
 * （`Admin@123` 只有 9 位，用 `validatePasswordStrength` 断言会先撞长度规则）——
 * 这正是「前提自证」在这份文件里反复起作用的地方。
 */

const {
  isBreachedPassword,
  normalizePasswordForBreachCheck,
  validatePasswordStrength,
  BREACHED_PASSWORD_STEMS,
  PASSWORD_RULES,
} = require('../../utils/helpers');

/** 与 helpers.js 同一句文案（断具体文案而非 truthy：否则「被顺带命中复杂度规则」也算过） */
const BREACHED_MSG = '该密码属于常见泄露口令，请更换为不易猜测的密码';

/** 逐条与 PASSWORD_RULES 同源，不硬编码 12/64——策略调整时前提自证会跟着走 */
const satisfiesComplexity = (pwd) =>
  typeof pwd === 'string' && PASSWORD_RULES.every((rule) => rule.regex.test(pwd));

/**
 * 把词干抬成「除黑名单外无懈可击」的口令：首个字母大写 + 数字尾巴 + 特殊字符。
 * 用 `replace(/[a-z]/…)` 而非 `charAt(0).toUpperCase()`——后者对 `1qaz2wsx` 这类
 * 以数字开头的词干会把数字「大写化」（等于没大写），构造出的口令缺大写字母，
 * 于是看起来像「词干不可达」，其实是构造器写错了（实测踩过，误报 4 条）。
 */
const inflate = (stem) => stem.replace(/[a-z]/, (c) => c.toUpperCase()) + '1234567890!';

describe('G8 词干表不变量（表与匹配器口径必须一致）', () => {
  test('表内每个条目都已是归一化后的词干 —— 混入字面量即红', () => {
    // 这是防「口径再次漂移」的主闸：若有人把 `admin@123` 写回表里，
    // 归一化它会得到 `admin`，与自身不等 ⇒ 该条目永远命中不了 ⇒ 本条判红。
    const notStem = [...BREACHED_PASSWORD_STEMS].filter(
      (entry) => normalizePasswordForBreachCheck(entry) !== entry
    );
    expect(notStem).toEqual([]);
  });

  test('反向对照：字面量确实会被上面的判据识破（证明闸门不空转）', () => {
    // 与上一条同源的反例：字面量形态必须被判为「不是词干」。
    expect(normalizePasswordForBreachCheck('admin@123')).not.toBe('admin@123');
    expect(normalizePasswordForBreachCheck('P@ssw0rd1234!')).not.toBe('P@ssw0rd1234!');
    expect(normalizePasswordForBreachCheck('admin@123')).toBe('admin');
  });

  test('每个词干至少含 2 个字母（少于 2 个字母的词干在策略下不可达）', () => {
    // 必要条件，不是洁癖：策略要求同时含大写与小写，而归一化保留字母序列，
    // 故词干的字母数 < 2 ⇒ 不存在任何「通过复杂度」的口令能归一化到它。
    const tooFewLetters = [...BREACHED_PASSWORD_STEMS].filter(
      (entry) => (entry.match(/[a-z]/g) || []).length < 2
    );
    expect(tooFewLetters).toEqual([]);
  });

  test('清单规模下界（防清单瘦身）', () => {
    // 旧表 40 条字面量只有 16 个有效词干；新表是一份**按词干**组织的表。
    // 设一个下界，避免将来「悄悄删空」把黑名单退化成摆设。
    expect(BREACHED_PASSWORD_STEMS.size).toBeGreaterThanOrEqual(100);
  });
});

describe('G8 逐条可达：每个词干都能拦下一条满足全部复杂度规则的口令', () => {
  const stems = [...BREACHED_PASSWORD_STEMS].sort();

  test.each(stems)('词干 %s 可达（构造反例：过复杂度、被黑名单拦）', (stem) => {
    const probe = inflate(stem);
    // 前提自证：这条反例必须真的过复杂度，否则「被拒」可能是被长度/复杂度规则拒的，
    // 与黑名单无关 —— 那样这条用例就成了空泛断言。
    expect(satisfiesComplexity(probe)).toBe(true);
    expect(normalizePasswordForBreachCheck(probe)).toBe(stem);
    expect(validatePasswordStrength(probe)).toBe(BREACHED_MSG);
  });
});

describe('G8 归一化语义边界（两侧口径的唯一来源）', () => {
  test('小写化 → 去所有非字母数字 → 去末尾连续数字', () => {
    expect(normalizePasswordForBreachCheck('Admin@123456')).toBe('admin');
    expect(normalizePasswordForBreachCheck('P@ssw0rd1234!')).toBe('pssw0rd');
    expect(normalizePasswordForBreachCheck('Fire@2026Safe!')).toBe('fire2026safe');
  });

  test('末尾数字只收敛一次且只收敛连续段（中间数字不受影响）', () => {
    expect(normalizePasswordForBreachCheck('Admin@123')).toBe('admin');
    expect(normalizePasswordForBreachCheck('Admin@1234')).toBe('admin');
    expect(normalizePasswordForBreachCheck('Admin@123456')).toBe('admin');
    // 数字在中间：保留（`fire2026safe` 里的 2026 不是末尾数字段）
    expect(normalizePasswordForBreachCheck('Fire@2026Safe')).toBe('fire2026safe');
  });

  test('空白与符号一律被剥离（F-A1 空白绕过在这条口径下不可能复发）', () => {
    expect(normalizePasswordForBreachCheck(' admin@123 ')).toBe('admin');
    expect(normalizePasswordForBreachCheck('\tAdmin@123456 \n')).toBe('admin');
    expect(normalizePasswordForBreachCheck('a d m i n 1 2 3')).toBe('admin');
  });

  test('归一化后为空的输入不得被判为命中', () => {
    expect(normalizePasswordForBreachCheck('12345678')).toBe('');
    expect(normalizePasswordForBreachCheck('!!!!!!!!')).toBe('');
    expect(isBreachedPassword('12345678')).toBe(false);
    expect(isBreachedPassword('!!!!!!!!')).toBe(false);
    expect(isBreachedPassword('        ')).toBe(false);
  });
});

describe('G8 回归指纹：旧匹配器漏掉的几族口令现在必须被拦', () => {
  // 这几族是旧实现「只归一化口令侧 + 表内存字面量」时**稳定漏掉**的形态：
  // ① 表里存的是 `passw0rd!` / `p@ssw0rd` / `abcd1234!` 这类**带符号/带数字**的写法，
  //    口令侧归一化后是纯词干 ⇒ 永不相等；
  // ② 表里存的是 `1qaz@wsx` 这类键盘走位 ⇒ 同理。
  // 修复后它们全部由「漏」变「拦」，本条即是这 24 条死条目复活的回归指纹。
  const formerlyMissed = [
    'Passw0rd!1234',
    'P@ssw0rd1234!',
    'Abcd1234!5678',
    '1Qaz@Wsx1234!',
    'Qwerty@12345',
    'Monkey@12345',
    'Sunshine@1234',
    'Iloveyou@1234',
    'Baseball@1234',
    'Football@1234',
    'ChangeMe@1234',
    // 注：必须是 12 位。原探针里写的 `Google@1234` 只有 11 位，会先被长度规则拒掉，
    // 那样这条用例就变成「被长度拒」而不是「被黑名单拒」——前提自证会当场判红。
    'Google@12345',
    'Samsung@12345',
    'Admin@2026!!',
  ];

  test.each(formerlyMissed)('%s 现在被黑名单拦下（此前漏过）', (pwd) => {
    expect(satisfiesComplexity(pwd)).toBe(true);
    expect(validatePasswordStrength(pwd)).toBe(BREACHED_MSG);
  });
});

describe('G8 精度：强口令不得被误伤', () => {
  // 词干匹配放宽了命中面（`SunshineRain99!` 归一化后是 `sunshinerain`，不是词干），
  // 所以必须同时钉住「不引入假阳性」。下面这些口令都含字典词，但整体不是词干，
  // 且都满足 12 位完整策略 —— 断言 `validatePasswordStrength === null` 才有意义。
  const strongPasswords = [
    'Vn6$Rw83pKx5',
    'Fire@2026Safe!',
    'Qz7#Lm42vTx9',
    'Kq4$Wm71zBx3',
    'Tj8%Rv52nHx7',
    'Dragonfly@2026!',
    'AmazonRainforest2026!',
    'FireStation2026!',
    'SunshineRain99!',
    'Passwordless99!',
    'MonkeyBusiness1!',
    'XiaomiPad2026!',
  ];

  test.each(strongPasswords)('%s 不被误判为泄露口令（且整条策略通过）', (pwd) => {
    expect(isBreachedPassword(pwd)).toBe(false);
    expect(validatePasswordStrength(pwd)).toBeNull();
  });

  test('历史夹具（不足 12 位）同样不命中黑名单 —— 精度只与归一化有关，与长度无关', () => {
    // `Xk7#mQ92vL` 是 helpers.test.js 里的既有夹具，只有 10 位，**不能**断言整条策略通过
    // （会先撞长度规则）。它在这里的作用是：证明「不命中」是归一化的结论，
    // 而不是「因为太短所以根本没走到黑名单」——短口令照样要能查词干表。
    expect(satisfiesComplexity('Xk7#mQ92vL')).toBe(false);
    expect(isBreachedPassword('Xk7#mQ92vL')).toBe(false);
    expect(normalizePasswordForBreachCheck('Xk7#mQ92vL')).toBe('xk7mq92vl');
  });
});

describe('G8 原 16 条有效词干仍被拦（修复不得造成回退）', () => {
  // 旧表 40 条里只有 16 个词干真正可达；这 16 条是修复前的**既有防护面**，
  // 修复后必须原样保留，否则「扩表」实为「换表」。
  const originallyEffective = [
    'Admin@123',
    'Password@123',
    'Welcome@1234',
    'Root@123456',
    'Test@123456',
    'Guest@123456',
    'Login@123456',
    'Secret@123456',
    'Master@123456',
    'Letmein@1234',
    'Shadow@123456',
    'Dragon@123456',
    'Monkey@123456',
    'Sunshine@1234',
    'Qwerty@123456',
    'Iloveyou@1234',
  ];

  test.each(originallyEffective)('%s 仍被判为泄露口令', (pwd) => {
    expect(isBreachedPassword(pwd)).toBe(true);
  });
});

describe('G8 非字符串/空值输入的失败方向', () => {
  test('非字符串一律返回 false（不抛错、不误拦）', () => {
    expect(isBreachedPassword('')).toBe(false);
    expect(isBreachedPassword(null)).toBe(false);
    expect(isBreachedPassword(undefined)).toBe(false);
    expect(isBreachedPassword(12345678)).toBe(false);
    expect(isBreachedPassword({})).toBe(false);
    expect(isBreachedPassword(['admin'])).toBe(false);
  });

  test('validatePasswordStrength 对非字符串仍返回「密码不能为空」而非泄露文案', () => {
    // 顺序语义：空值判定在长度/复杂度/黑名单之前，不能被黑名单文案覆盖。
    expect(validatePasswordStrength(null)).toBe('密码不能为空');
    expect(validatePasswordStrength('')).toBe('密码不能为空');
  });
});
