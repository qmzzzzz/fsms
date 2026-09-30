/**
 * 浏览器端 E2E 的两条结构性门禁（P3 批次：e2e/ + playwright.config.js 逐行审计产物）
 *
 * 为什么用 jest 单测来守 E2E，而不是靠人工 review：
 * 这两类缺陷的共同点是「用例仍然是绿的」——它们不会让自己失败，
 * 只会让 E2E 在功能真的坏掉时依然通过。所以必须由与本文件无关的
 * 静态不变量来拦，而不是等旅程变红。
 *
 * 门禁 1：retries 与 trace 的耦合。
 *   ci.yml 把 E2E 设为发布门禁且 retries=0（拒绝用重试把抖动洗成绿）。
 *   Playwright 的 'on-first-retry' 语义是「仅在首次重试时录制并保留 trace」
 *   （node_modules/playwright/types/test.d.ts TraceMode），0 重试下永远
 *   不存在第二次尝试 ⇒ 失败时一个现场都不留。而 trace 落在 outputDir
 *   （默认 test-results/），不是 playwright-report/——CI 只上传后者。
 *   两头一叠加，「失败应显性暴露并排查」这句注释原本是假的。
 *
 * 门禁 2：E2E 里引用的自研 class 选择器必须在真实前端源码中存在。
 *   起因是实测到的三个死选择器：`.app-main` 与 `.role-list` 在 web-admin/src
 *   中出现 0 次，但它们被写在 `.app-main, main` 这类「或」选择器里，
 *   命中的其实是恒真的兜底分支——移动端抽屉那条旅程因此从未断言过抽屉。
 *   这类缺陷人工几乎看不出来（选择器"看起来"没问题），但可以机检。
 *
 * 门禁 3：ci.yml 里 E2E 防裁剪下界 MIN_PASSED 必须与实际旅程数对得上。
 *   该下界唯一的职责是「旅程被静默裁剪时报警」，而它自己就是一个需要人工同步的
 *   魔数——这类魔数在本仓被反复记录为失真源头（coverage 阈值、bundle 预算、
 *   测试基线数字都栽过同一处）。此处把「人工同步」换成「机检对账」：数字不再
 *   需要靠人记得改，增删旅程与 CI 常量必须同时改，否则 test job 直接红。
 */

const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '../..');
const E2E_DIR = path.join(ROOT, 'e2e');
const FRONTEND_SRC = path.join(ROOT, 'web-admin', 'src');

/** Playwright 文档中的 TraceMode 全集 */
const VALID_TRACE_MODES = [
  'off',
  'on',
  'on-first-retry',
  'on-all-retries',
  'retain-on-failure',
  'retain-on-first-failure',
  'retain-on-failure-and-retries',
];

/**
 * 「失败时仍能留下 trace」的取值集合。
 * 'off' 与两种「只在重试时保留」的取值不在其中：0 重试下它们等价于不录制。
 */
const TRACES_RETAINED_WITHOUT_RETRY = ['on', 'retain-on-failure', 'retain-on-first-failure'];

/** 递归收集目录下的文件（无第三方依赖） */
function walk(dir, extensions) {
  const out = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      out.push(...walk(full, extensions));
    } else if (extensions.some((ext) => entry.name.endsWith(ext))) {
      out.push(full);
    }
  }
  return out;
}

/**
 * 从 e2e 源文件里提取「被当作 CSS class 选择器使用的字符串」。
 *
 * 只在成对的单/双引号字面量内部找 `.token`：链式调用（`.first()`、
 * `.toBeVisible()`）不是字符串，天然被排除；正则字面量（`/mobile-sidebar-open/`）
 * 同理。这样误报面收窄到"确实写成了选择器字符串"的东西。
 */
function collectClassTokens(files) {
  const tokens = [];
  for (const file of files) {
    const text = fs.readFileSync(file, 'utf8');
    for (const m of text.matchAll(/'([^'\\\n]*)'|"([^"\\\n]*)"/g)) {
      const literal = m[1] ?? m[2] ?? '';
      for (const t of literal.matchAll(/\.([A-Za-z][\w-]*)/g)) {
        tokens.push(t[1]);
      }
    }
  }
  return tokens;
}

describe('playwright.config.js：失败取证能力与 retries 一致', () => {
  let config;

  beforeAll(() => {
    config = require('../../playwright.config.js');
  });

  test('trace 取值必须是 Playwright 支持的 TraceMode', () => {
    expect(VALID_TRACE_MODES).toContain(config.use.trace);
  });

  test('retries=0 时 trace 必须在「首次失败」即保留，而不是等重试', () => {
    // 前提：本仓刻意把 retries 设为 0（不掩盖抖动）。
    // 若哪天有人恢复重试，这条就不该再约束 trace——分开断言，
    // 免得将来为了「修红」而顺手放宽 trace。
    if (config.retries === 0) {
      expect(TRACES_RETAINED_WITHOUT_RETRY).toContain(config.use.trace);
    } else {
      expect(config.use.trace).not.toBe('off');
    }
  });

  test('回归锚：on-first-retry 在 0 重试下不产生任何 trace（正是被修掉的取值）', () => {
    // 独立于上一条：显式钉住「曾经错用的取值」不满足集合，
    // 否则有人会把上面那组改成「除 off 外全部合法」来绕过门禁。
    expect(TRACES_RETAINED_WITHOUT_RETRY).not.toContain('on-first-retry');
    expect(TRACES_RETAINED_WITHOUT_RETRY).not.toContain('on-all-retries');
  });

  test('截图仍为 only-on-failure（与 trace 同属失败现场取证）', () => {
    expect(config.use.screenshot).toBe('only-on-failure');
  });

  test('两个设备项目都在', () => {
    const names = config.projects.map((p) => p.name);
    expect(names).toEqual(expect.arrayContaining(['desktop-chromium', 'mobile-chrome']));
  });
});

describe('E2E 旅程数与 CI 防裁剪下界一致', () => {
  const config = require('../../playwright.config.js');
  const CI_YML = path.join(ROOT, '.github', 'workflows', 'ci.yml');

  /**
   * 统计 spec 文件里声明的**无条件**旅程数。
   *
   * 三类形态必须分开，否则数字会错：
   *  1. `test(...)` / `test.only(...)` —— 真旅程，计入；
   *  2. `test.skip(cond)` / `test.fixme(...)` —— 条件旅程，**不计入**下界。
   *     它们跑不跑由 E2E_USER/E2E_PASS 是否注入决定，计入下界等于把"凭据没注入"
   *     变成门禁永远红；而真被跳过时 ci.yml 的 `skipped > 0` 已经判红，不重复计；
   *  3. `test.beforeEach` / `test.afterEach` / `test.describe` —— 不是旅程。
   *     这里最容易被误算：`test.beforeEach` 同样是"行首 test.xxx(" 形态，
   *     用宽松正则统计会凭空多出十几个"旅程"，下界跟着虚高，真正被裁剪时反而拦不住。
   */
  const countJourneys = (files) => {
    let unconditional = 0;
    let conditional = 0;
    for (const file of files) {
      for (const line of fs.readFileSync(file, 'utf8').split('\n')) {
        if (!/^\s*test(?:\.\w+)*\s*\(/.test(line)) continue;
        if (/^\s*test\.(beforeEach|afterEach|beforeAll|afterAll|describe)\s*\(/.test(line))
          continue;
        if (/^\s*test\.(skip|fixme)\s*\(/.test(line)) {
          conditional += 1;
        } else {
          unconditional += 1;
        }
      }
    }
    return { unconditional, conditional };
  };

  const specFiles = walk(E2E_DIR, ['.spec.js']);
  const { unconditional, conditional } = countJourneys(specFiles);
  const expectedMinPassed = unconditional * config.projects.length;

  test('确实数到了旅程（否则下界对账是空转）', () => {
    expect(specFiles.length).toBeGreaterThan(0);
    expect(unconditional).toBeGreaterThan(0);
  });

  test('ci.yml 的 MIN_PASSED 必须等于 无条件旅程数 × project 数', () => {
    const ciYml = fs.readFileSync(CI_YML, 'utf8');
    const m = ciYml.match(/const MIN_PASSED = (\d+);/);
    // 先钉住"取得到"：取不到时下面的 toBe 会拿 undefined 比数字，报错信息会被
    // 误读成"数字不对"，而真实原因是这道门禁被改名或删掉了。
    expect(m).not.toBeNull();
    expect(Number(m[1])).toBe(expectedMinPassed);
  });

  test('下界不得低于实际值（防止靠调小 MIN_PASSED 掩盖删减）', () => {
    // 上一条已钉住等式；这条单独存在，是为了让"把数字改小来让门禁变绿"这种绕过
    // 在失败信息里直接指向意图，而不是让人去比对两个大数字猜哪里错了。
    const minPassed = Number(fs.readFileSync(CI_YML, 'utf8').match(/const MIN_PASSED = (\d+);/)[1]);
    expect(minPassed).toBeGreaterThanOrEqual(expectedMinPassed);
  });

  test('条件旅程不计入下界（否则凭据缺失时门禁永远红）', () => {
    // 把这个"不算"钉成不变式：将来有人为了保险起见把条件旅程也加进 MIN_PASSED，
    // 门禁会在 E2E_USER/PASS 未注入的 runner 上恒红，而那不是缺陷、只是配置没到位。
    expect(conditional).toBeGreaterThan(0);
    const minPassed = Number(fs.readFileSync(CI_YML, 'utf8').match(/const MIN_PASSED = (\d+);/)[1]);
    const allJourneys = (unconditional + conditional) * config.projects.length;
    expect(minPassed).toBeLessThan(allJourneys);
  });
});

describe('e2e 选择器：自研 class 必须在真实前端源码中存在', () => {
  /** Element Plus 运行时生成的类（组件内部结构，源码里当然搜不到），按前缀放行 */
  const isFrameworkOwned = (token) => token.startsWith('el-');

  // 注意：必须在本作用域（收集阶段）就算好，不能放进 beforeAll——
  // test.each 的参数在收集期求值，beforeAll 要到执行期才跑，那时数组还是空的。
  const frontendFiles = walk(FRONTEND_SRC, ['.vue', '.js', '.ts', '.css']);
  const frontendCorpus = frontendFiles.map((f) => fs.readFileSync(f, 'utf8')).join('\n');

  const e2eFiles = walk(E2E_DIR, ['.js']);
  const selectorTokens = [...new Set(collectClassTokens(e2eFiles))].filter(
    (token) => !isFrameworkOwned(token)
  );

  test('确实扫到了待检 token（否则本门禁是空转）', () => {
    // 语料为空会让所有 token 都"消失"、门禁全红——方向是安全的，
    // 但报错信息会误导（看起来像选择器坏了而不是路径坏了），故显式钉住。
    expect(frontendFiles.length).toBeGreaterThan(20);
    expect(e2eFiles.length).toBeGreaterThan(0);
    expect(selectorTokens.length).toBeGreaterThan(3);
    // 至少覆盖抽屉契约用到的几个，确保提取逻辑真的在工作
    for (const known of ['app-wrapper', 'sidebar', 'collapse-btn', 'mobile-overlay']) {
      expect(selectorTokens).toContain(known);
    }
  });

  test.each(selectorTokens.sort())('选择器 .%s 在前端源码中有对应实现', (token) => {
    expect(frontendCorpus).toContain(token);
  });
});
