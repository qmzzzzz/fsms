/**
 * CI 门禁接线自检：确保「存在但没人调用」的门禁不再悄悄回到无人调用状态
 *
 * 实证过的两处腐化（都在 2026-09-19 被发现）：
 *  - `scripts/check-utf8.js` 早就存在，但 package.json 与工作流都没引用过它；
 *  - `scripts/compliance-check.js` 只被 `npm run security:audit` 引用，而该 script
 *    在任何 workflow 里都没有调用方 —— 于是「append-only 钩子还挂着吗 / 导出接口还在吗 /
 *    WAL 兜底被摘了吗」从未被自动兑现过，而 job 名 security-audit 让人以为它都查了
 *    （它只跑 npm audit）。
 *
 * 一道没人调用的门禁等于没有门禁，且比没有更糟：它给出**已设防的错觉**。
 * 本测试把「门禁脚本必须真的被 CI 执行到」钉成红灯：删掉那个步骤会红。
 * 判据的实际覆盖面要说清：匹配是**跨工作流全文**的（不区分 job），所以"把步骤挪到
 * 另一个 job"不会红——那种挪动若落到没有 node_modules 的 job，步骤自己会因为
 * 找不到依赖而失败（响的），不是静默放行；真正静默的失效是"引用还在、脚本没了"，
 * 因此每个登记项还断言脚本文件确实存在（见 gateScriptStatus）。
 *
 * 只读文件、不连 DB、不走网络 ⇒ 判定是确定性的。
 * 刻意**剥掉 YAML 注释**再匹配：注释里提到某个脚本名不算调用（否则「check-utf8.js
 * 早就存在」这类说明文字会让本测试恒绿）。
 */

const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..', '..', '..');
const read = (rel) => fs.readFileSync(path.join(ROOT, rel), 'utf8');

/**
 * 必须在 CI 中真实执行的门禁脚本。
 * 新增门禁脚本时把它登记进来——只有在它确实被工作流调用之后才登记得进去，
 * 否则本测试会因「找不到调用点」而红，方向正确。
 */
const CI_ENFORCED_GATE_SCRIPTS = [
  'scripts/compliance-check.js',
  'scripts/check-utf8.js',
  'scripts/lint-ratchet.js',
  'scripts/check-bundle-budget.js',
  // 冒烟与生产演练：经 `npm run test:e2e` / `npm run test:prod-drill` 间接调用，
  // 登记前它们确实被 CI 执行着——但登记才有红可报：删掉那两步今天不会惊动任何人。
  'scripts/e2e-smoke.js',
  'scripts/production-drill.js',
];

/** 剥掉整行注释与行尾注释，只留真正会执行的内容 */
const stripComments = (text) =>
  text
    .split(/\r?\n/)
    .filter((line) => !/^\s*#/.test(line))
    .map((line) => line.replace(/\s+#(?![^'"]*').*$/, ''))
    .join('\n');

const workflowCommandsText = () =>
  fs
    .readdirSync(path.join(ROOT, '.github/workflows'))
    .filter((f) => /\.(yml|yaml)$/.test(f))
    .map((f) => stripComments(read(`.github/workflows/${f}`)))
    .join('\n');

/** 两份 package.json：前端门禁（build:budget）的 script 定义在 web-admin 那一侧 */
const allNpmScripts = () => {
  const out = [];
  for (const rel of ['package.json', 'web-admin/package.json']) {
    const map = JSON.parse(read(rel)).scripts || {};
    for (const [name, cmd] of Object.entries(map)) out.push({ name, cmd, from: rel });
  }
  return out;
};

const escapeForRegex = (s) => s.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&');

/**
 * 找出某条门禁脚本在 CI 里的调用点。
 * @returns {string|null} 命中形式（用于失败时报「找没找到」而不是只报 false），null=未接线
 */
const findWiring = (script, ciText, npmScripts) => {
  const bare = path.basename(script);
  if (ciText.includes(script) || ciText.includes(bare)) return 'workflow 直接调用';
  for (const { name, cmd } of npmScripts) {
    if (!cmd.includes(bare)) continue;
    // script 名必须**整词**命中：`\\b` 在 `test:e2e` 与 `:browser` 之间也成立（e→: 是词边界），
    // 于是 `npm run test:e2e:browser` 会被当成 `test:e2e` 的调用点——删掉真正的 e2e-smoke
    // 步骤后本闸仍绿（冒烟门禁静默消失）。改成"名字后面只能跟空白/行尾"。
    const invoked = new RegExp(`npm\\s+run\\s+(?:\\S+\\s+)*${escapeForRegex(name)}(?![^\\s])`);
    if (invoked.test(ciText)) return `经 npm run ${name} 调用`;
  }
  return null;
};

/**
 * 一条登记门禁的完整"活着"判据：脚本文件在 **且** CI 真的调用它。
 * 只看接线会漏掉一种静默失效：文件被删/改名而 workflow 里的引用还在——
 * 那时 findWiring 照样命中（它匹配的是文本），门禁却已经不存在了。
 */
const gateScriptStatus = (script, ciText, npmScripts) => ({
  exists: fs.existsSync(path.join(ROOT, script)),
  wiring: findWiring(script, ciText, npmScripts),
});

describe('CI 门禁接线自检', () => {
  const ciText = workflowCommandsText();
  const npmScripts = allNpmScripts();

  test('前提自证：确实读到了工作流内容（读空会让本用例恒绿）', () => {
    expect(npmScripts.length).toBeGreaterThan(10);
    expect(ciText).toContain('npm run');
    // 剥注释这条判据本身也得可失败：工作流里确实有被剥掉的注释内容
    expect(stripComments('# 真被调用: npm run lint\nnpm run lint\n').trim()).toBe('npm run lint');
  });

  test.each(CI_ENFORCED_GATE_SCRIPTS)('%s 必须被 CI 执行到', (script) => {
    expect({ script, ...gateScriptStatus(script, ciText, npmScripts) }).toEqual({
      script,
      exists: true,
      wiring: expect.any(String),
    });
  });

  test('可证伪：exists 判据不是常量（把文件删掉必须能被这条闸看见）', () => {
    // 反向样例：不存在的脚本必须同时被两维判掉。若 exists 写成常量 true，这条会红。
    expect(gateScriptStatus('scripts/zzqA-no-such-gate.js', ciText, npmScripts)).toEqual({
      exists: false,
      wiring: null,
    });
  });

  test('可证伪：未接线的脚本必须判为 null（否则上面的用例恒真）', () => {
    expect(findWiring('scripts/zzqA-no-such-gate.js', ciText, npmScripts)).toBeNull();
    // 只出现在注释里的，不算接线——正是本测试最容易自欺的地方
    const onlyInComment = `# node scripts/ghost-gate.js\n- run: echo hi\n`;
    const text = stripComments(onlyInComment);
    expect(text).not.toContain('ghost-gate.js');
    expect(findWiring('scripts/ghost-gate.js', text, npmScripts)).toBeNull();
  });

  test('可证伪：同名前缀的另一条 script 不算接线（test:e2e ≠ test:e2e:browser）', () => {
    // 真实形状：ci.yml 里 `npm run test:e2e`（冒烟）与 `npm run test:e2e:browser`（Playwright）
    // 是两条不同的门禁，脚本名互为前缀。只要匹配用 `\b`，后者就能顶掉前者。
    const smoke = npmScripts.find((s) => s.cmd.includes('e2e-smoke.js'));
    expect(smoke).toBeDefined();
    const onlyBrowser = '- run: npm run test:e2e:browser -- --workers=1\n';
    // 旧口径在这段文本上命中 ⇒ 证明"假绿"不是假设，而是这一格的实际行为
    expect(
      new RegExp(`npm\\s+run\\s+(?:\\S+\\s+)*${escapeForRegex(smoke.name)}\\b`).test(onlyBrowser)
    ).toBe(true);
    // 新口径必须判未接线：谁把 ci.yml 里那步 `npm run test:e2e` 删掉，上面的用例就转红
    expect(findWiring('scripts/e2e-smoke.js', onlyBrowser, npmScripts)).toBeNull();
    // 真接线必须认得，且认的是"整词"那一条（防"改严到把真接线也判成红"）
    expect(
      findWiring('scripts/e2e-smoke.js', `- run: npm run ${smoke.name} --silent\n`, npmScripts)
    ).toBe(`经 npm run ${smoke.name} 调用`);
    expect(findWiring('scripts/e2e-smoke.js', ciText, npmScripts)).toEqual(expect.any(String));
  });
});

/**
 * 覆盖率作用域自检（2026-09-21 加）
 *
 * 发现的实证：`collectCoverageFrom` 只有一条"收 src 目录下所有 .js"的 include，
 * 没有任何排除测试目录的规则，于是测试基建被算进**生产**覆盖率分母。
 * 当轮 lcov 140 个文件里有 4 个来自 src/tests/：
 *   - `src/tests/deploy/helpers/stubExec.js` —— fn 0/14、br 0/46、line 0/79，
 *     一个 **0% 覆盖的测试替身**压住全局水位；
 *   - `src/tests/constants.js`、`fixtures/index.js`、`helpers/buildLoginEnvelope.js`
 *     则接近 100%，反向抬水位。
 * 净效果：剔除后 branches +0.64pt / functions +0.94pt / lines +0.81pt。
 *
 * 但本闸不是为了那 0.6pt，而是为了口径：**"给测试桩写用例"也能让生产覆盖率门禁变绿**，
 * 这类激励一旦存在，数字就不再代表生产代码。
 */
describe('覆盖率作用域：生产分母不得含测试基建', () => {
  const cfg = require('../../../jest.config.js');

  /** 只支持本节用到的 `*` 与 `**` 的最小 glob→正则（不引新依赖） */
  const toRe = (pattern) =>
    new RegExp(
      `^${pattern
        .replace(/[.+^${}()|[\]\\]/g, '\\$&')
        .replace(/\*\*/g, '@@')
        .replace(/\*/g, '[^/]*')
        .replace(/@@/g, '.*')}$`
    );

  /** jest 语义：命中任一 include 且未命中任何 exclude 才收集 */
  const isCollected = (patterns, file) => {
    const inc = patterns.filter((p) => !p.startsWith('!')).some((p) => toRe(p).test(file));
    const exc = patterns.filter((p) => p.startsWith('!')).some((p) => toRe(p.slice(1)).test(file));
    return inc && !exc;
  };

  test('前提自证：判据能区分收集/排除/写错的排除式（恒真的闸等于没有闸）', () => {
    expect(isCollected(['src/**/*.js'], 'src/utils/x.js')).toBe(true);
    // 回归态：没有排除式时，测试基建确实会被收进来——这条同时证明本缺陷真实存在
    expect(isCollected(['src/**/*.js'], 'src/tests/deploy/helpers/stubExec.js')).toBe(true);
    expect(
      isCollected(['src/**/*.js', '!src/tests/**'], 'src/tests/deploy/helpers/stubExec.js')
    ).toBe(false);
    expect(isCollected(['src/**/*.js', '!src/tests/**'], 'src/services/x.js')).toBe(true);
    // 排除式写错（少一个 s）必须仍然漏收——证明"有个 ! 开头就算合规"这种文本闸不可信
    expect(isCollected(['src/**/*.js', '!src/test/**'], 'src/tests/x.js')).toBe(true);
  });

  test('现网配置：生产文件仍被收集，4 个测试基建文件全部出局', () => {
    const patterns = cfg.collectCoverageFrom;
    expect(isCollected(patterns, 'src/services/reportStatsService.js')).toBe(true);
    expect(isCollected(patterns, 'src/controllers/authController.js')).toBe(true);
    for (const f of [
      'src/tests/constants.js',
      'src/tests/deploy/helpers/stubExec.js',
      'src/tests/fixtures/index.js',
      'src/tests/helpers/buildLoginEnvelope.js',
    ]) {
      expect(isCollected(patterns, f)).toBe(false);
    }
  });
});
