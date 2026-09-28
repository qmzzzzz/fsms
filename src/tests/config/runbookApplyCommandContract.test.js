/**
 * 运维手册里的 `--apply` 命令必须与该脚本自己实现的护栏一致
 *
 * 缺陷形状（本轮实测）：`destructiveGuard.assertApplyAllowed` 未设 `ALLOWED_SOURCE_DB`
 * 就 `process.exit(2)`（且在 connect 之前），而手册与**脚本自身的使用注释**仍写着
 * `node scripts/xxx.js --new-key … --apply`。照抄手册的运维会被硬拒在门口，
 * 下一步往往是"把护栏关掉"——fail-closed 的护栏被文档漂移反噬成更危险的操作。
 *
 * 判据不写在测试里：**从脚本源码推导**
 *   · 调用了 assertApplyAllowed ⇒ 文档命令必须带 `ALLOWED_SOURCE_DB=`
 *   · 声明了 CONFIRM_FLAG = '--yes' ⇒ 文档命令还必须带 `--yes`
 * 于是新增一个破坏性脚本时，这条用例会自动对它的手册提出同样的要求。
 *
 * 不扫 `deliverables/**`：那是发现台账，里面**故意**引用了错误的命令原文作为证据。
 */
const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '../../..');
const SCRIPTS_DIR = path.join(ROOT, 'scripts');

const DOC_GLOBS = ['README.md', 'CHANGELOG.md'];
for (const dir of ['docs', 'deployment']) {
  const abs = path.join(ROOT, dir);
  if (fs.existsSync(abs)) {
    for (const f of fs.readdirSync(abs)) if (f.endsWith('.md')) DOC_GLOBS.push(`${dir}/${f}`);
  }
}

/** 把 `... \` 续行与注释块里的多行命令拼成一行，便于按"一条命令"判定 */
const joinContinuations = (text) =>
  text.replace(/\\+\r?\n\s*#\s*\*\s*/g, ' ').replace(/\\\r?\n\s*/g, ' ');

/** 脚本源码 → 它自己要求的护栏 */
function guardContract(source) {
  return {
    needsWhitelist: /assertApplyAllowed\s*\(/.test(source),
    needsYes: /CONFIRM_FLAG\s*=\s*'--yes'/.test(source),
  };
}

const contracts = new Map();
for (const f of fs.readdirSync(SCRIPTS_DIR)) {
  if (!f.endsWith('.js')) continue;
  const src = fs.readFileSync(path.join(SCRIPTS_DIR, f), 'utf8');
  const c = guardContract(src);
  if (c.needsWhitelist || c.needsYes) contracts.set(f, c);
}

/** 从任意文本里抽出"带 --apply 的 node scripts/… 命令"（保留整行：护栏前缀在 node 之前） */
function applyCommands(text, origin) {
  const joined = joinContinuations(text);
  const out = [];
  // --apply 必须成词：`--apply-source` 是另一个脚本的另一套标志，不参与本判据
  const rx = /node\s+scripts\/([a-z0-9_-]+\.js)([^\n]*?--apply(?![\w-])[^\n]*)/;
  for (const line of joined.split('\n')) {
    const m = line.match(rx);
    if (!m) continue;
    out.push({
      origin,
      script: m[1],
      line: line.trim(),
      cmd: `node scripts/${m[1]}${m[2]}`.trim(),
      tail: m[2],
    });
  }
  return out;
}

const corpus = [];
for (const f of fs.readdirSync(SCRIPTS_DIR)) {
  if (f.endsWith('.js')) {
    // 只看使用注释：取到第一个非注释/空行之前的头部块，避免把实现代码当命令
    const src = fs.readFileSync(path.join(SCRIPTS_DIR, f), 'utf8');
    // 只扫头部注释：代码里的 usage 提示串（`[--apply]` 是「可选」记法）不是可复制执行的命令
    const header = src
      .split('\n')
      .slice(0, 40)
      .filter((l) => /^\s*(\*|\/\/|\/\*)/.test(l))
      .join('\n');
    corpus.push(...applyCommands(header, `scripts/${f}`));
  }
}
for (const rel of DOC_GLOBS) {
  const abs = path.join(ROOT, rel);
  if (!fs.existsSync(abs)) continue;
  corpus.push(...applyCommands(fs.readFileSync(abs, 'utf8'), rel));
}

describe('破坏性脚本的手册命令与其自身护栏一致', () => {
  test('判据集非空（脚本侧确有白名单/二次确认要求，否则本套件是空集假绿）', () => {
    expect(contracts.size).toBeGreaterThanOrEqual(4);
    const yesScripts = [...contracts].filter(([, c]) => c.needsYes).map(([n]) => n);
    expect(yesScripts.length).toBeGreaterThanOrEqual(1);
    expect(corpus.length).toBeGreaterThanOrEqual(5);
  });

  test.each(corpus.map((c) => [`${c.origin} → ${c.script}`, c]))(
    '%s：护栏要求的标志都在命令里',
    (_label, item) => {
      const c = contracts.get(item.script);
      // 未被护栏保护的脚本不该出现在这里（防止把判据挂到不相干脚本上）
      expect({ script: item.script, known: Boolean(c) }).toEqual({
        script: item.script,
        known: true,
      });
      const problems = [];
      if (c.needsWhitelist && !/ALLOWED_SOURCE_DB=/.test(item.line))
        problems.push('ALLOWED_SOURCE_DB=');
      if (c.needsYes && !/(^|[^\w-])--yes([^\w-]|$)/.test(item.tail)) problems.push('--yes');
      expect({ origin: item.origin, line: item.line, missing: problems }).toEqual({
        origin: item.origin,
        line: item.line,
        missing: [],
      });
    }
  );

  test('反向前提：把已修好的命令改回旧写法，判据必须报缺失', () => {
    const check = (cmd) => {
      const m = cmd.match(/node\s+scripts\/([a-z0-9_-]+\.js)(.*)/);
      const c = contracts.get(m[1]);
      return {
        whitelist: c.needsWhitelist && !/ALLOWED_SOURCE_DB=/.test(cmd),
        yes: c.needsYes && !/(^|[^\w-])--yes([^\w-]|$)/.test(m[2]),
      };
    };
    // 手册里现在的正确形态
    expect(
      check('ALLOWED_SOURCE_DB=<库名> node scripts/resign-audit-hmac.js --new-key x --apply --yes')
    ).toEqual({ whitelist: false, yes: false });
    // 本轮修掉的两种旧写法（缺白名单 / 缺二次确认）
    expect(check('node scripts/migrate-mfa-secret.js --new-key x --apply')).toEqual({
      whitelist: true,
      yes: false,
    });
    expect(check('ALLOWED_SOURCE_DB=<库名> node scripts/resign-audit-chain-v3.js --apply')).toEqual(
      { whitelist: false, yes: true }
    );
    // `--apply-source` 不得被当成本判据里的 --apply（否则误伤 run-rollback-drill）
    expect(applyCommands('node scripts/run-rollback-drill.js --apply-source', 'x')).toEqual([]);
    // `--yes` 后面跟中文标点仍算"带了二次确认"（曾因 \s|$ 边界漏判一次）
    expect(
      check('ALLOWED_SOURCE_DB=<库名> node scripts/resign-audit-chain-v3.js --apply --yes；')
    ).toEqual({ whitelist: false, yes: false });
  });
});
